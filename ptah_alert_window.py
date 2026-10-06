"""Display one PTAH alert in a separate terminal and record an explicit review choice."""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import unicodedata

import redis


ALERT_STREAMS = {"alerts:behavioral", "alerts:anomalies"}
STREAM_ID_PATTERN = re.compile(r"^[0-9]+-[0-9]+$")


def safe_text(value, limit: int = 1000) -> str:
    text = str(value)
    text = "".join(char for char in text if unicodedata.category(char) != "Cc")
    return text[:limit]


def display(payload: dict[str, str]) -> None:
    process = safe_text(payload.get("process_name", "unknown"), 160)
    pid = safe_text(payload.get("process_pid", "unknown"), 32)
    signal_name = safe_text(payload.get("rule_id", payload.get("engine", "PTAH signal")), 160)
    stream = payload.get("alert_stream", "")
    alert_id = payload.get("alert_id", "")

    print("\n" + "=" * 72)
    if payload.get("demo") == "true":
        print("PTAH DEMO — SIMULATED ALERT, NOT A REAL DETECTION")
    else:
        print("PTAH — SUSPICIOUS ACTIVITY: MANUAL REVIEW REQUIRED")
    print("=" * 72)
    print(f"Process: {process} (PID {pid})")
    print(f"Signal: {signal_name}")
    print(f"Source: {safe_text(stream, 64)} / {safe_text(alert_id, 64)}")
    print(f"Attribution confidence: {safe_text(payload.get('attribution_confidence', 'unknown'), 40)}")

    for key, label in (
        ("reconstruction_loss", "Model score"),
        ("threshold", "Model threshold"),
        ("recommended_response", "Suggested follow-up"),
        ("response_state", "Review state"),
    ):
        if payload.get(key):
            print(f"{label}: {safe_text(payload[key], 500)}")

    evidence = payload.get("evidence")
    if evidence:
        try:
            parsed = json.loads(evidence)
            evidence = json.dumps(parsed, ensure_ascii=False, indent=2)
        except (TypeError, json.JSONDecodeError):
            pass
        print("Evidence:")
        print(safe_text(evidence, 8000))
    if payload.get("destination_sample"):
        print(f"Remote destinations: {safe_text(payload['destination_sample'], 1500)}")

    print("\nPTAH is observing only. It has not blocked traffic or stopped this process.")
    print("Approve means record for manual follow-up; it does not run a response.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alert-json", required=True, help=argparse.SUPPRESS)
    parser.add_argument("--demo", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        payload = json.loads(args.alert_json)
    except json.JSONDecodeError as exc:
        parser.error(f"invalid alert data: {exc}")
    if not isinstance(payload, dict):
        parser.error("alert data must be an object")

    display(payload)
    if args.demo:
        print("\nThis is sample data only. No alert was written and no response was taken.")
        try:
            input("Press Enter to close this demo window: ")
        except EOFError:
            pass
        return 0

    stream = payload.get("alert_stream")
    alert_id = payload.get("alert_id")
    if stream not in ALERT_STREAMS or not isinstance(alert_id, str) or not STREAM_ID_PATTERN.fullmatch(alert_id):
        parser.error("alert stream or ID is invalid")

    try:
        choice = input("\n[A] Approve for manual follow-up   [D] Dismiss   [Enter] Leave pending: ").strip().lower()
    except EOFError:
        return 0
    if choice not in {"a", "d"}:
        print("Alert left pending; no decision was recorded.")
        return 0

    decision = "approve" if choice == "a" else "dismiss"
    note = "Approved for manual follow-up" if decision == "approve" else "Dismissed during manual review"
    try:
        client = redis.Redis(host="localhost", port=6379, decode_responses=True, socket_connect_timeout=2)
        client.ping()
        if not client.xrange(stream, min=alert_id, max=alert_id, count=1):
            raise ValueError("the alert is no longer present in Redis")
        client.xadd("alerts:decisions", {
            "alert_stream": stream,
            "alert_id": alert_id,
            "decision": decision,
            "note": note,
            "reviewed_at": f"{time.time():.3f}",
            "action_executed": "false",
        }, maxlen=5000, approximate=True)
        client.close()
        print(f"Recorded {decision}. PTAH executed no response action.")
    except (redis.RedisError, ValueError) as exc:
        print(f"Could not record the decision: {safe_text(exc, 300)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
