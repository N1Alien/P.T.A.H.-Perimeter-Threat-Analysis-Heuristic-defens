"""List alerts and record explicit human review decisions; never performs actions."""
from __future__ import annotations

import argparse
import json
import time

import redis


ALERT_STREAMS = ("alerts:behavioral", "alerts:anomalies")


def connect():
    client = redis.Redis(host="localhost", port=6379, decode_responses=True, socket_connect_timeout=2)
    client.ping()
    return client


def show_alerts(client, count):
    decisions = {}
    for _, fields in client.xrevrange("alerts:decisions", count=5000):
        key = (fields.get("alert_stream"), fields.get("alert_id"))
        decisions.setdefault(key, fields.get("decision", "reviewed"))
    for stream in ALERT_STREAMS:
        print(f"\n{stream}")
        entries = client.xrevrange(stream, count=count)
        if not entries:
            print("  no alerts")
            continue
        for entry_id, fields in entries:
            evidence = fields.get("evidence")
            if evidence:
                try:
                    evidence = json.dumps(json.loads(evidence), ensure_ascii=False)
                except json.JSONDecodeError:
                    pass
            print(
                f"  id={entry_id} state={decisions.get((stream, entry_id), fields.get('response_state', 'review'))} "
                f"process={fields.get('process_name', 'unknown')} "
                f"pid={fields.get('process_pid', 'unknown')} "
                f"rule={fields.get('rule_id', fields.get('engine', 'unknown'))} "
                f"attribution={fields.get('attribution_confidence', 'unknown')}"
            )
            if evidence:
                print(f"    evidence={evidence}")
            if fields.get("destination_sample"):
                print(f"    remote destinations={fields['destination_sample']}")
            if fields.get("recommended_response"):
                print(f"    recommendation={fields['recommended_response']}")


def record_decision(client, stream, entry_id, decision, note):
    if stream not in ALERT_STREAMS:
        raise ValueError(f"Alert stream must be one of: {', '.join(ALERT_STREAMS)}")
    if not client.xrange(stream, min=entry_id, max=entry_id, count=1):
        raise ValueError(f"Alert {entry_id!r} was not found in {stream}.")
    client.xadd("alerts:decisions", {
        "alert_stream": stream,
        "alert_id": entry_id,
        "decision": decision,
        "note": note,
        "reviewed_at": f"{time.time():.3f}",
        "action_executed": "false",
    }, maxlen=5000, approximate=True)
    print(f"Recorded {decision} for {stream} {entry_id}. PTAH executed no response action.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    listing = subparsers.add_parser("list", help="show recent behavior and model alerts")
    listing.add_argument("--count", type=int, default=20)
    decide = subparsers.add_parser("decide", help="record an explicit review decision")
    decide.add_argument("--stream", choices=ALERT_STREAMS, required=True)
    decide.add_argument("--id", required=True, help="Redis Stream alert ID")
    decide.add_argument("--decision", choices=("approve", "dismiss"), required=True)
    decide.add_argument("--note", default="")
    args = parser.parse_args()
    if args.command == "list" and args.count < 1:
        parser.error("--count must be positive")
    try:
        client = connect()
        if args.command == "list":
            show_alerts(client, args.count)
        else:
            record_decision(client, args.stream, args.id, args.decision, args.note)
        client.close()
    except (redis.RedisError, ValueError) as exc:
        parser.exit(1, f"PTAH review error: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
