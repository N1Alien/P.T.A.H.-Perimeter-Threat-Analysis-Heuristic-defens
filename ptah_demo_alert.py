"""Show a synthetic PTAH alert without starting sensors or writing to Redis."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def main() -> int:
    payload = {
        "demo": "true",
        "process_name": "synthetic-demo-process",
        "process_pid": "42424",
        "rule_id": "DEMO_UNUSUAL_CONNECTION_PATTERN",
        "attribution_confidence": "high (simulated)",
        "recommended_response": "Review the process and evidence manually.",
        "response_state": "pending_manual_review (simulated)",
        "evidence": json.dumps({
            "destination_sample": ["192.0.2.42:443"],
            "remote_port_count": 27,
            "packet_count": 6200,
            "note": "Synthetic demonstration values; not collected from this computer.",
        }),
    }
    alert_json = json.dumps(payload, ensure_ascii=True)
    notify_send = shutil.which("notify-send")
    konsole = shutil.which("konsole")
    opened = False

    if notify_send:
        try:
            result = subprocess.run(
                [notify_send, "--app-name=PTAH", "--urgency=critical",
                 "PTAH DEMO — NOT A REAL DETECTION",
                 "Synthetic sample process (PID 42424) — unusual connection pattern."],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False,
            )
            if result.returncode == 0:
                print("[+] Demo desktop notification sent.")
                opened = True
            else:
                print(f"[!] Desktop notification unavailable: {result.stderr.strip() or 'notification service rejected it'}")
        except OSError as exc:
            print(f"[!] Desktop notification unavailable: {exc}")
    else:
        print("[!] notify-send was not found; skipping desktop notification.")

    if konsole:
        try:
            subprocess.Popen(
                [konsole, "--separate", "-e", sys.executable,
                 str(ROOT / "ptah_alert_window.py"), "--demo", "--alert-json", alert_json],
                cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, start_new_session=True,
            )
            print("[+] Sent the synthetic alert details to Konsole.")
            opened = True
        except OSError as exc:
            print(f"[!] Could not open Konsole: {exc}")
    else:
        print("[!] Konsole was not found; skipping the separate alert window.")

    if not opened:
        print("No desktop alert surface could be opened. The synthetic alert was not saved.")
        return 1
    print("This demo does not start PTAH sensors, connect to Redis, or change system settings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
