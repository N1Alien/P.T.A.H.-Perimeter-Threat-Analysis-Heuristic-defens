# Contributing

Thanks for helping improve PTAH. It is an experimental Linux prototype; changes should preserve its passive, observation-only safety boundary.

## Before opening a change

- Explain the problem and the behavior you expect.
- Keep packet payloads, credentials, personal telemetry, and machine-specific paths out of commits and issue reports.
- Prefer synthetic fixtures over live packet capture or real process activity.
- Do not add automatic firewall, process-kill, or other enforcement behavior.

## Local checks

Create and install the project environment as described in [README.md](README.md), then run:

```bash
venv/bin/python -m unittest discover -s tests -v
venv/bin/python -m compileall -q ptah_orchestrator.py ptah_status.py ptah_review.py ptah_alert_window.py ptah_demo_alert.py analyzer sensors shared tests
```

The unit suite uses synthetic data and does not require Docker or packet-capture privileges. If a change needs live integration testing, describe the setup and results separately; never run tests that modify firewall rules or terminate unrelated processes.

## Pull requests

Keep changes focused, update documentation when user-visible behavior changes, and include test coverage for new pure logic. State clearly which checks were run and which platform-specific behavior remains unverified.
