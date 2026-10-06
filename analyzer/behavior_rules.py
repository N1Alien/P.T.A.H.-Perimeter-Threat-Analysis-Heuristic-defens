"""Conservative observation-only behavior signals; this module takes no action."""
from __future__ import annotations

import os
import math

from shared.config import get_mode, get_positive_int


def evaluate_behavior(payload: dict, *, mode: str | None = None) -> list[dict]:
    """Return review signals for one five-second process window.

    Signals are leads for a human to inspect, never proof of malicious activity.
    Encrypted payload entropy alone is intentionally not an alert condition.
    """
    active_mode = mode or get_mode()
    if active_mode != "observe":
        raise ValueError("Behavior rules only support passive observe mode.")

    byte_limit = get_positive_int("PTAH_RULE_BYTES_PER_WINDOW", 25_000_000)
    packet_limit = get_positive_int("PTAH_RULE_PACKETS_PER_WINDOW", 5_000)
    port_limit = get_positive_int("PTAH_RULE_REMOTE_PORTS_PER_WINDOW", 24)
    try:
        entropy_limit = float(os.environ.get("PTAH_RULE_ENTROPY_THRESHOLD", "7.5"))
    except ValueError as exc:
        raise ValueError("PTAH_RULE_ENTROPY_THRESHOLD must be a number between 0 and 8.") from exc
    if not math.isfinite(entropy_limit) or not 0 <= entropy_limit <= 8:
        raise ValueError("PTAH_RULE_ENTROPY_THRESHOLD must be a number between 0 and 8.")
    entropy_bytes_limit = get_positive_int("PTAH_RULE_ENTROPY_BYTES_PER_WINDOW", 1_000_000)

    packet_count = int(float(payload.get("packet_count", 0)))
    byte_count = int(float(payload.get("bytes_sum", 0)))
    port_count = int(float(payload.get("remote_port_count", 0)))
    entropy = float(payload.get("entropy_max", 0.0))
    process_name = payload.get("process_name") or "UNKNOWN_PROCESS"

    findings = []
    if payload.get("direction") == "outbound" and byte_count >= byte_limit:
        findings.append({
            "rule_id": "high_egress_volume",
            "severity": "medium",
            "summary": "High payload volume in a five-second observation window.",
            "evidence": {"bytes_sum": byte_count, "threshold": byte_limit},
        })
    if packet_count >= packet_limit:
        findings.append({
            "rule_id": "high_packet_rate",
            "severity": "low",
            "summary": "High packet count in a five-second observation window.",
            "evidence": {"packet_count": packet_count, "threshold": packet_limit},
        })
    if port_count >= port_limit:
        findings.append({
            "rule_id": "wide_remote_port_fanout",
            "severity": "medium",
            "summary": "One process contacted many remote ports in a short window.",
            "evidence": {"remote_port_count": port_count, "threshold": port_limit},
        })
    # High entropy is common for TLS and compressed data; require substantial
    # volume and port fan-out before raising a low-confidence review signal.
    if payload.get("direction") == "outbound" and entropy >= entropy_limit and byte_count >= entropy_bytes_limit and port_count >= max(3, port_limit // 4):
        findings.append({
            "rule_id": "high_entropy_multi_port_traffic",
            "severity": "low",
            "summary": "High-entropy payloads coincided with substantial traffic across several ports.",
            "evidence": {
                "entropy_max": entropy,
                "bytes_sum": byte_count,
                "remote_port_count": port_count,
            },
        })

    for finding in findings:
        if payload.get("process_pid") and payload.get("attribution_confidence") in {"high", "medium"}:
            recommendation = "Review the attributed process and evidence; decide any response manually."
        else:
            recommendation = "Review the network evidence; process attribution is uncertain, so do not assume an owner."
        finding.update({
            "process_name": process_name,
            "process_pid": payload.get("process_pid"),
            "attribution": payload.get("attribution", "unattributed"),
            "attribution_confidence": payload.get("attribution_confidence", "none"),
            "response_state": "pending_manual_review",
            "approval_required": True,
            "recommended_response": recommendation,
            "mode": "observe",
        })
    return findings
