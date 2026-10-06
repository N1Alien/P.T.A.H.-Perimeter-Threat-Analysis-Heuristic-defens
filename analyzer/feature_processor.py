"""Aggregate process-attributed network flow summaries into five-second windows."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import time

import redis.asyncio as aioredis

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analyzer.behavior_rules import evaluate_behavior
from shared.broker import RedisStreamProducer
from shared.config import get_mode
from shared.status import publish_status


def aggregate_features(events: list[dict]) -> list[dict]:
    """Pure aggregation function, also used by offline validation."""
    groups = {}
    for event in events:
        process_name = str(event.get("source_process") or "UNATTRIBUTED_NETWORK_TRAFFIC")
        try:
            pid = int(event.get("process_pid") or 0)
        except (TypeError, ValueError):
            pid = 0
        attribution = str(event.get("attribution") or "no_socket_match")
        direction = str(event.get("direction") or "unknown")
        try:
            create_time = float(event.get("process_create_time", 0) or 0)
        except (TypeError, ValueError):
            create_time = 0.0
        key = (process_name, pid, create_time, attribution, direction)
        packet_count = max(1, int(float(event.get("packet_count", 1))))
        payload_bytes = max(0, int(float(event.get("payload_bytes", event.get("packet_payload_len", 0)))))
        bucket = groups.setdefault(key, {
            "process_name": process_name,
            "process_pid": pid,
            "process_create_time": create_time,
            "attribution": attribution,
            "direction": direction,
            "attribution_confidence": str(event.get("attribution_confidence", "none")),
            "packet_count": 0,
            "bytes_sum": 0,
            "entropy_max": 0.0,
            "entropy_weighted_sum": 0.0,
            "cpu_weighted_sum": 0.0,
            "cpu_max": 0.0,
            "memory_weighted_sum": 0.0,
            "threads_max": 1,
            "remote_ips": set(),
            "remote_ports": set(),
            "protocols": set(),
            "destination_sample": set(),
            "metrics_weight": 0,
        })
        entropy_max = float(event.get("network_entropy", event.get("entropy_max", 0.0)))
        entropy_avg = float(event.get("network_entropy_avg", event.get("entropy_avg", entropy_max)))
        cpu = float(event.get("process_cpu_usage", event.get("cpu_avg", 0.0)))
        memory = float(event.get("process_memory_usage", event.get("mem_avg", 0.0)))
        threads = int(float(event.get("process_threads", event.get("threads_max", 1))))
        bucket["packet_count"] += packet_count
        bucket["bytes_sum"] += payload_bytes
        bucket["entropy_max"] = max(bucket["entropy_max"], entropy_max)
        bucket["entropy_weighted_sum"] += entropy_avg * packet_count
        metrics_fresh = str(event.get("process_metrics_fresh", "true")).strip().lower() in {"1", "true", "yes"}
        if metrics_fresh:
            bucket["cpu_weighted_sum"] += cpu * packet_count
            bucket["cpu_max"] = max(bucket["cpu_max"], cpu)
            bucket["memory_weighted_sum"] += memory * packet_count
            bucket["threads_max"] = max(bucket["threads_max"], threads)
            bucket["metrics_weight"] += packet_count
        dst_ip = event.get("remote_ip") or event.get("destination_ip") or event.get("dst_ip")
        remote_port = event.get("remote_port", event.get("destination_port", event.get("dst_port")))
        if dst_ip:
            bucket["remote_ips"].add(str(dst_ip))
            if len(bucket["destination_sample"]) < 8:
                bucket["destination_sample"].add(str(dst_ip))
        try:
            if int(remote_port) > 0:
                bucket["remote_ports"].add(int(remote_port))
        except (TypeError, ValueError):
            pass
        if event.get("protocol"):
            bucket["protocols"].add(str(event["protocol"]))

    aggregated = []
    for bucket in groups.values():
        actual_metrics_weight = bucket.pop("metrics_weight")
        weight = max(1, actual_metrics_weight)
        entropy_sum = bucket.pop("entropy_weighted_sum")
        cpu_sum = bucket.pop("cpu_weighted_sum")
        cpu_max = bucket["cpu_max"]
        memory_sum = bucket.pop("memory_weighted_sum")
        remote_ips = bucket.pop("remote_ips")
        remote_ports = bucket.pop("remote_ports")
        protocols = bucket.pop("protocols")
        destination_sample = bucket.pop("destination_sample")
        bucket.update({
            "entropy_avg": round(entropy_sum / weight, 4),
            "cpu_avg": round(cpu_sum / weight, 4),
            "cpu_max": cpu_max,
            "mem_avg": round(memory_sum / weight, 4),
            "remote_host_count": len(remote_ips),
            "remote_port_count": len(remote_ports),
            "protocols": sorted(protocols),
            "destination_sample": sorted(destination_sample),
            "process_metrics_fresh": actual_metrics_weight > 0,
            "model_eligible": (
                bucket["process_pid"] > 0
                and actual_metrics_weight > 0
                and bucket["attribution_confidence"] == "high"
            ),
        })
        aggregated.append(bucket)
    return aggregated


class PtahFeatureProcessor:
    def __init__(self, broker_host="localhost", broker_port=6379, window_size_sec=5):
        self.host = broker_host
        self.port = broker_port
        self.window_size = window_size_sec
        self.client = None
        self.raw_buffer = []
        self.window_count = 0
        self.last_id = "$"

    async def connect(self):
        self.client = await aioredis.Redis(host=self.host, port=self.port, decode_responses=True)
        print("[+] PTAH Feature Processor: Connected to the broker.")

    async def _record_findings(self, window):
        for finding in evaluate_behavior(window):
            identity = (
                f"{finding['rule_id']}:{finding.get('process_pid') or finding['process_name']}:"
                f"{window.get('process_create_time', 0)}:{window.get('direction', 'unknown')}"
            )
            dedupe_key = hashlib.sha256(identity.encode("utf-8")).hexdigest()
            first_in_cooldown = await self.client.set(
                f"ptah:rule-dedupe:{dedupe_key}", "1", ex=300, nx=True
            )
            if not first_in_cooldown:
                continue
            alert = {
                **finding,
                "observed_at": time.time(),
                "evidence": json.dumps(finding["evidence"], separators=(",", ":")),
                "destination_sample": json.dumps(window.get("destination_sample", [])),
                "remote_host_count": window.get("remote_host_count", 0),
                "remote_port_count": window.get("remote_port_count", 0),
            }
            await self.client.xadd(
                "alerts:behavioral", RedisStreamProducer.flatten_event(alert),
                maxlen=5000, approximate=True
            )
            print(
                f"[!] PTAH OBSERVATION: {finding['rule_id']} for "
                f"{finding['process_name']} — manual review required."
            )

    async def run(self):
        mode = get_mode()
        await self.connect()
        print(f"[*] PTAH Feature Processor: Aggregating {self.window_size}-second windows in {mode} mode.")
        await publish_status(
            self.client, "feature_processor", state="running", mode=mode,
            window_size=self.window_size,
        )
        last_report = time.monotonic()
        while True:
            start_time = asyncio.get_running_loop().time()
            while asyncio.get_running_loop().time() - start_time < self.window_size:
                try:
                    events = await self.client.xread({"telemetry:features": self.last_id}, count=500, block=500)
                    for _, messages in events:
                        for msg_id, payload in messages:
                            self.last_id = msg_id
                            self.raw_buffer.append(payload)
                except Exception as exc:
                    print(f"[-] PTAH Feature Processor: Redis read failed: {exc}")
                    await publish_status(self.client, "feature_processor", state="degraded", mode=mode)
                    await asyncio.sleep(1)
                await asyncio.sleep(0.1)

            windows = aggregate_features(self.raw_buffer)
            self.raw_buffer = []
            if not windows:
                windows = [{
                    "process_name": "NO_NETWORK_EVENTS",
                    "process_pid": 0,
                    "attribution": "none",
                    "attribution_confidence": "none",
                    "packet_count": 0,
                    "bytes_sum": 0,
                    "entropy_max": 0.0,
                    "entropy_avg": 0.0,
                    "cpu_avg": 0.0,
                    "cpu_max": 0.0,
                    "mem_avg": 0.0,
                    "threads_max": 1,
                    "remote_host_count": 0,
                    "remote_port_count": 0,
                    "protocols": [],
                    "destination_sample": [],
                    "model_eligible": False,
                }]

            for window in windows:
                await self.client.xadd(
                    "ml:features_window", RedisStreamProducer.flatten_event(window),
                    maxlen=20000, approximate=True
                )
                await self._record_findings(window)
            self.window_count += 1
            if time.monotonic() - last_report >= 10:
                last_report = time.monotonic()
                eligible = sum(bool(item.get("model_eligible")) for item in windows)
                print(
                    f"[+] PTAH Feature Processor: window {self.window_count}; "
                    f"{len(windows)} process groups, {eligible} model-eligible."
                )
            await publish_status(
                self.client, "feature_processor", state="running", mode=mode,
                window_count=self.window_count, latest_groups=len(windows),
                model_eligible_groups=sum(bool(item.get("model_eligible")) for item in windows),
            )


if __name__ == "__main__":
    try:
        get_mode()
        asyncio.run(PtahFeatureProcessor(window_size_sec=5).run())
    except KeyboardInterrupt:
        print("\n[-] PTAH Feature Processor: Shutting down.")
    except ValueError as exc:
        print(f"[-] PTAH Feature Processor configuration error: {exc}", file=sys.stderr)
