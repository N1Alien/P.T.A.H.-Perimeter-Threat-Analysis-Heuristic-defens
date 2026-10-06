"""Join packet socket ownership with recent process telemetry."""
from __future__ import annotations

import asyncio
import os
import sys
import time

import redis.asyncio as aioredis

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared.config import get_mode
from shared.broker import RedisStreamProducer
from shared.status import publish_status


KNOWN_ATTRIBUTION = {"socket_5_tuple", "udp_local_socket", "tcp_listener"}


def correlate_network_event(packet: dict, active_processes: dict, *, now=None,
                            process_ttl: float = 10.0) -> dict:
    """Build one process-aware model event without guessing from CPU activity."""
    now = time.time() if now is None else float(now)
    raw_pid = packet.get("process_pid")
    try:
        pid = int(raw_pid) if raw_pid not in (None, "", "0", 0) else None
    except (TypeError, ValueError):
        pid = None

    attribution = str(packet.get("attribution") or "no_socket_match")
    confidence = str(packet.get("attribution_confidence") or "none")
    process_name = str(packet.get("process_name") or "UNATTRIBUTED_NETWORK_TRAFFIC")
    process_state = active_processes.get(str(pid)) if pid is not None else None
    metrics_fresh = False
    metrics = {"cpu": 0.0, "memory": 0.0, "threads": 1}

    if pid is not None and attribution in KNOWN_ATTRIBUTION:
        if process_state:
            observed_at = float(process_state.get("observed_at", 0.0))
            network_create_time = packet.get("process_create_time")
            process_create_time = process_state.get("process_create_time")
            same_process = False
            if network_create_time not in (None, "", 0, "0") and process_create_time not in (None, "", 0, "0"):
                try:
                    same_process = abs(float(network_create_time) - float(process_create_time)) < 1.0
                except (TypeError, ValueError):
                    same_process = False
            metrics_fresh = same_process and 0 <= now - observed_at <= process_ttl
            if metrics_fresh:
                process_name = str(process_state.get("name") or process_name)
                metrics = {
                    "cpu": float(process_state.get("cpu", 0.0)),
                    "memory": float(process_state.get("memory", 0.0)),
                    "threads": int(process_state.get("threads", 1)),
                }

    if pid is None or attribution not in KNOWN_ATTRIBUTION:
        pid = None
        process_name = "UNATTRIBUTED_NETWORK_TRAFFIC"
        attribution = attribution if attribution not in KNOWN_ATTRIBUTION else "no_socket_match"
        confidence = "none"

    return {
        "source_process": process_name,
        "process_pid": pid or 0,
        "process_create_time": packet.get("process_create_time") or 0.0,
        "process_metrics_fresh": metrics_fresh,
        "process_cpu_usage": metrics["cpu"],
        "process_memory_usage": metrics["memory"],
        "process_threads": metrics["threads"],
        "attribution": attribution,
        "attribution_confidence": confidence,
        "packet_count": int(float(packet.get("packet_count", 1))),
        "packet_payload_len": int(float(packet.get("payload_bytes", packet.get("packet_payload_len", 0)))),
        "network_entropy": float(packet.get("entropy_max", packet.get("entropy", 0.0))),
        "network_entropy_avg": float(packet.get("entropy_avg", packet.get("entropy", 0.0))),
        "destination_ip": packet.get("dst_ip"),
        "source_ip": packet.get("src_ip"),
        "source_port": int(float(packet.get("src_port", 0))),
        "destination_port": int(float(packet.get("dst_port", 0))),
        "remote_ip": packet.get("src_ip") if packet.get("direction") == "inbound" else packet.get("dst_ip"),
        "remote_port": int(float(packet.get("src_port", 0))) if packet.get("direction") == "inbound" else int(float(packet.get("dst_port", 0))),
        "protocol": packet.get("protocol", "UNKNOWN"),
        "direction": packet.get("direction", "unknown"),
        "observed_at": float(packet.get("observed_at", now)),
    }


class PtahCoreAggregator:
    def __init__(self, broker_host="localhost", broker_port=6379):
        self.host = broker_host
        self.port = broker_port
        self.client = None
        self.active_processes = {}
        self.process_ttl = 10.0
        self.packet_windows = 0
        self.attributed_windows = 0

    async def connect(self):
        self.client = await aioredis.Redis(host=self.host, port=self.port, decode_responses=True)
        print("[+] PTAH Core: Connected to the data broker.")

    async def watch_processes(self):
        print("[*] PTAH Core: Process state monitor started...")
        last_id = "$"
        while True:
            try:
                events = await self.client.xread({"telemetry:processes": last_id}, count=100, block=1000)
                for _, messages in events:
                    for msg_id, payload in messages:
                        last_id = msg_id
                        pid = payload.get("pid")
                        if not pid:
                            continue
                        try:
                            self.active_processes[str(int(pid))] = {
                                "name": payload.get("name"),
                                "user": payload.get("user"),
                                "cpu": float(payload.get("cpu_percent", 0)),
                                "memory": float(payload.get("memory_percent", 0)),
                                "threads": int(payload.get("num_threads", 1)),
                                "process_create_time": payload.get("process_create_time"),
                                "observed_at": float(payload.get("observed_at", time.time())),
                            }
                        except (TypeError, ValueError):
                            continue
                cutoff = time.time() - 60
                self.active_processes = {
                    pid: state for pid, state in self.active_processes.items()
                    if float(state.get("observed_at", 0)) >= cutoff
                }
                await publish_status(
                    self.client, "core", state="running",
                    cached_processes=len(self.active_processes), mode=get_mode(),
                )
            except Exception as exc:
                print(f"[-] PTAH Core process stream error: {exc}")
                await publish_status(self.client, "core", state="degraded", mode=get_mode())
                await asyncio.sleep(1)

    async def watch_network(self):
        print("[*] PTAH Core: Network traffic correlation started...")
        last_id = "$"
        last_report = time.monotonic()
        while True:
            try:
                events = await self.client.xread({"telemetry:network": last_id}, count=500, block=1000)
                features = []
                for _, messages in events:
                    for msg_id, payload in messages:
                        last_id = msg_id
                        feature = correlate_network_event(
                            payload, self.active_processes, process_ttl=self.process_ttl
                        )
                        self.packet_windows += feature["packet_count"]
                        if feature["process_pid"] > 0:
                            self.attributed_windows += feature["packet_count"]
                        features.append(feature)
                if features:
                    pipeline = self.client.pipeline(transaction=False)
                    for feature in features:
                        pipeline.xadd(
                            "telemetry:features", RedisStreamProducer.flatten_event(feature),
                            maxlen=20000, approximate=True
                        )
                    await pipeline.execute()
                if time.monotonic() - last_report >= 10:
                    last_report = time.monotonic()
                    ratio = 100 * self.attributed_windows / self.packet_windows if self.packet_windows else 0
                    await publish_status(
                        self.client, "core", state="running",
                        packets_seen=self.packet_windows,
                        attributed_packets=self.attributed_windows,
                        attribution_percent=f"{ratio:.1f}", mode=get_mode(),
                    )
            except Exception as exc:
                print(f"[-] PTAH Core network stream error: {exc}")
                await publish_status(self.client, "core", state="degraded", mode=get_mode())
                await asyncio.sleep(1)

    async def run(self):
        await self.connect()
        await asyncio.gather(self.watch_processes(), self.watch_network())


if __name__ == "__main__":
    try:
        get_mode()
        asyncio.run(PtahCoreAggregator().run())
    except KeyboardInterrupt:
        print("\n[-] PTAH Core: Shutting down.")
    except ValueError as exc:
        print(f"[-] PTAH Core configuration error: {exc}", file=sys.stderr)
