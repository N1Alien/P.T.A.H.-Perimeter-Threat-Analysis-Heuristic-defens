"""Capture IP metadata and attribute packets through cached socket ownership."""
from __future__ import annotations

import asyncio
import math
import os
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import psutil
from scapy.all import conf, sniff, IP, IPv6, TCP, UDP

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sensors.socket_attribution import SocketAttributor, normalize_ip
from shared.broker import RedisStreamProducer
from shared.config import get_mode
from shared.status import publish_status


class NetworkSensor:
    def __init__(self, interface=None, broker_host="localhost", broker_port=6379,
                 refresh_interval=1.0, publish_interval=1.0, max_flows_per_window=4096):
        self.interface = interface or os.environ.get("PTAH_INTERFACE") or str(conf.iface)
        self.producer = RedisStreamProducer(host=broker_host, port=broker_port)
        self.loop = None
        self.attributor = SocketAttributor()
        self.refresh_interval = refresh_interval
        self.publish_interval = publish_interval
        self.max_flows_per_window = max_flows_per_window
        self._flow_lock = threading.Lock()
        self._flows = {}
        self._window_drops = 0
        self.packet_count = 0
        self.attributed_count = 0
        self._last_refresh_error = None

    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        entropy = 0.0
        length = len(data)
        for count in counts:
            if count:
                probability = count / length
                entropy -= probability * math.log2(probability)
        return round(entropy, 4)

    @staticmethod
    def _socket_address(address):
        if not address or len(address) < 2:
            return None
        return str(address[0]), int(address[1])

    @classmethod
    def read_socket_rows(cls):
        """Read process-owned internet sockets; called outside the packet callback."""
        process_cache = {}
        rows = []
        for connection in psutil.net_connections(kind="inet"):
            if connection.pid is None:
                continue
            if connection.type == socket.SOCK_STREAM:
                protocol = "TCP"
            elif connection.type == socket.SOCK_DGRAM:
                protocol = "UDP"
            else:
                continue
            local_addr = cls._socket_address(connection.laddr)
            remote_addr = cls._socket_address(connection.raddr)
            if not local_addr:
                continue
            pid = int(connection.pid)
            if pid not in process_cache:
                try:
                    process = psutil.Process(pid)
                    process_cache[pid] = (process.name(), process.create_time())
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    process_cache[pid] = ("UNKNOWN_PROCESS", None)
            process_name, create_time = process_cache[pid]
            rows.append({
                "protocol": protocol,
                "pid": pid,
                "process_name": process_name,
                "process_create_time": create_time,
                "local_addr": local_addr,
                "remote_addr": remote_addr,
            })
        return rows

    @staticmethod
    def read_local_ips():
        local_ips = set()
        for addresses in psutil.net_if_addrs().values():
            for address in addresses:
                if address.family in {socket.AF_INET, socket.AF_INET6} and address.address:
                    normalized = normalize_ip(address.address)
                    if normalized:
                        local_ips.add(normalized)
        return local_ips

    @classmethod
    def read_socket_snapshot(cls):
        return cls.read_socket_rows(), cls.read_local_ips()

    def process_packet(self, packet):
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
        elif packet.haslayer(IPv6):
            ip_layer = packet.getlayer(IPv6)
        else:
            return

        if packet.haslayer(TCP):
            transport = packet.getlayer(TCP)
            protocol = "TCP"
        elif packet.haslayer(UDP):
            transport = packet.getlayer(UDP)
            protocol = "UDP"
        else:
            # Packet metadata without a transport socket is retained as explicitly
            # unattributed; no process is guessed from unrelated activity.
            transport = None
            protocol = "OTHER"

        source_port = int(transport.sport) if transport else 0
        destination_port = int(transport.dport) if transport else 0
        owner = self.attributor.attribute(
            protocol, ip_layer.src, source_port, ip_layer.dst, destination_port
        )
        payload = bytes(transport.payload) if transport else b""
        payload_len = len(payload)
        direction = owner["direction"]
        event = {
            "src_ip": str(ip_layer.src),
            "dst_ip": str(ip_layer.dst),
            "src_port": source_port,
            "dst_port": destination_port,
            "protocol": protocol,
            "direction": direction,
            "packet_length": len(packet),
            "payload_bytes": payload_len,
            "entropy_max": self.calculate_shannon_entropy(payload),
            "process_pid": owner["pid"],
            "process_name": owner["process_name"],
            "process_create_time": owner["process_create_time"],
            "attribution": owner["attribution"],
            "attribution_confidence": owner["attribution_confidence"],
            "observed_at": time.time(),
        }
        # A one-second in-memory flow window bounds Redis write volume. Packet
        # payload bytes are never retained, only counts, sizes, and entropy.
        key = (
            event["process_pid"], event["process_name"], event["attribution"],
            event["process_create_time"],
            event["src_ip"], event["dst_ip"], source_port, destination_port,
            protocol, direction,
        )
        with self._flow_lock:
            self.packet_count += 1
            if owner["pid"] is not None:
                self.attributed_count += 1
            flow = self._flows.get(key)
            if flow is None:
                if len(self._flows) >= self.max_flows_per_window:
                    self._window_drops += 1
                    return
                flow = {**event, "packet_count": 0, "entropy_sum": 0.0}
                self._flows[key] = flow
            flow["packet_count"] += 1
            flow["payload_bytes"] += payload_len
            flow["entropy_sum"] += event["entropy_max"]
            flow["entropy_max"] = max(flow["entropy_max"], event["entropy_max"])
            flow["packet_length"] += len(packet)
            flow["observed_at"] = event["observed_at"]

    async def refresh_socket_owners(self):
        while True:
            try:
                rows, local_ips = await asyncio.to_thread(self.read_socket_snapshot)
                self.attributor.replace(rows, local_ips=local_ips)
                self._last_refresh_error = None
                await publish_status(
                    self.producer.client, "network_sensor", state="running",
                    socket_count=self.attributor.socket_count,
                    interface=self.interface, mode=get_mode(),
                )
            except Exception as exc:
                self.attributor.replace([])
                message = f"{type(exc).__name__}: {exc}"
                if message != self._last_refresh_error:
                    print(f"[-] PTAH Network Sensor socket-owner refresh failed: {message}")
                    self._last_refresh_error = message
                await publish_status(
                    self.producer.client, "network_sensor", state="degraded",
                    socket_count=self.attributor.socket_count, mode=get_mode(),
                )
            await asyncio.sleep(self.refresh_interval)

    async def publish_flows(self):
        last_report = time.monotonic()
        while True:
            await asyncio.sleep(self.publish_interval)
            with self._flow_lock:
                flows, self._flows = list(self._flows.values()), {}
                dropped, self._window_drops = self._window_drops, 0
                packets, attributed = self.packet_count, self.attributed_count
            for flow in flows:
                count = max(1, int(flow.pop("packet_count", 1)))
                entropy_sum = float(flow.pop("entropy_sum", 0.0))
                flow["entropy_avg"] = round(entropy_sum / count, 4)
                flow["packet_count"] = count
            try:
                await self.producer.send_events("telemetry:network", flows)
            except Exception as exc:
                print(f"[-] PTAH Network Sensor batch write failed: {exc}")
            if dropped:
                print(f"[-] PTAH Network Sensor: dropped {dropped} packets at the per-window flow cap.")
            if time.monotonic() - last_report >= 10:
                last_report = time.monotonic()
                ratio = (100.0 * attributed / packets) if packets else 0.0
                print(
                    f"[+] PTAH Network Sensor: {packets} packets seen; "
                    f"{ratio:.1f}% attributed; {len(flows)} flow summaries sent."
                )
                await publish_status(
                    self.producer.client, "network_sensor", state="running",
                    packets_seen=packets, attributed_packets=attributed,
                    last_window_flows=len(flows), flow_cap_drops=dropped,
                    mode=get_mode(),
                )

    def start_sniffing(self):
        print(f"[*] PTAH: Network Sensor started (listening on interface: {self.interface})...")
        sniff(iface=self.interface, prn=self.process_packet, store=False)

    async def run(self):
        await self.producer.connect()
        self.loop = asyncio.get_running_loop()
        executor = ThreadPoolExecutor(max_workers=1)
        socket_task = asyncio.create_task(self.refresh_socket_owners())
        publish_task = asyncio.create_task(self.publish_flows())
        try:
            await self.loop.run_in_executor(executor, self.start_sniffing)
        finally:
            socket_task.cancel()
            publish_task.cancel()
            await asyncio.gather(socket_task, publish_task, return_exceptions=True)
            executor.shutdown(wait=False, cancel_futures=True)
            await self.producer.close()


if __name__ == "__main__":
    try:
        get_mode()
        target_interface = os.environ.get("PTAH_INTERFACE") or str(conf.iface)
        print(f"[*] PTAH Network Sensor: Using interface '{target_interface}'. Set PTAH_INTERFACE to override.")
        asyncio.run(NetworkSensor(interface=target_interface).run())
    except KeyboardInterrupt:
        print("\n[-] PTAH: Shutting down the Network Sensor.")
    except ValueError as exc:
        print(f"[-] PTAH Network Sensor configuration error: {exc}", file=sys.stderr)
