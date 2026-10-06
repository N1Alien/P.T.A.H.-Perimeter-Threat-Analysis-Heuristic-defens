"""Map captured IP packets to processes using cached OS socket ownership."""
from __future__ import annotations

import ipaddress
import threading
from collections import defaultdict


UNATTRIBUTED = "UNATTRIBUTED_NETWORK_TRAFFIC"


def normalize_ip(value: str) -> str:
    value = str(value or "").split("%", 1)[0]
    if not value:
        return ""
    try:
        parsed = ipaddress.ip_address(value)
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
            return str(parsed.ipv4_mapped)
        return parsed.compressed
    except ValueError:
        return value.lower()


class SocketAttributor:
    """Refreshable socket index; ambiguous matches stay explicitly unattributed."""

    def __init__(self) -> None:
        self.exact = defaultdict(list)
        self.remote = defaultdict(list)
        self.local = defaultdict(list)
        self.socket_count = 0
        self.local_ips = set()
        self._lock = threading.Lock()

    def replace(self, rows, local_ips=None) -> None:
        exact = defaultdict(list)
        remote = defaultdict(list)
        local = defaultdict(list)
        known_local_ips = {normalize_ip(address) for address in (local_ips or []) if address}
        count = 0
        for row in rows:
            protocol = str(row.get("protocol", "")).upper()
            if protocol not in {"TCP", "UDP"}:
                continue
            local_addr = row.get("local_addr") or ("", 0)
            remote_addr = row.get("remote_addr") or ("", 0)
            try:
                local_ip, local_port = normalize_ip(local_addr[0]), int(local_addr[1])
                remote_ip, remote_port = normalize_ip(remote_addr[0]), int(remote_addr[1]) if remote_addr[1] else 0
                pid = int(row["pid"])
            except (KeyError, TypeError, ValueError, IndexError):
                continue
            owner = {
                "pid": pid,
                "process_name": str(row.get("process_name") or "UNKNOWN_PROCESS"),
                "process_create_time": row.get("process_create_time"),
            }
            local_key = (protocol, local_ip, local_port)
            local[local_key].append(owner)
            if local_ip not in {"0.0.0.0", "::", ""}:
                known_local_ips.add(local_ip)
            if remote_ip and remote_port:
                exact[(protocol, local_ip, local_port, remote_ip, remote_port)].append(owner)
                remote[(protocol, local_port, remote_ip, remote_port)].append((local_ip, owner))
            count += 1
        with self._lock:
            self.exact, self.remote, self.local = exact, remote, local
            self.socket_count = count
            self.local_ips = known_local_ips

    @staticmethod
    def _unique_owner(rows):
        unique = {(row["pid"], row.get("process_create_time")): row for row in rows}
        if len(unique) != 1:
            return None
        return next(iter(unique.values()))

    def attribute(self, protocol, src_ip, src_port, dst_ip, dst_port) -> dict:
        with self._lock:
            return self._attribute(protocol, src_ip, src_port, dst_ip, dst_port)

    def _attribute(self, protocol, src_ip, src_port, dst_ip, dst_port) -> dict:
        protocol = str(protocol or "").upper()
        src_ip, dst_ip = normalize_ip(src_ip), normalize_ip(dst_ip)
        try:
            src_port, dst_port = int(src_port), int(dst_port)
        except (TypeError, ValueError):
            return self._unattributed()

        outbound_key = (protocol, src_ip, src_port, dst_ip, dst_port)
        inbound_key = (protocol, dst_ip, dst_port, src_ip, src_port)
        # Prefer exact established-connection matches, preserving direction.
        for rows, flow_direction in (
            (self.exact.get(outbound_key, []), "outbound"),
            (self.exact.get(inbound_key, []), "inbound"),
        ):
            owner = self._unique_owner(rows)
            if owner:
                return self._result(owner, "socket_5_tuple", "high", flow_direction)
            if rows:
                return self._unattributed("ambiguous_socket_match")

        # Wildcard-bound sockets are considered only with a matching remote tuple.
        wildcard_matches = (
            ((src_port, dst_ip, dst_port), "outbound"),
            ((dst_port, src_ip, src_port), "inbound"),
        )
        for (local_port, remote_ip, remote_port), flow_direction in wildcard_matches:
            rows = [
                owner for local_ip, owner in self.remote.get(
                    (protocol, local_port, remote_ip, remote_port), []
                ) if local_ip in {"0.0.0.0", "::"}
            ]
            owner = self._unique_owner(rows)
            if owner:
                return self._result(owner, "socket_5_tuple", "high", flow_direction)
            if rows:
                return self._unattributed("ambiguous_socket_match")

        if protocol == "UDP":
            local_candidates = []
            if src_ip in self.local_ips:
                source_rows = list(self.local.get((protocol, src_ip, src_port), []))
                source_rows += self.local.get((protocol, "0.0.0.0", src_port), [])
                source_rows += self.local.get((protocol, "::", src_port), [])
                local_candidates.append((source_rows, "outbound"))
            if dst_ip in self.local_ips:
                destination_rows = list(self.local.get((protocol, dst_ip, dst_port), []))
                destination_rows += self.local.get((protocol, "0.0.0.0", dst_port), [])
                destination_rows += self.local.get((protocol, "::", dst_port), [])
                local_candidates.append((destination_rows, "inbound"))
            for local_rows, flow_direction in local_candidates:
                owner = self._unique_owner(local_rows)
                if owner:
                    return self._result(owner, "udp_local_socket", "low", flow_direction)
                if local_rows:
                    return self._unattributed("ambiguous_udp_socket")

        # A listening TCP socket can identify the service for a new inbound
        # SYN, but cannot prove which accepted connection handled that packet.
        if protocol == "TCP":
            listeners = []
            if dst_ip in self.local_ips:
                listeners = list(self.local.get((protocol, dst_ip, dst_port), []))
                listeners += self.local.get((protocol, "0.0.0.0", dst_port), [])
                listeners += self.local.get((protocol, "::", dst_port), [])
            owner = self._unique_owner(listeners)
            if owner:
                return self._result(owner, "tcp_listener", "low", "inbound")
            if listeners:
                return self._unattributed("ambiguous_tcp_listener")

        return self._unattributed()

    @staticmethod
    def _result(owner, method, confidence, direction="unknown"):
        return {
            **owner,
            "attribution": method,
            "attribution_confidence": confidence,
            "direction": direction,
        }

    @staticmethod
    def _unattributed(reason="no_socket_match"):
        return {
            "pid": None,
            "process_name": UNATTRIBUTED,
            "process_create_time": None,
            "attribution": reason,
            "attribution_confidence": "none",
            "direction": "unknown",
        }
