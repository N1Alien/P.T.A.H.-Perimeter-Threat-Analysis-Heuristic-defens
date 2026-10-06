"""Read-only compact PTAH health and model-progress view."""
from __future__ import annotations

import time

import redis


COMPONENTS = ("network_sensor", "process_sensor", "core", "feature_processor", "deep_engine", "graph")
STREAMS = (
    "telemetry:network", "telemetry:processes", "telemetry:features",
    "ml:features_window", "alerts:behavioral", "alerts:anomalies",
)


def main():
    client = redis.Redis(host="localhost", port=6379, decode_responses=True, socket_connect_timeout=2)
    try:
        client.ping()
    except redis.RedisError as exc:
        print(f"PTAH broker: unavailable ({exc})")
        return 1

    print("PTAH status (read-only)")
    for component in COMPONENTS:
        state = client.hgetall(f"ptah:status:{component}")
        if not state:
            print(f"{component}: no status published")
            continue
        try:
            age = max(0, int(time.time() - float(state.get("updated_at", 0))))
        except (TypeError, ValueError):
            age = -1
        freshness = "fresh" if 0 <= age <= 15 else "stale"
        parts = [f"state={state.get('state', 'unknown')}", f"age={age}s ({freshness})"]
        for key in ("mode", "device", "model_ready", "sample_count", "train_threshold",
                    "skipped_samples", "packets_seen", "attributed_packets",
                    "attribution_percent", "window_count", "latest_groups",
                    "socket_count", "interface", "processes_reported", "nodes", "edges",
                    "dropped_topology_updates"):
            if key in state:
                parts.append(f"{key}={state[key]}")
        print(f"{component}: " + ", ".join(parts))

    print("Redis stream lengths:")
    for stream in STREAMS:
        try:
            print(f"  {stream}: {client.xlen(stream)}")
        except redis.RedisError:
            print(f"  {stream}: unavailable")
    client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
