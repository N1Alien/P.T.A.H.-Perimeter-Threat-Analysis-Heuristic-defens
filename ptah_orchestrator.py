"""Start and supervise PTAH's local monitoring components."""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import unicodedata
from collections import deque
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))
from analyzer.behavior_rules import evaluate_behavior
from shared.config import get_mode, get_positive_int

ROOT = Path(__file__).resolve().parent
PYTHON = ROOT / "venv" / "bin" / "python"


class PtahOrchestrator:
    def __init__(self) -> None:
        self.mode = get_mode()
        evaluate_behavior({}, mode=self.mode)  # validate rule settings before starting sensors
        get_positive_int("PTAH_TRAIN_THRESHOLD", 500, minimum=30)
        capture_value = os.environ.get("PTAH_CAPTURE", "1").strip()
        if capture_value not in {"0", "1"}:
            raise ValueError("PTAH_CAPTURE must be either 0 or 1.")
        self.capture_enabled = capture_value == "1"
        if not PYTHON.is_file():
            raise RuntimeError(f"Virtual environment not found: {PYTHON}. See README.md.")
        if shutil.which("docker") is None:
            raise RuntimeError("Docker is required to run the Redis broker.")
        self.processes: list[dict] = []
        self.stop_event = asyncio.Event()
        self.compose_started = False
        self.alert_client = None
        self.alert_stream_ids: dict[str, str] = {}
        self.alert_window_times: deque[float] = deque()
        self.alert_window_cooldowns: dict[str, float] = {}
        self.alert_window_limit = 3
        self.alert_windows_enabled = os.environ.get("PTAH_ALERT_WINDOWS", "1").strip() == "1"
        self.konsole = shutil.which("konsole")
        self.notify_send = shutil.which("notify-send")

    @staticmethod
    def safe_text(value, limit: int = 300) -> str:
        text = str(value)
        text = "".join(char for char in text if unicodedata.category(char) != "Cc")
        return text[:limit]

    async def start_alert_reader(self) -> None:
        import redis.asyncio as aioredis

        self.alert_client = aioredis.Redis(
            host="localhost", port=6379, decode_responses=True,
            socket_connect_timeout=2,
        )
        await self.alert_client.ping()
        # Read only alerts generated during this run; old Redis history stays available
        # to the explicit review command but does not reopen old popup windows.
        self.alert_stream_ids = {}
        for stream in ("alerts:behavioral", "alerts:anomalies"):
            latest = await self.alert_client.xrevrange(stream, count=1)
            self.alert_stream_ids[stream] = latest[0][0] if latest else "0-0"

    def print_alert(self, stream: str, alert_id: str, fields: dict[str, str]) -> None:
        process = self.safe_text(fields.get("process_name", "unknown process"), 120)
        pid = self.safe_text(fields.get("process_pid", "unknown"), 24)
        kind = self.safe_text(fields.get("rule_id", fields.get("engine", "behavioral signal")), 120)
        confidence = self.safe_text(fields.get("attribution_confidence", "unknown"), 32)
        reason = self.safe_text(fields.get("reason", fields.get("summary", kind)), 240)
        print("\n" + "!" * 72)
        print(f"PTAH ALERT — MANUAL REVIEW REQUIRED ({stream}, id {alert_id})")
        print(f"Process: {process} (PID {pid})")
        print(f"Signal: {reason}")
        print(f"Network attribution confidence: {confidence}")
        print("PTAH has taken no action. Review the evidence before deciding what to do.")
        print("!" * 72, flush=True)

    def launch_alert_surfaces(self, stream: str, alert_id: str, fields: dict[str, str]) -> None:
        process = self.safe_text(fields.get("process_name", "unknown process"), 120)
        pid = self.safe_text(fields.get("process_pid", "unknown"), 24)
        kind = self.safe_text(fields.get("rule_id", fields.get("engine", "PTAH signal")), 120)
        body = f"{process} (PID {pid}) — {kind}. Open PTAH alert window for details."

        if self.notify_send:
            try:
                subprocess.Popen(
                    [self.notify_send, "--app-name=PTAH", "--urgency=critical",
                     "PTAH: manual review required", body],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, start_new_session=True,
                )
            except OSError as exc:
                print(f"[!] PTAH desktop notification unavailable: {exc}")

        if not self.alert_windows_enabled:
            return
        if not self.konsole:
            print("[!] Konsole was not found; alert details remain in this terminal.")
            return

        now = time.monotonic()
        self.alert_window_times = deque(t for t in self.alert_window_times if now - t < 60)
        identity = (
            f"{fields.get('process_pid') or fields.get('process_name', 'unknown')}:"
            f"{fields.get('process_create_time', '')}"
        )
        if (now - self.alert_window_cooldowns.get(identity, 0) < 60
                or len(self.alert_window_times) >= self.alert_window_limit):
            print("[!] Popup window rate limit reached; details are shown above and in the notification.")
            return

        payload = {str(key): str(value) for key, value in fields.items()}
        payload.update({"alert_stream": stream, "alert_id": alert_id})
        try:
            subprocess.Popen(
                [self.konsole, "--separate", "-e", str(PYTHON),
                 str(ROOT / "ptah_alert_window.py"), "--alert-json", json.dumps(payload)],
                cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, start_new_session=True,
            )
            self.alert_window_times.append(now)
            self.alert_window_cooldowns[identity] = now
            print("[+] Sent the alert details to Konsole.", flush=True)
        except OSError as exc:
            print(f"[!] Could not open Konsole alert window: {exc}")

    async def read_alerts(self) -> None:
        if not self.alert_client:
            return
        events = await self.alert_client.xread(self.alert_stream_ids, count=20, block=250)
        for stream, messages in events:
            for alert_id, fields in messages:
                self.alert_stream_ids[stream] = alert_id
                self.print_alert(stream, alert_id, fields)
                self.launch_alert_surfaces(stream, alert_id, fields)

    async def start_redis(self) -> None:
        print("[*] Starting the PTAH Redis broker...")
        before = subprocess.run(
            ["docker", "compose", "ps", "--status", "running", "--quiet", "redis"],
            cwd=ROOT, text=True, capture_output=True,
        )
        if before.returncode:
            raise RuntimeError(before.stderr.strip() or "Could not inspect the PTAH Redis service.")
        redis_was_running = bool(before.stdout.strip())
        result = subprocess.run(
            ["docker", "compose", "up", "-d", "redis"], cwd=ROOT,
            text=True, capture_output=True,
        )
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "Docker Compose could not start Redis.")
        self.compose_started = not redis_was_running

        import redis
        client = redis.Redis(host="localhost", port=6379, socket_connect_timeout=1)
        deadline = asyncio.get_running_loop().time() + 45
        try:
            while asyncio.get_running_loop().time() < deadline:
                try:
                    if await asyncio.to_thread(client.ping):
                        print("[+] Redis broker is ready.")
                        return
                except Exception:
                    await asyncio.sleep(1)
            raise RuntimeError("Redis did not become ready within 45 seconds.")
        finally:
            client.close()

    def start_component(self, name: str, script: str, *, use_sudo: bool = False) -> None:
        command = [str(PYTHON), "-u", str(ROOT / script)]
        if use_sudo:
            command = ["sudo", "--preserve-env=PTAH_INTERFACE", *command]
        print(f"[*] Starting {name}...")
        proc = subprocess.Popen(
            command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, process_group=0,
        )
        os.set_blocking(proc.stdout.fileno(), False)
        self.processes.append({"name": name, "proc": proc, "reported": False})

    async def monitor(self) -> None:
        print("\nPTAH is running in passive monitoring mode. Press Ctrl+C to stop it.\n")
        while not self.stop_event.is_set():
            for entry in self.processes:
                proc = entry["proc"]
                try:
                    while True:
                        line = proc.stdout.readline()
                        if not line:
                            break
                        print(f"[{entry['name']}] {line.rstrip()}")
                except (BlockingIOError, OSError):
                    pass
                if proc.poll() is not None and not entry["reported"]:
                    entry["reported"] = True
                    print(f"[!] {entry['name']} exited with status {proc.returncode}; stopping the incomplete pipeline.")
                    self.stop_event.set()
            try:
                await self.read_alerts()
            except Exception as exc:
                print(f"[!] PTAH alert display could not read Redis alerts: {type(exc).__name__}: {exc}")
                await asyncio.sleep(1)
            await asyncio.sleep(0.1)

    async def shutdown(self) -> None:
        print("\n[*] Stopping PTAH components...")
        for entry in self.processes:
            proc = entry["proc"]
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        for entry in self.processes:
            proc = entry["proc"]
            if proc.poll() is None:
                try:
                    await asyncio.wait_for(asyncio.to_thread(proc.wait), timeout=5)
                except asyncio.TimeoutError:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    await asyncio.to_thread(proc.wait)
            if proc.stdout:
                proc.stdout.close()
        if self.compose_started:
            subprocess.run(["docker", "compose", "stop", "redis"], cwd=ROOT, check=False)
        if self.alert_client:
            await self.alert_client.aclose()
        print("[+] PTAH stopped. Other Python processes were left untouched.")

    async def run(self) -> None:
        print(f"[*] PTAH mode: {self.mode} (passive; no response actions are executed).")
        if self.capture_enabled:
            print("[*] Network capture needs elevated packet-capture permission.")
            subprocess.run(["sudo", "-v"], check=True)
        await self.start_redis()
        await self.start_alert_reader()
        if self.capture_enabled:
            self.start_component("SENSOR:NET", "sensors/network_sensor.py", use_sudo=True)
        else:
            print("[*] Packet capture disabled by PTAH_CAPTURE=0.")
        self.start_component("SENSOR:PROC", "sensors/process_sensor.py")
        self.start_component("CORE", "analyzer/core.py")
        self.start_component("FEATURES", "analyzer/feature_processor.py")
        self.start_component("DEEP_ENGINE", "analyzer/deep_engine.py")
        self.start_component("GRAPH", "analyzer/graph_engine.py")
        await self.monitor()


async def main() -> None:
    app = None
    try:
        app = PtahOrchestrator()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, app.stop_event.set)
        await app.run()
    except (RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"[-] PTAH could not start: {exc}", file=sys.stderr)
        if app:
            app.stop_event.set()
    finally:
        if app:
            await app.shutdown()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
