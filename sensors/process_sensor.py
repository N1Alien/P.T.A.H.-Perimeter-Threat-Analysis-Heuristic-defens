import sys
import os
import asyncio
import time
import psutil

# Importujemy naszego asynchronicznego brokera
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared.broker import RedisStreamProducer
from shared.config import get_mode
from shared.status import publish_status

class ProcessSensor:
    def __init__(self, broker_host="localhost", broker_port=6379, interval=2.0):
        self.producer = RedisStreamProducer(host=broker_host, port=broker_port)
        self.interval = interval  # How often to scan the system in seconds

    async def run(self):
        await self.producer.connect()
        print(f"[*] PTAH: Process Sensor started (scanning every {self.interval}s)...")
        last_status = time.monotonic()
        await publish_status(
            self.producer.client, "process_sensor", state="running",
            scan_interval=self.interval, mode=get_mode(),
        )

        while True:
            try:
                process_count = 0
                # Iterujemy przez wszystkie uruchomione procesy w systemie Linux
                for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'num_threads', 'create_time']):
                    try:
                        # Pobieramy szczegółowe metadane o procesie
                        proc_info = proc.info

                        # Ignorujemy procesy systemowe o zerowym zużyciu, żeby nie zapychać bazy
                        if proc_info['cpu_percent'] == 0.0 and proc_info['memory_percent'] < 0.1:
                            continue

                        process_event = {
                            "pid": proc_info['pid'],
                            "name": proc_info['name'],
                            "user": proc_info['username'],
                            "cpu_percent": proc_info['cpu_percent'],
                            "memory_percent": round(proc_info['memory_percent'], 2),
                            "num_threads": proc_info['num_threads'],
                            "process_create_time": proc_info.get('create_time'),
                            "observed_at": time.time(),
                        }

                        # Wysyłamy dane o procesie do nowego strumienia w Redis
                        await self.producer.send_event("telemetry:processes", process_event)
                        process_count += 1

                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        # Processes in Linux appear and disappear rapidly, ignore those that have vanished in flight
                        continue

            except Exception as e:
                print(f"[-] Process sensor error: {e}")
                await publish_status(self.producer.client, "process_sensor", state="degraded", mode=get_mode())

            if time.monotonic() - last_status >= 10:
                last_status = time.monotonic()
                await publish_status(
                    self.producer.client, "process_sensor", state="running",
                    processes_reported=process_count, scan_interval=self.interval,
                    mode=get_mode(),
                )

            # Rest before the next scan cycle
            await asyncio.sleep(self.interval)

if __name__ == "__main__":
    sensor = ProcessSensor(interval=1.0) # Skanuj system co 1 sekundę
    try:
        asyncio.run(sensor.run())
    except KeyboardInterrupt:
        print("\n[-] PTAH: Shutting down the Process Sensor.")
