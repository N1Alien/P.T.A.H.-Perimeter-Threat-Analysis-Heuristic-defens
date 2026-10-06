import asyncio
from shared.broker import RedisStreamProducer

async def main():
    # This optional smoke script writes one synthetic event to local Redis.
    producer = RedisStreamProducer()
    await producer.connect()

    # Symulacja danych testowych
    test_alert = {
        "sensor_type": "initial_test",
        "message": "PTAH engine ready",
        "metrics": {"cpu_cores": 4, "gpu": "synthetic-demo-value"}
    }

    print("[*] Sending test event to telemetry:test...")
    await producer.send_event("telemetry:test", test_alert)
    await producer.close()
    print("[+] Test event sent successfully.")

if __name__ == "__main__":
    asyncio.run(main())
