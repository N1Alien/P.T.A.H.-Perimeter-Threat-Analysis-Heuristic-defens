import json
import redis.asyncio as aioredis

class RedisStreamProducer:
    def __init__(self, host='localhost', port=6379):
        self.host = host
        self.port = port
        self.client = None

    async def connect(self):
        """Inicjalizuje asynchroniczne połączenie z Redisem."""
        self.client = await aioredis.Redis(host=self.host, port=self.port, decode_responses=True)
        print("[+] Connected to the PTAH broker (Redis).")

    @staticmethod
    def flatten_event(event_data: dict) -> dict:
        """Convert nested values into Redis Stream-compatible strings."""
        flattened_data = {}
        for key, value in event_data.items():
            if value is None:
                continue
            if isinstance(value, (dict, list, tuple)):
                flattened_data[key] = json.dumps(value, separators=(",", ":"))
            else:
                flattened_data[key] = str(value)
        return flattened_data

    async def send_event(self, stream_name: str, event_data: dict):
        """Send one bounded event to a Redis Stream."""
        if not self.client:
            raise RuntimeError("The broker is not connected! Call connect() first.")
        await self.client.xadd(
            stream_name, self.flatten_event(event_data), maxlen=20000, approximate=True
        )

    async def send_events(self, stream_name: str, events: list[dict]):
        """Batch-write events to bound round trips under busy network traffic."""
        if not self.client:
            raise RuntimeError("The broker is not connected! Call connect() first.")
        if not events:
            return
        pipeline = self.client.pipeline(transaction=False)
        for event in events:
            pipeline.xadd(
                stream_name, self.flatten_event(event), maxlen=20000, approximate=True
            )
        await pipeline.execute()

    async def close(self):
        """Bezpieczne zamykanie połączenia."""
        if self.client:
            await self.client.aclose()
            print("[-] Disconnected from the PTAH broker.")
