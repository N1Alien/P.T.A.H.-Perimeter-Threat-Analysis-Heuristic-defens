"""Process-aware anomaly scoring with a visible, Redis-backed training state."""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import sys
import time

import torch
import torch.nn as nn
import torch.optim as optim
import redis.asyncio as aioredis

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared.config import get_mode, get_positive_int
from shared.broker import RedisStreamProducer
from shared.status import publish_status


class PtahAutoencoder(nn.Module):
    def __init__(self, input_dim=8):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 16), nn.ReLU(),
            nn.Linear(16, 4), nn.ReLU(),
            nn.Linear(4, 2),
        )
        self.decoder = nn.Sequential(
            nn.Linear(2, 4), nn.ReLU(),
            nn.Linear(4, 16), nn.ReLU(),
            nn.Linear(16, input_dim),
        )

    def forward(self, features):
        return self.decoder(self.encoder(features))


def is_true(value) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


class PtahDeepEngine:
    def __init__(self, broker_host="localhost", broker_port=6379, train_threshold=500):
        self.host = broker_host
        self.port = broker_port
        self.train_threshold = train_threshold
        self.client = None
        self.mode = "observe"
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = PtahAutoencoder(input_dim=8).to(self.device)
        self.optimizer = optim.Adam(self.model.parameters(), lr=0.005)
        self.criterion = nn.MSELoss()
        self.is_trained = False
        self.collected_samples = []
        self.skipped_samples = 0
        self.anomaly_threshold = 0.05
        self.mean = None
        self.std = None
        self.last_status = 0.0

    async def connect(self):
        self.client = await aioredis.Redis(host=self.host, port=self.port, decode_responses=True)
        print(f"[+] PTAH DEEP ENGINE: Connected to data broker on {self.device.type.upper()} device.")
        await self.publish_state("collecting_baseline")

    async def publish_state(self, state):
        await publish_status(
            self.client, "deep_engine", state=state, mode=self.mode,
            device=self.device.type, sample_count=len(self.collected_samples),
            train_threshold=self.train_threshold, skipped_samples=self.skipped_samples,
            model_ready=self.is_trained,
            anomaly_threshold=f"{self.anomaly_threshold:.6f}" if self.is_trained else None,
        )
        self.last_status = time.monotonic()

    @staticmethod
    def extract_features(payload):
        values = [
            float(payload.get("packet_count", 0)),
            float(payload.get("bytes_sum", 0)),
            float(payload.get("entropy_max", 0.0)),
            float(payload.get("entropy_avg", 0.0)),
            float(payload.get("cpu_avg", 0.0)),
            float(payload.get("cpu_max", 0.0)),
            float(payload.get("mem_avg", 0.0)),
            float(payload.get("threads_max", 1)),
        ]
        if not all(math.isfinite(value) for value in values):
            raise ValueError("Feature vector contains a non-finite value.")
        return values

    def train_model(self):
        if len(self.collected_samples) < self.train_threshold:
            raise RuntimeError("Refusing to train before the configured baseline is complete.")
        X = torch.tensor(self.collected_samples, dtype=torch.float32, device=self.device)
        self.mean = X.mean(dim=0, keepdim=True)
        self.std = X.std(dim=0, keepdim=True, unbiased=False).clamp_min(1e-6)
        X_scaled = (X - self.mean) / self.std

        self.model.train()
        for _ in range(200):
            self.optimizer.zero_grad(set_to_none=True)
            outputs = self.model(X_scaled)
            loss = self.criterion(outputs, X_scaled)
            loss.backward()
            self.optimizer.step()

        self.model.eval()
        with torch.no_grad():
            baseline_losses = torch.mean((self.model(X_scaled) - X_scaled) ** 2, dim=1)
            self.anomaly_threshold = float((baseline_losses.max() * 1.5).item())
        self.is_trained = True

    async def run(self):
        self.mode = get_mode()
        await self.connect()
        last_id = "$"
        print(f"[*] PTAH DEEP ENGINE: Collecting up to {self.train_threshold} process-attributed baseline windows.")
        while True:
            try:
                events = await self.client.xread({"ml:features_window": last_id}, count=100, block=1000)
                if not events:
                    if time.monotonic() - self.last_status >= 10:
                        await self.publish_state("model_ready" if self.is_trained else "waiting_for_process_traffic")
                    continue

                for _, messages in events:
                    for msg_id, payload in messages:
                        last_id = msg_id
                        eligible = is_true(payload.get("model_eligible", "false"))
                        if not eligible:
                            self.skipped_samples += 1
                            continue
                        try:
                            features = self.extract_features(payload)
                        except (TypeError, ValueError):
                            self.skipped_samples += 1
                            continue

                        process_name = payload.get("process_name", "UNKNOWN_PROCESS")
                        if not self.is_trained:
                            self.collected_samples.append(features)
                            sample_count = len(self.collected_samples)
                            if sample_count == 1 or sample_count % 25 == 0:
                                print(
                                    f"[*] PTAH DEEP ENGINE: Baseline {sample_count}/"
                                    f"{self.train_threshold} process windows."
                                )
                                await self.publish_state("collecting_baseline")
                            if sample_count >= self.train_threshold:
                                await self.publish_state("training")
                                await asyncio.to_thread(self.train_model)
                                print(
                                    "[++++] PTAH DEEP ENGINE: Model trained. "
                                    "PTAH remains in continuous observe mode."
                                )
                                await self.publish_state("model_ready")
                            continue

                        self.model.eval()
                        with torch.no_grad():
                            sample = torch.tensor([features], dtype=torch.float32, device=self.device)
                            scaled = (sample - self.mean) / self.std
                            reconstruction = self.model(scaled)
                            score = float(self.criterion(reconstruction, scaled).item())
                        if score > self.anomaly_threshold:
                            identity = (
                                f"model:{payload.get('process_pid') or process_name}:"
                                f"{payload.get('process_create_time', 0)}"
                            )
                            dedupe_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()
                            first_in_cooldown = await self.client.set(
                                f"ptah:model-dedupe:{dedupe_id}", "1", ex=300, nx=True
                            )
                            if not first_in_cooldown:
                                continue
                            alert = {
                                "process_name": process_name,
                                "process_pid": payload.get("process_pid", 0),
                                "process_create_time": payload.get("process_create_time", 0),
                                "engine": "pytorch_autoencoder",
                                "reconstruction_loss": round(score, 6),
                                "threshold": round(self.anomaly_threshold, 6),
                                "attribution": payload.get("attribution", "unknown"),
                                "attribution_confidence": payload.get("attribution_confidence", "none"),
                                "response_state": "pending_manual_review",
                                "approval_required": True,
                                "recommended_response": "Review the process and evidence; decide any response manually.",
                                "evidence": json.dumps({
                                    key: payload.get(key) for key in (
                                        "packet_count", "bytes_sum", "entropy_max", "entropy_avg",
                                        "cpu_avg", "cpu_max", "mem_avg", "threads_max",
                                        "remote_host_count", "remote_port_count", "destination_sample",
                                    )
                                }, separators=(",", ":")),
                                "mode": self.mode,
                            }
                            print(f"[!] PTAH MODEL SIGNAL: {process_name} requires manual review.")
                            await self.client.xadd(
                                "alerts:anomalies", RedisStreamProducer.flatten_event(alert),
                                maxlen=5000, approximate=True
                            )
                if time.monotonic() - self.last_status >= 10:
                    await self.publish_state("model_ready" if self.is_trained else "collecting_baseline")
            except Exception as exc:
                print(f"[-] PTAH DEEP ENGINE ERROR: {type(exc).__name__}: {exc}")
                await publish_status(self.client, "deep_engine", state="degraded", mode=self.mode)
                await asyncio.sleep(1)


if __name__ == "__main__":
    try:
        threshold = get_positive_int("PTAH_TRAIN_THRESHOLD", 500, minimum=30)
        get_mode()
        asyncio.run(PtahDeepEngine(train_threshold=threshold).run())
    except KeyboardInterrupt:
        print("\n[-] PTAH DEEP ENGINE: Terminating process.")
    except ValueError as exc:
        print(f"[-] PTAH DEEP ENGINE configuration error: {exc}", file=sys.stderr)
