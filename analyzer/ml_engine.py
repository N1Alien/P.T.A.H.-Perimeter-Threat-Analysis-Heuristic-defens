import sys
import os
import json
import asyncio
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import redis.asyncio as aioredis

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class PtahMLEngine:
    def __init__(self, broker_host="localhost", broker_port=6379, train_size=50):
        self.host = broker_host
        self.port = broker_port
        self.train_size = train_size # Ile okien potrzebujemy zebrać do wstępnego treningu
        self.client = None
        self.model = IsolationForest(contamination=0.02, random_state=42) # Szacujemy max 2% anomalii w tle
        self.is_trained = False
        self.training_data = []

    async def connect(self):
        self.client = await aioredis.Redis(host=self.host, port=self.port, decode_responses=True)
        print("[+] PTAH ML Engine: Connected to the broker.")

    def prepare_vector(self, payload):
        """Wyciąga cechy numeryczne ze zdarzenia w strumieniu."""
        return [
            int(payload.get("packet_count", 0)),
            int(payload.get("bytes_sum", 0)),
            float(payload.get("entropy_max", 0.0)),
            float(payload.get("entropy_avg", 0.0)),
            float(payload.get("cpu_avg", 0.0)),
            float(payload.get("cpu_max", 0.0)),
            float(payload.get("mem_avg", 0.0)),
            int(payload.get("threads_max", 1))
        ]

    async def run(self):
        await self.connect()
        print("[*] PTAH ML Engine: Listening for feature windows...")
        
        last_id = '$'
        
        while True:
            try:
                events = await self.client.xread({"ml:features_window": last_id}, count=10, block=1000)
                if not events:
                    continue
                    
                for stream, messages in events:
                    for msg_id, payload in messages:
                        last_id = msg_id
                        
                        process_name = payload.get("process_name")
                        features = self.prepare_vector(payload)
                        
                        # ETAP 1: Zbieranie danych do treningu (Budowa wzorca normalności)
                        if not self.is_trained:
                            self.training_data.append(features)
                            print(f"[*] PTAH ML Engine: Collecting profiling data ({len(self.training_data)}/{self.train_size}) from process: {process_name}")
                            
                            if len(self.training_data) >= self.train_size:
                                X_train = np.array(self.training_data)
                                self.model.fit(X_train)
                                self.is_trained = True
                                print("[++++] PTAH ML Engine: Model Successfully Trained! First line of defense is active.")
                        
                        # ETAP 2: Aktywna detekcja anomalii w czasie rzeczywistym
                        else:
                            X_test = np.array([features])
                            prediction = self.model.predict(X_test)[0] # 1 = norma, -1 = anomalia
                            
                            if prediction == -1:
                                score = self.model.score_samples(X_test)[0]
                                alert_event = {
                                    "process_name": process_name,
                                    "anomaly_score": round(float(score), 4),
                                    "trigger_metrics": json.dumps(payload)
                                }
                                print(f"[!!!] PTAH DETECTION: Anomalous behavior detected in process: {process_name}! Score: {score}")
                                # Sending alert to the dedicated defense channel
                                await self.client.xadd("alerts:anomalies", alert_event, maxlen=5000, approximate=True)
                                
            except Exception as e:
                print(f"[-] PTAH ML Engine Error: {e}")
                await asyncio.sleep(1)

if __name__ == "__main__":
    # Do celów szybkiego testu ustawiamy mały train_size=30 okien, na produkcji warto dać 200+
    engine = PtahMLEngine(train_size=30)
    try:
        asyncio.run(engine.run())
    except KeyboardInterrupt:
        print("\n[-] PTAH ML Engine: Shutting down.")
