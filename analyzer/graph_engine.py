import sys
import os
import asyncio
import networkx as nx
import redis.asyncio as aioredis
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class PtahGraphEngine:
    def __init__(self, broker_host="localhost", broker_port=6379):
        self.host = broker_host
        self.port = broker_port
        self.client = None
        self.max_nodes = 5000
        self.max_edges = 10000
        self.last_report = 0.0
        self.dropped_topology_updates = 0
        self.G = nx.DiGraph()
        print("[*] PTAH GRAPH ENGINE: InMemory Directed Graph initialized.")

    async def connect(self):
        self.client = await aioredis.Redis(host=self.host, port=self.port, decode_responses=True)
        print("[+] PTAH GRAPH ENGINE: Connected to data broker.")

    def update_topology(self, payload):
        """Updates the graph nodes and edges based on real-time features stream."""
        proc_name = payload.get("source_process", "UNKNOWN")
        dst_ip = payload.get("remote_ip") or payload.get("destination_ip", "0.0.0.0")
        process_pid = int(payload.get("process_pid", 0) or 0)
        entropy = float(payload.get("network_entropy", 0.0))
        now = time.monotonic()

        # 1. Ensure nodes exist with their behavioral properties
        process_node = f"PROCESS:{process_pid}:{proc_name}" if process_pid else f"PROCESS:UNKNOWN:{proc_name}"
        if not self.G.has_node(process_node):
            self._make_node_room()
            self.G.add_node(
                process_node, label=proc_name, pid=process_pid, type="PROCESS",
                cpu=float(payload.get("process_cpu_usage", 0)),
                attribution=payload.get("attribution", "unknown"),
                last_seen=now,
            )
        else:
            # Dynamically update process node metrics
            self.G.nodes[process_node]["cpu"] = float(payload.get("process_cpu_usage", 0))
            self.G.nodes[process_node]["last_seen"] = now

        if not self.G.has_node(dst_ip):
            self._make_node_room()
            self.G.add_node(dst_ip, type="IP")
        self.G.nodes[dst_ip]["last_seen"] = now

        # 2. Establish or update directed communication edge
        if not self.G.has_edge(process_node, dst_ip):
            if self.G.number_of_edges() >= self.max_edges:
                self._remove_oldest_edge()
            self.G.add_edge(
                process_node, dst_ip, weight=int(payload.get("packet_count", 1) or 1),
                max_entropy=entropy, direction=payload.get("direction", "unknown"), last_seen=now,
            )
        else:
            # If relationship already exists, increase flow weight and monitor peak entropy
            self.G[process_node][dst_ip]["weight"] += int(payload.get("packet_count", 1) or 1)
            if entropy > self.G[process_node][dst_ip]["max_entropy"]:
                self.G[process_node][dst_ip]["max_entropy"] = entropy
            self.G[process_node][dst_ip]["last_seen"] = now

    def _make_node_room(self):
        if self.G.number_of_nodes() < self.max_nodes:
            return
        oldest = min(self.G.nodes, key=lambda node: self.G.nodes[node].get("last_seen", 0))
        self.G.remove_node(oldest)
        self.dropped_topology_updates += 1

    def _remove_oldest_edge(self):
        if not self.G.edges:
            return
        edge = min(self.G.edges, key=lambda item: self.G.edges[item].get("last_seen", 0))
        self.G.remove_edge(*edge)
        self.dropped_topology_updates += 1

    def inspect_graph_metrics(self):
        """Analyzes graph properties to evaluate current infrastructure complexity."""
        num_nodes = self.G.number_of_nodes()
        num_edges = self.G.number_of_edges()

        # Calculate degree centrality to identify highly active hub processes
        centrality = nx.degree_centrality(self.G)
        top_hub = max(centrality, key=centrality.get) if centrality else "None"

        print(f"[+] PTAH GRAPH ENGINE: Graph active topology -> Nodes: {num_nodes} | Edges: {num_edges} | Primary Hub: '{top_hub}'")

    async def run(self):
        await self.connect()
        self.last_report = time.monotonic()
        last_id = '$'

        while True:
            try:
                # Read fresh correlated features from the core stream
                events = await self.client.xread({"telemetry:features": last_id}, count=50, block=1000)
                if not events:
                    if time.monotonic() - self.last_report >= 15:
                        self.last_report = time.monotonic()
                        await self.client.hset("ptah:status:graph", mapping={
                            "state": "waiting_for_features", "mode": "observe",
                            "nodes": self.G.number_of_nodes(), "edges": self.G.number_of_edges(),
                            "dropped_topology_updates": self.dropped_topology_updates,
                            "updated_at": f"{time.time():.3f}",
                        })
                    continue

                for stream, messages in events:
                    for msg_id, payload in messages:
                        last_id = msg_id
                        self.update_topology(payload)

                if time.monotonic() - self.last_report >= 15:
                    self.last_report = time.monotonic()
                    self.inspect_graph_metrics()
                    await self.client.hset("ptah:status:graph", mapping={
                        "state": "running", "mode": "observe",
                        "nodes": self.G.number_of_nodes(), "edges": self.G.number_of_edges(),
                        "dropped_topology_updates": self.dropped_topology_updates,
                        "updated_at": f"{time.time():.3f}",
                    })

            except Exception as e:
                print(f"[-] PTAH GRAPH ENGINE ERROR: {e}")
                await asyncio.sleep(1)

if __name__ == "__main__":
    engine = PtahGraphEngine()
    try:
        asyncio.run(engine.run())
    except KeyboardInterrupt:
        print("\n[-] PTAH GRAPH ENGINE: Terminating process.")
