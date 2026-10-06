import unittest

from sensors.socket_attribution import SocketAttributor, UNATTRIBUTED


def socket(protocol, pid, name, local, remote=(), created=100.0):
    return {
        "protocol": protocol,
        "pid": pid,
        "process_name": name,
        "process_create_time": created,
        "local_addr": local,
        "remote_addr": remote,
    }


class SocketAttributionTests(unittest.TestCase):
    def setUp(self):
        self.attributor = SocketAttributor()

    def test_exact_outbound_and_inbound_tcp_tuple(self):
        self.attributor.replace([
            socket("TCP", 42, "browser", ("192.0.2.10", 51000), ("198.51.100.8", 443)),
        ])
        outbound = self.attributor.attribute("TCP", "192.0.2.10", 51000, "198.51.100.8", 443)
        inbound = self.attributor.attribute("TCP", "198.51.100.8", 443, "192.0.2.10", 51000)
        self.assertEqual(outbound["pid"], 42)
        self.assertEqual(outbound["direction"], "outbound")
        self.assertEqual(outbound["attribution_confidence"], "high")
        self.assertEqual(inbound["pid"], 42)
        self.assertEqual(inbound["direction"], "inbound")

    def test_ambiguous_owner_is_not_guessed(self):
        self.attributor.replace([
            socket("UDP", 10, "resolver-a", ("0.0.0.0", 53000)),
            socket("UDP", 11, "resolver-b", ("0.0.0.0", 53000)),
        ], local_ips={"192.0.2.10"})
        result = self.attributor.attribute("UDP", "192.0.2.10", 53000, "198.51.100.8", 53)
        self.assertIsNone(result["pid"])
        self.assertEqual(result["process_name"], UNATTRIBUTED)
        self.assertEqual(result["attribution"], "ambiguous_udp_socket")

    def test_wildcard_udp_listener_matches_local_destination_not_remote_source(self):
        self.attributor.replace([
            socket("UDP", 53, "dns-service", ("0.0.0.0", 53)),
        ], local_ips={"192.0.2.10"})
        inbound = self.attributor.attribute("UDP", "198.51.100.8", 40000, "192.0.2.10", 53)
        outbound = self.attributor.attribute("UDP", "198.51.100.8", 53, "203.0.113.5", 50000)
        self.assertEqual(inbound["pid"], 53)
        self.assertEqual(inbound["direction"], "inbound")
        self.assertIsNone(outbound["pid"])

    def test_udp_unique_local_socket_has_low_confidence(self):
        self.attributor.replace([socket("UDP", 24, "ntp-client", ("192.0.2.10", 45000))])
        result = self.attributor.attribute("UDP", "192.0.2.10", 45000, "198.51.100.2", 123)
        self.assertEqual(result["pid"], 24)
        self.assertEqual(result["attribution_confidence"], "low")

    def test_unknown_packet_remains_unattributed_and_index_does_not_mutate(self):
        self.attributor.replace([socket("TCP", 42, "browser", ("192.0.2.10", 51000))])
        original_count = len(self.attributor.local[("TCP", "192.0.2.10", 51000)])
        result = self.attributor.attribute("TCP", "203.0.113.1", 40, "198.51.100.8", 443)
        self.assertEqual(result["process_name"], UNATTRIBUTED)
        self.attributor.attribute("TCP", "192.0.2.10", 51000, "198.51.100.8", 443)
        self.assertEqual(len(self.attributor.local[("TCP", "192.0.2.10", 51000)]), original_count)


if __name__ == "__main__":
    unittest.main()
