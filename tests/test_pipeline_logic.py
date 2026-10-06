import os
import unittest
from unittest.mock import patch

from analyzer.behavior_rules import evaluate_behavior
from analyzer.core import correlate_network_event
from analyzer.feature_processor import aggregate_features
from shared.broker import RedisStreamProducer


class PipelineLogicTests(unittest.TestCase):
    def test_network_event_matches_fresh_process_metrics_by_pid_and_start_time(self):
        process = {
            "name": "browser",
            "cpu": 12.5,
            "memory": 3.0,
            "threads": 18,
            "process_create_time": 100.0,
            "observed_at": 105.0,
        }
        result = correlate_network_event({
            "process_pid": 42,
            "process_name": "browser",
            "process_create_time": 100.0,
            "attribution": "socket_5_tuple",
            "attribution_confidence": "high",
            "packet_count": 4,
            "payload_bytes": 900,
            "entropy_max": 6.1,
            "observed_at": 106.0,
        }, {"42": process}, now=106.0)
        self.assertEqual(result["source_process"], "browser")
        self.assertEqual(result["process_pid"], 42)
        self.assertEqual(result["process_cpu_usage"], 12.5)
        self.assertTrue(result["process_metrics_fresh"])

    def test_pid_reuse_does_not_reuse_old_process_metrics(self):
        result = correlate_network_event({
            "process_pid": 42,
            "process_name": "new-process",
            "process_create_time": 200.0,
            "attribution": "socket_5_tuple",
            "attribution_confidence": "high",
        }, {"42": {
            "name": "old-process", "cpu": 99, "memory": 40, "threads": 9,
            "process_create_time": 100.0, "observed_at": 100.0,
        }}, now=101.0)
        self.assertEqual(result["source_process"], "new-process")
        self.assertFalse(result["process_metrics_fresh"])
        self.assertEqual(result["process_cpu_usage"], 0)

    def test_unattributed_event_never_receives_an_unrelated_process(self):
        result = correlate_network_event({
            "process_pid": None,
            "attribution": "no_socket_match",
        }, {"42": {"name": "busy-process", "cpu": 100}}, now=10)
        self.assertEqual(result["source_process"], "UNATTRIBUTED_NETWORK_TRAFFIC")
        self.assertEqual(result["process_pid"], 0)

    def test_aggregation_sums_flows_and_counts_remote_destinations(self):
        events = [
            {"source_process": "browser", "process_pid": 42, "attribution": "socket_5_tuple",
             "attribution_confidence": "high",
             "packet_count": 2, "payload_bytes": 300, "network_entropy": 4.0,
             "network_entropy_avg": 3.0, "destination_ip": "198.51.100.1", "destination_port": 443},
            {"source_process": "browser", "process_pid": 42, "attribution": "socket_5_tuple",
             "attribution_confidence": "high",
             "packet_count": 3, "payload_bytes": 700, "network_entropy": 6.0,
             "network_entropy_avg": 5.0, "destination_ip": "198.51.100.2", "destination_port": 8443},
        ]
        [result] = aggregate_features(events)
        self.assertEqual(result["packet_count"], 5)
        self.assertEqual(result["bytes_sum"], 1000)
        self.assertEqual(result["remote_host_count"], 2)
        self.assertEqual(result["remote_port_count"], 2)
        self.assertEqual(result["entropy_max"], 6.0)
        self.assertTrue(result["model_eligible"])

    def test_model_excludes_stale_process_metrics(self):
        [result] = aggregate_features([{
            "source_process": "browser", "process_pid": 42,
            "attribution": "socket_5_tuple", "process_metrics_fresh": "false",
            "packet_count": 2, "payload_bytes": 200,
        }])
        self.assertFalse(result["model_eligible"])
        self.assertFalse(result["process_metrics_fresh"])

    def test_entropy_alone_does_not_raise_a_finding(self):
        with patch.dict(os.environ, {
            "PTAH_RULE_BYTES_PER_WINDOW": "10000",
            "PTAH_RULE_PACKETS_PER_WINDOW": "100",
            "PTAH_RULE_REMOTE_PORTS_PER_WINDOW": "10",
            "PTAH_RULE_ENTROPY_BYTES_PER_WINDOW": "1000",
        }, clear=False):
            findings = evaluate_behavior({
                "process_name": "browser", "packet_count": 20, "bytes_sum": 2000,
                "entropy_max": 7.99, "remote_port_count": 1,
            }, mode="observe")
        self.assertEqual(findings, [])

    def test_behavior_signal_requires_manual_review_and_never_executes(self):
        with patch.dict(os.environ, {
            "PTAH_RULE_BYTES_PER_WINDOW": "10000",
            "PTAH_RULE_PACKETS_PER_WINDOW": "100",
            "PTAH_RULE_REMOTE_PORTS_PER_WINDOW": "10",
            "PTAH_RULE_ENTROPY_BYTES_PER_WINDOW": "1000",
        }, clear=False):
            [finding] = evaluate_behavior({
            "process_name": "browser", "process_pid": 42,
            "attribution": "socket_5_tuple", "attribution_confidence": "high", "packet_count": 20,
            "bytes_sum": 12000, "remote_port_count": 1, "direction": "outbound",
            }, mode="observe")
        self.assertTrue(finding["approval_required"])
        self.assertEqual(finding["response_state"], "pending_manual_review")
        self.assertIn("manually", finding["recommended_response"])

    def test_non_observe_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            evaluate_behavior({}, mode="enforce")

    def test_redis_stream_fields_are_flat_strings(self):
        fields = RedisStreamProducer.flatten_event({
            "enabled": True, "evidence": {"bytes": 12}, "samples": [1, 2], "missing": None,
        })
        self.assertEqual(fields["enabled"], "True")
        self.assertEqual(fields["evidence"], '{"bytes":12}')
        self.assertEqual(fields["samples"], "[1,2]")
        self.assertNotIn("missing", fields)


if __name__ == "__main__":
    unittest.main()
