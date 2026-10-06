import io
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from ptah_alert_window import display, safe_text


class AlertWindowTests(unittest.TestCase):
    def test_safe_text_removes_terminal_control_characters(self):
        self.assertEqual(safe_text("name\x1b[2J\nnext"), "name[2Jnext")

    def test_demo_alert_is_visibly_labeled_and_contains_no_control_codes(self):
        output = io.StringIO()
        with redirect_stdout(output):
            display({
                "demo": "true",
                "process_name": "sample\x1b[31m",
                "process_pid": "42424",
                "rule_id": "SYNTHETIC_RULE",
            })
        rendered = output.getvalue()
        self.assertIn("SIMULATED ALERT, NOT A REAL DETECTION", rendered)
        self.assertNotIn("\x1b", rendered)

    def test_demo_mode_does_not_connect_to_redis_or_record_decision(self):
        command_line = [
            "ptah_alert_window.py", "--demo", "--alert-json",
            '{"demo":"true","process_name":"sample","rule_id":"DEMO"}',
        ]
        with patch.object(sys, "argv", command_line), patch("builtins.input", return_value=""), \
                patch("ptah_alert_window.redis.Redis", side_effect=AssertionError("must not connect to Redis")), \
                redirect_stdout(io.StringIO()):
            from ptah_alert_window import main
            self.assertEqual(main(), 0)


if __name__ == "__main__":
    unittest.main()
