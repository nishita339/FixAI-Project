"""
Unit Test Suite — Phase 1: Security Event Harvesting (Brute-Force Detection)
=============================================================================
"""

import sys
import time
import unittest
from pathlib import Path

# Ensure paths
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security.event_monitor import EventMonitor, BruteForceAlert


class TestPhase1EventMonitor(unittest.TestCase):
    def setUp(self):
        self.alerts = []
        self.monitor = EventMonitor(
            window_seconds=60.0,
            threshold=5,
            cooldown_seconds=30.0,
            on_alert=lambda a: self.alerts.append(a),
        )

    def test_under_threshold_no_alert(self):
        """4 failed attempts from the same source should not trigger an alert."""
        source_ip = "192.168.1.100"
        for i in range(4):
            alert = self.monitor.record_failed_logon(
                source_ip=source_ip,
                target_username=f"user_{i}",
                timestamp=1000.0 + i,
            )
            self.assertIsNone(alert)
        self.assertEqual(len(self.alerts), 0)
        self.assertEqual(self.monitor.get_window_count(source_ip), 4)

    def test_threshold_breach_triggers_alert(self):
        """5 failed attempts within 60s must trigger a BruteForceAlert."""
        source_ip = "10.0.0.15"
        for i in range(4):
            self.assertIsNone(
                self.monitor.record_failed_logon(
                    source_ip=source_ip,
                    target_username="admin",
                    timestamp=1000.0 + (i * 2),
                )
            )

        # 5th attempt at t=1008s (within 8s of 1st attempt)
        alert = self.monitor.record_failed_logon(
            source_ip=source_ip,
            target_username="admin",
            timestamp=1008.0,
        )

        self.assertIsNotNone(alert)
        self.assertIsInstance(alert, BruteForceAlert)
        self.assertEqual(alert.source_ip, "10.0.0.15")
        self.assertEqual(alert.target_username, "admin")
        self.assertEqual(alert.attempt_count, 5)
        self.assertEqual(alert.time_window_seconds, 8.0)
        self.assertIn("10.0.0.15", alert.recommended_action)
        self.assertEqual(len(self.alerts), 1)

    def test_sliding_window_expiration(self):
        """Attempts older than 60 seconds must be evicted from the sliding window."""
        source_ip = "172.16.0.40"
        # 3 attempts at t=1000s
        for _ in range(3):
            self.monitor.record_failed_logon(source_ip=source_ip, timestamp=1000.0)

        # 2 attempts at t=1070s (70s later -> previous 3 attempts must be expired)
        for _ in range(2):
            self.monitor.record_failed_logon(source_ip=source_ip, timestamp=1070.0)

        # Count at t=1070s should only be 2, NOT 5
        self.assertEqual(self.monitor.get_window_count(source_ip), 2)
        self.assertEqual(len(self.alerts), 0)

    def test_multi_source_isolation(self):
        """Failed logons from different IP addresses must be tracked independently."""
        ip_a = "192.168.1.50"
        ip_b = "192.168.1.60"

        # 4 attempts from A
        for _ in range(4):
            self.monitor.record_failed_logon(source_ip=ip_a, timestamp=1000.0)

        # 4 attempts from B
        for _ in range(4):
            self.monitor.record_failed_logon(source_ip=ip_b, timestamp=1000.0)

        # Neither breached threshold 5
        self.assertEqual(len(self.alerts), 0)
        self.assertEqual(self.monitor.get_window_count(ip_a), 4)
        self.assertEqual(self.monitor.get_window_count(ip_b), 4)

        # 5th attempt from A triggers alert for A only
        alert_a = self.monitor.record_failed_logon(source_ip=ip_a, timestamp=1005.0)
        self.assertIsNotNone(alert_a)
        self.assertEqual(alert_a.source_ip, ip_a)
        self.assertEqual(len(self.alerts), 1)

    def test_cooldown_rate_limiting(self):
        """Subsequent failures during the cooldown period must not trigger duplicate alerts."""
        source_ip = "198.51.100.22"
        # 5 attempts trigger 1st alert
        for i in range(5):
            self.monitor.record_failed_logon(source_ip=source_ip, timestamp=1000.0 + i)
        self.assertEqual(len(self.alerts), 1)

        # 6th attempt within cooldown (30s) at t=1010s
        alert_6 = self.monitor.record_failed_logon(source_ip=source_ip, timestamp=1010.0)
        self.assertIsNone(alert_6)
        self.assertEqual(len(self.alerts), 1)


if __name__ == "__main__":
    unittest.main()
