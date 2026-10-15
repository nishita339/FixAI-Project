"""
FixAI Improvement #7 — Network Socket & C2 Beaconing Monitor Test Suite
========================================================================

Comprehensive tests for:
- Shannon entropy calculation on domain names
- Private / loopback IP classification
- NetworkConnection dataclass serialization
- C2BeaconAlert dataclass serialization
- Static connection inspection (C2 ports, LotL, tunnels, DGA)
- Temporal beaconing detection (low-jitter periodic callbacks)
- Beacon jitter threshold enforcement
- Alert cooldown / deduplication
- Immediate threat alerts for suspicious static indicators
- NLG narration for all C2 alert types
- AlertBridge integration via on_network_c2_alert callback
- Telemetry summary
"""

import collections
import math
import sys
import os
import time
import unittest
from unittest.mock import MagicMock, patch

# Ensure the local_agent package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from security.network_monitor import (
    NetworkMonitor,
    NetworkConnection,
    C2BeaconAlert,
    calculate_domain_entropy,
    is_private_or_loopback_ip,
    SUSPICIOUS_C2_PORTS,
    SUSPICIOUS_TUNNEL_DOMAINS,
    SUSPICIOUS_LOTL_NETWORK_EXES,
)
from security.alert_bridge import (
    AlertBridge,
    SecurityAlertMessage,
    SecurityNLGEngine,
)


# ============================================================================
# Shannon Entropy Tests
# ============================================================================

class TestDomainEntropy(unittest.TestCase):
    """Tests for calculate_domain_entropy()."""

    def test_empty_string_entropy_zero(self):
        self.assertEqual(calculate_domain_entropy(""), 0.0)

    def test_single_char_entropy_zero(self):
        self.assertEqual(calculate_domain_entropy("a"), 0.0)

    def test_repeated_chars_low_entropy(self):
        """All identical characters → entropy = 0."""
        self.assertEqual(calculate_domain_entropy("aaaaaaa"), 0.0)

    def test_two_char_alternating_entropy(self):
        """Alternating two characters → entropy = 1.0."""
        entropy = calculate_domain_entropy("abababab.com")
        self.assertAlmostEqual(entropy, 1.0, places=2)

    def test_high_entropy_random_domain(self):
        """Random-looking strings should have high entropy (>3.0)."""
        entropy = calculate_domain_entropy("x7kq9m2np5.evil.com")
        self.assertGreater(entropy, 3.0)

    def test_dga_like_domain_flags_high(self):
        """DGA-style domain like 'kxj4m9qz2p8f' should exceed typical threshold."""
        entropy = calculate_domain_entropy("kxj4m9qz2p8f.com")
        self.assertGreater(entropy, 3.5)

    def test_normal_domain_moderate_entropy(self):
        """Normal English domains should have moderate entropy."""
        entropy = calculate_domain_entropy("google.com")
        # "google" has limited character diversity
        self.assertLess(entropy, 3.5)

    def test_strip_port_from_domain(self):
        """Port suffix should be stripped before entropy calculation."""
        e1 = calculate_domain_entropy("test.com:443")
        e2 = calculate_domain_entropy("test.com")
        self.assertEqual(e1, e2)

    def test_none_returns_zero(self):
        """None-like empty edge case."""
        self.assertEqual(calculate_domain_entropy(""), 0.0)

    def test_numeric_domain_entropy(self):
        """Numeric-heavy strings like C2 IPs should have calculable entropy."""
        entropy = calculate_domain_entropy("192.168.1.1")
        self.assertGreater(entropy, 0.0)


# ============================================================================
# IP Classification Tests
# ============================================================================

class TestIPClassification(unittest.TestCase):
    """Tests for is_private_or_loopback_ip()."""

    def test_loopback_v4(self):
        self.assertTrue(is_private_or_loopback_ip("127.0.0.1"))

    def test_loopback_v6(self):
        self.assertTrue(is_private_or_loopback_ip("::1"))

    def test_private_10_network(self):
        self.assertTrue(is_private_or_loopback_ip("10.0.0.1"))

    def test_private_172_network(self):
        self.assertTrue(is_private_or_loopback_ip("172.16.0.1"))

    def test_private_192_network(self):
        self.assertTrue(is_private_or_loopback_ip("192.168.1.100"))

    def test_public_ip_not_private(self):
        self.assertFalse(is_private_or_loopback_ip("8.8.8.8"))

    def test_public_ip_cloudflare(self):
        self.assertFalse(is_private_or_loopback_ip("1.1.1.1"))

    def test_zero_address(self):
        self.assertTrue(is_private_or_loopback_ip("0.0.0.0"))

    def test_wildcard(self):
        self.assertTrue(is_private_or_loopback_ip("*"))

    def test_localhost_string(self):
        self.assertTrue(is_private_or_loopback_ip("localhost"))

    def test_empty_string(self):
        self.assertTrue(is_private_or_loopback_ip(""))

    def test_link_local(self):
        self.assertTrue(is_private_or_loopback_ip("169.254.1.1"))


# ============================================================================
# Data Model Tests
# ============================================================================

class TestNetworkConnectionDataclass(unittest.TestCase):
    """Tests for NetworkConnection serialization."""

    def test_to_dict_contains_all_fields(self):
        conn = NetworkConnection(
            pid=1234,
            process_name="chrome.exe",
            proto="tcp",
            local_ip="192.168.1.10",
            local_port=54321,
            remote_ip="142.250.190.78",
            remote_port=443,
            status="ESTABLISHED",
            domain="www.google.com",
            entropy=2.1,
            is_suspicious=False,
            suspicious_reasons=[],
        )
        d = conn.to_dict()
        self.assertEqual(d["pid"], 1234)
        self.assertEqual(d["process_name"], "chrome.exe")
        self.assertEqual(d["proto"], "tcp")
        self.assertEqual(d["remote_ip"], "142.250.190.78")
        self.assertEqual(d["remote_port"], 443)
        self.assertEqual(d["status"], "ESTABLISHED")
        self.assertEqual(d["domain"], "www.google.com")
        self.assertAlmostEqual(d["entropy"], 2.1)
        self.assertFalse(d["is_suspicious"])
        self.assertIsInstance(d["suspicious_reasons"], list)

    def test_defaults(self):
        conn = NetworkConnection(
            pid=1, process_name="test", proto="tcp",
            local_ip="", local_port=0, remote_ip="", remote_port=0, status="NONE"
        )
        self.assertIsNone(conn.domain)
        self.assertEqual(conn.entropy, 0.0)
        self.assertFalse(conn.is_suspicious)
        self.assertEqual(conn.suspicious_reasons, [])


class TestC2BeaconAlertDataclass(unittest.TestCase):
    """Tests for C2BeaconAlert serialization."""

    def test_to_dict_roundtrip(self):
        alert = C2BeaconAlert(
            alert_id="test-123",
            timestamp="2026-10-16T00:00:00Z",
            severity="CRITICAL",
            alert_type="C2_BEACONING",
            process_name="malware.exe",
            pid=666,
            remote_ip="185.99.133.7",
            remote_port=4444,
            domain="evil.example.com",
            beacon_interval_seconds=30.0,
            jitter_ratio=0.05,
            connection_count=10,
            mitre_technique="T1071",
            description="Beacon detected",
            confidence=0.95,
        )
        d = alert.to_dict()
        self.assertEqual(d["alert_id"], "test-123")
        self.assertEqual(d["severity"], "CRITICAL")
        self.assertEqual(d["alert_type"], "C2_BEACONING")
        self.assertEqual(d["pid"], 666)
        self.assertEqual(d["remote_port"], 4444)
        self.assertAlmostEqual(d["beacon_interval_seconds"], 30.0)
        self.assertAlmostEqual(d["jitter_ratio"], 0.05)
        self.assertAlmostEqual(d["confidence"], 0.95)


# ============================================================================
# Static Socket Inspection Tests
# ============================================================================

class TestStaticInspection(unittest.TestCase):
    """Tests for NetworkMonitor.inspect_connection() static checks."""

    def setUp(self):
        self.monitor = NetworkMonitor()

    def test_suspicious_c2_port_flags(self):
        """Connection to known C2 port 4444 should be flagged."""
        conn = NetworkConnection(
            pid=100, process_name="payload.exe", proto="tcp",
            local_ip="192.168.1.10", local_port=50000,
            remote_ip="185.99.133.7", remote_port=4444, status="ESTABLISHED"
        )
        reasons = self.monitor.inspect_connection(conn)
        self.assertTrue(conn.is_suspicious)
        self.assertTrue(any("4444" in r for r in reasons))
        self.assertTrue(any("T1571" in r for r in reasons))

    def test_normal_https_port_clean(self):
        """Connection to port 443 should not trigger C2 port flag."""
        conn = NetworkConnection(
            pid=100, process_name="chrome.exe", proto="tcp",
            local_ip="192.168.1.10", local_port=50000,
            remote_ip="142.250.190.78", remote_port=443, status="ESTABLISHED"
        )
        reasons = self.monitor.inspect_connection(conn)
        self.assertFalse(conn.is_suspicious)
        self.assertEqual(len(reasons), 0)

    def test_lotl_powershell_outbound(self):
        """powershell.exe connecting externally should flag LotL."""
        conn = NetworkConnection(
            pid=200, process_name="powershell.exe", proto="tcp",
            local_ip="192.168.1.10", local_port=50000,
            remote_ip="45.33.32.156", remote_port=80, status="ESTABLISHED"
        )
        reasons = self.monitor.inspect_connection(conn)
        self.assertTrue(conn.is_suspicious)
        self.assertTrue(any("LotL" in r for r in reasons))
        self.assertTrue(any("T1059" in r for r in reasons))

    def test_lotl_certutil_outbound(self):
        """certutil.exe connecting externally should flag."""
        conn = NetworkConnection(
            pid=300, process_name="certutil.exe", proto="tcp",
            local_ip="192.168.1.10", local_port=50000,
            remote_ip="104.18.0.1", remote_port=80, status="ESTABLISHED"
        )
        reasons = self.monitor.inspect_connection(conn)
        self.assertTrue(conn.is_suspicious)
        self.assertTrue(any("certutil.exe" in r for r in reasons))

    def test_lotl_local_connection_not_flagged(self):
        """powershell.exe connecting to localhost should NOT flag LotL."""
        conn = NetworkConnection(
            pid=200, process_name="powershell.exe", proto="tcp",
            local_ip="127.0.0.1", local_port=50000,
            remote_ip="127.0.0.1", remote_port=8080, status="ESTABLISHED"
        )
        reasons = self.monitor.inspect_connection(conn)
        self.assertFalse(conn.is_suspicious)
        self.assertEqual(len(reasons), 0)

    def test_tunnel_domain_ngrok(self):
        """Connection to ngrok domain should flag tunnel proxy."""
        conn = NetworkConnection(
            pid=400, process_name="agent.exe", proto="tcp",
            local_ip="192.168.1.10", local_port=50000,
            remote_ip="52.1.2.3", remote_port=443, status="ESTABLISHED",
            domain="abc123.ngrok-free.app",
        )
        reasons = self.monitor.inspect_connection(conn)
        self.assertTrue(conn.is_suspicious)
        self.assertTrue(any("tunnel" in r.lower() for r in reasons))
        self.assertTrue(any("T1572" in r for r in reasons))

    def test_tunnel_domain_duckdns(self):
        """Connection to duckdns should flag."""
        conn = NetworkConnection(
            pid=400, process_name="agent.exe", proto="tcp",
            local_ip="192.168.1.10", local_port=50000,
            remote_ip="52.1.2.3", remote_port=443, status="ESTABLISHED",
            domain="myhost.duckdns.org",
        )
        reasons = self.monitor.inspect_connection(conn)
        self.assertTrue(conn.is_suspicious)

    def test_dga_high_entropy_domain(self):
        """High-entropy domain should flag DGA."""
        conn = NetworkConnection(
            pid=500, process_name="svchost.exe", proto="tcp",
            local_ip="192.168.1.10", local_port=50000,
            remote_ip="45.33.32.0", remote_port=443, status="ESTABLISHED",
            domain="xk4q9zmn2pr8f7tj.evil.com",
        )
        reasons = self.monitor.inspect_connection(conn)
        self.assertTrue(conn.is_suspicious)
        self.assertTrue(any("DGA" in r for r in reasons))
        self.assertTrue(any("T1568" in r for r in reasons))

    def test_c2_port_on_private_ip_not_flagged(self):
        """C2 port to private IP should NOT trigger suspicious flag."""
        conn = NetworkConnection(
            pid=100, process_name="test.exe", proto="tcp",
            local_ip="192.168.1.10", local_port=50000,
            remote_ip="10.0.0.5", remote_port=4444, status="ESTABLISHED"
        )
        reasons = self.monitor.inspect_connection(conn)
        self.assertFalse(conn.is_suspicious)

    def test_multiple_reasons_accumulate(self):
        """powershell.exe connecting to suspicious port should give multiple reasons."""
        conn = NetworkConnection(
            pid=200, process_name="powershell.exe", proto="tcp",
            local_ip="192.168.1.10", local_port=50000,
            remote_ip="185.99.133.7", remote_port=4444, status="ESTABLISHED"
        )
        reasons = self.monitor.inspect_connection(conn)
        self.assertTrue(conn.is_suspicious)
        self.assertGreaterEqual(len(reasons), 2)  # C2 port + LotL


# ============================================================================
# Temporal Beaconing Detection Tests
# ============================================================================

class TestBeaconDetection(unittest.TestCase):
    """Tests for the temporal C2 beacon pattern detection engine."""

    def setUp(self):
        self.alerts_received = []
        self.monitor = NetworkMonitor(
            min_beacon_samples=4,
            max_beacon_jitter=0.20,
            alert_callback=lambda alert: self.alerts_received.append(alert),
        )

    def _make_conn(self, remote_ip="185.99.133.7", remote_port=4444, pid=100, pname="beacon.exe"):
        return NetworkConnection(
            pid=pid, process_name=pname, proto="tcp",
            local_ip="192.168.1.10", local_port=50000,
            remote_ip=remote_ip, remote_port=remote_port, status="ESTABLISHED"
        )

    def test_beacon_detected_low_jitter(self):
        """Periodic connections with minimal jitter should trigger C2 alert."""
        conn = self._make_conn()
        base_time = 1000.0
        interval = 30.0  # 30-second beacon

        for i in range(6):
            t = base_time + (i * interval)
            result = self.monitor.record_connection(conn, current_time=t)
        
        # Should have triggered an alert
        self.assertEqual(len(self.alerts_received), 1)
        alert = self.alerts_received[0]
        self.assertEqual(alert.alert_type, "C2_BEACONING")
        self.assertEqual(alert.severity, "CRITICAL")  # connects to C2 port 4444
        self.assertAlmostEqual(alert.beacon_interval_seconds, 30.0, delta=1.0)
        self.assertLessEqual(alert.jitter_ratio, 0.20)

    def test_no_beacon_high_jitter(self):
        """Irregular connection intervals should NOT trigger beacon alert."""
        conn = self._make_conn(remote_port=80)
        # Random intervals: 5, 45, 3, 60, 20
        times = [100.0, 105.0, 150.0, 153.0, 213.0, 233.0]

        for t in times:
            self.monitor.record_connection(conn, current_time=t)

        self.assertEqual(len(self.alerts_received), 0)

    def test_insufficient_samples_no_alert(self):
        """Fewer than min_beacon_samples should not trigger."""
        conn = self._make_conn()
        for i in range(3):  # Only 3 samples, need 4
            self.monitor.record_connection(conn, current_time=1000.0 + i * 30.0)
        self.assertEqual(len(self.alerts_received), 0)

    def test_exactly_min_samples_triggers(self):
        """Exactly min_beacon_samples with low jitter should trigger."""
        conn = self._make_conn()
        for i in range(4):
            self.monitor.record_connection(conn, current_time=1000.0 + i * 60.0)
        self.assertEqual(len(self.alerts_received), 1)

    def test_private_ip_target_ignored(self):
        """Connections to private IPs should not be tracked for beaconing."""
        conn = self._make_conn(remote_ip="192.168.1.1", remote_port=8080)
        for i in range(10):
            result = self.monitor.record_connection(conn, current_time=1000.0 + i * 30.0)
            self.assertIsNone(result)
        self.assertEqual(len(self.alerts_received), 0)

    def test_alert_cooldown_prevents_spam(self):
        """Same target should not trigger duplicate alerts within 120s cooldown."""
        conn = self._make_conn()
        base = 1000.0

        # First burst: triggers alert
        for i in range(6):
            self.monitor.record_connection(conn, current_time=base + i * 30.0)
        self.assertEqual(len(self.alerts_received), 1)

        # Immediate second burst: should be suppressed (within 120s cooldown)
        for i in range(6):
            self.monitor.record_connection(conn, current_time=base + 200.0 + i * 30.0)
        self.assertEqual(len(self.alerts_received), 1)  # Still only 1 alert

    def test_different_targets_separate_tracking(self):
        """Different remote targets should be tracked independently."""
        conn_a = self._make_conn(remote_ip="45.1.1.1", remote_port=4444)
        conn_b = self._make_conn(remote_ip="46.2.2.2", remote_port=8888)

        base = 1000.0
        for i in range(6):
            self.monitor.record_connection(conn_a, current_time=base + i * 30.0)
            self.monitor.record_connection(conn_b, current_time=base + i * 30.0)

        self.assertEqual(len(self.alerts_received), 2)

    def test_beacon_callback_invoked(self):
        """Alert callback should be invoked when beacon is detected."""
        callback_called = []
        monitor = NetworkMonitor(
            min_beacon_samples=4,
            max_beacon_jitter=0.20,
            alert_callback=lambda a: callback_called.append(a.alert_id),
        )
        conn = NetworkConnection(
            pid=100, process_name="beacon.exe", proto="tcp",
            local_ip="192.168.1.10", local_port=50000,
            remote_ip="185.99.133.7", remote_port=443, status="ESTABLISHED"
        )
        for i in range(6):
            monitor.record_connection(conn, current_time=1000.0 + i * 60.0)
        self.assertEqual(len(callback_called), 1)

    def test_very_fast_intervals_filtered(self):
        """Intervals < 0.5s mean should be treated as streaming, not beaconing."""
        conn = self._make_conn()
        for i in range(10):
            self.monitor.record_connection(conn, current_time=1000.0 + i * 0.2)
        self.assertEqual(len(self.alerts_received), 0)

    def test_confidence_boost_for_low_jitter(self):
        """Very low jitter (<= 0.08) should boost confidence above 0.75."""
        conn = self._make_conn()
        for i in range(8):
            self.monitor.record_connection(conn, current_time=1000.0 + i * 30.0)
        self.assertEqual(len(self.alerts_received), 1)
        self.assertGreater(self.alerts_received[0].confidence, 0.75)


# ============================================================================
# Immediate Threat Alert Tests
# ============================================================================

class TestImmediateThreatAlerts(unittest.TestCase):
    """Tests for _create_immediate_threat_alert on static indicators."""

    def setUp(self):
        self.alerts_received = []
        self.monitor = NetworkMonitor(
            alert_callback=lambda a: self.alerts_received.append(a),
        )

    def test_scan_once_flags_suspicious_port(self):
        """scan_once with a mocked connection to C2 port produces immediate alert."""
        conn = NetworkConnection(
            pid=100, process_name="malware.exe", proto="tcp",
            local_ip="192.168.1.10", local_port=50000,
            remote_ip="185.99.133.7", remote_port=4444, status="ESTABLISHED"
        )
        # Manually inspect and create immediate alert
        self.monitor.inspect_connection(conn)
        alert = self.monitor._create_immediate_threat_alert(conn)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, "SUSPICIOUS_OUTBOUND")

    def test_tunnel_alert_type(self):
        """Tunnel domain connections should create TUNNEL_PROXY alert type."""
        conn = NetworkConnection(
            pid=100, process_name="agent.exe", proto="tcp",
            local_ip="192.168.1.10", local_port=50000,
            remote_ip="52.1.2.3", remote_port=443, status="ESTABLISHED",
            domain="abc.ngrok-free.app",
        )
        self.monitor.inspect_connection(conn)
        alert = self.monitor._create_immediate_threat_alert(conn)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, "TUNNEL_PROXY")

    def test_dga_alert_type(self):
        """DGA domain should create DGA_DOMAIN alert type."""
        conn = NetworkConnection(
            pid=100, process_name="svchost.exe", proto="tcp",
            local_ip="192.168.1.10", local_port=50000,
            remote_ip="45.33.32.0", remote_port=443, status="ESTABLISHED",
            domain="xk4q9zmn2pr8f7tj.evil.com",
        )
        self.monitor.inspect_connection(conn)
        alert = self.monitor._create_immediate_threat_alert(conn)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, "DGA_DOMAIN")

    def test_lotl_critical_severity(self):
        """LotL executable outbound should be CRITICAL severity."""
        conn = NetworkConnection(
            pid=200, process_name="powershell.exe", proto="tcp",
            local_ip="192.168.1.10", local_port=50000,
            remote_ip="45.33.32.156", remote_port=80, status="ESTABLISHED"
        )
        self.monitor.inspect_connection(conn)
        alert = self.monitor._create_immediate_threat_alert(conn)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, "CRITICAL")

    def test_immediate_cooldown(self):
        """Same target should not generate duplicate immediate alerts within cooldown."""
        conn = NetworkConnection(
            pid=100, process_name="malware.exe", proto="tcp",
            local_ip="192.168.1.10", local_port=50000,
            remote_ip="185.99.133.7", remote_port=4444, status="ESTABLISHED"
        )
        self.monitor.inspect_connection(conn)
        alert1 = self.monitor._create_immediate_threat_alert(conn)
        self.assertIsNotNone(alert1)
        alert2 = self.monitor._create_immediate_threat_alert(conn)
        self.assertIsNone(alert2)  # Cooldown active


# ============================================================================
# NLG Narration Tests
# ============================================================================

class TestNetworkNLGNarration(unittest.TestCase):
    """Tests for SecurityNLGEngine.narrate_network_c2_threat()."""

    def test_c2_beacon_narration(self):
        msg = SecurityNLGEngine.narrate_network_c2_threat(
            alert_type="C2_BEACONING",
            process_name="beacon.exe",
            pid=1234,
            remote_ip="185.99.133.7",
            remote_port=4444,
            domain="evil.com",
            beacon_interval_seconds=30.0,
            jitter_ratio=0.05,
            connection_count=10,
            mitre_technique="T1071",
            description="Beacon detected",
            severity="CRITICAL",
        )
        self.assertIsInstance(msg, SecurityAlertMessage)
        self.assertEqual(msg.severity, "CRITICAL")
        self.assertEqual(msg.alert_type, "C2_BEACONING")
        self.assertIn("C2 BEACONING", msg.title)
        self.assertIn("beacon.exe", msg.threat_description)
        self.assertIn("evil.com", msg.threat_description)
        self.assertEqual(msg.source_module, "network_monitor")
        self.assertGreater(len(msg.actionable_steps), 0)

    def test_tunnel_proxy_narration(self):
        msg = SecurityNLGEngine.narrate_network_c2_threat(
            alert_type="TUNNEL_PROXY",
            process_name="agent.exe",
            pid=500,
            remote_ip="52.1.2.3",
            remote_port=443,
            domain="abc.ngrok-free.app",
            beacon_interval_seconds=0.0,
            jitter_ratio=0.0,
            connection_count=1,
            mitre_technique="T1572",
            description="Tunnel connection",
        )
        self.assertEqual(msg.alert_type, "TUNNEL_PROXY")
        self.assertIn("Reverse Tunnel", msg.title)
        self.assertIn("tunneling", msg.threat_description.lower())

    def test_dga_domain_narration(self):
        msg = SecurityNLGEngine.narrate_network_c2_threat(
            alert_type="DGA_DOMAIN",
            process_name="svchost.exe",
            pid=800,
            remote_ip="45.33.32.0",
            remote_port=443,
            domain="xk4q9zmn2pr8f7tj.evil.com",
            beacon_interval_seconds=0.0,
            jitter_ratio=0.0,
            connection_count=1,
            mitre_technique="T1568.002",
            description="DGA domain",
        )
        self.assertEqual(msg.alert_type, "DGA_DOMAIN")
        self.assertIn("DGA", msg.title)

    def test_suspicious_outbound_narration(self):
        msg = SecurityNLGEngine.narrate_network_c2_threat(
            alert_type="SUSPICIOUS_OUTBOUND",
            process_name="malware.exe",
            pid=999,
            remote_ip="185.99.133.7",
            remote_port=4444,
            domain="evil.com",
            beacon_interval_seconds=0.0,
            jitter_ratio=0.0,
            connection_count=1,
            mitre_technique="T1571",
            description="Suspicious outbound",
        )
        self.assertEqual(msg.alert_type, "SUSPICIOUS_OUTBOUND")
        self.assertIn("Suspicious Outbound", msg.title)

    def test_narration_serialization(self):
        """NLG message should serialize to dict properly."""
        msg = SecurityNLGEngine.narrate_network_c2_threat(
            alert_type="C2_BEACONING",
            process_name="test.exe",
            pid=1,
            remote_ip="1.2.3.4",
            remote_port=80,
            domain="test.com",
            beacon_interval_seconds=60.0,
            jitter_ratio=0.1,
            connection_count=5,
            mitre_technique="T1071",
            description="Test",
        )
        d = msg.to_dict()
        self.assertIn("alert_id", d)
        self.assertIn("raw_details", d)
        self.assertEqual(d["raw_details"]["process_name"], "test.exe")


# ============================================================================
# AlertBridge Integration Tests
# ============================================================================

class TestAlertBridgeNetworkIntegration(unittest.TestCase):
    """Tests for AlertBridge.on_network_c2_alert() callback."""

    def test_on_network_c2_alert_dispatches(self):
        """on_network_c2_alert should create alert and add to history."""
        bridge = AlertBridge()

        mock_c2_alert = MagicMock()
        mock_c2_alert.alert_type = "C2_BEACONING"
        mock_c2_alert.process_name = "beacon.exe"
        mock_c2_alert.pid = 1234
        mock_c2_alert.remote_ip = "185.99.133.7"
        mock_c2_alert.remote_port = 4444
        mock_c2_alert.domain = "evil.com"
        mock_c2_alert.beacon_interval_seconds = 30.0
        mock_c2_alert.jitter_ratio = 0.05
        mock_c2_alert.connection_count = 10
        mock_c2_alert.mitre_technique = "T1071"
        mock_c2_alert.description = "Beacon detected"
        mock_c2_alert.severity = "CRITICAL"

        bridge.on_network_c2_alert(mock_c2_alert)

        self.assertEqual(bridge.alert_count, 1)
        history = bridge.alert_history
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["alert_type"], "C2_BEACONING")
        self.assertEqual(history[0]["severity"], "CRITICAL")
        self.assertIn("beacon.exe", history[0]["threat_description"])

    def test_on_network_c2_alert_tunnel_type(self):
        """Tunnel alerts should dispatch correctly through bridge."""
        bridge = AlertBridge()

        mock_alert = MagicMock()
        mock_alert.alert_type = "TUNNEL_PROXY"
        mock_alert.process_name = "agent.exe"
        mock_alert.pid = 500
        mock_alert.remote_ip = "52.1.2.3"
        mock_alert.remote_port = 443
        mock_alert.domain = "abc.ngrok.io"
        mock_alert.beacon_interval_seconds = 0.0
        mock_alert.jitter_ratio = 0.0
        mock_alert.connection_count = 1
        mock_alert.mitre_technique = "T1572"
        mock_alert.description = "Tunnel detected"
        mock_alert.severity = "HIGH"

        bridge.on_network_c2_alert(mock_alert)
        self.assertEqual(bridge.alert_count, 1)
        history = bridge.alert_history
        self.assertEqual(history[0]["alert_type"], "TUNNEL_PROXY")

    def test_telemetry_summary_includes_network_alerts(self):
        """Telemetry summary should include network alert type counts."""
        bridge = AlertBridge()

        mock_alert = MagicMock()
        mock_alert.alert_type = "DGA_DOMAIN"
        mock_alert.process_name = "svchost.exe"
        mock_alert.pid = 800
        mock_alert.remote_ip = "45.33.32.0"
        mock_alert.remote_port = 443
        mock_alert.domain = "x7k9m2np5.evil.com"
        mock_alert.beacon_interval_seconds = 0.0
        mock_alert.jitter_ratio = 0.0
        mock_alert.connection_count = 1
        mock_alert.mitre_technique = "T1568.002"
        mock_alert.description = "DGA"
        mock_alert.severity = "HIGH"

        bridge.on_network_c2_alert(mock_alert)
        summary = bridge.get_telemetry_summary()
        self.assertEqual(summary["total_alerts"], 1)
        self.assertIn("DGA_DOMAIN", summary["alert_type_counts"])


# ============================================================================
# Monitor Telemetry Tests
# ============================================================================

class TestNetworkMonitorTelemetry(unittest.TestCase):
    """Tests for NetworkMonitor telemetry and alert getter methods."""

    def test_get_beacon_alerts_empty(self):
        monitor = NetworkMonitor()
        self.assertEqual(monitor.get_beacon_alerts(), [])

    def test_get_network_telemetry_empty(self):
        monitor = NetworkMonitor()
        telemetry = monitor.get_network_telemetry()
        self.assertEqual(telemetry["active_external_targets_tracked"], 0)
        self.assertEqual(telemetry["total_network_alerts"], 0)
        self.assertIsNone(telemetry["latest_alert"])

    def test_telemetry_after_beacon_alert(self):
        monitor = NetworkMonitor(min_beacon_samples=4, max_beacon_jitter=0.20)
        conn = NetworkConnection(
            pid=100, process_name="beacon.exe", proto="tcp",
            local_ip="192.168.1.10", local_port=50000,
            remote_ip="185.99.133.7", remote_port=4444, status="ESTABLISHED"
        )
        for i in range(6):
            monitor.record_connection(conn, current_time=1000.0 + i * 30.0)

        telemetry = monitor.get_network_telemetry()
        self.assertGreaterEqual(telemetry["total_network_alerts"], 1)
        self.assertIsNotNone(telemetry["latest_alert"])
        self.assertEqual(telemetry["latest_alert"]["alert_type"], "C2_BEACONING")


# ============================================================================
# Monitor Lifecycle Tests
# ============================================================================

class TestMonitorLifecycle(unittest.TestCase):
    """Tests for NetworkMonitor start/stop lifecycle."""

    def test_start_sets_running(self):
        monitor = NetworkMonitor(check_interval=100.0)
        monitor.start()
        self.assertTrue(monitor.is_running)
        monitor.stop()
        self.assertFalse(monitor.is_running)

    def test_double_start_no_duplicate_thread(self):
        monitor = NetworkMonitor(check_interval=100.0)
        monitor.start()
        thread1 = monitor._thread
        monitor.start()  # Should be no-op
        self.assertIs(monitor._thread, thread1)
        monitor.stop()

    def test_stop_without_start(self):
        """stop() without start() should not raise."""
        monitor = NetworkMonitor()
        monitor.stop()  # Should not raise


# ============================================================================
# Constants Sanity Tests
# ============================================================================

class TestConstantsIntegrity(unittest.TestCase):
    """Sanity checks on the IOC constant tables."""

    def test_suspicious_ports_non_empty(self):
        self.assertGreater(len(SUSPICIOUS_C2_PORTS), 10)

    def test_suspicious_ports_contains_metasploit(self):
        self.assertIn(4444, SUSPICIOUS_C2_PORTS)

    def test_tunnel_domains_non_empty(self):
        self.assertGreater(len(SUSPICIOUS_TUNNEL_DOMAINS), 5)

    def test_tunnel_domains_contains_ngrok(self):
        self.assertTrue(any("ngrok" in d for d in SUSPICIOUS_TUNNEL_DOMAINS))

    def test_lotl_exes_non_empty(self):
        self.assertGreater(len(SUSPICIOUS_LOTL_NETWORK_EXES), 5)

    def test_lotl_contains_powershell(self):
        self.assertIn("powershell.exe", SUSPICIOUS_LOTL_NETWORK_EXES)

    def test_lotl_all_lowercase(self):
        for exe in SUSPICIOUS_LOTL_NETWORK_EXES:
            self.assertEqual(exe, exe.lower())


if __name__ == "__main__":
    unittest.main()
