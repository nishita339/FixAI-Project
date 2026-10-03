"""
FixAI EDR — Phase 5 Unit Tests: Plain-English Alert Bridge & Desktop Notifications
====================================================================================

Tests cover:
 1. NLG Brute-Force Narrative — template output correctness
 2. NLG Malicious File Narrative — entropy + YARA reasons rendering
 3. NLG Fileless Threat Narrative — WMI persistence vs LotL
 4. NLG Quarantine Action Narrative — vault confirmation
 5. NLG Firewall Block Narrative — IP block notification
 6. SecurityAlertMessage serialization (to_dict, to_plain_text, to_toast_summary)
 7. AlertBridge end-to-end IPC dispatch (callback invocation)
 8. AlertBridge brute-force callback integration with Phase 1 BruteForceAlert
 9. AlertBridge malicious file callback integration with Phase 2 MaliciousFileAlert
10. AlertBridge fileless threat callback integration with Phase 3 FilelessThreatAlert
11. AlertBridge alert history tracking and telemetry summary
12. DesktopNotifier initialization (non-crashing)
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch
from dataclasses import dataclass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from security.alert_bridge import (
    AlertBridge,
    SecurityAlertMessage,
    SecurityNLGEngine,
    DesktopNotifier,
)


# ============================================================================
# Mock Alert Data Classes (simulating Phase 1–3 outputs)
# ============================================================================

@dataclass
class MockBruteForceAlert:
    source_ip: str = "198.51.100.22"
    target_user: str = "Administrator"
    attempt_count: int = 12
    window_seconds: float = 45.0


@dataclass
class MockMaliciousFileAlert:
    filename: str = "payload.exe"
    filepath: str = r"C:\Users\test\Downloads\payload.exe"
    entropy: float = 7.85
    yara_matches: list = None
    sha256: str = "abc123def456"
    severity: str = "HIGH"

    def __post_init__(self):
        if self.yara_matches is None:
            self.yara_matches = ["SuspiciousDropper"]


@dataclass
class MockFilelessThreatAlert:
    alert_type: str = "WMI_PERSISTENCE"
    parent_name: str = "scrcons.exe"
    parent_pid: int = 1000
    child_name: str = "powershell.exe"
    child_pid: int = 2000
    child_cmdline: str = "powershell.exe -enc SQBuAHY..."
    mitre_technique: str = "T1546.003"
    parent_cmdline: str = "scrcons.exe"


@dataclass
class MockQuarantineRecord:
    original_filename: str = "trojan.dll"
    original_sha256: str = "deadbeef" * 8
    quarantine_id: str = "test-q-id-1234"
    quarantined_path: str = r"C:\FixAI_Quarantine\test-q-id-1234.quarantined"


class TestPhase5AlertBridge(unittest.TestCase):
    """Phase 5: Plain-English Alert Bridge & Desktop Notification Tests"""

    # ====================================================================
    # Test 1: NLG Brute-Force Narrative
    # ====================================================================
    def test_nlg_brute_force_narrative(self):
        """Brute-force NLG template should contain IP, count, and user in plain English."""
        nlg = SecurityNLGEngine()
        alert = nlg.narrate_brute_force(
            source_ip="10.0.0.15",
            target_user="admin",
            attempt_count=50,
            window_seconds=30.0,
        )
        self.assertEqual(alert.alert_type, "BRUTE_FORCE")
        self.assertEqual(alert.severity, "HIGH")
        self.assertIn("10.0.0.15", alert.threat_description)
        self.assertIn("50", alert.threat_description)
        self.assertIn("admin", alert.threat_description)
        self.assertIn("blocked", alert.action_taken.lower())
        self.assertEqual(len(alert.actionable_steps), 3)
        self.assertEqual(alert.source_module, "event_monitor")

    # ====================================================================
    # Test 2: NLG Malicious File Narrative (Entropy + YARA)
    # ====================================================================
    def test_nlg_malicious_file_narrative(self):
        """Malicious file NLG should mention entropy value and YARA signature names."""
        nlg = SecurityNLGEngine()
        alert = nlg.narrate_malicious_file(
            filename="ransomware.exe",
            filepath=r"C:\Downloads\ransomware.exe",
            entropy=7.95,
            yara_matches=["RansomwareTTP", "SuspiciousDropper"],
            sha256="abcdef1234567890",
        )
        self.assertEqual(alert.alert_type, "MALICIOUS_FILE")
        self.assertIn("7.95", alert.threat_description)
        self.assertIn("RansomwareTTP", alert.threat_description)
        self.assertIn("SuspiciousDropper", alert.threat_description)
        self.assertIn("AES-256", alert.action_taken)
        self.assertIn("quarantine", alert.action_taken.lower())

    def test_nlg_malicious_file_entropy_only(self):
        """When only entropy is high (no YARA), narrative should still be coherent."""
        nlg = SecurityNLGEngine()
        alert = nlg.narrate_malicious_file(
            filename="packed.exe",
            filepath=r"C:\Temp\packed.exe",
            entropy=7.5,
            yara_matches=[],
        )
        self.assertIn("Shannon entropy", alert.threat_description)
        self.assertNotIn("YARA", alert.threat_description)

    # ====================================================================
    # Test 3: NLG Fileless Threat Narrative (WMI vs LotL)
    # ====================================================================
    def test_nlg_fileless_wmi_persistence(self):
        """WMI persistence narrative should be CRITICAL and mention scrcons.exe."""
        nlg = SecurityNLGEngine()
        alert = nlg.narrate_fileless_threat(
            parent_name="scrcons.exe",
            parent_pid=500,
            child_name="powershell.exe",
            child_pid=600,
            child_cmdline="powershell.exe -enc ...",
            mitre_technique="T1546.003",
            alert_type="WMI_PERSISTENCE",
        )
        self.assertEqual(alert.severity, "CRITICAL")
        self.assertIn("scrcons.exe", alert.threat_description)
        self.assertIn("fileless", alert.threat_description.lower())

    def test_nlg_fileless_lotl_execution(self):
        """LotL execution narrative should be HIGH severity."""
        nlg = SecurityNLGEngine()
        alert = nlg.narrate_fileless_threat(
            parent_name="mshta.exe",
            parent_pid=800,
            child_name="cmd.exe",
            child_pid=900,
            child_cmdline="cmd.exe /c whoami",
            mitre_technique="T1218",
            alert_type="LOTL_EXECUTION",
        )
        self.assertEqual(alert.severity, "HIGH")
        self.assertIn("mshta.exe", alert.threat_description)

    # ====================================================================
    # Test 4: NLG Quarantine Action Narrative
    # ====================================================================
    def test_nlg_quarantine_action(self):
        """Quarantine confirmation narrative should reference vault path and SHA-256."""
        nlg = SecurityNLGEngine()
        alert = nlg.narrate_quarantine_action(
            filename="trojan.dll",
            sha256="deadbeefdeadbeef",
            quarantine_id="q-1234",
            vault_path=r"C:\FixAI_Quarantine\q-1234.quarantined",
        )
        self.assertEqual(alert.alert_type, "QUARANTINE")
        self.assertIn("trojan.dll", alert.threat_description)
        self.assertIn("AES-256", alert.action_taken)

    # ====================================================================
    # Test 5: NLG Firewall Block Narrative
    # ====================================================================
    def test_nlg_firewall_block(self):
        """Firewall block narrative should contain the blocked IP and rule name."""
        nlg = SecurityNLGEngine()
        alert = nlg.narrate_firewall_block(
            ip="198.51.100.22",
            rule_name="FixAI-Block-198.51.100.22",
            reason="Brute-force intrusion attempt",
        )
        self.assertEqual(alert.alert_type, "FIREWALL")
        self.assertIn("198.51.100.22", alert.threat_description)
        self.assertIn("FixAI-Block", alert.action_taken)

    # ====================================================================
    # Test 6: SecurityAlertMessage Serialization
    # ====================================================================
    def test_alert_message_to_dict(self):
        """SecurityAlertMessage.to_dict() must include all required fields."""
        nlg = SecurityNLGEngine()
        alert = nlg.narrate_brute_force("1.2.3.4", "root", 10, 30.0)
        d = alert.to_dict()

        required_keys = [
            "alert_id", "timestamp", "severity", "alert_type", "title",
            "threat_description", "action_taken", "actionable_steps",
            "source_module", "plain_text", "raw_details",
        ]
        for key in required_keys:
            self.assertIn(key, d, f"Missing key: {key}")

    def test_alert_message_to_plain_text(self):
        """to_plain_text() should produce a multi-line human-readable narrative."""
        nlg = SecurityNLGEngine()
        alert = nlg.narrate_brute_force("5.6.7.8", "admin", 20, 60.0)
        text = alert.to_plain_text()
        self.assertIn("The Threat:", text)
        self.assertIn("Action Taken:", text)
        self.assertIn("What You Should Do:", text)
        self.assertIn("1.", text)
        self.assertIn("2.", text)
        self.assertIn("3.", text)

    def test_alert_message_to_toast_summary(self):
        """to_toast_summary() should produce a compact 2-line string."""
        nlg = SecurityNLGEngine()
        alert = nlg.narrate_brute_force("9.8.7.6", "user", 5, 10.0)
        toast = alert.to_toast_summary()
        self.assertTrue(len(toast) < 250, "Toast summary should be compact")
        self.assertIn("\n", toast)

    # ====================================================================
    # Test 7: AlertBridge End-to-End Dispatch
    # ====================================================================
    def test_alert_bridge_dispatch_fires_callback(self):
        """AlertBridge should invoke the on_alert_callback with a SecurityAlertMessage."""
        received = []
        bridge = AlertBridge(
            enable_desktop_notifications=False,
            on_alert_callback=lambda alert: received.append(alert),
        )

        mock_bf = MockBruteForceAlert()
        bridge.on_brute_force_alert(mock_bf)

        self.assertEqual(len(received), 1)
        self.assertIsInstance(received[0], SecurityAlertMessage)
        self.assertEqual(received[0].alert_type, "BRUTE_FORCE")

    # ====================================================================
    # Test 8: AlertBridge + Phase 1 BruteForceAlert Integration
    # ====================================================================
    def test_bridge_brute_force_integration(self):
        """Bridge should correctly extract fields from a BruteForceAlert."""
        bridge = AlertBridge(enable_desktop_notifications=False)
        mock_bf = MockBruteForceAlert(
            source_ip="192.168.1.100",
            target_user="LocalAdmin",
            attempt_count=25,
            window_seconds=55.0,
        )
        bridge.on_brute_force_alert(mock_bf)

        self.assertEqual(bridge.alert_count, 1)
        history = bridge.alert_history
        self.assertIn("192.168.1.100", history[0]["threat_description"])
        self.assertIn("25", history[0]["threat_description"])

    # ====================================================================
    # Test 9: AlertBridge + Phase 2 MaliciousFileAlert Integration
    # ====================================================================
    def test_bridge_malicious_file_integration(self):
        """Bridge should correctly translate a MaliciousFileAlert into NLG."""
        bridge = AlertBridge(enable_desktop_notifications=False)
        mock_mf = MockMaliciousFileAlert()
        bridge.on_malicious_file_alert(mock_mf)

        self.assertEqual(bridge.alert_count, 1)
        history = bridge.alert_history
        self.assertEqual(history[0]["alert_type"], "MALICIOUS_FILE")
        self.assertIn("payload.exe", history[0]["threat_description"])

    # ====================================================================
    # Test 10: AlertBridge + Phase 3 FilelessThreatAlert Integration
    # ====================================================================
    def test_bridge_fileless_threat_integration(self):
        """Bridge should correctly translate a FilelessThreatAlert into NLG."""
        bridge = AlertBridge(enable_desktop_notifications=False)
        mock_ft = MockFilelessThreatAlert()
        bridge.on_fileless_threat_alert(mock_ft)

        self.assertEqual(bridge.alert_count, 1)
        history = bridge.alert_history
        self.assertEqual(history[0]["alert_type"], "FILELESS_THREAT")
        self.assertIn("scrcons.exe", history[0]["threat_description"])

    # ====================================================================
    # Test 11: AlertBridge Alert History & Telemetry Summary
    # ====================================================================
    def test_bridge_telemetry_summary(self):
        """get_telemetry_summary() should produce correct aggregate counts."""
        bridge = AlertBridge(enable_desktop_notifications=False)

        # Fire 3 different alert types
        bridge.on_brute_force_alert(MockBruteForceAlert())
        bridge.on_brute_force_alert(MockBruteForceAlert())
        bridge.on_malicious_file_alert(MockMaliciousFileAlert())
        bridge.on_fileless_threat_alert(MockFilelessThreatAlert())

        summary = bridge.get_telemetry_summary()
        self.assertEqual(summary["total_alerts"], 4)
        self.assertEqual(summary["alert_type_counts"]["BRUTE_FORCE"], 2)
        self.assertEqual(summary["alert_type_counts"]["MALICIOUS_FILE"], 1)
        self.assertEqual(summary["alert_type_counts"]["FILELESS_THREAT"], 1)
        self.assertIsNotNone(summary["last_alert"])

    # ====================================================================
    # Test 12: AlertBridge + Phase 4 Quarantine/Firewall Integration
    # ====================================================================
    def test_bridge_quarantine_integration(self):
        """Bridge should produce a QUARANTINE alert for quarantine records."""
        bridge = AlertBridge(enable_desktop_notifications=False)
        mock_qr = MockQuarantineRecord()
        bridge.on_quarantine_action(mock_qr)

        self.assertEqual(bridge.alert_count, 1)
        history = bridge.alert_history
        self.assertEqual(history[0]["alert_type"], "QUARANTINE")
        self.assertIn("trojan.dll", history[0]["threat_description"])

    def test_bridge_firewall_block_integration(self):
        """Bridge should produce a FIREWALL alert for IP blocks."""
        bridge = AlertBridge(enable_desktop_notifications=False)
        bridge.on_firewall_block(
            ip="10.0.0.99",
            rule_name="FixAI-Block-10.0.0.99",
            reason="Brute-force intrusion attempt",
        )

        self.assertEqual(bridge.alert_count, 1)
        history = bridge.alert_history
        self.assertEqual(history[0]["alert_type"], "FIREWALL")
        self.assertIn("10.0.0.99", history[0]["threat_description"])

    # ====================================================================
    # Test 13: DesktopNotifier Initialization (Non-Crashing)
    # ====================================================================
    def test_desktop_notifier_init_does_not_crash(self):
        """DesktopNotifier should initialize without raising exceptions."""
        try:
            notifier = DesktopNotifier()
            self.assertIsNotNone(notifier)
        except Exception as e:
            self.fail(f"DesktopNotifier() raised {e}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
