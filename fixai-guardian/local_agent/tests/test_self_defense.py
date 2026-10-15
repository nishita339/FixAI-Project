"""
FixAI Improvement #8 — Agent Self-Defense & Anti-Tamper Test Suite
===================================================================

Tests for:
- Cryptographic SHA-256 calculation of protected assets
- Registration and unregistration of critical files
- Detection of file modifications (hash mismatch)
- Detection of file deletions (asset missing)
- Heartbeat emission, sequence increment, and disk persistence
- Heartbeat health verification and timeout detection
- Guardian start/stop lifecycle
- Status telemetry generation
- Plain-English NLG narration for tamper alerts
- AlertBridge integration via on_agent_tamper_alert callback
"""

import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock

# Ensure the local_agent package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from security.self_defense import (
    AgentSelfDefense,
    TamperIncident,
)
from security.alert_bridge import (
    AlertBridge,
    SecurityAlertMessage,
    SecurityNLGEngine,
)


class TestSelfDefenseFIM(unittest.TestCase):
    """File Integrity Monitoring tests for protected agent assets."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="fixai_selfdef_test_")
        self.test_file = os.path.join(self.temp_dir, "agent_core.py")
        with open(self.test_file, "w") as f:
            f.write("# FixAI Core Agent Logic\nVERSION = '1.0.0'\n")

        self.heartbeat_file = os.path.join(self.temp_dir, "test.heartbeat")
        self.alerts = []
        self.defense = AgentSelfDefense(
            protected_files=[self.test_file],
            heartbeat_file=self.heartbeat_file,
            heartbeat_timeout=2.0,
            alert_callback=lambda a: self.alerts.append(a),
        )

    def tearDown(self):
        self.defense.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_calculate_file_hash(self):
        h = AgentSelfDefense.calculate_file_hash(self.test_file)
        self.assertIsNotNone(h)
        self.assertEqual(len(h), 64)

    def test_calculate_hash_missing_file_returns_none(self):
        missing = os.path.join(self.temp_dir, "nonexistent.file")
        self.assertIsNone(AgentSelfDefense.calculate_file_hash(missing))

    def test_register_protected_file(self):
        new_file = os.path.join(self.temp_dir, "model.joblib")
        with open(new_file, "wb") as f:
            f.write(b"BINARY_MODEL_DATA_MAGIC_1234")

        success = self.defense.register_protected_file(new_file)
        self.assertTrue(success)
        self.assertIn(os.path.abspath(new_file), self.defense._file_baselines)

    def test_register_missing_file_fails(self):
        success = self.defense.register_protected_file("C:\\fake_path_12345.bin")
        self.assertFalse(success)

    def test_unregister_protected_file(self):
        abs_p = os.path.abspath(self.test_file)
        self.assertTrue(self.defense.unregister_protected_file(abs_p))
        self.assertNotIn(abs_p, self.defense._file_baselines)
        # Second call returns False
        self.assertFalse(self.defense.unregister_protected_file(abs_p))

    def test_verify_integrity_clean(self):
        incidents = self.defense.verify_integrity()
        self.assertEqual(len(incidents), 0)
        self.assertEqual(len(self.alerts), 0)

    def test_verify_integrity_detects_modification(self):
        # Tamper with the protected file
        with open(self.test_file, "a") as f:
            f.write("# INJECTED MALICIOUS CODE BY ADVERSARY\n")

        incidents = self.defense.verify_integrity()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(len(self.alerts), 1)

        inc = incidents[0]
        self.assertEqual(inc.tamper_type, "FILE_MODIFIED")
        self.assertEqual(inc.severity, "CRITICAL")
        self.assertIn("T1562.001", inc.mitre_technique)
        self.assertIsNotNone(inc.expected_sha256)
        self.assertIsNotNone(inc.actual_sha256)
        self.assertNotEqual(inc.expected_sha256, inc.actual_sha256)

    def test_verify_integrity_detects_deletion(self):
        os.remove(self.test_file)
        incidents = self.defense.verify_integrity()
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.tamper_type, "FILE_DELETED")
        self.assertEqual(inc.severity, "CRITICAL")
        self.assertIsNone(inc.actual_sha256)

    def test_multiple_files_integrity(self):
        f2 = os.path.join(self.temp_dir, "rules.yar")
        with open(f2, "w") as f:
            f.write("rule Test { condition: true }")
        self.defense.register_protected_file(f2)

        # Modify both
        with open(self.test_file, "w") as f:
            f.write("modified1")
        with open(f2, "w") as f:
            f.write("modified2")

        incidents = self.defense.verify_integrity()
        self.assertEqual(len(incidents), 2)


class TestHeartbeatAndAntiKill(unittest.TestCase):
    """Process heartbeat and watchdog tests."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="fixai_hb_test_")
        self.heartbeat_file = os.path.join(self.temp_dir, "agent.heartbeat")
        self.alerts = []
        self.defense = AgentSelfDefense(
            heartbeat_file=self.heartbeat_file,
            heartbeat_timeout=1.0,
            alert_callback=lambda a: self.alerts.append(a),
        )

    def tearDown(self):
        self.defense.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_emit_heartbeat_updates_state_and_file(self):
        self.defense.emit_heartbeat()
        self.assertEqual(self.defense._heartbeat_sequence, 1)
        self.assertTrue(os.path.exists(self.heartbeat_file))
        with open(self.heartbeat_file, "r") as f:
            content = f.read()
        self.assertIn("PID=", content)
        self.assertIn("SEQ=1", content)

    def test_check_heartbeat_healthy_initially(self):
        self.defense.emit_heartbeat()
        healthy, elapsed = self.defense.check_heartbeat()
        self.assertTrue(healthy)
        self.assertLess(elapsed, 0.5)

    def test_check_heartbeat_detects_timeout(self):
        self.defense.emit_heartbeat()
        # Simulate time jump 5.0 seconds into the future
        future_time = self.defense._last_heartbeat + 5.0
        healthy, elapsed = self.defense.check_heartbeat(current_time=future_time)
        self.assertFalse(healthy)
        self.assertGreaterEqual(elapsed, 5.0)

    def test_report_heartbeat_failure(self):
        inc = self.defense.report_heartbeat_failure(elapsed=6.5)
        self.assertEqual(inc.tamper_type, "HEARTBEAT_TIMEOUT")
        self.assertEqual(inc.severity, "CRITICAL")
        self.assertIn("ceased", inc.description.lower())
        self.assertEqual(len(self.alerts), 1)

    def test_lifecycle_start_stop(self):
        self.defense.start()
        self.assertTrue(self.defense.is_running)
        time.sleep(0.1)
        self.defense.stop()
        self.assertFalse(self.defense.is_running)


class TestDefenseStatusAndTelemetry(unittest.TestCase):
    """Telemetry and status report tests."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="fixai_status_test_")
        self.test_file = os.path.join(self.temp_dir, "guard.py")
        with open(self.test_file, "w") as f:
            f.write("# Guardian")
        self.defense = AgentSelfDefense(
            protected_files=[self.test_file],
            heartbeat_file=os.path.join(self.temp_dir, "hb.dat"),
        )

    def tearDown(self):
        self.defense.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_get_defense_status(self):
        self.defense.emit_heartbeat()
        status = self.defense.get_defense_status()
        self.assertIn("guardian_active", status)
        self.assertIn("heartbeat_healthy", status)
        self.assertTrue(status["heartbeat_healthy"])
        self.assertEqual(status["protected_assets_count"], 1)
        self.assertEqual(status["total_tamper_incidents"], 0)

    def test_status_records_incident(self):
        os.remove(self.test_file)
        self.defense.verify_integrity()
        status = self.defense.get_defense_status()
        self.assertEqual(status["total_tamper_incidents"], 1)
        self.assertIsNotNone(status["latest_incident"])
        self.assertEqual(status["latest_incident"]["tamper_type"], "FILE_DELETED")


class TestSelfDefenseNLGAndAlertBridge(unittest.TestCase):
    """Tests for NLG narration and AlertBridge integration."""

    def test_narrate_file_deleted(self):
        msg = SecurityNLGEngine.narrate_agent_tamper(
            tamper_type="FILE_DELETED",
            target_path="C:\\FixAI\\models\\telemetry.joblib",
        )
        self.assertEqual(msg.severity, "CRITICAL")
        self.assertEqual(msg.alert_type, "AGENT_TAMPER")
        self.assertIn("Deleted", msg.title)
        self.assertIn("telemetry.joblib", msg.threat_description)
        self.assertEqual(msg.source_module, "self_defense")

    def test_narrate_file_modified(self):
        msg = SecurityNLGEngine.narrate_agent_tamper(
            tamper_type="FILE_MODIFIED",
            target_path="C:\\FixAI\\security\\quarantine.py",
            expected_sha256="abcdef1234567890abcdef1234567890",
            actual_sha256="123456abcdef7890123456abcdef7890",
        )
        self.assertEqual(msg.alert_type, "AGENT_TAMPER")
        self.assertIn("Modified", msg.title)
        self.assertIn("mismatch", msg.threat_description)

    def test_narrate_heartbeat_timeout(self):
        msg = SecurityNLGEngine.narrate_agent_tamper(
            tamper_type="HEARTBEAT_TIMEOUT",
            description="No signal received for 8.0s",
        )
        self.assertIn("TIMEOUT", msg.title)
        self.assertIn("heartbeat ceased", msg.threat_description.lower())

    def test_alert_bridge_on_agent_tamper_alert(self):
        bridge = AlertBridge()
        incident = TamperIncident(
            alert_id="test-tamper-001",
            timestamp="2026-10-16T00:00:00Z",
            tamper_type="FILE_MODIFIED",
            target_path="C:\\FixAI\\main.py",
            expected_sha256="aaa",
            actual_sha256="bbb",
            severity="CRITICAL",
            mitre_technique="T1562.001",
            description="Modified",
        )
        bridge.on_agent_tamper_alert(incident)
        self.assertEqual(bridge.alert_count, 1)
        latest = bridge.alert_history[0]
        self.assertEqual(latest["alert_type"], "AGENT_TAMPER")
        self.assertEqual(latest["severity"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
