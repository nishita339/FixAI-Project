"""
FixAI EDR — Improvement #2: Ransomware Canary Tests
=====================================================

Tests for the honeypot canary file ransomware detection system:
- Canary deployment and cleanup
- SHA-256 integrity verification
- Watchdog event handler alerting
- AlertBridge integration
- Edge cases
"""

import os
import sys
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure the local_agent directory is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security.ransomware_canary import (
    RansomwareCanary,
    RansomwareCanaryAlert,
    CanaryRecord,
    CANARY_MAGIC,
    CANARY_TEMPLATES,
    compute_sha256,
    compute_content_sha256,
    _CanaryEventHandler,
)


class TestCanaryConstants(unittest.TestCase):
    """Test canary constants and magic values."""

    def test_canary_magic_exists(self):
        self.assertIn("FIXAI-CANARY", CANARY_MAGIC)

    def test_canary_templates_not_empty(self):
        self.assertGreater(len(CANARY_TEMPLATES), 0)

    def test_all_templates_have_magic(self):
        """Every canary template must embed the magic string."""
        for template in CANARY_TEMPLATES:
            self.assertIn(CANARY_MAGIC, template["content"])

    def test_all_templates_have_filename_and_content(self):
        for template in CANARY_TEMPLATES:
            self.assertIn("filename", template)
            self.assertIn("content", template)
            self.assertTrue(len(template["filename"]) > 0)
            self.assertTrue(len(template["content"]) > 0)

    def test_templates_have_realistic_names(self):
        """Filenames should look like real documents."""
        filenames = [t["filename"] for t in CANARY_TEMPLATES]
        # At least one should contain common document-like words
        all_names = " ".join(filenames).lower()
        self.assertTrue(
            any(word in all_names for word in ["financial", "tax", "password", "confidential"]),
            f"Canary filenames should look realistic: {filenames}"
        )


class TestSHA256Helpers(unittest.TestCase):
    """Test SHA-256 computation helpers."""

    def test_compute_sha256_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("test content")
            f.flush()
            path = f.name
        try:
            sha = compute_sha256(path)
            self.assertEqual(len(sha), 64)  # SHA-256 hex digest length
            self.assertTrue(all(c in "0123456789abcdef" for c in sha))
        finally:
            os.unlink(path)

    def test_compute_sha256_nonexistent(self):
        sha = compute_sha256("/nonexistent/file.txt")
        self.assertEqual(sha, "")

    def test_compute_content_sha256(self):
        sha = compute_content_sha256("hello world")
        self.assertEqual(len(sha), 64)
        # Known SHA-256 for "hello world"
        self.assertEqual(sha, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")

    def test_same_content_same_hash(self):
        h1 = compute_content_sha256("identical")
        h2 = compute_content_sha256("identical")
        self.assertEqual(h1, h2)

    def test_different_content_different_hash(self):
        h1 = compute_content_sha256("content A")
        h2 = compute_content_sha256("content B")
        self.assertNotEqual(h1, h2)


class TestCanaryDeployment(unittest.TestCase):
    """Test canary file deployment and cleanup."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="fixai_canary_test_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_deploy_creates_files(self):
        canary = RansomwareCanary(canary_dirs=[self.test_dir])
        deployed = canary.deploy()
        self.assertEqual(deployed, len(CANARY_TEMPLATES))
        for template in CANARY_TEMPLATES:
            filepath = os.path.join(self.test_dir, template["filename"])
            self.assertTrue(os.path.exists(filepath), f"Missing: {filepath}")

    def test_deployed_files_contain_magic(self):
        canary = RansomwareCanary(canary_dirs=[self.test_dir])
        canary.deploy()
        for template in CANARY_TEMPLATES:
            filepath = os.path.join(self.test_dir, template["filename"])
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn(CANARY_MAGIC, content)

    def test_deploy_records_sha256(self):
        canary = RansomwareCanary(canary_dirs=[self.test_dir])
        canary.deploy()
        for record in canary.deployed_canaries:
            self.assertEqual(len(record.sha256), 64)
            self.assertGreater(record.content_length, 0)

    def test_canary_count(self):
        canary = RansomwareCanary(canary_dirs=[self.test_dir])
        canary.deploy()
        self.assertEqual(canary.canary_count, len(CANARY_TEMPLATES))

    def test_deploy_skips_nonexistent_dirs(self):
        canary = RansomwareCanary(canary_dirs=["/nonexistent/path"])
        deployed = canary.deploy()
        self.assertEqual(deployed, 0)

    def test_deploy_idempotent(self):
        """Deploying twice should not re-create already deployed canaries."""
        canary = RansomwareCanary(canary_dirs=[self.test_dir])
        first = canary.deploy()
        second = canary.deploy()
        self.assertEqual(first, len(CANARY_TEMPLATES))
        self.assertEqual(second, 0)

    def test_cleanup_removes_files(self):
        canary = RansomwareCanary(canary_dirs=[self.test_dir])
        canary.deploy()
        removed = canary.cleanup()
        self.assertEqual(removed, len(CANARY_TEMPLATES))
        for template in CANARY_TEMPLATES:
            filepath = os.path.join(self.test_dir, template["filename"])
            self.assertFalse(os.path.exists(filepath))

    def test_cleanup_clears_records(self):
        canary = RansomwareCanary(canary_dirs=[self.test_dir])
        canary.deploy()
        canary.cleanup()
        self.assertEqual(canary.canary_count, 0)
        self.assertEqual(len(canary.deployed_canaries), 0)

    def test_deploy_multiple_dirs(self):
        dir2 = tempfile.mkdtemp(prefix="fixai_canary_test2_")
        try:
            canary = RansomwareCanary(canary_dirs=[self.test_dir, dir2])
            deployed = canary.deploy()
            self.assertEqual(deployed, len(CANARY_TEMPLATES) * 2)
        finally:
            shutil.rmtree(dir2, ignore_errors=True)

    def test_custom_templates(self):
        custom = [{"filename": "trap.txt", "content": f"Trap data {CANARY_MAGIC}"}]
        canary = RansomwareCanary(canary_dirs=[self.test_dir], templates=custom)
        deployed = canary.deploy()
        self.assertEqual(deployed, 1)
        self.assertTrue(os.path.exists(os.path.join(self.test_dir, "trap.txt")))


class TestIntegrityVerification(unittest.TestCase):
    """Test the verify_integrity method."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="fixai_canary_integ_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_all_intact(self):
        canary = RansomwareCanary(canary_dirs=[self.test_dir])
        canary.deploy()
        result = canary.verify_integrity()
        self.assertEqual(result["intact"], len(CANARY_TEMPLATES))
        self.assertEqual(result["modified"], 0)
        self.assertEqual(result["missing"], 0)

    def test_detect_modified(self):
        canary = RansomwareCanary(canary_dirs=[self.test_dir])
        canary.deploy()
        # Tamper with first canary
        first_record = canary.deployed_canaries[0]
        with open(first_record.filepath, "w") as f:
            f.write("ENCRYPTED BY RANSOMWARE")
        result = canary.verify_integrity()
        self.assertEqual(result["modified"], 1)
        self.assertEqual(result["intact"], len(CANARY_TEMPLATES) - 1)

    def test_detect_deleted(self):
        canary = RansomwareCanary(canary_dirs=[self.test_dir])
        canary.deploy()
        first_record = canary.deployed_canaries[0]
        os.remove(first_record.filepath)
        result = canary.verify_integrity()
        self.assertEqual(result["missing"], 1)

    def test_alerts_list_populated(self):
        canary = RansomwareCanary(canary_dirs=[self.test_dir])
        canary.deploy()
        first_record = canary.deployed_canaries[0]
        os.remove(first_record.filepath)
        result = canary.verify_integrity()
        self.assertEqual(len(result["alerts"]), 1)
        self.assertEqual(result["alerts"][0]["status"], "MISSING")


class TestCanaryEventHandler(unittest.TestCase):
    """Test the watchdog event handler directly."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="fixai_canary_handler_")
        self.alerts = []
        self.canary = RansomwareCanary(
            canary_dirs=[self.test_dir],
            on_alert=lambda a: self.alerts.append(a),
        )
        self.canary.deploy()

    def tearDown(self):
        self.canary.cleanup()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_handler_detects_modification(self):
        """Handler should fire alert when canary content changes."""
        handler = _CanaryEventHandler(self.canary._canary_records, lambda a: self.alerts.append(a))
        first_record = self.canary.deployed_canaries[0]
        # Modify canary file
        with open(first_record.filepath, "w") as f:
            f.write("RANSOMWARE ENCRYPTED")
        # Simulate watchdog event
        mock_event = MagicMock()
        mock_event.is_directory = False
        mock_event.src_path = first_record.filepath
        handler.on_modified(mock_event)
        self.assertEqual(len(self.alerts), 1)
        self.assertEqual(self.alerts[0].event_type, "MODIFIED")

    def test_handler_detects_deletion(self):
        handler = _CanaryEventHandler(self.canary._canary_records, lambda a: self.alerts.append(a))
        first_record = self.canary.deployed_canaries[0]
        mock_event = MagicMock()
        mock_event.is_directory = False
        mock_event.src_path = first_record.filepath
        handler.on_deleted(mock_event)
        self.assertEqual(len(self.alerts), 1)
        self.assertEqual(self.alerts[0].event_type, "DELETED")

    def test_handler_detects_move(self):
        handler = _CanaryEventHandler(self.canary._canary_records, lambda a: self.alerts.append(a))
        first_record = self.canary.deployed_canaries[0]
        mock_event = MagicMock()
        mock_event.is_directory = False
        mock_event.src_path = first_record.filepath
        handler.on_moved(mock_event)
        self.assertEqual(len(self.alerts), 1)
        self.assertEqual(self.alerts[0].event_type, "MOVED")

    def test_handler_ignores_non_canary_files(self):
        handler = _CanaryEventHandler(self.canary._canary_records, lambda a: self.alerts.append(a))
        mock_event = MagicMock()
        mock_event.is_directory = False
        mock_event.src_path = os.path.join(self.test_dir, "random_file.txt")
        handler.on_modified(mock_event)
        handler.on_deleted(mock_event)
        handler.on_moved(mock_event)
        self.assertEqual(len(self.alerts), 0)

    def test_handler_ignores_directories(self):
        handler = _CanaryEventHandler(self.canary._canary_records, lambda a: self.alerts.append(a))
        mock_event = MagicMock()
        mock_event.is_directory = True
        mock_event.src_path = self.test_dir
        handler.on_modified(mock_event)
        self.assertEqual(len(self.alerts), 0)

    def test_handler_no_duplicate_alerts(self):
        """Same file should only alert once."""
        handler = _CanaryEventHandler(self.canary._canary_records, lambda a: self.alerts.append(a))
        first_record = self.canary.deployed_canaries[0]
        mock_event = MagicMock()
        mock_event.is_directory = False
        mock_event.src_path = first_record.filepath
        handler.on_deleted(mock_event)
        handler.on_deleted(mock_event)
        self.assertEqual(len(self.alerts), 1)

    def test_handler_no_alert_if_content_unchanged(self):
        """Modified event with same SHA should NOT trigger alert."""
        handler = _CanaryEventHandler(self.canary._canary_records, lambda a: self.alerts.append(a))
        first_record = self.canary.deployed_canaries[0]
        mock_event = MagicMock()
        mock_event.is_directory = False
        mock_event.src_path = first_record.filepath
        # File content is unchanged — SHA matches
        handler.on_modified(mock_event)
        self.assertEqual(len(self.alerts), 0)


class TestRansomwareCanaryAlert(unittest.TestCase):
    """Test the RansomwareCanaryAlert dataclass."""

    def test_alert_has_critical_severity(self):
        alert = RansomwareCanaryAlert()
        self.assertEqual(alert.severity, "CRITICAL")

    def test_alert_to_dict(self):
        alert = RansomwareCanaryAlert(
            event_type="DELETED",
            canary_filename="test.txt",
            canary_path="/tmp/test.txt",
        )
        d = alert.to_dict()
        self.assertEqual(d["event_type"], "DELETED")
        self.assertEqual(d["canary_filename"], "test.txt")
        self.assertIn("alert_id", d)
        self.assertIn("timestamp", d)

    def test_alert_id_unique(self):
        a1 = RansomwareCanaryAlert()
        a2 = RansomwareCanaryAlert()
        self.assertNotEqual(a1.alert_id, a2.alert_id)


class TestTelemetrySummary(unittest.TestCase):
    """Test telemetry summary generation."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="fixai_canary_telem_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_summary_keys(self):
        canary = RansomwareCanary(canary_dirs=[self.test_dir])
        canary.deploy()
        summary = canary.get_telemetry_summary()
        self.assertIn("canary_monitoring_active", summary)
        self.assertIn("total_canaries", summary)
        self.assertIn("canaries_intact", summary)
        self.assertIn("canaries_tampered", summary)
        self.assertIn("monitored_directories", summary)

    def test_summary_intact(self):
        canary = RansomwareCanary(canary_dirs=[self.test_dir])
        canary.deploy()
        summary = canary.get_telemetry_summary()
        self.assertEqual(summary["total_canaries"], len(CANARY_TEMPLATES))
        self.assertEqual(summary["canaries_intact"], len(CANARY_TEMPLATES))
        self.assertEqual(summary["canaries_tampered"], 0)


class TestAlertBridgeCanaryIntegration(unittest.TestCase):
    """Test AlertBridge.on_ransomware_canary_alert integration."""

    def test_bridge_has_canary_callback(self):
        from security.alert_bridge import AlertBridge
        bridge = AlertBridge(enable_desktop_notifications=False)
        self.assertTrue(hasattr(bridge, "on_ransomware_canary_alert"))
        self.assertTrue(callable(bridge.on_ransomware_canary_alert))

    def test_bridge_dispatches_canary_alert(self):
        from security.alert_bridge import AlertBridge
        from security.webhook_notifier import WebhookConfig

        dispatched = []
        bridge = AlertBridge(
            enable_desktop_notifications=False,
            on_alert_callback=lambda a: dispatched.append(a),
            webhook_config=WebhookConfig(),  # No webhooks
        )
        alert = RansomwareCanaryAlert(
            event_type="DELETED",
            canary_filename="Important_Financial_Report_2026.pdf.txt",
            canary_path="C:\\Users\\test\\Desktop\\Important_Financial_Report_2026.pdf.txt",
            original_sha256="abc123",
            canary_dir="C:\\Users\\test\\Desktop",
        )
        bridge.on_ransomware_canary_alert(alert)
        self.assertEqual(len(dispatched), 1)
        self.assertEqual(dispatched[0].severity, "CRITICAL")
        self.assertEqual(dispatched[0].alert_type, "RANSOMWARE_CANARY")
        self.assertIn("RANSOMWARE DETECTED", dispatched[0].title)

    def test_nlg_narrate_ransomware_canary(self):
        from security.alert_bridge import SecurityNLGEngine
        msg = SecurityNLGEngine.narrate_ransomware_canary(
            event_type="MODIFIED",
            canary_filename="Tax_Documents.xlsx",
            canary_path="C:\\Documents\\Tax_Documents.xlsx",
            original_sha256="deadbeef",
            canary_dir="C:\\Documents",
        )
        self.assertEqual(msg.severity, "CRITICAL")
        self.assertIn("ransomware", msg.threat_description.lower())
        self.assertIn("IMMEDIATELY disconnect", msg.actionable_steps[0])


if __name__ == "__main__":
    unittest.main()
