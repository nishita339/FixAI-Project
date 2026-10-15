"""
FixAI Improvement #10 — Windows Background Service Test Suite
=============================================================

Tests for:
- FixAIService initialization and path resolution
- PID file writing, validation, and removal
- Status file serialization and health checks
- Service status reporting (RUNNING / STOPPED)
- Autostart query logic
"""

import json
import os
import sys
import tempfile
import unittest

# Ensure local_agent is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from service import (
    FixAIService,
    SERVICE_NAME,
    PID_FILE,
    STATUS_FILE,
)


class TestFixAIService(unittest.TestCase):
    """Tests for the service manager."""

    def setUp(self):
        self.service = FixAIService()
        # Clean up any residual PID file
        if os.path.exists(PID_FILE):
            try:
                os.remove(PID_FILE)
            except Exception:
                pass

    def tearDown(self):
        if os.path.exists(PID_FILE):
            try:
                os.remove(PID_FILE)
            except Exception:
                pass

    def test_init_defaults(self):
        """Service should resolve the main agent entrypoint."""
        self.assertTrue(os.path.isabs(self.service.agent_script))
        self.assertTrue(self.service.agent_script.endswith("main.py"))

    def test_status_stopped_when_no_pid(self):
        """When no PID file exists, status should be STOPPED."""
        st = self.service.status()
        self.assertEqual(st["service_name"], SERVICE_NAME)
        self.assertEqual(st["status"], "STOPPED")
        self.assertIsNone(st["pid"])

    def test_write_and_remove_pid(self):
        """PID file should be written and removed accurately."""
        # Use our own current process PID as a live PID
        my_pid = os.getpid()
        self.service._write_pid(my_pid)
        self.assertTrue(os.path.exists(PID_FILE))

        # Check PID reading
        read_pid = self.service.get_running_pid()
        self.assertEqual(read_pid, my_pid)

        # Remove PID
        self.service._remove_pid()
        self.assertFalse(os.path.exists(PID_FILE))
        self.assertIsNone(self.service.get_running_pid())

    def test_update_status_file(self):
        """Status updates should persist valid JSON."""
        self.service._update_status("RUNNING", {"test_key": "val_123"})
        self.assertTrue(os.path.exists(STATUS_FILE))

        with open(STATUS_FILE, "r") as f:
            data = json.load(f)

        self.assertEqual(data["status"], "RUNNING")
        self.assertEqual(data["service_name"], SERVICE_NAME)
        self.assertEqual(data["test_key"], "val_123")

    def test_autostart_query(self):
        """Autostart query should return a boolean without throwing."""
        res = self.service.is_autostart_registered()
        self.assertIsInstance(res, bool)


if __name__ == "__main__":
    unittest.main()
