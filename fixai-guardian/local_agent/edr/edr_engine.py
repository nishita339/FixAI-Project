"""
FixAI EDR — Unified Endpoint Detection & Response (EDR) Engine
===============================================================

Orchestrates the entire cybersecurity detection, threat hunting,
and autonomic self-healing lifecycle:
  1. Event Log Harvesting & Drain parsing
  2. Shannon Entropy & Heuristic file analysis
  3. WMI Persistence & LotL process hierarchy hunting
  4. 4-Phase Guarded Quarantine State Machine
  5. Plain-English NLG Alerting over Session 0 IPC bridge
"""

from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .drain_parser import DrainParser
from .entropy_scanner import EntropyScanner, EntropyScanResult
from .event_log_monitor import EventLogMonitor, SecurityEvent
from .nlg_narrative import NLGNarrativeEngine, SecurityNarrative
from .quarantine_vault import QuarantineVault
from .wmi_persistence_hunter import WmiPersistenceHunter

logger = logging.getLogger("fixai.edr")


class EDREngine:
    """
    Central EDR coordinator that couples host telemetry observation
    with real-time intrusion detection and guarded threat neutralization.
    """

    def __init__(
        self,
        on_security_alert: Optional[Callable[[SecurityNarrative], None]] = None,
        entropy_threshold: float = 7.15,
        brute_force_window: int = 60,
    ):
        self.on_security_alert = on_security_alert
        self.drain_parser = DrainParser()
        self.event_log_monitor = EventLogMonitor(brute_force_window_seconds=brute_force_window)
        self.entropy_scanner = EntropyScanner(entropy_threshold=entropy_threshold)
        self.wmi_hunter = WmiPersistenceHunter()
        self.vault = QuarantineVault()
        self.nlg = NLGNarrativeEngine()

        self._recent_threats: List[Dict[str, Any]] = []
        self._scanned_files_cache: set[str] = set()

        logger.info("🛡️ FixAI Unified EDR Engine initialized.")

    def inspect_file(self, file_path: Path | str, auto_quarantine: bool = True) -> Optional[EntropyScanResult]:
        """
        Inspect a newly created or modified file:
          1. Calculate Shannon Entropy & check heuristic signatures.
          2. If MALICIOUS and auto_quarantine is True:
             - Run Guarded 4-Phase Quarantine State Machine.
             - Generate plain-English NLG narrative alert.
             - Dispatch alert callback for desktop toast dispatch.
        """
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            return None

        # Check only executables, libraries, and script types
        scannable_exts = {
            ".exe", ".dll", ".bin", ".scr", ".bat", ".cmd",
            ".ps1", ".vbs", ".js", ".hta", ".wsf",
        }
        if p.suffix.lower() not in scannable_exts:
            return None

        scan_res = self.entropy_scanner.scan_file(p)
        if not scan_res:
            return None

        if scan_res.threat_level == "MALICIOUS":
            logger.warning(
                "🚨 MALICIOUS FILE INTERCEPTED: %s (Entropy: %.2f, Matches: %s)",
                p.name, scan_res.entropy, scan_res.heuristic_matches,
            )

            if auto_quarantine:
                # Execute Phase 2 -> Phase 3 Guarded Quarantine
                artifact = self.vault.quarantine_file(
                    p,
                    reason=f"High entropy ({scan_res.entropy}) + Heuristics: {scan_res.heuristic_matches}",
                )
                if artifact:
                    narrative = self.nlg.generate_malicious_file_narrative(
                        p.name, scan_res.entropy, scan_res.sha256,
                    )
                    self._dispatch_alert(narrative)
                    self._recent_threats.append({
                        "type": "MALICIOUS_FILE_QUARANTINED",
                        "path": str(p),
                        "sha256": scan_res.sha256,
                        "quarantine_id": artifact.quarantine_id,
                        "entropy": scan_res.entropy,
                        "narrative": narrative.to_dict(),
                        "timestamp": time.time(),
                    })

        elif scan_res.threat_level == "SUSPICIOUS":
            logger.info("⚠️ Suspicious file flagged: %s (Entropy: %.2f)", p.name, scan_res.entropy)

        return scan_res

    def run_detection_tick(self) -> Dict[str, Any]:
        """
        Execute one complete detection cycle:
          - Harvest security event logs and analyze failed logon velocity.
          - Scan WMI repositories for fileless persistence bindings.
          - Inspect process hierarchies for LotL exploitation.
        """
        tick_start = time.time()

        # 1. Harvest & Analyze Event Logs
        events = self.event_log_monitor.harvest_events()
        event_analysis = self.event_log_monitor.analyze_event_stream(events)

        # Dispatch alerts for event log threats
        for threat in event_analysis.get("threats", []):
            threat_type = threat.get("threat_type")
            if threat_type == "BRUTE_FORCE_COMPROMISE":
                ip = threat.get("source_ip", "Unknown")
                count = threat.get("failure_count", 5)
                # Auto-firewall containment
                self.vault.sever_network_c2(remote_ip=ip)
                narrative = self.nlg.generate_brute_force_narrative(ip, count, compromised=True)
                self._dispatch_alert(narrative)
            elif threat_type == "ACTIVE_BRUTE_FORCE_ATTACK":
                ip = threat.get("source_ip", "Unknown")
                count = threat.get("failure_count", 5)
                self.vault.sever_network_c2(remote_ip=ip)
                narrative = self.nlg.generate_brute_force_narrative(ip, count, compromised=False)
                self._dispatch_alert(narrative)
            elif threat_type == "UNEXPECTED_KERNEL_PANIC":
                narrative = self.nlg.generate_kernel_panic_narrative()
                self._dispatch_alert(narrative)

        # 2. WMI Persistence Hunt
        wmi_threats = self.wmi_hunter.scan_wmi_subscriptions()
        for wt in wmi_threats:
            narrative = self.nlg.generate_wmi_persistence_narrative(wt.name, wt.command_or_script)
            self._dispatch_alert(narrative)
            self._recent_threats.append({
                "type": "WMI_PERSISTENCE_DETECTED",
                "name": wt.name,
                "consumer": wt.consumer_type,
                "narrative": narrative.to_dict(),
                "timestamp": time.time(),
            })

        # 3. LotL Process Hierarchy Anomaly Check
        lotl_anomalies = self.wmi_hunter.scan_anomalous_process_hierarchies()
        for la in lotl_anomalies:
            pid = la.get("pid")
            if pid:
                # Phase 1: Suspend active malicious process in memory
                self.vault.isolate_process(pid)

            narrative = SecurityNarrative(
                title="WMI LotL Execution Hijack Intercepted",
                threat=la.get("description", "Anomalous process hierarchy detected."),
                action_taken=f"Process PID {pid} suspended in memory to prevent payload execution.",
                actionable_steps=[
                    "Inspect the running process tree in Task Manager.",
                    "Review active WMI subscriptions using the FixAI Recovery Console.",
                    "Authorize remediation to permanently terminate the rogue process.",
                ],
                severity="CRITICAL",
            )
            self._dispatch_alert(narrative)

        elapsed_ms = (time.time() - tick_start) * 1000

        # Construct comprehensive EDR Telemetry block
        return {
            "elapsed_ms": round(elapsed_ms, 1),
            "event_log_metrics": {
                "failed_logon_velocity": event_analysis.get("recent_failed_logon_velocity", 0),
                "auth_failures": event_analysis.get("auth_failures_in_tick", 0),
                "auth_successes": event_analysis.get("auth_successes_in_tick", 0),
                "unexpected_shutdowns": event_analysis.get("unexpected_shutdowns", 0),
            },
            "wmi_persistence_threats_count": len(wmi_threats),
            "lotl_anomalies_count": len(lotl_anomalies),
            "active_threats_count": len(event_analysis.get("threats", [])) + len(wmi_threats) + len(lotl_anomalies),
            "quarantined_artifacts_count": len(self.vault.list_quarantined_artifacts()),
            "threat_summary": [t["type"] for t in self._recent_threats[-5:]],
            "status": "SECURE" if (len(wmi_threats) == 0 and len(lotl_anomalies) == 0 and not event_analysis.get("has_active_threat")) else "ELEVATED",
        }

    def _dispatch_alert(self, narrative: SecurityNarrative) -> None:
        """Forward alert to the configured callback."""
        if self.on_security_alert:
            try:
                self.on_security_alert(narrative)
            except Exception as e:
                logger.warning("Error dispatching security alert callback: %s", e)
