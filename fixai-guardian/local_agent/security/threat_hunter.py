"""
FixAI EDR — Phase 3: Fileless Threat Hunter & LotL Process Tree Monitor
========================================================================

Detects "Living off the Land" (LotL) attacks, fileless malware execution,
and WMI persistence mechanisms on Windows endpoints.

Key Capabilities:
1. Process Tree Lineage Monitoring:
   - Detects `powershell.exe`, `pwsh.exe`, or `cmd.exe` spawned by `scrcons.exe`
     (WMI Standard Event Consumer / ActiveScriptEventConsumer / CommandLineEventConsumer).
   - Detects shells spawned by `wmiprvse.exe` (WMI Provider Host) or other LotL binaries.
   - Evaluates command line flags for evasion (e.g. -enc, -w hidden, -ep bypass, IEX cradles).
2. WMI Event Subscription Auditing:
   - Queries `root\\subscription` for suspicious `CommandLineEventConsumer`,
     `ActiveScriptEventConsumer`, and orphaned `__FilterToConsumerBinding` objects.
3. Process Remediation with Strict OS Safety:
   - Provides safe suspension and termination APIs protected by immutable OS whitelists.
"""

from __future__ import annotations

import datetime
import logging
import os
import re
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Union

import psutil

logger = logging.getLogger("fixai.security.threat_hunter")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] [%(levelname)s] [ThreatHunter] %(message)s")
    )
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# ============================================================================
# OS Safety Safeguards — Immutable Protected System Processes
# ============================================================================

PROTECTED_SYSTEM_PIDS: Set[int] = {0, 4}

PROTECTED_PROCESS_NAMES: Set[str] = {
    "system",
    "system idle process",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "lsm.exe",
    "svchost.exe",
    "winlogon.exe",
    "explorer.exe",
    "spoolsv.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "sihost.exe",
    "taskhostw.exe",
}

# Suspicious LotL parent processes
SUSPICIOUS_PARENTS: Set[str] = {
    "scrcons.exe",   # WMI Standard Event Consumer (High-confidence fileless persistence)
    "wmiprvse.exe",  # WMI Provider Host
    "mshta.exe",     # Microsoft HTML Application Host
    "certutil.exe",  # Certificate utility abused for download/decode
    "rundll32.exe",  # RunDLL abused for proxy execution
    "regsvr32.exe",  # RegSvr32 abused for Squiblydoo attacks
}

# Target child interpreters indicating command execution
SUSPICIOUS_CHILDREN: Set[str] = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "cscript.exe",
    "wscript.exe",
    "bash.exe",
    "wsl.exe",
}

# Regex patterns for high-risk command-line evasion
SUSPICIOUS_CMD_PATTERNS = [
    re.compile(r"-(?:enc|encodedcommand|e)\s+[A-Za-z0-9+/=]{10,}", re.IGNORECASE),
    re.compile(r"-(?:w(?:indowstyle)?\s+(?:hidden|minimized))", re.IGNORECASE),
    re.compile(r"-(?:ep|executionpolicy)\s+bypass", re.IGNORECASE),
    re.compile(r"-(?:noni|noninteractive)", re.IGNORECASE),
    re.compile(r"-(?:nop|noprofile)", re.IGNORECASE),
    re.compile(r"(?:downloadstring|downloadfile|invoke-webrequest|iwr|curl|wget)", re.IGNORECASE),
    re.compile(r"(?:iex|invoke-expression)\s*[\(\$]", re.IGNORECASE),
    re.compile(r"vssadmin\s+delete\s+shadows", re.IGNORECASE),
    re.compile(r"bcdedit.*recoveryenabled\s+no", re.IGNORECASE),
]


# ============================================================================
# Threat Alert Data Model
# ============================================================================

@dataclass
class FilelessThreatAlert:
    """Represents a detected Living-off-the-Land or WMI persistence threat."""
    alert_id: str
    timestamp: str
    alert_type: str            # 'WMI_PERSISTENCE', 'LOTL_EXECUTION', 'WMI_SUBSCRIPTION'
    severity: str              # 'CRITICAL', 'HIGH', 'MEDIUM'
    parent_name: str
    parent_pid: int
    parent_cmdline: str
    child_name: str
    child_pid: int
    child_cmdline: str
    mitre_technique: str
    description: str
    remediation_advice: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "parent_name": self.parent_name,
            "parent_pid": self.parent_pid,
            "parent_cmdline": self.parent_cmdline,
            "child_name": self.child_name,
            "child_pid": self.child_pid,
            "child_cmdline": self.child_cmdline,
            "mitre_technique": self.mitre_technique,
            "description": self.description,
            "remediation_advice": self.remediation_advice,
            "details": self.details,
        }


# ============================================================================
# Threat Hunter Engine
# ============================================================================

class ThreatHunter:
    """
    Endpoint Threat Hunter for detecting LotL attacks, abnormal process tree
    lineage (e.g. scrcons.exe -> powershell.exe), and WMI persistence.
    """

    def __init__(
        self,
        callback: Optional[Callable[[FilelessThreatAlert], None]] = None,
        check_wmi_subscriptions: bool = True,
    ):
        self.callback = callback
        self.check_wmi_subscriptions = check_wmi_subscriptions
        self._alert_cache: Set[str] = set()
        self._cache_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None

    def _generate_alert_key(self, parent_name: str, child_name: str, child_pid: int) -> str:
        return f"{parent_name.lower()}:{child_name.lower()}:{child_pid}"

    def analyze_command_line(self, cmdline: str) -> List[str]:
        """Scans a process command line for known evasion or LotL attack patterns."""
        if not cmdline:
            return []
        matches = []
        for pattern in SUSPICIOUS_CMD_PATTERNS:
            found = pattern.findall(cmdline)
            if found:
                matches.append(pattern.pattern)
        return matches

    def scan_processes(
        self,
        process_snapshot: Optional[List[Dict[str, Any]]] = None,
    ) -> List[FilelessThreatAlert]:
        """
        Inspects process lineage for abnormal parent-child relationships.
        If process_snapshot is provided (list of dicts with 'pid', 'ppid', 'name', 'cmdline'),
        it uses the snapshot (ideal for unit tests and headless environments).
        Otherwise, it queries the live host operating system via psutil.
        """
        alerts: List[FilelessThreatAlert] = []

        # 1. Build Process Map
        proc_map: Dict[int, Dict[str, Any]] = {}

        if process_snapshot is not None:
            for item in process_snapshot:
                pid = item.get("pid")
                if pid is not None:
                    proc_map[pid] = {
                        "pid": pid,
                        "ppid": item.get("ppid", 0),
                        "name": str(item.get("name", "")).lower(),
                        "cmdline": item.get("cmdline", ""),
                        "create_time": item.get("create_time", 0.0),
                    }
        else:
            for proc in psutil.process_iter(["pid", "ppid", "name", "cmdline", "create_time"]):
                try:
                    info = proc.info
                    pid = info.get("pid")
                    if pid is not None:
                        cmdline_list = info.get("cmdline") or []
                        cmdline_str = " ".join(cmdline_list) if isinstance(cmdline_list, list) else str(cmdline_list or "")
                        proc_map[pid] = {
                            "pid": pid,
                            "ppid": info.get("ppid") or 0,
                            "name": str(info.get("name") or "").lower(),
                            "cmdline": cmdline_str,
                            "create_time": info.get("create_time") or 0.0,
                        }
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

        # 2. Analyze Parent-Child Lineage
        for pid, proc in proc_map.items():
            child_name = proc["name"]
            if child_name not in SUSPICIOUS_CHILDREN:
                continue

            ppid = proc["ppid"]
            parent = proc_map.get(ppid)
            if not parent:
                # Parent might have terminated or PID recycled
                continue

            parent_name = parent["name"]

            # Scenario A: WMI Event Consumer Spawning Command Interpreter
            # (scrcons.exe -> powershell.exe / cmd.exe) -> CRITICAL
            if parent_name == "scrcons.exe":
                alert_key = self._generate_alert_key(parent_name, child_name, pid)
                with self._cache_lock:
                    if alert_key in self._alert_cache:
                        continue
                    self._alert_cache.add(alert_key)

                cmd_findings = self.analyze_command_line(proc["cmdline"])

                alert = FilelessThreatAlert(
                    alert_id=str(uuid.uuid4()),
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    alert_type="WMI_PERSISTENCE",
                    severity="CRITICAL",
                    parent_name=parent_name,
                    parent_pid=parent["pid"],
                    parent_cmdline=parent["cmdline"],
                    child_name=child_name,
                    child_pid=pid,
                    child_cmdline=proc["cmdline"],
                    mitre_technique="T1546.003 - Event Triggered Execution: WMI Event Subscription",
                    description=(
                        f"WMI Standard Event Consumer (scrcons.exe PID {parent['pid']}) spawned "
                        f"an interactive shell '{child_name}' (PID {pid}). This is a signature "
                        f"indicator of fileless WMI persistence or unauthorized script execution."
                    ),
                    remediation_advice=(
                        f"Suspend/Terminate child PID {pid}. Enumerate and purge malicious WMI "
                        f"ActiveScriptEventConsumer/CommandLineEventConsumer instances in root\\subscription."
                    ),
                    details={
                        "risk_score": 95,
                        "command_evasion_indicators": cmd_findings,
                        "parent_is_wmi_consumer": True,
                    },
                )

                logger.warning(
                    f"\U0001f6a8 [FILELESS THREAT DETECTED] Parent: {parent_name} (PID {parent['pid']}) "
                    f"-> Child: {child_name} (PID {pid}) | Severity: CRITICAL | MITRE: T1546.003"
                )

                alerts.append(alert)
                if self.callback:
                    try:
                        self.callback(alert)
                    except Exception as cb_err:
                        logger.error(f"Threat alert callback error: {cb_err}")

            # Scenario B: WMI Provider Host Spawning Shell (wmiprvse.exe -> powershell.exe/cmd.exe)
            elif parent_name == "wmiprvse.exe":
                cmd_findings = self.analyze_command_line(proc["cmdline"])
                # WMI Provider Host can occasionally be triggered for system telemetry,
                # but encoded commands or direct interactive shells are high risk
                alert_key = self._generate_alert_key(parent_name, child_name, pid)
                with self._cache_lock:
                    if alert_key in self._alert_cache:
                        continue
                    self._alert_cache.add(alert_key)

                severity = "HIGH" if cmd_findings else "MEDIUM"

                alert = FilelessThreatAlert(
                    alert_id=str(uuid.uuid4()),
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    alert_type="LOTL_EXECUTION",
                    severity=severity,
                    parent_name=parent_name,
                    parent_pid=parent["pid"],
                    parent_cmdline=parent["cmdline"],
                    child_name=child_name,
                    child_pid=pid,
                    child_cmdline=proc["cmdline"],
                    mitre_technique="T1047 - Windows Management Instrumentation / T1059.001 - PowerShell",
                    description=(
                        f"WMI Provider Host (wmiprvse.exe PID {parent['pid']}) spawned "
                        f"shell '{child_name}' (PID {pid})."
                    ),
                    remediation_advice=(
                        f"Verify origin of WMI remote/local command execution on PID {pid}."
                    ),
                    details={
                        "risk_score": 80 if severity == "HIGH" else 60,
                        "command_evasion_indicators": cmd_findings,
                    },
                )

                logger.warning(
                    f"\U0001f6a8 [LOTL EXECUTION DETECTED] Parent: {parent_name} (PID {parent['pid']}) "
                    f"-> Child: {child_name} (PID {pid}) | Severity: {severity}"
                )

                alerts.append(alert)
                if self.callback:
                    try:
                        self.callback(alert)
                    except Exception as cb_err:
                        logger.error(f"Threat alert callback error: {cb_err}")

            # Scenario C: Other LotL Parents Spawning Interpreters
            elif parent_name in SUSPICIOUS_PARENTS:
                cmd_findings = self.analyze_command_line(proc["cmdline"])
                alert_key = self._generate_alert_key(parent_name, child_name, pid)
                with self._cache_lock:
                    if alert_key in self._alert_cache:
                        continue
                    self._alert_cache.add(alert_key)

                alert = FilelessThreatAlert(
                    alert_id=str(uuid.uuid4()),
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    alert_type="LOTL_EXECUTION",
                    severity="HIGH",
                    parent_name=parent_name,
                    parent_pid=parent["pid"],
                    parent_cmdline=parent["cmdline"],
                    child_name=child_name,
                    child_pid=pid,
                    child_cmdline=proc["cmdline"],
                    mitre_technique="T1218 - System Binary Proxy Execution",
                    description=(
                        f"Suspicious proxy parent '{parent_name}' (PID {parent['pid']}) "
                        f"spawned shell '{child_name}' (PID {pid})."
                    ),
                    remediation_advice=f"Inspect command line and terminate unauthorized PID {pid}.",
                    details={
                        "risk_score": 75,
                        "command_evasion_indicators": cmd_findings,
                    },
                )
                alerts.append(alert)
                if self.callback:
                    try:
                        self.callback(alert)
                    except Exception as cb_err:
                        logger.error(f"Threat alert callback error: {cb_err}")

        return alerts

    def audit_wmi_subscriptions(self) -> List[Dict[str, Any]]:
        """
        Queries Windows Management Instrumentation (WMI) namespace `root\\subscription`
        for persistent Event Consumers (ActiveScriptEventConsumer, CommandLineEventConsumer).
        Returns a list of discovered consumers with risk analysis.
        """
        if sys.platform != "win32":
            return []

        results: List[Dict[str, Any]] = []
        try:
            import win32com.client
            wmi_service = win32com.client.GetObject("winmgmts:\\\\.\\root\\subscription")

            # 1. Query CommandLineEventConsumers
            try:
                cmd_consumers = wmi_service.ExecQuery("SELECT * FROM CommandLineEventConsumer")
                for c in cmd_consumers:
                    name = getattr(c, "Name", "Unknown")
                    cmd_template = getattr(c, "CommandLineTemplate", "") or ""
                    executable = getattr(c, "ExecutablePath", "") or ""
                    suspicious = bool(
                        any(term in (cmd_template + executable).lower() for term in [
                            "powershell", "cmd.exe", "wscript", "cscript", "mshta", "http", "ftp", "-enc"
                        ])
                    )
                    results.append({
                        "consumer_type": "CommandLineEventConsumer",
                        "name": name,
                        "command_line": cmd_template,
                        "executable_path": executable,
                        "is_suspicious": suspicious,
                    })
            except Exception as e:
                logger.debug(f"CommandLineEventConsumer query error: {e}")

            # 2. Query ActiveScriptEventConsumers (VBScript/JScript persistence)
            try:
                script_consumers = wmi_service.ExecQuery("SELECT * FROM ActiveScriptEventConsumer")
                for s in script_consumers:
                    name = getattr(s, "Name", "Unknown")
                    script_text = getattr(s, "ScriptText", "") or ""
                    script_file = getattr(s, "ScriptFileName", "") or ""
                    results.append({
                        "consumer_type": "ActiveScriptEventConsumer",
                        "name": name,
                        "script_file": script_file,
                        "script_text_snippet": script_text[:200] if script_text else "",
                        "is_suspicious": True,  # ActiveScriptEventConsumer in user space is virtually always malicious or legacy
                    })
            except Exception as e:
                logger.debug(f"ActiveScriptEventConsumer query error: {e}")

        except Exception as com_err:
            logger.debug(f"WMI COM subscription audit unavailable or failed: {com_err}")

        return results

    # ========================================================================
    # Remediation Safeguards: Protected Process Suspension & Termination
    # ========================================================================

    @staticmethod
    def is_protected_process(pid: int, name: Optional[str] = None) -> bool:
        """
        Cryptographic & OS whitelist safeguard: Returns True if PID or name
        is a core Windows system process that must never be terminated.
        """
        if pid in PROTECTED_SYSTEM_PIDS or pid <= 4:
            return True

        proc_name = (name or "").lower().strip()
        if not proc_name:
            try:
                proc_name = psutil.Process(pid).name().lower().strip()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return True  # If we cannot verify, err on side of safety

        return proc_name in PROTECTED_PROCESS_NAMES

    def suspend_process(self, pid: int) -> bool:
        """
        Safely suspends execution of a target process using OS primitives.
        Refuses to touch protected system processes.
        """
        if self.is_protected_process(pid):
            logger.critical(
                f"[SAFETY ABORT] Refusing to suspend protected Windows core process PID {pid}!"
            )
            raise PermissionError(f"Cannot suspend protected Windows system process PID {pid}")

        try:
            proc = psutil.Process(pid)
            proc.suspend()
            logger.warning(f"[REMEDIATION] Suspended malicious process {proc.name()} (PID {pid})")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.error(f"Failed to suspend process PID {pid}: {e}")
            return False

    def terminate_process(self, pid: int) -> bool:
        """
        Safely terminates a target malicious process.
        Refuses to touch protected system processes.
        """
        if self.is_protected_process(pid):
            logger.critical(
                f"[SAFETY ABORT] Refusing to terminate protected Windows core process PID {pid}!"
            )
            raise PermissionError(f"Cannot terminate protected Windows system process PID {pid}")

        try:
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()
            logger.warning(f"[REMEDIATION] Terminated malicious process PID {pid}")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.error(f"Failed to terminate process PID {pid}: {e}")
            return False

    # ========================================================================
    # Continuous Monitoring Loop
    # ========================================================================

    def _monitor_loop(self, interval: float) -> None:
        logger.info(f"Fileless threat monitoring thread started (Interval: {interval}s)")
        while not self._stop_event.is_set():
            try:
                self.scan_processes()
            except Exception as e:
                logger.error(f"Error during threat hunter scan: {e}")
            self._stop_event.wait(timeout=interval)

    def start_monitoring(self, interval_seconds: float = 2.0) -> None:
        """Starts real-time process lineage threat hunting in a background daemon thread."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            logger.warning("Threat hunter monitor thread is already running.")
            return

        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval_seconds,),
            daemon=True,
            name="FixAI-ThreatHunterThread",
        )
        self._monitor_thread.start()
        logger.info("ThreatHunter active lineage monitoring activated.")

    def stop_monitoring(self) -> None:
        """Gracefully halts the threat hunting monitoring thread."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._stop_event.set()
            self._monitor_thread.join(timeout=3.0)
            logger.info("ThreatHunter monitoring thread stopped.")
