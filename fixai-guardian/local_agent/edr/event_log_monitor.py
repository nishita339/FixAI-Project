"""
FixAI EDR — Security Event Log Harvester & Analyzer
===================================================

Monitors and analyzes operating system security event logs:
  - Windows Event Log Subsystem via win32evtlog (or fallback parser)
  - Critical Event IDs tracked:
      * 4624: Audit Success (Successful user logon)
      * 4625: Audit Failure (Failed user logon - Credential stuffing / Brute force)
      * 41: Kernel-Power / Unexpected shutdown (DoS or rootkit reboot)
      * 1074: User32 / Planned restart or shutdown
  - Sliding-Window Time-Series Intrusion Detection:
      * Evaluates failed logon velocity over temporal window (e.g. 60s).
      * Flags brute-force threshold breach (>= 5 failures).
      * Detects brute-force success condition: 4625 burst -> 4624 from matching target.
  - Drain Algorithm Integration:
      * Pipes log strings into DrainParser for streaming template vectorization.
"""

from __future__ import annotations

import collections
import logging
import sys
import time
from typing import Any, Deque, Dict, List, Optional, Tuple

from .drain_parser import DrainParser

logger = logging.getLogger("fixai.edr.eventlog")

# Check if native Windows Event Log API is available
HAS_WIN32EVTLOG = False
if sys.platform == "win32":
    try:
        import win32evtlog
        import win32evtlogutil
        HAS_WIN32EVTLOG = True
    except ImportError:
        HAS_WIN32EVTLOG = False


class SecurityEvent:
    """Standardized representation of a security audit event."""

    def __init__(
        self,
        event_id: int,
        log_type: str,
        time_created: float,
        source: str,
        message: str,
        account: Optional[str] = None,
        source_ip: Optional[str] = None,
        template_id: Optional[int] = None,
    ):
        self.event_id = event_id
        self.log_type = log_type
        self.time_created = time_created
        self.source = source
        self.message = message
        self.account = account or "SYSTEM"
        self.source_ip = source_ip or "127.0.0.1"
        self.template_id = template_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "log_type": self.log_type,
            "time_created": self.time_created,
            "source": self.source,
            "message": self.message,
            "account": self.account,
            "source_ip": self.source_ip,
            "template_id": self.template_id,
        }


class EventLogMonitor:
    """
    Harvests Windows Security & System Event logs, parses log templates via Drain,
    and maintains sliding-window analysis for brute-force attacks and anomalous reboots.
    """

    def __init__(
        self,
        brute_force_window_seconds: int = 60,
        brute_force_failure_threshold: int = 5,
    ):
        self.brute_force_window = brute_force_window_seconds
        self.failure_threshold = brute_force_failure_threshold
        self.parser = DrainParser()

        # Sliding window for failed logons: deque of (timestamp, account, source_ip)
        self._failed_logons: Deque[Tuple[float, str, str]] = collections.deque()
        self._last_security_poll_time = time.time()
        self._active_threats: List[Dict[str, Any]] = []

    def harvest_events(self) -> List[SecurityEvent]:
        """Harvest new events from Windows Event Log or fallback simulation."""
        events: List[SecurityEvent] = []

        if HAS_WIN32EVTLOG and sys.platform == "win32":
            events.extend(self._harvest_windows_events("Security", [4624, 4625]))
            events.extend(self._harvest_windows_events("System", [41, 1074]))
        else:
            # Fallback or platform check
            logger.debug("Native Windows Event Log API unavailable, running in passive mode")

        return events

    def _harvest_windows_events(self, log_name: str, target_ids: List[int]) -> List[SecurityEvent]:
        """Harvest specific event IDs from a Windows event log channel."""
        events = []
        try:
            hand = win32evtlog.OpenEventLog(None, log_name)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            records = win32evtlog.ReadEventLog(hand, flags, 0)
            now = time.time()

            for record in records:
                evt_id = record.EventID & 0x1FFFFFFF  # Strip severity mask
                time_generated = record.TimeGenerated.timestamp() if hasattr(record.TimeGenerated, "timestamp") else now

                # Only process events within recent window (last 60 seconds)
                if now - time_generated > 60:
                    break

                if evt_id in target_ids:
                    strings = record.StringInserts or []
                    msg = " | ".join(str(s) for s in strings[:6])
                    parsed = self.parser.parse(msg)

                    account = strings[5] if len(strings) > 5 and evt_id in (4624, 4625) else "N/A"
                    source_ip = strings[18] if len(strings) > 18 and evt_id in (4624, 4625) else "127.0.0.1"

                    evt = SecurityEvent(
                        event_id=evt_id,
                        log_type=log_name,
                        time_created=time_generated,
                        source=str(record.SourceName),
                        message=msg,
                        account=str(account),
                        source_ip=str(source_ip),
                        template_id=parsed["cluster_id"],
                    )
                    events.append(evt)

            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            logger.debug("Windows event log harvest notice (%s): %s", log_name, e)

        return events

    def analyze_event_stream(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """
        Process security events, update sliding windows, and evaluate intrusion patterns.

        Returns:
            Dict containing active brute-force indicators, logon statistics,
            system restart conditions, and threat alerts.
        """
        now = time.time()

        # Evict old entries from sliding window
        while self._failed_logons and (now - self._failed_logons[0][0] > self.brute_force_window):
            self._failed_logons.popleft()

        threats = []
        auth_successes = 0
        auth_failures = 0
        unexpected_shutdowns = 0
        planned_restarts = 0

        for evt in events:
            if evt.event_id == 4625:
                # Audit Failure
                auth_failures += 1
                self._failed_logons.append((evt.time_created, evt.account, evt.source_ip))
            elif evt.event_id == 4624:
                # Audit Success
                auth_successes += 1
                # Check for brute-force compromise: burst of failures followed by success
                matching_failures = [
                    f for f in self._failed_logons
                    if (f[1] == evt.account or f[2] == evt.source_ip)
                ]
                if len(matching_failures) >= self.failure_threshold:
                    threats.append({
                        "threat_type": "BRUTE_FORCE_COMPROMISE",
                        "severity": "CRITICAL",
                        "account": evt.account,
                        "source_ip": evt.source_ip,
                        "failure_count": len(matching_failures),
                        "description": (
                            f"Brute-force attack succeeded! {len(matching_failures)} failed logons "
                            f"were immediately followed by Audit Success (Event ID 4624) for user '{evt.account}' "
                            f"from IP {evt.source_ip}."
                        ),
                    })
            elif evt.event_id == 41:
                unexpected_shutdowns += 1
                threats.append({
                    "threat_type": "UNEXPECTED_KERNEL_PANIC",
                    "severity": "HIGH",
                    "description": "Kernel-Power Event ID 41 detected: system suffered an unexpected shutdown or hard reboot.",
                })
            elif evt.event_id == 1074:
                planned_restarts += 1

        # Check for ongoing brute force (threshold reached without success yet)
        if len(self._failed_logons) >= self.failure_threshold:
            recent_ips = collections.Counter(f[2] for f in self._failed_logons)
            for ip, count in recent_ips.items():
                if count >= self.failure_threshold:
                    threats.append({
                        "threat_type": "ACTIVE_BRUTE_FORCE_ATTACK",
                        "severity": "HIGH",
                        "source_ip": ip,
                        "failure_count": count,
                        "description": (
                            f"Active credential stuffing/brute force detected: {count} failed logon attempts "
                            f"within {self.brute_force_window}s from IP {ip}."
                        ),
                    })

        self._active_threats = threats

        return {
            "window_seconds": self.brute_force_window,
            "recent_failed_logon_velocity": len(self._failed_logons),
            "auth_failures_in_tick": auth_failures,
            "auth_successes_in_tick": auth_successes,
            "unexpected_shutdowns": unexpected_shutdowns,
            "planned_restarts": planned_restarts,
            "threats": threats,
            "has_active_threat": len(threats) > 0,
        }
