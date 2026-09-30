"""
FixAI Security Subsystem — Phase 1: Security Event Harvesting (Brute-Force Detection)
=====================================================================================

Monitors Windows Security Event Logs for Event ID 4625 (Failed Logon).
Implements a strict, thread-safe sliding window algorithm:
- Window Duration: 60 seconds
- Threshold: 5+ failed logon attempts from the same source
- Triggers: BruteForceAlert with source IP, targeted accounts, velocity, and mitigation payload.

Handles non-elevated environments gracefully (Windows Security Event Log requires
SeSecurityPrivilege / elevation). If permission is denied, enters safe fallback mode
while preserving manual/synthetic telemetry ingest.
"""

from __future__ import annotations

import logging
import sys
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("fixai.security.event_monitor")

# Windows Event ID Constants
EVENT_ID_LOGON_FAILURE = 4625
EVENT_ID_LOGON_SUCCESS = 4624

# Logon Type Decoders (Windows NT Security)
LOGON_TYPES: Dict[int, str] = {
    2: "Interactive (Console/Keyboard)",
    3: "Network (SMB/RPC/Shared Folder)",
    4: "Batch (Scheduled Task)",
    5: "Service",
    7: "Unlock (Screen Lock)",
    8: "NetworkCleartext (IIS/Web)",
    9: "NewCredentials (RunAs)",
    10: "RemoteInteractive (RDP/Terminal Services)",
    11: "CachedInteractive",
}


@dataclass
class FailedLogonAttempt:
    """Represents a single failed authentication event."""
    timestamp: float
    source_ip: str
    target_username: str
    workstation_name: str = ""
    logon_type: int = 3
    failure_status: str = "0xC000006D"  # STATUS_LOGON_FAILURE
    sub_status: str = "0xC000006A"      # STATUS_WRONG_PASSWORD


@dataclass
class BruteForceAlert:
    """Triggered when 5+ failed attempts occur within 60s from the same source."""
    alert_id: str
    source_ip: str
    target_username: str
    attempt_count: int
    time_window_seconds: float
    first_attempt_time: float
    last_attempt_time: float
    logon_type: int
    logon_type_desc: str
    failure_reason: str
    recommended_action: str
    detected_at: float = field(default_factory=time.time)
    iso_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def summary(self) -> str:
        return (
            f"[🚨 BRUTE-FORCE DETECTED] Source: {self.source_ip} | "
            f"Target: {self.target_username} | Attempts: {self.attempt_count} in {self.time_window_seconds:.1f}s | "
            f"Type: {self.logon_type_desc} | Action: {self.recommended_action}"
        )


class EventMonitor:
    """
    Continuous Windows Security Event Log Monitor with Sliding-Window
    Brute-Force Attack Detection.
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        threshold: int = 5,
        cooldown_seconds: float = 30.0,
        on_alert: Optional[Callable[[BruteForceAlert], None]] = None,
    ):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.cooldown_seconds = cooldown_seconds
        self.on_alert = on_alert

        # Thread-safe sliding window tracking:
        # source_key -> List[FailedLogonAttempt]
        self._sliding_window: Dict[str, List[FailedLogonAttempt]] = defaultdict(list)
        # source_key -> last_alert_timestamp (for rate-limiting repeat alerts)
        self._last_alert_time: Dict[str, float] = {}
        self._lock = threading.Lock()

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._last_record_number: int = 0
        self._has_security_log_access = False

    # ── Sliding Window Engine ──────────────────────────────────────────

    def record_failed_logon(
        self,
        source_ip: str,
        target_username: str = "Administrator",
        workstation_name: str = "",
        logon_type: int = 3,
        failure_status: str = "0xC000006D",
        sub_status: str = "0xC000006A",
        timestamp: Optional[float] = None,
    ) -> Optional[BruteForceAlert]:
        """
        Record a failed logon attempt into the sliding window.
        Returns a BruteForceAlert if threshold (5+ in 60s) is breached, else None.
        """
        now = timestamp if timestamp is not None else time.time()
        # Normalize source key
        clean_ip = (source_ip or "").strip()
        if not clean_ip or clean_ip == "-" or clean_ip == "::1":
            clean_ip = workstation_name.strip() or "127.0.0.1"

        attempt = FailedLogonAttempt(
            timestamp=now,
            source_ip=clean_ip,
            target_username=target_username.strip() or "Unknown",
            workstation_name=workstation_name.strip(),
            logon_type=logon_type,
            failure_status=failure_status,
            sub_status=sub_status,
        )

        with self._lock:
            history = self._sliding_window[clean_ip]
            history.append(attempt)

            # Evict entries older than window_seconds (60s)
            cutoff = now - self.window_seconds
            self._sliding_window[clean_ip] = [a for a in history if a.timestamp >= cutoff]
            valid_window = self._sliding_window[clean_ip]

            count = len(valid_window)
            if count >= self.threshold:
                # Check cooldown to prevent alert flooding
                last_alert = self._last_alert_time.get(clean_ip, 0.0)
                if (now - last_alert) >= self.cooldown_seconds:
                    self._last_alert_time[clean_ip] = now
                    first_time = valid_window[0].timestamp
                    last_time = valid_window[-1].timestamp
                    type_desc = LOGON_TYPES.get(logon_type, f"LogonType-{logon_type}")

                    alert = BruteForceAlert(
                        alert_id=f"alert-bf-{uuid.uuid4().hex[:10]}",
                        source_ip=clean_ip,
                        target_username=target_username,
                        attempt_count=count,
                        time_window_seconds=round(last_time - first_time, 2),
                        first_attempt_time=first_time,
                        last_attempt_time=last_time,
                        logon_type=logon_type,
                        logon_type_desc=type_desc,
                        failure_reason=f"Status: {failure_status} / SubStatus: {sub_status} (Invalid Credentials)",
                        recommended_action=f"Enact host firewall inbound block rule for attacking IP {clean_ip}",
                        detected_at=now,
                    )

                    logger.warning(alert.summary())

                    if self.on_alert:
                        try:
                            self.on_alert(alert)
                        except Exception as exc:
                            logger.error("Error executing on_alert callback: %s", exc)

                    return alert

        return None

    def get_window_count(self, source_ip: str, now: Optional[float] = None) -> int:
        """Return the current number of active attempts in the 60s sliding window."""
        with self._lock:
            history = self._sliding_window.get(source_ip, [])
            if not history:
                return 0
            eval_time = now if now is not None else history[-1].timestamp
            cutoff = eval_time - self.window_seconds
            return len([a for a in history if a.timestamp >= cutoff])

    def reset_window(self, source_ip: Optional[str] = None) -> None:
        """Reset the sliding window for a specific source or all sources."""
        with self._lock:
            if source_ip:
                self._sliding_window.pop(source_ip, None)
                self._last_alert_time.pop(source_ip, None)
            else:
                self._sliding_window.clear()
                self._last_alert_time.clear()

    # ── Windows Security Event Log Harvester ───────────────────────────

    def _harvest_windows_events(self) -> None:
        """
        Polls Windows Security Event Log using pywin32 win32evtlog.
        Reads Event ID 4625 (Audit Failure: An account failed to log on).
        """
        if sys.platform != "win32":
            logger.info("Non-Windows OS detected: win32evtlog harvester disabled.")
            return

        try:
            import win32evtlog  # type: ignore
            import win32evtlogutil  # type: ignore
            import win32con  # type: ignore
        except ImportError:
            logger.warning("pywin32 not installed. Event log harvesting unavailable.")
            return

        try:
            hand = win32evtlog.OpenEventLog(None, "Security")
            self._has_security_log_access = True
            logger.info("✅ win32evtlog: Successfully opened Windows Security Event Log stream.")
        except Exception as exc:
            self._has_security_log_access = False
            logger.warning(
                "⚠️ win32evtlog: Security Event Log requires Administrator elevation (%s). "
                "EventMonitor is active in API/Synthetic mode.", exc
            )
            return

        flags = (
            win32evtlog.EVENTLOG_BACKWARDS_READ
            | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )

        try:
            # Prime position to latest record
            total_records = win32evtlog.GetNumberOfEventLogRecords(hand)
            self._last_record_number = total_records
        except Exception:
            pass

        while self._running:
            try:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    time.sleep(2.0)
                    continue

                for event in events:
                    # Windows event ID mask: event.EventID & 0xFFFF
                    event_id = event.EventID & 0xFFFF

                    if event_id == EVENT_ID_LOGON_FAILURE:
                        record_num = event.RecordNumber
                        if record_num <= self._last_record_number and self._last_record_number != 0:
                            # Already processed
                            continue

                        self._last_record_number = max(self._last_record_number, record_num)

                        # Extract StringInserts from Event 4625
                        inserts = event.StringInserts or ()
                        target_user = "Unknown"
                        workstation = ""
                        source_ip = "127.0.0.1"
                        logon_type = 3
                        failure_status = "0xC000006D"
                        sub_status = "0xC000006A"

                        # Parse standard Windows 10/11 Event 4625 layout:
                        # Index 5: TargetUserName
                        # Index 8/10: LogonType
                        # Index 11/13: WorkstationName
                        # Index 18/19: IpAddress
                        # Index 19/20: IpPort
                        if len(inserts) > 5 and inserts[5]:
                            target_user = str(inserts[5])
                        if len(inserts) > 10 and str(inserts[10]).isdigit():
                            logon_type = int(inserts[10])
                        elif len(inserts) > 8 and str(inserts[8]).isdigit():
                            logon_type = int(inserts[8])
                        if len(inserts) > 11 and inserts[11]:
                            workstation = str(inserts[11])
                        if len(inserts) > 19 and inserts[19] and inserts[19] != "-":
                            source_ip = str(inserts[19])
                        elif len(inserts) > 18 and inserts[18] and inserts[18] != "-":
                            source_ip = str(inserts[18])

                        event_time = (
                            event.TimeGenerated.replace(tzinfo=timezone.utc).timestamp()
                            if hasattr(event, "TimeGenerated") and event.TimeGenerated
                            else time.time()
                        )

                        self.record_failed_logon(
                            source_ip=source_ip,
                            target_username=target_user,
                            workstation_name=workstation,
                            logon_type=logon_type,
                            failure_status=failure_status,
                            sub_status=sub_status,
                            timestamp=event_time,
                        )

            except Exception as exc:
                logger.debug("win32evtlog harvesting tick note: %s", exc)

            time.sleep(2.0)

        try:
            win32evtlog.CloseEventLog(hand)
        except Exception:
            pass

    # ── Daemon Control ─────────────────────────────────────────────────

    def start(self) -> None:
        """Start the background event monitoring daemon thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._harvest_windows_events,
            name="FixAI-Security-EventMonitor",
            daemon=True,
        )
        self._thread.start()
        logger.info("🛡️  EventMonitor daemon thread started (Sliding Window: %ds, Threshold: %d)", self.window_seconds, self.threshold)

    def stop(self) -> None:
        """Stop the background event monitoring daemon thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("EventMonitor daemon thread stopped.")

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def has_security_log_access(self) -> bool:
        return self._has_security_log_access
