"""
FixAI EDR — Phase 5: Plain-English Security Alert Bridge & Desktop Notifications
==================================================================================

Bridges the Phase 1–4 security subsystem (event_monitor, file_monitor,
threat_hunter, quarantine) into the user-facing notification layer via:

1. **Template-Based Natural Language Generation (NLG):**
   Each alert type (BruteForce, MaliciousFile, FilelessThreat, Quarantine,
   FirewallBlock) has a dedicated narrative template that renders a
   plain-English SecurityAlertMessage with:
     - A human-readable title
     - A clear threat description
     - The autonomic action taken
     - Numbered actionable recommendations for the user

2. **Desktop Toast Notifications via `desktop-notifier`:**
   SecurityAlertMessages are dispatched as native Windows Toast
   notifications (Windows Runtime / WinRT) using the `desktop-notifier`
   library, with a fallback to PowerShell WinRT toast if unavailable.

3. **IPC Alert Dispatcher:**
   A unified AlertBridge class that the Telemetry Daemon (main.py) uses
   to subscribe to events from all 4 security phases and automatically
   route them through NLG → desktop notification → optional webhook.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("fixai.security.alert_bridge")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] [%(levelname)s] [AlertBridge] %(message)s")
    )
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


# ============================================================================
# Security Alert Message — Unified Alert Data Model
# ============================================================================

@dataclass
class SecurityAlertMessage:
    """
    A plain-English security alert message produced by the NLG engine.
    Designed for display as a desktop toast notification and IPC payload.
    """
    alert_id: str
    timestamp: str
    severity: str                    # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    alert_type: str                  # 'BRUTE_FORCE', 'MALICIOUS_FILE', 'FILELESS_THREAT', 'QUARANTINE', 'FIREWALL'
    title: str
    threat_description: str
    action_taken: str
    actionable_steps: List[str]
    source_module: str               # 'event_monitor', 'file_monitor', 'threat_hunter', 'quarantine'
    raw_details: Dict[str, Any] = field(default_factory=dict)

    def to_plain_text(self) -> str:
        """Renders the full plain-English alert as multi-line text."""
        steps = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(self.actionable_steps))
        return (
            f"\u26a0\ufe0f {self.title}\n\n"
            f"The Threat:\n{self.threat_description}\n\n"
            f"Action Taken:\n{self.action_taken}\n\n"
            f"What You Should Do:\n{steps}"
        )

    def to_toast_summary(self) -> str:
        """Compact 2-line summary for desktop toast notifications (max ~140 chars)."""
        threat_short = self.threat_description[:100]
        action_short = self.action_taken[:60]
        return f"{threat_short}\n{action_short}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "alert_type": self.alert_type,
            "title": self.title,
            "threat_description": self.threat_description,
            "action_taken": self.action_taken,
            "actionable_steps": self.actionable_steps,
            "source_module": self.source_module,
            "plain_text": self.to_plain_text(),
            "raw_details": self.raw_details,
        }


# ============================================================================
# Template-Based NLG Engine — Translates Raw Alerts → Plain English
# ============================================================================

class SecurityNLGEngine:
    """
    Converts raw security events from Phase 1–4 modules into structured,
    plain-English SecurityAlertMessages using pre-defined narrative templates.
    """

    @staticmethod
    def narrate_brute_force(
        source_ip: str,
        target_user: str,
        attempt_count: int,
        window_seconds: float,
        ip_blocked: bool = True,
    ) -> SecurityAlertMessage:
        """Phase 1: Brute-force login attack detected via Event ID 4625."""
        import uuid
        return SecurityAlertMessage(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            severity="HIGH",
            alert_type="BRUTE_FORCE",
            title="Active Brute-Force Intrusion Attempt Detected",
            threat_description=(
                f"A continuous hacking attempt was detected. Over {attempt_count} failed "
                f"login attempts to the '{target_user}' account were recorded from external "
                f"IP address {source_ip} within {window_seconds:.0f} seconds."
            ),
            action_taken=(
                f"The attacking IP address ({source_ip}) has been "
                + ("blocked by your local firewall." if ip_blocked else "flagged for manual review.")
                + " Your active sessions remain secured."
            ),
            actionable_steps=[
                "Change your user account password immediately using a strong, unique passphrase.",
                "Enable Multi-Factor Authentication (MFA) on all connected accounts.",
                "Verify your network router's firewall settings to restrict unsolicited inbound traffic.",
            ],
            source_module="event_monitor",
            raw_details={
                "source_ip": source_ip,
                "target_user": target_user,
                "attempt_count": attempt_count,
                "window_seconds": window_seconds,
                "ip_blocked": ip_blocked,
            },
        )

    @staticmethod
    def narrate_malicious_file(
        filename: str,
        filepath: str,
        entropy: float,
        yara_matches: List[str],
        sha256: str = "",
        quarantined: bool = True,
    ) -> SecurityAlertMessage:
        """Phase 2: Malicious file detected via Shannon entropy / YARA."""
        import uuid
        reasons = []
        if entropy > 7.2:
            reasons.append(f"abnormally high Shannon entropy ({entropy:.2f}/8.0) indicating encrypted payload or packer")
        if yara_matches:
            reasons.append(f"matched YARA signatures: {', '.join(yara_matches)}")
        reason_text = " and ".join(reasons) if reasons else "heuristic analysis"

        return SecurityAlertMessage(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            severity="HIGH",
            alert_type="MALICIOUS_FILE",
            title="Malicious File Intercepted & Quarantined" if quarantined else "Suspicious File Detected",
            threat_description=(
                f"A newly dropped file '{filename}' was flagged as malicious due to {reason_text}. "
                f"This file poses a severe security risk and may contain ransomware, a trojan, or obfuscated exploit code."
            ),
            action_taken=(
                f"The file has been intercepted and moved to a secure, AES-256 encrypted quarantine vault. "
                f"It cannot execute or spread."
                if quarantined else
                f"The file has been flagged for manual review. Exercise extreme caution."
            ),
            actionable_steps=[
                "Delete the original download source, email attachment, or USB transfer that introduced the file.",
                "Avoid launching unverified files with double extensions (e.g. .pdf.exe, .doc.scr).",
                "If you believe this is a false positive, access the FixAI recovery console to request a review.",
            ],
            source_module="file_monitor",
            raw_details={
                "filename": filename,
                "filepath": filepath,
                "entropy": entropy,
                "yara_matches": yara_matches,
                "sha256": sha256,
                "quarantined": quarantined,
            },
        )

    @staticmethod
    def narrate_fileless_threat(
        parent_name: str,
        parent_pid: int,
        child_name: str,
        child_pid: int,
        child_cmdline: str,
        mitre_technique: str,
        alert_type: str = "WMI_PERSISTENCE",
    ) -> SecurityAlertMessage:
        """Phase 3: Fileless/LotL threat detected via process tree analysis."""
        import uuid

        if alert_type == "WMI_PERSISTENCE":
            title = "Fileless WMI Malware Persistence Detected"
            threat = (
                f"A hidden, persistent script execution was detected. The Windows Management "
                f"Instrumentation Event Consumer ({parent_name}, PID {parent_pid}) spawned "
                f"an interactive command shell '{child_name}' (PID {child_pid}). "
                f"This is a signature indicator of fileless malware that survives reboots."
            )
            severity = "CRITICAL"
        else:
            title = "Living-off-the-Land (LotL) Attack Intercepted"
            threat = (
                f"A suspicious proxy parent process '{parent_name}' (PID {parent_pid}) "
                f"spawned command interpreter '{child_name}' (PID {child_pid}). "
                f"This technique is commonly used by advanced attackers to evade antivirus detection."
            )
            severity = "HIGH"

        return SecurityAlertMessage(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            severity=severity,
            alert_type="FILELESS_THREAT",
            title=title,
            threat_description=threat,
            action_taken=(
                f"The malicious child process (PID {child_pid}) has been flagged for "
                f"suspension. WMI subscription audit is in progress."
            ),
            actionable_steps=[
                "Initiate a full offline antivirus scan of your operating system.",
                "Review recently installed third-party software and browser extensions.",
                "Do not authorize unexpected administrative credential or UAC prompts.",
            ],
            source_module="threat_hunter",
            raw_details={
                "parent_name": parent_name,
                "parent_pid": parent_pid,
                "child_name": child_name,
                "child_pid": child_pid,
                "child_cmdline": child_cmdline,
                "mitre_technique": mitre_technique,
            },
        )

    @staticmethod
    def narrate_quarantine_action(
        filename: str,
        sha256: str,
        quarantine_id: str,
        vault_path: str,
    ) -> SecurityAlertMessage:
        """Phase 4: File quarantined in AES-256 vault."""
        import uuid
        return SecurityAlertMessage(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            severity="MEDIUM",
            alert_type="QUARANTINE",
            title="Threat Neutralized — File Secured in Quarantine Vault",
            threat_description=(
                f"The malicious file '{filename}' (SHA-256: {sha256[:16]}...) has been "
                f"permanently neutralized and moved to the encrypted quarantine vault."
            ),
            action_taken=(
                f"File encrypted with AES-256-CBC, extension stripped, and stored at "
                f"{vault_path}. The original file has been securely deleted."
            ),
            actionable_steps=[
                "No immediate action required — the threat has been fully contained.",
                "You may review quarantined items in the FixAI Security Console.",
                "Contact your IT administrator if you need to restore the file for analysis.",
            ],
            source_module="quarantine",
            raw_details={
                "filename": filename,
                "sha256": sha256,
                "quarantine_id": quarantine_id,
                "vault_path": vault_path,
            },
        )

    @staticmethod
    def narrate_firewall_block(
        ip: str,
        rule_name: str,
        reason: str = "Brute-force intrusion attempt",
    ) -> SecurityAlertMessage:
        """Phase 4: Firewall rule injected to block attacking IP."""
        import uuid
        return SecurityAlertMessage(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            severity="HIGH",
            alert_type="FIREWALL",
            title="Network Threat Blocked — Firewall Rule Injected",
            threat_description=(
                f"An attacking IP address ({ip}) has been identified as a threat source. "
                f"Reason: {reason}."
            ),
            action_taken=(
                f"A Windows Defender Firewall inbound block rule '{rule_name}' has been "
                f"injected to prevent all further communication from {ip}."
            ),
            actionable_steps=[
                "Verify the blocked IP is not a trusted internal device (check with your IT team).",
                "If legitimate, the block can be reversed via the FixAI Security Console.",
                "Consider enabling VPN or network segmentation for additional protection.",
            ],
            source_module="quarantine",
            raw_details={
                "blocked_ip": ip,
                "rule_name": rule_name,
                "reason": reason,
            },
        )


# ============================================================================
# Desktop Notification Dispatcher (desktop-notifier + fallback)
# ============================================================================

class DesktopNotifier:
    """
    Dispatches native desktop toast notifications using the `desktop-notifier`
    library (WinRT on Windows). Falls back to PowerShell WinRT toast on failure.
    """

    APP_NAME = "FixAI Guardian"

    # Severity → emoji prefix for toast title
    SEVERITY_EMOJI = {
        "CRITICAL": "\U0001f6a8",  # 🚨
        "HIGH": "\u26a0\ufe0f",     # ⚠️
        "MEDIUM": "\u2139\ufe0f",   # ℹ️
        "LOW": "\u2705",            # ✅
    }

    def __init__(self):
        self._notifier = None
        self._loop = None
        self._loop_thread = None
        self._init_notifier()

    def _init_notifier(self) -> None:
        """Initialize the desktop-notifier async event loop in a background thread."""
        try:
            from desktop_notifier import DesktopNotifier as DN
            self._loop = asyncio.new_event_loop()
            self._notifier = DN(app_name=self.APP_NAME)

            def _run_loop(loop: asyncio.AbstractEventLoop):
                asyncio.set_event_loop(loop)
                loop.run_forever()

            self._loop_thread = threading.Thread(
                target=_run_loop,
                args=(self._loop,),
                daemon=True,
                name="FixAI-NotifierLoop",
            )
            self._loop_thread.start()
            logger.info("Desktop notifier initialized (desktop-notifier / WinRT)")
        except ImportError:
            logger.info("desktop-notifier not available; using PowerShell fallback")
            self._notifier = None
        except Exception as e:
            logger.warning(f"Desktop notifier init error: {e}; using fallback")
            self._notifier = None

    def send(self, alert: SecurityAlertMessage) -> None:
        """
        Sends a desktop toast notification for a SecurityAlertMessage.
        Non-blocking — dispatches in background thread.
        """
        emoji = self.SEVERITY_EMOJI.get(alert.severity, "\u26a0\ufe0f")
        title = f"{emoji} {alert.title}"
        body = alert.to_toast_summary()

        if self._notifier and self._loop:
            self._send_via_desktop_notifier(title, body)
        else:
            self._send_via_powershell_fallback(title, body)

    def _send_via_desktop_notifier(self, title: str, body: str) -> None:
        """Dispatch via desktop-notifier library (async-safe)."""
        async def _send():
            try:
                await self._notifier.send(title=title, message=body)
            except Exception as e:
                logger.debug(f"desktop-notifier send error: {e}")

        try:
            asyncio.run_coroutine_threadsafe(_send(), self._loop)
        except Exception as e:
            logger.debug(f"Failed to schedule notification: {e}")
            self._send_via_powershell_fallback(title, body)

    @staticmethod
    def _send_via_powershell_fallback(title: str, body: str) -> None:
        """Fallback: PowerShell WinRT toast notification."""
        if sys.platform != "win32":
            logger.info(f"[NOTIFICATION] {title}: {body}")
            return

        def _dispatch():
            try:
                safe_title = title.replace("'", "").replace('"', "")
                safe_body = body.replace("'", "").replace('"', "").replace("\n", " ")
                ps_cmd = (
                    "[Windows.UI.Notifications.ToastNotificationManager, "
                    "Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; "
                    "$template = [Windows.UI.Notifications.ToastNotificationManager]::"
                    "GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
                    f"$template.GetElementsByTagName('text').Item(0).AppendChild("
                    f"$template.CreateTextNode('{safe_title}')) | Out-Null; "
                    f"$template.GetElementsByTagName('text').Item(1).AppendChild("
                    f"$template.CreateTextNode('{safe_body}')) | Out-Null; "
                    "$toast = [Windows.UI.Notifications.ToastNotification]::new($template); "
                    "[Windows.UI.Notifications.ToastNotificationManager]::"
                    "CreateToastNotifier('FixAI Guardian').Show($toast);"
                )
                subprocess.run(
                    ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps_cmd],
                    capture_output=True,
                    timeout=5,
                )
            except Exception as e:
                logger.debug(f"PowerShell toast fallback error: {e}")

        threading.Thread(target=_dispatch, daemon=True).start()


# ============================================================================
# Alert Bridge — Unified IPC Dispatcher (Phase 1–4 → Desktop + Webhook)
# ============================================================================

class AlertBridge:
    """
    Central IPC bridge that connects the Phase 1–4 security subsystem
    to the User-Space desktop notification layer.

    Usage in main.py:
        bridge = AlertBridge()

        # Phase 1 callback
        event_monitor = EventMonitor(callback=bridge.on_brute_force_alert)

        # Phase 2 callback
        file_monitor = FileMonitor(callback=bridge.on_malicious_file_alert)

        # Phase 3 callback
        threat_hunter = ThreatHunter(callback=bridge.on_fileless_threat_alert)
    """

    def __init__(
        self,
        enable_desktop_notifications: bool = True,
        on_alert_callback: Optional[Callable[[SecurityAlertMessage], None]] = None,
    ):
        self.nlg = SecurityNLGEngine()
        self.notifier = DesktopNotifier() if enable_desktop_notifications else None
        self.on_alert_callback = on_alert_callback
        self._alert_history: List[SecurityAlertMessage] = []
        self._alert_history_lock = threading.Lock()
        logger.info("AlertBridge initialized — Security IPC to desktop active")

    def _dispatch(self, alert: SecurityAlertMessage) -> None:
        """Central dispatch: log → desktop notification → callback → history."""
        logger.warning(
            f"\U0001f514 [{alert.severity}] {alert.title} | "
            f"Type: {alert.alert_type} | Module: {alert.source_module}"
        )

        # 1. Desktop toast notification
        if self.notifier:
            try:
                self.notifier.send(alert)
            except Exception as e:
                logger.debug(f"Desktop notification dispatch error: {e}")

        # 2. Optional callback (e.g. to send to backend/Convex)
        if self.on_alert_callback:
            try:
                self.on_alert_callback(alert)
            except Exception as e:
                logger.debug(f"Alert callback error: {e}")

        # 3. Append to history
        with self._alert_history_lock:
            self._alert_history.append(alert)
            # Keep history bounded
            if len(self._alert_history) > 200:
                self._alert_history = self._alert_history[-100:]

    # ================================================================
    # Phase 1 Callback: Brute-Force Alert
    # ================================================================
    def on_brute_force_alert(self, brute_force_alert: Any) -> None:
        """
        Receives a BruteForceAlert from Phase 1 EventMonitor and
        translates it into a plain-English desktop notification.
        """
        alert_msg = self.nlg.narrate_brute_force(
            source_ip=getattr(brute_force_alert, "source_ip", "Unknown"),
            target_user=getattr(brute_force_alert, "target_user", "Unknown"),
            attempt_count=getattr(brute_force_alert, "attempt_count", 5),
            window_seconds=getattr(brute_force_alert, "window_seconds", 60.0),
            ip_blocked=True,
        )
        self._dispatch(alert_msg)

    # ================================================================
    # Phase 2 Callback: Malicious File Alert
    # ================================================================
    def on_malicious_file_alert(self, malicious_alert: Any) -> None:
        """
        Receives a MaliciousFileAlert from Phase 2 FileMonitor and
        translates it into a plain-English desktop notification.
        """
        alert_msg = self.nlg.narrate_malicious_file(
            filename=getattr(malicious_alert, "filename", "unknown"),
            filepath=getattr(malicious_alert, "filepath", ""),
            entropy=getattr(malicious_alert, "entropy", 0.0),
            yara_matches=getattr(malicious_alert, "yara_matches", []) or [],
            sha256=getattr(malicious_alert, "sha256", ""),
            quarantined=False,  # Phase 2 detects; Phase 4 quarantines
        )
        self._dispatch(alert_msg)

    # ================================================================
    # Phase 3 Callback: Fileless Threat Alert
    # ================================================================
    def on_fileless_threat_alert(self, threat_alert: Any) -> None:
        """
        Receives a FilelessThreatAlert from Phase 3 ThreatHunter and
        translates it into a plain-English desktop notification.
        """
        alert_msg = self.nlg.narrate_fileless_threat(
            parent_name=getattr(threat_alert, "parent_name", "unknown"),
            parent_pid=getattr(threat_alert, "parent_pid", 0),
            child_name=getattr(threat_alert, "child_name", "unknown"),
            child_pid=getattr(threat_alert, "child_pid", 0),
            child_cmdline=getattr(threat_alert, "child_cmdline", ""),
            mitre_technique=getattr(threat_alert, "mitre_technique", ""),
            alert_type=getattr(threat_alert, "alert_type", "LOTL_EXECUTION"),
        )
        self._dispatch(alert_msg)

    # ================================================================
    # Phase 4 Callbacks: Quarantine & Firewall
    # ================================================================
    def on_quarantine_action(self, record: Any) -> None:
        """
        Receives a QuarantineRecord from Phase 4 QuarantineVault and
        generates a confirmation notification.
        """
        alert_msg = self.nlg.narrate_quarantine_action(
            filename=getattr(record, "original_filename", "unknown"),
            sha256=getattr(record, "original_sha256", ""),
            quarantine_id=getattr(record, "quarantine_id", ""),
            vault_path=getattr(record, "quarantined_path", ""),
        )
        self._dispatch(alert_msg)

    def on_firewall_block(self, ip: str, rule_name: str, reason: str = "Brute-force") -> None:
        """
        Generates a desktop notification when a firewall rule is injected.
        """
        alert_msg = self.nlg.narrate_firewall_block(
            ip=ip,
            rule_name=rule_name,
            reason=reason,
        )
        self._dispatch(alert_msg)

    # ================================================================
    # History & Telemetry
    # ================================================================
    @property
    def alert_history(self) -> List[Dict[str, Any]]:
        """Returns the recent alert history as serializable dicts."""
        with self._alert_history_lock:
            return [a.to_dict() for a in self._alert_history]

    @property
    def alert_count(self) -> int:
        with self._alert_history_lock:
            return len(self._alert_history)

    def get_telemetry_summary(self) -> Dict[str, Any]:
        """Returns a compact summary for the telemetry payload."""
        with self._alert_history_lock:
            counts: Dict[str, int] = {}
            for a in self._alert_history:
                counts[a.alert_type] = counts.get(a.alert_type, 0) + 1
            return {
                "total_alerts": len(self._alert_history),
                "alert_type_counts": counts,
                "last_alert": self._alert_history[-1].to_dict() if self._alert_history else None,
            }
