#!/usr/bin/env python3
"""
FixAI — User Agent (Session 1 / Desktop Notifications)
=======================================================

This is the lightweight user-session companion process that runs in
the user's interactive session (Session 1) where desktop toasts are visible.

Architecture:
  - Reads telemetry state from IPC file written by TelemetryDaemon (Session 0)
  - Reads pending alert queue from IPC alerts file
  - Displays desktop notifications via plyer / PowerShell WinRT Toast / notify-send
  - Consumes and clears alert entries after displaying them

Why this exists:
  Windows services run in Session 0 (isolated desktop). Any call to
  ToastNotificationManager, MessageBox, or plyer from Session 0 is silently
  swallowed by the OS. This process runs in the user's session where UI works.

Usage:
    python user_agent.py                # Run in foreground
    pythonw user_agent.py               # Run as background GUI-less process
"""

from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure UTF-8 output on Windows
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ───────────────────────────────────────────────────────────────────────────
# Configuration
# ───────────────────────────────────────────────────────────────────────────

# IPC paths — must match telemetry_daemon.py
if sys.platform == "win32":
    IPC_DIR = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "FixAI" / "ipc"
else:
    IPC_DIR = Path("/var/run/fixai")

IPC_STATE_FILE = IPC_DIR / "telemetry_state.json"
IPC_ALERTS_FILE = IPC_DIR / "pending_alerts.json"

POLL_INTERVAL = 2  # seconds — how often to check IPC files

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [USER-AGENT] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("fixai-user-agent")

_running = True


def _handle_shutdown(signum: int, _frame: Any) -> None:
    global _running
    logger.info("UserAgent received signal %s — stopping...", signum)
    _running = False


signal.signal(signal.SIGINT, _handle_shutdown)
signal.signal(signal.SIGTERM, _handle_shutdown)


# ───────────────────────────────────────────────────────────────────────────
# Desktop Notification Dispatcher
# ───────────────────────────────────────────────────────────────────────────

def send_desktop_notification(title: str, message: str) -> None:
    """
    Cross-platform desktop notification dispatcher (non-blocking).
    This is the same function as in main.py — runs in user's Session 1.
    """
    def _dispatch():
        try:
            # 1. Try plyer
            try:
                import plyer
                plyer.notification.notify(
                    title=title,
                    message=message,
                    app_name="FixAI Guardian",
                    timeout=5,
                )
                return
            except Exception:
                pass

            # 2. Windows native PowerShell toast
            if sys.platform == "win32":
                safe_title = title.replace("'", "").replace('"', "")
                safe_msg = message.replace("'", "").replace('"', "").replace("\n", " ")
                ps_cmd = (
                    "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; "
                    "$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
                    f"$template.GetElementsByTagName('text').Item(0).AppendChild($template.CreateTextNode('{safe_title}')) | Out-Null; "
                    f"$template.GetElementsByTagName('text').Item(1).AppendChild($template.CreateTextNode('{safe_msg}')) | Out-Null; "
                    "$toast = [Windows.UI.Notifications.ToastNotification]::new($template); "
                    "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('FixAI Guardian').Show($toast);"
                )
                subprocess.run(
                    ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps_cmd],
                    capture_output=True,
                    timeout=5,
                )
                return

            # 3. Linux notify-send
            if sys.platform.startswith("linux"):
                subprocess.run(["notify-send", title, message], capture_output=True, timeout=5)
                return

            # 4. macOS osascript
            if sys.platform == "darwin":
                clean_msg = message.replace('"', '\\"')
                clean_title = title.replace('"', '\\"')
                osascript_code = f'display notification "{clean_msg}" with title "{clean_title}"'
                subprocess.run(["osascript", "-e", osascript_code], capture_output=True, timeout=5)
                return

        except Exception as e:
            logger.debug("Desktop notification dispatch skipped: %s", e)

    t = threading.Thread(target=_dispatch, daemon=True)
    t.start()


# ───────────────────────────────────────────────────────────────────────────
# IPC Reader
# ───────────────────────────────────────────────────────────────────────────

def _read_ipc_state() -> Optional[Dict[str, Any]]:
    """Read the telemetry state from the IPC file."""
    try:
        if IPC_STATE_FILE.exists():
            return json.loads(IPC_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return None


def _consume_ipc_alerts() -> List[Dict[str, Any]]:
    """
    Read and clear pending alerts from the IPC alerts file.
    Returns list of alert dicts, then empties the file.
    """
    alerts: List[Dict[str, Any]] = []
    try:
        if not IPC_ALERTS_FILE.exists():
            return []

        raw = IPC_ALERTS_FILE.read_text(encoding="utf-8").strip()
        if raw:
            alerts = json.loads(raw)

        # Clear the file after reading
        if alerts:
            IPC_ALERTS_FILE.write_text("[]", encoding="utf-8")

    except Exception as exc:
        logger.debug("IPC alerts read error: %s", exc)

    return alerts


# ───────────────────────────────────────────────────────────────────────────
# Main Loop
# ───────────────────────────────────────────────────────────────────────────

def run_user_agent() -> None:
    """
    Main loop for the UserAgent process.
    Polls IPC files every 2 seconds and dispatches desktop notifications.
    """
    logger.info("================================================================")
    logger.info("  FixAI User Agent (Session 1 — Desktop Notifications)")
    logger.info("  IPC Dir    : %s", IPC_DIR)
    logger.info("  Poll Rate  : %d seconds", POLL_INTERVAL)
    logger.info("================================================================")

    # Track already-shown alerts to avoid duplicates
    shown_alert_timestamps: set[float] = set()
    last_risk = "LOW"
    daemon_connected = False

    while _running:
        try:
            # 1. Read telemetry state from daemon
            state = _read_ipc_state()
            if state:
                if not daemon_connected:
                    logger.info("✅ Connected to TelemetryDaemon via IPC")
                    daemon_connected = True

                # Check if daemon is alive (written within last 30 seconds)
                daemon_ts = state.get("timestamp", 0)
                if time.time() - daemon_ts > 30:
                    if daemon_connected:
                        logger.warning("⚠️  TelemetryDaemon appears stale (last update: %.0fs ago)", time.time() - daemon_ts)
                        daemon_connected = False
            else:
                if daemon_connected:
                    logger.warning("🔌 Lost connection to TelemetryDaemon — IPC file missing")
                    daemon_connected = False

            # 2. Consume and display pending alerts
            alerts = _consume_ipc_alerts()
            for alert in alerts:
                alert_ts = alert.get("timestamp", 0)
                # Skip if already shown (dedup by timestamp)
                if alert_ts in shown_alert_timestamps:
                    continue

                title = alert.get("title", "FixAI Alert")
                message = alert.get("message", "")
                alert_type = alert.get("type", "UNKNOWN")

                logger.info("🔔 Dispatching notification: [%s] %s", alert_type, title)
                if alert.get("plain_text"):
                    logger.info("📋 Plain-English Narrative:\n%s", alert["plain_text"])
                send_desktop_notification(title, message)
                shown_alert_timestamps.add(alert_ts)

            # Keep shown set bounded
            if len(shown_alert_timestamps) > 100:
                shown_alert_timestamps = set(sorted(shown_alert_timestamps)[-50:])

        except Exception as exc:
            logger.debug("UserAgent cycle error: %s", exc)

        time.sleep(POLL_INTERVAL)

    logger.info("FixAI UserAgent stopped.")


if __name__ == "__main__":
    run_user_agent()
