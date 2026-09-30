#!/usr/bin/env python3
"""
FixAI — Edge Agent Daemon
==========================

Continuously collects real host hardware metrics via psutil,
runs real-time Edge AI inference via EdgeAIEngine.analyze(),
and streams telemetry + failure diagnostics to Convex.

Loop Interval: 5 seconds (configurable via POLL_INTERVAL)
"""

from __future__ import annotations

import logging
import os
import platform
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

import psutil
import requests
from dotenv import load_dotenv

# Ensure UTF-8 output on Windows terminals
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Add parent directory to path for clean imports
sys.path.append(str(Path(__file__).resolve().parent))

from ai_engine.inference import EdgeAIEngine
from recovery.executor import RecoveryManager
from watchdog_monitor import WatchdogMonitor, DiskFillAlert
from osquery_collector import OsqueryCollector
from edr import EDREngine, SecurityNarrative

# ───────────────────────────────────────────────────────────────────────────
# Configuration
# ───────────────────────────────────────────────────────────────────────────
load_dotenv()

POLL_INTERVAL: int = int(os.getenv("POLL_INTERVAL", os.getenv("FIXAI_POLL_INTERVAL", "5")))
CONVEX_TELEMETRY_URL: str = os.getenv(
    "CONVEX_TELEMETRY_URL",
    os.getenv("BACKEND_URL", "http://localhost:8000/api/v1/agent/ingest"),
)
CONVEX_DEVICE_API_KEY: str = os.getenv(
    "CONVEX_DEVICE_API_KEY",
    os.getenv("FIXAI_DEVICE_API_KEY", "fixai-device-secret-key-2026"),
)
DEVICE_NAME: str = os.getenv("DEVICE_NAME", os.getenv("FIXAI_DEVICE_NAME", "Local-Workstation"))
DEVICE_ID: str = os.getenv("DEVICE_ID", f"dev-{abs(hash(DEVICE_NAME)) % 100000:05d}")

# Setup structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("fixai-agent")

# Graceful shutdown flag
_running: bool = True


def _handle_shutdown(signum: int, _frame: Any) -> None:
    """Handle termination signals gracefully."""
    global _running
    logger.info("Received termination signal (%s). Shutting down FixAI agent gracefully...", signum)
    _running = False


signal.signal(signal.SIGINT, _handle_shutdown)
signal.signal(signal.SIGTERM, _handle_shutdown)


# ───────────────────────────────────────────────────────────────────────────
# System Specs & Notifications
# ───────────────────────────────────────────────────────────────────────────

def get_system_specs() -> Dict[str, Any]:
    """Retrieve host hardware specifications for device registration and sync."""
    return {
        "os": f"{platform.system()} {platform.release()}",
        "cpuModel": platform.processor() or "x86_64",
        "cores": psutil.cpu_count(logical=True) or 4,
        "ramGb": round(psutil.virtual_memory().total / (1024**3), 1),
    }


def send_desktop_notification(title: str, message: str) -> None:
    """
    Cross-platform desktop notification dispatcher (non-blocking).
    Uses native Windows Runtime Toast notifications on Windows,
    notify-send on Linux, osascript on macOS, or plyer if installed.
    """
    def _dispatch():
        try:
            # 1. Try plyer if available
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
# Metric Collection
# ───────────────────────────────────────────────────────────────────────────

def get_disk_percent() -> float:
    """Safely obtain system disk utilization percentage across OS platforms."""
    try:
        path = "C:\\" if sys.platform == "win32" else "/"
        return float(psutil.disk_usage(path).percent)
    except Exception:
        return 75.0


def collect_hardware_metrics() -> Dict[str, float]:
    """
    Collect real-time hardware telemetry using psutil.

    Returns:
        Dict with keys: 'cpu', 'ram', 'latency', 'error_rate', 'disk', 'temp', 'battery'
    """
    cpu_usage = float(psutil.cpu_percent(interval=1.0))
    memory_info = psutil.virtual_memory()
    disk_usage = get_disk_percent()

    # Laptop Battery Sensing (Real ACPI)
    battery_pct = 100.0
    try:
        batt = psutil.sensors_battery()
        if batt:
            battery_pct = float(batt.percent)
    except Exception:
        battery_pct = 95.0

    # Laptop CPU Core Temperature Sensing
    core_temp = 48.0
    try:
        temps = psutil.sensors_temperatures() if hasattr(psutil, "sensors_temperatures") else {}
        if temps:
            for name, entries in temps.items():
                if entries:
                    core_temp = float(entries[0].current)
                    break
        else:
            # Infer thermal profile from CPU stress curve
            core_temp = 42.0 + (cpu_usage * 0.45)
    except Exception:
        core_temp = 42.0 + (cpu_usage * 0.45)

    # In standalone local mode, network latency and HTTP 5xx error rate
    # are set to safe operational baseline metrics.
    mock_latency = 12.0
    mock_error_rate = 0.0

    return {
        "cpu": round(cpu_usage, 1),
        "ram": round(float(memory_info.percent), 1),
        "latency": round(mock_latency, 1),
        "error_rate": round(mock_error_rate, 2),
        "disk": round(disk_usage, 1),
        "temp": round(core_temp, 1),
        "battery": round(battery_pct, 1),
    }


# ───────────────────────────────────────────────────────────────────────────
# Telemetry Dispatcher
# ───────────────────────────────────────────────────────────────────────────

def send_telemetry_payload(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    POST the telemetry and AI diagnosis payload to Convex.

    Catches all connection and HTTP errors so the agent does not crash
    if network connectivity drops.
    """
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": CONVEX_DEVICE_API_KEY,
        "x-device-key": CONVEX_DEVICE_API_KEY,
    }

    try:
        response = requests.post(
            CONVEX_TELEMETRY_URL,
            json=payload,
            headers=headers,
            timeout=5.0,
        )
        if response.status_code in (200, 201, 204):
            logger.info("☁️  Telemetry synced successfully (HTTP %s)", response.status_code)
            try:
                return response.json()
            except Exception:
                return {"status": "ok"}
        else:
            logger.warning(
                "⚠️  Convex endpoint returned non-200 status [%d]: %s",
                response.status_code,
                response.text[:120],
            )
            return None

    except requests.exceptions.Timeout:
        logger.warning("⏱️  Convex request timed out. Will retry next cycle.")
        return None
    except requests.exceptions.ConnectionError:
        logger.warning("🔌  Network connection error. Server unreachable at %s", CONVEX_TELEMETRY_URL)
        return None
    except requests.exceptions.RequestException as exc:
        logger.error("❌  HTTP request failed: %s", exc)
        return None


# ───────────────────────────────────────────────────────────────────────────
# Main Agent Loop
# ───────────────────────────────────────────────────────────────────────────

def run_agent() -> None:
    """Main execution loop for the FixAI local agent."""
    logger.info("================================================================")
    logger.info("  FixAI Local Agent Starting (Production-Grade)")
    logger.info("  Device Name   : %s (ID: %s)", DEVICE_NAME, DEVICE_ID)
    logger.info("  Convex URL    : %s", CONVEX_TELEMETRY_URL)
    logger.info("  Poll Interval : %d seconds", POLL_INTERVAL)
    logger.info("================================================================")

    # Load models and recovery manager once at initialization
    try:
        engine = EdgeAIEngine()
        recovery_mgr = RecoveryManager()
    except Exception as e:
        logger.critical("Failed to initialize agent components: %s", e)
        sys.exit(1)

    # ── EDR Security Alert Callback -> Desktop Notification ─────────────
    def _on_edr_alert(narrative: SecurityNarrative) -> None:
        logger.warning("🚨 EDR ALERT: %s", narrative.title)
        send_desktop_notification(
            narrative.title,
            narrative.to_toast_summary(),
        )

    edr = EDREngine(on_security_alert=_on_edr_alert)

    # ── Upgrade #2: Watchdog File System Monitor ────────────────────────
    def _on_disk_fill_alert(alert: DiskFillAlert) -> None:
        """Callback fired by WatchdogMonitor when a disk fill is detected."""
        logger.warning(
            "🚨 WATCHDOG ALERT: %s at %s (%.1fMB > %.1fMB limit). Truncated: %s",
            alert.alert_type, alert.path, alert.size_mb, alert.limit_mb, alert.truncated,
        )
        send_desktop_notification(
            "FixAI Disk Fill Alert",
            f"{alert.alert_type} overflow detected at {alert.path} "
            f"({alert.size_mb}MB). Auto-truncated: {alert.truncated}",
        )

    # Hook WatchdogMonitor to forward newly discovered files to EDR scanner
    watchdog = WatchdogMonitor(on_alert=_on_disk_fill_alert, on_file_discovered=edr.inspect_file)
    watchdog.start()

    # ── Upgrade #1: Osquery Deep Telemetry ──────────────────────────────
    osquery = OsqueryCollector()
    osquery_available = osquery.is_available()
    if osquery_available:
        logger.info("✅ Osquery integration active — deep OS telemetry enabled")
    else:
        logger.info("ℹ️  Osquery not installed — using psutil-only telemetry (install from https://osquery.io)")

    cycle_count = 0
    last_alert_risk = "LOW"
    last_alert_time = 0.0
    specs = get_system_specs()
    last_osquery_data: Dict[str, Any] = {}
    last_edr_telemetry: Dict[str, Any] = {}
    OSQUERY_EVERY_N_CYCLES = 6  # collect osquery data every ~30 seconds (6 * 5s)

    while _running:
        cycle_start = time.time()
        cycle_count += 1

        try:
            # 1. Collect real host metrics (psutil)
            metrics = collect_hardware_metrics()

            # 2. Run real-time edge AI inference
            ai_results = engine.analyze(metrics)

            # 2b. Run EDR detection tick (Event logs, WMI persistence, LotL hierarchies)
            try:
                last_edr_telemetry = edr.run_detection_tick()
            except Exception as e:
                logger.debug("EDR tick error: %s", e)

            logger.info(
                "Cycle #%d: CPU=%.1f%%, RAM=%.1f%%, Disk=%.1f%% | Anomaly=%.2f, P_fail=%.2f, Risk=%s, EDR=%s",
                cycle_count,
                metrics["cpu"],
                metrics["ram"],
                metrics["disk"],
                ai_results["anomaly_score"],
                ai_results["p_failure"],
                ai_results["risk"],
                last_edr_telemetry.get("status", "SECURE"),
            )
            logger.info("NLG Diagnosis: %s", ai_results["nlg_explanation"])

            # 2c. Collect deep OS telemetry via osquery (every N cycles)
            if osquery_available and (cycle_count % OSQUERY_EVERY_N_CYCLES == 0):
                try:
                    last_osquery_data = osquery.collect()
                    sec_signals = last_osquery_data.get("security_signals", {})
                    stopped_count = sec_signals.get("stopped_auto_services_count", 0)
                    if stopped_count > 3:
                        logger.warning(
                            "⚠️  Osquery: %d auto-start services are stopped — possible sabotage or crash",
                            stopped_count,
                        )
                except Exception as exc:
                    logger.debug("Osquery collection error (will retry): %s", exc)

            # 3. Check for risk threshold transition to notify desktop
            current_risk = str(ai_results.get("risk", "LOW")).upper()
            now_t = time.time()
            if current_risk in ("MEDIUM", "HIGH"):
                if current_risk != last_alert_risk or (now_t - last_alert_time > 60):
                    send_desktop_notification(
                        f"FixAI Alert: {current_risk} Risk Detected",
                        f"Anomaly: {ai_results['anomaly_score']:.2f} | P(Failure): {ai_results['p_failure']:.2f} | {ai_results['nlg_explanation'][:80]}",
                    )
                    last_alert_risk = current_risk
                    last_alert_time = now_t
            else:
                if last_alert_risk in ("MEDIUM", "HIGH"):
                    send_desktop_notification(
                        "FixAI System Restored",
                        f"Health stabilized at normal baseline. Anomaly score: {ai_results['anomaly_score']:.2f}",
                    )
                last_alert_risk = "LOW"

            # 4. Assemble combined payload for Convex & FastAPI
            payload = {
                "device_id": DEVICE_ID,
                "device_name": DEVICE_NAME,
                "timestamp": int(time.time() * 1000),
                "specs": specs,
                "metrics": metrics,
                "ai_results": ai_results,
                # Compatibility fields for backend bridge
                "telemetry": {
                    "cpu": metrics["cpu"],
                    "ram": metrics["ram"],
                    "latency": metrics["latency"],
                    "errorRate": metrics["error_rate"],
                    "disk": metrics["disk"],
                },
                "ai_verdict": {
                    "anomalyScore": ai_results["anomaly_score"],
                    "pFailure": ai_results["p_failure"],
                    "risk": ai_results["risk"],
                },
                "shap": ai_results.get("shap_weights", {}),
                "shap_weights": ai_results.get("shap_weights", {}),
                "nlg_explanation": ai_results.get("nlg_explanation", ""),
                # ── Production telemetry enrichments ──
                "osquery_data": last_osquery_data if last_osquery_data else None,
                "edr_telemetry": last_edr_telemetry if last_edr_telemetry else None,
                "watchdog_status": watchdog.get_status(),
            }

            # 5. Stream to Convex / Backend
            send_telemetry_payload(payload)

            # 6. Check and execute pending user/auto recovery actions
            pending_actions = recovery_mgr.poll_for_actions()
            if pending_actions:
                for action in pending_actions:
                    action_id = str(action.get("id", action.get("action_id", f"act-{int(time.time())}")))
                    action_name = str(action.get("action_name", action.get("playbook_name", "flush_cache")))
                    incident_id = action.get("incident_id")

                    logger.info("⚡ Processing recovery action: '%s' (Action ID: %s)", action_name, action_id)
                    exec_result = recovery_mgr.execute_playbook(action_name, action.get("params"))

                    if exec_result.get("success"):
                        # Validate fix after soak period
                        val_res = recovery_mgr.validate_fix(
                            action_id=action_id,
                            incident_id=incident_id,
                            action_name=action_name,
                            soak_seconds=15,
                        )
                        if val_res.get("is_health_restored"):
                            send_desktop_notification(
                                "FixAI Self-Healing Succeeded",
                                f"Playbook '{action_name}' executed. System health restored to baseline.",
                            )

        except Exception as exc:
            logger.exception("Unexpected error during agent cycle: %s", exc)

        # 7. Sleep for the remaining interval period
        elapsed = time.time() - cycle_start
        sleep_duration = max(0.1, POLL_INTERVAL - elapsed)
        time.sleep(sleep_duration)

    # ── Cleanup ─────────────────────────────────────────────────────────
    watchdog.stop()
    logger.info("FixAI Agent stopped successfully.")


if __name__ == "__main__":
    run_agent()

