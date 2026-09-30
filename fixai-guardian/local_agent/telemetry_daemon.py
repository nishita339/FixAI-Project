#!/usr/bin/env python3
"""
FixAI — Telemetry Daemon (Session 0 / High-Privilege)
======================================================

This is the headless telemetry collection daemon designed to run as a
Windows Service in Session 0 (SYSTEM account, no UI access).

Architecture:
  - Runs with elevated privileges (can access ACPI, hardware sensors, services)
  - Collects psutil metrics + osquery telemetry + AI inference
  - Writes results to a local IPC file (JSON) every cycle
  - The companion UserAgent (user_agent.py) reads this file from Session 1
    and displays desktop notifications

IPC Mechanism:
  - File-based IPC via %PROGRAMDATA%/FixAI/ipc/telemetry_state.json
  - Atomic write (write to .tmp, then rename) to prevent partial reads
  - UserAgent polls this file every 2 seconds

Usage:
    python telemetry_daemon.py                  # Run in foreground
    python telemetry_daemon.py --install         # Install as Windows Service (requires pywin32)
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

import psutil
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
DEVICE_NAME: str = os.getenv("DEVICE_NAME", os.getenv("FIXAI_DEVICE_NAME", "Local-Workstation"))
DEVICE_ID: str = os.getenv("DEVICE_ID", f"dev-{abs(hash(DEVICE_NAME)) % 100000:05d}")

# IPC directory — accessible by both Session 0 (SYSTEM) and Session 1 (User)
if sys.platform == "win32":
    IPC_DIR = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "FixAI" / "ipc"
else:
    IPC_DIR = Path("/var/run/fixai")

IPC_STATE_FILE = IPC_DIR / "telemetry_state.json"
IPC_ALERTS_FILE = IPC_DIR / "pending_alerts.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [DAEMON] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("fixai-daemon")

_running: bool = True


def _handle_shutdown(signum: int, _frame: Any) -> None:
    global _running
    logger.info("Daemon received signal %s — shutting down...", signum)
    _running = False


signal.signal(signal.SIGINT, _handle_shutdown)
signal.signal(signal.SIGTERM, _handle_shutdown)


# ───────────────────────────────────────────────────────────────────────────
# IPC: Atomic File Write
# ───────────────────────────────────────────────────────────────────────────

def _write_ipc_state(state: Dict[str, Any]) -> None:
    """
    Write telemetry state to IPC file atomically.
    Uses write-to-temp + rename pattern to prevent partial reads.
    """
    try:
        IPC_DIR.mkdir(parents=True, exist_ok=True)
        tmp_file = IPC_STATE_FILE.with_suffix(".tmp")
        tmp_file.write_text(json.dumps(state, default=str), encoding="utf-8")
        tmp_file.replace(IPC_STATE_FILE)
    except Exception as exc:
        logger.debug("IPC state write failed: %s", exc)


def _write_ipc_alert(alert_data: Dict[str, Any]) -> None:
    """Append an alert to the IPC alerts file for the UserAgent to consume."""
    try:
        IPC_DIR.mkdir(parents=True, exist_ok=True)
        alerts = []
        if IPC_ALERTS_FILE.exists():
            try:
                alerts = json.loads(IPC_ALERTS_FILE.read_text(encoding="utf-8"))
            except Exception:
                alerts = []

        alerts.append(alert_data)
        # Keep only last 20 alerts
        alerts = alerts[-20:]

        tmp_file = IPC_ALERTS_FILE.with_suffix(".tmp")
        tmp_file.write_text(json.dumps(alerts, default=str), encoding="utf-8")
        tmp_file.replace(IPC_ALERTS_FILE)
    except Exception as exc:
        logger.debug("IPC alert write failed: %s", exc)


# ───────────────────────────────────────────────────────────────────────────
# Metric Collection (same as main.py — shared logic)
# ───────────────────────────────────────────────────────────────────────────

def collect_hardware_metrics() -> Dict[str, float]:
    """Collect real-time hardware telemetry using psutil."""
    cpu_usage = float(psutil.cpu_percent(interval=1.0))
    memory_info = psutil.virtual_memory()

    try:
        path = "C:\\" if sys.platform == "win32" else "/"
        disk_usage = float(psutil.disk_usage(path).percent)
    except Exception:
        disk_usage = 75.0

    battery_pct = 100.0
    try:
        batt = psutil.sensors_battery()
        if batt:
            battery_pct = float(batt.percent)
    except Exception:
        battery_pct = 95.0

    core_temp = 48.0
    try:
        temps = psutil.sensors_temperatures() if hasattr(psutil, "sensors_temperatures") else {}
        if temps:
            for name, entries in temps.items():
                if entries:
                    core_temp = float(entries[0].current)
                    break
        else:
            core_temp = 42.0 + (cpu_usage * 0.45)
    except Exception:
        core_temp = 42.0 + (cpu_usage * 0.45)

    return {
        "cpu": round(cpu_usage, 1),
        "ram": round(float(memory_info.percent), 1),
        "latency": 12.0,
        "error_rate": 0.0,
        "disk": round(disk_usage, 1),
        "temp": round(core_temp, 1),
        "battery": round(battery_pct, 1),
    }


# ───────────────────────────────────────────────────────────────────────────
# Daemon Main Loop
# ───────────────────────────────────────────────────────────────────────────

def run_daemon() -> None:
    """
    Main daemon loop — collects metrics, runs AI inference, writes IPC state.
    Does NOT display any UI (no toasts, no windows) — safe for Session 0.
    """
    logger.info("================================================================")
    logger.info("  FixAI Telemetry Daemon (Session 0)")
    logger.info("  Device     : %s (ID: %s)", DEVICE_NAME, DEVICE_ID)
    logger.info("  IPC Dir    : %s", IPC_DIR)
    logger.info("  Interval   : %d seconds", POLL_INTERVAL)
    logger.info("================================================================")

    try:
        engine = EdgeAIEngine()
        recovery_mgr = RecoveryManager()
    except Exception as e:
        logger.critical("Failed to initialize daemon: %s", e)
        sys.exit(1)

    # ── EDR Security Alert Callback -> IPC Session 1 Bridge ─────────────
    def _on_edr_alert(narrative: SecurityNarrative) -> None:
        logger.warning("🚨 EDR ALERT: %s", narrative.title)
        _write_ipc_alert({
            "type": "EDR_SECURITY_ALERT",
            "title": narrative.title,
            "message": narrative.to_toast_summary(),
            "plain_text": narrative.to_plain_text(),
            "severity": narrative.severity,
            "timestamp": time.time(),
        })

    edr = EDREngine(on_security_alert=_on_edr_alert)

    # Watchdog — alerts go to IPC file instead of desktop notifications
    def _on_disk_alert(alert: DiskFillAlert) -> None:
        logger.warning("🚨 WATCHDOG: %s", alert)
        _write_ipc_alert({
            "type": "DISK_FILL",
            "title": "FixAI Disk Fill Alert",
            "message": f"{alert.alert_type} overflow at {alert.path} ({alert.size_mb}MB). Truncated: {alert.truncated}",
            "timestamp": time.time(),
        })

    # Hook WatchdogMonitor to also forward newly discovered files to EDR scanner
    watchdog = WatchdogMonitor(on_alert=_on_disk_alert, on_file_discovered=edr.inspect_file)
    watchdog.start()

    osquery = OsqueryCollector()
    osquery_available = osquery.is_available()

    cycle_count = 0
    last_osquery_data: Dict[str, Any] = {}
    last_edr_telemetry: Dict[str, Any] = {}

    while _running:
        cycle_start = time.time()
        cycle_count += 1

        try:
            metrics = collect_hardware_metrics()
            ai_results = engine.analyze(metrics)

            # EDR detection tick (Event logs, WMI persistence, LotL hierarchies)
            try:
                last_edr_telemetry = edr.run_detection_tick()
            except Exception as e:
                logger.debug("EDR tick note: %s", e)

            # Osquery every ~30s
            if osquery_available and (cycle_count % 6 == 0):
                try:
                    last_osquery_data = osquery.collect()
                except Exception:
                    pass

            # Build state for IPC
            risk = str(ai_results.get("risk", "LOW")).upper()
            state = {
                "device_id": DEVICE_ID,
                "device_name": DEVICE_NAME,
                "timestamp": time.time(),
                "cycle": cycle_count,
                "metrics": metrics,
                "ai_results": {
                    "anomaly_score": ai_results.get("anomaly_score", 0),
                    "p_failure": ai_results.get("p_failure", 0),
                    "risk": risk,
                    "nlg_explanation": ai_results.get("nlg_explanation", ""),
                },
                "osquery_data": last_osquery_data or None,
                "edr_telemetry": last_edr_telemetry or None,
                "watchdog_status": watchdog.get_status(),
            }

            # Write state atomically to IPC file
            _write_ipc_state(state)

            # Write alert to IPC if risk changed
            if risk in ("MEDIUM", "HIGH"):
                _write_ipc_alert({
                    "type": "RISK_ALERT",
                    "title": f"FixAI Alert: {risk} Risk Detected",
                    "message": (
                        f"Anomaly: {ai_results['anomaly_score']:.2f} | "
                        f"P(Failure): {ai_results['p_failure']:.2f} | "
                        f"{ai_results.get('nlg_explanation', '')[:80]}"
                    ),
                    "timestamp": time.time(),
                })

            logger.info(
                "Cycle #%d: CPU=%.1f%%, RAM=%.1f%%, Risk=%s, EDR=%s | IPC written",
                cycle_count, metrics["cpu"], metrics["ram"], risk,
                last_edr_telemetry.get("status", "SECURE"),
            )

            # Recovery actions
            pending = recovery_mgr.poll_for_actions()
            for action in pending:
                action_name = str(action.get("action_name", "flush_cache"))
                action_id = str(action.get("id", f"act-{int(time.time())}"))
                exec_result = recovery_mgr.execute_playbook(action_name, action.get("params"))
                if exec_result.get("success"):
                    val = recovery_mgr.validate_fix(
                        action_id=action_id,
                        incident_id=action.get("incident_id"),
                        action_name=action_name,
                    )
                    if val.get("is_health_restored"):
                        _write_ipc_alert({
                            "type": "SELF_HEAL",
                            "title": "FixAI Self-Healing Succeeded",
                            "message": f"Playbook '{action_name}' restored health.",
                            "timestamp": time.time(),
                        })

        except Exception as exc:
            logger.exception("Daemon cycle error: %s", exc)

        elapsed = time.time() - cycle_start
        time.sleep(max(0.1, POLL_INTERVAL - elapsed))

    watchdog.stop()
    logger.info("FixAI Telemetry Daemon stopped.")


if __name__ == "__main__":
    run_daemon()
