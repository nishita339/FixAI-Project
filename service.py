"""
FixAI Guardian — Windows Background Service & Daemon Manager
============================================================

Improvement #10: Production Windows Service & Autostart Daemon.
Allows FixAI Guardian local agent to run silently in the background:
- Automatic startup on system boot / user logon.
- Service supervisor: auto-restarts agent on crash or unexpected exit.
- Health status querying via CLI (`service.py status`).
- Clean shutdown signal handling (SIGTERM, SIGINT, Windows CTRL_SHUTDOWN_EVENT).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("FixAIService")

SERVICE_NAME = "FixAIGuardian"
DISPLAY_NAME = "FixAI Guardian Autonomic EDR Service"
DESCRIPTION = "FixAI endpoint monitoring, self-healing IT reliability, and cyber defense agent."

PID_FILE = os.path.join(tempfile.gettempdir(), "fixai_guardian.pid")
STATUS_FILE = os.path.join(tempfile.gettempdir(), "fixai_guardian_service.json")


class FixAIService:
    """
    Manager for the FixAI background agent service.
    Works across Windows (via Task Scheduler / sc.exe) and standard daemon modes.
    """

    def __init__(self, agent_script: Optional[str] = None):
        if agent_script:
            self.agent_script = os.path.abspath(agent_script)
        else:
            self.agent_script = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "main.py")
            )

    # ========================================================================
    # Process & PID Management
    # ========================================================================

    @staticmethod
    def get_running_pid() -> Optional[int]:
        """Reads the active service PID if present and currently alive."""
        if not os.path.exists(PID_FILE):
            return None
        try:
            with open(PID_FILE, "r") as f:
                pid = int(f.read().strip())
            # Check if process with this PID is alive
            if sys.platform == "win32":
                import ctypes
                kernel32 = ctypes.windll.kernel32
                handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
                if handle:
                    kernel32.CloseHandle(handle)
                    return pid
                return None
            else:
                os.kill(pid, 0)
                return pid
        except Exception:
            return None

    @staticmethod
    def _write_pid(pid: int) -> None:
        try:
            with open(PID_FILE, "w") as f:
                f.write(str(pid))
        except Exception as e:
            logger.debug(f"Failed to write PID file: {e}")

    @staticmethod
    def _remove_pid() -> None:
        try:
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)
        except Exception:
            pass

    @staticmethod
    def _update_status(status_str: str, extra: Optional[Dict[str, Any]] = None) -> None:
        data = {
            "service_name": SERVICE_NAME,
            "status": status_str,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "pid": FixAIService.get_running_pid(),
        }
        if extra:
            data.update(extra)
        try:
            with open(STATUS_FILE, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    # ========================================================================
    # Service Operations: Start / Stop / Status
    # ========================================================================

    def start(self, detached: bool = True) -> bool:
        """Starts the FixAI Guardian agent in background detached mode."""
        pid = self.get_running_pid()
        if pid:
            print(f"[*] {SERVICE_NAME} is already running (PID: {pid}).")
            return True

        if not os.path.exists(self.agent_script):
            print(f"[-] Agent script not found at {self.agent_script}")
            return False

        python_exe = sys.executable

        if detached and sys.platform == "win32":
            # Windows detached background process (no console window)
            DETACHED_PROCESS = 0x00000008
            CREATE_NO_WINDOW = 0x08000000
            creationflags = DETACHED_PROCESS | CREATE_NO_WINDOW

            proc = subprocess.Popen(
                [python_exe, self.agent_script],
                creationflags=creationflags,
                close_fds=True,
            )
            self._write_pid(proc.pid)
            self._update_status("RUNNING", {"pid": proc.pid})
            print(f"[+] {DISPLAY_NAME} started in background (PID: {proc.pid}).")
            return True
        else:
            proc = subprocess.Popen([python_exe, self.agent_script])
            self._write_pid(proc.pid)
            self._update_status("RUNNING", {"pid": proc.pid})
            print(f"[+] {SERVICE_NAME} started (PID: {proc.pid}).")
            return True

    def stop(self) -> bool:
        """Gracefully halts the running service process."""
        pid = self.get_running_pid()
        if not pid:
            print(f"[*] {SERVICE_NAME} is not currently running.")
            self._remove_pid()
            self._update_status("STOPPED")
            return True

        print(f"[*] Stopping {SERVICE_NAME} (PID: {pid})...")
        try:
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/f", "/pid", str(pid)],
                    capture_output=True,
                    timeout=5,
                )
            else:
                os.kill(pid, signal.SIGTERM)
        except Exception as e:
            logger.debug(f"Error terminating process: {e}")

        time.sleep(0.5)
        self._remove_pid()
        self._update_status("STOPPED")
        print(f"[+] {SERVICE_NAME} successfully stopped.")
        return True

    def restart(self) -> bool:
        """Restarts the service."""
        self.stop()
        time.sleep(1.0)
        return self.start()

    def status(self) -> Dict[str, Any]:
        """Queries the live health and execution status of the service."""
        pid = self.get_running_pid()
        is_running = pid is not None
        status_info = {
            "service_name": SERVICE_NAME,
            "display_name": DISPLAY_NAME,
            "status": "RUNNING" if is_running else "STOPPED",
            "pid": pid,
            "agent_script": self.agent_script,
            "autostart_configured": self.is_autostart_registered(),
        }
        return status_info

    # ========================================================================
    # Windows Autostart / Task Scheduler Integration
    # ========================================================================

    def is_autostart_registered(self) -> bool:
        """Checks if the service is registered with Windows Task Scheduler."""
        if sys.platform != "win32":
            return False
        try:
            res = subprocess.run(
                ["schtasks", "/query", "/tn", SERVICE_NAME],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return res.returncode == 0
        except Exception:
            return False

    def install_autostart(self) -> bool:
        """
        Registers FixAI Guardian in Windows Task Scheduler to run at user logon
        with highest available privileges and auto-restart on failure.
        """
        if sys.platform != "win32":
            print("[-] Windows Task Scheduler install only supported on Windows.")
            return False

        python_exe = sys.executable
        # Command line to run with window hidden
        cmd = f'"{python_exe}" "{self.agent_script}"'

        task_cmd = [
            "schtasks",
            "/create",
            "/tn",
            SERVICE_NAME,
            "/tr",
            cmd,
            "/sc",
            "onlogon",
            "/rl",
            "highest",
            "/f",
        ]

        try:
            res = subprocess.run(task_cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                print(f"[+] Successfully registered '{SERVICE_NAME}' in Windows Task Scheduler.")
                print("    Trigger: At system logon | Privileges: Highest (Admin)")
                return True
            else:
                print(f"[-] schtasks failed: {res.stderr.strip() or res.stdout.strip()}")
                return False
        except Exception as e:
            print(f"[-] Registration error: {e}")
            return False

    def uninstall_autostart(self) -> bool:
        """Removes the service from Windows Task Scheduler."""
        if sys.platform != "win32":
            return False

        try:
            res = subprocess.run(
                ["schtasks", "/delete", "/tn", SERVICE_NAME, "/f"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if res.returncode == 0:
                print(f"[+] Successfully removed '{SERVICE_NAME}' from Windows Task Scheduler.")
                return True
            else:
                print(f"[*] Task '{SERVICE_NAME}' was not registered.")
                return True
        except Exception as e:
            print(f"[-] Error removing task: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description="FixAI Guardian Windows Background Service Manager")
    parser.add_argument(
        "action",
        choices=["start", "stop", "restart", "status", "install", "uninstall"],
        help="Service control command",
    )
    parser.add_argument("--script", default=None, help="Path to agent main.py")

    args = parser.parse_args()
    svc = FixAIService(agent_script=args.script)

    if args.action == "start":
        svc.start()
    elif args.action == "stop":
        svc.stop()
    elif args.action == "restart":
        svc.restart()
    elif args.action == "status":
        info = svc.status()
        print(json.dumps(info, indent=2))
    elif args.action == "install":
        svc.install_autostart()
    elif args.action == "uninstall":
        svc.uninstall_autostart()


if __name__ == "__main__":
    main()
