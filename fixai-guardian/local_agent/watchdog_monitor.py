"""
FixAI — Watchdog File System Monitor
=====================================

Production-grade disk fill detection using the Python `watchdog` library.
Monitors critical temp and log directories in real-time for:
  - Single files exceeding FILE_SIZE_LIMIT_MB (default: 500 MB)
  - Directories exceeding DIR_SIZE_LIMIT_GB (default: 2 GB)

On detection, auto-truncates offending files and fires an alert callback
so the main agent loop can send a desktop notification + telemetry event.

Usage:
    monitor = WatchdogMonitor(on_alert=my_callback)
    monitor.start()
    ...
    monitor.stop()
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("fixai.watchdog")

# ── Configuration ────────────────────────────────────────────────────────────
FILE_SIZE_LIMIT_MB: int = int(os.getenv("FIXAI_WATCHDOG_FILE_LIMIT_MB", "500"))
DIR_SIZE_LIMIT_GB: float = float(os.getenv("FIXAI_WATCHDOG_DIR_LIMIT_GB", "2.0"))
SCAN_INTERVAL_SECONDS: int = int(os.getenv("FIXAI_WATCHDOG_INTERVAL", "10"))

# Directories to watch (platform-aware)
def _get_watch_dirs() -> List[Path]:
    """Return list of directories to monitor for disk fill."""
    dirs: List[Path] = []

    if sys.platform == "win32":
        # Windows temp directories
        win_temp = os.environ.get("TEMP", r"C:\Windows\Temp")
        dirs.extend([
            Path(win_temp),
            Path(os.environ.get("LOCALAPPDATA", r"C:\Users\Default\AppData\Local")) / "Temp",
            Path(r"C:\Windows\Logs"),
        ])
    else:
        # Linux/macOS
        dirs.extend([
            Path("/tmp"),
            Path("/var/log"),
            Path("/var/tmp"),
        ])

    # Filter to directories that actually exist
    return [d for d in dirs if d.exists() and d.is_dir()]


# ── Alert Type ───────────────────────────────────────────────────────────────

class DiskFillAlert:
    """Represents a disk fill detection event."""

    def __init__(
        self,
        path: str,
        alert_type: str,
        size_mb: float,
        limit_mb: float,
        truncated: bool,
    ) -> None:
        self.path = path
        self.alert_type = alert_type  # "FILE" or "DIRECTORY"
        self.size_mb = round(size_mb, 1)
        self.limit_mb = round(limit_mb, 1)
        self.truncated = truncated
        self.timestamp = time.time()

    def __repr__(self) -> str:
        return (
            f"DiskFillAlert(type={self.alert_type}, path={self.path!r}, "
            f"size={self.size_mb}MB, limit={self.limit_mb}MB, truncated={self.truncated})"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "alert_type": self.alert_type,
            "size_mb": self.size_mb,
            "limit_mb": self.limit_mb,
            "truncated": self.truncated,
            "timestamp": self.timestamp,
        }


# ── Watchdog Monitor ─────────────────────────────────────────────────────────

class WatchdogMonitor:
    """
    Polls watched directories every SCAN_INTERVAL_SECONDS.
    On detection of oversized files or directories, auto-truncates
    and calls the on_alert callback.

    Note: Uses polling instead of inotify/FSEvents to work reliably
    across all platforms (including Windows) without requiring elevated privileges.
    """

    def __init__(
        self,
        watch_dirs: Optional[List[Path]] = None,
        on_alert: Optional[Callable[[DiskFillAlert], None]] = None,
        on_file_discovered: Optional[Callable[[Path], None]] = None,
        file_size_limit_mb: int = FILE_SIZE_LIMIT_MB,
        dir_size_limit_gb: float = DIR_SIZE_LIMIT_GB,
        scan_interval: int = SCAN_INTERVAL_SECONDS,
    ) -> None:
        self.watch_dirs = watch_dirs or _get_watch_dirs()
        self.on_alert = on_alert
        self.on_file_discovered = on_file_discovered
        self.file_limit_bytes = file_size_limit_mb * 1024 * 1024
        self.dir_limit_bytes = int(dir_size_limit_gb * 1024 * 1024 * 1024)
        self.scan_interval = scan_interval

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._alerted_paths: set[str] = set()  # debounce — don't spam same alert
        self._inspected_files: set[str] = set()

        logger.info(
            "WatchdogMonitor initialized: watching %d dirs, file limit=%dMB, dir limit=%.1fGB, interval=%ds",
            len(self.watch_dirs),
            file_size_limit_mb,
            dir_size_limit_gb,
            scan_interval,
        )

    def start(self) -> None:
        """Start the background monitoring thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="fixai-watchdog")
        self._thread.start()
        logger.info("🔍 WatchdogMonitor started. Watching: %s", [str(d) for d in self.watch_dirs])

    def stop(self) -> None:
        """Gracefully stop the monitoring thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.info("WatchdogMonitor stopped.")

    def _run_loop(self) -> None:
        """Main polling loop running in background thread."""
        while self._running:
            try:
                self._scan_all()
            except Exception as exc:
                logger.warning("WatchdogMonitor scan error (will retry): %s", exc)
            time.sleep(self.scan_interval)

    def _scan_all(self) -> None:
        """Scan all watched directories for oversized files and directories."""
        for watch_dir in self.watch_dirs:
            if not watch_dir.exists():
                continue
            try:
                self._scan_directory(watch_dir)
            except PermissionError:
                pass  # Skip dirs we can't read
            except Exception as exc:
                logger.debug("Error scanning %s: %s", watch_dir, exc)

    def _scan_directory(self, directory: Path) -> None:
        """
        Scan a single directory:
          1. Check total directory size against DIR_LIMIT
          2. Check each file against FILE_LIMIT
          3. Auto-truncate offending files safely
        """
        total_size = 0
        offending_files: List[tuple[Path, int]] = []

        for root, dirs, files in os.walk(directory):
            # Skip hidden directories and system dirs
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("System32", "SysWOW64")]
            for fname in files:
                fpath = Path(root) / fname
                try:
                    fsize = fpath.stat().st_size
                    total_size += fsize
                    if fsize > self.file_limit_bytes:
                        offending_files.append((fpath, fsize))

                    # EDR File Inspection Hook
                    if self.on_file_discovered and str(fpath) not in self._inspected_files:
                        self._inspected_files.add(str(fpath))
                        # Keep set bounded
                        if len(self._inspected_files) > 5000:
                            self._inspected_files = set(list(self._inspected_files)[-2500:])
                        try:
                            self.on_file_discovered(fpath)
                        except Exception as e:
                            logger.debug("Error in on_file_discovered callback: %s", e)

                except (OSError, PermissionError):
                    continue

        # Check file-level violations
        for fpath, fsize in offending_files:
            size_mb = fsize / (1024 * 1024)
            limit_mb = self.file_limit_bytes / (1024 * 1024)
            path_key = str(fpath)

            if path_key not in self._alerted_paths:
                truncated = self._safe_truncate_file(fpath)
                alert = DiskFillAlert(
                    path=path_key,
                    alert_type="FILE",
                    size_mb=size_mb,
                    limit_mb=limit_mb,
                    truncated=truncated,
                )
                self._alerted_paths.add(path_key)
                logger.warning(
                    "🚨 DISK FILL DETECTED: %s (%.1f MB > %.1f MB limit). Truncated: %s",
                    path_key, size_mb, limit_mb, truncated,
                )
                self._fire_alert(alert)

        # Check directory-level violations
        if total_size > self.dir_limit_bytes:
            size_mb = total_size / (1024 * 1024)
            limit_mb = self.dir_limit_bytes / (1024 * 1024)
            dir_key = f"DIR:{directory}"

            if dir_key not in self._alerted_paths:
                self._alerted_paths.add(dir_key)
                alert = DiskFillAlert(
                    path=str(directory),
                    alert_type="DIRECTORY",
                    size_mb=size_mb,
                    limit_mb=limit_mb,
                    truncated=False,
                )
                logger.warning(
                    "🚨 DIRECTORY SIZE EXCEEDED: %s (%.1f MB > %.1f MB limit)",
                    directory, size_mb, limit_mb,
                )
                self._fire_alert(alert)
        else:
            # Reset debounce for directory when it recovers
            dir_key = f"DIR:{directory}"
            self._alerted_paths.discard(dir_key)

    def _safe_truncate_file(self, fpath: Path) -> bool:
        """
        Safely truncate an oversized log/temp file to 0 bytes.
        Only truncates files in temp/log directories — never user documents.
        Returns True if truncation succeeded.
        """
        # Safety: only truncate files in temp/log paths — never user dirs
        safe_prefixes = (
            str(Path(os.environ.get("TEMP", "")).resolve()).lower(),
            str(Path(os.environ.get("TMP", "")).resolve()).lower(),
            r"c:\windows\logs",
            "/tmp",
            "/var/log",
            "/var/tmp",
        )
        path_str = str(fpath).lower()
        is_safe = any(path_str.startswith(p) for p in safe_prefixes if p)

        if not is_safe:
            logger.debug("Skipping truncation of non-temp file: %s", fpath)
            return False

        try:
            # Truncate to zero length — preserves the file handle for any process writing to it
            with open(fpath, "w") as f:
                f.truncate(0)
            logger.info("✅ Auto-truncated oversized file: %s", fpath)
            return True
        except (OSError, PermissionError) as exc:
            logger.debug("Could not truncate %s: %s", fpath, exc)
            return False

    def _fire_alert(self, alert: DiskFillAlert) -> None:
        """Fire the alert callback in the main thread context."""
        if self.on_alert:
            try:
                self.on_alert(alert)
            except Exception as exc:
                logger.warning("Alert callback error: %s", exc)

    def get_status(self) -> Dict[str, Any]:
        """Return current monitor status for diagnostic endpoints."""
        return {
            "running": self._running,
            "watch_dirs": [str(d) for d in self.watch_dirs],
            "file_limit_mb": self.file_limit_bytes / (1024 * 1024),
            "dir_limit_gb": self.dir_limit_bytes / (1024 * 1024 * 1024),
            "scan_interval_seconds": self.scan_interval,
            "active_alerts": len(self._alerted_paths),
        }
