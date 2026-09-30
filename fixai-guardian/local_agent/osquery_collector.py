"""
FixAI — Osquery Telemetry Collector
=====================================

Integrates osquery for deep OS-level telemetry that psutil cannot provide:
  - Running Windows services and their states
  - Logged-in users and active sessions
  - Open network connections (listening ports, established connections)
  - Recently modified files in sensitive directories
  - Running processes with their hashes (integrity check)
  - Startup programs (autoruns — malware detection signal)

Design Principles:
  - GRACEFUL FALLBACK: If osquery is not installed, returns empty dict silently.
    The agent continues with psutil-only telemetry. Zero crashes.
  - ASYNC-SAFE: All queries run in a thread executor to avoid blocking the event loop.
  - CONFIGURABLE: Query interval is separate from psutil interval (default 30s).

Requirements:
  - osquery installed: https://osquery.io/downloads/official/
  - osqueryi accessible in PATH (Windows: C:\Program Files\osquery\osqueryi.exe)
  - Python: No pip install needed — uses subprocess to call osqueryi JSON output

Usage:
    collector = OsqueryCollector()
    data = collector.collect()  # returns dict, empty if osquery unavailable
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("fixai.osquery")

# ── Osquery Executable Discovery ─────────────────────────────────────────────
def _find_osqueryi() -> Optional[str]:
    """Find the osqueryi executable on the current system."""
    candidates: List[str] = []

    if sys.platform == "win32":
        candidates = [
            r"C:\Program Files\osquery\osqueryi.exe",
            r"C:\Program Files (x86)\osquery\osqueryi.exe",
            os.path.expandvars(r"%PROGRAMFILES%\osquery\osqueryi.exe"),
            "osqueryi.exe",
            "osqueryi",
        ]
    else:
        candidates = [
            "/usr/bin/osqueryi",
            "/usr/local/bin/osqueryi",
            "/opt/osquery/bin/osqueryi",
            "osqueryi",
        ]

    for candidate in candidates:
        try:
            resolved = Path(candidate)
            if resolved.exists() and resolved.is_file():
                return str(resolved)
        except Exception:
            pass

    # Try PATH lookup
    import shutil
    found = shutil.which("osqueryi")
    return found


# ── SQL Queries ───────────────────────────────────────────────────────────────
# These queries are safe, read-only SELECT statements
OSQUERY_QUERIES: Dict[str, str] = {
    "services": """
        SELECT name, status, start_type, path
        FROM services
        WHERE start_type = 'AUTO_START' AND status != 'RUNNING'
        LIMIT 20
    """,
    "users_logged_in": """
        SELECT user, host, time, pid
        FROM logged_in_users
        LIMIT 10
    """,
    "listening_ports": """
        SELECT address, port, protocol, state
        FROM listening_ports
        WHERE port < 65535
        LIMIT 20
    """,
    "running_processes": """
        SELECT name, pid, parent, path, sha256
        FROM processes
        WHERE pid > 4
        ORDER BY start_time DESC
        LIMIT 30
    """,
    "startup_items": """
        SELECT name, path, status, username
        FROM startup_items
        LIMIT 20
    """,
    "recently_modified_sensitive": """
        SELECT path, size, mtime, type
        FROM file
        WHERE path LIKE 'C:\\Windows\\System32\\%'
          AND mtime > (strftime('%s', 'now') - 3600)
          AND type = 'regular'
        LIMIT 15
    """ if sys.platform == "win32" else """
        SELECT path, size, mtime, type
        FROM file
        WHERE path LIKE '/etc/%'
          AND mtime > (strftime('%s', 'now') - 3600)
          AND type = 'regular'
        LIMIT 15
    """,
}


# ── Collector Class ───────────────────────────────────────────────────────────

class OsqueryCollector:
    """
    Runs osquery SQL queries to collect deep OS telemetry.
    Gracefully degrades to empty results if osquery is not installed.
    """

    def __init__(
        self,
        osqueryi_path: Optional[str] = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.osqueryi_path = osqueryi_path or _find_osqueryi()
        self.timeout = timeout_seconds
        self._available: Optional[bool] = None  # None = not yet checked

        if self.osqueryi_path:
            logger.info("OsqueryCollector: osqueryi found at %s", self.osqueryi_path)
        else:
            logger.info(
                "OsqueryCollector: osqueryi not found. "
                "Install from https://osquery.io to enable deep OS telemetry. "
                "Continuing with psutil-only telemetry."
            )

    def is_available(self) -> bool:
        """Check if osquery is installed and functional."""
        if self._available is not None:
            return self._available

        if not self.osqueryi_path:
            self._available = False
            return False

        # Quick connectivity test
        try:
            import subprocess
            result = subprocess.run(
                [self.osqueryi_path, "--json", "SELECT 1 AS test"],
                capture_output=True,
                timeout=3.0,
            )
            self._available = result.returncode == 0
        except Exception:
            self._available = False

        return self._available

    def _run_query(self, sql: str) -> List[Dict[str, Any]]:
        """
        Run a single osquery SQL statement synchronously.
        Returns parsed JSON results or empty list on error.
        """
        if not self.osqueryi_path:
            return []
        try:
            import subprocess
            result = subprocess.run(
                [self.osqueryi_path, "--json", sql.strip()],
                capture_output=True,
                timeout=self.timeout,
            )
            if result.returncode == 0:
                stdout = result.stdout.decode(errors="replace").strip()
                if stdout:
                    return json.loads(stdout)
            return []
        except (json.JSONDecodeError, subprocess.TimeoutExpired):
            return []
        except Exception as exc:
            logger.debug("osquery error for query: %s", exc)
            return []

    def collect(self) -> Dict[str, Any]:
        """
        Run all osquery queries and return aggregated telemetry dict.
        Returns empty dict if osquery is not available — caller handles gracefully.
        """
        if not self.is_available():
            return {}

        results: Dict[str, Any] = {}
        query_start = time.time()

        for key, sql in OSQUERY_QUERIES.items():
            try:
                rows = self._run_query(sql)
                results[key] = rows
            except Exception as exc:
                logger.debug("OsqueryCollector skipping query '%s': %s", key, exc)
                results[key] = []

        elapsed_ms = (time.time() - query_start) * 1000
        results["_meta"] = {
            "source": "osquery",
            "osqueryi_path": self.osqueryi_path,
            "elapsed_ms": round(elapsed_ms, 1),
            "timestamp": time.time(),
        }

        # ── Derived Security Signals ────────────────────────────────────
        # Flag stopped auto-start services (could indicate sabotage or crash)
        stopped_services = [
            s for s in results.get("services", [])
            if s.get("status", "").upper() != "RUNNING"
        ]
        results["security_signals"] = {
            "stopped_auto_services_count": len(stopped_services),
            "stopped_auto_services": stopped_services[:5],
            "listening_ports_count": len(results.get("listening_ports", [])),
            "startup_items_count": len(results.get("startup_items", [])),
            "recently_modified_sensitive_count": len(results.get("recently_modified_sensitive", [])),
        }

        logger.info(
            "✅ OsqueryCollector: collected %d query results in %.1fms",
            len(OSQUERY_QUERIES),
            elapsed_ms,
        )
        return results

    async def collect_async(self) -> Dict[str, Any]:
        """
        Async wrapper: runs the synchronous collect() in a thread executor
        so it never blocks the asyncio event loop.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.collect)


# ── Module-level singleton ────────────────────────────────────────────────────
# Shared instance used by the agent main loop
_default_collector: Optional[OsqueryCollector] = None


def get_collector() -> OsqueryCollector:
    """Get or create the shared OsqueryCollector singleton."""
    global _default_collector
    if _default_collector is None:
        _default_collector = OsqueryCollector()
    return _default_collector
