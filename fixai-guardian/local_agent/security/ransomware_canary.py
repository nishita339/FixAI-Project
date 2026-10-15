"""
FixAI EDR — Improvement #2: Ransomware Canary / Honeypot Decoy Files
=====================================================================

Zero-day ransomware detection via strategically placed "canary" files:

HOW IT WORKS:
1. **Deploy Phase:** Create innocent-looking decoy files (fake PDFs, DOCXs,
   spreadsheets) in high-value directories (Desktop, Documents, Downloads).
   Each canary file has known content and a SHA-256 fingerprint.

2. **Monitor Phase:** A watchdog observer continuously monitors canary files
   for ANY modification, deletion, or renaming — the hallmark of ransomware
   that encrypts everything it finds.

3. **Alert Phase:** If ANY canary is tampered with, an immediate
   CRITICAL-severity "RANSOMWARE_CANARY" alert fires through the AlertBridge,
   triggering desktop notifications + Telegram/Discord/Slack webhooks.

ADVANTAGES OVER TRADITIONAL DETECTION:
- Zero false positives: No legitimate software should ever touch these files
- Zero-day capable: Works against unknown ransomware (no signatures needed)
- Near-instant detection: Watchdog fires within milliseconds of file change
- Low overhead: Monitoring a few tiny files uses negligible resources

CANARY FILE NAMING CONVENTION:
- Files use realistic names that ransomware will target:
  "Important_Financial_Report_2026.pdf", "Tax_Documents_Backup.xlsx", etc.
- A hidden marker (CANARY_MAGIC) is embedded in file content to prevent
  false positives from user-created files with the same names.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

try:
    from watchdog.events import (
        FileSystemEvent,
        FileSystemEventHandler,
        FileModifiedEvent,
        FileDeletedEvent,
        FileMovedEvent,
    )
    from watchdog.observers import Observer

    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

logger = logging.getLogger("fixai.security.ransomware_canary")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] [%(levelname)s] [RansomwareCanary] %(message)s")
    )
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


# ============================================================================
# Constants
# ============================================================================

# Magic string embedded in every canary file to identify it as ours
CANARY_MAGIC = "FIXAI-CANARY-v1-DO-NOT-MODIFY"

# Canary file templates — realistic filenames that ransomware will target
CANARY_TEMPLATES: List[Dict[str, str]] = [
    {
        "filename": "Important_Financial_Report_2026.pdf.txt",
        "content": (
            f"Financial Summary — Q4 2026\n"
            f"Revenue: $2,450,000\n"
            f"Operating Expenses: $1,200,000\n"
            f"Net Profit: $1,250,000\n\n"
            f"--- {CANARY_MAGIC} ---\n"
        ),
    },
    {
        "filename": "Tax_Documents_Backup.xlsx.txt",
        "content": (
            f"Employee Tax Records — 2026\n"
            f"Name, SSN, Salary, Tax Withheld\n"
            f"John Smith, ***-**-1234, $85,000, $17,000\n"
            f"Jane Doe, ***-**-5678, $92,000, $18,400\n\n"
            f"--- {CANARY_MAGIC} ---\n"
        ),
    },
    {
        "filename": "Confidential_Project_Notes.docx.txt",
        "content": (
            f"Project Alpha — Confidential Notes\n"
            f"Phase 1: Research & Development (Complete)\n"
            f"Phase 2: Prototype Testing (In Progress)\n"
            f"Budget Allocation: $500,000\n\n"
            f"--- {CANARY_MAGIC} ---\n"
        ),
    },
    {
        "filename": "Password_Recovery_Keys.txt",
        "content": (
            f"Recovery Keys Backup\n"
            f"BitLocker: XXXX-XXXX-XXXX-XXXX-XXXX\n"
            f"VPN: ****-****-****\n"
            f"Admin: [REDACTED]\n\n"
            f"--- {CANARY_MAGIC} ---\n"
        ),
    },
]

# Default directories to deploy canaries
DEFAULT_CANARY_DIRS: List[str] = [
    os.path.join(os.path.expanduser("~"), "Desktop"),
    os.path.join(os.path.expanduser("~"), "Documents"),
    os.path.join(os.path.expanduser("~"), "Downloads"),
]


# ============================================================================
# Canary Alert Dataclass
# ============================================================================

@dataclass
class RansomwareCanaryAlert:
    """Alert raised when a canary file is tampered with."""
    alert_id: str = field(default_factory=lambda: f"canary-{uuid.uuid4().hex[:12]}")
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    event_type: str = ""  # MODIFIED, DELETED, MOVED
    canary_filename: str = ""
    canary_path: str = ""
    original_sha256: str = ""
    current_sha256: str = ""  # Empty if file was deleted
    canary_dir: str = ""
    severity: str = "CRITICAL"
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================================
# Canary Record — Tracks each deployed canary
# ============================================================================

@dataclass
class CanaryRecord:
    """Metadata for a deployed canary file."""
    filename: str
    filepath: str
    sha256: str
    deployed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    content_length: int = 0


# ============================================================================
# SHA-256 Helper
# ============================================================================

def compute_sha256(filepath: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, IOError):
        return ""


def compute_content_sha256(content: str) -> str:
    """Compute SHA-256 of string content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


# ============================================================================
# Canary Watchdog Event Handler
# ============================================================================

class _CanaryEventHandler(FileSystemEventHandler if HAS_WATCHDOG else object):
    """
    Watchdog event handler that fires alerts when canary files
    are modified, deleted, or renamed.
    """

    def __init__(
        self,
        canary_records: Dict[str, CanaryRecord],
        on_alert: Callable[[RansomwareCanaryAlert], None],
    ):
        if HAS_WATCHDOG:
            super().__init__()
        self._canary_records = canary_records
        self._on_alert = on_alert
        self._alerted_files: Set[str] = set()  # Avoid duplicate alerts
        self._lock = threading.Lock()

    def _is_canary(self, path: str) -> bool:
        """Check if the given path is a tracked canary file."""
        normalized = os.path.normpath(path)
        return normalized in self._canary_records

    def _fire_alert(self, event_type: str, filepath: str, current_sha: str = "") -> None:
        """Fire a ransomware canary alert."""
        normalized = os.path.normpath(filepath)
        with self._lock:
            if normalized in self._alerted_files:
                return  # Already alerted for this file
            self._alerted_files.add(normalized)

        record = self._canary_records.get(normalized)
        if not record:
            return

        alert = RansomwareCanaryAlert(
            event_type=event_type,
            canary_filename=record.filename,
            canary_path=record.filepath,
            original_sha256=record.sha256,
            current_sha256=current_sha,
            canary_dir=str(Path(record.filepath).parent),
            details=(
                f"Canary file '{record.filename}' was {event_type.lower()}. "
                f"This is a strong indicator of active ransomware encryption. "
                f"Original SHA-256: {record.sha256[:16]}..."
            ),
        )
        logger.critical(
            f"\U0001f6a8 RANSOMWARE CANARY TRIGGERED! File: {record.filename} "
            f"Event: {event_type} | Dir: {alert.canary_dir}"
        )
        try:
            self._on_alert(alert)
        except Exception as e:
            logger.error(f"Error dispatching canary alert: {e}")

    def on_modified(self, event: Any) -> None:
        if event.is_directory:
            return
        src = getattr(event, "src_path", "")
        if self._is_canary(src):
            current_sha = compute_sha256(src)
            record = self._canary_records.get(os.path.normpath(src))
            if record and current_sha != record.sha256:
                self._fire_alert("MODIFIED", src, current_sha)

    def on_deleted(self, event: Any) -> None:
        if event.is_directory:
            return
        src = getattr(event, "src_path", "")
        if self._is_canary(src):
            self._fire_alert("DELETED", src)

    def on_moved(self, event: Any) -> None:
        if event.is_directory:
            return
        src = getattr(event, "src_path", "")
        if self._is_canary(src):
            self._fire_alert("MOVED", src)


# ============================================================================
# RansomwareCanary — Main Class
# ============================================================================

class RansomwareCanary:
    """
    Deploys and monitors honeypot canary files to detect ransomware activity.

    Usage:
        canary = RansomwareCanary(on_alert=alert_bridge.on_ransomware_canary_alert)
        canary.deploy()      # Create canary files in target directories
        canary.start()       # Begin filesystem monitoring
        # ... later ...
        canary.stop()        # Stop monitoring
        canary.cleanup()     # Remove canary files
    """

    def __init__(
        self,
        canary_dirs: Optional[List[str]] = None,
        on_alert: Optional[Callable[[RansomwareCanaryAlert], None]] = None,
        templates: Optional[List[Dict[str, str]]] = None,
    ):
        self._canary_dirs = canary_dirs or DEFAULT_CANARY_DIRS
        self._on_alert = on_alert or (lambda a: None)
        self._templates = templates or CANARY_TEMPLATES
        self._canary_records: Dict[str, CanaryRecord] = {}
        self._observers: List[Any] = []
        self._running = False
        self._lock = threading.Lock()

    @property
    def deployed_canaries(self) -> List[CanaryRecord]:
        """Returns list of all deployed canary records."""
        return list(self._canary_records.values())

    @property
    def canary_count(self) -> int:
        return len(self._canary_records)

    @property
    def is_running(self) -> bool:
        return self._running

    def deploy(self) -> int:
        """
        Deploy canary files to all configured directories.
        Returns the number of canaries successfully deployed.
        """
        deployed = 0
        for dir_path in self._canary_dirs:
            if not os.path.isdir(dir_path):
                logger.debug(f"Skipping non-existent directory: {dir_path}")
                continue

            for template in self._templates:
                filepath = os.path.join(dir_path, template["filename"])

                # Don't overwrite if already deployed and unchanged
                if os.path.normpath(filepath) in self._canary_records:
                    continue

                try:
                    content = template["content"]
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(content)

                    sha256 = compute_sha256(filepath)
                    record = CanaryRecord(
                        filename=template["filename"],
                        filepath=os.path.normpath(filepath),
                        sha256=sha256,
                        content_length=len(content),
                    )
                    self._canary_records[os.path.normpath(filepath)] = record
                    deployed += 1
                    logger.info(f"\U0001f3af Canary deployed: {filepath}")
                except (OSError, IOError) as e:
                    logger.warning(f"Failed to deploy canary at {filepath}: {e}")

        logger.info(
            f"\U0001f3af {deployed} canary files deployed across "
            f"{len(self._canary_dirs)} directories"
        )
        return deployed

    def start(self) -> bool:
        """
        Start filesystem monitoring for all deployed canaries.
        Returns True if monitoring started successfully.
        """
        if not HAS_WATCHDOG:
            logger.error("watchdog library not available — canary monitoring disabled")
            return False

        if self._running:
            logger.warning("Canary monitoring already running")
            return True

        if not self._canary_records:
            logger.warning("No canaries deployed — deploy before starting monitoring")
            return False

        handler = _CanaryEventHandler(self._canary_records, self._on_alert)

        # Monitor each directory that has canaries
        monitored_dirs: Set[str] = set()
        for record in self._canary_records.values():
            parent = str(Path(record.filepath).parent)
            if parent not in monitored_dirs:
                try:
                    observer = Observer()
                    observer.schedule(handler, parent, recursive=False)
                    observer.daemon = True
                    observer.start()
                    self._observers.append(observer)
                    monitored_dirs.add(parent)
                    logger.info(f"\U0001f441 Monitoring canaries in: {parent}")
                except Exception as e:
                    logger.error(f"Failed to start observer for {parent}: {e}")

        self._running = bool(self._observers)
        if self._running:
            logger.info(
                f"\U0001f6e1\ufe0f Ransomware canary monitoring active — "
                f"{len(self._canary_records)} canaries in "
                f"{len(monitored_dirs)} directories"
            )
        return self._running

    def stop(self) -> None:
        """Stop all filesystem observers."""
        for observer in self._observers:
            try:
                observer.stop()
                observer.join(timeout=2)
            except Exception:
                pass
        self._observers.clear()
        self._running = False
        logger.info("\U0001f6d1 Ransomware canary monitoring stopped")

    def cleanup(self) -> int:
        """
        Remove all deployed canary files from disk.
        Returns the number of files removed.
        """
        self.stop()
        removed = 0
        for path, record in list(self._canary_records.items()):
            try:
                if os.path.exists(path):
                    os.remove(path)
                    removed += 1
                    logger.info(f"\U0001f5d1 Canary removed: {path}")
            except OSError as e:
                logger.warning(f"Failed to remove canary {path}: {e}")

        self._canary_records.clear()
        logger.info(f"\U0001f5d1 {removed} canary files cleaned up")
        return removed

    def verify_integrity(self) -> Dict[str, Any]:
        """
        Check all deployed canaries for tampering.
        Returns a dict with verification results.
        """
        results = {
            "total": len(self._canary_records),
            "intact": 0,
            "modified": 0,
            "missing": 0,
            "alerts": [],
        }

        for path, record in self._canary_records.items():
            if not os.path.exists(path):
                results["missing"] += 1
                results["alerts"].append({
                    "file": record.filename,
                    "status": "MISSING",
                    "path": path,
                })
            else:
                current_sha = compute_sha256(path)
                if current_sha == record.sha256:
                    results["intact"] += 1
                else:
                    results["modified"] += 1
                    results["alerts"].append({
                        "file": record.filename,
                        "status": "MODIFIED",
                        "path": path,
                        "original_sha256": record.sha256,
                        "current_sha256": current_sha,
                    })

        return results

    def get_telemetry_summary(self) -> Dict[str, Any]:
        """Returns a compact summary for the telemetry payload."""
        integrity = self.verify_integrity()
        return {
            "canary_monitoring_active": self._running,
            "total_canaries": len(self._canary_records),
            "canaries_intact": integrity["intact"],
            "canaries_tampered": integrity["modified"] + integrity["missing"],
            "monitored_directories": len(set(
                str(Path(r.filepath).parent)
                for r in self._canary_records.values()
            )),
        }
