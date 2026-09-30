"""
FixAI Security Subsystem — Phase 2: Real-Time Malware Detection (Heuristics & YARA)
===================================================================================

Monitors the Downloads and Temp directories in real time using `watchdog`.
When a new executable (.exe, .ps1, .dll, .bat, etc.) is created or modified:
1. Calculates its Shannon Entropy (entropy > 7.2 flags packed malware / ransomware).
2. Runs a YARA scanner with heuristic rules (detects dropper strings, LotL commands, test signatures).
3. Computes SHA-256 hash for forensic traceability.
4. Triggers MaliciousFileAlert if heuristics or YARA rules are breached.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import sys
import threading
import time
import uuid
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

try:
    import yara  # type: ignore
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

logger = logging.getLogger("fixai.security.file_monitor")

# Monitored executable and script file extensions
SUSPICIOUS_EXTENSIONS: Set[str] = {
    ".exe",
    ".ps1",
    ".dll",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".scr",
    ".bin",
    ".msi",
}

# Shannon entropy threshold (pure random / AES encrypted / packed malware is typically > 7.2)
ENTROPY_THRESHOLD: float = 7.2

# Default Heuristic & Test YARA Rule
DEFAULT_YARA_RULES = """
rule SuspiciousDropper {
    meta:
        description = "Detects suspicious droppers, obfuscated PowerShell, ransomware commands, and test payloads"
        author = "FixAI DevSecOps"
        severity = "HIGH"
    strings:
        $s1 = "Invoke-Expression" nocase
        $s2 = "DownloadString" nocase
        $s3 = "powershell.exe -enc" nocase
        $s4 = "powershell.exe -e " nocase
        $s5 = "sekurlsa::logonpasswords" nocase
        $s6 = "vssadmin delete shadows" nocase
        $s7 = "mimikatz" nocase
        $s8 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        $s9 = "FIXAI_TEST_MALWARE_SIGNATURE"
    condition:
        any of them
}

rule SuspiciousRansomwareNote {
    meta:
        description = "Detects common ransomware extortion and decryptor strings"
        author = "FixAI DevSecOps"
        severity = "CRITICAL"
    strings:
        $r1 = "YOUR FILES ARE ENCRYPTED" nocase
        $r2 = "pay bitcoin to recover" nocase
        $r3 = ".locked" nocase
    condition:
        any of them
}
"""


def calculate_shannon_entropy(file_path: Path | str, chunk_size: int = 65536) -> float:
    """
    Calculate Shannon Entropy H(X) = -sum(P(x) * log2(P(x))) for a given file.
    Value ranges from 0.0 (completely uniform/zero variance) to 8.0 (pure random/encrypted).
    Entropy > 7.2 strongly correlates with UPX/packed executables, crypters, and ransomware.
    """
    path = Path(file_path)
    if not path.is_file() or path.stat().st_size == 0:
        return 0.0

    counts = Counter()
    total_bytes = 0

    try:
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                counts.update(chunk)
                total_bytes += len(chunk)

        if total_bytes == 0:
            return 0.0

        entropy = 0.0
        for count in counts.values():
            p_x = count / total_bytes
            entropy -= p_x * math.log2(p_x)

        return round(entropy, 3)
    except Exception as exc:
        logger.debug("Could not calculate entropy for %s: %s", path, exc)
        return 0.0


def calculate_sha256(file_path: Path | str, chunk_size: int = 65536) -> str:
    """Compute cryptographic SHA-256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest().lower()
    except Exception:
        return ""


@dataclass
class MaliciousFileAlert:
    """Alert triggered when a file violates entropy heuristics or matches YARA signatures."""
    alert_id: str
    file_path: str
    file_name: str
    file_size_bytes: int
    sha256: str
    entropy: float
    is_high_entropy: bool
    yara_matches: List[str]
    threat_reasons: List[str]
    severity: str
    detected_at: float = field(default_factory=time.time)
    iso_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def summary(self) -> str:
        return (
            f"[🚨 MALICIOUS FILE DETECTED] File: {self.file_name} | Path: {self.file_path} | "
            f"Entropy: {self.entropy:.2f}/8.0 (High: {self.is_high_entropy}) | "
            f"YARA Matches: {self.yara_matches or 'None'} | "
            f"Severity: {self.severity} | Reasons: {', '.join(self.threat_reasons)}"
        )


def _get_default_watch_dirs() -> List[Path]:
    """Resolve standard user Downloads and system Temp directories."""
    dirs: List[Path] = []

    # 1. User Downloads directory
    user_downloads = Path.home() / "Downloads"
    if user_downloads.exists():
        dirs.append(user_downloads)

    # 2. System and User Temp directories
    if sys.platform == "win32":
        win_temp = os.environ.get("TEMP", r"C:\Windows\Temp")
        dirs.append(Path(win_temp))
        local_temp = Path(os.environ.get("LOCALAPPDATA", "")) / "Temp"
        if local_temp.exists():
            dirs.append(local_temp)
    else:
        dirs.extend([Path("/tmp"), Path("/var/tmp")])

    # De-duplicate while preserving order
    seen = set()
    valid_dirs = []
    for d in dirs:
        resolved = d.resolve()
        if resolved.exists() and resolved.is_dir() and resolved not in seen:
            seen.add(resolved)
            valid_dirs.append(resolved)

    return valid_dirs


class _FileEventHandler(FileSystemEventHandler):
    """Internal Watchdog event handler dispatching file creation/modification to scanner."""

    def __init__(self, monitor: FileMonitor):
        super().__init__()
        self.monitor = monitor

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.monitor._on_file_activity(Path(event.src_path))

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.monitor._on_file_activity(Path(event.src_path))


class FileMonitor:
    """
    Real-Time File Integrity & Malware Detection Service using Watchdog,
    Shannon Entropy heuristics, and YARA pattern signatures.
    """

    def __init__(
        self,
        watch_dirs: Optional[List[Path]] = None,
        entropy_threshold: float = ENTROPY_THRESHOLD,
        yara_rules_source: str = DEFAULT_YARA_RULES,
        on_alert: Optional[Callable[[MaliciousFileAlert], None]] = None,
        allowed_extensions: Optional[Set[str]] = None,
        debounce_seconds: float = 2.0,
    ):
        self.watch_dirs = watch_dirs if watch_dirs is not None else _get_default_watch_dirs()
        self.entropy_threshold = entropy_threshold
        self.on_alert = on_alert
        self.allowed_extensions = allowed_extensions or SUSPICIOUS_EXTENSIONS
        self.debounce_seconds = debounce_seconds

        # Compile YARA rules if available
        self.yara_rules = None
        if HAS_YARA:
            try:
                self.yara_rules = yara.compile(source=yara_rules_source)
                logger.info("✅ YARA scanner initialized with heuristic signature rules.")
            except Exception as exc:
                logger.warning("Failed to compile YARA rules: %s", exc)

        self._observer: Optional[Observer] = None
        self._running = False
        # Dedup cache: path -> last_scanned_timestamp
        self._scanned_cache: Dict[str, float] = {}
        self._lock = threading.Lock()

    def scan_file_manually(self, file_path: Path | str) -> Optional[MaliciousFileAlert]:
        """
        Scan a single file directly against Shannon entropy heuristics and YARA rules.
        Returns a MaliciousFileAlert if the file is flagged suspicious, else None.
        """
        path = Path(file_path)
        if not path.is_file():
            return None

        # Check extension filter
        ext = path.suffix.lower()
        if self.allowed_extensions and ext not in self.allowed_extensions:
            return None

        # Give file writer a brief moment if file is freshly created and locked
        time.sleep(0.05)

        try:
            file_size = path.stat().st_size
        except Exception:
            return None

        if file_size == 0:
            return None

        entropy = calculate_shannon_entropy(path)
        sha256 = calculate_sha256(path)

        # 1. YARA Scanning
        yara_matches: List[str] = []
        if self.yara_rules:
            try:
                matches = self.yara_rules.match(str(path))
                yara_matches = [m.rule for m in matches]
            except Exception as exc:
                logger.debug("YARA scan error for %s: %s", path, exc)

        # 2. Heuristic Analysis
        threat_reasons: List[str] = []
        is_high_entropy = entropy >= self.entropy_threshold

        if is_high_entropy:
            threat_reasons.append(
                f"Abnormally high Shannon entropy ({entropy:.2f} > {self.entropy_threshold:.2f}) indicates encrypted payload, packer, or ransomware"
            )

        if yara_matches:
            threat_reasons.append(
                f"Matched YARA signatures: {', '.join(yara_matches)}"
            )

        # If flagged by either entropy or YARA, construct alert
        if threat_reasons:
            severity = "CRITICAL" if (is_high_entropy and yara_matches) else "HIGH"

            alert = MaliciousFileAlert(
                alert_id=f"alert-mal-{uuid.uuid4().hex[:10]}",
                file_path=str(path.resolve()),
                file_name=path.name,
                file_size_bytes=file_size,
                sha256=sha256,
                entropy=entropy,
                is_high_entropy=is_high_entropy,
                yara_matches=yara_matches,
                threat_reasons=threat_reasons,
                severity=severity,
            )

            logger.warning(alert.summary())

            if self.on_alert:
                try:
                    self.on_alert(alert)
                except Exception as exc:
                    logger.error("Error executing on_alert callback: %s", exc)

            return alert

        return None

    def _on_file_activity(self, file_path: Path) -> None:
        """Internal debounced dispatcher called when a watched file event occurs."""
        path_str = str(file_path.resolve())
        now = time.time()

        with self._lock:
            last_scanned = self._scanned_cache.get(path_str, 0.0)
            if (now - last_scanned) < self.debounce_seconds:
                return
            self._scanned_cache[path_str] = now

        self.scan_file_manually(file_path)

    def start(self) -> None:
        """Start the watchdog filesystem observer daemon."""
        if self._running:
            return

        self._observer = Observer()
        handler = _FileEventHandler(self)

        watched_count = 0
        for directory in self.watch_dirs:
            if directory.exists() and directory.is_dir():
                self._observer.schedule(handler, str(directory), recursive=False)
                watched_count += 1
                logger.info("👁️  Watching directory for dropped executables: %s", directory)

        if watched_count > 0:
            self._observer.start()
            self._running = True
            logger.info("🛡️  FileMonitor watchdog active on %d directories (Entropy threshold: %.1f)", watched_count, self.entropy_threshold)
        else:
            logger.warning("FileMonitor: No valid directories found to watch.")

    def stop(self) -> None:
        """Stop the watchdog filesystem observer."""
        self._running = False
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=3.0)
            logger.info("FileMonitor watchdog observer stopped.")

    @property
    def is_running(self) -> bool:
        return self._running
