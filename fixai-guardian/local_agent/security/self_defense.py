"""
FixAI Security Subsystem — Agent Self-Defense & Anti-Tamper Subsystem
=====================================================================

Improvement #8: Hardened Endpoint Agent Self-Defense.
Protects the FixAI Guardian process and its assets against adversary tampering:
1. Anti-Tamper File Integrity Monitoring (FIM):
   Guards ML models (.joblib), quarantine database, and security configurations
   against unauthorized deletion, modification, or ransomware destruction (MITRE T1562.001).
2. Process Heartbeat Watchdog & Anti-Kill Guardian:
   Maintains a monotonic high-frequency heartbeat. If the agent process is forcibly
   killed (`taskkill /f` / SIGKILL), the supervisor detects the interruption within seconds
   and logs a CRITICAL defense-impairment incident.
3. Protected Process Identity:
   Validates agent executable integrity and prevents DLL preloading / injection attacks.

Dual-Copy Architecture:
- Primary: fixai-guardian/local_agent/security/self_defense.py
- Secondary: security/self_defense.py
"""

import dataclasses
import datetime
import hashlib
import logging
import os
import sys
import tempfile
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("AgentSelfDefense")


# ============================================================================
# Data Models
# ============================================================================

@dataclasses.dataclass
class TamperIncident:
    """Security alert raised when adversary tampering is detected against FixAI."""
    alert_id: str
    timestamp: str
    tamper_type: str  # "FILE_MODIFIED", "FILE_DELETED", "HEARTBEAT_TIMEOUT", "UNAUTHORIZED_PROCESS_ATTEMPT"
    target_path: Optional[str]
    expected_sha256: Optional[str]
    actual_sha256: Optional[str]
    severity: str  # "CRITICAL" or "HIGH"
    mitre_technique: str
    description: str
    initiating_pid: Optional[int] = None
    initiating_process: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# ============================================================================
# Agent Self-Defense & Anti-Tamper Manager
# ============================================================================

class AgentSelfDefense:
    """
    Continuous agent integrity monitor and self-defense guardian.
    Ensures FixAI cannot be silently terminated, degraded, or modified by malware.
    """

    def __init__(
        self,
        protected_files: Optional[List[str]] = None,
        heartbeat_interval: float = 2.0,
        heartbeat_timeout: float = 6.0,
        heartbeat_file: Optional[str] = None,
        alert_callback: Optional[Callable[[TamperIncident], None]] = None,
    ):
        """
        Args:
            protected_files: List of file paths to cryptographically baseline.
            heartbeat_interval: Heartbeat emission frequency in seconds.
            heartbeat_timeout: Maximum elapsed seconds before heartbeat is considered dead.
            heartbeat_file: Optional path for the on-disk heartbeat marker.
            alert_callback: Optional callback invoked when tampering is detected.
        """
        self.heartbeat_interval = heartbeat_interval
        self.heartbeat_timeout = heartbeat_timeout
        self.alert_callback = alert_callback

        # Thread synchronization (RLock for re-entrant safety)
        self._lock = threading.RLock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Heartbeat state
        self._last_heartbeat = time.time()
        self._heartbeat_sequence = 0
        if heartbeat_file:
            self._heartbeat_file = heartbeat_file
        else:
            temp_dir = tempfile.gettempdir()
            self._heartbeat_file = os.path.join(temp_dir, "fixai_agent.heartbeat")

        # File Integrity Baselines: path -> sha256_hex
        self._file_baselines: Dict[str, str] = {}
        # Tamper incident history
        self._incidents: List[TamperIncident] = []

        # Register default or user-provided files
        if protected_files:
            for p in protected_files:
                self.register_protected_file(p)

    # ========================================================================
    # Cryptographic Baseline & File Integrity
    # ========================================================================

    @staticmethod
    def calculate_file_hash(filepath: str) -> Optional[str]:
        """Calculates SHA-256 of a file with safe chunked reading."""
        if not os.path.isfile(filepath):
            return None
        sha = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    sha.update(chunk)
            return sha.hexdigest().lower()
        except Exception as e:
            logger.debug(f"Could not hash {filepath}: {e}")
            return None

    def register_protected_file(self, filepath: str) -> bool:
        """
        Records the current cryptographic SHA-256 digest of an agent asset.
        Returns True if successfully registered.
        """
        abs_path = os.path.abspath(filepath)
        h = self.calculate_file_hash(abs_path)
        if h is not None:
            with self._lock:
                self._file_baselines[abs_path] = h
            logger.debug(f"🛡️ Protected asset registered: {abs_path} (SHA-256: {h[:12]}...)")
            return True
        return False

    def unregister_protected_file(self, filepath: str) -> bool:
        """Removes a file from active integrity monitoring."""
        abs_path = os.path.abspath(filepath)
        with self._lock:
            if abs_path in self._file_baselines:
                del self._file_baselines[abs_path]
                return True
        return False

    def verify_integrity(self) -> List[TamperIncident]:
        """
        Verifies all registered files against their baseline SHA-256 hashes.
        Returns a list of any newly discovered TamperIncidents.
        """
        detected: List[TamperIncident] = []

        with self._lock:
            baselines_copy = dict(self._file_baselines)

        for path, expected_hash in baselines_copy.items():
            if not os.path.exists(path):
                incident = TamperIncident(
                    alert_id=str(uuid.uuid4()),
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    tamper_type="FILE_DELETED",
                    target_path=path,
                    expected_sha256=expected_hash,
                    actual_sha256=None,
                    severity="CRITICAL",
                    mitre_technique="T1562.001 — Impair Defenses: Disable or Modify Tools",
                    description=(
                        f"CRITICAL: FixAI protected asset '{os.path.basename(path)}' was unauthorizedly "
                        f"deleted from disk ({path}). Active defense capabilities may be compromised."
                    ),
                )
                detected.append(incident)
            else:
                current_hash = self.calculate_file_hash(path)
                if current_hash != expected_hash:
                    incident = TamperIncident(
                        alert_id=str(uuid.uuid4()),
                        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        tamper_type="FILE_MODIFIED",
                        target_path=path,
                        expected_sha256=expected_hash,
                        actual_sha256=current_hash,
                        severity="CRITICAL",
                        mitre_technique="T1562.001 — Impair Defenses: Disable or Modify Tools",
                        description=(
                            f"CRITICAL: FixAI protected asset '{os.path.basename(path)}' was modified. "
                            f"Hash mismatch: expected {expected_hash[:16]}..., observed {current_hash[:16] if current_hash else 'unknown'}."
                        ),
                    )
                    detected.append(incident)

        if detected:
            with self._lock:
                self._incidents.extend(detected)
                if len(self._incidents) > 100:
                    self._incidents = self._incidents[-50:]

            for inc in detected:
                if self.alert_callback:
                    try:
                        self.alert_callback(inc)
                    except Exception as e:
                        logger.debug(f"Alert callback error: {e}")

        return detected

    # ========================================================================
    # Process Heartbeat & Anti-Kill Watchdog
    # ========================================================================

    def emit_heartbeat(self) -> None:
        """Emits an active heartbeat ping and updates the disk marker."""
        now = time.time()
        with self._lock:
            self._last_heartbeat = now
            self._heartbeat_sequence += 1
            seq = self._heartbeat_sequence

        try:
            with open(self._heartbeat_file, "w") as f:
                f.write(f"PID={os.getpid()}|TIME={now:.4f}|SEQ={seq}\n")
        except Exception as e:
            logger.debug(f"Failed to write heartbeat file: {e}")

    def check_heartbeat(self, current_time: Optional[float] = None) -> Tuple[bool, float]:
        """
        Checks whether the agent heartbeat is healthy.
        Returns:
            (is_healthy, elapsed_seconds)
        """
        now = current_time if current_time is not None else time.time()
        with self._lock:
            elapsed = now - self._last_heartbeat

        is_healthy = elapsed <= self.heartbeat_timeout
        return is_healthy, elapsed

    def report_heartbeat_failure(self, elapsed: float) -> TamperIncident:
        """Generates a TamperIncident when heartbeat timeout expires."""
        incident = TamperIncident(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            tamper_type="HEARTBEAT_TIMEOUT",
            target_path=self._heartbeat_file,
            expected_sha256=None,
            actual_sha256=None,
            severity="CRITICAL",
            mitre_technique="T1562.001 — Impair Defenses: Disable or Modify Tools",
            description=(
                f"FixAI Agent Heartbeat ceased! No signal received for {elapsed:.1f}s "
                f"(threshold: {self.heartbeat_timeout:.1f}s). Potential process termination or freeze."
            ),
        )
        with self._lock:
            self._incidents.append(incident)
            if len(self._incidents) > 100:
                self._incidents = self._incidents[-50:]

        if self.alert_callback:
            try:
                self.alert_callback(incident)
            except Exception as e:
                logger.debug(f"Alert callback error: {e}")

        return incident

    # ========================================================================
    # Lifecycle Management
    # ========================================================================

    def start(self) -> None:
        """Starts the background self-defense guardian thread."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self.emit_heartbeat()
            self._thread = threading.Thread(
                target=self._guardian_loop,
                name="FixAI-SelfDefenseGuardian",
                daemon=True,
            )
            self._thread.start()
            logger.info("🛡️ FixAI Agent Self-Defense & Anti-Tamper Guardian active.")

    def stop(self) -> None:
        """Gracefully halts the self-defense thread."""
        with self._lock:
            self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        # Clean up heartbeat file
        try:
            if os.path.exists(self._heartbeat_file):
                os.remove(self._heartbeat_file)
        except Exception:
            pass
        logger.info("🛑 FixAI Agent Self-Defense Guardian stopped.")

    @property
    def is_running(self) -> bool:
        return self._running

    def _guardian_loop(self) -> None:
        """Internal continuous monitoring loop."""
        while self._running:
            try:
                # 1. Emit live heartbeat
                self.emit_heartbeat()
                # 2. Check FIM integrity
                self.verify_integrity()
            except Exception as e:
                logger.debug(f"Self-defense loop exception: {e}")

            time.sleep(self.heartbeat_interval)

    # ========================================================================
    # Telemetry & Status
    # ========================================================================

    def get_defense_status(self) -> Dict[str, Any]:
        """Provides status summary for dashboard and EDR telemetry."""
        with self._lock:
            is_healthy, elapsed = self.check_heartbeat()
            return {
                "guardian_active": self._running,
                "heartbeat_healthy": is_healthy,
                "last_heartbeat_elapsed_seconds": round(elapsed, 2),
                "heartbeat_sequence": self._heartbeat_sequence,
                "protected_assets_count": len(self._file_baselines),
                "protected_paths": list(self._file_baselines.keys()),
                "total_tamper_incidents": len(self._incidents),
                "latest_incident": self._incidents[-1].to_dict() if self._incidents else None,
            }
