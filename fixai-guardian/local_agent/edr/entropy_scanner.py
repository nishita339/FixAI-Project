"""
FixAI EDR — Shannon Entropy Scanner & Heuristic Pattern Matcher
===============================================================

Implements information-theoretic Shannon Entropy evaluation and dynamic
pattern matching to detect obfuscated, packed, and polymorphic malware.

Mathematical Formulation:
  H(X) = - \\sum_{i=0}^{255} P(x_i) \\log_2 P(x_i)

Where P(x_i) represents the empirical probability of byte value i (0..255).
Uncompressed / legitimate OS binaries: H(X) \\in [5.0, 6.6]
Packed, compressed, or encrypted malware (UPX, crypters): H(X) > 7.15
"""

from __future__ import annotations

import collections
import math
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class EntropyScanResult:
    """Detailed result of an entropy and heuristic scan on a file."""

    def __init__(
        self,
        file_path: str,
        file_size: int,
        entropy: float,
        is_packed: bool,
        heuristic_matches: List[str],
        threat_level: str,  # "CLEAN", "SUSPICIOUS", "MALICIOUS"
        sha256: str = "",
    ):
        self.file_path = file_path
        self.file_size = file_size
        self.entropy = round(entropy, 3)
        self.is_packed = is_packed
        self.heuristic_matches = heuristic_matches
        self.threat_level = threat_level
        self.sha256 = sha256

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_size": self.file_size,
            "entropy": self.entropy,
            "is_packed": self.is_packed,
            "heuristic_matches": self.heuristic_matches,
            "threat_level": self.threat_level,
            "sha256": self.sha256,
        }


# ── Heuristic Signature Patterns ──────────────────────────────────────────────
SUSPICIOUS_PATTERNS = [
    # PowerShell and Script download cradles
    (re.compile(rb"(?i)powershell(\.exe)?\s+(-(w|windowstyle)\s+hidden\s+)?(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}"), "OBFUSCATED_POWERSHELL_PAYLOAD"),
    (re.compile(rb"(?i)(new-object\s+net\.webclient)\.(downloadstring|downloaddata|downloadfile)"), "POWERSHELL_DOWNLOAD_CRADLE"),
    (re.compile(rb"(?i)(invoke-expression|iex)\s*[\(\$]"), "IEX_EXECUTION_HOOK"),
    (re.compile(rb"(?i)vssadmin\s+delete\s+shadows(\s+/all|\s+/quiet)?"), "RANSOMWARE_SHADOW_COPY_DELETION"),
    (re.compile(rb"(?i)bcdedit\s+/set\s+.*bootstatuspolicy\s+ignoreallfailures"), "RANSOMWARE_BOOT_TAMPERING"),
    (re.compile(rb"(?i)(mimikatz|sekurlsa|lsadump|kerberos::)"), "CREDENTIAL_DUMPER_STRINGS"),
    # Memory Injection & Process Hollowing APIs
    (re.compile(rb"(?i)(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|QueueUserAPC|NtUnmapViewOfSection)"), "PROCESS_INJECTION_API"),
    # Reverse Shell and Raw Socket Spawns
    (re.compile(rb"(?i)(cmd\.exe|powershell\.exe)\s*/c\s*nc(\.exe)?\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"), "NETCAT_REVERSE_SHELL"),
]


class EntropyScanner:
    """
    Evaluates Shannon Entropy and inspects byte patterns of binaries and scripts.
    """

    def __init__(self, entropy_threshold: float = 7.15):
        self.entropy_threshold = entropy_threshold

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Compute Shannon entropy of a byte sequence.
        Returns float in [0.0, 8.0].
        """
        if not data:
            return 0.0

        length = len(data)
        counts = collections.Counter(data)
        entropy = 0.0

        for count in counts.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)

        return entropy

    def scan_file(self, file_path: Path | str) -> Optional[EntropyScanResult]:
        """
        Read file bytes, compute entropy, calculate SHA-256, and evaluate heuristics.
        """
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            return None

        import hashlib

        try:
            size = p.stat().st_size
            if size == 0:
                return EntropyScanResult(str(p), 0, 0.0, False, [], "CLEAN", "")

            # For large files (>20MB), sample up to first 2MB + last 512KB for performance
            hasher = hashlib.sha256()
            data = b""

            with open(p, "rb") as f:
                if size <= 2 * 1024 * 1024:
                    data = f.read()
                    hasher.update(data)
                else:
                    head = f.read(2 * 1024 * 1024)
                    hasher.update(head)
                    f.seek(max(0, size - 512 * 1024))
                    tail = f.read(512 * 1024)
                    data = head + tail
                    # Complete hash of rest of file
                    f.seek(0)
                    while chunk := f.read(65536):
                        hasher.update(chunk)

            sha256 = hasher.hexdigest()
            entropy = self.calculate_entropy(data)
            is_packed = entropy >= self.entropy_threshold

            # Evaluate heuristic signatures
            matches = []
            for pattern, label in SUSPICIOUS_PATTERNS:
                if pattern.search(data):
                    matches.append(label)

            # Determine overall threat level
            if matches and is_packed:
                threat_level = "MALICIOUS"
            elif matches:
                threat_level = "MALICIOUS" if len(matches) > 1 else "SUSPICIOUS"
            elif is_packed and p.suffix.lower() in (".exe", ".dll", ".bin", ".scr"):
                threat_level = "SUSPICIOUS"
            else:
                threat_level = "CLEAN"

            return EntropyScanResult(
                file_path=str(p),
                file_size=size,
                entropy=entropy,
                is_packed=is_packed,
                heuristic_matches=matches,
                threat_level=threat_level,
                sha256=sha256,
            )

        except (PermissionError, OSError):
            return None
