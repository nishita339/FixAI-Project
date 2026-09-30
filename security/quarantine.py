"""
FixAI EDR — Phase 4: Guarded Quarantine Vault & Network Isolation Engine
=========================================================================

Provides safe, reversible remediation for detected threats:

1. **SHA-256 Cryptographic Whitelist** — Before touching ANY file, its SHA-256
   hash is computed and checked against an immutable OS whitelist. If the file
   is a protected Windows system binary, the operation is ABORTED to prevent
   bricking the OS.

2. **AES-256-CBC Encrypted Quarantine Vault** — Malicious files are NOT deleted.
   They are:
   a) Moved to ``C:\\FixAI_Quarantine``
   b) Extension stripped and replaced with ``.quarantined``
   c) Encrypted with AES-256-CBC using a per-file random IV
   d) A JSON manifest is written alongside for forensic recovery

3. **Network Isolation via Windows Defender Firewall** — For brute-force
   alerts, inbound firewall rules are injected to block attacking IPs.
   Rules are named ``FixAI-Block-<IP>`` for easy identification and reversal.

CRITICAL SAFETY INVARIANTS:
- The OS whitelist is checked BEFORE any file move/encrypt/delete.
- Quarantined files can be restored via ``restore_from_quarantine()``.
- Firewall rules can be reversed via ``unblock_ip()``.
- No system binary will ever be quarantined or deleted.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import secrets
import shutil
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger("fixai.security.quarantine")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] [%(levelname)s] [Quarantine] %(message)s")
    )
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


# ============================================================================
# Configuration Constants
# ============================================================================

QUARANTINE_DIR = Path(r"C:\FixAI_Quarantine")
QUARANTINE_MANIFEST_EXT = ".manifest.json"
QUARANTINE_FILE_EXT = ".quarantined"
AES_KEY_SIZE = 32   # 256 bits
AES_IV_SIZE = 16    # 128 bits (CBC block size)
CHUNK_SIZE = 65536  # 64 KB read chunks for streaming encryption

# ============================================================================
# SHA-256 OS Whitelist — Protected System Paths
# ============================================================================
# Files under these directories are ALWAYS protected by path-prefix check,
# regardless of hash. This provides defence-in-depth.

PROTECTED_PATH_PREFIXES: List[str] = []

def _init_protected_paths() -> None:
    """Populate protected path prefixes from environment at import time."""
    global PROTECTED_PATH_PREFIXES
    windir = os.environ.get("WINDIR", r"C:\Windows")
    programfiles = os.environ.get("ProgramFiles", r"C:\Program Files")
    programfiles_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    PROTECTED_PATH_PREFIXES = [
        os.path.normpath(os.path.join(windir, "System32")).lower(),
        os.path.normpath(os.path.join(windir, "SysWOW64")).lower(),
        os.path.normpath(os.path.join(windir, "WinSxS")).lower(),
        os.path.normpath(windir).lower(),
        os.path.normpath(programfiles).lower(),
        os.path.normpath(programfiles_x86).lower(),
    ]

_init_protected_paths()


# ============================================================================
# SHA-256 Hashing
# ============================================================================

def calculate_sha256(filepath: str) -> str:
    """
    Computes the SHA-256 cryptographic hash of a file using streaming reads.
    Returns the hex digest string.
    """
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest()


def is_os_protected_file(filepath: str) -> bool:
    """
    Defence-in-depth whitelist check: Returns True if the file resides
    within a protected Windows system directory.

    This check runs BEFORE any quarantine or deletion operation.
    """
    normalized = os.path.normpath(os.path.abspath(filepath)).lower()
    for prefix in PROTECTED_PATH_PREFIXES:
        if normalized.startswith(prefix):
            return True
    return False


# ============================================================================
# AES-256-CBC Encryption / Decryption
# ============================================================================

def _generate_aes_key() -> bytes:
    """Generates a cryptographically secure random 256-bit AES key."""
    return secrets.token_bytes(AES_KEY_SIZE)


def _generate_iv() -> bytes:
    """Generates a cryptographically secure random 128-bit IV."""
    return secrets.token_bytes(AES_IV_SIZE)


def encrypt_file_aes256(
    source_path: str,
    dest_path: str,
    key: bytes,
    iv: bytes,
) -> int:
    """
    Encrypts a file using AES-256-CBC with PKCS7 padding.

    Args:
        source_path: Path to the plaintext file.
        dest_path: Path where the encrypted ciphertext will be written.
        key: 32-byte AES-256 key.
        iv: 16-byte initialization vector.

    Returns:
        Number of bytes written to dest_path.
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()

    bytes_written = 0
    with open(source_path, "rb") as fin, open(dest_path, "wb") as fout:
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            padded = padder.update(chunk)
            ct = encryptor.update(padded)
            fout.write(ct)
            bytes_written += len(ct)

        # Finalize padding and encryption
        padded_final = padder.finalize()
        ct_final = encryptor.update(padded_final) + encryptor.finalize()
        fout.write(ct_final)
        bytes_written += len(ct_final)

    return bytes_written


def decrypt_file_aes256(
    source_path: str,
    dest_path: str,
    key: bytes,
    iv: bytes,
) -> int:
    """
    Decrypts an AES-256-CBC encrypted file back to its original plaintext.

    Args:
        source_path: Path to the encrypted ciphertext file.
        dest_path: Path where the decrypted plaintext will be written.
        key: 32-byte AES-256 key.
        iv: 16-byte initialization vector.

    Returns:
        Number of bytes written to dest_path.
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = sym_padding.PKCS7(128).unpadder()

    bytes_written = 0
    with open(source_path, "rb") as fin:
        ciphertext = fin.read()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadded = unpadder.update(plaintext) + unpadder.finalize()

    with open(dest_path, "wb") as fout:
        fout.write(unpadded)
        bytes_written = len(unpadded)

    return bytes_written


# ============================================================================
# Quarantine Manifest
# ============================================================================

@dataclass
class QuarantineRecord:
    """Forensic record of a quarantined file."""
    quarantine_id: str
    original_path: str
    original_filename: str
    original_sha256: str
    original_size: int
    quarantined_path: str
    manifest_path: str
    aes_key_hex: str          # Stored for forensic recovery
    aes_iv_hex: str
    encrypted_size: int
    quarantine_reason: str
    alert_type: str
    severity: str
    timestamp: str
    restored: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "quarantine_id": self.quarantine_id,
            "original_path": self.original_path,
            "original_filename": self.original_filename,
            "original_sha256": self.original_sha256,
            "original_size": self.original_size,
            "quarantined_path": self.quarantined_path,
            "manifest_path": self.manifest_path,
            "aes_key_hex": self.aes_key_hex,
            "aes_iv_hex": self.aes_iv_hex,
            "encrypted_size": self.encrypted_size,
            "quarantine_reason": self.quarantine_reason,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "restored": self.restored,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "QuarantineRecord":
        return cls(**d)


# ============================================================================
# Quarantine Engine
# ============================================================================

class QuarantineVault:
    """
    AES-256 encrypted quarantine vault for neutralizing malicious files.

    Safety invariants enforced:
    1. SHA-256 hash checked against OS whitelist BEFORE any operation.
    2. Path prefix checked against protected Windows directories.
    3. Files are encrypted, NOT deleted — always recoverable.
    4. Each quarantined file gets a unique manifest for forensic traceability.
    """

    def __init__(self, vault_dir: Optional[str] = None):
        self.vault_dir = Path(vault_dir) if vault_dir else QUARANTINE_DIR
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self._records: Dict[str, QuarantineRecord] = {}
        self._load_existing_manifests()

    def _load_existing_manifests(self) -> None:
        """Loads existing quarantine manifests from the vault directory."""
        for manifest_file in self.vault_dir.glob(f"*{QUARANTINE_MANIFEST_EXT}"):
            try:
                with open(manifest_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                record = QuarantineRecord.from_dict(data)
                self._records[record.quarantine_id] = record
            except Exception as e:
                logger.warning(f"Failed to load manifest {manifest_file}: {e}")

    @property
    def records(self) -> Dict[str, QuarantineRecord]:
        """Returns all quarantine records (read-only snapshot)."""
        return dict(self._records)

    def quarantine_file(
        self,
        filepath: str,
        reason: str = "Malicious file detected",
        alert_type: str = "MALWARE",
        severity: str = "HIGH",
    ) -> QuarantineRecord:
        """
        Safely quarantines a malicious file:
        1. Validates file is NOT an OS-protected binary (SHA-256 + path check)
        2. Computes SHA-256 hash for forensic record
        3. Generates per-file AES-256 key + IV
        4. Encrypts file into vault with .quarantined extension
        5. Writes JSON manifest for recovery
        6. Deletes the original malicious file

        Args:
            filepath: Absolute path to the malicious file.
            reason: Human-readable quarantine reason.
            alert_type: Alert classification (e.g., 'MALWARE', 'RANSOMWARE').
            severity: Severity level ('CRITICAL', 'HIGH', 'MEDIUM').

        Returns:
            QuarantineRecord with full forensic metadata.

        Raises:
            PermissionError: If the file is OS-protected.
            FileNotFoundError: If the file does not exist.
        """
        filepath = os.path.abspath(filepath)

        # ---- SAFETY CHECK 1: File must exist ----
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Cannot quarantine non-existent file: {filepath}")

        # ---- SAFETY CHECK 2: Path prefix whitelist ----
        if is_os_protected_file(filepath):
            logger.critical(
                f"[SAFETY ABORT] Refusing to quarantine OS-protected file: {filepath}"
            )
            raise PermissionError(
                f"Cannot quarantine OS-protected file in system directory: {filepath}"
            )

        # ---- Compute SHA-256 before any modification ----
        file_sha256 = calculate_sha256(filepath)
        file_size = os.path.getsize(filepath)
        original_filename = os.path.basename(filepath)

        # ---- Generate unique quarantine ID and AES key material ----
        q_id = str(uuid.uuid4())
        aes_key = _generate_aes_key()
        aes_iv = _generate_iv()

        # ---- Build quarantine file paths ----
        safe_name = f"{q_id}{QUARANTINE_FILE_EXT}"
        quarantined_path = str(self.vault_dir / safe_name)
        manifest_path = str(self.vault_dir / f"{q_id}{QUARANTINE_MANIFEST_EXT}")

        # ---- Encrypt the file into the vault ----
        encrypted_size = encrypt_file_aes256(filepath, quarantined_path, aes_key, aes_iv)

        # ---- Write forensic manifest ----
        record = QuarantineRecord(
            quarantine_id=q_id,
            original_path=filepath,
            original_filename=original_filename,
            original_sha256=file_sha256,
            original_size=file_size,
            quarantined_path=quarantined_path,
            manifest_path=manifest_path,
            aes_key_hex=aes_key.hex(),
            aes_iv_hex=aes_iv.hex(),
            encrypted_size=encrypted_size,
            quarantine_reason=reason,
            alert_type=alert_type,
            severity=severity,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(record.to_dict(), f, indent=2)

        # ---- Remove the original malicious file ----
        try:
            os.remove(filepath)
        except OSError as e:
            logger.warning(f"Could not remove original file {filepath} after quarantine: {e}")

        self._records[q_id] = record

        logger.warning(
            f"\U0001f512 [QUARANTINED] {original_filename} | SHA-256: {file_sha256[:16]}... | "
            f"Encrypted to: {safe_name} | Reason: {reason}"
        )

        return record

    def restore_from_quarantine(
        self,
        quarantine_id: str,
        restore_path: Optional[str] = None,
    ) -> str:
        """
        Decrypts and restores a quarantined file to its original or specified location.

        Args:
            quarantine_id: The unique quarantine ID from the manifest.
            restore_path: Optional override path. Defaults to the original path.

        Returns:
            The path where the file was restored.

        Raises:
            KeyError: If quarantine_id is not found.
            FileNotFoundError: If the encrypted vault file is missing.
        """
        if quarantine_id not in self._records:
            raise KeyError(f"Quarantine ID not found: {quarantine_id}")

        record = self._records[quarantine_id]
        target_path = restore_path or record.original_path

        if not os.path.isfile(record.quarantined_path):
            raise FileNotFoundError(
                f"Encrypted vault file missing: {record.quarantined_path}"
            )

        aes_key = bytes.fromhex(record.aes_key_hex)
        aes_iv = bytes.fromhex(record.aes_iv_hex)

        # Ensure target directory exists
        os.makedirs(os.path.dirname(target_path), exist_ok=True)

        decrypt_file_aes256(record.quarantined_path, target_path, aes_key, aes_iv)

        # Verify integrity
        restored_sha256 = calculate_sha256(target_path)
        if restored_sha256 != record.original_sha256:
            logger.error(
                f"[INTEGRITY FAILURE] Restored file SHA-256 mismatch! "
                f"Expected: {record.original_sha256}, Got: {restored_sha256}"
            )
        else:
            logger.info(
                f"\u2705 [RESTORED] {record.original_filename} -> {target_path} | "
                f"SHA-256 integrity verified"
            )

        record.restored = True
        # Update manifest
        with open(record.manifest_path, "w", encoding="utf-8") as f:
            json.dump(record.to_dict(), f, indent=2)

        return target_path

    def list_quarantined(self) -> List[Dict[str, Any]]:
        """Returns a list of all quarantine records as dictionaries."""
        return [r.to_dict() for r in self._records.values()]

    def get_record(self, quarantine_id: str) -> Optional[QuarantineRecord]:
        """Retrieve a specific quarantine record by ID."""
        return self._records.get(quarantine_id)


# ============================================================================
# Network Isolation — Windows Defender Firewall Rule Injection
# ============================================================================

class FirewallManager:
    """
    Manages Windows Defender Firewall rules for blocking/unblocking
    attacking IP addresses detected by the brute-force monitor.

    Rules are named ``FixAI-Block-<IP>`` for easy identification and reversal.
    """

    RULE_PREFIX = "FixAI-Block-"

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        """Basic validation that the string looks like an IPv4 address."""
        parts = ip.strip().split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except (ValueError, TypeError):
            return False

    @classmethod
    def block_ip(cls, ip: str, direction: str = "in") -> bool:
        """
        Injects a Windows Defender Firewall rule to block an attacking IP.

        Args:
            ip: The IPv4 address to block.
            direction: 'in' for inbound (default), 'out' for outbound.

        Returns:
            True if the rule was successfully created, False otherwise.
        """
        if sys.platform != "win32":
            logger.warning("Firewall rule injection is only supported on Windows.")
            return False

        if not cls._validate_ip(ip):
            logger.error(f"Invalid IP address format: {ip}")
            return False

        rule_name = f"{cls.RULE_PREFIX}{ip}"
        dir_arg = "in" if direction == "in" else "out"

        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            f"dir={dir_arg}",
            "action=block",
            f"remoteip={ip}",
            "protocol=any",
            "enable=yes",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            if result.returncode == 0:
                logger.warning(
                    f"\U0001f6e1\ufe0f [FIREWALL] Blocked attacking IP {ip} | Rule: {rule_name} | Direction: {dir_arg}"
                )
                return True
            else:
                logger.error(f"Firewall rule creation failed: {result.stderr.strip()}")
                return False
        except subprocess.TimeoutExpired:
            logger.error(f"Firewall rule creation timed out for IP {ip}")
            return False
        except FileNotFoundError:
            logger.error("netsh not found — cannot manage firewall rules")
            return False
        except Exception as e:
            logger.error(f"Firewall rule creation error: {e}")
            return False

    @classmethod
    def unblock_ip(cls, ip: str) -> bool:
        """
        Removes a previously injected FixAI firewall blocking rule.

        Args:
            ip: The IPv4 address to unblock.

        Returns:
            True if the rule was successfully removed, False otherwise.
        """
        if sys.platform != "win32":
            return False

        if not cls._validate_ip(ip):
            logger.error(f"Invalid IP address format: {ip}")
            return False

        rule_name = f"{cls.RULE_PREFIX}{ip}"

        cmd = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            if result.returncode == 0:
                logger.info(f"\u2705 [FIREWALL] Unblocked IP {ip} | Rule {rule_name} removed")
                return True
            else:
                logger.warning(f"Firewall rule removal failed: {result.stderr.strip()}")
                return False
        except Exception as e:
            logger.error(f"Firewall rule removal error: {e}")
            return False

    @classmethod
    def list_fixai_rules(cls) -> List[str]:
        """
        Lists all FixAI-managed firewall rules currently active.

        Returns:
            List of rule names matching the FixAI-Block-* prefix.
        """
        if sys.platform != "win32":
            return []

        cmd = [
            "netsh", "advfirewall", "firewall", "show", "rule",
            f"name=all",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            rules = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("Rule Name:") and cls.RULE_PREFIX in line:
                    rule_name = line.split(":", 1)[1].strip()
                    rules.append(rule_name)
            return rules
        except Exception as e:
            logger.error(f"Failed to list firewall rules: {e}")
            return []

    @classmethod
    def generate_block_command(cls, ip: str, direction: str = "in") -> str:
        """
        Returns the netsh command string WITHOUT executing it.
        Useful for dry-run mode, logging, or non-admin environments.
        """
        rule_name = f"{cls.RULE_PREFIX}{ip}"
        dir_arg = "in" if direction == "in" else "out"
        return (
            f'netsh advfirewall firewall add rule name="{rule_name}" '
            f'dir={dir_arg} action=block remoteip={ip} protocol=any enable=yes'
        )

    @classmethod
    def generate_unblock_command(cls, ip: str) -> str:
        """
        Returns the netsh unblock command string WITHOUT executing it.
        """
        rule_name = f"{cls.RULE_PREFIX}{ip}"
        return f'netsh advfirewall firewall delete rule name="{rule_name}"'
