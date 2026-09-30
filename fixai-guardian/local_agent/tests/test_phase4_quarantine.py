"""
FixAI EDR — Phase 4 Unit Tests: Guarded Quarantine Vault & Network Isolation
==============================================================================

Tests cover:
 1. SHA-256 hash computation correctness
 2. OS protected file path detection (System32, WinSxS, Program Files)
 3. Quarantine of a malicious file (encrypt + manifest + original deleted)
 4. Restore from quarantine (decrypt + SHA-256 integrity verification)
 5. OS safety abort — quarantining a System32 file raises PermissionError
 6. Quarantine of non-existent file raises FileNotFoundError
 7. AES-256-CBC round-trip encryption/decryption correctness
 8. Firewall command generation (dry-run, no admin required)
 9. IP validation (valid/invalid IPv4 addresses)
10. QuarantineRecord serialization round-trip
11. Vault manifest persistence and reload
"""

import hashlib
import json
import os
import sys
import tempfile
import shutil
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from security.quarantine import (
    QuarantineVault,
    QuarantineRecord,
    FirewallManager,
    calculate_sha256,
    is_os_protected_file,
    encrypt_file_aes256,
    decrypt_file_aes256,
    _generate_aes_key,
    _generate_iv,
)


class TestPhase4Quarantine(unittest.TestCase):
    """Phase 4: Guarded Quarantine & Network Isolation Tests"""

    def setUp(self):
        """Create isolated temp directories for vault and test files."""
        self.test_dir = tempfile.mkdtemp(prefix="fixai_test_quarantine_")
        self.vault_dir = os.path.join(self.test_dir, "vault")
        os.makedirs(self.vault_dir, exist_ok=True)
        self.vault = QuarantineVault(vault_dir=self.vault_dir)

    def tearDown(self):
        """Clean up temp directories."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # ====================================================================
    # Test 1: SHA-256 Hash Computation
    # ====================================================================
    def test_sha256_known_content(self):
        """SHA-256 of known content must match Python's hashlib reference."""
        test_file = os.path.join(self.test_dir, "known.bin")
        content = b"FixAI Security Module Test Content 2024"
        with open(test_file, "wb") as f:
            f.write(content)

        computed = calculate_sha256(test_file)
        expected = hashlib.sha256(content).hexdigest()
        self.assertEqual(computed, expected)

    def test_sha256_empty_file(self):
        """SHA-256 of an empty file must match the well-known empty hash."""
        test_file = os.path.join(self.test_dir, "empty.bin")
        with open(test_file, "wb") as f:
            pass  # empty file

        computed = calculate_sha256(test_file)
        expected = hashlib.sha256(b"").hexdigest()
        self.assertEqual(computed, expected)

    # ====================================================================
    # Test 2: OS Protected File Path Detection
    # ====================================================================
    def test_system32_is_protected(self):
        """Files under C:\\Windows\\System32 must be detected as protected."""
        self.assertTrue(is_os_protected_file(r"C:\Windows\System32\cmd.exe"))

    def test_syswow64_is_protected(self):
        """Files under SysWOW64 must be detected as protected."""
        self.assertTrue(is_os_protected_file(r"C:\Windows\SysWOW64\notepad.exe"))

    def test_program_files_is_protected(self):
        """Files under Program Files must be detected as protected."""
        self.assertTrue(is_os_protected_file(r"C:\Program Files\SomeApp\app.exe"))

    def test_user_downloads_not_protected(self):
        """Files in user Downloads should NOT be protected."""
        downloads = os.path.join(os.environ.get("USERPROFILE", r"C:\Users\test"), "Downloads", "malware.exe")
        self.assertFalse(is_os_protected_file(downloads))

    def test_temp_dir_not_protected(self):
        """Files in temp directories should NOT be protected."""
        temp_file = os.path.join(self.test_dir, "suspicious.exe")
        self.assertFalse(is_os_protected_file(temp_file))

    # ====================================================================
    # Test 3: Full Quarantine Lifecycle (Encrypt + Manifest + Delete Original)
    # ====================================================================
    def test_quarantine_malicious_file(self):
        """Quarantining a file should encrypt it, create manifest, and delete the original."""
        # Create a fake malicious file
        malware_path = os.path.join(self.test_dir, "ransomware_payload.exe")
        malware_content = b"\x00" * 100 + b"ENCRYPTED_RANSOMWARE_PAYLOAD" + os.urandom(200)
        with open(malware_path, "wb") as f:
            f.write(malware_content)

        original_sha256 = hashlib.sha256(malware_content).hexdigest()

        # Quarantine it
        record = self.vault.quarantine_file(
            malware_path,
            reason="High entropy packed executable",
            alert_type="RANSOMWARE",
            severity="CRITICAL",
        )

        # Assertions
        self.assertIsNotNone(record)
        self.assertEqual(record.original_sha256, original_sha256)
        self.assertEqual(record.original_filename, "ransomware_payload.exe")
        self.assertEqual(record.alert_type, "RANSOMWARE")
        self.assertEqual(record.severity, "CRITICAL")
        self.assertFalse(record.restored)

        # Original file should be deleted
        self.assertFalse(os.path.exists(malware_path))

        # Encrypted vault file should exist
        self.assertTrue(os.path.isfile(record.quarantined_path))

        # Manifest should exist
        self.assertTrue(os.path.isfile(record.manifest_path))

        # Encrypted file should NOT be identical to original content
        with open(record.quarantined_path, "rb") as f:
            encrypted_content = f.read()
        self.assertNotEqual(encrypted_content, malware_content)

    # ====================================================================
    # Test 4: Restore from Quarantine (Decrypt + SHA-256 Integrity Verify)
    # ====================================================================
    def test_restore_from_quarantine(self):
        """Restoring a quarantined file must produce byte-identical content."""
        # Create and quarantine
        malware_path = os.path.join(self.test_dir, "trojan.dll")
        malware_content = os.urandom(512) + b"TROJAN_PAYLOAD_MARKER"
        with open(malware_path, "wb") as f:
            f.write(malware_content)

        original_sha256 = hashlib.sha256(malware_content).hexdigest()
        record = self.vault.quarantine_file(malware_path, reason="Trojan detected")

        # Restore to a new location
        restore_path = os.path.join(self.test_dir, "restored_trojan.dll")
        result_path = self.vault.restore_from_quarantine(record.quarantine_id, restore_path)

        self.assertEqual(result_path, restore_path)
        self.assertTrue(os.path.isfile(restore_path))

        # Verify byte-identical content
        with open(restore_path, "rb") as f:
            restored_content = f.read()
        self.assertEqual(restored_content, malware_content)

        # Verify SHA-256 matches
        restored_sha256 = hashlib.sha256(restored_content).hexdigest()
        self.assertEqual(restored_sha256, original_sha256)

    # ====================================================================
    # Test 5: OS Safety Abort — System32 File Quarantine Raises PermissionError
    # ====================================================================
    def test_quarantine_system32_file_raises(self):
        """Attempting to quarantine a System32 file must raise PermissionError."""
        system32_file = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "cmd.exe")
        if os.path.isfile(system32_file):
            with self.assertRaises(PermissionError):
                self.vault.quarantine_file(system32_file, reason="Test — should be blocked")

    # ====================================================================
    # Test 6: Quarantine Non-Existent File Raises FileNotFoundError
    # ====================================================================
    def test_quarantine_nonexistent_file_raises(self):
        """Quarantining a non-existent file must raise FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            self.vault.quarantine_file(
                os.path.join(self.test_dir, "does_not_exist.exe"),
                reason="Ghost file",
            )

    # ====================================================================
    # Test 7: AES-256-CBC Round-Trip Encryption/Decryption
    # ====================================================================
    def test_aes256_round_trip(self):
        """AES-256-CBC encrypt then decrypt must produce identical plaintext."""
        plaintext = os.urandom(1024) + b"PLAINTEXT_SENTINEL"
        source = os.path.join(self.test_dir, "plain.bin")
        encrypted = os.path.join(self.test_dir, "cipher.bin")
        decrypted = os.path.join(self.test_dir, "decrypted.bin")

        with open(source, "wb") as f:
            f.write(plaintext)

        key = _generate_aes_key()
        iv = _generate_iv()

        # Encrypt
        enc_size = encrypt_file_aes256(source, encrypted, key, iv)
        self.assertGreater(enc_size, 0)

        # Encrypted content must differ from plaintext
        with open(encrypted, "rb") as f:
            ct = f.read()
        self.assertNotEqual(ct, plaintext)

        # Decrypt
        dec_size = decrypt_file_aes256(encrypted, decrypted, key, iv)
        self.assertGreater(dec_size, 0)

        # Must match original
        with open(decrypted, "rb") as f:
            result = f.read()
        self.assertEqual(result, plaintext)

    def test_aes256_small_file(self):
        """AES-256 round trip works for files smaller than one AES block (16 bytes)."""
        tiny_content = b"TINY"  # 4 bytes — smaller than AES block
        source = os.path.join(self.test_dir, "tiny.bin")
        encrypted = os.path.join(self.test_dir, "tiny_enc.bin")
        decrypted = os.path.join(self.test_dir, "tiny_dec.bin")

        with open(source, "wb") as f:
            f.write(tiny_content)

        key = _generate_aes_key()
        iv = _generate_iv()

        encrypt_file_aes256(source, encrypted, key, iv)
        decrypt_file_aes256(encrypted, decrypted, key, iv)

        with open(decrypted, "rb") as f:
            result = f.read()
        self.assertEqual(result, tiny_content)

    # ====================================================================
    # Test 8: Firewall Command Generation (Dry-Run)
    # ====================================================================
    def test_firewall_block_command_generation(self):
        """generate_block_command should produce valid netsh syntax."""
        cmd = FirewallManager.generate_block_command("198.51.100.22")
        self.assertIn("netsh advfirewall firewall add rule", cmd)
        self.assertIn("FixAI-Block-198.51.100.22", cmd)
        self.assertIn("action=block", cmd)
        self.assertIn("remoteip=198.51.100.22", cmd)

    def test_firewall_unblock_command_generation(self):
        """generate_unblock_command should produce valid netsh delete syntax."""
        cmd = FirewallManager.generate_unblock_command("10.0.0.15")
        self.assertIn("netsh advfirewall firewall delete rule", cmd)
        self.assertIn("FixAI-Block-10.0.0.15", cmd)

    # ====================================================================
    # Test 9: IP Address Validation
    # ====================================================================
    def test_valid_ipv4(self):
        """Standard IPv4 addresses should pass validation."""
        self.assertTrue(FirewallManager._validate_ip("192.168.1.1"))
        self.assertTrue(FirewallManager._validate_ip("10.0.0.1"))
        self.assertTrue(FirewallManager._validate_ip("255.255.255.255"))
        self.assertTrue(FirewallManager._validate_ip("0.0.0.0"))

    def test_invalid_ipv4(self):
        """Malformed IPs should fail validation."""
        self.assertFalse(FirewallManager._validate_ip("999.999.999.999"))
        self.assertFalse(FirewallManager._validate_ip("abc.def.ghi.jkl"))
        self.assertFalse(FirewallManager._validate_ip("192.168.1"))
        self.assertFalse(FirewallManager._validate_ip(""))
        self.assertFalse(FirewallManager._validate_ip("not-an-ip"))

    # ====================================================================
    # Test 10: QuarantineRecord Serialization Round-Trip
    # ====================================================================
    def test_record_serialization_roundtrip(self):
        """QuarantineRecord.to_dict() -> from_dict() should produce identical records."""
        record = QuarantineRecord(
            quarantine_id="test-uuid-1234",
            original_path=r"C:\Users\test\Downloads\malware.exe",
            original_filename="malware.exe",
            original_sha256="a" * 64,
            original_size=1024,
            quarantined_path=r"C:\FixAI_Quarantine\test-uuid-1234.quarantined",
            manifest_path=r"C:\FixAI_Quarantine\test-uuid-1234.manifest.json",
            aes_key_hex="b" * 64,
            aes_iv_hex="c" * 32,
            encrypted_size=1040,
            quarantine_reason="YARA signature match",
            alert_type="MALWARE",
            severity="HIGH",
            timestamp="2024-01-01T00:00:00+00:00",
        )
        d = record.to_dict()
        restored = QuarantineRecord.from_dict(d)

        self.assertEqual(restored.quarantine_id, record.quarantine_id)
        self.assertEqual(restored.original_sha256, record.original_sha256)
        self.assertEqual(restored.aes_key_hex, record.aes_key_hex)
        self.assertEqual(restored.quarantine_reason, record.quarantine_reason)
        self.assertFalse(restored.restored)

    # ====================================================================
    # Test 11: Vault Manifest Persistence & Reload
    # ====================================================================
    def test_vault_manifest_reload(self):
        """A new QuarantineVault instance should reload existing manifests from disk."""
        # Create and quarantine a file
        malware_path = os.path.join(self.test_dir, "persist_test.exe")
        with open(malware_path, "wb") as f:
            f.write(os.urandom(256))

        record = self.vault.quarantine_file(malware_path, reason="Persistence test")
        q_id = record.quarantine_id

        # Create a NEW vault instance pointing to the same directory
        new_vault = QuarantineVault(vault_dir=self.vault_dir)

        # It should have loaded the manifest automatically
        self.assertIn(q_id, new_vault.records)
        loaded_record = new_vault.get_record(q_id)
        self.assertIsNotNone(loaded_record)
        self.assertEqual(loaded_record.original_filename, "persist_test.exe")
        self.assertEqual(loaded_record.quarantine_reason, "Persistence test")

    # ====================================================================
    # Test 12: Multiple Files Quarantined in Same Vault
    # ====================================================================
    def test_multiple_files_quarantined(self):
        """Vault should handle multiple quarantined files independently."""
        records = []
        for i in range(3):
            path = os.path.join(self.test_dir, f"malware_{i}.exe")
            with open(path, "wb") as f:
                f.write(os.urandom(128 + i * 50))
            record = self.vault.quarantine_file(path, reason=f"Test malware {i}")
            records.append(record)

        self.assertEqual(len(self.vault.list_quarantined()), 3)

        # Each should have a unique ID
        ids = {r.quarantine_id for r in records}
        self.assertEqual(len(ids), 3)

        # Each should be restorable independently
        for record in records:
            restore_path = os.path.join(self.test_dir, f"restored_{record.original_filename}")
            self.vault.restore_from_quarantine(record.quarantine_id, restore_path)
            self.assertTrue(os.path.isfile(restore_path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
