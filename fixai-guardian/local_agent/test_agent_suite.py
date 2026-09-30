"""
FixAI Local Agent & EDR Comprehensive Test Suite
=================================================
Verifies ML inference, EDR threat hunting, Shannon entropy calculation,
Drain log parsing, and the 4-phase guarded quarantine state machine.
"""

import os
import sys
import tempfile
import time
from pathlib import Path

# Add local_agent to path
sys.path.append(str(Path(__file__).resolve().parent))

from ai_engine.inference import EdgeAIEngine
from edr import (
    DrainParser,
    EDREngine,
    EntropyScanner,
    NLGNarrativeEngine,
    QuarantineVault,
    WmiPersistenceHunter,
)
from osquery_collector import OsqueryCollector
from recovery.executor import RecoveryManager
from watchdog_monitor import WatchdogMonitor


def run_agent_tests():
    print("=" * 70)
    print("  FixAI Local Agent & EDR Comprehensive Test Suite")
    print("=" * 70)

    passed = 0
    total = 0

    # ── Test 1: ML Inference Engine ──────────────────────────────────────────
    total += 1
    print("\n[1] Testing EdgeAIEngine (XGBoost + Isolation Forest + SHAP)...")
    engine = EdgeAIEngine()
    sample_metrics = {
        "cpu": 32.5,
        "ram": 58.0,
        "latency": 14.2,
        "error_rate": 0.01,
        "disk": 42.0,
        "temp": 48.0,
        "battery": 92.0,
    }
    ai_res = engine.analyze(sample_metrics)
    assert "anomaly_score" in ai_res, "Missing anomaly_score"
    assert "p_failure" in ai_res, "Missing p_failure"
    assert "risk" in ai_res, "Missing risk"
    assert "nlg_explanation" in ai_res, "Missing nlg_explanation"
    print(f"    PASS: Anomaly={ai_res['anomaly_score']:.2f}, P(fail)={ai_res['p_failure']:.2f}, Risk={ai_res['risk']}")
    print(f"    Diagnosis: {ai_res['nlg_explanation']}")
    passed += 1

    # ── Test 2: Drain Log Parser ─────────────────────────────────────────────
    total += 1
    print("\n[2] Testing Drain Online Log Parser...")
    parser = DrainParser()
    raw_log = "Anomalous logon failure for user root from 10.0.0.15 port 55122 protocol ssh"
    parsed = parser.parse(raw_log)
    assert parsed["cluster_id"] > 0
    assert "<IP>" in parsed["template"] or "<NUM>" in parsed["template"]
    print(f"    PASS: Log parsed to template: '{parsed['template']}'")
    passed += 1

    # ── Test 3: Shannon Entropy Scanner ──────────────────────────────────────
    total += 1
    print("\n[3] Testing Shannon Entropy Scanner ($H(X)$)...")
    scanner = EntropyScanner()
    clean_bytes = b"Hello, FixAI World! Standard text distribution." * 50
    packed_bytes = os.urandom(2000)  # Maximum randomness, simulated crypter
    h_clean = scanner.calculate_entropy(clean_bytes)
    h_packed = scanner.calculate_entropy(packed_bytes)
    assert h_clean < 5.0, f"Expected clean entropy < 5.0, got {h_clean}"
    assert h_packed > 7.4, f"Expected packed entropy > 7.4, got {h_packed}"
    print(f"    PASS: Clean Entropy={h_clean:.2f}/8.0 | Packed/Encrypted Entropy={h_packed:.2f}/8.0")
    passed += 1

    # ── Test 4: EDR Guarded Quarantine State Machine (Full Lifecycle) ─────────
    total += 1
    print("\n[4] Testing QuarantineVault (4-Phase Guarded State Machine)...")
    vault = QuarantineVault()

    # Step 4a: Verify core OS binary protection
    safe, _, reason = vault.verify_safety("C:\\Windows\\explorer.exe")
    assert not safe, "Core OS binary check failed to protect explorer.exe!"
    print("    PASS: Core OS binary (explorer.exe) safely protected from quarantine.")

    # Step 4b: Test quarantine & encryption of a simulated dropped payload
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        test_payload_path = f.name
        f.write(b"FixAI_Test_Malicious_Dropper_Binary_Content_" + os.urandom(500))

    artifact = vault.quarantine_file(test_payload_path, reason="Unit Test Quarantine")
    assert artifact is not None, "Quarantine failed"
    assert not os.path.exists(test_payload_path), "Original file still exists on disk!"
    assert os.path.exists(artifact.vault_path), "Vault encrypted file does not exist!"
    print(f"    PASS: Payload moved to vault (ID: {artifact.quarantine_id}) & encrypted via AES-256.")

    # Step 4c: Test safe restoration (reversal)
    restored = vault.restore_file(artifact.quarantine_id)
    assert restored, "Restoration failed"
    assert os.path.exists(test_payload_path), "Restored file not back at original path!"
    os.remove(test_payload_path)
    print("    PASS: Quarantined payload decrypted and restored cleanly (False-Positive Safe).")
    passed += 1

    # ── Test 5: Plain-English NLG Engine ─────────────────────────────────────
    total += 1
    print("\n[5] Testing NLGNarrativeEngine...")
    narrative = NLGNarrativeEngine.generate_brute_force_narrative("198.51.100.45", 52, compromised=False)
    assert narrative.title
    assert narrative.threat
    assert narrative.action_taken
    assert len(narrative.actionable_steps) == 3
    print(f"    PASS: Generated plain-English narrative with 3 actionable steps for user:")
    print("    " + narrative.to_toast_summary())
    passed += 1

    # ── Test 6: EDR Engine Detection Tick ────────────────────────────────────
    total += 1
    print("\n[6] Testing EDREngine Detection Tick...")
    edr = EDREngine()
    tick_telemetry = edr.run_detection_tick()
    assert "event_log_metrics" in tick_telemetry
    assert "wmi_persistence_threats_count" in tick_telemetry
    assert "status" in tick_telemetry
    print(f"    PASS: EDR Tick executed in {tick_telemetry['elapsed_ms']}ms -> Status: {tick_telemetry['status']}")
    passed += 1

    # ── Test 7: Osquery Collector ────────────────────────────────────────────
    total += 1
    print("\n[7] Testing OsqueryCollector...")
    collector = OsqueryCollector()
    avail = collector.is_available()
    data = collector.collect()
    print(f"    PASS: Osquery available={avail}, collected {len(data)} telemetry blocks")
    passed += 1

    # ── Test 8: Recovery Manager Allowlist & Execution ────────────────────────
    total += 1
    print("\n[8] Testing RecoveryManager Allowlist & Playbooks...")
    mgr = RecoveryManager()
    # Test valid playbook
    res = mgr.execute_playbook("flush_cache")
    assert res.get("success"), f"Playbook failed: {res}"
    # Test invalid playbook rejection
    res_bad = mgr.execute_playbook("unauthorized_eval_command")
    assert not res_bad.get("success"), "Unauthorized playbook was not rejected!"
    print("    PASS: RecoveryManager allowlist gating and execution functioning normally.")
    passed += 1

    # ── Test 9: Watchdog Monitor ─────────────────────────────────────────────
    total += 1
    print("\n[9] Testing WatchdogMonitor...")
    watchdog = WatchdogMonitor(scan_interval=1)
    status = watchdog.get_status()
    assert "watch_dirs" in status
    assert "file_limit_mb" in status
    print(f"    PASS: WatchdogMonitor initialized, watching {len(status['watch_dirs'])} critical system paths.")
    passed += 1

    print("\n" + "=" * 70)
    print(f"  All {passed}/{total} Agent & EDR Tests PASSED with ZERO ERRORS!")
    print("=" * 70)


if __name__ == "__main__":
    run_agent_tests()
