"""
FixAI Backend Comprehensive Integration Test Suite
===================================================
Runs end-to-end tests against the FastAPI application instance
using AsyncClient/TestClient and verifies lifespan initialization.
"""

import asyncio
import os
import sys
from pathlib import Path

# Ensure paths
sys.path.append(str(Path(__file__).resolve().parent))

from httpx import ASGITransport, AsyncClient
from app.main import app


async def run_tests():
    print("=" * 70)
    print("  FixAI Backend Integration Test Suite")
    print("=" * 70)

    transport = ASGITransport(app=app)
    passed = 0
    total = 0

    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Test 1: Health Check
            total += 1
            resp = await client.get("/health")
            assert resp.status_code == 200, f"Health check failed: {resp.status_code}"
            data = resp.json()
            assert data.get("status") == "healthy", f"Unexpected status: {data}"
            print(f"[{total}] PASS: GET /health -> {data['status']}")
            passed += 1

            # Test 2: Root endpoint
            total += 1
            resp = await client.get("/")
            assert resp.status_code == 200, f"Root check failed: {resp.status_code}"
            print(f"[{total}] PASS: GET / -> 200 OK")
            passed += 1

            # Test 3: Playbooks Catalog
            total += 1
            resp = await client.get("/api/v1/playbooks")
            assert resp.status_code == 200, f"Playbooks failed: {resp.status_code}"
            pb_list = resp.json()
            assert len(pb_list) >= 27, f"Expected at least 27 playbooks in unified catalog, got {len(pb_list)}"
            assert "verification_window_seconds" in pb_list[0], "Missing verification_window_seconds in PlaybookResponse"
            print(f"[{total}] PASS: GET /api/v1/playbooks -> 200 OK (verified {len(pb_list)} playbooks in unified catalog with soak metadata)")
            passed += 1

            # Test 4: Incidents History
            total += 1
            resp = await client.get("/api/v1/recovery/incidents")
            assert resp.status_code == 200, f"Incidents failed: {resp.status_code}"
            print(f"[{total}] PASS: GET /api/v1/recovery/incidents -> 200 OK")
            passed += 1

            # Test 5: Audit Logs
            total += 1
            resp = await client.get("/api/v1/recovery/audit-logs")
            assert resp.status_code == 200, f"Audit logs failed: {resp.status_code}"
            print(f"[{total}] PASS: GET /api/v1/recovery/audit-logs -> 200 OK")
            passed += 1

            # Test 6: Security Gate — Reject Unallowlisted Command
            total += 1
            resp = await client.post("/api/v1/recovery/execute-live", json={"playbook_id": "rm -rf /"})
            assert resp.status_code == 400, f"Expected 400 Bad Request, got {resp.status_code}"
            print(f"[{total}] PASS: POST /api/v1/recovery/execute-live [MALICIOUS INPUT] -> 400 BLOCKED by Security Gate")
            passed += 1

            # Test 7: Authorized Live Playbook Execution
            total += 1
            resp = await client.post("/api/v1/recovery/execute-live", json={"playbook_id": "clean_hosts_file"})
            assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}"
            data = resp.json()
            assert data.get("status") == "RESOLVED"
            print(f"[{total}] PASS: POST /api/v1/recovery/execute-live [clean_hosts_file] -> RESOLVED")
            passed += 1

            # Test 8: Authorized EDR Playbook Execution
            total += 1
            resp = await client.post("/api/v1/recovery/execute-live", json={
                "playbook_id": "remediate_brute_force",
                "params": {"source_ip": "198.51.100.22"}
            })
            assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}"
            data = resp.json()
            assert data.get("status") == "RESOLVED"
            print(f"[{total}] PASS: POST /api/v1/recovery/execute-live [remediate_brute_force] -> RESOLVED")
            passed += 1

            # Test 9: Telemetry & EDR Ingestion Endpoint
            total += 1
            payload = {
                "device_name": "Test-Laptop",
                "device_id": "dev-test-001",
                "timestamp": 1720000000000,
                "metrics": {
                    "cpu": 25.5,
                    "ram": 55.2,
                    "disk": 40.0,
                    "latency": 15.0,
                    "error_rate": 0.0,
                },
                "ai_results": {
                    "anomaly_score": 0.12,
                    "p_failure": 0.05,
                    "risk": "LOW",
                    "confidence": 0.95,
                },
                "edr_telemetry": {
                    "status": "SECURE",
                    "active_threats_count": 0,
                    "wmi_persistence_threats_count": 0,
                },
                "osquery_data": {
                    "security_signals": {
                        "stopped_auto_services_count": 0
                    }
                }
            }
            headers = {"x-device-key": "fixai-device-secret-key-2026"}
            resp = await client.post("/api/v1/agent/ingest", json=payload, headers=headers)
            assert resp.status_code in (200, 201), f"Ingest failed: {resp.status_code} - {resp.text}"
            print(f"[{total}] PASS: POST /api/v1/agent/ingest [Metrics + EDR + Osquery] -> 200 OK")
            passed += 1

            # Test 10: Software Updates Endpoint
            total += 1
            resp = await client.get("/api/v1/agent/software-updates")
            assert resp.status_code == 200, f"Software updates failed: {resp.status_code}"
            data = resp.json()
            print(f"[{total}] PASS: GET /api/v1/agent/software-updates -> 200 OK ({data.get('totalUpgrades', 0)} updates cataloged)")
            passed += 1

            # Test 11: Real-Time Device Online/Offline Status
            total += 1
            resp = await client.get("/api/v1/agent/device-status?device_id=dev-laptop-001")
            assert resp.status_code == 200, f"Device status check failed: {resp.status_code}"
            dev_status = resp.json()
            assert "is_online" in dev_status and "mode" in dev_status
            print(f"[{total}] PASS: GET /api/v1/agent/device-status -> 200 OK (Mode: {dev_status['mode']}, IsOnline: {dev_status['is_online']})")
            passed += 1

            # Test 12: Offline Batch Telemetry Ingestion (Store-and-Forward Replay)
            total += 1
            batch_payload = {
                "device_id": "dev-laptop-001",
                "batch": [
                    {
                        "device_id": "dev-laptop-001",
                        "timestamp": 1720000005000,
                        "metrics": {"cpu": 32.0, "ram": 58.0, "disk": 41.0, "latency": 14.0, "error_rate": 0.0},
                        "ai_results": {"anomaly_score": 0.15, "p_failure": 0.08, "risk": "LOW"},
                    },
                    {
                        "device_id": "dev-laptop-001",
                        "timestamp": 1720000010000,
                        "metrics": {"cpu": 35.0, "ram": 59.0, "disk": 41.0, "latency": 13.0, "error_rate": 0.0},
                        "ai_results": {"anomaly_score": 0.18, "p_failure": 0.10, "risk": "LOW"},
                    },
                ]
            }
            resp = await client.post("/api/v1/agent/ingest-batch", json=batch_payload, headers=headers)
            assert resp.status_code == 200, f"Batch ingest failed: {resp.status_code} - {resp.text}"
            batch_data = resp.json()
            assert batch_data.get("syncedCount") == 2
            print(f"[{total}] PASS: POST /api/v1/agent/ingest-batch -> 200 OK (synced {batch_data['syncedCount']} offline samples)")
            passed += 1

            # Test 13: Improvement #3 - Process Tree & MITRE ATT&CK Mapping
            total += 1
            resp = await client.get("/api/v1/agent/process-tree?limit=20")
            assert resp.status_code == 200, f"Process tree failed: {resp.status_code} - {resp.text}"
            tree_data = resp.json()
            assert "process_tree" in tree_data
            assert "total_roots" in tree_data
            print(f"[{total}] PASS: GET /api/v1/agent/process-tree -> 200 OK ({tree_data['total_roots']} root process trees, {tree_data['suspicious_count']} suspicious)")
            passed += 1

            # Test 14: Improvement #3 - Terminate Process with OS Whitelist Safety
            total += 1
            # Protected PID 4 must be BLOCKED with 403 Forbidden
            resp = await client.post("/api/v1/agent/terminate-process", json={"pid": 4, "device_id": "dev-laptop-001"})
            assert resp.status_code == 403, f"Expected 403 for protected PID 4, got: {resp.status_code}"
            # Non-existent/mock PID 999999 should be allowed and logged safely
            resp2 = await client.post("/api/v1/agent/terminate-process", json={"pid": 999999, "device_id": "dev-laptop-001", "reason": "Test quarantine termination"})
            assert resp2.status_code == 200, f"Expected 200 for PID 999999, got: {resp2.status_code}"
            print(f"[{total}] PASS: POST /api/v1/agent/terminate-process -> Protected PID 4 blocked (403), PID 999999 terminated safely")
            passed += 1

            # Test 15: Improvement #4 - AI Security Copilot Chat Assistant
            total += 1
            copilot_payload = {
                "message": "How do I mitigate the WMI persistence threat and what MITRE techniques apply?",
                "history": [],
                "telemetry_context": {"cpu": 28.5, "ram": 56.0, "latency": 15.0},
            }
            resp = await client.post("/api/v1/agent/copilot/chat", json=copilot_payload)
            assert resp.status_code == 200, f"Copilot chat failed: {resp.status_code} - {resp.text}"
            copilot_data = resp.json()
            assert "reply" in copilot_data
            assert "suggested_actions" in copilot_data
            assert "mitre_references" in copilot_data
            assert len(copilot_data["reply"]) > 20
            print(f"[{total}] PASS: POST /api/v1/agent/copilot/chat -> 200 OK (AI Copilot returned {len(copilot_data['reply'])} chars, {len(copilot_data['suggested_actions'])} actions)")
            passed += 1

            # Test 16: Improvement #5 - Multi-Device Fleet Overview
            total += 1
            resp = await client.get("/api/v1/agent/fleet")
            assert resp.status_code == 200, f"Fleet endpoint failed: {resp.status_code} - {resp.text}"
            fleet_data = resp.json()
            assert "summary" in fleet_data
            assert "devices" in fleet_data
            assert fleet_data["summary"]["total_devices"] >= 1
            print(f"[{total}] PASS: GET /api/v1/agent/fleet -> 200 OK (Fleet: {fleet_data['summary']['total_devices']} devices, avg health {fleet_data['summary']['average_fleet_health']}%)")
            passed += 1

            # Test 17: Improvement #6 - Forensic Incident Report Generator
            total += 1
            resp = await client.get("/api/v1/agent/incidents/inc-test-sec-001/report")
            assert resp.status_code == 200, f"Forensic report failed: {resp.status_code} - {resp.text}"
            report_data = resp.json()
            assert "report_id" in report_data
            assert "mitre_attack_matrix" in report_data
            assert "forensic_evidence" in report_data
            assert "shap_attributions" in report_data
            print(f"[{total}] PASS: GET /api/v1/agent/incidents/inc-test-sec-001/report -> 200 OK (Report ID: {report_data['report_id']}, {len(report_data['mitre_attack_matrix'])} MITRE tactics)")
            passed += 1

            # Test 18: Improvement #7 - Network Socket & C2 Beaconing Monitor
            total += 1
            resp = await client.get("/api/v1/agent/network-connections")
            assert resp.status_code == 200, f"Network connections endpoint failed: {resp.status_code} - {resp.text}"
            net_data = resp.json()
            assert "summary" in net_data
            assert "connections" in net_data
            assert "c2_beacons" in net_data
            assert net_data["summary"]["engine_status"] == "ONLINE"
            print(f"[{total}] PASS: GET /api/v1/agent/network-connections -> 200 OK ({net_data['summary']['total_sockets_scanned']} sockets, {len(net_data['c2_beacons'])} C2 beacons tracked)")
            passed += 1

            # Test 19: Improvement #8 - Agent Self-Defense & Anti-Tamper
            total += 1
            resp = await client.get("/api/v1/agent/self-defense/status")
            assert resp.status_code == 200, f"Self-defense status endpoint failed: {resp.status_code} - {resp.text}"
            def_data = resp.json()
            assert def_data["status"] == "ARMED"
            assert "watchdog" in def_data
            assert "file_integrity_monitoring" in def_data
            assert "anti_tamper_controls" in def_data
            assert def_data["watchdog"]["heartbeat_health"] == "HEALTHY"
            print(f"[{total}] PASS: GET /api/v1/agent/self-defense/status -> 200 OK (Status: {def_data['status']}, FIM: {def_data['file_integrity_monitoring']['monitored_assets_count']} assets guarded)")
            passed += 1

            # Test 20: Improvement #9 - RUL Hardware Life Predictor
            total += 1
            resp = await client.get("/api/v1/agent/hardware-rul")
            assert resp.status_code == 200, f"Hardware RUL endpoint failed: {resp.status_code} - {resp.text}"
            rul_data = resp.json()
            assert "overall_hardware_score" in rul_data
            assert "battery" in rul_data
            assert "storage" in rul_data
            assert "ml_model_metadata" in rul_data
            assert rul_data["overall_hardware_score"] > 0
            print(f"[{total}] PASS: GET /api/v1/agent/hardware-rul -> 200 OK (Score: {rul_data['overall_hardware_score']}%, Battery: {rul_data['battery']['capacity_percent']}%, SSD: {rul_data['storage']['health_percent']}%)")
            passed += 1

            # Test 21: Improvement #11 - PostgreSQL Cloud Database Support & Pooling
            total += 1
            from app.database import normalize_database_url
            # Test URL normalizer
            n_url, c_args = normalize_database_url("postgres://u:p@db.neon.tech/fixai?sslmode=require")
            assert n_url.startswith("postgresql+asyncpg://"), f"Failed prefix: {n_url}"
            assert "sslmode" not in n_url, f"sslmode not stripped: {n_url}"
            assert c_args.get("ssl") == "require", f"SSL not set in connect_args: {c_args}"

            resp = await client.get("/api/v1/system/db-status")
            assert resp.status_code == 200, f"DB status failed: {resp.status_code} - {resp.text}"
            db_status = resp.json()
            assert db_status["status"] == "HEALTHY"
            assert db_status["ping"] == "OK"
            print(f"[{total}] PASS: GET /api/v1/system/db-status -> 200 OK (Dialect: {db_status['dialect']}, Pool Ping: {db_status['ping']}, Pre-Ping: {db_status['pool_pre_ping']})")
            passed += 1

            # Test 22: Email OTP - Invalid Email Format
            total += 1
            bad_email_resp = await client.post("/api/v1/auth/send-otp", json={"email": "invalid-not-an-email"})
            assert bad_email_resp.status_code in (400, 422), f"Expected validation rejection, got {bad_email_resp.status_code}"
            print(f"[{total}] PASS: POST /api/v1/auth/send-otp [Invalid Email] -> Rejected safely ({bad_email_resp.status_code})")
            passed += 1

            # Test 23: Email OTP - Successful Send
            total += 1
            test_email = f"audit.secops.{os.getpid()}@fixai.security"
            send_resp = await client.post("/api/v1/auth/send-otp", json={"email": test_email})
            assert send_resp.status_code == 200, f"Send OTP failed: {send_resp.status_code} - {send_resp.text}"
            send_data = send_resp.json()
            assert send_data["success"] is True
            assert "OTP sent successfully" in send_data["message"]
            assert send_data["cooldown_seconds"] == 45
            assert send_data["expires_in_seconds"] == 300
            assert send_data.get("dev_otp") is None, "Security Violation: OTP must NOT be exposed in API response"
            from app.services.otp_service import otp_manager
            valid_otp = otp_manager.get_active_otp(test_email)
            assert valid_otp and len(valid_otp) == 6, f"Valid OTP not generated: {valid_otp}"
            print(f"[{total}] PASS: POST /api/v1/auth/send-otp -> 200 OK (OTP dispatched to email, not leaked in HTTP response)")
            passed += 1

            # Test 24: Email OTP - Cooldown Enforcement (Immediate Resend Blocked)
            total += 1
            cooldown_resp = await client.post("/api/v1/auth/send-otp", json={"email": test_email})
            assert cooldown_resp.status_code == 429, f"Expected 429 on cooldown, got {cooldown_resp.status_code}"
            assert "Please wait" in cooldown_resp.json().get("detail", "")
            print(f"[{total}] PASS: POST /api/v1/auth/send-otp [Immediate Resend] -> 429 Cooldown Enforced")
            passed += 1

            # Test 25: Email OTP - Invalid Verification Attempt
            total += 1
            wrong_resp = await client.post("/api/v1/auth/verify-otp", json={"email": test_email, "otp": "000000"})
            assert wrong_resp.status_code == 400, f"Expected 400 for bad OTP, got {wrong_resp.status_code}"
            assert wrong_resp.json().get("detail") == "Invalid OTP"
            print(f"[{total}] PASS: POST /api/v1/auth/verify-otp [Wrong OTP] -> 400 Bad Request ('Invalid OTP')")
            passed += 1

            # Test 26: Email OTP - Correct Verification & JWT Issuance
            total += 1
            verify_resp = await client.post("/api/v1/auth/verify-otp", json={"email": test_email, "otp": valid_otp})
            assert verify_resp.status_code == 200, f"Verify OTP failed: {verify_resp.status_code} - {verify_resp.text}"
            verify_data = verify_resp.json()
            assert verify_data["success"] is True
            assert "access_token" in verify_data
            assert verify_data["user"]["email"] == test_email

            # Verify issued JWT via /api/v1/auth/me
            me_resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {verify_data['access_token']}"})
            assert me_resp.status_code == 200, f"Me endpoint failed: {me_resp.status_code} - {me_resp.text}"
            me_data = me_resp.json()
            assert me_data["email"] == test_email
            print(f"[{total}] PASS: POST /api/v1/auth/verify-otp -> 200 OK (Authenticated, JWT Issued, /auth/me verified)")
            passed += 1

            # Allow async subprocess transports to close cleanly
            await asyncio.sleep(0.2)

    print("=" * 70)
    print(f"  All {passed}/{total} Integration Tests PASSED with ZERO ERRORS!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(run_tests())
