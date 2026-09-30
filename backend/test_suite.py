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

            # Allow async subprocess transports to close cleanly
            await asyncio.sleep(0.2)

    print("=" * 70)
    print(f"  All {passed}/{total} Integration Tests PASSED with ZERO ERRORS!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(run_tests())
