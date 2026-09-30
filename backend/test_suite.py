"""
FixAI Backend Comprehensive Integration Test Suite
===================================================
Runs end-to-end tests against the FastAPI application instance
using AsyncClient/TestClient.
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
        print(f"[{total}] PASS: GET /api/v1/playbooks -> 200 OK (returned {len(resp.json())} items)")
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

        # Allow async subprocess transports to close cleanly
        await asyncio.sleep(0.2)

    print("=" * 70)
    print(f"  All {passed}/{total} Integration Tests PASSED with ZERO ERRORS!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(run_tests())
