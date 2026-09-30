"""
FixAI Backend — Database Auto-Reconciliation & Unified Catalog Seeder
=====================================================================

Ensures all essential database tables, columns, admin users, default devices,
and the complete catalog of 27+ AIOps, Hardware Diagnostics, and EDR Playbooks
are automatically seeded on startup with zero manual setup.
"""

import json
from datetime import datetime, timezone
from sqlalchemy import text


# Unified catalog of all 27+ playbooks
ALL_PLAYBOOKS = [
    {
        "id": "flush_cache",
        "name": "Flush Application Cache",
        "risk_tier": "LOW",
        "verification_window_seconds": 10,
        "description": "Purge in-memory application caches and temporary buffer stores.",
    },
    {
        "id": "purge_tmp",
        "name": "Purge Stale Temporary Files",
        "risk_tier": "LOW",
        "verification_window_seconds": 15,
        "description": "Purge orphaned scratch files and temporary storage directories.",
    },
    {
        "id": "restart_worker",
        "name": "Restart Background Worker",
        "risk_tier": "MEDIUM",
        "verification_window_seconds": 20,
        "description": "Gracefully reload local background processing worker thread.",
    },
    {
        "id": "restart_background_service",
        "name": "Restart Background Service",
        "risk_tier": "MEDIUM",
        "verification_window_seconds": 25,
        "description": "Gracefully reload local daemon and background service process.",
    },
    {
        "id": "retry_service",
        "name": "Retry Service Health Check",
        "risk_tier": "LOW",
        "verification_window_seconds": 10,
        "description": "Trigger upstream connectivity verification ping and retry request queue.",
    },
    {
        "id": "kill_high_mem_process",
        "name": "Terminate High-Memory Process",
        "risk_tier": "LOW",
        "verification_window_seconds": 15,
        "description": "Safely recycle non-critical process causing memory pressure.",
    },
    {
        "id": "restart_container",
        "name": "Restart Service Container",
        "risk_tier": "MEDIUM",
        "verification_window_seconds": 30,
        "description": "Recycle isolated execution container environment.",
    },
    {
        "id": "scale_instances",
        "name": "Scale Resource Worker Instances",
        "risk_tier": "MEDIUM",
        "verification_window_seconds": 40,
        "description": "Dynamically adjust worker thread pool allocation for high-throughput loads.",
    },
    {
        "id": "db_maintenance",
        "name": "Database Maintenance Window",
        "risk_tier": "HIGH",
        "verification_window_seconds": 60,
        "description": "Execute database vacuum and index defragmentation pass.",
    },
    # ── Laptop Hardware & Diagnostics Playbooks ──
    {
        "id": "cool_down_cpu",
        "name": "CPU Thermal Throttling Mitigation",
        "risk_tier": "LOW",
        "verification_window_seconds": 15,
        "description": "Apply balanced ACPI power policy, cap clock state, and prioritize cooling.",
    },
    {
        "id": "optimize_battery_health",
        "name": "Battery ACPI & Power Calibration",
        "risk_tier": "LOW",
        "verification_window_seconds": 10,
        "description": "Engage battery saver profile and throttle power-draining background tasks.",
    },
    {
        "id": "reset_network_adapter",
        "name": "Wi-Fi DNS Flush & Winsock Stack Reset",
        "risk_tier": "LOW",
        "verification_window_seconds": 12,
        "description": "Flush DNS resolver cache and re-index TCP/IP interface sockets.",
    },
    {
        "id": "restart_graphics_subsystem",
        "name": "Recycle Desktop Window Manager (DWM)",
        "risk_tier": "MEDIUM",
        "verification_window_seconds": 15,
        "description": "Soft refresh DWM display pipeline to resolve VRAM leaks and screen stutter.",
    },
    {
        "id": "optimize_storage_trim",
        "name": "SSD Hardware TRIM & Sector Clean",
        "risk_tier": "LOW",
        "verification_window_seconds": 15,
        "description": "Execute filesystem storage TRIM and cleanup error crash journals.",
    },
    {
        "id": "restart_audio_service",
        "name": "Restart Windows Audio & Endpoint Services",
        "risk_tier": "LOW",
        "verification_window_seconds": 10,
        "description": "Restart Audiosrv and AudioEndpointBuilder services.",
    },
    {
        "id": "fix_windows_update",
        "name": "Reset Windows Update Cache & BITS",
        "risk_tier": "MEDIUM",
        "verification_window_seconds": 20,
        "description": "Purge corrupted update download cache and synchronize BITS service.",
    },
    {
        "id": "rescan_pnp_devices",
        "name": "PnP Hardware Bus Re-enumeration",
        "risk_tier": "LOW",
        "verification_window_seconds": 10,
        "description": "Re-enumerate USB, HID, and peripheral device controller hardware tree.",
    },
    {
        "id": "repair_system_files",
        "name": "System Component Store Integrity Check",
        "risk_tier": "MEDIUM",
        "verification_window_seconds": 30,
        "description": "Validate Windows component store and Visual C++ runtime dependencies.",
    },
    {
        "id": "clean_hosts_file",
        "name": "Clean Hosts File & Adware Hooks",
        "risk_tier": "LOW",
        "verification_window_seconds": 5,
        "description": "Purge unauthorized browser redirect rules and adware DNS hooks.",
    },
    {
        "id": "kill_runaway_process",
        "name": "Terminate Runaway Hanging Process",
        "risk_tier": "MEDIUM",
        "verification_window_seconds": 10,
        "description": "Safely terminate runaway thread or non-responding worker.",
    },
    {
        "id": "repair_boot_configuration",
        "name": "Scan EFI BCD Bootloader Configuration",
        "risk_tier": "LOW",
        "verification_window_seconds": 15,
        "description": "Verify EFI partition integrity and clear invalid boot device registry flags.",
    },
    {
        "id": "resolve_driver_conflicts",
        "name": "Cycle Device Power Bus & Resolve Driver Conflicts",
        "risk_tier": "LOW",
        "verification_window_seconds": 10,
        "description": "Clear Device Manager Code 43 / Code 10 errors on peripheral controllers.",
    },
    {
        "id": "fix_app_freeze",
        "name": "Release Locked DCOM/RPC Handles",
        "risk_tier": "LOW",
        "verification_window_seconds": 5,
        "description": "Release locked IPC/RPC handles causing UI thread application freezes.",
    },
    # ── EDR & Cybersecurity Playbooks ──
    {
        "id": "quarantine_threat_payload",
        "name": "4-Phase Guarded Quarantine & AES-256 Vault",
        "risk_tier": "HIGH",
        "verification_window_seconds": 10,
        "description": "Isolate process, verify SHA-256 against OS core whitelist, and move file to AES-256 vault.",
    },
    {
        "id": "isolate_c2_network",
        "name": "Sever Command & Control (C2) Network Link",
        "risk_tier": "MEDIUM",
        "verification_window_seconds": 8,
        "description": "Inject host firewall drop rule to sever active Command & Control data exfiltration.",
    },
    {
        "id": "purge_wmi_persistence",
        "name": "Purge Fileless WMI Event Consumer Persistence",
        "risk_tier": "HIGH",
        "verification_window_seconds": 12,
        "description": "Purge rogue WMI Event Filters and CommandLineEventConsumers from root\\subscription.",
    },
    {
        "id": "remediate_brute_force",
        "name": "Mitigate Credential Brute-Force Attack",
        "risk_tier": "MEDIUM",
        "verification_window_seconds": 8,
        "description": "Enact host firewall inbound block rule for attacking IP and reset auth failure velocity.",
    },
    {
        "id": "upgrade_software_package",
        "name": "Upgrade Outdated Software Package",
        "risk_tier": "LOW",
        "verification_window_seconds": 30,
        "description": "Download and install signed vendor software update via Windows Package Manager.",
    },
]


def sync_and_seed_database(sync_conn) -> None:
    """
    Called within engine.begin() on startup. Reconciles schema columns,
    seeds default administrator, provisioned device, and the unified playbook catalog.
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Column reconciliation for SQLite
    try:
        res = sync_conn.execute(text("PRAGMA table_info(playbooks)")).fetchall()
        cols = [r[1] for r in res]
        if cols and "verification_window_seconds" not in cols:
            sync_conn.execute(text("ALTER TABLE playbooks ADD COLUMN verification_window_seconds INTEGER DEFAULT 15"))
    except Exception:
        pass

    # 2. Seed Default User if table is empty
    try:
        user_count = sync_conn.execute(text("SELECT COUNT(*) FROM users")).scalar()
        if user_count == 0:
            sync_conn.execute(
                text(
                    "INSERT INTO users (id, email, username, hashed_password, role, created_at) "
                    "VALUES (:id, :email, :username, :password, :role, :created_at)"
                ),
                {
                    "id": "user-admin-001",
                    "email": "admin@fixai.local",
                    "username": "admin",
                    "password": "$2b$12$e8kZ1fC6X9vY0uQ8rL7eEOv4yZ2b9q8w7e6r5t4y3u2i1o0p9a8s",
                    "role": "ADMIN",
                    "created_at": now_iso,
                },
            )
    except Exception:
        pass

    # 3. Seed Default Devices if missing (dev-laptop-001 & primary-laptop)
    try:
        default_devices = [
            ("dev-laptop-001", "Local Workstation"),
            ("primary-laptop", "Primary Endpoint"),
        ]
        for dev_id, dev_name in default_devices:
            existing = sync_conn.execute(text("SELECT id FROM devices WHERE id = :id"), {"id": dev_id}).first()
            if not existing:
                sync_conn.execute(
                    text(
                        "INSERT INTO devices (id, user_id, name, api_key, api_key_hash, status, health_score, failure_risk, anomaly_score, agent_online, last_heartbeat, created_at, updated_at) "
                        "VALUES (:id, :user_id, :name, :api_key, :api_key, 'HEALTHY', 100.0, 0.0, 0.0, 1, :now, :now, :now)"
                    ),
                    {
                        "id": dev_id,
                        "user_id": "user-admin-001",
                        "name": dev_name,
                        "api_key": "fixai-device-secret-key-2026",
                        "now": now_iso,
                    },
                )
    except Exception:
        pass

    # 4. Upsert / Seed All Playbooks into unified catalog
    try:
        existing_playbook_ids = set(
            sync_conn.execute(text("SELECT id FROM playbooks")).scalars().all()
        )
        for pb in ALL_PLAYBOOKS:
            if pb["id"] not in existing_playbook_ids:
                sync_conn.execute(
                    text(
                        "INSERT INTO playbooks (id, name, risk_tier, allowed_params, description, verification_window_seconds, created_at) "
                        "VALUES (:id, :name, :risk_tier, :allowed_params, :description, :verification_window_seconds, :created_at)"
                    ),
                    {
                        "id": pb["id"],
                        "name": pb["name"],
                        "risk_tier": pb["risk_tier"],
                        "allowed_params": json.dumps({}),
                        "description": pb["description"],
                        "verification_window_seconds": pb["verification_window_seconds"],
                        "created_at": now_iso,
                    },
                )
    except Exception:
        pass
