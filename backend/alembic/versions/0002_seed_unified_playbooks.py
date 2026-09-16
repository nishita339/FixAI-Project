"""Seed unified playbook catalog

Revision ID: 0002_seed_unified_playbooks
Revises: 0001_initial_schema
Create Date: 2026-09-13 18:30:00.000000

"""
from datetime import datetime, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002_seed_unified_playbooks"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

UNIFIED_PLAYBOOKS = [
    {
        "id": "flush_cache",
        "name": "Flush Application Cache",
        "risk_tier": "LOW",
        "allowed_params": {"service": ["app_service", "redis", "all"]},
        "description": "Clears temporary cache files and in-memory caches. Zero downtime.",
    },
    {
        "id": "retry_service",
        "name": "Retry Failed Requests",
        "risk_tier": "LOW",
        "allowed_params": {"max_retries": [1, 2, 3, 5], "backoff_ms": [100, 250, 500]},
        "description": "Triggers connectivity checks and retries pending requests.",
    },
    {
        "id": "purge_tmp",
        "name": "Purge Temporary Files",
        "risk_tier": "LOW",
        "allowed_params": {"path": ["/tmp/fixai_cache", "temp", "logs"], "older_than_hours": [1, 6, 24]},
        "description": "Safely removes stale temporary artifacts to reclaim storage.",
    },
    {
        "id": "kill_high_mem_process",
        "name": "Terminate High-Memory Process",
        "risk_tier": "MEDIUM",
        "allowed_params": {"threshold_percent": [70, 80, 85, 90]},
        "description": "Identifies and terminates runaway user-space processes leaking memory.",
    },
    {
        "id": "restart_worker",
        "name": "Restart Background Worker",
        "risk_tier": "MEDIUM",
        "allowed_params": {"worker_name": ["celery", "rq", "background_worker", "default"]},
        "description": "Recycles background worker subprocesses to release leaked handles.",
    },
    {
        "id": "restart_container",
        "name": "Restart Service Container",
        "risk_tier": "MEDIUM",
        "allowed_params": {"container_name": ["app_service", "web", "api"]},
        "description": "Restarts application container or process to reset runtime state.",
    },
    {
        "id": "restart_background_service",
        "name": "Restart Background Service",
        "risk_tier": "MEDIUM",
        "allowed_params": {"service_name": ["fixai-worker", "nginx", "uvicorn"]},
        "description": "Restarts managed system background service unit.",
    },
    {
        "id": "scale_instances",
        "name": "Scale Service Instances",
        "risk_tier": "MEDIUM",
        "allowed_params": {"replicas": [1, 2, 3, 4]},
        "description": "Increases service instance count to absorb request spikes.",
    },
    {
        "id": "db_maintenance",
        "name": "Database Maintenance Window",
        "risk_tier": "HIGH",
        "allowed_params": {"vacuum": True, "reindex": True},
        "description": "Performs database maintenance and resets pools. Strictly manual guidance only.",
    },
]


def upgrade() -> None:
    now = datetime.now(timezone.utc)
    playbooks_table = sa.table(
        "playbooks",
        sa.column("id", sa.String),
        sa.column("name", sa.String),
        sa.column("risk_tier", sa.String),
        sa.column("allowed_params", sa.JSON),
        sa.column("description", sa.String),
        sa.column("created_at", sa.DateTime),
    )

    # Insert unified playbooks
    for pb in UNIFIED_PLAYBOOKS:
        op.execute(
            playbooks_table.delete().where(playbooks_table.c.id == pb["id"])
        )
        op.bulk_insert(
            playbooks_table,
            [
                {
                    "id": pb["id"],
                    "name": pb["name"],
                    "risk_tier": pb["risk_tier"],
                    "allowed_params": pb["allowed_params"],
                    "description": pb["description"],
                    "created_at": now,
                }
            ],
        )


def downgrade() -> None:
    playbooks_table = sa.table("playbooks", sa.column("id", sa.String))
    for pb in UNIFIED_PLAYBOOKS:
        op.execute(playbooks_table.delete().where(playbooks_table.c.id == pb["id"]))
