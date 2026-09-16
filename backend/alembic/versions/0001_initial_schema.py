"""Initial schema and seed device

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-09-13 18:00:00.000000

"""
from datetime import datetime, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. users table
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("email", sa.String(length=255), unique=True, index=True, nullable=False),
        sa.Column("username", sa.String(length=100), unique=True, index=True, nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=20), server_default="SRE", nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )

    # 2. devices table
    op.create_table(
        "devices",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=False, index=True),
        sa.Column("name", sa.String(length=100), nullable=False, index=True),
        sa.Column("api_key", sa.String(length=255), nullable=True, index=True),
        sa.Column("api_key_hash", sa.String(length=255), nullable=True, index=True),
        sa.Column("status", sa.String(length=20), server_default="HEALTHY", nullable=False),
        sa.Column("health_score", sa.Float(), server_default="100.0", nullable=False),
        sa.Column("failure_risk", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("anomaly_score", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("agent_online", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("specs", sa.JSON(), nullable=True),
        sa.Column("last_heartbeat", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )

    # 3. playbooks table
    op.create_table(
        "playbooks",
        sa.Column("id", sa.String(length=50), primary_key=True),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("risk_tier", sa.String(length=20), nullable=False),
        sa.Column("allowed_params", sa.JSON(), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )

    # 4. incidents table
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("device_id", sa.String(length=36), sa.ForeignKey("devices.id"), nullable=False, index=True),
        sa.Column("status", sa.String(length=30), server_default="OPEN", nullable=False, index=True),
        sa.Column("risk", sa.String(length=20), server_default="MEDIUM", nullable=False),
        sa.Column("primary_cause", sa.String(length=100), nullable=False),
        sa.Column("explanation", sa.String(length=500), nullable=False),
        sa.Column("failure_probability", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("anomaly_score", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("shap", sa.JSON(), nullable=True),
        sa.Column("playbook_id", sa.String(length=50), sa.ForeignKey("playbooks.id"), nullable=True),
        sa.Column("scenario_key", sa.String(length=100), nullable=True, index=True),
        sa.Column("detected_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
    )

    # 5. telemetry_samples table
    op.create_table(
        "telemetry_samples",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("device_id", sa.String(length=36), sa.ForeignKey("devices.id"), nullable=False, index=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False, index=True),
        sa.Column("cpu", sa.Float(), nullable=False),
        sa.Column("ram", sa.Float(), nullable=False),
        sa.Column("latency", sa.Float(), nullable=False),
        sa.Column("error_rate", sa.Float(), nullable=False),
        sa.Column("disk", sa.Float(), nullable=False),
    )

    # 6. audit_logs table
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("device_id", sa.String(length=36), sa.ForeignKey("devices.id"), nullable=True),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("policy_decision", sa.String(length=20), nullable=False),
        sa.Column("reason", sa.String(length=255), nullable=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
    )

    # Seed an initial user and device for immediate testing
    now = datetime.now(timezone.utc)
    users_table = sa.table(
        "users",
        sa.column("id", sa.String),
        sa.column("email", sa.String),
        sa.column("username", sa.String),
        sa.column("hashed_password", sa.String),
        sa.column("role", sa.String),
        sa.column("created_at", sa.DateTime),
    )
    devices_table = sa.table(
        "devices",
        sa.column("id", sa.String),
        sa.column("user_id", sa.String),
        sa.column("name", sa.String),
        sa.column("api_key", sa.String),
        sa.column("api_key_hash", sa.String),
        sa.column("status", sa.String),
        sa.column("health_score", sa.Float),
        sa.column("failure_risk", sa.Float),
        sa.column("anomaly_score", sa.Float),
        sa.column("agent_online", sa.Boolean),
        sa.column("specs", sa.JSON),
        sa.column("last_heartbeat", sa.DateTime),
        sa.column("created_at", sa.DateTime),
        sa.column("updated_at", sa.DateTime),
    )

    op.bulk_insert(
        users_table,
        [
            {
                "id": "usr-admin-001",
                "email": "admin@fixai.internal",
                "username": "admin",
                "hashed_password": "scrypt:mock-initial-hash",
                "role": "ADMIN",
                "created_at": now,
            }
        ],
    )

    op.bulk_insert(
        devices_table,
        [
            {
                "id": "dev-laptop-001",
                "user_id": "usr-admin-001",
                "name": "My Laptop",
                "api_key": "fixai-device-secret-key-2026",
                "api_key_hash": "fixai-device-secret-key-2026",
                "status": "HEALTHY",
                "health_score": 100.0,
                "failure_risk": 0.0,
                "anomaly_score": 0.0,
                "agent_online": True,
                "specs": {"os": "Windows", "cpuModel": "Intel/AMD", "cores": 8, "ramGb": 16},
                "last_heartbeat": now,
                "created_at": now,
                "updated_at": now,
            }
        ],
    )


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("telemetry_samples")
    op.drop_table("incidents")
    op.drop_table("playbooks")
    op.drop_table("devices")
    op.drop_table("users")
