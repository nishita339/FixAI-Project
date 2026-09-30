"""
FixAI Local Agent — Store-and-Forward Offline Telemetry Buffer
=============================================================

Persists hardware telemetry, EDR security signals, and Edge AI inference
diagnostics to a local SQLite buffer whenever the endpoint is disconnected
or air-gapped from the backend. When connectivity is restored, cached
telemetry is automatically flushed in chronological order to the backend
batch ingestion endpoint without data loss.
"""

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import requests

logger = logging.getLogger("fixai.offline_buffer")


class OfflineTelemetryBuffer:
    """Manages an embedded, crash-resilient store-and-forward queue."""

    def __init__(self, db_path: Path | str | None = None, max_entries: int = 5000):
        if db_path is None:
            db_path = Path(__file__).resolve().parent / "offline_telemetry.db"
        self.db_path = Path(db_path)
        self.max_entries = max_entries
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self) -> None:
        """Create the offline queue table if it does not exist."""
        try:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS offline_queue (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        payload TEXT NOT NULL,
                        created_at REAL NOT NULL
                    );
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_offline_created ON offline_queue(created_at);"
                )
        except Exception as exc:
            logger.error("Failed to initialize offline telemetry SQLite database: %s", exc)

    def enqueue(self, payload: Dict[str, Any]) -> bool:
        """
        Store a telemetry payload in local SQLite queue.
        Enforces max queue depth via FIFO eviction if queue is full.
        """
        try:
            payload_str = json.dumps(payload)
            now = time.time()
            with self._get_connection() as conn:
                # FIFO prune if exceeded max_entries
                count = conn.execute("SELECT COUNT(*) FROM offline_queue").fetchone()[0]
                if count >= self.max_entries:
                    excess = count - self.max_entries + 1
                    conn.execute(
                        "DELETE FROM offline_queue WHERE id IN (SELECT id FROM offline_queue ORDER BY id ASC LIMIT ?)",
                        (excess,),
                    )

                conn.execute(
                    "INSERT INTO offline_queue (payload, created_at) VALUES (?, ?)",
                    (payload_str, now),
                )
            return True
        except Exception as exc:
            logger.error("Failed to enqueue offline telemetry: %s", exc)
            return False

    def count(self) -> int:
        """Return the number of un-synced offline records."""
        try:
            with self._get_connection() as conn:
                res = conn.execute("SELECT COUNT(*) FROM offline_queue").fetchone()
                return int(res[0]) if res else 0
        except Exception:
            return 0

    def peek(self, limit: int = 50) -> List[Tuple[int, Dict[str, Any]]]:
        """Fetch the oldest records up to limit without deleting."""
        items: List[Tuple[int, Dict[str, Any]]] = []
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT id, payload FROM offline_queue ORDER BY id ASC LIMIT ?",
                    (limit,),
                )
                for row_id, payload_str in cursor.fetchall():
                    try:
                        items.append((row_id, json.loads(payload_str)))
                    except Exception:
                        items.append((row_id, {}))
        except Exception as exc:
            logger.error("Failed to peek offline queue: %s", exc)
        return items

    def remove(self, ids: List[int]) -> None:
        """Remove successfully synchronized record IDs from queue."""
        if not ids:
            return
        try:
            with self._get_connection() as conn:
                placeholders = ",".join("?" for _ in ids)
                conn.execute(f"DELETE FROM offline_queue WHERE id IN ({placeholders})", ids)
        except Exception as exc:
            logger.error("Failed to remove synchronized records from offline queue: %s", exc)

    def flush_to_backend(
        self,
        batch_url: str,
        headers: Dict[str, str],
        batch_size: int = 50,
        timeout: float = 6.0,
    ) -> int:
        """
        Drains the offline queue by posting batches to the backend batch ingestion endpoint.
        Returns total number of flushed records.
        """
        total_flushed = 0
        while True:
            records = self.peek(limit=batch_size)
            if not records:
                break

            ids = [r[0] for r in records]
            payloads = [r[1] for r in records]

            try:
                batch_body = {
                    "batch": payloads,
                }
                resp = requests.post(batch_url, json=batch_body, headers=headers, timeout=timeout)
                if resp.status_code in (200, 201):
                    self.remove(ids)
                    total_flushed += len(ids)
                    logger.info("🔄 Flushed %d offline telemetry samples to backend (HTTP %s)", len(ids), resp.status_code)
                else:
                    logger.warning("Backend batch flush returned status %d — will retry next tick", resp.status_code)
                    break
            except Exception as exc:
                logger.debug("Network error during offline buffer flush: %s", exc)
                break

        return total_flushed
