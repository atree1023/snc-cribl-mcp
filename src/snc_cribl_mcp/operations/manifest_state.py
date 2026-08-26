"""Durable plans and apply receipts for configuration-manifest workflows."""

from __future__ import annotations

import json
import sqlite3
import threading
import weakref
from contextlib import suppress
from pathlib import Path
from typing import Any, cast


class ManifestStateStore:
    """Persist immutable manifest plans and apply receipts in SQLite."""

    def __init__(self, database_path: Path | None = None) -> None:
        """Initialize a store; ``None`` selects an isolated in-memory database."""
        self._database_path = database_path
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        self._connection_finalizer: weakref.finalize[[], ManifestStateStore] | None = None

    def _ensure_connection(self) -> sqlite3.Connection:
        """Open and initialize the SQLite connection on first use."""
        with self._lock:
            if self._connection is not None:
                return self._connection
            database_path = self._database_path
            if database_path is None:
                connection = sqlite3.connect(":memory:", check_same_thread=False)
            else:
                database_path.parent.mkdir(parents=True, exist_ok=True)
                connection = sqlite3.connect(database_path, check_same_thread=False)
            connection.row_factory = sqlite3.Row
            self._connection = connection
            self._connection_finalizer = weakref.finalize(self, connection.close)
            self._initialize(connection)
            return connection

    def _initialize(self, connection: sqlite3.Connection) -> None:
        """Create state tables when missing."""
        with self._lock, connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS manifest_plans (
                    plan_sha256 TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    intent_sha256 TEXT NOT NULL,
                    manifest_path TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS manifest_receipts (
                    receipt_sha256 TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL,
                    intent_sha256 TEXT NOT NULL,
                    manifest_path TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS manifest_receipts_job_id ON manifest_receipts(job_id)")

    def close(self) -> None:
        """Close the SQLite connection and release its file handle."""
        with self._lock:
            finalizer = self._connection_finalizer
            if finalizer is not None and finalizer.alive:
                finalizer()
            self._connection = None
            self._connection_finalizer = None

    def __del__(self) -> None:
        """Best-effort cleanup for short-lived stores and test processes."""
        with suppress(Exception):
            self.close()

    @staticmethod
    def _json(value: object) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @staticmethod
    def _payload(row: sqlite3.Row | None, *, description: str) -> dict[str, Any]:
        if row is None:
            msg = f"Unknown {description}."
            raise ValueError(msg)
        decoded = json.loads(cast("str", row["payload_json"]))
        if not isinstance(decoded, dict):
            msg = f"Stored {description} is invalid."
            raise TypeError(msg)
        return cast("dict[str, Any]", decoded)

    def save_plan(
        self,
        *,
        plan_sha256: str,
        operation: str,
        intent_sha256: str,
        manifest_path: str,
        created_at: str,
        payload: dict[str, Any],
    ) -> None:
        """Persist an immutable reviewed plan."""
        connection = self._ensure_connection()
        with self._lock, connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO manifest_plans
                    (plan_sha256, operation, intent_sha256, manifest_path, created_at, payload_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (plan_sha256, operation, intent_sha256, manifest_path, created_at, self._json(payload)),
            )

    def get_plan(self, plan_sha256: str, *, operation: str | None = None) -> dict[str, Any]:
        """Return a reviewed plan by digest and optionally enforce its operation."""
        connection = self._ensure_connection()
        with self._lock:
            row = connection.execute(
                "SELECT operation, payload_json FROM manifest_plans WHERE plan_sha256 = ?",
                (plan_sha256,),
            ).fetchone()
        payload = self._payload(row, description=f"manifest plan '{plan_sha256}'")
        if operation is not None and row is not None and row["operation"] != operation:
            msg = f"Manifest plan '{plan_sha256}' belongs to operation '{row['operation']}', not '{operation}'."
            raise ValueError(msg)
        return payload

    def save_receipt(
        self,
        *,
        receipt_sha256: str,
        job_id: str,
        intent_sha256: str,
        manifest_path: str,
        created_at: str,
        payload: dict[str, Any],
    ) -> None:
        """Persist an apply receipt used to authorize later commit/deploy."""
        connection = self._ensure_connection()
        with self._lock, connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO manifest_receipts
                    (receipt_sha256, job_id, intent_sha256, manifest_path, created_at, payload_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (receipt_sha256, job_id, intent_sha256, manifest_path, created_at, self._json(payload)),
            )

    def get_receipt(self, *, receipt_sha256: str | None = None, job_id: str | None = None) -> dict[str, Any]:
        """Return one apply receipt by digest or apply job id."""
        if (receipt_sha256 is None) == (job_id is None):
            msg = "Provide exactly one of receipt_sha256 or job_id."
            raise ValueError(msg)
        connection = self._ensure_connection()
        with self._lock:
            if receipt_sha256 is not None:
                row = connection.execute(
                    "SELECT payload_json FROM manifest_receipts WHERE receipt_sha256 = ?",
                    (receipt_sha256,),
                ).fetchone()
                description = f"manifest receipt '{receipt_sha256}'"
            else:
                row = connection.execute(
                    "SELECT payload_json FROM manifest_receipts WHERE job_id = ?",
                    (job_id,),
                ).fetchone()
                description = f"manifest receipt for job '{job_id}'"
        return self._payload(row, description=description)


__all__ = ["ManifestStateStore"]
