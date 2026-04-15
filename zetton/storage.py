# Zetton - Quantum Software Reverse Engineering Framework
# Copyright (c) 2026 Keeban Villarreal
# Licensed under AGPL-3.0. See LICENSE and COPYRIGHT for details.
# Commercial licensing: keeban.villarreal@my.utsa.edu
"""
Zetton StorageManager — SQLite persistence layer for analysis results.

Cache key: SHA-256 hash of the file + analysis_type.
The same binary at different paths hits the same cache entry.
"""

import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

_DB_DIR = Path.home() / ".zetton"
_DB_PATH = _DB_DIR / "zetton.db"


class StorageManager:
    """Manages a SQLite database at ~/.zetton/zetton.db."""

    def __init__(self, db_path: Path = _DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS binaries (
                    hash        TEXT PRIMARY KEY,
                    path        TEXT NOT NULL,
                    name        TEXT NOT NULL,
                    file_type   TEXT NOT NULL,
                    size        INTEGER,
                    first_seen  TEXT NOT NULL,
                    last_seen   TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS analyses (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    binary_hash     TEXT    NOT NULL,
                    binary_path     TEXT    NOT NULL,
                    binary_name     TEXT    NOT NULL,
                    file_type       TEXT    NOT NULL,
                    analysis_type   TEXT    NOT NULL,
                    results         TEXT    NOT NULL,
                    created_at      TEXT    NOT NULL,
                    updated_at      TEXT    NOT NULL,
                    FOREIGN KEY (binary_hash) REFERENCES binaries(hash)
                );

                CREATE INDEX IF NOT EXISTS idx_analyses_hash_type
                    ON analyses(binary_hash, analysis_type);
            """)

    # ── Public API ───────────────────────────────────────────────────────────

    @staticmethod
    def compute_hash(file_path: str) -> str:
        """Compute the SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def save_analysis(
        self,
        binary_path: str,
        analysis_type: str,
        results: dict,
        file_type: str = "binary",
    ) -> str:
        """
        Persist analysis results for a file.

        Computes the SHA-256 hash of the file, upserts the binary record,
        then inserts or updates the analysis row for (hash, analysis_type).

        Returns the SHA-256 hash.
        """
        path = Path(binary_path)
        file_hash = self.compute_hash(binary_path)
        name = path.name
        size = path.stat().st_size if path.exists() else 0
        now = datetime.now().isoformat()
        results_json = json.dumps(results, default=str)

        with self._connect() as conn:
            # Upsert binary record
            conn.execute(
                """
                INSERT INTO binaries (hash, path, name, file_type, size, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(hash) DO UPDATE SET
                    path      = excluded.path,
                    last_seen = excluded.last_seen
                """,
                (file_hash, str(binary_path), name, file_type, size, now, now),
            )

            # Upsert analysis row
            existing = conn.execute(
                "SELECT id FROM analyses WHERE binary_hash = ? AND analysis_type = ?",
                (file_hash, analysis_type),
            ).fetchone()

            if existing:
                conn.execute(
                    """
                    UPDATE analyses
                    SET results = ?, updated_at = ?, binary_path = ?
                    WHERE binary_hash = ? AND analysis_type = ?
                    """,
                    (results_json, now, str(binary_path), file_hash, analysis_type),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO analyses
                        (binary_hash, binary_path, binary_name, file_type,
                         analysis_type, results, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        file_hash, str(binary_path), name, file_type,
                        analysis_type, results_json, now, now,
                    ),
                )

        return file_hash

    def get_analysis(self, binary_path: str, analysis_type: str) -> Optional[dict]:
        """
        Return cached results for (SHA-256 of file, analysis_type), or None.

        Cache lookup is by hash, so the same binary at different paths hits
        the same cache entry.
        """
        file_hash = self.compute_hash(binary_path)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT results FROM analyses WHERE binary_hash = ? AND analysis_type = ?",
                (file_hash, analysis_type),
            ).fetchone()
        return json.loads(row["results"]) if row else None

    def get_all_analyses(self, binary_path: str) -> list:
        """Return all cached analyses for a file (as a list of dicts)."""
        file_hash = self.compute_hash(binary_path)
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT analysis_type, results, created_at, updated_at
                FROM analyses WHERE binary_hash = ?
                ORDER BY updated_at DESC
                """,
                (file_hash,),
            ).fetchall()
        return [
            {
                "analysis_type": r["analysis_type"],
                "results": json.loads(r["results"]),
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]

    def list_binaries(self) -> list:
        """Return all known binaries with their analysis counts."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    b.hash, b.path, b.name, b.file_type, b.size,
                    b.first_seen, b.last_seen,
                    COUNT(a.id) AS analysis_count
                FROM binaries b
                LEFT JOIN analyses a ON b.hash = a.binary_hash
                GROUP BY b.hash
                ORDER BY b.last_seen DESC
                """,
            ).fetchall()
        return [
            {
                "hash": r["hash"],
                "path": r["path"],
                "name": r["name"],
                "file_type": r["file_type"],
                "size": r["size"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
                "analysis_count": r["analysis_count"],
            }
            for r in rows
        ]

    def get_history(self, binary_hash: str) -> list:
        """Return the analysis history for a binary identified by its hash."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT analysis_type, created_at, updated_at
                FROM analyses WHERE binary_hash = ?
                ORDER BY updated_at DESC
                """,
                (binary_hash,),
            ).fetchall()
        return [
            {
                "analysis_type": r["analysis_type"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]

    def clear_cache(self, binary_path: Optional[str] = None) -> int:
        """
        Clear the cache.

        If binary_path is given, delete only entries for that file's hash.
        Otherwise delete all cached data. Returns the number of analyses deleted.
        """
        with self._connect() as conn:
            if binary_path:
                file_hash = self.compute_hash(binary_path)
                n = conn.execute(
                    "DELETE FROM analyses WHERE binary_hash = ?", (file_hash,)
                ).rowcount
                # Remove the binary record only if no analyses remain
                remaining = conn.execute(
                    "SELECT COUNT(*) FROM analyses WHERE binary_hash = ?", (file_hash,)
                ).fetchone()[0]
                if remaining == 0:
                    conn.execute("DELETE FROM binaries WHERE hash = ?", (file_hash,))
            else:
                n = conn.execute("DELETE FROM analyses").rowcount
                conn.execute("DELETE FROM binaries")
        return n
