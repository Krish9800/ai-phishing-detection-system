"""SQLite database manager for phishing detection scans and telemetry."""

import json
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from phish_ai.models.enums import RiskLevel, TargetType, Verdict
from phish_ai.models.schemas import (
    HeaderFeatures,
    NLPFeatures,
    ScanResult,
    ThreatIndicator,
    UrlForensicRecord,
)


class DatabaseManager:
    """Thread-safe SQLite database manager running in WAL mode."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self) -> None:
        """Create database tables and indices from schema definition."""
        schema_path = Path(__file__).parent / "schema.sql"
        schema_sql = schema_path.read_text(encoding="utf-8")
        with self._get_connection() as conn:
            conn.executescript(schema_sql)

    def save_scan(self, result: ScanResult) -> None:
        """Persist a completed scan assessment."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scan_results (
                    scan_id, timestamp, target_type, target_identifier, verdict,
                    risk_level, phishing_probability, confidence_score,
                    header_features_json, nlp_features_json, url_records_json,
                    threat_indicators_json, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.scan_id,
                    result.timestamp.isoformat(),
                    result.target_type.value,
                    result.target_identifier,
                    result.verdict.value,
                    result.risk_level.value,
                    result.phishing_probability,
                    result.confidence_score,
                    json.dumps(result.header_features.model_dump(mode="json"))
                    if result.header_features
                    else None,
                    json.dumps(result.nlp_features.model_dump(mode="json"))
                    if result.nlp_features
                    else None,
                    json.dumps([u.model_dump(mode="json") for u in result.url_records]),
                    json.dumps([t.model_dump(mode="json") for t in result.top_threat_indicators]),
                    json.dumps(result.metadata),
                ),
            )

    def _row_to_scan(self, row: sqlite3.Row) -> ScanResult:
        """Helper deserializing SQLite row into ScanResult object."""
        header_data: dict[str, Any] | None = (
            json.loads(row["header_features_json"]) if row["header_features_json"] else None
        )
        nlp_data: dict[str, Any] | None = (
            json.loads(row["nlp_features_json"]) if row["nlp_features_json"] else None
        )
        url_data: list[dict[str, Any]] = (
            json.loads(row["url_records_json"]) if row["url_records_json"] else []
        )
        threat_data: list[dict[str, Any]] = (
            json.loads(row["threat_indicators_json"]) if row["threat_indicators_json"] else []
        )
        meta_data: dict[str, Any] = json.loads(row["metadata_json"]) if row["metadata_json"] else {}

        return ScanResult(
            scan_id=row["scan_id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            target_type=TargetType(row["target_type"]),
            target_identifier=row["target_identifier"],
            verdict=Verdict(row["verdict"]),
            risk_level=RiskLevel(row["risk_level"]),
            phishing_probability=row["phishing_probability"],
            confidence_score=row["confidence_score"],
            header_features=HeaderFeatures(**header_data) if header_data else None,
            nlp_features=NLPFeatures(**nlp_data) if nlp_data else None,
            url_records=[UrlForensicRecord(**u) for u in url_data],
            top_threat_indicators=[ThreatIndicator(**t) for t in threat_data],
            metadata=meta_data,
        )

    def get_scan(self, scan_id: str) -> ScanResult | None:
        """Fetch single scan by its scan_id."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM scan_results WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
            return self._row_to_scan(row) if row else None

    def list_scans(
        self,
        verdict: Verdict | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ScanResult]:
        """Fetch chronological list of scans, optionally filtered by verdict."""
        with self._get_connection() as conn:
            if verdict:
                query = (
                    "SELECT * FROM scan_results WHERE verdict = ? "
                    "ORDER BY timestamp DESC LIMIT ? OFFSET ?"
                )
                rows = conn.execute(query, (verdict.value, limit, offset)).fetchall()
            else:
                query = "SELECT * FROM scan_results ORDER BY timestamp DESC LIMIT ? OFFSET ?"
                rows = conn.execute(query, (limit, offset)).fetchall()

            return [self._row_to_scan(r) for r in rows]
