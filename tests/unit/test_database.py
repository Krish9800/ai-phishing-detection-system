"""Unit tests for SQLite WAL database manager."""

from pathlib import Path

from phish_ai.db.database import DatabaseManager
from phish_ai.models.enums import AuthStatus, RiskLevel, TargetType, Verdict
from phish_ai.models.schemas import (
    HeaderFeatures,
    NLPFeatures,
    ScanResult,
    ThreatIndicator,
    UrlForensicRecord,
)


def test_database_init_and_scan_lifecycle(tmp_path: Path) -> None:
    """Verify storing, retrieving, and filtering scan records."""
    db_file = tmp_path / "test_phish.db"
    db = DatabaseManager(db_file)
    db.init_db()

    # Empty initially
    assert len(db.list_scans()) == 0

    # Create test scans
    scan1 = ScanResult(
        target_type=TargetType.EMAIL,
        target_identifier="Important Security Update",
        verdict=Verdict.PHISHING,
        risk_level=RiskLevel.HIGH,
        phishing_probability=0.88,
        confidence_score=0.76,
        header_features=HeaderFeatures(
            from_address="security@evil.com",
            from_domain="evil.com",
            spf_status=AuthStatus.FAIL,
        ),
        nlp_features=NLPFeatures(urgency_score=0.8),
        url_records=[
            UrlForensicRecord(
                url="http://evil.com/login",
                domain="evil.com",
                tld=".com",
                length=21,
                shannon_entropy=2.8,
            )
        ],
        top_threat_indicators=[
            ThreatIndicator(
                indicator_name="AUTH_FAIL",
                category="Header",
                description="SPF check failed",
                weight=0.3,
            )
        ],
    )

    scan2 = ScanResult(
        target_type=TargetType.URL,
        target_identifier="https://github.com",
        verdict=Verdict.CLEAN,
        risk_level=RiskLevel.LOW,
        phishing_probability=0.05,
        confidence_score=0.90,
    )

    db.save_scan(scan1)
    db.save_scan(scan2)

    # List all
    all_scans = db.list_scans()
    assert len(all_scans) == 2

    # Filter by verdict
    phish_scans = db.list_scans(verdict=Verdict.PHISHING)
    assert len(phish_scans) == 1
    assert phish_scans[0].scan_id == scan1.scan_id
    assert phish_scans[0].header_features is not None
    assert phish_scans[0].header_features.from_domain == "evil.com"
    assert len(phish_scans[0].url_records) == 1

    clean_scans = db.list_scans(verdict=Verdict.CLEAN)
    assert len(clean_scans) == 1
    assert clean_scans[0].scan_id == scan2.scan_id

    # Retrieve by ID
    retrieved = db.get_scan(scan1.scan_id)
    assert retrieved is not None
    assert retrieved.target_identifier == "Important Security Update"

    # Non-existent scan ID
    assert db.get_scan("non-existent") is None
