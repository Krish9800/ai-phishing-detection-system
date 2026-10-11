"""Integration tests for FastAPI REST control plane."""

from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from phish_ai.api.app import create_app
from phish_ai.config.settings import Settings
from phish_ai.db.database import DatabaseManager
from phish_ai.ml.classifier import PhishingEnsembleClassifier
from phish_ai.models.enums import Verdict


@pytest.fixture
def test_db(tmp_path: Path) -> Generator[DatabaseManager, None, None]:
    """Provide a fresh SQLite test database."""
    db_file = tmp_path / "test_api_phish.db"
    db = DatabaseManager(db_file)
    db.init_db()
    yield db


@pytest.fixture
def client(test_db: DatabaseManager, tmp_path: Path) -> Generator[TestClient, None, None]:
    """Provide FastAPI test client."""
    settings = Settings(db_path=tmp_path / "test_api_phish.db")
    classifier = PhishingEnsembleClassifier(settings)
    app = create_app(settings=settings, db=test_db, classifier=classifier)
    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint(client: TestClient) -> None:
    """Test service health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "ai-phishing-detection-system"
    assert data["database_connected"] is True


def test_analyze_email_endpoint(client: TestClient) -> None:
    """Test end-to-end email phishing analysis endpoint."""
    payload = {
        "from_address": "PayPal Support <security@paypa1-update.xyz>",
        "subject": "URGENT: Your account has been suspended",
        "body": (
            "Dear customer, unauthorized activity detected. Immediate wire transfer required. "
            "Click here to verify: http://198.51.100.44/login"
        ),
    }

    response = client.post("/analyze/email", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == Verdict.PHISHING.value
    assert data["phishing_probability"] >= 0.50
    assert len(data["top_threat_indicators"]) >= 2
    assert data["header_features"]["has_display_name_spoof"] is True
    assert len(data["url_records"]) == 1
    assert data["url_records"][0]["has_ip_host"] is True


def test_analyze_url_endpoint(client: TestClient) -> None:
    """Test URL analysis endpoint."""
    payload = {"url": "https://paypa1-security.xyz/login"}
    response = client.post("/analyze/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["target_type"] == "URL"
    assert data["target_identifier"] == "https://paypa1-security.xyz/login"
    assert len(data["url_records"]) == 1
    assert data["url_records"][0]["has_homoglyphs"] is True


def test_scans_endpoints_query_and_filter(client: TestClient) -> None:
    """Test listing and retrieving saved scan reports."""
    # Run analysis to generate scan records
    client.post(
        "/analyze/email",
        json={
            "from_address": "alice@company.com",
            "subject": "Team Lunch",
            "body": "Let's meet tomorrow for lunch.",
        },
    )
    client.post(
        "/analyze/url",
        json={"url": "http://198.51.100.55/evil"},
    )

    # List scans
    resp_list = client.get("/scans")
    assert resp_list.status_code == 200
    scans = resp_list.json()
    assert len(scans) == 2

    # Filter by verdict
    resp_clean = client.get("/scans?verdict=clean")
    assert resp_clean.status_code == 200
    assert len(resp_clean.json()) >= 1

    # Invalid verdict
    resp_inv = client.get("/scans?verdict=invalid_verdict")
    assert resp_inv.status_code == 400

    # Get by scan ID
    target_id = scans[0]["scan_id"]
    resp_single = client.get(f"/scans/{target_id}")
    assert resp_single.status_code == 200
    assert resp_single.json()["scan_id"] == target_id

    # Non-existent scan ID
    resp_missing = client.get("/scans/non-existent-id")
    assert resp_missing.status_code == 404
