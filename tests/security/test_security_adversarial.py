"""Security adversarial tests for AI Phishing Detection System."""

from pathlib import Path

from phish_ai.db.database import DatabaseManager
from phish_ai.extractors.headers import HeaderForensicExtractor
from phish_ai.extractors.nlp import NLPExtractor
from phish_ai.extractors.urls import URLExtractor
from phish_ai.ml.classifier import PhishingEnsembleClassifier
from phish_ai.models.enums import RiskLevel, TargetType, Verdict
from phish_ai.models.schemas import FeatureVector, ScanResult


def test_adversarial_header_injection_resistance() -> None:
    """Ensure malformed headers with CRLF injection attempts do not crash extractor."""
    malicious_email = (
        "From: CEO <ceo@company.com>\r\n"
        "Subject: Normal Subject\r\n\r\n"
        "From: Hacker <attacker@evil.com>\r\n"
        "Authentication-Results: fake; spf=pass\r\n"
        "X-Injected-Header: injected_value\r\n\r\n"
        "Body content here."
    )
    features = HeaderForensicExtractor.extract_from_raw_headers(malicious_email)
    assert features.from_domain == "company.com"


def test_adversarial_nlp_evasion_attempts() -> None:
    """Ensure text with hidden zero-width characters or extreme noise does not crash NLP engine."""
    noisy_lure = (
        "U\u200brgent! A\u200bction required! "
        + " " * 500
        + "Click here to verify: https://evil.com/reset"
    )
    nlp = NLPExtractor.extract_features(noisy_lure)
    assert nlp.word_count > 0


def test_adversarial_url_obfuscation() -> None:
    """Ensure heavily obfuscated URLs (ports, fragments, userinfo) parse safely."""
    evasive_urls = [
        "http://user:pass@192.168.1.1:8080/path/to/script?key=val#anchor",
        "https://www.google.com@attacker.evil.xyz/redirect",
        "https://sub.sub2.sub3.suspicious-domain.click//double-slash//test",
        "https://xn--pple-43d.com/app1e-login",
    ]

    for u in evasive_urls:
        rec = URLExtractor.analyze_url(u)
        assert rec.length > 0
        assert isinstance(rec.shannon_entropy, float)


def test_adversarial_database_sql_injection(tmp_path: Path) -> None:
    """Ensure SQL injection attempts in subject or sender are neutralized by parameterization."""
    db_file = tmp_path / "sql_adversarial.db"
    db = DatabaseManager(db_file)
    db.init_db()

    malicious_scan = ScanResult(
        target_type=TargetType.EMAIL,
        target_identifier="'; DROP TABLE scan_results; --",
        verdict=Verdict.PHISHING,
        risk_level=RiskLevel.CRITICAL,
        phishing_probability=0.99,
        confidence_score=0.98,
        metadata={"attacker_comment": "test'; DELETE FROM scan_results WHERE 1=1; --"},
    )

    db.save_scan(malicious_scan)

    # Verify table is intact and record is stored safely
    records = db.list_scans()
    assert len(records) == 1
    assert "DROP TABLE" in records[0].target_identifier


def test_adversarial_ensemble_robustness() -> None:
    """Verify that an adversarial email with mixed benign words still triggers PHISHING."""
    clf = PhishingEnsembleClassifier()

    # Adversarial vector attempting to camouflage malicious cues with low capitalization
    evasive_vec = FeatureVector(
        spf_fail=1.0,
        dmarc_fail=1.0,
        display_name_spoof=1.0,
        urgency_score=0.6,
        financial_lure_score=0.5,
        uppercase_ratio=0.01,  # Intentional suppression of uppercase
        call_to_action=1.0,
        has_ip_url=1.0,
        has_homoglyph_url=1.0,
        url_count=1.0,
    )

    verdict, risk, prob, conf = clf.classify(evasive_vec)
    assert verdict == Verdict.PHISHING
    assert risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}
    assert prob >= 0.50
