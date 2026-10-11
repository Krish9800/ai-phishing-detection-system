"""Unit tests for ML classifier ensemble and explainability."""

from phish_ai.ml.classifier import PhishingEnsembleClassifier
from phish_ai.models.enums import RiskLevel, Verdict
from phish_ai.models.schemas import FeatureVector


def test_benign_feature_vector_classification() -> None:
    """Verify clean email features produce CLEAN verdict and low probability."""
    clf = PhishingEnsembleClassifier()
    clean_vec = FeatureVector(
        spf_fail=0.0,
        dkim_fail=0.0,
        dmarc_fail=0.0,
        display_name_spoof=0.0,
        urgency_score=0.0,
        financial_lure_score=0.0,
        threat_score=0.0,
        max_url_entropy=2.5,
        has_ip_url=0.0,
        has_homoglyph_url=0.0,
        has_suspicious_tld=0.0,
        url_count=1.0,
    )

    verdict, risk, prob, confidence = clf.classify(clean_vec)
    assert verdict == Verdict.CLEAN
    assert risk == RiskLevel.LOW
    assert prob < 0.30
    assert confidence > 0.0

    indicators = clf.explain(clean_vec)
    assert len(indicators) == 0


def test_phishing_feature_vector_classification_and_explanation() -> None:
    """Verify high threat signals yield PHISHING verdict with explainable indicators."""
    clf = PhishingEnsembleClassifier()
    phish_vec = FeatureVector(
        spf_fail=1.0,
        dkim_fail=0.0,
        dmarc_fail=1.0,
        display_name_spoof=1.0,
        return_path_mismatch=1.0,
        urgency_score=0.8,
        financial_lure_score=0.7,
        threat_score=0.6,
        call_to_action=1.0,
        max_url_entropy=4.2,
        has_ip_url=1.0,
        has_homoglyph_url=1.0,
        has_suspicious_tld=1.0,
        url_count=2.0,
    )

    verdict, risk, prob, confidence = clf.classify(phish_vec)
    assert verdict == Verdict.PHISHING
    assert risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}
    assert prob >= 0.50

    indicators = clf.explain(phish_vec)
    assert len(indicators) >= 4
    names = [i.indicator_name for i in indicators]
    assert "DISPLAY_NAME_SPOOF" in names
    assert "AUTH_CHECK_FAILED" in names
    assert "RAW_IP_URL" in names
    assert "HOMOGLYPH_DOMAIN" in names
