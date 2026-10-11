"""Unit tests for domain models and feature contracts."""

from phish_ai.models.enums import AuthStatus, RiskLevel, TargetType, Verdict
from phish_ai.models.schemas import (
    FeatureVector,
    HeaderFeatures,
    NLPFeatures,
    ScanResult,
    ThreatIndicator,
    UrlForensicRecord,
)


def test_domain_enums() -> None:
    """Verify enum representations and consistency."""
    assert Verdict.CLEAN == "CLEAN"
    assert Verdict.PHISHING == "PHISHING"
    assert RiskLevel.CRITICAL == "CRITICAL"
    assert AuthStatus.FAIL == "FAIL"
    assert TargetType.EMAIL == "EMAIL"


def test_feature_vector_serialization() -> None:
    """Verify FeatureVector converts properly to fixed-dimension numeric array."""
    vec = FeatureVector(
        spf_fail=1.0,
        dkim_fail=0.0,
        dmarc_fail=1.0,
        urgency_score=0.85,
        max_url_entropy=4.2,
        has_ip_url=1.0,
    )
    arr = vec.to_array()
    assert len(arr) == 15
    assert arr[0] == 1.0  # spf_fail
    assert arr[2] == 1.0  # dmarc_fail
    assert arr[5] == 0.85  # urgency_score
    assert arr[10] == 4.2  # max_url_entropy
    assert arr[11] == 1.0  # has_ip_url


def test_scan_result_model() -> None:
    """Verify comprehensive ScanResult building."""
    hdr = HeaderFeatures(
        from_address="security@paypal-update.xyz",
        from_domain="paypal-update.xyz",
        spf_status=AuthStatus.FAIL,
        has_display_name_spoof=True,
    )
    nlp = NLPFeatures(
        urgency_score=0.9,
        threat_intimidation_score=0.7,
        call_to_action_detected=True,
    )
    url_rec = UrlForensicRecord(
        url="http://192.168.1.100/login",
        domain="192.168.1.100",
        tld="",
        length=27,
        shannon_entropy=3.1,
        has_ip_host=True,
    )
    indicator = ThreatIndicator(
        indicator_name="IP_BASED_URL",
        category="URL",
        description="Host uses raw IPv4 address",
        weight=0.8,
    )

    result = ScanResult(
        target_type=TargetType.EMAIL,
        target_identifier="Urgent: Your account is suspended",
        verdict=Verdict.PHISHING,
        risk_level=RiskLevel.CRITICAL,
        phishing_probability=0.96,
        confidence_score=0.95,
        header_features=hdr,
        nlp_features=nlp,
        url_records=[url_rec],
        top_threat_indicators=[indicator],
    )

    assert result.verdict == Verdict.PHISHING
    assert result.risk_level == RiskLevel.CRITICAL
    assert result.phishing_probability == 0.96
    assert len(result.top_threat_indicators) == 1
    assert result.scan_id.startswith("scn-")
