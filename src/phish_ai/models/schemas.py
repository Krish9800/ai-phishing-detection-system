"""Data schemas and feature contracts for phishing forensics and ML inference."""

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from phish_ai.models.enums import AuthStatus, RiskLevel, TargetType, Verdict


class HeaderFeatures(BaseModel):
    """Forensic signals extracted from RFC 5322 email headers."""

    from_address: str
    from_domain: str
    reply_to: str | None = None
    return_path: str | None = None
    subject: str = ""
    spf_status: AuthStatus = AuthStatus.NONE
    dkim_status: AuthStatus = AuthStatus.NONE
    dmarc_status: AuthStatus = AuthStatus.NONE
    has_display_name_spoof: bool = False
    return_path_mismatch: bool = False
    received_hop_count: int = 0
    client_ip: str | None = None


class NLPFeatures(BaseModel):
    """Linguistic, psychological, and semantic indicators extracted from text."""

    urgency_score: float = 0.0  # 0.0 to 1.0 based on urgency keyword density
    threat_intimidation_score: float = 0.0
    financial_lure_score: float = 0.0
    call_to_action_detected: bool = False
    grammatical_anomaly_ratio: float = 0.0
    sentiment_polarity: float = 0.0  # -1.0 (highly negative/threatening) to 1.0 (positive)
    word_count: int = 0
    uppercase_ratio: float = 0.0
    exclamation_count: int = 0


class UrlForensicRecord(BaseModel):
    """Forensic lexical properties of an extracted URL."""

    url: str
    domain: str
    tld: str
    length: int
    shannon_entropy: float
    has_ip_host: bool = False
    is_punycode: bool = False
    has_homoglyphs: bool = False
    suspicious_tld: bool = False
    subdomain_depth: int = 0
    path_length: int = 0
    query_param_count: int = 0
    has_at_symbol: bool = False
    has_double_slash_redirect: bool = False


class FeatureVector(BaseModel):
    """Normalized numeric and categorical feature vector fed into ML classifier."""

    # Header signals (scaled 0-1)
    spf_fail: float = 0.0
    dkim_fail: float = 0.0
    dmarc_fail: float = 0.0
    display_name_spoof: float = 0.0
    return_path_mismatch: float = 0.0

    # NLP signals
    urgency_score: float = 0.0
    financial_lure_score: float = 0.0
    threat_score: float = 0.0
    uppercase_ratio: float = 0.0
    call_to_action: float = 0.0

    # URL signals
    max_url_entropy: float = 0.0
    has_ip_url: float = 0.0
    has_homoglyph_url: float = 0.0
    has_suspicious_tld: float = 0.0
    url_count: float = 0.0

    def to_array(self) -> list[float]:
        """Convert features to ordered numeric float array for ML model."""
        return [
            self.spf_fail,
            self.dkim_fail,
            self.dmarc_fail,
            self.display_name_spoof,
            self.return_path_mismatch,
            self.urgency_score,
            self.financial_lure_score,
            self.threat_score,
            self.uppercase_ratio,
            self.call_to_action,
            self.max_url_entropy,
            self.has_ip_url,
            self.has_homoglyph_url,
            self.has_suspicious_tld,
            self.url_count,
        ]


class ThreatIndicator(BaseModel):
    """Single explainable threat finding contributing to verdict."""

    indicator_name: str
    category: str  # Header, NLP, URL, Reputation
    description: str
    weight: float  # Importance / confidence delta
    mitre_technique: str = "T1566"


class ScanResult(BaseModel):
    """Comprehensive phishing assessment report."""

    scan_id: str = Field(default_factory=lambda: f"scn-{uuid.uuid4().hex[:12]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target_type: TargetType
    target_identifier: str  # Subject or URL
    verdict: Verdict
    risk_level: RiskLevel
    phishing_probability: float  # 0.00 to 1.00
    confidence_score: float  # 0.00 to 1.00
    header_features: HeaderFeatures | None = None
    nlp_features: NLPFeatures | None = None
    url_records: list[UrlForensicRecord] = Field(default_factory=list)
    top_threat_indicators: list[ThreatIndicator] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
