"""Real-time email and URL phishing forensic analysis endpoints."""

from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from phish_ai.db.database import DatabaseManager
from phish_ai.extractors.headers import HeaderForensicExtractor
from phish_ai.extractors.nlp import NLPExtractor
from phish_ai.extractors.urls import URLExtractor
from phish_ai.ml.classifier import PhishingEnsembleClassifier
from phish_ai.models.enums import AuthStatus, TargetType
from phish_ai.models.schemas import (
    FeatureVector,
    ScanResult,
)

router = APIRouter(prefix="/analyze", tags=["Analysis"])


class EmailAnalysisRequest(BaseModel):
    """Raw email or structured fields for analysis."""

    raw_email: str | None = Field(
        default=None, description="Complete RFC 5322 .eml format text string"
    )
    subject: str = Field(default="", description="Email subject line")
    body: str = Field(default="", description="Email plain text or HTML body")
    from_address: str = Field(default="", description="Sender email address")


class UrlAnalysisRequest(BaseModel):
    """Target URL for phishing and homograph analysis."""

    url: str = Field(..., description="Target HTTP or HTTPS URL to inspect")


def get_db(request: Request) -> DatabaseManager:
    return request.app.state.db  # type: ignore[no-any-return]


def get_classifier(request: Request) -> PhishingEnsembleClassifier:
    return request.app.state.classifier  # type: ignore[no-any-return]


@router.post("/email", response_model=dict[str, Any])
async def analyze_email(
    payload: EmailAnalysisRequest,
    db: DatabaseManager = Depends(get_db),
    classifier: PhishingEnsembleClassifier = Depends(get_classifier),
) -> dict[str, Any]:
    """Analyze an email for spoofing, deceptive headers, NLP lures, and malicious URLs."""
    raw_content = payload.raw_email
    if not raw_content:
        # Build synthetic RFC 5322 string from fields
        raw_content = (
            f"From: {payload.from_address}\r\nSubject: {payload.subject}\r\n\r\n{payload.body}"
        )

    # 1. Header extraction
    headers = HeaderForensicExtractor.extract_from_raw_headers(raw_content)

    # 2. Body extraction
    body_text = payload.body if payload.body else raw_content
    nlp = NLPExtractor.extract_features(body_text)

    # 3. URL extraction
    urls = URLExtractor.extract_urls_from_text(body_text)
    url_records = [URLExtractor.analyze_url(u) for u in urls]

    # 4. Construct FeatureVector for ML
    spf_fail_val = 1.0 if headers.spf_status == AuthStatus.FAIL else 0.0
    dkim_fail_val = 1.0 if headers.dkim_status == AuthStatus.FAIL else 0.0
    dmarc_fail_val = 1.0 if headers.dmarc_status == AuthStatus.FAIL else 0.0
    max_entropy = max((u.shannon_entropy for u in url_records), default=0.0)
    has_ip = 1.0 if any(u.has_ip_host for u in url_records) else 0.0
    has_homoglyph = 1.0 if any(u.has_homoglyphs for u in url_records) else 0.0
    has_bad_tld = 1.0 if any(u.suspicious_tld for u in url_records) else 0.0

    features = FeatureVector(
        spf_fail=spf_fail_val,
        dkim_fail=dkim_fail_val,
        dmarc_fail=dmarc_fail_val,
        display_name_spoof=1.0 if headers.has_display_name_spoof else 0.0,
        return_path_mismatch=1.0 if headers.return_path_mismatch else 0.0,
        urgency_score=nlp.urgency_score,
        financial_lure_score=nlp.financial_lure_score,
        threat_score=nlp.threat_intimidation_score,
        uppercase_ratio=nlp.uppercase_ratio,
        call_to_action=1.0 if nlp.call_to_action_detected else 0.0,
        max_url_entropy=max_entropy,
        has_ip_url=has_ip,
        has_homoglyph_url=has_homoglyph,
        has_suspicious_tld=has_bad_tld,
        url_count=float(len(url_records)),
    )

    verdict, risk, prob, confidence = classifier.classify(features)
    threat_indicators = classifier.explain(features)

    scan_result = ScanResult(
        target_type=TargetType.EMAIL,
        target_identifier=headers.subject or headers.from_address,
        verdict=verdict,
        risk_level=risk,
        phishing_probability=prob,
        confidence_score=confidence,
        header_features=headers,
        nlp_features=nlp,
        url_records=url_records,
        top_threat_indicators=threat_indicators,
        metadata={"client_ip": headers.client_ip},
    )

    db.save_scan(scan_result)
    return scan_result.model_dump(mode="json")


@router.post("/url", response_model=dict[str, Any])
async def analyze_url(
    payload: UrlAnalysisRequest,
    db: DatabaseManager = Depends(get_db),
    classifier: PhishingEnsembleClassifier = Depends(get_classifier),
) -> dict[str, Any]:
    """Analyze a single target URL for typosquatting, Punycode, IP host, and entropy."""
    url_record = URLExtractor.analyze_url(payload.url)

    features = FeatureVector(
        max_url_entropy=url_record.shannon_entropy,
        has_ip_url=1.0 if url_record.has_ip_host else 0.0,
        has_homoglyph_url=1.0 if url_record.has_homoglyphs else 0.0,
        has_suspicious_tld=1.0 if url_record.suspicious_tld else 0.0,
        url_count=1.0,
    )

    verdict, risk, prob, confidence = classifier.classify(features)
    threat_indicators = classifier.explain(features)

    scan_result = ScanResult(
        target_type=TargetType.URL,
        target_identifier=payload.url,
        verdict=verdict,
        risk_level=risk,
        phishing_probability=prob,
        confidence_score=confidence,
        url_records=[url_record],
        top_threat_indicators=threat_indicators,
    )

    db.save_scan(scan_result)
    return scan_result.model_dump(mode="json")
