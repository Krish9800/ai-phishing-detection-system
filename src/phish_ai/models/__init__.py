"""Models package initialization and exports."""

from phish_ai.models.enums import AuthStatus, RiskLevel, TargetType, Verdict
from phish_ai.models.schemas import (
    FeatureVector,
    HeaderFeatures,
    NLPFeatures,
    ScanResult,
    ThreatIndicator,
    UrlForensicRecord,
)

__all__ = [
    "AuthStatus",
    "FeatureVector",
    "HeaderFeatures",
    "NLPFeatures",
    "RiskLevel",
    "ScanResult",
    "TargetType",
    "ThreatIndicator",
    "UrlForensicRecord",
    "Verdict",
]
