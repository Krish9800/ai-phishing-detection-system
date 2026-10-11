"""Core domain enumerations for AI Phishing Detection System."""

from enum import StrEnum


class Verdict(StrEnum):
    """Overall classification verdict for scanned target."""

    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"


class RiskLevel(StrEnum):
    """Categorized threat risk level."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AuthStatus(StrEnum):
    """Authentication verification result (SPF / DKIM / DMARC)."""

    PASS = "PASS"  # nosec B105
    FAIL = "FAIL"
    SOFTFAIL = "SOFTFAIL"
    NONE = "NONE"
    NEUTRAL = "NEUTRAL"
    TEMPERROR = "TEMPERROR"
    PERMERROR = "PERMERROR"


class TargetType(StrEnum):
    """Target category analyzed."""

    EMAIL = "EMAIL"
    URL = "URL"
    TEXT = "TEXT"
