"""Foundation unit tests for settings and initial setup."""

from pathlib import Path

from phish_ai.config.settings import Settings, get_settings


def test_settings_defaults() -> None:
    """Verify default configuration settings."""
    settings = get_settings()
    assert settings.app_name == "AI Phishing Detection System"
    assert settings.environment == "production"
    assert settings.phishing_threshold == 0.50
    assert settings.suspicious_threshold == 0.30
    assert ".xyz" in settings.high_risk_tlds
    assert "urgent" in settings.urgency_keywords
    assert isinstance(settings.db_path, Path)


def test_settings_custom_override() -> None:
    """Verify custom settings overrides."""
    custom = Settings(
        environment="testing",
        phishing_threshold=0.65,
        suspicious_threshold=0.35,
        high_risk_tlds=[".bad"],
    )
    assert custom.environment == "testing"
    assert custom.phishing_threshold == 0.65
    assert custom.suspicious_threshold == 0.35
    assert custom.high_risk_tlds == [".bad"]
