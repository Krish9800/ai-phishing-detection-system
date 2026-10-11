"""Runtime configuration settings for AI Phishing Detection System."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration settings for phishing detection pipeline."""

    model_config = SettingsConfigDict(
        env_prefix="PHISH_AI_",
        env_file=".env",
        extra="ignore",
    )

    # General configuration
    app_name: str = "AI Phishing Detection System"
    environment: str = "production"
    log_level: str = "INFO"

    # Persistent Storage
    db_path: Path = Path("data/phish_ai.db")

    # ML Classifier Thresholds
    phishing_threshold: float = 0.50  # Probability above which email is classified as Phishing
    suspicious_threshold: float = 0.30  # Probability range [0.30, 0.50) marked as Suspicious

    # Forensic rules
    high_risk_tlds: list[str] = [
        ".zip",
        ".mov",
        ".top",
        ".xyz",
        ".work",
        ".gq",
        ".cf",
        ".tk",
        ".ml",
        ".ga",
        ".loan",
        ".click",
        ".country",
    ]

    urgency_keywords: list[str] = [
        "urgent",
        "immediately",
        "action required",
        "suspended",
        "unauthorized",
        "compromised",
        "verify your account",
        "password expired",
        "security alert",
        "terminate",
        "wire transfer",
        "invoice attached",
        "payment overdue",
        "gift card",
    ]


def get_settings() -> Settings:
    """Return default application settings instance."""
    return Settings()
