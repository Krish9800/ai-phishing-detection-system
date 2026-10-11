"""Linguistic, psychological, and semantic NLP feature extractor for email bodies."""

import re

from phish_ai.models.schemas import NLPFeatures


class NLPExtractor:
    """Extracts psychological, emotional, and call-to-action indicators from text."""

    URGENCY_TRIGGERS: list[str] = [
        "urgent",
        "immediately",
        "action required",
        "suspended",
        "terminate",
        "compromised",
        "within 24 hours",
        "within 48 hours",
        "deadline",
        "expir",
        "critical alert",
        "unauthorized activity",
        "security breach",
        "act now",
        "limited time",
    ]

    THREAT_TRIGGERS: list[str] = [
        "legal action",
        "law enforcement",
        "police",
        "fbi",
        "arrest",
        "fine",
        "penalty",
        "suspend your account",
        "permanent deletion",
        "loss of access",
        "prosecut",
        "court",
        "warrant",
    ]

    FINANCIAL_TRIGGERS: list[str] = [
        "wire transfer",
        "payment overdue",
        "invoice attached",
        "direct deposit",
        "bank account",
        "credit card",
        "bitcoin",
        "crypto",
        "wallet",
        "gift card",
        "refund approved",
        "tax refund",
        "payroll",
        "compensation",
        "billing statement",
    ]

    CALL_TO_ACTION_PATTERNS: list[str] = [
        r"click here",
        r"log in now",
        r"sign in here",
        r"verify your identity",
        r"verify your account",
        r"update your details",
        r"reset your password",
        r"download attachment",
        r"view invoice",
        r"confirm your email",
        r"follow the link below",
    ]

    @classmethod
    def extract_features(cls, text: str) -> NLPFeatures:
        """Analyze text and compute normalized psychological and structural indicators."""
        if not text or not text.strip():
            return NLPFeatures()

        clean_lower = text.lower()
        words = re.findall(r"\b\w+\b", text)
        word_count = len(words)

        if word_count == 0:
            return NLPFeatures()

        # Urgency density score
        urgency_matches = sum(1 for trigger in cls.URGENCY_TRIGGERS if trigger in clean_lower)
        urgency_score = min(1.0, urgency_matches * 0.25)

        # Threat / intimidation score
        threat_matches = sum(1 for trigger in cls.THREAT_TRIGGERS if trigger in clean_lower)
        threat_score = min(1.0, threat_matches * 0.30)

        # Financial lure score
        financial_matches = sum(1 for trigger in cls.FINANCIAL_TRIGGERS if trigger in clean_lower)
        financial_score = min(1.0, financial_matches * 0.25)

        # Call to action detection
        call_to_action = any(
            re.search(pattern, clean_lower) for pattern in cls.CALL_TO_ACTION_PATTERNS
        )

        # Uppercase ratio (excessive capitalization often used in urgency/fear lures)
        alpha_chars = [c for c in text if c.isalpha()]
        uppercase_ratio = 0.0
        if alpha_chars:
            uppercase_ratio = sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars)

        # Exclamation mark frequency
        exclamation_count = text.count("!")

        # Sentiment polarity estimate: threats and urgent penalties drive negative polarity
        polarity = 0.0
        if threat_matches > 0 or urgency_matches > 0:
            polarity = -min(1.0, (threat_matches * 0.3) + (urgency_matches * 0.2))

        return NLPFeatures(
            urgency_score=round(urgency_score, 3),
            threat_intimidation_score=round(threat_score, 3),
            financial_lure_score=round(financial_score, 3),
            call_to_action_detected=call_to_action,
            grammatical_anomaly_ratio=0.0,
            sentiment_polarity=round(polarity, 3),
            word_count=word_count,
            uppercase_ratio=round(uppercase_ratio, 3),
            exclamation_count=exclamation_count,
        )
