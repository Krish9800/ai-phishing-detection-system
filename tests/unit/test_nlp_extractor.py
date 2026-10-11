"""Unit tests for NLP and semantic feature extractor."""

from phish_ai.extractors.nlp import NLPExtractor


def test_empty_text_handling() -> None:
    """Verify empty or whitespace strings return zeroed NLP features."""
    feat = NLPExtractor.extract_features("")
    assert feat.word_count == 0
    assert feat.urgency_score == 0.0
    assert feat.call_to_action_detected is False


def test_urgency_and_financial_phishing_lure() -> None:
    """Verify detection of combined urgency, financial, and call to action cues."""
    lure_text = (
        "URGENT ACTION REQUIRED! Your bank account has been suspended due to unauthorized "
        "activity. An overdue invoice attached requires wire transfer immediately within 24 hours. "
        "Click here to verify your account or face permanent deletion!"
    )
    feat = NLPExtractor.extract_features(lure_text)

    assert feat.urgency_score >= 0.5
    assert feat.financial_lure_score >= 0.5
    assert feat.threat_intimidation_score >= 0.25
    assert feat.call_to_action_detected is True
    assert feat.uppercase_ratio > 0.05
    assert feat.exclamation_count >= 2
    assert feat.sentiment_polarity < 0.0


def test_clean_benign_text() -> None:
    """Verify normal business correspondence yields low threat scores."""
    clean_text = (
        "Hi Krish, hope you are having a productive week. Looking forward to our scheduled "
        "sprint review meeting tomorrow afternoon. Please review the attached design doc when "
        "you have some free time. Thanks, Alice."
    )
    feat = NLPExtractor.extract_features(clean_text)

    assert feat.urgency_score == 0.0
    assert feat.threat_intimidation_score == 0.0
    assert feat.financial_lure_score == 0.0
    assert feat.call_to_action_detected is False
    assert feat.exclamation_count == 0
