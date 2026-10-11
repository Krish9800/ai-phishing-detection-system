"""Machine learning ensemble classifier and feature attribution explainer."""

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from phish_ai.config.settings import Settings
from phish_ai.models.enums import RiskLevel, Verdict
from phish_ai.models.schemas import FeatureVector, ThreatIndicator


class PhishingEnsembleClassifier:
    """Ensemble ML classifier combining calibrated linear model with heuristic weights."""

    FEATURE_NAMES: list[str] = [
        "spf_fail",
        "dkim_fail",
        "dmarc_fail",
        "display_name_spoof",
        "return_path_mismatch",
        "urgency_score",
        "financial_lure_score",
        "threat_score",
        "uppercase_ratio",
        "call_to_action",
        "max_url_entropy",
        "has_ip_url",
        "has_homoglyph_url",
        "has_suspicious_tld",
        "url_count",
    ]

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings()
        self.scaler = StandardScaler()
        self.model = LogisticRegression(C=1.0, random_state=42, max_iter=200)
        self._bootstrap_model()

    def _bootstrap_model(self) -> None:
        """Bootstrap classifier on curated benchmark synthetic dataset."""
        # Synthetic baseline dataset representing typical security telemetry
        # Shape: (N_samples, 15_features)
        x_benign = [
            # Normal email 1: All auth passes, no urgency, normal URL
            [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.05, 0.0, 2.8, 0.0, 0.0, 0.0, 1.0],
            # Normal email 2: Neutral auth, slight caps, no threats
            [0.0, 0.0, 0.0, 0.0, 0.0, 0.1, 0.0, 0.0, 0.08, 0.0, 2.5, 0.0, 0.0, 0.0, 0.0],
            # Normal email 3: Billing receipt, no spoofing, no threat
            [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.2, 0.0, 0.04, 1.0, 3.1, 0.0, 0.0, 0.0, 2.0],
            # Normal email 4: High URL count, newsletter
            [0.0, 0.0, 0.0, 0.0, 0.0, 0.05, 0.0, 0.0, 0.02, 0.0, 3.0, 0.0, 0.0, 0.0, 5.0],
        ]

        x_phish = [
            # Phishing 1: Auth fails, display spoof, urgency, homoglyph url
            [1.0, 1.0, 1.0, 1.0, 1.0, 0.8, 0.7, 0.6, 0.35, 1.0, 4.5, 0.0, 1.0, 1.0, 2.0],
            # Phishing 2: IP URL, financial lure, CTA
            [1.0, 0.0, 1.0, 0.0, 1.0, 0.6, 0.9, 0.5, 0.20, 1.0, 3.8, 1.0, 0.0, 1.0, 1.0],
            # Phishing 3: Display spoof, urgent credential reset
            [0.0, 0.0, 1.0, 1.0, 1.0, 0.9, 0.4, 0.8, 0.25, 1.0, 4.2, 0.0, 1.0, 1.0, 1.0],
            # Phishing 4: Raw IP URL + urgency + financial
            [1.0, 1.0, 1.0, 0.0, 0.0, 0.7, 0.8, 0.6, 0.18, 1.0, 3.6, 1.0, 0.0, 0.0, 1.0],
        ]

        x_train = np.array(x_benign + x_phish, dtype=float)
        y = np.array([0, 0, 0, 0, 1, 1, 1, 1], dtype=int)

        self.scaler.fit(x_train)
        x_scaled = self.scaler.transform(x_train)
        self.model.fit(x_scaled, y)

    def predict_probability(self, features: FeatureVector) -> float:
        """Compute calibrated probability (0.0 to 1.0) that target is phishing."""
        x = np.array([features.to_array()], dtype=float)
        x_scaled = self.scaler.transform(x)
        # Class 1 is phishing
        prob: float = float(self.model.predict_proba(x_scaled)[0][1])
        return round(prob, 3)

    def classify(self, features: FeatureVector) -> tuple[Verdict, RiskLevel, float, float]:
        """Classify feature vector into Verdict, RiskLevel, probability, and confidence."""
        prob = self.predict_probability(features)

        # Forensic threat boost: severe indicators guarantee minimum risk floors
        indicators = self.explain(features)
        total_indicator_weight = sum(ind.weight for ind in indicators)
        adjusted_prob = min(1.0, max(prob, min(0.95, total_indicator_weight)))

        # Confidence is distance from decision boundary (0.50)
        confidence = round(float(abs(adjusted_prob - 0.50) * 2.0), 3)

        if adjusted_prob >= self.settings.phishing_threshold:
            verdict = Verdict.PHISHING
            risk_level = RiskLevel.CRITICAL if adjusted_prob >= 0.80 else RiskLevel.HIGH
        elif adjusted_prob >= self.settings.suspicious_threshold:
            verdict = Verdict.SUSPICIOUS
            risk_level = RiskLevel.MEDIUM
        else:
            verdict = Verdict.CLEAN
            risk_level = RiskLevel.LOW

        return verdict, risk_level, round(adjusted_prob, 3), confidence

    def explain(self, features: FeatureVector) -> list[ThreatIndicator]:
        """Generate human-readable, SHAP-inspired explainability indicators."""
        indicators: list[ThreatIndicator] = []
        vec_dict = features.model_dump()

        # Check critical threat contributors
        if vec_dict.get("display_name_spoof", 0) > 0:
            indicators.append(
                ThreatIndicator(
                    indicator_name="DISPLAY_NAME_SPOOF",
                    category="Header",
                    description="Sender header displays brand impersonation pattern",
                    weight=0.35,
                    mitre_technique="T1566.001",
                )
            )

        if vec_dict.get("spf_fail", 0) > 0 or vec_dict.get("dmarc_fail", 0) > 0:
            indicators.append(
                ThreatIndicator(
                    indicator_name="AUTH_CHECK_FAILED",
                    category="Header",
                    description="SPF or DMARC authentication checks failed",
                    weight=0.25,
                    mitre_technique="T1566.001",
                )
            )

        if vec_dict.get("has_ip_url", 0) > 0:
            indicators.append(
                ThreatIndicator(
                    indicator_name="RAW_IP_URL",
                    category="URL",
                    description="Embedded URL points to raw IP address instead of domain",
                    weight=0.40,
                    mitre_technique="T1566.002",
                )
            )

        if vec_dict.get("has_homoglyph_url", 0) > 0:
            indicators.append(
                ThreatIndicator(
                    indicator_name="HOMOGLYPH_DOMAIN",
                    category="URL",
                    description="Domain contains deceptive character substitution or typosquatting",
                    weight=0.40,
                    mitre_technique="T1566.002",
                )
            )

        if vec_dict.get("has_suspicious_tld", 0) > 0:
            indicators.append(
                ThreatIndicator(
                    indicator_name="SUSPICIOUS_TLD",
                    category="URL",
                    description="Target domain resides on high-risk TLD frequently used in malware",
                    weight=0.20,
                    mitre_technique="T1566.002",
                )
            )

        if vec_dict.get("urgency_score", 0) >= 0.5:
            indicators.append(
                ThreatIndicator(
                    indicator_name="PSYCHOLOGICAL_URGENCY",
                    category="NLP",
                    description="Body exhibits high density of urgent action pressure cues",
                    weight=0.25,
                    mitre_technique="T1566.001",
                )
            )

        if vec_dict.get("financial_lure_score", 0) >= 0.5:
            indicators.append(
                ThreatIndicator(
                    indicator_name="FINANCIAL_LURE",
                    category="NLP",
                    description="Body contains wire transfer, invoice, or banking credential cues",
                    weight=0.25,
                    mitre_technique="T1566.001",
                )
            )

        return indicators
