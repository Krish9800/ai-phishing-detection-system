# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-11

### Added
- **Core Architecture & Schemas**: Domain enums (`Verdict`, `RiskLevel`, `AuthStatus`), forensic feature models, and numeric feature vector contracts.
- **RFC 5322 Email Header Forensics**: Header parsing, SPF/DKIM/DMARC status evaluation, return-path discrepancy checks, and brand display-name spoof detection.
- **Linguistic & Semantic NLP Feature Extractor**: Psychological urgency cue density, threat/intimidation indicators, financial lure detection, and call-to-action scoring.
- **Lexical & Structural URL Forensics**: Shannon entropy calculation, Punycode/IDN detection, homoglyph attack heuristics, IP host detection, and risky TLD matching.
- **ML Ensemble & Explainability Engine**: Calibrated Logistic Regression classifier combined with SHAP-inspired threat indicator attribution and MITRE ATT&CK mapping.
- **SQLite WAL Persistence**: Transactional scan ledger with indexing on timestamps, verdicts, and target categories.
- **FastAPI Control Plane**: Endpoints for email scanning (`/analyze/email`), URL scanning (`/analyze/url`), scan history (`/scans`), and health checks (`/health`).
- **Typer CLI Administration Tool**: Command-line interface with `scan-email`, `scan-url`, and `scans` reporting commands.
- **Security Hardening**: Multi-stage rootless Dockerfile (UID 10001), STRIDE threat model, and adversarial testbed.
