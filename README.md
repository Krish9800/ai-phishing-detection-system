# AI Phishing Detection System

[![Phish AI Continuous Integration](https://github.com/krish/ai-phishing-detection-system/actions/workflows/ci.yml/badge.svg)](https://github.com/krish/ai-phishing-detection-system/actions/workflows/ci.yml)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![Coverage](https://img.shields.io/badge/coverage-96%25-brightgreen.svg)]()
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked: mypy](https://img.shields.io/badge/type%20checked-mypy%20strict-blue.svg)](https://mypy-lang.org/)

Multi-modal AI-assisted phishing detection system combining RFC 5322 email header forensics, body NLP psychological cues, lexical URL intelligence, and explainable machine learning ensemble classification.

---

## Key Capabilities

1. **RFC 5322 Header & Authentication Forensics**:
   - Parses `Authentication-Results` for SPF, DKIM, and DMARC alignment (`PASS`, `FAIL`, `NONE`, `SOFTFAIL`).
   - Identifies display-name brand impersonation (`PayPal Support <attacker@evil.com>`).
   - Flags sender domain and `Return-Path` bounce envelope discrepancies.
   - Traces origin client IP addresses from `Received` hop chains.

2. **Semantic & Psychological NLP Body Profiling**:
   - Scores urgency cue density (`act now`, `immediately`, `within 24 hours`).
   - Detects financial lures (`wire transfer`, `overdue invoice`, `gift card`).
   - Flags threat intimidation patterns (`legal action`, `arrest`, `permanent deletion`).
   - Identifies deceptive calls-to-action (`verify your account`, `confirm identity`).

3. **URL Lexical & Reputation Forensics**:
   - Computes Shannon entropy on host and path strings to detect algorithmic randomness.
   - Detects raw IP hosts, suspicious TLDs (`.zip`, `.top`, `.xyz`), and Punycode (`xn--`).
   - Heuristically flags homoglyph substitutions and deceptive typosquatting.

4. **Calibrated ML Classifier & Explainability**:
   - Scikit-learn Logistic Regression ensemble yielding calibrated probability scores (0.00–1.00).
   - Generates transparent, human-readable threat indicator attribution breakdowns.
   - Maps each finding to MITRE ATT&CK techniques (T1566.001 / T1566.002).

5. **Persistence & SOC Integration**:
   - SQLite Write-Ahead Logging (WAL) store for high-throughput scan recording.
   - FastAPI REST API for enterprise mail gateway integration.
   - Rich Typer CLI analyst tool (`phish-ai`).

---

## Quickstart

### 1. Installation
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. CLI Usage
```bash
# Analyze a raw .eml email file
phish-ai scan-email suspicious_email.eml

# Analyze a target URL
phish-ai scan-url "https://paypa1-update.xyz/login"

# List past scan assessments
phish-ai scans --limit 10
```

### 3. Start REST API
```bash
uvicorn phish_ai.api.app:create_app --factory --host 127.0.0.1 --port 8000
```

---

## Security & Verification
- **Rootless Container:** Multi-stage Dockerfile drops all capabilities and runs as UID 10001.
- **STRIDE Threat Model:** Documented in [`docs/threat_model.md`](docs/threat_model.md).
- **Quality Gates:** 100% strict Mypy types, 0 Bandit security issues, >=90% test coverage.

---

## License
MIT License - see `LICENSE` for details.
