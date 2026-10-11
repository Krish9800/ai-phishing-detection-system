# STRIDE Threat Model: AI Phishing Detection System

## 1. System Overview
The AI Phishing Detection System performs multi-modal forensic inspection of incoming emails and URLs to identify spear-phishing, credential harvesting, brand impersonation, and fast-flux malicious infrastructure.

```
+-----------------------------------------------------------------------------------------+
|                                    Inbound Pipeline                                     |
|                                                                                         |
|       [ Inbound .eml / URL ] ───► [ RFC 5322 Forensics (SPF/DKIM/DMARC) ]               |
|                                   [ Body NLP Psychological Profiler ]                   |
|                                   [ URL Lexical & Homoglyph Analyzer ]                  |
|                                                     │                                   |
|                                                     ▼                                   |
|                                      [ Feature Vector Construction ]                    |
|                                                     │                                   |
|                                                     ▼                                   |
|                                      [ Calibrated ML Classifier ]                       |
|                                                     │                                   |
|                                                     ▼                                   |
|                                      [ Explainability & Attribution ]                   |
|                                                     │                                   |
|                                                     ▼                                   |
|                                      [ SQLite WAL Scan Store ]                          |
|                                                     │                                   |
|                      +------------------------------+-------------------------------+   |
|                      │                                                              │   |
|                      ▼                                                              ▼   |
|             [ FastAPI REST API ]                                           [ Typer CLI Tool ]   |
|             (Port 8000, JSON)                                              (Analyst Triage)     |
+-----------------------------------------------------------------------------------------+
```

---

## 2. STRIDE Threat Analysis Matrix

| Threat Category | Potential Attack Vector | Impact | Mitigation Mechanism |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker spoofs trusted internal domains or CEO display name to conduct BEC (Business Email Compromise). | Critical | Header parser cross-verifies display names against Return-Path and SPF/DKIM/DMARC alignment. |
| **Tampering** | Adversary injects adversarial text perturbations into email body to bypass ML model. | High | Multi-layered defense combines statistical ML with deterministic rule-based threat overrides. |
| **Repudiation** | Attacker claims flagged email was an erroneous false positive. | Medium | Full explainability report documents exact feature attributions, weights, and forensic evidence. |
| **Information Disclosure** | Unauthorized actors query REST endpoints to view sensitive email subjects or contents. | High | Docker container drops all capabilities (`cap_drop: ALL`); API binds to localhost; minimal retention. |
| **Denial of Service** | Malformed MIME attachments or catastrophic regex backtracking (ReDoS) crashes scanner. | High | Regex patterns use bounded linear-time expressions without nested unbounded repetitions. |
| **Elevation of Privilege** | Vulnerability in NLP tokenizer or SQLite exploited to compromise host. | Critical | Rootless execution as UID 10001, `no-new-privileges: true`, and parameterized SQL statements. |

---

## 3. Defense-in-Depth Implementation
- **Parameterized Persistence:** All scan metrics, headers, and NLP indicators are persisted using parameterized SQLite statements (`?` placeholders).
- **Hardened Containerization:** Read-only root filesystem with isolated ephemeral tmpfs.
- **Fail-Safe Classification:** Deterministic risk boosts ensure critical cues (e.g. raw IP host URLs or homoglyph domains) are not suppressed by ML probability smoothing.
