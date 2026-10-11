-- Schema definition for AI Phishing Detection System
-- Runs in SQLite WAL (Write-Ahead Logging) mode

CREATE TABLE IF NOT EXISTS scan_results (
    scan_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_identifier TEXT NOT NULL,
    verdict TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    phishing_probability REAL NOT NULL,
    confidence_score REAL NOT NULL,
    header_features_json TEXT,
    nlp_features_json TEXT,
    url_records_json TEXT,
    threat_indicators_json TEXT,
    metadata_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_results(timestamp);
CREATE INDEX IF NOT EXISTS idx_scan_verdict ON scan_results(verdict);
CREATE INDEX IF NOT EXISTS idx_scan_target_type ON scan_results(target_type);
