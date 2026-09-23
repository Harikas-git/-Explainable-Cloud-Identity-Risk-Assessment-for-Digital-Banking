-- Database Schema for Explainable Cloud Identity Risk Assessment in Digital Banking
-- Compliant with GDPR Article 22 & ISO/IEC 27001 Audit Standards

CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(64) PRIMARY KEY,
    full_name VARCHAR(128) NOT NULL,
    banking_role VARCHAR(64) NOT NULL,
    department VARCHAR(64) NOT NULL,
    clearance_level INT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS registered_devices (
    device_id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) REFERENCES users(user_id),
    os_name VARCHAR(64),
    os_version VARCHAR(32),
    hardware_fido2_enabled BOOLEAN DEFAULT FALSE,
    trust_score REAL DEFAULT 0.95,
    last_compliance_scan TIMESTAMP
);

CREATE TABLE IF NOT EXISTS access_policies (
    policy_id VARCHAR(32) PRIMARY KEY,
    policy_name VARCHAR(128) NOT NULL,
    threshold_low REAL NOT NULL,
    threshold_high REAL NOT NULL,
    requires_hardware_mfa BOOLEAN DEFAULT TRUE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS audit_logs (
    request_id VARCHAR(64) PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    banking_role VARCHAR(64) NOT NULL,
    target_resource VARCHAR(128) NOT NULL,
    risk_score REAL NOT NULL,
    decision VARCHAR(16) NOT NULL, -- 'GRANT', 'STEP_UP_MFA', 'DENY'
    policy_matched VARCHAR(128) NOT NULL,
    is_override BOOLEAN DEFAULT FALSE,
    integrity_hash CHAR(64) NOT NULL, -- SHA-256 Digest
    end_user_explanation TEXT,
    counterfactual_remediation TEXT,
    raw_feature_payload TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_logs(decision);
