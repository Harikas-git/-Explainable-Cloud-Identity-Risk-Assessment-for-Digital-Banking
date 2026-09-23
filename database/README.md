# Database & Audit Trail Subsystem

## Purpose
The `database/` directory manages data persistence for access requests, contextual feature vectors, authorization decisions, and tamper-evident compliance audit records in **Explainable Cloud Identity Risk Assessment for Digital Banking**.

## Storage Architecture
1. **Relational Data Model (`schema.sql`):**
   - Tables for `users`, `devices`, `sessions`, `access_policies`, and `audit_records`.
   - Designed for high-throughput relational databases (PostgreSQL / SQLite) supporting banking compliance indices.
2. **Tamper-Evident Immutable Audit Log (`access_audit_log.jsonl`):**
   - Append-only JSON Lines format.
   - Each entry contains a cryptographic **SHA-256 integrity hash** computed over the concatenated request payload, feature attributions, policy decision, and timestamp.
   - Conforms to **GDPR Article 22** (Right to Explanation) and **ISO/IEC 27001** (Non-repudiation and audit logging).

## Compliance & Privacy Guardrails
- Personally Identifiable Information (PII) is pseudonymized using salted user identifiers.
- Contextual biometric signals (keystroke dynamics) are stored strictly as normalized anomaly indices ($0.0 \text{ to } 1.0$) rather than raw keystroke logs, preserving privacy.
