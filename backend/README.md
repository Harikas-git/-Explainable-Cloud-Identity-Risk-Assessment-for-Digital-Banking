# Backend Subsystem: Adaptive Zero-Trust Authorization Pipeline

## Purpose
The `backend/` directory houses the core business logic, context extraction engine, dynamic policy decision thresholds, and regulatory audit logger for **Explainable Cloud Identity Risk Assessment in Digital Banking**.

## Submodules & Architecture
- **`context_layer.py` (Stage 1):** Ingests incoming subject requests, device telemetry, and environmental signals. Performs vector normalization and runs deterministic red-flag heuristics (impossible travel velocity $>900\text{ km/h}$, Tor IP detection, brute-force counters).
- **`decision_module.py` (Stage 3):** Implements multi-tier dynamic access policy evaluation:
  - $R < 35.0$: `GRANT` (Frictionless access to banking services)
  - $35.0 \le R < 75.0$: `STEP_UP_MFA` (Triggers hardware key or biometric challenge)
  - $R \ge 75.0$: `DENY` (Immediate session termination and SOC security event)
  - Enforces deterministic policy overrides that supersede probabilistic scoring.
- **`audit_logger.py` (Stage 5):** Produces tamper-evident, cryptographically sealed (SHA-256) audit trails compliant with **GDPR Article 22** and **ISO/IEC 27001**.
- **`config.py`**: Global system parameters, threshold constants ($\theta_{\text{low}}, \theta_{\text{high}}$), and banking role definitions.

## Key APIs & Extension Points
The backend is designed for direct integration with enterprise Identity Providers (IdPs) like Okta, AWS IAM Identity Center, Keycloak, or Microsoft Entra ID via SAML 2.0 or OIDC session hooks.
