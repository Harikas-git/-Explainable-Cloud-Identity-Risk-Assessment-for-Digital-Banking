# Research Gap & Problem Formulation

**Project:** Explainable Cloud Identity Risk Assessment for Digital Banking  
**Authors:** Harika, Ashmit, Priyanshu | 3rd Year CSE, VIT Vellore  

---

## 🔍 Critical Synthesis of Current Literature

Synthesizing contemporary research across AI-driven Identity and Access Management (Jimmy, 2025; Vegas & Llamas, 2024), Cybersecurity XAI (Rjoub et al., 2023), and formal access-control explainability (Hasel Mehri et al., 2025) highlights four distinct research gaps:

```
+--------------------------------------------------------------------------------------------------+
|                                    EXISTING LANDSCAPE                                            |
+---------------------------------+--------------------------------+-------------------------------+
| AI-Driven IAM Systems           | General Cybersecurity XAI      | Formal Access Explainability  |
| (Jimmy 2025, Vegas 2024)        | (Rjoub et al. 2023)            | (Hasel Mehri et al. 2025)     |
| - High accuracy risk scoring    | - SHAP / LIME threat classification | - Formal Explanation Graphs   |
| - Adaptive authentication       | - Explains feature weights only| - Mathematical metrics        |
| - Black-box opacity             | - Disconnected from IAM logic  | - Purely theoretical model    |
+---------------------------------+--------------------------------+-------------------------------+
                                                  |
                                                  v
+--------------------------------------------------------------------------------------------------+
|                                    IDENTIFIED RESEARCH GAP                                       |
|  No operationalized framework bridges AI risk scoring, SHAP/LIME feature attributions, and       |
|  formal explanation graphs into a cohesive, auditable, multi-stakeholder access decision engine. |
+--------------------------------------------------------------------------------------------------+
```

---

## ⚠️ The Four Deficiencies

### 1. Accuracy Optimization at the Expense of Interpretability
Current commercial and academic AI-IAM solutions (e.g., adaptive authentication gateways) optimize objective performance metrics (precision, recall, and ROC-AUC of anomalous logins). Explainability is either ignored or treated as an offline diagnostic tool rather than a core functional requirement of access enforcement.

### 2. Semantic Disconnect in Generic Cybersecurity XAI
Generic XAI frameworks (e.g., standard SHAP or LIME) produce raw numerical feature importance coefficients (e.g., `feature_17 = +0.42`). These values are meaningless to non-technical bank tellers and insufficient for compliance auditors who require policy-aligned justifications (e.g., *"Login attempted outside authorized branch hours from an untrusted external IP"*).

### 3. Lack of Operationalization of Formal Explanation Models
Hasel Mehri et al. (SACMAT '25) established a formal mathematical model for evaluating explanation graph quality. However, their contribution remains purely theoretical—they do not provide an applied system architecture or an operational algorithm that integrates live streaming cloud telemetry, continuous risk scoring, and dynamic policy thresholding.

### 4. Absence of Multi-Stakeholder Rationale Views
Existing identity systems do not differentiate explanations by audience persona:
- **End-Users** require simple, actionable, non-jargon explanations and concrete remediation paths (e.g., *"Connect to corporate VPN to reduce session risk"*).
- **SOC Analysts** require detailed Shapley value breakdowns, correlation matrices, and raw telemetry context.
- **Compliance Auditors** require cryptographically signed, immutable records demonstrating non-discriminatory, policy-sound decision making (GDPR Article 22, ISO/IEC 27001).

---

## 🎯 Proposed Solution & Scope

Our framework bridges this gap by operationalizing a 5-stage pipeline combining:
1. Continuous ML risk regression ($R \in [0, 100]$).
2. Local efficiency-calibrated Shapley attributions ($\sum \phi_i = \text{Risk} - \mathbb{E}[\text{Risk}]$).
3. The formal **Explanation Graph** $\mathcal{G} = (\mathcal{V}, \mathcal{E})$ from Hasel Mehri et al. (2025).
4. Multi-stakeholder narrative synthesis.
5. Tamper-evident SHA-256 compliance auditing.
