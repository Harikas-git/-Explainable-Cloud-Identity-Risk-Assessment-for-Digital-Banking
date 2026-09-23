# Presentation Slide Deck Outline & Defense Preparation
**Project Title:** Explainable Cloud Identity Risk Assessment for Digital Banking  
**Course / Evaluation:** Academic Review 1 & 2 | B.Tech CSE (3rd Year), VIT Vellore  
**Presenters:** Harika, Ashmit, Priyanshu  

---

## 📽️ Slide Breakdown (12 Slides)

### Slide 1: Title & Team Introduction
* **Title:** Explainable Cloud Identity Risk Assessment for Digital Banking (XCIRA-DB)
* **Team Details:** Harika, Ashmit, Priyanshu | School of Computer Science & Engineering, VIT Vellore
* **Guide / Supervisor:** Faculty in Charge

### Slide 2: Industry Motivation & The Digital Banking Context
* Cloud banking infrastructures (AWS/Azure) face heightened credential-based identity attacks.
* Traditional static RBAC and binary 2FA are vulnerable to session hijacking and token theft.
* High stakes: SWIFT wire transfers, core banking customer databases, and automated fraud.

### Slide 3: Problem Statement & The "Black-Box" Dilemma
* Modern AI-IAM introduces opacity: automated risk scores deny access without human-interpretable reasoning.
* Consequences: Employee frustration, prolonged SOC investigation times, regulatory exposure (GDPR Article 22, PCI-DSS v4.0, RBI Cybersecurity Framework).

### Slide 4: Literature Survey (4 Foundational Papers)
* **Hasel Mehri et al. (SACMAT '25 - Best Paper):** Formal theoretical model of access-control explainability via Explanation Graphs $\mathcal{G} = (\mathcal{V}, \mathcal{E})$.
* **Rjoub et al. (IEEE TNSM 2023):** Survey of cybersecurity XAI (SHAP, LIME).
* **Jimmy (JAIGS 2025):** AI in enterprise IAM: opportunities and ethical transparency gaps.
* **Vegas & Llamas (MDPI Future Internet 2024):** Industrial IAM, biometric telemetry, and edge constraints.

### Slide 5: Identified Research Gap
* Gap between purely theoretical graph models (SACMAT '25) and applied real-time cloud risk scoring.
* Lack of multi-stakeholder explanation views (End-User vs. SOC Analyst vs. Compliance Auditor).

### Slide 6: Proposed 5-Stage System Architecture
* Stage 1: Identity & Context Layer (Feature normalization)
* Stage 2: Risk Scoring Engine (Ensemble GBDT / Random Forest)
* Stage 3: Access Decision Module ($\theta_{\text{low}}=35$, $\theta_{\text{high}}=75$, Overrides)
* Stage 4: Explanation Graph Layer (SHAP attribution + DAG generation)
* Stage 5: Audit & Compliance Console (SHA-256 tamper-evident logs)

### Slide 7: Mathematical Model & Explanation Soundness
* Risk score calibration: $\text{Risk}(x) \in [0, 100]$
* Formal Explanation Graph: $\mathcal{G} = (\mathcal{V}, \mathcal{E}, \lambda_{\mathcal{V}}, \lambda_{\mathcal{E}})$
* Local Soundness Proof: $\sum \phi_i = \text{Risk}(x) - \mathbb{E}[\text{Risk}]$ guaranteeing 100% of risk is accounted for without hallucination.

### Slide 8: Individual Work Distribution & Ownership
* **Harika:** Explanation Layer, DAG generation, SHAP integration, Literature Survey.
* **Ashmit:** ML Risk Scoring Engine, Synthetic Telemetry Generator, Feature Engineering.
* **Priyanshu:** Policy Engine, Dynamic Thresholding, Compliance Audit Logger, Web Console.

### Slide 9: Working Prototype & Live Demonstration
* Demonstration of the interactive web console (`frontend/app.py`).
* Real-time sliders, dynamic gauge, live Mermaid graph, and SHAP delta bars.

### Slide 10: Experimental Results & Benchmarks
* Evaluation across 3 realistic banking scenarios:
  * Scenario 1 (Routine Teller): Risk 16.3 $\rightarrow$ **GRANT**
  * Scenario 2 (Remote Approver): Risk 52.6 $\rightarrow$ **STEP_UP_MFA**
  * Scenario 3 (Impossible Travel Attack): Risk 88.3 $\rightarrow$ **DENY**
* Sub-15ms decision latency, 100% explanation soundness.

### Slide 11: Compliance & Regulatory Alignment
* **GDPR Article 22:** Right to automated decision explanation delivered via plain English & counterfactuals.
* **ISO/IEC 27001:** Cryptographic SHA-256 tamper-evident audit trails.

### Slide 12: Future Roadmap & Conclusion
* Roadmap: Integration with AWS CloudTrail live streaming, federated learning for multi-branch privacy.
* Summary of contributions.
* Q&A / Defense.

---

## 💡 Anticipated Viva Questions & Defense Notes

1. **Q: Why use SHAP instead of LIME for access control?**  
   *A:* SHAP guarantees *efficiency* (the sum of feature attributions equals the total difference between prediction and expected value), which is mathematically required for our Explanation Graph soundness proof. LIME does not guarantee efficiency.

2. **Q: How does the system handle real-time latency in banking?**  
   *A:* Tree-based SHAP (TreeExplainer) evaluates in low milliseconds ($<15\text{ ms}$). Deterministic overrides (like impossible travel $>900\text{ km/h}$) execute in sub-millisecond time without invoking ML inference.

3. **Q: How is user privacy protected in behavioral biometrics?**  
   *A:* Raw keystrokes or mouse coordinates are never logged or stored. Only normalized statistical anomaly coefficients ($0.0 \text{ to } 1.0$) are passed to the context layer.
