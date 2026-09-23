# AI Models & Explainability Subsystem

## Purpose
The `ai_models/` directory encapsulates all machine learning algorithms, statistical feature attribution pipelines, and formal explanation graph generators for **Explainable Cloud Identity Risk Assessment in Digital Banking**.

## Submodules
- **`risk_engine.py` (Stage 2):**
  - Implements the continuous risk scoring engine.
  - Trains an ensemble of **Gradient Boosted Decision Trees (GBDT)** and **Random Forest Regressors** on historical banking access baselines.
  - Evaluates continuous risk score $R \in [0, 100]$.
  - Provides mathematical expected baseline $\mathbb{E}[R]$ for population risk drift.
- **`explanation_layer.py` (Stage 4):**
  - Computes post-hoc Shapley feature attributions $\phi_i$ (SHAP / LIME inspired).
  - Formalizes the **Explanation Graph** $\mathcal{G} = (\mathcal{V}, \mathcal{E})$ operationalizing Hasel Mehri et al. (*SACMAT '25*).
  - Guarantees local efficiency / explanation soundness:
    $$\sum_{i=1}^{M} \phi_i = \text{Risk}(x) - \mathbb{E}[\text{Risk}]$$
  - Generates multi-stakeholder natural language rationales (End-User, SOC Security Analyst, Counterfactual Remediation).
- **`synthetic_data.py`:**
  - Generates synthetic banking cloud telemetry across three operational distributions:
    1. *Routine Low-Risk* (Branch tellers, office workstations, managed VPN).
    2. *Moderate / Anomaly* (Remote managers, domestic travel, off-hours batch jobs).
    3. *Hostile Compromise* (Tor relays, impossible travel speed, brute-force credential stuffing).

## Mathematical Formulation
An explanation graph is defined as an annotated directed acyclic graph:
$$\mathcal{G} = (\mathcal{V}, \mathcal{E}, \lambda_{\mathcal{V}}, \lambda_{\mathcal{E}})$$
where vertices represent identity attributes, risk scoring nodes, policy thresholds, and terminal decisions; edges encode causal attribution weights corresponding to computed Shapley values.
