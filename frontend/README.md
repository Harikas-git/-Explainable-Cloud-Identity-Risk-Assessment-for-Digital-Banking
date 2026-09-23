# Frontend Subsystem: Zero-Trust Interactive Simulation Console

## Purpose
The `frontend/` directory contains the user interface and presentation components for the **Explainable Cloud Identity Risk Assessment** system. It provides an intuitive interface for security operators, system evaluators, and academic reviewers to simulate access requests in real time and visually explore the resulting decisions and explanations.

## Key Components
- **`app.py`**: A standalone zero-dependency Python HTTP server and Single Page Application (SPA).
- **Interactive Contextual Sliders**: Allows fine-grained manipulation of 9 continuous and categorical signals (device trust, IP reputation, geo-velocity, off-hours anomaly, failed login attempts, VPN status, privilege elevation, and keystroke dynamics).
- **Dynamic Decision Display**: Real-time animated risk gauge ($0 \text{ to } 100$) and status badges (`GRANT` in green, `STEP-UP MFA` in amber, `DENY` in red).
- **Mermaid.js Explanation Graph Visualizer**: Direct client-side rendering of the formal Directed Acyclic Graph (DAG) specified by Hasel Mehri et al. (*SACMAT '25*).
- **SHAP Attribution Breakdown**: Visual horizontal bars illustrating exact positive and negative contributions toward the risk score.
- **Role-Tailored Narrative Tabs**: Switchable perspectives for **End-Users** (plain English), **SOC Analysts** (technical metrics), and **Remediation Plans** (counterfactual steps).

## How to Run
```bash
python frontend/app.py
```
Open `http://localhost:8000` in your web browser.
