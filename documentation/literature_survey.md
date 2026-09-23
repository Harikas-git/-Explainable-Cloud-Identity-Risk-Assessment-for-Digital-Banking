# Literature Survey: Explainable AI & Cloud Identity Risk Assessment

**Project:** Explainable Cloud Identity Risk Assessment for Digital Banking  
**Authors:** Harika, Ashmit, Priyanshu | 3rd Year CSE, VIT Vellore  

---

## 1. Towards Explainable Access Control [BlueSky Paper]
* **Authors:** G. Hasel Mehri, C. Morisset, N. Zannone
* **Publication:** ACM Symposium on Access Control Models and Technologies (**SACMAT '25**), pp. 117–126, 2025.
* **DOI:** `10.1145/3734436.3734439` *(Best Paper Award)*
* **Critical Analysis:**
  Access control systems are foundational to cybersecurity because they govern how sensitive resources are reached, keep confidential data protected, and preserve system integrity across varied policies and stakeholders (owners, administrators, end-users). Drawing on concepts from explainable AI (XAI) and explainable security, this paper introduces what is presented as the first formal model of access-control explainability. Explainability is conceptualized as a measurable property of an **Explanation Graph** $\mathcal{G} = (\mathcal{V}, \mathcal{E})$ constructed around access authorization events. This theoretical framework provides a rigorous foundation to reason about *why* a decision was reached rather than simply *what* the outcome was.
* **Limitations in Existing Literature:** The paper is predominantly theoretical and stops short of operationalizing the explanation graph for streaming, continuous risk scores in live cloud identity gateways.

---

## 2. A Survey on Explainable Artificial Intelligence for Cybersecurity
* **Authors:** G. Rjoub, O. A. Wahab, C. Bentaleb, A. Nour, E. B. Karoui
* **Publication:** **IEEE Transactions on Network and Service Management**, vol. 20, no. 2, 2023. arXiv: `2303.12942`.
* **Critical Analysis:**
  Rjoub et al. systematically classify cybersecurity threat vectors and evaluate the role of Explainable AI (XAI) in producing interpretable security models for high-stakes operational environments. They review feature-attribution frameworks, specifically **SHAP** (Shapley Additive exPlanations) and **LIME** (Local Interpretable Model-agnostic Explanations), assessing their utility in intrusion detection, network anomaly detection, and authentication telemetry.
* **Limitations in Existing Literature:** While SHAP and LIME identify numerical feature weights (e.g., packet rate, port deviation), they are not structurally aligned with multi-stakeholder authorization semantics (e.g., banking role hierarchies, compliance overrides, and counterfactual remediation paths).

---

## 3. AI-Driven Identity and Access Management: Opportunities, Challenges, and Future Directions
* **Authors:** F. Jimmy
* **Publication:** **Journal of Artificial Intelligence General Science (JAIGS)**, vol. 8(02), pp. 224–244, 2025.
* **Critical Analysis:**
  Jimmy investigates how artificial intelligence is transforming modern IAM by replacing brittle, static access matrices with continuous behavioral analytics, adaptive multi-factor authentication, and machine learning risk scoring. The paper highlights significant security benefits, including proactive credential stuffing mitigation and session anomaly detection. However, Jimmy identifies major industry roadblocks: the "black-box" dilemma in SOC triage, risk of algorithmic bias against remote workers, and integration latency in enterprise identity providers.
* **Relevance to Project:** Establishes the necessity for human-in-the-loop, explainable risk scoring in high-throughput cloud environments.

---

## 4. Opportunities and Challenges of AI Applied to IAM in Industrial Environments
* **Authors:** J. Vegas, C. Llamas
* **Publication:** **MDPI Future Internet**, vol. 16, no. 12, art. 469, 2024. DOI: `10.3390/fi16120469`.
* **Critical Analysis:**
  Vegas and Llamas examine the application of AI and biometric multi-factor authentication in industrial and enterprise critical infrastructure. They emphasize that while AI enhances robustness against impersonation attacks, mission-critical environments cannot tolerate unexplainable automated lockouts that halt operations. They identify emerging research directions, including edge computing for low latency, federated learning for privacy preservation, and explainable AI for regulatory compliance.
* **Relevance to Project:** Provides the operational foundation for banking zero-trust systems where decision latency, auditability, and safety overrides are mandatory.
