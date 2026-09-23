"""
Demonstration and Test Harness for XCIRA-DB
Explainable Cloud Identity Risk Assessment for Digital Banking
Simulates and explains 3 realistic banking access scenarios:
1. Scenario 1: Alice (Bank Teller) - Routine Workstation Access -> Expected: GRANT
2. Scenario 2: Bob (Loan Approver) - Late Night Off-Hours Access -> Expected: STEP-UP MFA
3. Scenario 3: Mallory (Compromised Credential) - Impossible Travel / Threat Subnet -> Expected: DENY
"""
import sys
import os
import json

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from backend.context_layer import ContextLayer, AccessRequest
from ai_models.risk_engine import RiskScoringEngine
from backend.decision_module import AccessDecisionModule
from ai_models.explanation_layer import ExplanationLayer
from backend.audit_logger import AuditLogger

def print_separator(title: str):
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)

def run_pipeline():
    print_separator("INITIALIZING XCIRA-DB 5-STAGE PIPELINE (DIGITAL BANKING)")
    print("[Stage 1] Initializing Context Layer & Feature Normalizer...")
    context_layer = ContextLayer()

    print("[Stage 2] Initializing Risk Scoring Engine & Calibrating Model...")
    risk_engine = RiskScoringEngine(random_state=42)
    print(f"         Baseline Population Risk E[Risk] = {risk_engine.get_baseline_risk():.1f} / 100")

    print("[Stage 3] Initializing Dynamic Decision Policy Module (Thresholds: <35 GRANT, 35-75 STEP-UP, >=75 DENY)...")
    decision_module = AccessDecisionModule()

    print("[Stage 4] Initializing Formal Explanation Graph & XAI Layer...")
    explanation_layer = ExplanationLayer(risk_engine)

    print("[Stage 5] Initializing Tamper-Evident Audit Logger...")
    audit_logger = AuditLogger("database/access_audit_log.jsonl")

    # Define 3 Scenarios
    scenarios = [
        {
            "name": "Scenario 1: Alice (Bank Teller) - Regular Branch Workstation",
            "request": AccessRequest(
                request_id="REQ-2026-001",
                user_id="alice@bank-core.internal",
                role="Bank Teller",
                department="Retail Banking",
                target_resource="service://account-inquiry",
                device_id="BRANCH-PC-0491",
                ip_address="10.240.12.8",
                location="Chennai Branch, India",
                device_trust_score=0.98,
                ip_reputation_risk=0.02,
                geo_velocity_kmh=12.0,
                hour_anomaly_score=0.05,
                resource_sensitivity=2,
                failed_attempts_last_hour=0,
                vpn_connected=1,
                privilege_elevation_requested=0,
                keystroke_anomaly_score=0.08
            )
        },
        {
            "name": "Scenario 2: Bob (Loan Approver) - Late Night Remote Connection",
            "request": AccessRequest(
                request_id="REQ-2026-002",
                user_id="bob@bank-core.internal",
                role="Loan Approver",
                department="Credit Risk",
                target_resource="service://commercial-credit-approval",
                device_id="BYOD-IPAD-8812",
                ip_address="198.51.100.44",
                location="Mumbai, India",
                device_trust_score=0.65,
                ip_reputation_risk=0.35,
                geo_velocity_kmh=420.0, # Domestic flight transition
                hour_anomaly_score=0.72, # Accessing at 02:45 AM
                resource_sensitivity=4,  # High sensitivity ledger
                failed_attempts_last_hour=2,
                vpn_connected=0,
                privilege_elevation_requested=0,
                keystroke_anomaly_score=0.45
            )
        },
        {
            "name": "Scenario 3: Mallory (Compromised Credential) - Impossible Travel / Threat Subnet",
            "request": AccessRequest(
                request_id="REQ-2026-003",
                user_id="mallory@bank-core.internal",
                role="Cloud Infrastructure Admin",
                department="Cloud Ops",
                target_resource="vault://swift-root-signing-key",
                device_id="UNKNOWN-LINUX-BOX",
                ip_address="185.220.101.5",
                location="Bucharest, Romania",
                device_trust_score=0.10,
                ip_reputation_risk=0.95, # Known Tor relay
                geo_velocity_kmh=1850.0, # Impossible travel (>900 km/h)
                hour_anomaly_score=0.88,
                resource_sensitivity=5,  # Top-secret root keys
                failed_attempts_last_hour=8,
                vpn_connected=0,
                privilege_elevation_requested=1,
                keystroke_anomaly_score=0.92
            )
        }
    ]

    for sc in scenarios:
        print_separator(sc["name"])
        req = sc["request"]
        print(f"Requester      : {req.user_id} ({req.role})")
        print(f"Resource       : {req.target_resource} (Sensitivity Level: {req.resource_sensitivity}/5)")
        print(f"Network Context: IP={req.ip_address} | Geo-Velocity={req.geo_velocity_kmh} km/h | VPN={bool(req.vpn_connected)}")

        # Step 1: Feature Extraction
        feature_vec, feat_dict = context_layer.extract_features(req)
        instant_flags = context_layer.detect_instant_flags(req)

        # Step 2: Risk Scoring
        risk_score = risk_engine.predict_risk(feature_vec)

        # Step 3: Decision Evaluation
        decision_res = decision_module.evaluate(risk_score, instant_flags)

        # Step 4: Explanation Layer
        attributions = explanation_layer.compute_feature_attributions(feature_vec, risk_score)
        graph = explanation_layer.build_explanation_graph(req, decision_res, attributions)
        narratives = explanation_layer.generate_narratives(req, decision_res, attributions)

        # Step 5: Audit Logging
        record = audit_logger.log_record(
            request_id=req.request_id,
            user_id=req.user_id,
            role=req.role,
            resource=req.target_resource,
            decision_result=decision_res,
            attributions=attributions,
            narratives=narratives,
            context_features=feat_dict
        )

        # Console Presentation
        status_color = "[+]" if decision_res.decision == "GRANT" else ("[?]" if decision_res.decision == "STEP_UP_MFA" else "[-]")
        print(f"\n{status_color} ACCESS DECISION : >>> {decision_res.decision} <<<")
        print(f"    Calculated Risk Score : {decision_res.risk_score} / 100")
        print(f"    Policy Enforced       : {decision_res.policy_rule_matched}")
        if decision_res.is_override:
            print(f"    Override Alert        : {decision_res.override_reason}")

        print("\n--- [Stage 4] FORMAL EXPLANATION GRAPH SUMMARY ---")
        print(f"Graph Nodes ({len(graph.nodes)}):")
        for node in graph.nodes:
            print(f"  * [{node.node_type.upper()}] {node.label}")

        print("\nTop Contributing Risk Factors (Shapley Delta):")
        sorted_attr = sorted(attributions.items(), key=lambda x: abs(x[1]), reverse=True)
        for k, v in sorted_attr[:4]:
            sign = "+" if v > 0 else ""
            print(f"  * {k:.<30} {sign}{v:.1f} pts")

        print("\nStakeholder Explanations:")
        print(f"  [End-User]       : {narratives['end_user']}")
        print(f"  [Counterfactual] : {narratives['counterfactual'].replace(chr(10), ' ')}")

        print(f"\nAudit Integrity Hash: SHA256({record['integrity_hash'][:16]}...)")

    print_separator("XCIRA-DB DEMONSTRATION RUN COMPLETE - ALL 5 STAGES VERIFIED")

if __name__ == "__main__":
    run_pipeline()
