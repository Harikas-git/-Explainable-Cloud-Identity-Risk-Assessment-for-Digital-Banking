"""
Unit and Integration Tests for XRAC-AI System
Verifies:
1. Context Layer feature extraction and instant flag detection
2. Risk Scoring Engine range and sensitivity bounds
3. Decision Module threshold transitions (Grant, Step-up, Deny) and policy overrides
4. Explanation Layer DAG node count, soundness (local efficiency), and narrative generation
5. Audit Logger tamper-evident SHA-256 hash generation
"""
import unittest
import numpy as np
import config
from src.context_layer import ContextLayer, AccessRequest
from src.risk_engine import RiskScoringEngine
from src.decision_module import AccessDecisionModule, DecisionOutcome
from src.explanation_layer import ExplanationLayer
from src.audit_logger import AuditLogger

class TestXRACSystem(unittest.TestCase):

    def setUp(self):
        self.context_layer = ContextLayer()
        self.risk_engine = RiskScoringEngine(random_state=42)
        self.decision_module = AccessDecisionModule()
        self.explanation_layer = ExplanationLayer(self.risk_engine)
        self.audit_logger = AuditLogger("test_audit_log.jsonl")

    def test_context_layer_extraction(self):
        req = AccessRequest(
            request_id="T-01",
            user_id="test@corp.internal",
            role="DevOps Admin",
            department="IT",
            target_resource="db://users",
            device_id="DEV-01",
            ip_address="10.0.0.1",
            location="Internal",
            device_trust_score=0.90,
            geo_velocity_kmh=1200.0 # triggers impossible travel
        )
        vec, feat_dict = self.context_layer.extract_features(req)
        self.assertEqual(len(vec), len(config.FEATURE_NAMES))
        self.assertEqual(feat_dict["device_trust_score"], 0.90)

        flags = self.context_layer.detect_instant_flags(req)
        self.assertTrue(flags["impossible_travel"])

    def test_risk_scoring_bounds(self):
        # Benign feature vector
        benign_vec = np.array([0.99, 0.01, 10.0, 0.05, 1.0, 0.0, 1.0, 0.0, 0.05], dtype=np.float32)
        score_low = self.risk_engine.predict_risk(benign_vec)
        self.assertGreaterEqual(score_low, 0.0)
        self.assertLess(score_low, 35.0)

        # High-risk vector
        hostile_vec = np.array([0.10, 0.95, 1200.0, 0.90, 5.0, 8.0, 0.0, 1.0, 0.90], dtype=np.float32)
        score_high = self.risk_engine.predict_risk(hostile_vec)
        self.assertGreaterEqual(score_high, 75.0)
        self.assertLessEqual(score_high, 100.0)

    def test_decision_thresholds_and_overrides(self):
        # Test low risk -> GRANT
        res_grant = self.decision_module.evaluate(20.0, {})
        self.assertEqual(res_grant.decision, DecisionOutcome.GRANT)

        # Test medium risk -> STEP_UP_MFA
        res_stepup = self.decision_module.evaluate(50.0, {})
        self.assertEqual(res_stepup.decision, DecisionOutcome.STEP_UP_MFA)

        # Test high risk -> DENY
        res_deny = self.decision_module.evaluate(85.0, {})
        self.assertEqual(res_deny.decision, DecisionOutcome.DENY)

        # Test override on impossible travel
        res_override = self.decision_module.evaluate(20.0, {"impossible_travel": True})
        self.assertEqual(res_override.decision, DecisionOutcome.DENY)
        self.assertTrue(res_override.is_override)

    def test_explanation_graph_soundness(self):
        req = AccessRequest(
            request_id="T-02",
            user_id="test2@corp.internal",
            role="Financial Officer",
            department="Finance",
            target_resource="db://accounts",
            device_id="DEV-02",
            ip_address="192.168.1.1",
            location="Remote",
            hour_anomaly_score=0.70
        )
        vec, feat_dict = self.context_layer.extract_features(req)
        flags = self.context_layer.detect_instant_flags(req)
        risk = self.risk_engine.predict_risk(vec)
        dec = self.decision_module.evaluate(risk, flags)
        
        attributions = self.explanation_layer.compute_feature_attributions(vec, risk)
        graph = self.explanation_layer.build_explanation_graph(req, dec, attributions)

        # Verify DAG structure
        self.assertGreaterEqual(len(graph.nodes), 4)
        self.assertGreaterEqual(len(graph.edges), 3)
        self.assertEqual(graph.soundness_score, 100.0)
        self.assertIn("graph LR", graph.mermaid_diagram)

    def test_audit_cryptographic_integrity(self):
        dec_res = self.decision_module.evaluate(25.0, {})
        record = self.audit_logger.log_record(
            request_id="T-AUDIT-01",
            user_id="audit_user",
            role="Auditor",
            resource="test_res",
            decision_result=dec_res,
            attributions={"vpn_connected": -10.0},
            narratives={"end_user": "OK", "counterfactual": "None"},
            context_features={"vpn_connected": 1}
        )
        self.assertIn("integrity_hash", record)
        self.assertEqual(len(record["integrity_hash"]), 64) # SHA-256 hex digest length

if __name__ == "__main__":
    unittest.main()
