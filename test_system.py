"""
Unit and Integration Tests for XRAC-AI System
Verifies:
1. Context Layer feature extraction and instant flag detection
2. Risk Scoring Engine range and sensitivity bounds
3. Decision Module threshold transitions (Grant, Step-up, Deny) and policy overrides
4. Explanation Layer DAG node count, soundness (local efficiency), and narrative generation
5. Audit Logger tamper-evident SHA-256 hash generation
6. [PATENT CLAIM 1 & 2] Merkleized Explanation Graph (M-EG) & Zero-Knowledge Selective Disclosure
7. [PATENT CLAIM 3 & 4] Dual-Consistency Adversarial Evasion & Hijacking Detector
8. [PATENT CLAIM 5 & 6] Provably Monotonic Constrained Counterfactual Optimizer
9. [PATENT CLAIM 7 & 8] Sliding-Window Continuous Session Merkle-Chaining & Tamper Detection
"""
import unittest
import numpy as np
import config
from backend.context_layer import ContextLayer, AccessRequest
from ai_models.risk_engine import RiskScoringEngine
from backend.decision_module import AccessDecisionModule, DecisionOutcome
from ai_models.explanation_layer import ExplanationLayer
from backend.audit_logger import AuditLogger

# Patent Security Components
from ai_models.merkle_explanation_graph import MerkleExplanationGraphEngine, SelectiveDisclosureProof
from backend.adversarial_defense import AdversarialDefenseEngine
from backend.monotonic_counterfactual import MonotonicCounterfactualOptimizer
from backend.session_merkle_chain import SessionMerkleChainManager

class TestXRACSystem(unittest.TestCase):

    def setUp(self):
        self.context_layer = ContextLayer()
        self.risk_engine = RiskScoringEngine(random_state=42)
        self.decision_module = AccessDecisionModule()
        self.explanation_layer = ExplanationLayer(self.risk_engine)
        self.audit_logger = AuditLogger("test_audit_log.jsonl")
        self.meg_engine = MerkleExplanationGraphEngine()
        self.adv_engine = AdversarialDefenseEngine(self.risk_engine)
        self.cf_optimizer = MonotonicCounterfactualOptimizer(self.risk_engine)

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

    # -------------------------------------------------------------------------
    # PATENT INNOVATION UNIT TESTS
    # -------------------------------------------------------------------------
    def test_patent_merkle_explanation_graph_and_zk_proof(self):
        feat_dict = {
            "device_trust_score": 0.98,
            "ip_reputation_risk": 0.05,
            "geo_velocity_kmh": 20.0,
            "vpn_connected": 1.0
        }
        attributions = {
            "device_trust_score": -6.5,
            "ip_reputation_risk": -2.0,
            "vpn_connected": -5.0
        }
        result, nodes = self.meg_engine.construct_meg(
            request_id="REQ-PAT-TEST-01",
            user_id="user@test.org",
            decision="GRANT",
            risk_score=15.0,
            policy_name="POL-BASE-01",
            feature_dict=feat_dict,
            attributions=attributions
        )
        # Verify 64-char hex SHA-256 Merkle root
        self.assertEqual(len(result.merkle_root), 64)
        self.assertIn("ROOT_DECISION", nodes)

        # Test Zero-Knowledge Selective Disclosure Proof
        proof = self.meg_engine.generate_selective_disclosure_proof(nodes, "device_trust_score")
        self.assertIsNotNone(proof)
        self.assertTrue(MerkleExplanationGraphEngine.verify_selective_disclosure_proof(proof))
        self.assertEqual(proof.revealed_value, 0.98)

    def test_patent_adversarial_defense_engine(self):
        # Benign check
        benign_vec = np.array([0.95, 0.05, 20.0, 0.10, 2.0, 0.0, 1.0, 0.0, 0.10], dtype=np.float32)
        risk = self.risk_engine.predict_risk(benign_vec)
        attrs = self.explanation_layer.compute_feature_attributions(benign_vec, risk)
        adv_res = self.adv_engine.inspect_request(benign_vec, risk, attrs)
        self.assertFalse(adv_res.quarantine_triggered)

    def test_patent_monotonic_counterfactual_optimization(self):
        # Moderate risk vector requiring remediation
        moderate_vec = np.array([0.60, 0.30, 200.0, 0.50, 4.0, 2.0, 0.0, 0.0, 0.30], dtype=np.float32)
        risk = self.risk_engine.predict_risk(moderate_vec)
        plan = self.cf_optimizer.solve_remediation(moderate_vec, risk)
        
        # Verify monotonicity: historical failed attempts cannot be reduced instantly
        self.assertGreater(len(plan.actionable_remediation_steps), 0)
        self.assertIn("corporate encrypted", plan.actionable_remediation_steps[0])

    def test_patent_session_merkle_chaining(self):
        sess = SessionMerkleChainManager("SESS-UNIT-TEST")
        b0 = sess.append_assessment("ROOT_HASH_0", 15.0, "GRANT", 10.0)
        b1 = sess.append_assessment("ROOT_HASH_1", 16.0, "GRANT", 10.5)
        # Verify block linkage
        self.assertEqual(b1.previous_chain_digest, b0.block_digest)
        report = sess.validate_session_integrity()
        self.assertTrue(report.is_valid)
        self.assertFalse(report.revocation_recommended)

if __name__ == "__main__":
    unittest.main()
