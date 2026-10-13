"""
Unified Patent-Grade Security Authorization Pipeline
Orchestrates:
1. Merkleized Explanation Graph (M-EG) Engine with Selective Disclosure Proofs
2. Dual-Consistency Adversarial Evasion & Hijacking Detector (DC-AEHD)
3. Provably Monotonic Constrained Counterfactual Optimizer (PMCCO)
4. Sliding-Window Continuous Session Merkle-Chaining (SW-MC)
"""
import time
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional

from backend.context_layer import ContextLayer, AccessRequest
from ai_models.risk_engine import RiskScoringEngine
from backend.decision_module import AccessDecisionModule, DecisionResult, DecisionOutcome
from ai_models.explanation_layer import ExplanationLayer
from ai_models.merkle_explanation_graph import MerkleExplanationGraphEngine, MerkleExplanationGraphResult, SelectiveDisclosureProof
from backend.adversarial_defense import AdversarialDefenseEngine, AdversarialCheckResult
from backend.monotonic_counterfactual import MonotonicCounterfactualOptimizer, MonotonicRemediationPlan
from backend.session_merkle_chain import SessionMerkleChainManager
from backend.audit_logger import AuditLogger

@dataclass
class PatentedAuthorizationToken:
    request_id: str
    session_id: str
    user_id: str
    decision: str
    risk_score: float
    merkle_root: str
    session_chain_digest: str
    adversarial_defense_status: str
    is_adversarial_quarantine: bool
    remediation_feasible: bool
    selective_audit_proof: Optional[Dict[str, Any]]
    counterfactual_plan: Dict[str, Any]
    attestation_signature: str
    timestamp: str

class PatentSecurityPipeline:
    """End-to-End Enterprise Zero-Trust Authorization Engine with Patent Security Inventions."""

    def __init__(self):
        self.context_layer = ContextLayer()
        self.risk_engine = RiskScoringEngine(random_state=42)
        self.decision_module = AccessDecisionModule()
        self.explanation_layer = ExplanationLayer(self.risk_engine)
        self.meg_engine = MerkleExplanationGraphEngine()
        self.adversarial_engine = AdversarialDefenseEngine(self.risk_engine)
        self.counterfactual_optimizer = MonotonicCounterfactualOptimizer(self.risk_engine)
        self.audit_logger = AuditLogger("database/access_audit_log.jsonl")
        self.session_chains: Dict[str, SessionMerkleChainManager] = {}

    def get_or_create_session(self, session_id: str) -> SessionMerkleChainManager:
        if session_id not in self.session_chains:
            self.session_chains[session_id] = SessionMerkleChainManager(session_id)
        return self.session_chains[session_id]

    def authorize_request(
        self,
        req: AccessRequest,
        session_id: str = "SESS-CORP-9921",
        audit_feature_target: str = "geo_velocity_kmh"
    ) -> PatentedAuthorizationToken:
        """
        Executes full patent-grade zero-trust evaluation pipeline.
        """
        # Step 1: Context Ingestion & Normalization
        feat_vec, feat_dict = self.context_layer.extract_features(req)
        instant_flags = self.context_layer.detect_instant_flags(req)

        # Step 2: Continuous Risk Scoring
        risk_score = self.risk_engine.predict_risk(feat_vec)

        # Step 3: Explanation Attribution (Shapley Values)
        attributions = self.explanation_layer.compute_feature_attributions(feat_vec, risk_score)

        # Step 4: [INVENTION 2] Adversarial Evasion & Hijacking Inspection
        adv_check: AdversarialCheckResult = self.adversarial_engine.inspect_request(
            feat_vec, risk_score, attributions
        )

        # Step 5: Policy Evaluation with Adversarial Quarantine Overrides
        if adv_check.is_adversarial and adv_check.quarantine_triggered:
            decision_res = DecisionResult(
                decision=DecisionOutcome.DENY,
                risk_score=max(risk_score, 85.0),
                threshold_low=self.decision_module.theta_low,
                threshold_high=self.decision_module.theta_high,
                policy_rule_matched="POL-PATENT-SEC-01: Adversarial Perturbation / Hijack Detected",
                is_override=True,
                override_reason=f"Detected adversarial divergence ({adv_check.attack_type}) with confidence {adv_check.confidence_score*100:.1f}%.",
                required_action="Session quarantined in honeypot buffer. Physical FIDO2 hardware token challenge issued."
            )
        else:
            decision_res = self.decision_module.evaluate(risk_score, instant_flags)

        # Step 6: [INVENTION 3] Provably Monotonic Counterfactual Optimization
        remediation_plan: MonotonicRemediationPlan = self.counterfactual_optimizer.solve_remediation(
            feat_vec, risk_score
        )

        # Step 7: [INVENTION 1] Construct Merkleized Explanation Graph (M-EG)
        meg_result, nodes_dict = self.meg_engine.construct_meg(
            request_id=req.request_id,
            user_id=req.user_id,
            decision=decision_res.decision,
            risk_score=decision_res.risk_score,
            policy_name=decision_res.policy_rule_matched,
            feature_dict=feat_dict,
            attributions=attributions
        )

        # Generate Zero-Knowledge Selective Disclosure Proof for specified target feature
        sel_proof: Optional[SelectiveDisclosureProof] = self.meg_engine.generate_selective_disclosure_proof(
            nodes_dict, audit_feature_target
        )

        # Step 8: [INVENTION 4] Sliding-Window Session Merkle-Chaining
        session_mgr = self.get_or_create_session(session_id)
        feat_norm = float(feat_vec.sum())
        chained_block = session_mgr.append_assessment(
            merkle_root=meg_result.merkle_root,
            risk_score=decision_res.risk_score,
            decision=decision_res.decision,
            feature_vector_norm=feat_norm
        )
        session_report = session_mgr.validate_session_integrity()

        # Step 9: Tamper-Evident Audit Logging
        narratives = self.explanation_layer.generate_narratives(req, decision_res, attributions)
        # Augment narrative with monotonic counterfactual
        narratives["counterfactual"] = "\n".join(remediation_plan.actionable_remediation_steps)

        audit_rec = self.audit_logger.log_record(
            request_id=req.request_id,
            user_id=req.user_id,
            role=req.role,
            resource=req.target_resource,
            decision_result=decision_res,
            attributions=attributions,
            narratives=narratives,
            context_features=feat_dict
        )

        # Step 10: Emit Cryptographically Signed Authorization Token
        token = PatentedAuthorizationToken(
            request_id=req.request_id,
            session_id=session_id,
            user_id=req.user_id,
            decision=decision_res.decision,
            risk_score=decision_res.risk_score,
            merkle_root=meg_result.merkle_root,
            session_chain_digest=chained_block.block_digest,
            adversarial_defense_status=adv_check.attack_type or "CLEAN",
            is_adversarial_quarantine=adv_check.quarantine_triggered,
            remediation_feasible=remediation_plan.remediation_feasible,
            selective_audit_proof=asdict(sel_proof) if sel_proof else None,
            counterfactual_plan=asdict(remediation_plan),
            attestation_signature=meg_result.cryptographic_signature,
            timestamp=meg_result.timestamp
        )

        return token
