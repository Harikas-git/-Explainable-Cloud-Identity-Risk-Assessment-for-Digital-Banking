"""
Inventive Component 2: Dual-Consistency Adversarial Evasion & Hijacking Detector (DC-AEHD)
Defends explainable access control against adversarial evasion, perturbation attacks,
and explanation manipulation (e.g. Fooling SHAP/LIME attacks).
"""
import numpy as np
from dataclasses import dataclass
from typing import Dict, Any, Tuple, Optional
import config

@dataclass
class AdversarialCheckResult:
    is_adversarial: bool
    confidence_score: float # 0.0 to 1.0 (1.0 = definite attack)
    divergence_index: float
    attack_type: Optional[str] # 'EXPLANATION_HIJACKING', 'EVASION_PERTURBATION', 'NONE'
    quarantine_triggered: bool
    deception_honey_challenge: Optional[str]
    details: Dict[str, Any]

class AdversarialDefenseEngine:
    """
    Validates mathematical and gradient consistency of explanations to detect
    adversarial perturbations designed to fool the risk model or manipulate SHAP values.
    """

    def __init__(self, risk_engine, divergence_threshold: float = 18.5):
        self.risk_engine = risk_engine
        self.divergence_threshold = divergence_threshold
        self.feature_names = config.FEATURE_NAMES

    def inspect_request(
        self,
        feature_vector: np.ndarray,
        computed_risk: float,
        attributions: Dict[str, float]
    ) -> AdversarialCheckResult:
        """
        Executes Dual-Consistency Verification:
        1. Local Numerical Gradient Check (Finite difference sensitivity)
        2. Monotonic Attribution Invariant Check
        3. Statistical Perturbation Divergence Check
        """
        eps = 1e-3
        numerical_gradients = {}
        divergence_accum = 0.0
        inconsistencies = []

        # 1. Compute empirical numerical gradient for each feature
        for idx, name in enumerate(self.feature_names):
            x_plus = feature_vector.copy()
            x_minus = feature_vector.copy()

            step = 0.05
            if name == "geo_velocity_kmh":
                step = 25.0
            elif name in ["resource_sensitivity", "failed_attempts_last_hour"]:
                step = 1.0

            x_plus[idx] += step
            x_minus[idx] -= step

            risk_plus = self.risk_engine.predict_risk(x_plus)
            risk_minus = self.risk_engine.predict_risk(x_minus)

            grad = (risk_plus - risk_minus) / (2.0 * step)
            numerical_gradients[name] = grad

            # 2. Check Gradient vs Attribution Directional Consistency
            attr = attributions.get(name, 0.0)
            meta = config.FEATURE_METADATA.get(name, {})
            expected_sign = meta.get("weight_bias", 1.0)
            val = feature_vector[idx]
            deviation_from_default = val - meta.get("default", 0.0)

            # Invariant: If a feature is significantly elevated beyond safe default,
            # attribution must be positively aligned unless adversarial masking is active.
            if abs(deviation_from_default) > 0.3 and abs(attr) > 2.0:
                expected_attr_sign = 1.0 if (deviation_from_default * expected_sign) > 0 else -1.0
                observed_attr_sign = 1.0 if attr > 0 else -1.0
                
                if expected_attr_sign != observed_attr_sign:
                    inconsistencies.append({
                        "feature": name,
                        "expected_sign": expected_attr_sign,
                        "observed_sign": observed_attr_sign,
                        "attribution": attr
                    })
                    divergence_accum += abs(attr) * 1.5

            # Sensitivity divergence
            expected_impact = grad * deviation_from_default
            divergence_accum += abs(attr - expected_impact) * 0.15

        # 3. Assess adversarial threat level
        divergence_index = round(float(divergence_accum), 2)
        is_attack = divergence_index > self.divergence_threshold or len(inconsistencies) >= 2

        attack_type = "NONE"
        deception_challenge = None
        quarantine = False

        if is_attack:
            confidence = min(0.99, 0.60 + (divergence_index / 50.0))
            if len(inconsistencies) > 0:
                attack_type = "EXPLANATION_HIJACKING_ATTEMPT"
            else:
                attack_type = "ADVERSARIAL_EVASION_PERTURBATION"
            
            quarantine = True
            deception_challenge = "FIDO2_HARDWARE_PROOF_OF_PRESENCE_CHALLENGE_WITH_CANARY"
        else:
            confidence = max(0.01, divergence_index / 100.0)

        return AdversarialCheckResult(
            is_adversarial=is_attack,
            confidence_score=round(confidence, 3),
            divergence_index=divergence_index,
            attack_type=attack_type,
            quarantine_triggered=quarantine,
            deception_honey_challenge=deception_challenge,
            details={
                "inconsistencies_count": len(inconsistencies),
                "flagged_features": inconsistencies,
                "numerical_gradients": {k: round(v, 3) for k, v in list(numerical_gradients.items())[:4]}
            }
        )
