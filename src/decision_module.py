"""
Stage 3: Access Decision Module
Applies dynamic security policy thresholds and regulatory overrides
to determine the access outcome: GRANT, STEP_UP_MFA, or DENY.
"""
from dataclasses import dataclass
from typing import Dict, Any, Optional
import config

class DecisionOutcome:
    GRANT = "GRANT"
    STEP_UP_MFA = "STEP_UP_MFA"
    DENY = "DENY"

@dataclass
class DecisionResult:
    decision: str
    risk_score: float
    threshold_low: float
    threshold_high: float
    policy_rule_matched: str
    is_override: bool
    override_reason: Optional[str]
    required_action: str

class AccessDecisionModule:
    """Evaluates computed risk score and contextual flags against access policies."""

    def __init__(self, theta_low: float = config.THETA_LOW, theta_high: float = config.THETA_HIGH):
        self.theta_low = theta_low
        self.theta_high = theta_high

    def evaluate(self, risk_score: float, flags: Dict[str, bool]) -> DecisionResult:
        """
        Determines the access decision based on thresholds and security overrides.
        """
        # Hard Security Overrides
        if flags.get("impossible_travel", False):
            return DecisionResult(
                decision=DecisionOutcome.DENY,
                risk_score=risk_score,
                threshold_low=self.theta_low,
                threshold_high=self.theta_high,
                policy_rule_matched="POL-OVERRIDE-01: Impossible Travel Detected (>900 km/h)",
                is_override=True,
                override_reason="Detected physical displacement exceeding commercial aircraft velocity.",
                required_action="Account temporarily locked. Security Operations Center (SOC) review required."
            )

        if flags.get("malicious_ip_indicator", False) and risk_score >= self.theta_low:
            return DecisionResult(
                decision=DecisionOutcome.DENY,
                risk_score=risk_score,
                threshold_low=self.theta_low,
                threshold_high=self.theta_high,
                policy_rule_matched="POL-OVERRIDE-02: High-Risk IP / Tor Exit Node Prohibited",
                is_override=True,
                override_reason="Connection originated from blacklisted threat proxy or known malicious subnet.",
                required_action="Disconnect from untrusted proxy and reconnect via authorized corporate VPN."
            )

        # Standard Policy Threshold Evaluation
        if risk_score < self.theta_low:
            return DecisionResult(
                decision=DecisionOutcome.GRANT,
                risk_score=risk_score,
                threshold_low=self.theta_low,
                threshold_high=self.theta_high,
                policy_rule_matched=f"POL-BASE-01: Low Risk Access Permitted (Score < {self.theta_low})",
                is_override=False,
                override_reason=None,
                required_action="Access granted seamlessly without user interruption."
            )
        elif risk_score < self.theta_high:
            return DecisionResult(
                decision=DecisionOutcome.STEP_UP_MFA,
                risk_score=risk_score,
                threshold_low=self.theta_low,
                threshold_high=self.theta_high,
                policy_rule_matched=f"POL-BASE-02: Moderate Risk Detected ({self.theta_low} <= Score < {self.theta_high})",
                is_override=False,
                override_reason=None,
                required_action="Prompt user for biometric hardware key (FIDO2) or authenticator app push notification."
            )
        else:
            return DecisionResult(
                decision=DecisionOutcome.DENY,
                risk_score=risk_score,
                threshold_low=self.theta_low,
                threshold_high=self.theta_high,
                policy_rule_matched=f"POL-BASE-03: High Risk Score Exceeded Threshold (Score >= {self.theta_high})",
                is_override=False,
                override_reason=None,
                required_action="Request rejected. Anomaly notification dispatched to Security Operations Center."
            )
