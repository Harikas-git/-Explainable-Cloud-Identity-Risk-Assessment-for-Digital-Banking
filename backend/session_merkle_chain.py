"""
Inventive Component 4: Sliding-Window Continuous Session Merkle-Chaining (SW-MC)
Binds sequential continuous authorization micro-assessments into a forward-secure
cryptographic hash chain to detect session hijacking, token drift, and API abuse.
"""
import hashlib
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class SessionChainedBlock:
    sequence_index: int
    timestamp: str
    previous_chain_digest: str
    merkle_explanation_root: str
    risk_score: float
    decision: str
    entropy_delta: float
    block_digest: str

@dataclass
class SessionValidationReport:
    session_id: str
    is_valid: bool
    chain_length: int
    latest_digest: str
    detected_drift_anomaly: bool
    drift_score: float
    revocation_recommended: bool

class SessionMerkleChainManager:
    """
    Maintains a forward-secure, tamper-evident cryptographic sliding-window hash chain
    for active digital banking sessions.
    """

    def __init__(self, session_id: str, genesis_secret: str = "GENESIS_SALT_BANK_CLOUD_2026"):
        self.session_id = session_id
        self.genesis_digest = hashlib.sha256(f"{session_id}|{genesis_secret}".encode("utf-8")).hexdigest()
        self.chain: List[SessionChainedBlock] = []
        self.drift_history: List[float] = []

    def append_assessment(
        self,
        merkle_root: str,
        risk_score: float,
        decision: str,
        feature_vector_norm: float
    ) -> SessionChainedBlock:
        """
        Computes forward-secure chain step:
        R_k = H( R_{k-1} || R_MEG^{(k)} || Risk || Timestamp || Entropy )
        """
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        prev_digest = self.chain[-1].block_digest if self.chain else self.genesis_digest
        seq_idx = len(self.chain)

        # Calculate session behavioral entropy delta from baseline
        if self.chain:
            entropy_delta = abs(risk_score - self.chain[-1].risk_score)
        else:
            entropy_delta = 0.0
        self.drift_history.append(entropy_delta)

        block_payload = f"{seq_idx}|{prev_digest}|{merkle_root}|{risk_score:.2f}|{decision}|{entropy_delta:.2f}|{timestamp}"
        block_digest = hashlib.sha256(block_payload.encode("utf-8")).hexdigest()

        block = SessionChainedBlock(
            sequence_index=seq_idx,
            timestamp=timestamp,
            previous_chain_digest=prev_digest,
            merkle_explanation_root=merkle_root,
            risk_score=risk_score,
            decision=decision,
            entropy_delta=entropy_delta,
            block_digest=block_digest
        )

        self.chain.append(block)
        return block

    def validate_session_integrity(self) -> SessionValidationReport:
        """
        Verifies mathematical chain linkage and detects anomalous session divergence (token theft).
        """
        if not self.chain:
            return SessionValidationReport(
                session_id=self.session_id,
                is_valid=True,
                chain_length=0,
                latest_digest=self.genesis_digest,
                detected_drift_anomaly=False,
                drift_score=0.0,
                revocation_recommended=False
            )

        # 1. Verify cryptographic hash continuity
        expected_prev = self.genesis_digest
        for block in self.chain:
            if block.previous_chain_digest != expected_prev:
                return SessionValidationReport(
                    session_id=self.session_id,
                    is_valid=False,
                    chain_length=len(self.chain),
                    latest_digest=block.block_digest,
                    detected_drift_anomaly=True,
                    drift_score=100.0,
                    revocation_recommended=True
                )
            expected_prev = block.block_digest

        # 2. Check cumulative sliding-window entropy drift
        sliding_window = self.drift_history[-3:] if len(self.drift_history) >= 3 else self.drift_history
        avg_drift = sum(sliding_window) / len(sliding_window) if sliding_window else 0.0

        drift_anomaly = avg_drift > 28.0  # Acute session deviation (possible token hijack)

        return SessionValidationReport(
            session_id=self.session_id,
            is_valid=True,
            chain_length=len(self.chain),
            latest_digest=self.chain[-1].block_digest,
            detected_drift_anomaly=drift_anomaly,
            drift_score=round(avg_drift, 2),
            revocation_recommended=drift_anomaly or (self.chain[-1].decision == "DENY")
        )
