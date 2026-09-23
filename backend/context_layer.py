"""
Stage 1: Identity & Context Layer
Ingests subject attributes, environmental context, device telemetry, and behavioral signals,
normalizing them into standardized feature vectors for risk scoring in digital banking.
"""
from dataclasses import dataclass, asdict
from typing import Dict, Any, Tuple, Optional
import numpy as np

try:
    from backend import config
except ImportError:
    import config

@dataclass
class AccessRequest:
    request_id: str
    user_id: str
    role: str
    department: str
    target_resource: str
    device_id: str
    ip_address: str
    location: str
    # Contextual Signals
    device_trust_score: float = 0.95
    ip_reputation_risk: float = 0.05
    geo_velocity_kmh: float = 25.0
    hour_anomaly_score: float = 0.10
    resource_sensitivity: int = 2
    failed_attempts_last_hour: int = 0
    vpn_connected: int = 1
    privilege_elevation_requested: int = 0
    keystroke_anomaly_score: float = 0.10

class ContextLayer:
    """Normalizes and extracts feature vectors from heterogeneous access requests."""

    def __init__(self):
        self.feature_names = config.FEATURE_NAMES

    def extract_features(self, req: AccessRequest) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Transforms an AccessRequest into a 1D numpy array aligned with trained models,
        and returns a dictionary of extracted values.
        """
        raw_dict = asdict(req)
        feature_dict = {}
        values = []

        for name in self.feature_names:
            val = float(raw_dict.get(name, config.FEATURE_METADATA[name]["default"]))
            feature_dict[name] = val
            values.append(val)

        feature_vector = np.array(values, dtype=np.float32)
        return feature_vector, feature_dict

    def detect_instant_flags(self, req: AccessRequest) -> Dict[str, bool]:
        """Identifies deterministic red flags or policy trips prior to probabilistic modeling."""
        flags = {
            "impossible_travel": req.geo_velocity_kmh > 900.0,
            "high_failed_attempts": req.failed_attempts_last_hour >= 5,
            "malicious_ip_indicator": req.ip_reputation_risk >= 0.85,
            "compromised_device": req.device_trust_score <= 0.20,
            "critical_resource_target": req.resource_sensitivity >= 5
        }
        return flags
