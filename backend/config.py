"""
Configuration and Policy Definitions for Digital Banking Cloud IAM
"""
from dataclasses import dataclass
from typing import Dict, List

# Policy Thresholds for Digital Banking Access Decisions
# Continuous Risk Score: R in [0, 100]
THETA_LOW = 35.0    # R < 35 -> GRANT
THETA_HIGH = 75.0   # 35 <= R < 75 -> STEP-UP MFA; R >= 75 -> DENY

# Feature Configuration and Normalization Metadata
FEATURE_METADATA = {
    "device_trust_score": {
        "description": "Device health and security posture (0: Compromised/Unknown, 1: Managed/Encrypted)",
        "min": 0.0,
        "max": 1.0,
        "default": 0.95,
        "weight_bias": -1.0 # higher trust lowers risk
    },
    "ip_reputation_risk": {
        "description": "Threat intelligence score for requesting IP (0: Verified ISP, 1: Tor/Known Proxy)",
        "min": 0.0,
        "max": 1.0,
        "default": 0.05,
        "weight_bias": 1.0 # higher reputation risk increases risk
    },
    "geo_velocity_kmh": {
        "description": "Travel speed from prior authentication location in km/h (>900 km/h is impossible travel)",
        "min": 0.0,
        "max": 2500.0,
        "default": 20.0,
        "weight_bias": 1.0
    },
    "hour_anomaly_score": {
        "description": "Deviation from user's typical historical working hours (0: standard, 1: acute anomaly)",
        "min": 0.0,
        "max": 1.0,
        "default": 0.1,
        "weight_bias": 1.0
    },
    "resource_sensitivity": {
        "description": "Data classification level of requested resource (1: Public, 2: Internal, 3: Confidential Accounts, 4: Restricted Transfers, 5: Critical SWIFT/Secrets)",
        "min": 1,
        "max": 5,
        "default": 2,
        "weight_bias": 1.0
    },
    "failed_attempts_last_hour": {
        "description": "Number of failed authentication attempts within the preceding 60 minutes",
        "min": 0,
        "max": 20,
        "default": 0,
        "weight_bias": 1.0
    },
    "vpn_connected": {
        "description": "Is request traversing corporate managed VPN tunnel (1: Yes, 0: Direct Internet)",
        "min": 0,
        "max": 1,
        "default": 1,
        "weight_bias": -1.0
    },
    "privilege_elevation_requested": {
        "description": "Does this action require JIT administrative privilege elevation (1: Yes, 0: Standard)",
        "min": 0,
        "max": 1,
        "default": 0,
        "weight_bias": 1.0
    },
    "keystroke_anomaly_score": {
        "description": "Behavioral biometric deviation score in keystroke/mouse dynamics (0: authentic, 1: bot/imposter)",
        "min": 0.0,
        "max": 1.0,
        "default": 0.1,
        "weight_bias": 1.0
    }
}

FEATURE_NAMES = list(FEATURE_METADATA.keys())

# System Roles in Digital Banking
DEFAULT_ROLES = [
    "Bank Teller",
    "Loan Approver",
    "Cloud Infrastructure Admin",
    "SWIFT Payment Officer",
    "Compliance Auditor"
]
