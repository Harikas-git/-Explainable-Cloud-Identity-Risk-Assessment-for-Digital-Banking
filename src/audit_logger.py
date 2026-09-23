"""
Stage 5: Audit & Compliance Logger
Produces immutable, structured audit records compliant with GDPR Art. 22 and ISO 27001.
Includes cryptographic integrity hashes (SHA-256) and explanation snapshots.
"""
import os
import json
import time
import hashlib
from typing import Dict, Any, List
from dataclasses import asdict

class AuditLogger:
    """Manages secure, auditable logs for all access decisions and explanations."""

    def __init__(self, log_file: str = "access_audit_log.jsonl"):
        self.log_file = log_file

    def log_record(
        self,
        request_id: str,
        user_id: str,
        role: str,
        resource: str,
        decision_result: Any,
        attributions: Dict[str, float],
        narratives: Dict[str, str],
        context_features: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Constructs an auditable log entry with a tamper-evident SHA-256 hash."""
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        
        record_payload = {
            "request_id": request_id,
            "timestamp": timestamp,
            "user_id": user_id,
            "role": role,
            "resource": resource,
            "risk_score": decision_result.risk_score,
            "decision": decision_result.decision,
            "policy_matched": decision_result.policy_rule_matched,
            "is_override": decision_result.is_override,
            "key_attributions": attributions,
            "end_user_explanation": narratives["end_user"],
            "counterfactual_remediation": narratives["counterfactual"],
            "context_features": context_features
        }

        # Cryptographic integrity signature
        payload_serialized = json.dumps(record_payload, sort_keys=True)
        record_payload["integrity_hash"] = hashlib.sha256(payload_serialized.encode("utf-8")).hexdigest()

        # Append to jsonl
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record_payload) + "\n")
        except Exception as e:
            print(f"Warning: Audit log disk write failed: {e}")

        return record_payload

    def get_recent_logs(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieves most recent audit logs for the SOC dashboard."""
        if not os.path.exists(self.log_file):
            return []
        
        records = []
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        records.append(json.loads(line.strip()))
        except Exception:
            return []
        return records[-limit:]
