"""
rules_engine.py

Purpose:
- Load rule-based intrusion detection rules from YAML
- Evaluate rules against a single feature window
- Return matched rules + rule-based risk score

This module complements ML detection (Hybrid IDS).
"""

import yaml
from pathlib import Path


# ==============================
# Paths
# ==============================
BASE_DIR = Path(__file__).resolve().parent.parent
RULES_FILE = BASE_DIR / "rules" / "rules.yaml"


# ==============================
# Rule Engine
# ==============================
class RulesEngine:
    def __init__(self, rules_path: Path = RULES_FILE):
        self.rules_path = rules_path
        self.rules = []
        self._load_rules()

    def _load_rules(self):
        """Load rules from YAML file"""
        if not self.rules_path.exists():
            raise FileNotFoundError(f"Rules file not found: {self.rules_path}")

        with open(self.rules_path, "r") as f:
            self.rules = yaml.safe_load(f)

        if not isinstance(self.rules, list):
            raise ValueError("Rules file must contain a list of rules")

        print(f"✅ Loaded {len(self.rules)} detection rules")

    # ==============================
    # Rule Evaluation
    # ==============================
    def evaluate(self, feature_dict: dict) -> dict:
        """
        Evaluate all rules against one feature window

        Returns:
        {
            "matched_rules": [ {rule_id, description, severity} ],
            "rule_score": float (0–1)
        }
        """

        matched_rules = []
        total_severity_score = 0.0

        for rule in self.rules:
            try:
                # Evaluate condition safely using feature_dict only
                if self._evaluate_condition(rule["condition"], feature_dict):
                    matched_rules.append({
                        "rule_id": rule["id"],
                        "description": rule.get("description", ""),
                        "severity": rule.get("severity", "low")
                    })

                    total_severity_score += self._severity_to_score(
                        rule.get("severity", "low")
                    )

            except Exception as e:
                print(f"⚠️ Rule evaluation failed [{rule.get('id')}]: {e}")

        # Normalize rule score to 0–1
        rule_score = min(total_severity_score, 1.0)

        return {
            "matched_rules": matched_rules,
            "rule_score": round(rule_score, 3)
        }

    # ==============================
    # Helpers
    # ==============================
    def _evaluate_condition(self, condition: str, features: dict) -> bool:
        """
        Evaluate rule condition using feature dictionary only
        """
        return bool(eval(condition, {}, features))

    def _severity_to_score(self, severity: str) -> float:
        """
        Convert severity label to numeric score
        """
        mapping = {
            "low": 0.2,
            "medium": 0.4,
            "high": 0.7,
            "critical": 1.0
        }
        return mapping.get(severity.lower(), 0.2)


# ==============================
# Singleton instance
# ==============================
_rules_instance = None


def get_rules_engine():
    global _rules_instance
    if _rules_instance is None:
        _rules_instance = RulesEngine()
    return _rules_instance


# ==============================
# Quick standalone test
# ==============================
if __name__ == "__main__":
    print("\n🔍 Running rules_engine self-test...\n")

    # Example fake feature window
    test_features = {
        "bytes_out": 500000,
        "bytes_in": 20000,
        "unique_dst_ports": 120,
        "dns_requests_per_min": 80,
        "login_failures": 15
    }

    engine = get_rules_engine()
    result = engine.evaluate(test_features)

    print("Matched rules:", result["matched_rules"])
    print("Rule score:", result["rule_score"])
