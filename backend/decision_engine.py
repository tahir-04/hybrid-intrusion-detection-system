"""
decision_engine.py

Purpose:
- Combine ML-based anomaly detection with rule-based detection
- Produce a final intrusion decision and severity
- Act as the brain of the Hybrid IDS

Flow:
features
  ├── ML model (anomaly score)
  ├── Rule engine (rule score)
  └── Decision engine → FINAL ALERT
"""

from model_loader import get_model
from rules_engine import get_rules_engine


# ==============================
# Decision Engine
# ==============================
class DecisionEngine:
    def __init__(
        self,
        ml_weight: float = 0.6,
        rule_weight: float = 0.4,
        alert_threshold: float = 0.7
    ):
        self.ml_weight = ml_weight
        self.rule_weight = rule_weight
        self.alert_threshold = alert_threshold

        self.model = get_model()
        self.rules_engine = get_rules_engine()

    # ==============================
    # Final Decision Logic
    # ==============================
    def evaluate(self, feature_dict: dict) -> dict:
        """
        Evaluate one traffic window using hybrid logic

        Returns:
        {
            "ml_score": float,
            "rule_score": float,
            "final_score": float,
            "is_intrusion": bool,
            "severity": str,
            "matched_rules": list
        }
        """

        # ML prediction
        ml_result = self.model.predict(feature_dict)
        ml_score = ml_result["anomaly_score"]

        # Rule evaluation
        rule_result = self.rules_engine.evaluate(feature_dict)
        rule_score = rule_result["rule_score"]
        matched_rules = rule_result["matched_rules"]

        # Hybrid fusion
        final_score = (
            self.ml_weight * ml_score +
            self.rule_weight * rule_score
        )

        final_score = round(final_score, 4)
        is_intrusion = final_score >= self.alert_threshold

        severity = self._determine_severity(final_score, matched_rules)

        return {
            "ml_score": ml_score,
            "rule_score": rule_score,
            "final_score": final_score,
            "is_intrusion": is_intrusion,
            "severity": severity,
            "matched_rules": matched_rules
        }

    # ==============================
    # Severity Mapping
    # ==============================
    def _determine_severity(self, final_score: float, matched_rules: list) -> str:
        """
        Determine alert severity based on score and rules
        """

        if any(r["severity"] == "critical" for r in matched_rules):
            return "critical"

        if final_score >= 0.9:
            return "critical"
        elif final_score >= 0.75:
            return "high"
        elif final_score >= 0.5:
            return "medium"
        else:
            return "low"


# ==============================
# Singleton instance
# ==============================
_decision_engine = None


def get_decision_engine():
    global _decision_engine
    if _decision_engine is None:
        _decision_engine = DecisionEngine()
    return _decision_engine


# ==============================
# Standalone Test
# ==============================
if __name__ == "__main__":
    print("\n🔍 Running decision_engine self-test...\n")

    import pandas as pd
    from pathlib import Path

    BASE_DIR = Path(__file__).resolve().parent.parent
    DATA_PATH = BASE_DIR / "models" / "processed_features.csv"

    # Load real processed features (schema-safe)
    df = pd.read_csv(DATA_PATH)

    # Pick ONE real row that matches training schema
    sample_features = df.iloc[0].to_dict()

    engine = get_decision_engine()
    result = engine.evaluate(sample_features)

    print("Decision result:")
    for k, v in result.items():
        print(f"{k}: {v}")
