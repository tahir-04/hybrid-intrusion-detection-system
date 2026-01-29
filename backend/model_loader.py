"""
model_loader.py

Purpose:
- Load trained ML artifacts exported from Google Colab
- Perform inference on a single feature vector
- Return anomaly score for Hybrid IDS

Used by:
- rules_engine
- decision_engine
- traffic simulator
- Streamlit dashboard
"""

import json
import numpy as np
from pathlib import Path
from joblib import load


# ==============================
# Paths
# ==============================
BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"

UNSUPERVISED_MODEL_PATH = MODELS_DIR / "unsupervised_model.joblib"
SCALER_PATH = MODELS_DIR / "scaler.joblib"
LABEL_ENCODER_PATH = MODELS_DIR / "label_encoder.joblib"
FEATURE_META_PATH = MODELS_DIR / "feature_metadata.json"
SHAP_BACKGROUND_PATH = MODELS_DIR / "shap_background_data.npy"


# ==============================
# Model Loader
# ==============================
class ModelLoader:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_order = None
        self.shap_background = None

        self._load_artifacts()

    def _load_artifacts(self):
        """Load ML artifacts into memory"""

        self.model = load(UNSUPERVISED_MODEL_PATH)
        self.scaler = load(SCALER_PATH)
        self.label_encoder = load(LABEL_ENCODER_PATH)

        with open(FEATURE_META_PATH, "r") as f:
            metadata = json.load(f)

        # ✅ CORRECT key from your metadata
        self.feature_order = metadata["feature_columns"]

        self.shap_background = np.load(SHAP_BACKGROUND_PATH)

        print("✅ ML artifacts loaded successfully")
        print("   Model:", type(self.model))
        print("   Number of features:", len(self.feature_order))

    # ==============================
    # Feature preparation
    # ==============================
    def prepare_features(self, feature_dict: dict) -> np.ndarray:
        """
        Convert feature dictionary into scaled numpy array
        """

        try:
            feature_vector = np.array(
                [feature_dict[f] for f in self.feature_order],
                dtype=float
            ).reshape(1, -1)
        except KeyError as e:
            raise ValueError(f"Missing feature in input data: {e}")

        return self.scaler.transform(feature_vector)

    # ==============================
    # Inference
    # ==============================
    def predict(self, feature_dict: dict) -> dict:
        """
        Run inference on one traffic window
        """

        X = self.prepare_features(feature_dict)

        raw_score = self.model.decision_function(X)[0]
        prediction = self.model.predict(X)[0]

        anomaly_score = float(np.clip(1 - raw_score, 0.0, 1.0))

        return {
            "anomaly_score": round(anomaly_score, 4),
            "is_anomaly": bool(prediction == -1)
        }


# ==============================
# Singleton access
# ==============================
_model_instance = None


def get_model():
    global _model_instance
    if _model_instance is None:
        _model_instance = ModelLoader()
    return _model_instance


# ==============================
# Standalone test
# ==============================
if __name__ == "__main__":
    import pandas as pd

    print("\n✅ Running model_loader standalone test...\n")

    df = pd.read_csv(MODELS_DIR / "processed_features.csv")
    sample = df.iloc[0].to_dict()

    model = get_model()
    result = model.predict(sample)

    print("✅ Prediction result:", result)
