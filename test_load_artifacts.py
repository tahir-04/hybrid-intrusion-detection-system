from joblib import load
import numpy as np

# Load ML artifacts
model = load("models/unsupervised_model.joblib")
scaler = load("models/scaler.joblib")
label_encoder = load("models/label_encoder.joblib")

# Load SHAP data
shap_background = np.load("models/shap_background_data.npy")
sample_shap = np.load("models/sample_shap_values.npy")

print("✅ Model loaded:", type(model))
print("✅ Scaler loaded:", type(scaler))
print("✅ Label encoder loaded:", type(label_encoder))
print("✅ SHAP background shape:", shap_background.shape)
print("✅ Sample SHAP shape:", sample_shap.shape)
print("Model object:", model)
