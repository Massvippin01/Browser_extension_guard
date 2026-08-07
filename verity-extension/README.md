# Verity: Website Authenticity (Stage 2)

A real-time, on-device evaluator for website authenticity to protect against financial phishing and impersonation.

## Stage 2: Machine Learning Architecture

In Stage 2, an additive local Machine Learning layer was introduced using **onnxruntime-web**. 

```text
URL
 ↓
Stage 1 Rules ──────────────┐
                            │
DOM Signals                 │
 ↓                          │
Feature Extraction          │
 ↓                          │
ONNX Runtime Web            │
 ↓                          │
ML Risk Score ──────────────┤
                            ↓
                   calculateVerdict()
                            ↓
                     Final Verdict
```

### Training Pipeline
The ML model (Logistic Regression) is trained offline on the public UCI Phishing Websites dataset. 
To guarantee parity, only purely structural URL features (e.g., `having_IP_Address`, `URL_Length`, `Prefix_Suffix`) are used, ensuring exactly the same semantics in Python and in the Chrome Extension offline.

To retrain the model and regenerate all artifacts:
```bash
cd training
pip install -r requirements.txt
python train_model.py
```
This script downloads the dataset, trains the model, and generates:
- `background/model/phishing_model.onnx`
- `background/model/feature_order.json`
- `background/model/feature_schema.json`
- `training/model_metrics.json`

### ML Fallback
If the ONNX model is missing, fails to load, or encounters malformed inputs, the ML risk score silently falls back to `null`. The existing Rule-only scoring engine continues working seamlessly. 

### Benchmark Mode
The extension popup includes a local Benchmark Mode that scores 50 test URLs against the production feature extraction and inference pipeline, reporting real latency (min/median/max) and accuracy.

### Limitations
- **Dataset limitations:** Public datasets may not reflect real-time distribution shifts in modern phishing attacks.
- **Feature approximations:** Deep network features (like DNS records) are omitted to maintain a fully offline architecture.
- **False Positives/Negatives:** The model is a Logistic Regression baseline. It serves as one signal among multiple rule-based signals.

## Loading the Extension
1. Open Chrome and navigate to `chrome://extensions`.
2. Enable **Developer mode** in the top right.
3. Click **Load unpacked** and select the `verity-extension` directory.
