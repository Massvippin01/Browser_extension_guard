# Verity: Website Authenticity (Stage 2)

A real-time, on-device evaluator for website authenticity to protect against financial phishing, scams, and impersonation.

## Architecture

Verity uses a hybrid client-side evaluation architecture:

```text
URL & Page Navigation
 ↓
Rules Engine (rules.js, payment-detector.js, etc.) ──┐
                                                    │
DOM Signals (content-script.js)                     │
 ↓                                                  │
Feature Extraction (feature-extractor.js)          │
 ↓                                                  │
ONNX Runtime Web (phishing_model.onnx)              │
 ↓                                                  │
ML Risk Score ──────────────────────────────────────┤
                                                    ↓
                                           calculateRisk()
                                                    ↓
                                              Final Verdict
```

### ML Pipeline & Offline Model
The local machine learning model is executed client-side via **onnxruntime-web** using purely structural URL features (e.g., `having_IP_Address`, `URL_Length`, `Prefix_Suffix`, `having_Sub_Domain`).

To retrain the model and regenerate artifacts:
```bash
cd training
pip install -r requirements.txt
python train_model.py
```
This script downloads training data, trains the model, and outputs:
- `background/model/phishing_model.onnx`
- `background/model/feature_order.json`
- `background/model/feature_schema.json`
- `training/model_metrics.json`

### ML Fallback
If the ONNX model is missing, fails to load, or encounters malformed inputs, the ML risk score silently falls back to `null`. The rule-based scoring engine continues working independently.

## Known Limitations

1. **ML Model Accuracy (from `training/model_metrics.json`)**:
   - **Synthetic Test Split**: 62.08% accuracy, 59.15% precision, 64.22% recall, 61.58% F1 score.
   - **Live Real-World Validation (1,000 samples from PhishTank + Tranco Top-1000)**: **42.0% accuracy**, 45.45% precision, 80.0% recall, 57.97% F1 score.
   - The ML model is an experimental baseline classifier with high false-positive rates on real-world web traffic; it serves strictly as an auxiliary signal alongside deterministic rule-based checks.

2. **English-Centric Heuristics**:
   - Text heuristics for detecting social engineering, KYC urgency, utility cutoffs, and payment traps currently inspect English keywords only (e.g., "disconnected", "cashback", "urgent notice"). Sites using Hindi, other Indian regional languages, or non-English text bypass these keyword heuristics.

3. **No Public Suffix List (PSL)**:
   - Hostname and subdomain parsing rely on naive period splitting rather than the Mozilla Public Suffix List. Domains with multi-part suffixes (e.g., `.co.in`, `.com.au`, `.gov.uk`) may not have their apex domain distinguished accurately from subdomains.

4. **Desktop Chromium Only**:
   - The extension relies on Manifest V3 desktop APIs (`chrome.webNavigation`, `chrome.webRequest`, `chrome.downloads`, `chrome.offscreen`) and is supported exclusively on desktop Chromium browsers (Chrome, Brave, Edge).

5. **No Active Telemetry or Federated Retraining**:
   - The extension operates fully client-side. The backend endpoint `/telemetry/report` in `verity-cloud` is an unpersisted demo stub with no federated learning or retraining pipeline connected. Remote threat intelligence is opt-in and disabled by default.

## Loading the Extension
1. Open Chrome and navigate to `chrome://extensions`.
2. Enable **Developer mode** in the top right.
3. Click **Load unpacked** and select the `verity-extension` directory.
