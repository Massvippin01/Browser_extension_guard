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
ML Risk Score (scaled by ML_WEIGHT) ────────────────┤
                                                    ↓
                                           calculateRisk()
                                                    ↓
                                              Final Verdict
```

### ML Pipeline, Ablation, and Decision Rule
Verity includes an on-device machine learning pipeline powered by ONNX Runtime Web in an offscreen document (`background/offscreen.html`).
- **Baseline Model (`phishing_model.onnx`):** 8 naive structural features, trained on synthetic URLs. In ablation on real held-out data, it failed to improve detection.
- **Retrained Model V2 (`background/model/phishing_model_v2.onnx`):** LightGBM model utilizing 18 rich lexical, entropy, and domain features trained exclusively on real threat and benign feeds (5-fold domain-grouped CV: 98.7% F1).
- **Wiring & Parity:** V2 feature extraction is implemented in `background/rich-feature-extractor.js` and wired into `background/offscreen.js` with `ML_WEIGHT = 1.0`. Feature extraction parity between Python and JavaScript is strictly verified by `tests/parity.test.js`.

### Test Suite & Benchmark Commands
- **Unit and Parity Tests:**
  ```bash
  npm test
  ```
- **Full Benchmark (Bootstrap 95% CIs across Phishing, Malware, Safe):**
  ```bash
  npm run benchmark
  ```
- **Real Browser E2E Test (Puppeteer + Unpacked Extension):**
  ```bash
  npm run e2e
  ```

## Benchmark Dataset Composition (V2.1)

The defensible benchmark suite (`npm run benchmark`) evaluates **4,750 real URLs** (zero synthetic or invented URLs), split into strictly domain-disjoint `dev` (2,338 URLs, 1,478 domains) and `test` (2,412 URLs, 1,459 domains) sets:
- **Benign set (2,050 URLs):**
  - Real Tranco Top 1M list (tranco-list.eu): 1,000 top ranked domains + 1,000 domains sampled from ranks 1,000 to 100,000.
  - Curated hard cases: 50 real government, bank, UPI, tracking, shortener, and ccTLD URLs.
- **Phishing set (1,500 URLs):**
  - Phishing.Database active feed (1,000 URLs).
  - OpenPhish community feed (500 URLs).
- **Malware set (1,200 URLs):**
  - URLhaus recent malware URL feed (1,200 URLs kept in a separate malware category).

## Known Limitations

1. **ML Model Baseline:**
   - The shipped baseline ONNX model (`phishing_model.onnx`) achieves only 42.0% live accuracy on real-world web traffic due to reliance on 8 structural features without DOM context. Per the ablation decision rule, `ML_WEIGHT = 0` is enforced in the shipping engine.

2. **English-Centric Heuristics:**
   - Text heuristics for detecting social engineering, KYC urgency, utility cutoffs, and payment traps currently inspect English keywords only (e.g., "disconnected", "cashback", "urgent notice"). Sites using Hindi, other Indian regional languages, or non-English text bypass these keyword heuristics.

3. **No Public Suffix List (PSL):**
   - Hostname and subdomain parsing rely on naive period splitting rather than the Mozilla Public Suffix List. Domains with multi-part suffixes (e.g., `.co.in`, `.com.au`, `.gov.uk`) may not have their apex domain distinguished accurately from subdomains, leading to false positives on unlisted regional institutions.

4. **Desktop Chromium Only:**
   - The extension relies on Manifest V3 desktop APIs (`chrome.webNavigation`, `chrome.webRequest`, `chrome.downloads`, `chrome.offscreen`) and is supported exclusively on desktop Chromium browsers (Chrome, Brave, Edge).

5. **No Active Telemetry or Federated Retraining:**
   - The extension operates fully client-side. The backend endpoint `/telemetry/report` in `verity-cloud` is an unpersisted demo stub with no federated learning or retraining pipeline connected. Remote threat intelligence is opt-in and disabled by default.

## Loading the Extension
1. Open Chrome and navigate to `chrome://extensions`.
2. Enable **Developer mode** in the top right.
3. Click **Load unpacked** and select the `verity-extension` directory.
