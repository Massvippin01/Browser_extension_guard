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

## Allowlist Semantics & Abuse Protection

Verity uses an independent allowlist (`config/legit_domains.json`) coupled with PSL registered-domain extraction (`shared/psl.js`). To ensure defense-in-depth, allowlist semantics are strictly bounded:

### What Being on the Allowlist Caps
- **Caution Cap (Score ≤ 40):** Verified benign and scheduled banking domains cap heuristic URL and DOM analysis scores at Caution (max 40). Legitimate password fields, login forms, payment gateways, and banking keywords on verified domains can never trigger a Block or Danger overlay.

### What Can STILL Cause a Block on an Allowlisted Domain
Being on the allowlist never grants carte blanche for malicious execution:
1. **Cross-Domain Credential Exfiltration (`SIG_CROSS_DOMAIN_CREDENTIAL_EXFIL`):** If an allowlisted page contains a credential or login form whose target `action` posts to a different registered domain, Verity triggers an immediate **Block (Score: 85)**.
   > **Coverage Boundary:** Detection inspects top-level HTML `<form action="...">` attributes at DOM scan time. It does **NOT** cover asynchronous JavaScript network exfiltration (`fetch()`, `XMLHttpRequest`, `navigator.sendBeacon()`, WebSockets) or credentials entered into cross-origin `<iframe>` elements.
2. **Dangerous File Downloads (`DOWNLOAD_CHROME_DANGEROUS`):** If a downloaded file is flagged as dangerous or malicious by Chrome's native security engine, Verity triggers a **Block (Score: 90)** regardless of the host domain.
3. **Malware from Untrusted Origins (`DOWNLOAD_SOURCE_MALICIOUS` + `DOWNLOAD_EXECUTABLE`):** Executables originating from unverified or malicious redirect chains override the allowlist cap.
4. **Active Threat Intelligence (`THREAT_INTEL_MALWARE`):** Known malware indicators override the allowlist cap.

### Explicit Allowlist Exclusions
- **PSL Private Section Platforms:** Domains matching the Public Suffix List (PSL) `PRIVATE` section (`*.github.io`, `*.pages.dev`, `*.firebaseapp.com`, `*.web.app`, `*.workers.dev`, `*.azurewebsites.net`, etc.) **never inherit** parent domain allowlist status, as private suffixes establish independent multi-tenant boundaries.
- **Shared User-Content Paths:** Multi-tenant services sharing a root domain by path (`sites.google.com`, `docs.google.com/forms`, `forms.gle`, `drive.google.com`, `notion.site`, `s3.amazonaws.com`, `storage.googleapis.com`, `blob.core.windows.net`) do not inherit allowlist protection on user-generated paths.

## Known Limitations

1. **ML Model Baseline:**
   - The shipped baseline ONNX model (`phishing_model.onnx`) achieves only 42.0% live accuracy on real-world web traffic due to reliance on 8 structural features without DOM context. Per the ablation decision rule, `ML_WEIGHT = 0` is enforced in the shipping engine.

2. **English-Centric Heuristics:**
   - Text heuristics for detecting social engineering, KYC urgency, utility cutoffs, and payment traps currently inspect English keywords only (e.g., "disconnected", "cashback", "urgent notice"). Sites using Hindi, other Indian regional languages, or non-English text bypass these keyword heuristics.

3. **Desktop Chromium Only:**
   - The extension relies on Manifest V3 desktop APIs (`chrome.webNavigation`, `chrome.webRequest`, `chrome.downloads`, `chrome.offscreen`) and is supported exclusively on desktop Chromium browsers (Chrome, Brave, Edge).

4. **Credential Exfiltration Boundaries:**
   - Credential exfiltration analysis scans top-level HTML form action attributes (`form.action`). It does not hook or intercept dynamic JavaScript runtime network calls (`fetch`, `XMLHttpRequest`, `sendBeacon`, WebSockets) and does not scan cross-origin iframes.

5. **No Active Telemetry or Federated Retraining:**
   - The extension operates fully client-side. The backend endpoint `/telemetry/report` in `verity-cloud` is an unpersisted demo stub with no federated learning or retraining pipeline connected. Remote threat intelligence is opt-in and disabled by default.

## Loading the Extension
1. Open Chrome and navigate to `chrome://extensions`.
2. Enable **Developer mode** in the top right.
3. Click **Load unpacked** and select the `verity-extension` directory.
