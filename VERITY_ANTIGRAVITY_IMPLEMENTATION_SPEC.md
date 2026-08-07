# VERITY — Security Detection & ML Implementation Specification

## 1. Goal

Verity is a Chrome Manifest V3 browser-protection extension designed to detect phishing, scam, malicious, impersonation, banking/payment fraud, and suspicious websites in real time.

The system must NOT rely on a single blacklist, a single keyword, or a single ML prediction.

Use a **hybrid detection architecture**:

```text
Website
  ↓
Chrome Extension
  ↓
Feature Extraction
  ↓
URL + Redirect + Domain + Page + Brand + Reputation Analysis
  ↓
Feature Vector
  ↓
Lightweight ML Classifier
  ↓
Rule Engine + Critical Rules + ML
  ↓
Final Risk Score
  ↓
ALLOW / WARN / BLOCK
```

---

# 2. Core Detection Layers

## 2.1 URL Analysis

### Purpose
Analyze the URL before relying on page content.

### Extract these signals

- URL length
- Hostname length
- Path length
- Query length
- Number of subdomains
- Number of dots
- Number of hyphens
- Number of special characters
- Number of digits
- IP address used as hostname
- Suspicious TLD
- URL encoding
- `@` character
- Punycode / IDN
- Excessive subdomains
- Random-looking hostname
- Suspicious path keywords
- Suspicious query parameters
- Login-related keywords
- Verification-related keywords
- Payment-related keywords
- Banking-related keywords
- Typosquatting indicators
- Brand similarity

### Important

Do NOT make:

```text
"contains bank" = malicious
```

or:

```text
".xyz" = malicious
```

These are only signals.

Each signal becomes a feature.

---

# 3. Redirect Analysis

## Purpose

Detect suspicious navigation chains, shortened URLs, tracking chains, and final destinations that differ from the initial link.

Example:

```text
bit.ly/abc
    ↓
tracker.example
    ↓
random-domain.xyz
    ↓
fake-bank-login.xyz
```

## Features

Track:

- Redirect count
- Unique domains
- Cross-domain redirects
- Shortener usage
- Final destination
- Intermediate domains
- Destination domain reputation
- Whether final destination differs from expected destination
- Suspicious TLDs in the chain
- Known malicious domains in the chain

## Implementation

Use Chrome Manifest V3 navigation/network APIs permitted by the extension's permissions.

Maintain a short-lived navigation record per tab:

```text
tabId
initialURL
redirectChain[]
currentURL
timestamp
```

Do not automatically classify every redirect as malicious.

Example:

```text
google.com
  ↓
accounts.google.com
```

is normal.

But:

```text
bit.ly
  ↓
random-domain.xyz
  ↓
fake-bank-login.xyz
```

should produce multiple risk signals.

---

# 4. Domain & Infrastructure Analysis

## Local signals

Can be calculated without ML:

- Domain structure
- TLD
- Subdomain count
- Punycode
- IP hostname
- Domain entropy/randomness
- Brand similarity
- Suspicious naming patterns

## External signals

The browser does not directly provide everything.

For:

- Domain registration age
- WHOIS information
- Known malicious IP
- Threat reputation
- Historical abuse
- DNS reputation

use a reputation/domain intelligence API when available.

Cache results to reduce latency and API usage.

`unknown` must NOT automatically mean malicious.

---

# 5. Brand Impersonation

## Purpose

Detect fake websites pretending to be trusted companies.

Maintain a protected brand list:

```text
Google
Microsoft
Apple
PayPal
Amazon
Meta
Netflix
Banks
Payment providers
Crypto exchanges
etc.
```

For each detected domain:

1. Normalize the hostname.
2. Compare it against protected domains.
3. Calculate string similarity.
4. Apply domain-specific rules.
5. Produce a `brand_similarity` feature.

Example:

```text
paypal.com
paypa1-security-login.xyz
```

Potential result:

```text
brand_similarity = 0.92
```

Use algorithms such as:

- Levenshtein/edit distance
- Character substitutions
- Token similarity
- Normalized hostname comparison
- Punycode/homograph detection

Do NOT block solely because similarity is high.

Combine it with other signals.

---

# 6. Page / DOM Analysis

Use a Chrome content script to inspect the loaded page.

## Detect

- Forms
- Password inputs
- Email inputs
- Username fields
- OTP fields
- PIN fields
- Card number fields
- CVV fields
- Expiry fields
- UPI/payment fields
- Wallet recovery/seed phrase requests
- Hidden forms
- Iframes
- External scripts/resources
- Suspicious visible text
- Urgency/threat language
- Fake CAPTCHA/update prompts
- Suspicious download behavior

Example:

```text
password_fields = 1
otp_fields = 1
payment_fields = 0
forms = 1
financial_keywords = 4
```

These become ML/risk-engine features.

---

# 7. Banking & Payment Protection

This is a high-priority detection category.

## Detect financial intent

Signals include:

### Identity

- Bank branding
- Payment-provider branding
- Financial-service branding

### Credentials

- Customer ID
- Username
- Password
- PIN

### Authentication

- OTP
- Verification code
- Security code

### Payment

- Card number
- Expiry
- CVV
- UPI/payment information
- Account details

## Strong phishing combination

A combination such as:

```text
Financial brand
+
Unrelated/lookalike domain
+
Login form
+
Password field
+
OTP field
```

should produce a high risk score.

Do NOT block merely because a page contains the word `bank`.

Example:

```text
"How to protect your bank account"
```

is not phishing by itself.

---

# 8. Reputation / Threat Intelligence

Use external reputation intelligence to detect already-known threats.

Possible results:

```text
known malicious
phishing
malware
scam
suspicious
safe
unknown
```

Use reputation as one feature.

Do not treat:

```text
unknown = safe
```

and do not necessarily treat:

```text
unknown = dangerous
```

Unknown websites should be evaluated using behavioral and structural signals.

Cache reputation responses locally.

---

# 9. Detecting Brand-New Scam Websites

A newly launched scam may not be present in a reputation database.

Therefore Verity must detect **previously unseen threats** through characteristics.

Example:

```text
secure-hdfc-verification.xyz

Domain:
- new/unknown
- resembles protected financial brand
- suspicious TLD

URL:
- login/verification keywords

Page:
- bank branding
- password form
- OTP field

Navigation:
- suspicious redirect chain
```

No single feature proves phishing.

Together they create strong evidence.

This is where the ML classifier is useful.

---

# 10. Lightweight ML Model

## Purpose

The ML model combines extracted features and learns patterns from labeled phishing/benign data.

Recommended starting models:

1. Random Forest
2. XGBoost
3. Logistic Regression as baseline

Do NOT start with a large neural network or LLM.

The model receives a feature vector such as:

```text
url_length
subdomain_count
redirect_count
shortener_used
punycode
ip_hostname
suspicious_keyword_count
brand_similarity
password_form
otp_form
payment_form
financial_keyword_count
domain_age
reputation_score
etc.
```

Example:

```text
[
  83,
  3,
  4,
  1,
  0,
  0,
  5,
  0.92,
  1,
  1,
  0,
  4,
  12,
  0.5
]
```

The model outputs a probability/risk estimate:

```text
phishing_probability = 0.94
```

The model is for **inference**, not training, inside the user's browser.

Training happens separately.

---

# 11. Does ML Need a Backend?

Not necessarily.

For a lightweight tabular model:

```text
Chrome Extension
    ↓
Feature Extraction
    ↓
Local ML Model
    ↓
Risk
```

can work without a backend or GPU.

A backend can be added for:

- Threat intelligence
- Centralized reputation
- Model updates
- Larger models
- Shared blocklists
- Analytics, if privacy-appropriate

A GPU server is NOT required for the lightweight model.

---

# 12. Risk Scoring

Do not let one weak signal determine the verdict.

Use weighted evidence.

Illustrative starting contributions:

```text
Known malicious reputation          +50
Strong brand impersonation          +30
Suspicious redirect chain           +20
Credential/payment collection       +15
Punycode/homograph                  +20
Suspicious URL structure            +15
Suspicious page language            +10
Unknown/new domain                   +5
```

Example thresholds:

```text
0–29     LOW / SAFE
30–59    SUSPICIOUS
60–79    HIGH RISK
80+      DANGEROUS
```

These are starting values only.

They must be calibrated using a labeled test dataset.

---

# 13. Critical Rules / Overrides

Some signals are strong enough to bypass normal scoring.

Example:

```text
Confirmed known phishing URL
        ↓
Immediate BLOCK
```

or:

```text
Known malicious domain
+
credential harvesting
        ↓
Immediate BLOCK
```

The ML model should not override a confirmed critical security finding.

---

# 14. ML + Rules Fusion

Final decision should combine:

```text
Deterministic rules
+
ML probability
+
Reputation
+
Critical security signals
```

Example:

```text
URL analysis       → 22
Redirect analysis  → 18
Page analysis      → 15
Brand analysis     → 25
Reputation         → 10
ML prediction      → 94%
```

Final result:

```text
RISK = HIGH / DANGEROUS
ACTION = BLOCK
```

The exact mathematical fusion should be implemented centrally in one risk-engine module.

---

# 15. Protection Levels

## SAFE

Allow normally.

## SUSPICIOUS

Show warning page/popup.

Provide:

- Risk explanation
- Detected signals
- Go Back
- Continue Anyway

## HIGH RISK

Show full-page warning.

Require explicit user action before continuing.

## DANGEROUS

Block the entire page/navigation.

Show:

```text
🛑 Dangerous Website Blocked

Why:
- Brand impersonation
- Suspicious redirect chain
- Credential collection
- Poor reputation

Risk: 94/100

[Go Back]
```

---

# 16. Extension Architecture

Recommended MV3 components:

```text
manifest.json

service_worker.js
    ↓
Navigation monitoring
Risk orchestration
Rule engine
Messaging
State

content_script.js
    ↓
DOM analysis
Form detection
Page-text signals
Behavioral signals

feature-extractor.js
    ↓
Normalizes all observations

brand-detector.js
    ↓
Brand similarity

reputation.js
    ↓
Threat intelligence + cache

ml-model/
    ↓
Lightweight model inference

risk-engine.js
    ↓
Rules + ML + reputation + critical overrides

warning/
block/
    ↓
User-facing protection UI

popup/
    ↓
Current website status
Risk score
Reasons
```

Keep the detection logic modular so each layer can be tested independently.

---

# 17. Performance Requirements

The extension should:

- Analyze URL signals immediately.
- Avoid blocking the browser thread with heavy work.
- Cache reputation results.
- Limit repeated analysis for the same page.
- Avoid sending unnecessary browsing data externally.
- Run lightweight ML locally when practical.
- Fail safely when an external reputation service is unavailable.
- Keep detection latency low enough that normal browsing feels instant.

---

# 18. Privacy

Prefer local processing for:

- URL feature extraction
- URL heuristics
- Brand similarity
- DOM feature extraction
- ML inference
- Risk scoring

Only send data to external services when necessary.

Do not send passwords, OTPs, card numbers, or sensitive form values to a backend.

For page analysis, detect the **presence/type** of sensitive fields rather than collecting their values.

---

# 19. Testing Strategy

Create test categories:

### Benign

- Google
- Microsoft
- Amazon
- Normal blogs
- Normal e-commerce
- Normal banking pages
- Normal payment pages

### Known malicious

- Known phishing URLs
- Known scam domains
- Malware test URLs where safe/legal test environments are available

### Synthetic/unseen phishing

Create controlled test pages with:

- Lookalike domains
- Fake bank login
- Fake payment page
- Fake OTP page
- Suspicious redirects
- Shortened URLs
- Punycode/homograph domains

### Measure

Do not claim 100% accuracy.

Measure:

- Precision
- Recall
- F1 score
- False positive rate
- False negative rate
- Detection latency

For security, false negatives and false positives both matter.

---

# 20. Recommended Development Order

## Stage 1
URL parser + deterministic rules + block/warning UI.

## Stage 2
Redirect tracking.

## Stage 3
Page/DOM analysis.

## Stage 4
Brand impersonation.

## Stage 5
Banking/payment detection.

## Stage 6
Reputation/threat-intelligence integration.

## Stage 7
Prepare labeled dataset.

## Stage 8
Train Random Forest/XGBoost and evaluate against a baseline.

## Stage 9
Export/convert model for lightweight local inference.

## Stage 10
Integrate ML with the feature vector.

## Stage 11
Implement final risk fusion and critical overrides.

## Stage 12
Calibrate thresholds and test false positives/false negatives.

## Stage 13
Polish the warning/block UI and explanations.

---

# 21. Judge Explanation

Use this explanation:

> "Verity uses a hybrid browser-security architecture. The Chrome extension uses browser APIs and JavaScript to extract measurable signals from URLs, navigation chains and webpage DOM content. We analyze domain structure, redirects, brand impersonation, financial intent and reputation. These signals become a feature vector for a lightweight ML classifier. The ML prediction is combined with deterministic security rules and critical threat intelligence in an explainable risk engine. Based on the final risk, Verity allows, warns or blocks the website."

---

# 22. Important Technical Limitations

Do NOT claim:

- 100% detection
- 100% accuracy
- Every new scam will be detected
- HTTPS means safe
- A new domain means malicious
- Bitly means malicious
- A keyword means phishing
- ML alone can determine whether a site is dangerous

Correct positioning:

> Verity uses multiple independent signals to increase detection accuracy and identify both known and previously unseen phishing patterns.

---

# 23. Final System

```text
                     WEBSITE
                        ↓
              ┌─────────────────┐
              │ Chrome MV3      │
              │ Extension       │
              └────────┬────────┘
                       ↓
             ┌──────────────────┐
             │ Feature          │
             │ Extraction       │
             └────────┬─────────┘
                      ↓
       ┌──────────────┼──────────────┐
       ↓              ↓              ↓
      URL          REDIRECT         PAGE
    ANALYSIS       ANALYSIS       ANALYSIS
       ↓              ↓              ↓
       └──────────────┼──────────────┘
                      ↓
              DOMAIN + BRAND
                  ANALYSIS
                      ↓
              REPUTATION CHECK
                      ↓
               FEATURE VECTOR
                      ↓
             LIGHTWEIGHT ML
                      ↓
                RISK SCORE
                      ↓
             ┌────────┴────────┐
             ↓                 ↓
        RULE ENGINE       CRITICAL RULES
             └────────┬────────┘
                      ↓
              FINAL DECISION
                      ↓
          ┌───────────┼───────────┐
          ↓           ↓           ↓
        ALLOW        WARN        BLOCK
```

**Implementation principle:** Build the deterministic detection pipeline first. Add ML only after the feature extraction pipeline works and you have labeled data. This makes the system testable, explainable, and easier to debug.
