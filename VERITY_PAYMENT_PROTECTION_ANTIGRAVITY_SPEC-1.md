# VERITY — PAYMENT WEBSITE PROTECTION
## Antigravity Implementation Specification

## Objective

Implement ONE complete, real, working security feature in Verity:

> **Payment Website Protection**

The feature detects suspicious or fake payment pages and payment phishing attempts before users submit sensitive payment information.

This must be a real browser implementation — not a mock, hardcoded demo, or simulated detector.

It must also detect newly created scam domains that are not yet present in reputation databases.

---

# 1. Core Detection Flow

```text
User opens payment website
        ↓
URL Analysis
        ↓
Redirect Analysis
        ↓
Domain / Brand Analysis
        ↓
Page / DOM Analysis
        ↓
Payment Intent Detection
        ↓
Payment-Field Detection
        ↓
Reputation Check
        ↓
Feature Vector
        ↓
Risk Engine
        ↓
ML Classifier (if a real trained model exists)
        ↓
Final Payment Risk Score
        ↓
ALLOW / WARN / BLOCK
```

Never make one weak signal equal "scam".

---

# 2. Payment Intent Detection

Detect whether the page is actually trying to perform a payment.

### Page signals

Look for combinations of:

- Pay now
- Make payment
- Checkout
- Complete payment
- Card payment
- Enter card details
- Payment verification
- Transaction
- Billing
- UPI
- Wallet
- Secure payment

### Form signals

Detect:

- payment form
- checkout form
- card form
- UPI form
- bank-transfer form
- wallet form

### Sensitive field presence

Detect the presence of:

- card number
- expiry date
- CVV
- UPI ID
- account number
- payment PIN
- OTP / verification code

IMPORTANT: Never collect the actual values.

Only produce features such as:

```text
card_field = true
cvv_field = true
otp_field = true
payment_form = true
```

Never store or transmit:

- card numbers
- CVV
- OTP values
- passwords
- PIN values
- bank credentials

---

# 3. Payment Brand Detection

Create a configurable list of legitimate payment providers and financial brands.

Examples:

- PayPal
- Stripe
- Razorpay
- PhonePe
- Google Pay
- Amazon Pay
- major banks
- other trusted payment providers

Create a central configuration instead of hardcoding provider logic throughout the extension.

Example:

```json
{
  "name": "ExamplePay",
  "officialDomains": [
    "examplepay.com"
  ],
  "aliases": [
    "Example Pay"
  ]
}
```

The detection logic must support adding providers without rewriting the detector.

---

# 4. Domain Verification

This is one of the most important signals.

Example:

```text
Claimed provider:
PayPal

Actual domain:
paypal-secure-verification.example
```

Produce:

```text
claimed_brand = PayPal
actual_domain = paypal-secure-verification.example
official_domain_match = false
```

Then calculate brand similarity.

Example:

```text
brand_similarity = 0.91
```

Do NOT consider a domain legitimate simply because the brand name appears in the hostname.

Validate against the official-domain allowlist.

---

# 5. URL Analysis

Use JavaScript and browser-provided URL information.

Extract:

- URL length
- hostname length
- path length
- query length
- subdomain count
- hyphen count
- digit count
- special-character count
- IP hostname
- punycode / IDN
- URL encoding
- suspicious TLD
- suspicious payment keywords
- login keywords
- verification keywords
- random-looking hostname
- suspicious path
- suspicious query parameters
- typosquatting indicators

Example:

```text
url_length = 91
subdomain_count = 2
has_punycode = false
has_ip_hostname = false
payment_keyword_count = 4
```

Do not block only because a payment keyword exists.

---

# 6. Redirect Analysis

Use the appropriate Chrome Manifest V3 navigation/network APIs.

Track the navigation chain per tab.

Example:

```text
message-link
    ↓
shortener
    ↓
tracking-domain
    ↓
unknown-payment-domain
    ↓
payment form
```

Track:

```text
redirect_count
unique_domains
shortener_used
cross_domain_redirect
final_domain
final_domain_changed
suspicious_intermediate_domain
```

A redirect alone is not malicious.

Legitimate:

```text
merchant.com
    ↓
trusted-payment-provider.com
```

must not automatically be blocked.

---

# 7. Payment Form Analysis

Use a content script to inspect the DOM.

Identify fields using:

- input `type`
- `name`
- `id`
- `autocomplete`
- associated labels
- nearby text
- form structure

Detect:

- card number
- expiry
- CVV
- UPI
- account number
- payment PIN
- OTP

Example output:

```json
{
  "payment_form": true,
  "card_field": true,
  "expiry_field": true,
  "cvv_field": true,
  "otp_field": false
}
```

Never read entered values.

---

# 8. Trusted Payment Provider Handling

A legitimate merchant can redirect to an external payment provider.

Example:

```text
merchant.com
    ↓
trusted-payment-provider.com
```

This should not automatically be blocked.

Maintain a configurable allowlist of legitimate payment-provider domains.

Distinguish:

```text
Known trusted provider
```

from:

```text
Unknown/lookalike provider
```

This is important for reducing false positives.

---

# 9. Suspicious Payment Scenario

Example:

```text
shop-example.example
        ↓
shortener
        ↓
payment-secure-example.example
```

Page contains:

```text
Secure Payment
Enter Card Number
Expiry
CVV
OTP
```

Provider is unknown and the domain resembles a trusted provider.

This should produce a high-risk result.

---

# 10. Reputation

Create a reputation module supporting a real threat-intelligence/reputation API when configured.

Possible states:

```text
SAFE
MALICIOUS
PHISHING
SUSPICIOUS
UNKNOWN
UNAVAILABLE
```

Important:

```text
UNKNOWN != SAFE
UNKNOWN != MALICIOUS
```

If the API is unavailable, the local detection pipeline must continue working.

Cache results appropriately.

Never send sensitive payment values to reputation services.

---

# 11. Brand-New Payment Scam Detection

This is a key requirement.

Example:

```text
new-payment-verification.example
```

Reputation:

```text
UNKNOWN
```

But Verity detects:

```text
Payment page                 ✓
Card fields                 ✓
CVV field                   ✓
OTP field                   ✓
Fake provider branding      ✓
Official domain mismatch    ✓
Suspicious URL              ✓
Suspicious redirect chain   ✓
```

The page should still be classified as high risk.

This is the core advantage over a blacklist-only approach.

---

# 12. Feature Vector

Create a normalized feature vector containing signals such as:

```text
payment_intent
payment_form
card_field
expiry_field
cvv_field
otp_field
official_provider_match
brand_similarity
domain_mismatch
url_length
subdomain_count
punycode
ip_hostname
redirect_count
shortener_used
suspicious_url
reputation
```

Example:

```json
{
  "payment_intent": 1,
  "payment_form": 1,
  "card_field": 1,
  "expiry_field": 1,
  "cvv_field": 1,
  "otp_field": 1,
  "official_provider_match": 0,
  "brand_similarity": 0.93,
  "domain_mismatch": 1,
  "redirect_count": 3,
  "shortener_used": 1,
  "suspicious_url": 1
}
```

---

# 13. Lightweight ML

The ML model should classify the extracted feature vector.

Recommended starting models:

1. Random Forest
2. XGBoost
3. Logistic Regression baseline

Do not introduce a large neural network or LLM for this feature.

Example real model output:

```text
payment_phishing_probability = 0.96
```

IMPORTANT:

Do not fake an ML probability.

If no trained model exists yet, implement the model interface but use the deterministic risk engine until a real trained model is integrated.

---

# 14. Risk Engine

Create one central module responsible for the final payment risk.

Illustrative initial weights:

```text
Known malicious reputation                +50
Fake payment-brand impersonation          +30
Official-domain mismatch                  +25
Card + CVV collection on suspicious site  +25
OTP collection on suspicious site         +20
Suspicious redirect chain                  +15
Punycode/homograph                         +20
Suspicious URL                             +10
Unknown provider/domain                    +5
```

These are starting engineering values, not final scientific weights.

Suggested starting levels:

```text
0–29      SAFE
30–59     SUSPICIOUS
60–79     HIGH RISK
80–100    DANGEROUS
```

Normalize the final score to 0–100.

Later calibrate the weights and thresholds against labeled test data.

---

# 15. Critical Rules

Some findings should override normal scoring.

Example:

```text
KNOWN MALICIOUS DOMAIN
+
PAYMENT/CREDENTIAL HARVESTING
=
BLOCK
```

Another:

```text
FAKE PAYMENT BRAND
+
CARD/CVV COLLECTION
+
DOMAIN MISMATCH
=
HIGH-CONFIDENCE PAYMENT PHISHING
```

The ML model must not downgrade a confirmed critical threat.

---

# 16. User Protection UI

For high-confidence payment phishing, block the page.

Example:

```text
🛑 VERITY BLOCKED THIS PAYMENT PAGE

HIGH-CONFIDENCE PAYMENT PHISHING

Risk Score
94 / 100

Detected:

✓ Fake payment provider
✓ Official domain mismatch
✓ Card information requested
✓ CVV requested
✓ Suspicious URL
✓ Suspicious redirect chain

Your payment information may be at risk.

[ Go Back ]
```

For medium risk:

```text
⚠️ PAYMENT PAGE LOOKS SUSPICIOUS

Risk Score: 67 / 100

[ Go Back ]
[ Continue Anyway ]
```

For low risk:

```text
✓ Payment page appears safe

Risk: 12 / 100
```

The UI must show evidence, not just:

```text
AI says dangerous
```

---

# 17. Explainability

The final result should contain structured reasons.

Example:

```json
{
  "riskScore": 91,
  "level": "dangerous",
  "reasons": [
    "Payment form detected",
    "Card and CVV fields detected",
    "Payment provider does not match official domain",
    "Suspicious redirect chain",
    "Domain resembles a trusted payment provider"
  ]
}
```

Use these reasons in the popup and block page.

---

# 18. Privacy

Payment protection must be privacy-first.

NEVER transmit or store:

```text
card numbers
CVV
OTP
passwords
PIN
bank credentials
```

Only process structural/security features.

Prefer local processing for:

- URL analysis
- DOM feature extraction
- brand matching
- risk scoring
- ML inference

---

# 19. Backend / GPU

The feature should work without a GPU.

A lightweight local architecture is:

```text
Chrome
 ↓
JavaScript feature extraction
 ↓
Rules
 ↓
Lightweight ML
 ↓
Risk
```

A backend can optionally provide:

- reputation APIs
- threat intelligence
- centralized model updates
- shared blocklists

The core payment detector must continue functioning if the backend is unavailable.

---

# 20. Suggested Module Structure

Reuse the existing Verity architecture first.

If equivalent modules do not exist, use a structure similar to:

```text
src/
  detectors/
    paymentDetector.js
    urlDetector.js
    redirectDetector.js
    brandDetector.js
    pageDetector.js

  risk/
    riskEngine.js

  reputation/
    reputationService.js

  ml/
    model.js

  config/
    paymentBrands.json
    trustedDomains.json

  content/
    paymentContentDetector.js

  background/
    navigationMonitor.js

  ui/
    warning/
    block/
```

Do not duplicate detection logic.

The risk engine should be the single source of truth for the final decision.

---

# 21. Antigravity Implementation Rules

Before modifying anything:

1. Inspect the existing Verity repository.
2. Understand the current Manifest V3 architecture.
3. Identify existing service worker, content scripts, messaging, rule engine, popup, overlay/block page, and storage.
4. Reuse working infrastructure.
5. Do not replace working systems unnecessarily.
6. Add payment protection as a modular feature.
7. Use real Chrome APIs and DOM inspection.
8. Do not create fake API responses.
9. Do not create fake ML probabilities.
10. Never log sensitive payment values.
11. Handle reputation API failure gracefully.
12. Avoid duplicate page analysis.
13. Keep the extension responsive.
14. Do not break existing Verity functionality.

---

# 22. Testing

Create controlled test cases.

## Test A — Legitimate payment

```text
Trusted merchant
+
trusted payment provider
+
normal payment fields
```

Expected:

```text
LOW RISK
ALLOW
```

## Test B — Fake payment provider

```text
Lookalike provider domain
+
payment form
+
card
+
CVV
```

Expected:

```text
HIGH RISK
BLOCK
```

## Test C — Brand-new scam

```text
Unknown domain
+
fake payment provider branding
+
card
+
CVV
+
OTP
```

Reputation:

```text
UNKNOWN
```

Expected:

```text
HIGH RISK / BLOCK
```

This test is essential.

## Test D — Legitimate provider redirect

```text
merchant
 ↓
trusted payment provider
```

Expected:

```text
ALLOW
```

## Test E — Suspicious redirect

```text
merchant
 ↓
shortener
 ↓
unknown domain
 ↓
fake payment page
```

Expected:

```text
HIGH RISK
```

---

# 23. Acceptance Criteria

The feature is complete only when:

- [ ] Real payment forms are detected.
- [ ] Card/CVV/OTP field presence is detected without reading values.
- [ ] Payment intent is detected.
- [ ] Trusted payment providers are configurable.
- [ ] Official domain mismatch is detected.
- [ ] Brand similarity works.
- [ ] Redirect chains are tracked.
- [ ] URL risk features are extracted.
- [ ] Reputation integration is supported.
- [ ] Unknown reputation does not disable detection.
- [ ] New/unlisted phishing pages can be detected using multiple local signals.
- [ ] Risk score is explainable.
- [ ] Warning UI works.
- [ ] Block UI works.
- [ ] Legitimate payment pages are not automatically blocked.
- [ ] Sensitive payment data is never stored/transmitted.
- [ ] Existing Verity features continue working.
- [ ] No fake ML result is used.
- [ ] Feature works when the reputation service is unavailable.

---

# 24. Strong Hackathon Demonstration

### Legitimate payment

```text
Trusted merchant
        ↓
Trusted payment provider
        ↓
Normal payment form
        ↓
🟢 ALLOW
```

### Fake payment

```text
New unknown domain
        ↓
Pretends to be trusted provider
        ↓
Card + CVV + OTP
        ↓
Official-domain mismatch
        ↓
Suspicious URL/redirect
        ↓
Reputation = UNKNOWN
        ↓
🔴 BLOCK
```

This demonstrates that Verity is not simply a blacklist.

It uses:

```text
Browser APIs
+
JavaScript
+
DOM analysis
+
URL analysis
+
Redirect analysis
+
Brand verification
+
Reputation
+
Rules
+
Optional lightweight ML
```

to make an explainable security decision.

---

# 25. Security Position

Do NOT claim:

- 100% payment scam detection
- 100% accuracy
- every new scam will be caught
- every unknown domain is malicious
- every payment page is dangerous
- HTTPS means safe
- a payment keyword means phishing

Correct project claim:

> **Verity combines payment-intent detection, domain/brand verification, redirect analysis, page-structure analysis, reputation intelligence and optional lightweight ML to identify high-confidence payment phishing attempts, including previously unknown domains.**

---

# 26. Final Instruction

Implement this feature completely in the existing Verity codebase.

First inspect the current implementation and reuse:

- Manifest V3 setup
- service worker
- content scripts
- messaging
- existing rule engine
- popup
- block overlay
- storage
- existing URL detection

Do not rebuild working systems.

Implement the feature in small, testable modules.

After implementation, manually test every acceptance case above.

If a browser API or permission is unavailable, use the closest supported Manifest V3 approach and document the limitation instead of inventing functionality.

The final result must be a real, working **Payment Website Protection** feature that can be demonstrated in Chrome.
