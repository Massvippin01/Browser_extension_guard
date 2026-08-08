# VERITY — URL SHORTENER & REDIRECT SAFETY TRACKER
## Detailed Feature Specification + Antigravity Implementation Plan

## 1. Objective

Implement a real browser-security feature that detects malicious destinations hidden behind URL shorteners and redirect chains.

Examples:

- `bit.ly/...`
- `tinyurl.com/...`
- `t.co/...`
- `short.io/...`
- `rebrand.ly/...`
- other configurable shorteners

**Important:** A URL shortener itself is NOT malicious.

The system must determine whether the **destination and redirect behavior** are suspicious.

---

# 2. Core Idea

Safe:

```text
bit.ly/abc
    ↓
trusted.example.com
```

Suspicious:

```text
bit.ly/abc
    ↓
unknown-example.xyz
```

Dangerous:

```text
bit.ly/abc
    ↓
tracking-example.xyz
    ↓
fake-bank-login.xyz
    ↓
payment form
```

Therefore:

```text
Shortener Detection
        ↓
Redirect Tracking
        ↓
Intermediate Domain Analysis
        ↓
Final Destination Analysis
        ↓
Brand / URL / Reputation / Page Analysis
        ↓
Existing Verity Risk Engine
        ↓
ALLOW / WARN / BLOCK
```

---

# 3. What the Feature Detects

Track:

- known URL shorteners
- redirect count
- unique domains
- cross-domain redirects
- intermediate domains
- final destination
- suspicious intermediate domains
- suspicious final domains
- HTTPS → HTTP downgrade
- redirect loops
- excessive redirect chains
- brand impersonation
- domain mismatch
- malicious reputation
- phishing reputation
- payment/credential harvesting on the final page

---

# 4. Known Shortener Database

Create a configurable file:

```text
config/urlShorteners.json
```

Example:

```json
{
  "shorteners": [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "short.io",
    "rebrand.ly",
    "cutt.ly"
  ]
}
```

Do not hardcode shortener logic throughout the extension.

The database should be easy to update.

IMPORTANT:

```text
shortenerDetected = true
```

does NOT mean:

```text
dangerous = true
```

It is only one security signal.

---

# 5. Redirect Tracking

Use the existing Chrome Manifest V3 navigation infrastructure if Verity already has it.

Track navigation per tab.

Example session:

```javascript
{
  tabId: 12,
  initialUrl: "https://bit.ly/abc",
  urls: [
    "https://bit.ly/abc",
    "https://tracking.example",
    "https://fake-bank.example"
  ],
  domains: [
    "bit.ly",
    "tracking.example",
    "fake-bank.example"
  ],
  redirectCount: 2,
  crossDomainRedirectCount: 2,
  shortenerDetected: true,
  startTime: 1780000000000,
  lastUpdate: 1780000002000
}
```

The session must be temporary and cleaned up.

---

# 6. Per-Tab Session Lifecycle

Create a redirect session when navigation begins.

Track until:

- navigation completes
- navigation is replaced
- tab closes
- timeout occurs
- session becomes stale

Clean up state when finished.

Do not permanently record the user's entire browsing history.

---

# 7. Redirect Chain

Example:

```text
bit.ly/abc
    ↓
tracking.example
    ↓
redirect.example.net
    ↓
fake-bank-login.xyz
```

Represent it as:

```json
{
  "initialUrl": "https://bit.ly/abc",
  "redirectCount": 3,
  "domains": [
    "bit.ly",
    "tracking.example",
    "redirect.example.net",
    "fake-bank-login.xyz"
  ],
  "finalUrl": "https://fake-bank-login.xyz"
}
```

The final destination is the most important object, but intermediate domains also matter.

---

# 8. Cross-Domain Detection

Compare consecutive destinations.

Example:

```text
bit.ly
 ↓
tracking.example
```

Cross-domain:

```text
true
```

But:

```text
tracking.example/page1
 ↓
tracking.example/page2
```

Cross-domain:

```text
false
```

Cross-domain redirects are a supporting signal, not proof of malicious activity.

---

# 9. Excessive Redirect Detection

Example:

```text
bit.ly
 ↓
a.com
 ↓
b.com
 ↓
c.com
 ↓
d.com
 ↓
e.com
 ↓
fake-login.xyz
```

Generate:

```text
excessiveRedirects = true
```

Use a configurable maximum chain length.

Do NOT automatically block solely because the chain is long.

Legitimate services can have multiple redirects.

---

# 10. Intermediate Domain Analysis

Analyze every unique domain in the chain.

Check:

- reputation
- suspicious TLD
- IP hostname
- punycode
- random-looking hostname
- excessive subdomains
- suspicious keywords
- brand impersonation
- known phishing indicators

Example:

```text
bit.ly
   ↓
random-security.xyz
   ↓
trusted-site.com
```

Even if the final destination is legitimate, the intermediate domain should be recorded as a security signal.

---

# 11. Final Destination Analysis

Once the final destination is known, reuse the existing Verity detectors.

Run:

```text
URL Detector
Brand Detector
Reputation Service
Payment Detector
Page Detector
Risk Engine
```

Example:

```text
bit.ly/abc
    ↓
hdfc-login-security.xyz
```

Final-page analysis may detect:

```text
brandMismatch = true
suspiciousUrl = true
paymentIntent = true
cardField = true
cvvField = true
otpField = true
```

The redirect tracker adds:

```text
shortenerDetected = true
redirectCount = 1
crossDomainRedirectCount = 1
```

The central risk engine combines everything.

---

# 12. HTTPS Downgrade

Detect:

```text
https://trusted.example
        ↓
http://suspicious.example
```

Set:

```text
httpsDowngrade = true
```

This increases risk.

But:

```text
HTTP = malicious
```

must NOT be assumed.

It is only a supporting signal.

An upgrade:

```text
http://example.com
        ↓
https://example.com
```

is normal and should not increase risk.

---

# 13. Redirect Loop Detection

Example:

```text
a.com
 ↓
b.com
 ↓
a.com
 ↓
b.com
```

Detect:

```text
redirectLoop = true
```

Terminate tracking safely.

Use:

```text
MAX_REDIRECTS
```

and session timeouts so the extension cannot track indefinitely.

---

# 14. Reputation

Each important domain can be checked against the existing reputation service.

Possible results:

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

If the reputation service fails, local analysis must continue.

Use caching and deduplication to avoid unnecessary requests.

---

# 15. Brand Impersonation

Reuse Verity's existing brand database.

Example:

```text
bit.ly/abc
    ↓
hdfc-login-security.xyz
```

If the destination claims to be HDFC Bank:

```text
brandSimilarity = high
officialDomainMatch = false
```

This should increase risk.

Never assume:

```text
brand name in hostname = legitimate
```

or:

```text
brand name in hostname = malicious
```

Validate against official domains.

---

# 16. Payment Scam Example

Example chain:

```text
bit.ly/secure-payment
        ↓
tracking-example.xyz
        ↓
hdfc-login-security.xyz
```

Final page contains:

```text
Card Number
Expiry
CVV
OTP
```

Signals:

```text
shortenerDetected = true
redirectCount = 2
crossDomainRedirectCount = 2
suspiciousIntermediateDomain = true
brandMismatch = true
paymentIntent = true
cardField = true
cvvField = true
otpField = true
```

Expected:

```text
🔴 DANGEROUS
```

The existing Payment Protection feature should supply the payment signals.

Do not duplicate its logic.

---

# 17. Safe Shortener Example

```text
bit.ly/official-store
        ↓
trusted-store.example
```

Signals:

```text
shortener = true
redirectCount = 1
trustedFinalDomain = true
reputation = SAFE
```

Expected:

```text
🟢 ALLOW
```

The user should not be blocked simply because Bitly was used.

---

# 18. Unknown Destination Example

```text
bit.ly/abc123
        ↓
unknown-example.xyz
```

If the only evidence is:

```text
shortener = true
unknownDomain = true
```

do NOT call it dangerous.

Possible result:

```text
🟡 SUSPICIOUS
```

or an appropriate neutral/unknown state.

The final classification must depend on the central risk engine.

---

# 19. Known Malicious Destination

```text
bit.ly/abc
        ↓
known-malicious.example
```

If reputation says:

```text
MALICIOUS
```

this is a critical signal.

Expected:

```text
🛑 BLOCK
```

A confirmed malicious result should not be downgraded by weak safe signals.

---

# 20. Redirect Risk Feature Object

Send a normalized object to the existing risk engine:

```json
{
  "analysisContext": "redirect",
  "shortenerDetected": true,
  "redirectCount": 3,
  "uniqueDomainCount": 4,
  "crossDomainRedirectCount": 3,
  "excessiveRedirects": true,
  "suspiciousIntermediateDomain": true,
  "httpsDowngrade": false,
  "redirectLoop": false,
  "finalDomainSuspicious": true,
  "finalDomainMalicious": false,
  "brandMismatch": true
}
```

Do not create a separate redirect scoring system.

---

# 21. Central Risk Engine

The architecture must remain:

```text
Redirect Tracker
       ↓
Redirect Features
       ↓
Existing Risk Engine
       ↓
Final Risk
```

Not:

```text
Redirect Tracker
       ↓
Separate Redirect Risk Engine
```

This prevents inconsistent decisions across Verity.

---

# 22. Example Risk Decision

Input:

```text
shortenerDetected = true
redirectCount = 3
crossDomainRedirects = 3
suspiciousIntermediateDomain = true
brandMismatch = true
paymentIntent = true
cardField = true
cvvField = true
reputation = UNKNOWN
```

Central engine:

```text
Risk Score: 91/100
Level: DANGEROUS
Action: BLOCK
```

The UI must display the result generated by the risk engine.

Do not hardcode the number in the UI.

---

# 23. Warning UI

For medium risk:

```text
⚠️ SUSPICIOUS REDIRECT

This link redirects through multiple domains.

Initial URL:
bit.ly/AbC123

Final destination:
unknown-example.xyz

Redirects: 2

Risk: 62/100

[ ← Go Back ]
[ Continue ]
```

---

# 24. Dangerous Block UI

For high-confidence threats:

```text
🛑 DANGEROUS REDIRECT BLOCKED

The shortened link leads to a
high-risk website.

Redirect chain:

bit.ly/AbC123
      ↓
tracking-example.xyz
      ↓
fake-bank-login.xyz

Detected:

✓ URL shortener
✓ Multiple redirects
✓ Suspicious intermediate domain
✓ Bank impersonation
✓ Domain mismatch
✓ Payment information requested

Risk: 94/100

[ Go Back ]
```

Do not show sensitive payment values.

---

# 25. Redirect Chain Visualization

This is an important judge-facing feature.

Show:

```text
🔗 REDIRECT ANALYSIS

1. bit.ly
       ↓
2. tracking-example.xyz
       ↓
3. fake-bank-login.xyz
```

Each domain can have a status:

```text
🟢 trusted
🟡 unknown
🔴 suspicious/malicious
```

This makes the detection process easy to understand.

---

# 26. Pre-Navigation vs Post-Navigation

The feature should work in two stages.

## Stage 1 — Navigation Tracking

Track:

```text
shortener
 ↓
redirect
 ↓
redirect
 ↓
final URL
```

## Stage 2 — Deep Page Analysis

After the final page loads:

```text
final URL
 ↓
DOM analysis
 ↓
payment detection
 ↓
credential detection
 ↓
brand verification
 ↓
final risk
```

This is stronger than attempting to rely only on the shortened URL.

---

# 27. Important Browser Implementation Rule

Do NOT automatically resolve every shortened link with:

```javascript
fetch(shortenedUrl)
```

Reasons:

- redirects may behave differently outside actual browser navigation
- CORS restrictions
- tracking side effects
- privacy concerns
- unnecessary network requests
- possible malicious content

Prefer the user's real navigation and supported Chrome navigation APIs.

---

# 28. Search Result Integration

This feature should integrate with Verity's Search Result Safety feature.

Example:

```text
Google result:

HDFC Secure Payment
https://bit.ly/abc123

🟡 SHORTENED LINK
```

User clicks:

```text
bit.ly
 ↓
tracking.example
 ↓
fake-bank-login.xyz
```

Redirect tracker detects the chain.

Then:

```text
🔴 BLOCKED
```

Full Verity chain:

```text
Search Protection
       ↓
Shortener Detection
       ↓
Redirect Tracking
       ↓
Destination Analysis
       ↓
Page / Payment Protection
```

---

# 29. Optional Hover Preview

When the user hovers over a shortened URL, Verity may display:

```text
🔗 Verity

Shortened URL detected.

Destination:
Not yet verified

Security checks will run during navigation.
```

Do not automatically visit the URL on hover.

---

# 30. Performance

The tracker must be lightweight.

Use:

- session-based tracking
- deduplication
- caching
- bounded redirect chains
- asynchronous reputation checks
- cleanup timers

Avoid:

- continuous scanning
- unlimited redirect history
- repeated reputation requests
- expensive ML inference for every navigation event

---

# 31. Privacy

Never collect:

```text
passwords
OTP
CVV
card numbers
bank credentials
```

The redirect feature only needs:

```text
URLs
domains
navigation metadata
security features
risk results
```

Do not permanently store complete browsing history.

Redirect sessions should be short-lived.

---

# 32. Suggested Architecture

Reuse existing Verity modules.

If equivalent modules do not already exist:

```text
src/
  redirect/
    redirectTracker.js
    redirectSession.js
    redirectAnalyzer.js
    shortenerDetector.js
    redirectRiskFeatures.js

  config/
    urlShorteners.json

  ui/
    redirectWarning.js
    redirectDetails.js
```

Existing modules remain authoritative:

```text
src/
  detectors/
    urlDetector.js
    brandDetector.js
    paymentDetector.js
    pageDetector.js

  reputation/
    reputationService.js

  risk/
    riskEngine.js

  navigation/
    navigationMonitor.js
```

Do not duplicate functionality.

---

# 33. Testing

## Test A — Safe Shortener

```text
bit.ly
 ↓
trusted official domain
```

Expected:

```text
🟢 ALLOW
```

## Test B — Unknown Destination

```text
bit.ly
 ↓
unknown-example.xyz
```

Expected:

```text
🟡 SUSPICIOUS
```

only if there is enough supporting evidence.

## Test C — Malicious Destination

```text
bit.ly
 ↓
known-malicious-test-domain
```

Expected:

```text
🔴 BLOCK
```

## Test D — Multi-Hop Scam

```text
bit.ly
 ↓
tracking.xyz
 ↓
redirect.xyz
 ↓
fake-bank-login.xyz
```

Expected:

```text
🔴 HIGH RISK / BLOCK
```

## Test E — Payment Scam

```text
bit.ly
 ↓
fake-payment.xyz
 ↓
payment form
 ↓
card + CVV + OTP
```

Expected:

```text
🔴 BLOCK
```

## Test F — HTTPS Downgrade

```text
https://safe.example
 ↓
http://suspicious.example
```

Expected:

```text
risk increase
```

but not automatically malicious.

## Test G — Redirect Loop

```text
a.com
 ↓
b.com
 ↓
a.com
 ↓
b.com
```

Expected:

```text
loop detected
session terminated safely
```

## Test H — Normal Website

```text
example.com
```

Expected:

```text
no unnecessary redirect warning
```

---

# 34. Acceptance Criteria

The feature is complete only when:

- [ ] Known URL shorteners are configurable.
- [ ] Shortener detection does not automatically mean malicious.
- [ ] Redirect chains are tracked.
- [ ] Redirect count is calculated.
- [ ] Unique domains are calculated.
- [ ] Cross-domain redirects are detected.
- [ ] Intermediate domains are analyzed.
- [ ] Final destination is identified.
- [ ] HTTPS downgrade is detected.
- [ ] Redirect loops are detected.
- [ ] Excessive redirect chains are handled.
- [ ] Reputation can be checked.
- [ ] Final destination uses existing URL/domain analysis.
- [ ] Brand impersonation can increase risk.
- [ ] Payment detection can increase risk.
- [ ] Existing risk engine determines the final action.
- [ ] Safe shorteners are not blocked.
- [ ] Unknown domains are not automatically treated as malicious.
- [ ] Known malicious destinations can be blocked.
- [ ] Warning UI displays the redirect chain.
- [ ] Block UI explains the reasons.
- [ ] No sensitive information is collected.
- [ ] Sessions are cleaned up.
- [ ] Performance remains acceptable.
- [ ] Existing Verity features continue working.

---

# 35. Judge Demonstration

## Demonstration 1 — Legitimate Shortener

```text
bit.ly/legitimate-test
```

Chain:

```text
bit.ly
 ↓
trusted-domain.example
```

Result:

```text
🟢 SAFE
```

Explain:

> "Verity does not treat URL shorteners as malicious. It evaluates where they actually lead."

---

## Demonstration 2 — Phishing Shortener

Controlled test:

```text
bit.ly/phishing-test
```

Chain:

```text
bit.ly
 ↓
tracking.example
 ↓
fake-bank-login.example
```

Verity:

```text
🛑 DANGEROUS REDIRECT BLOCKED
```

Reasons:

```text
✓ URL shortener
✓ Multiple redirects
✓ Suspicious intermediate domain
✓ Bank impersonation
✓ Domain mismatch
```

---

# 36. Judge Explanation

Use:

> **"Attackers can hide malicious destinations behind URL shorteners. Verity does not simply trust the visible shortened URL. It tracks the actual browser navigation chain, identifies intermediate domains, analyzes the final destination, and combines those signals with our existing URL, brand, reputation and page protection. This allows us to detect a malicious destination even when the initial link looks harmless."**

---

# 37. Why This Feature Matters

Without redirect tracking:

```text
bit.ly/abc123
      ↓
Looks harmless
      ↓
User opens it
      ↓
Fake bank
```

With Verity:

```text
bit.ly/abc123
      ↓
Redirect tracking
      ↓
Final destination discovered
      ↓
Domain analysis
      ↓
Brand analysis
      ↓
Reputation
      ↓
Page/payment analysis
      ↓
BLOCK
```

This gives Verity protection against a common way attackers conceal malicious destinations.

---

# 38. ML Requirement

This feature does NOT require ML.

It can work using:

```text
Chrome APIs
+
JavaScript
+
URL parsing
+
Domain analysis
+
Reputation
+
Existing rule-based risk engine
```

If a real lightweight ML model is later available, redirect features can become part of its feature vector:

```text
shortenerDetected
redirectCount
domainCount
crossDomainCount
brandMismatch
suspiciousIntermediateDomain
httpsDowngrade
finalDomainRisk
```

Never fake an ML probability.

---

# 39. Security Position

Do NOT claim:

- all shortened URLs are dangerous
- all redirects are malicious
- every multi-hop redirect is a scam
- every unknown domain is malicious
- redirect tracking provides 100% detection
- the final URL can always be known before navigation
- reputation alone is enough

Correct claim:

> **"Verity treats shortened URLs and redirects as an additional attack surface. It tracks the navigation chain, evaluates intermediate and final destinations, combines those signals with reputation, brand, URL and page analysis, and makes the final decision through the central risk engine."**

---

# 40. Final Antigravity Instruction

Implement this feature completely in the existing Verity codebase.

Before changing code:

1. Inspect the existing Manifest V3 architecture.
2. Inspect current navigation monitoring.
3. Inspect the URL detector.
4. Inspect the brand detector.
5. Inspect the reputation service.
6. Inspect the payment/page detectors.
7. Inspect the existing risk engine.
8. Inspect the warning/block overlay.
9. Reuse existing functionality.
10. Do not create duplicate scoring or detection systems.

Then implement:

```text
Shortener Detection
        ↓
Redirect Session Tracking
        ↓
Redirect Chain Analysis
        ↓
Intermediate Domain Analysis
        ↓
Final Destination Analysis
        ↓
Existing Verity Risk Engine
        ↓
Explainable Warning / Block
```

Use real Chrome Manifest V3 APIs.

Do not simulate redirect chains.

Do not fake reputation results.

Do not fake ML results.

Do not automatically block legitimate URL shorteners.

Do not collect sensitive user information.

The finished feature must work in a real Chrome session and be demonstrable using controlled test links.

Final architecture:

```text
                  VERITY
                     │
          ┌──────────┴──────────┐
          │                     │
    Search Protection      Direct Navigation
          │                     │
          └──────────┬──────────┘
                     │
             Redirect Tracker
                     │
          ┌──────────┴──────────┐
          │                     │
   Shortener Detection    Redirect Analysis
          │                     │
          └──────────┬──────────┘
                     │
              Final Destination
                     │
       ┌─────────────┼─────────────┐
       │             │             │
      URL          Brand       Reputation
   Analysis       Analysis       Check
       │             │             │
       └─────────────┼─────────────┘
                     │
              Page / Payment
                Detection
                     │
                     ↓
              CENTRAL RISK ENGINE
                     │
              ┌──────┼──────┐
              ↓      ↓      ↓
            ALLOW   WARN   BLOCK
```
