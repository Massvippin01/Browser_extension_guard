# VERITY — SEARCH RESULT SAFETY PROTECTION
## Antigravity Implementation Specification

## 1. Feature Objective

Implement the next major Verity feature:

> **Search Result Safety Protection**

When a user performs a search in Google, Bing, DuckDuckGo, or another supported search engine, Verity analyzes the destination URLs shown in the search results and displays a clear safety indicator before the user opens the result.

Example:

```text
HDFC Bank – Official Website
https://www.hdfcbank.com
🟢 SAFE

HDFC Bank Secure Verification
https://hdfc-login-security.example
🔴 DANGEROUS

Customer Support
https://unknown-example.example
🟡 SUSPICIOUS
```

The feature must be real and implementable using Chrome Manifest V3 extension APIs, content scripts, the existing Verity detection engine, and the existing warning/block system.

Do NOT build a fake/demo-only implementation.

---

# 2. Core Design Principle

Do NOT attempt to determine whether the user's search query itself is safe.

Instead:

```text
Search Query
     ↓
Search Engine Results
     ↓
Extract Destination URLs
     ↓
Analyze Each Result
     ↓
URL + Domain + Brand + Reputation
     ↓
Existing Verity Risk Engine
     ↓
Safety Label
```

The search query can provide context, but the destination URL is the primary security object.

Example:

```text
Search:
"HDFC Bank login"

Result:
https://hdfcbank.com
```

should be treated very differently from:

```text
Search:
"HDFC Bank login"

Result:
https://hdfc-login-security.example
```

---

# 3. Supported Search Engines

Initially support the search engines that Verity can reliably identify and parse.

Start with:

- Google Search
- Bing Search

Optionally add:

- DuckDuckGo
- Yahoo

Create a search-engine adapter architecture rather than putting engine-specific selectors throughout the code.

Example:

```text
search/
  engines/
    google.js
    bing.js
    duckduckgo.js
```

Each adapter should expose a common interface such as:

```text
isSearchPage()
extractResults()
getResultLink()
getResultTitle()
getResultSnippet()
```

If a search engine changes its DOM, only its adapter should require modification.

---

# 4. Search Result Extraction

Use a content script running on supported search-result pages.

Extract only visible/actual result information needed for security analysis.

For each result, create a normalized object:

```json
{
  "url": "https://example.com/login",
  "title": "Example Login",
  "snippet": "Sign in to your account",
  "position": 1
}
```

Do not assume every `<a>` element is a search result.

Avoid:

- navigation menus
- advertisements where possible
- footer links
- internal search-engine links
- unrelated page links

The adapter should identify actual organic search results.

---

# 5. URL Normalization

Before analysis, normalize each destination URL.

Perform:

- URL parsing
- hostname extraction
- lowercase hostname normalization
- trailing-dot handling
- default-port normalization
- safe decoding where appropriate
- tracking-parameter handling for analysis
- redirect/wrapped-result extraction where possible

Do NOT destroy the original URL.

Store both:

```text
displayUrl
normalizedUrl
```

Never execute JavaScript from a search-result URL.

---

# 6. Search Result Risk Analysis

Each result should use the existing Verity detection engine.

Do NOT create a second independent scoring system unless required.

The result analyzer should call existing modules such as:

```text
URL Detector
Brand Detector
Reputation Service
Risk Engine
```

The search feature should act as an orchestration layer.

Architecture:

```text
Search Result
     ↓
Search Result Analyzer
     ↓
Existing Verity Detectors
     ↓
Existing Risk Engine
     ↓
Search Result Safety Label
```

This avoids duplicate logic and ensures that search-result protection and direct website protection produce consistent results.

---

# 7. Signals to Analyze Before Click

For every result, analyze lightweight signals that can be determined without opening the website.

### URL

- URL length
- hostname length
- path length
- query length
- subdomain count
- hyphen count
- digit count
- special characters
- IP hostname
- punycode / IDN
- suspicious TLD
- suspicious keywords
- login keywords
- payment keywords
- verification keywords
- random-looking hostname
- suspicious path
- typosquatting indicators

### Domain

- trusted official domain
- known malicious domain
- known phishing domain
- domain reputation
- brand similarity
- official-domain mismatch

### Reputation

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

---

# 8. Search Context Signals

The visible result title and snippet may provide useful contextual signals.

Example:

```text
Title:
"Verify your bank account immediately"

Snippet:
"Your account will be suspended unless you verify..."
```

Possible context features:

```text
urgency_language
account_threat_language
credential_request_language
payment_language
reward_language
verification_language
```

These must be weak/supporting signals.

Never do:

```text
contains "verify" = dangerous
```

Use combinations.

Example:

```text
financial_brand
+
urgent_verification_language
+
lookalike_domain
```

is much stronger.

---

# 9. Brand Impersonation

Use Verity's existing protected-brand database.

For every result:

```text
result URL
      ↓
brand similarity
      ↓
official-domain verification
```

Example:

```text
Claimed/recognized brand:
HDFC Bank

Destination:
hdfc-login-security.example

Official domain:
NO

Brand similarity:
HIGH
```

This should increase risk.

Do not assume:

```text
brand name appears in URL = fake
```

and do not assume:

```text
brand name appears in URL = legitimate
```

Always compare against the official-domain allowlist.

---

# 10. Result Safety Classification

Use a simple, understandable classification.

### 🟢 SAFE

Use when evidence strongly supports legitimacy.

Possible conditions:

```text
trusted official domain
+
safe reputation
+
no major suspicious signals
```

### 🟡 SUSPICIOUS

Use when evidence is uncertain or mixed.

Example:

```text
unknown domain
+
some suspicious URL characteristics
```

Do not block automatically.

### 🔴 DANGEROUS

Use when there is strong evidence.

Examples:

```text
known phishing domain
```

or:

```text
known malicious reputation
```

or:

```text
strong brand impersonation
+
domain mismatch
+
multiple suspicious URL signals
```

The exact thresholds must come from the existing risk engine.

---

# 11. Do Not Overuse "SAFE"

A major requirement:

Do not display:

```text
🟢 SAFE
```

just because:

```text
reputation = unknown
```

Unknown should normally result in:

```text
No strong safety conclusion
```

or:

```text
🟡 CHECKED / UNKNOWN
```

depending on the final design.

Only display strong "SAFE" when there is meaningful evidence.

---

# 12. UI Design

The safety indicator should be subtle and not destroy the search engine's layout.

Recommended:

```text
HDFC Bank – Official Website
https://hdfcbank.com
[🟢 SAFE]
```

For suspicious:

```text
HDFC Customer Verification
https://hdfc-login-security.example
[🟡 SUSPICIOUS]
```

For dangerous:

```text
HDFC Account Verification
https://hdfc-login-security.example
[🔴 DANGEROUS]
```

Use CSS that is:

- isolated
- non-destructive
- responsive
- accessible
- visually consistent with Verity
- unlikely to break the search page

Use a Shadow DOM or carefully isolated styles if appropriate.

---

# 13. Explainability on Hover/Click

Clicking or hovering the indicator should show concise reasons.

Example:

```text
🔴 DANGEROUS

Risk: 91/100

Why?
✓ Domain resembles HDFC Bank
✓ Destination is not an official HDFC domain
✓ Suspicious URL structure
✓ Poor reputation

[ View Details ]
```

For safe:

```text
🟢 SAFE

Risk: 4/100

✓ Official domain
✓ Trusted reputation
✓ No major suspicious indicators
```

Do not expose technical implementation details unnecessarily.

---

# 14. Pre-Click Protection

Search-result labeling is the first layer.

The second layer is protection when the user actually clicks a suspicious result.

Flow:

```text
User clicks result
       ↓
Navigation begins
       ↓
Existing Verity navigation monitor
       ↓
URL / redirect analysis
       ↓
Page analysis after load
       ↓
Final risk decision
       ↓
ALLOW / WARN / BLOCK
```

The existing direct website protection remains the final protection layer.

Do NOT rely only on the search-result label.

---

# 15. Important: Never Open Every Result Automatically

Do NOT visit every search result in the background just to analyze it.

Reasons:

- privacy
- performance
- unwanted network requests
- tracking concerns
- potential malicious content
- unnecessary bandwidth

Before click, use:

```text
URL
domain
brand
reputation
search-result context
```

After click, use:

```text
redirect
DOM
page behavior
payment/credential detection
```

This two-stage architecture is important.

---

# 16. Search Result Cache

Implement caching to avoid repeated analysis.

Cache key:

```text
normalized URL
```

Store:

```text
risk level
risk score
reasons
timestamp
```

Example:

```json
{
  "riskScore": 82,
  "level": "dangerous",
  "reasons": [
    "Known phishing domain",
    "Brand impersonation"
  ],
  "timestamp": 1780000000000
}
```

Use a reasonable expiration time.

Do not cache sensitive page contents.

---

# 17. Dynamic Search Results

Search engines may dynamically update results.

Use an appropriate strategy such as:

- initial scan
- MutationObserver
- debounced rescans

Example:

```text
Search page loads
      ↓
scan results
      ↓
results change
      ↓
MutationObserver
      ↓
debounced rescan
```

IMPORTANT:

Do not scan continuously on every DOM mutation.

Use:

```text
debounce
deduplication
processed-result tracking
```

to prevent CPU usage.

---

# 18. Result Deduplication

The same URL may appear multiple times.

Normalize the URL and avoid repeatedly analyzing identical destinations.

Example:

```text
https://example.com/?utm_source=google
https://example.com/
```

may represent the same destination.

Use safe normalization for comparison while preserving the original result URL.

---

# 19. Search Advertisements

Treat advertisements carefully.

Do not automatically label every ad as malicious.

If the search engine provides a recognizable ad result:

```text
AD / SPONSORED
```

keep that context visible.

Apply the same URL/domain security checks where technically appropriate.

Never claim:

```text
ad = dangerous
```

without evidence.

---

# 20. Search Result Ranking Signals

Do NOT attempt to determine whether Google/Bing's ranking is correct.

Verity only evaluates security risk.

Do not change:

- ranking
- search relevance
- search engine behavior

Only add security information.

---

# 21. Risk Score

Use the existing Verity risk engine.

Example signals:

```text
Known malicious reputation             strong increase
Known phishing reputation              strong increase
Official trusted domain                strong decrease
Brand/domain mismatch                  increase
High brand similarity                  increase
Punycode                               increase
IP hostname                            increase
Suspicious URL                         increase
Suspicious redirect history             increase
Urgency language                       small increase
Credential/payment language             small increase
Unknown reputation                     neutral/uncertain
```

Do not hardcode arbitrary scoring separately in the search module.

The central risk engine should remain authoritative.

---

# 22. Search-Specific Risk Context

Add a context field:

```text
analysisContext = "search_result"
```

The same URL can later be analyzed with:

```text
analysisContext = "direct_navigation"
```

This allows Verity to know where the signal came from without duplicating the detection engine.

---

# 23. Recommended Architecture

Use the existing Verity system wherever possible.

Suggested additional modules:

```text
src/
  search/
    searchManager.js
    resultAnalyzer.js
    resultCache.js

    engines/
      google.js
      bing.js
      duckduckgo.js

    ui/
      safetyBadge.js
      safetyTooltip.js
      searchStyles.css
```

Existing modules should remain authoritative:

```text
src/
  detectors/
    urlDetector.js
    brandDetector.js
    redirectDetector.js
    pageDetector.js

  risk/
    riskEngine.js

  reputation/
    reputationService.js

  navigation/
    navigationMonitor.js
```

Do not duplicate these modules inside `search/`.

---

# 24. Manifest V3 Requirements

Inspect the current `manifest.json` first.

Only request permissions that are actually required.

Potential requirements may include:

```text
host permissions for supported search engines
content_scripts for search pages
existing navigation permissions already used by Verity
```

Do not add broad permissions unnecessarily.

Keep the extension permission footprint minimal.

---

# 25. Performance Requirements

Search-result analysis must be lightweight.

Target behavior:

```text
Search page opens
      ↓
results are detected quickly
      ↓
URL/domain checks run asynchronously
      ↓
badges appear progressively
```

Do not block the entire search page waiting for a reputation API.

If reputation is slow:

```text
initial local analysis
      ↓
show preliminary result
      ↓
reputation arrives
      ↓
update result
```

Do not freeze the browser.

---

# 26. Error Handling

If:

```text
search engine DOM changes
```

do not crash the extension.

If:

```text
reputation API fails
```

continue using local analysis.

If:

```text
result URL cannot be parsed
```

skip that result safely.

If:

```text
content script cannot access a result
```

do not break the search page.

All failures should degrade gracefully.

---

# 27. Privacy Requirements

Do not collect:

- search history unnecessarily
- search queries remotely
- passwords
- payment data
- page contents unnecessarily

Prefer local processing.

If a reputation service requires a URL:

```text
send only the minimum URL/domain information required
```

Do not send:

```text
search query + browsing history + page content
```

unless explicitly required and clearly disclosed.

---

# 28. Testing

Create controlled tests.

## Test A — Official result

```text
Search:
HDFC Bank

Result:
https://www.hdfcbank.com
```

Expected:

```text
🟢 SAFE
```

## Test B — Lookalike result

```text
https://hdfc-login-security.example
```

Expected:

```text
🔴 DANGEROUS
```

when sufficient impersonation/security evidence exists.

## Test C — Unknown site

```text
https://new-example.example
```

Expected:

```text
🟡 SUSPICIOUS
```

or an appropriately neutral/unknown state if there is insufficient evidence.

Never label unknown as automatically safe.

## Test D — Malicious reputation

Known test threat URL.

Expected:

```text
🔴 DANGEROUS
```

## Test E — Normal search

Search something unrelated:

```text
best gaming laptop
```

Expected:

- results still render normally
- Verity does not noticeably slow the page
- no excessive badges
- no broken layout

## Test F — Dynamic results

Scroll or load more results.

Expected:

```text
new results
    ↓
automatically analyzed
```

## Test G — Click dangerous result

Expected:

```text
search result = 🔴
      ↓
click
      ↓
Verity warning/block
```

The existing direct-navigation protection must still work.

---

# 29. Acceptance Criteria

The feature is complete only when:

- [ ] Google results can be detected.
- [ ] Bing results can be detected.
- [ ] Search result destination URLs are extracted correctly.
- [ ] Result title/snippet can be extracted where available.
- [ ] URL analysis works.
- [ ] Brand/domain analysis works.
- [ ] Reputation integration works.
- [ ] Unknown reputation does not mean SAFE.
- [ ] Search result safety labels appear correctly.
- [ ] Dangerous results receive a clear warning indicator.
- [ ] Clicking a dangerous result triggers existing Verity protection.
- [ ] Safe results remain clickable normally.
- [ ] Dynamic search results are handled.
- [ ] Duplicate URLs are not repeatedly analyzed.
- [ ] Search pages remain responsive.
- [ ] Search engine layout is not broken.
- [ ] Reputation failure does not break the feature.
- [ ] No sensitive user data is collected.
- [ ] Existing Verity detection continues working.
- [ ] No fake risk scores or fake reputation responses are used.

---

# 30. Judge Demonstration

Use a controlled demonstration.

### Search 1

```text
HDFC Bank login
```

Show:

```text
HDFC Bank – Official Website
https://www.hdfcbank.com

🟢 SAFE
```

Then show a controlled fake result:

```text
HDFC Bank Secure Login
https://hdfc-login-security.example

🔴 DANGEROUS
```

Clicking it should trigger:

```text
🛑 VERITY BLOCKED THIS WEBSITE

Reasons:

✓ Brand/domain mismatch
✓ Lookalike domain
✓ Suspicious URL
✓ High phishing risk
```

This demonstrates the full chain:

```text
SEARCH
  ↓
DETECT
  ↓
EXPLAIN
  ↓
PROTECT
```

---

# 31. Judge Explanation

Use this explanation:

> "Verity extends protection to the search stage. Instead of waiting for the user to enter a suspicious website, our extension analyzes destination URLs directly inside search results. We combine domain structure, brand impersonation, reputation and contextual signals to provide an explainable safety indicator. When the user clicks a high-risk result, our existing navigation and page analysis provide a second layer of protection."

---

# 32. Important Limitations

Do NOT claim:

- every search result can be perfectly classified
- 100% safe detection
- Google/Bing ranking is being evaluated
- every unknown website is dangerous
- every search result is opened/scanned
- search snippets alone prove phishing

Correct positioning:

> **Search Result Safety Protection is an early-warning layer. It identifies high-confidence suspicious destinations before the user opens them, while Verity's deeper navigation and page analysis provides the final protection after navigation begins.**

---

# 33. Final Implementation Instruction for Antigravity

Implement this feature in the existing Verity codebase.

Before modifying code:

1. Inspect the entire existing extension architecture.
2. Identify the current Manifest V3 setup.
3. Identify the existing URL detector.
4. Identify the existing brand detector.
5. Identify the existing reputation service.
6. Identify the existing risk engine.
7. Identify the current navigation/block/warning system.
8. Reuse all existing detection infrastructure.
9. Do not create duplicate risk engines.
10. Do not break existing functionality.

Then:

1. Implement Google search-result extraction.
2. Implement Bing search-result extraction.
3. Create a common search-engine adapter interface.
4. Implement normalized result objects.
5. Connect results to the existing Verity detection engine.
6. Add search-specific safety labels.
7. Add explainable reasons.
8. Add dynamic-result handling.
9. Add caching and deduplication.
10. Add pre-click protection through the existing navigation system.
11. Test all acceptance criteria.
12. Verify that normal browsing and search remain fast.

The final feature must feel like a real browser security product:

```text
Search
   ↓
🟢 SAFE
🟡 SUSPICIOUS
🔴 DANGEROUS
   ↓
Click
   ↓
Deep Verity Protection
   ↓
ALLOW / WARN / BLOCK
```

Do not implement a superficial visual badge.

The badge must represent a real security analysis.
