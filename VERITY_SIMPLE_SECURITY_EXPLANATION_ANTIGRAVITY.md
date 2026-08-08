# VERITY — SIMPLE SECURITY EXPLANATION
## Minimal Explainable Risk UI — Antigravity Implementation Plan

## Goal

Add a simple explanation whenever Verity warns or blocks a website/download.

The user should immediately understand:

1. Is it safe?
2. What is suspicious?
3. What should I do?

Keep it short. Maximum **2–3 reasons + 1 recommendation**.

---

## 1. UI

### Safe

```text
🟢 SAFE

No major security issues detected.
```

### Suspicious

```text
🟡 SUSPICIOUS

Why?
• Suspicious domain
• Unknown reputation

Recommendation:
Be careful before entering personal information.
```

### Dangerous

```text
🔴 DANGEROUS

Why?
• Possible bank impersonation
• Payment information requested
• Suspicious redirect

Recommendation:
Do not enter your information.
```

### Dangerous Download

```text
🔴 DANGEROUS DOWNLOAD

Why?
• Suspicious website
• Executable file
• Misleading filename

Recommendation:
Do not open this file.
```

---

## 2. Architecture

Do NOT create another detection or scoring engine.

Use:

```text
Existing Verity Risk Engine
        ↓
Existing Security Signals
        ↓
Explanation Generator
        ↓
Top 2–3 Human-Readable Reasons
        ↓
Recommendation
        ↓
Existing Warning / Block UI
```

The explanation layer only translates existing signals into understandable text.

---

## 3. Reuse Existing Signals

Examples:

```javascript
{
  suspiciousDomain: true,
  brandImpersonation: true,
  passwordForm: true,
  paymentForm: true,
  suspiciousRedirect: true,
  unknownReputation: true,
  executableDownload: true,
  doubleExtension: true
}
```

Use the project's actual signal names if they already differ.

Do not create duplicate detectors.

---

## 4. Reason Mapping

Create or extend a centralized explanation map:

```javascript
const EXPLANATION_REASONS = {
  brandImpersonation: "Possible brand impersonation",
  suspiciousDomain: "Suspicious domain",
  suspiciousRedirect: "Suspicious redirect detected",
  unknownReputation: "Website has little or no reputation",
  passwordForm: "Password information may be at risk",
  paymentForm: "Payment information requested",
  executableDownload: "Executable file download detected",
  doubleExtension: "Misleading file extension detected",
  maliciousReputation: "Website has a dangerous reputation"
};
```

Reuse existing signal names.

---

## 5. Reason Priority

If many signals exist, show only the most important 2–3.

Recommended priority:

```text
1. Known malicious/dangerous reputation
2. Brand impersonation
3. Payment/credential theft
4. Suspicious redirect
5. Executable/dangerous download
6. Misleading filename
7. Suspicious domain
8. Unknown reputation
```

Example:

```text
brandImpersonation = true
paymentForm = true
suspiciousDomain = true
unknownReputation = true
```

Show:

```text
Why?
• Possible brand impersonation
• Payment information requested
• Suspicious domain
```

Do not show all four.

---

## 6. Human-Friendly Language

Avoid technical wording.

Instead of:

```text
typosquatting detected
```

show:

```text
Possible brand impersonation
```

Instead of:

```text
high entropy domain
```

show:

```text
Suspicious domain
```

Instead of:

```text
redirect chain length = 4
```

show:

```text
Suspicious redirect detected
```

Instead of:

```text
credential harvesting vector
```

show:

```text
Password information may be at risk
```

---

## 7. Recommendation Mapping

### SAFE

```text
No major security issues detected.
```

### SUSPICIOUS

```text
Be careful before entering personal information.
```

### DANGEROUS WEBSITE

```text
Do not enter passwords, OTPs, or payment information.
```

### DANGEROUS DOWNLOAD

```text
Do not open this file.
```

### BLOCKED

```text
Verity blocked this page to protect you.
```

---

## 8. Risk Level

Reuse Verity's existing risk level.

Do NOT create a second score.

```text
Existing Risk Engine
        ↓
Existing Score / Classification
        ↓
SAFE / SUSPICIOUS / DANGEROUS
        ↓
Explanation Generator
```

The explanation layer must never change the underlying security decision.

---

## 9. Website Block Overlay

Keep existing block/enforcement logic unchanged.

Only improve the explanation:

```text
🛑 VERITY PROTECTION

This website appears dangerous.

Why?
• Possible bank impersonation
• Payment information requested
• Suspicious domain

Recommendation:
Do not enter your information.

[ Go Back ]
[ Continue Anyway ]
```

---

## 10. Payment Protection

Use the same explanation layer:

```text
🔴 PAYMENT WARNING

This payment page looks suspicious.

Why?
• Possible bank impersonation
• Payment information requested
• Suspicious domain

Recommendation:
Do not enter card or OTP details.
```

Do not expose sensitive information.

---

## 11. Redirect Protection

Example:

```text
🔴 DANGEROUS

Why?
• Suspicious redirect detected
• Final website appears unsafe
• Unknown reputation

Recommendation:
Do not continue.
```

Do not put the entire redirect chain in the main warning.

---

## 12. Download Protection

Use the same explanation layer:

```text
🔴 DANGEROUS DOWNLOAD

Why?
• Suspicious website
• Executable file
• Misleading filename

Recommendation:
Do not open this file.
```

Keep Download Protection's detection and policy unchanged.

---

## 13. Search Protection

Keep search-result explanations extremely small:

```text
🟢 SAFE
```

```text
🟡 CAUTION
```

```text
🔴 DANGEROUS
```

Optional tooltip:

```text
Suspicious domain
```

Do not place large explanations beside every search result.

---

## 14. Popup

Example:

```text
VERITY

🔴 DANGEROUS

Fake bank website detected.

Why?
• Brand impersonation
• Payment form
• Suspicious domain

[ View Details ]
```

Keep the popup compact.

---

## 15. Optional Details

If the current UI supports it, add a collapsed section:

```text
Why is this dangerous?
▾

• Possible brand impersonation
• Payment form detected
• Suspicious redirect
```

Collapsed by default.

Do not turn the main warning into a technical report.

---

## 16. Implementation

If no equivalent module exists, create:

```text
src/security/explanationGenerator.js
```

Responsibilities:

```text
risk signals
    ↓
priority sorting
    ↓
top 2–3 reasons
    ↓
recommendation
    ↓
UI-ready object
```

Example:

```javascript
{
  level: "dangerous",

  title: "This website appears dangerous.",

  reasons: [
    "Possible bank impersonation",
    "Payment information requested",
    "Suspicious domain"
  ],

  recommendation:
    "Do not enter your information."
}
```

---

## 17. Example Function

```javascript
function generateSecurityExplanation(signals, level) {
  const reasons = getTopReasons(signals, 3);

  return {
    level,
    reasons,
    recommendation: getRecommendation(level, signals)
  };
}
```

Keep it deterministic and local.

No AI API is required.

---

## 18. Do NOT

Do not:

- create a new detection engine
- create a new risk score
- add an AI/ML model
- call an external API
- change existing detection logic
- change existing blocking logic
- show every internal signal
- expose debug information
- expose sensitive information
- claim certainty beyond the existing risk decision

This is only an **explanation layer**.

---

## 19. Testing

### Safe

Normal trusted website:

```text
🟢 SAFE

No major security issues detected.
```

### Suspicious

Suspicious unknown website:

```text
🟡 SUSPICIOUS

Why?
• Suspicious domain
• Unknown reputation

Recommendation:
Be careful before entering personal information.
```

### Fake Bank

```text
🔴 DANGEROUS

Why?
• Possible bank impersonation
• Payment information requested
• Suspicious domain

Recommendation:
Do not enter your information.
```

### Redirect

```text
🔴 DANGEROUS

Why?
• Suspicious redirect detected
• Final website appears unsafe
• Unknown reputation
```

### Download

```text
🔴 DANGEROUS DOWNLOAD

Why?
• Suspicious website
• Executable file
• Misleading filename
```

---

## 20. Acceptance Criteria

- [ ] Uses existing Verity security signals.
- [ ] Uses existing risk classification.
- [ ] No second risk engine.
- [ ] No AI/ML dependency.
- [ ] No external API required.
- [ ] Maximum 2–3 reasons.
- [ ] Reasons are human-readable.
- [ ] Recommendation is shown.
- [ ] Safe/suspicious/dangerous states work.
- [ ] Payment Protection uses the explanation layer.
- [ ] Redirect Protection uses the explanation layer.
- [ ] Download Protection uses the explanation layer.
- [ ] Search Protection remains compact.
- [ ] Existing blocking/enforcement behavior remains unchanged.
- [ ] No sensitive data is exposed.
- [ ] Existing Verity features continue working.

---

# FINAL ANTIGRAVITY INSTRUCTION

Implement the **Simple Security Explanation Layer** in the existing Verity Chrome extension.

First inspect the current risk engine, security signals, warning overlay, block page, popup, payment protection, redirect protection, search protection and download protection.

Do not modify the underlying detection logic or scoring.

Create or extend an explanation generator that converts existing security signals into:

```text
Status
+
Maximum 2–3 reasons
+
One recommendation
```

Use simple language and reuse the existing risk classification.

Examples:

```text
🔴 DANGEROUS

Why?
• Possible bank impersonation
• Payment information requested
• Suspicious domain

Recommendation:
Do not enter your information.
```

```text
🔴 DANGEROUS DOWNLOAD

Why?
• Suspicious website
• Executable file
• Misleading filename

Recommendation:
Do not open this file.
```

```text
🟢 SAFE

No major security issues detected.
```

Requirements:

- Reuse existing signals.
- Reuse existing risk level.
- Do not create a new score.
- Do not add AI/ML.
- Do not call external APIs.
- Do not change blocking/enforcement logic.
- Do not expose technical debugging information.
- Keep the UI minimal and professional.
- Make the explanation deterministic.
- Make it consistent across website, payment, redirect, search and download warnings.

The final result should let a normal user understand **why Verity warned them in 2–3 seconds**, without overwhelming them with technical details.
