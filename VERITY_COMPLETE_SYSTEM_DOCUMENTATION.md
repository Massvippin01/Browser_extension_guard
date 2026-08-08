# 🛡️ VERITY — Enterprise Web & Download Security Protection Suite
## Master Technical Architecture, Feature & Algorithm Reference Manual

---

## 📋 Executive Summary
**Verity** is a real-time, zero-day client-side security extension engineered on Chrome Extension Manifest V3. It combines **heuristic pattern analysis**, **string edit distance (Levenshtein)**, **Domain Generation Algorithm (DGA) detection**, **redirect chain tracking**, **DOM credential intelligence**, **payment protection**, **automatic pop-up / pop-under interception**, **persistent session override memory**, and **local download policy enforcement** to protect users against phishing, malvertising, scam websites, fake payment gateways, and malicious file downloads **before** damage occurs.

Unlike traditional antivirus tools that rely solely on static domain blocklists (which fail against brand-new Zero-Day phishing links), Verity analyzes the **mathematical, structural, behavioral, and DOM characteristics** of pages, pop-ups, and downloads in real time on the user's device.

---

## 📐 Overall Architecture Diagram

```
[ Incoming Navigation / Pop-up Window / File Download ]
                    │
                    ▼
 ┌─────────────────────────────────────────────────────────────┐
 │               Service Worker (Background Orchestrator)      │
 ├──────────────────────────────┬──────────────────────────────┤
 │  webNavigation Listener      │  Pop-up & Download Monitor   │
 └──────────────┬───────────────┴──────────────┬───────────────┘
                │                              │
                ▼                              ▼
 ┌──────────────────────────────┐ ┌───────────────────────────┐
 │   URL & Brand Heuristics     │ │ Pop-up & Download Suite   │
 │   - IP / HTTPS / Subdomains  │ │ - Chrome tabs.remove()    │
 │   - Tokenized Brand Impers.  │ │ - Filename & Ext Analysis │
 │   - Levenshtein Typosquat    │ │ - Double Extension Check  │
 │   - DGA / Consonant Subdomain│ │ - Shortener Origin Risk   │
 │   - Ad Tracker Fingerprints  │ │ - Auto Chrome Cancel      │
 └──────────────┬───────────────┘ └─────────────┬─────────────┘
                │                               │
                ▼                               │
 ┌──────────────────────────────┐               │
 │ Redirect & Shortener Tracker │               │
 │ - Multi-hop chain tracking   │               │
 │ - Loop detection (A->B->A)   │               │
 └──────────────┬───────────────┘               │
                │                               │
                ▼                               │
 ┌──────────────────────────────┐               │
 │ DOM & Payment Protection     │               │
 │ - Sensitive Credential Input │               │
 │ - Financial Terminology      │               │
 │ - Payment Gateway Imperson.  │               │
 └──────────────┬───────────────┘               │
                │                               │
                ▼                               ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                Adaptive Risk Engine (risk-engine.js)       │
 ├─────────────────────────────────────────────────────────────┤
 │ Score (0 - 100) -> Safe (0-34) | Caution (35-69) | Danger(70+)│
 └──────────────┬───────────────────────────────┬──────────────┘
                │                               │
                ▼                               ▼
 ┌──────────────────────────────┐ ┌───────────────────────────┐
 │ Shadow DOM Block Screen      │ │ Pop-up & Download Toasts  │
 │ - window.stop()              │ │ - Isolated Shadow DOM     │
 │ - Persistent Override Memory │ │ - Auto-dismiss toast      │
 └──────────────┬───────────────┘ └───────────────────────────┘
```

---

## 🛠️ Complete Feature Matrix & Technical Implementation

### 1. Zero-Day URL & Domain Heuristics Engine
*File: `verity-extension/background/rules.js`*

Verity executes 9 synchronous heuristic rules on every URL navigation before page load:

| Rule Name | What It Checks | Technical / Algorithmic Mechanism | Risk Score Contribution |
| :--- | :--- | :--- | :--- |
| **1. Direct IP Hostname** (`isIpBasedUrl`) | Detects URLs using IP addresses directly instead of domain names (e.g. `http://192.168.1.1/login`). | Regex matching for IPv4/IPv6 string patterns (`/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/`). Direct IP hosting is a hallmark of phishing and C2 servers. | **+35 pts** |
| **2. Insecure HTTP Check** (`hasMissingHttps`) | Detects missing SSL/TLS encryption on sensitive pages. | Checks `url.protocol === 'http:'`. | **+15 - +25 pts** |
| **3. Excessive Subdomains** (`hasExcessiveSubdomains`) | Detects hostnames with > 4 subdomain levels (e.g. `a.b.c.d.example.com`). | Splits hostname by `.` and evaluates depth. Phishing kits often nest subdomains to obscure the real root domain. | **+30 pts** |
| **4. Token-Bounded Brand Impersonation** (`hasBrandNameInWrongDomain`) | Detects protected brand names (PayPal, HDFC, Google, UPS, SBI, etc.) inside unauthorized domains. | Uses **token-boundary regex (`(^\|[-.])brand([-.]\|$)`)** for short brands (≤ 4 chars) to prevent false positives on legitimate words like `groups.google.com`. | **+90 pts (Instant Block)** |
| **5. Obfuscated URL & Tracking Tokens** (`hasSuspiciousUrlPattern`, `hasMalvertisingPattern`) | Detects mixed-case tracking tokens (`/bkNTV1YPIT4j`), Base64-like blobs, long paths (>200 chars), path depth > 6, and asterisk fingerprints (`*`). | Path depth, query string length analysis, and regex search for mixed-case alphanumeric tokens (`/^[A-Za-z0-9_-]{8,35}$/`). | **+40 - +85 pts** |
| **6. DGA Subdomain & Synthetic Hostname Scanner** (`hasRandomLookingHostname`) | Detects randomly generated subdomains and DGA hostnames (e.g. `mobjwplhbaiiwsficq.theknownfacts.com` or `dstimaariracon.org`). | Evaluates **consonant cluster regex (`/[bcdfghjklmnpqrstvwxyz]{5,}/i`)**, vowel ratio (< 20%), 3-consonant start clusters (`/^[bcdfghjklmnpqrstvwxyz]{3,}/i`), and digit-letter mixing across all subdomains. | **+65 pts** |
| **7. Ad/Affiliate Tracker Fingerprinting** (`hasAffiliateTrackerPattern`) | Identifies tracker-heavy URLs carrying tracking parameters (`p1`..`p7`, `pub_rfid`, `ymid`, `var`, `z`, `sz`, `campaign_id`) and UUIDs. | Search parameter key/value analysis combined with UUID regex (`/^[a-f0-9]{8}-[a-f0-9]{4}-.../i`). | **+35 - +85 pts** |
| **8. Homograph & Punycode Scanner** (`hasPunycodeOrKeywords`) | Detects Internationalized Domain Name (IDN) spoofing (e.g. `xn--apple-43d.com`) and security keywords. | Searches for `xn--` prefix and auth keywords (`login`, `verify`, `secure`, `bank`). | **+55 - +85 pts** |
| **9. Media Piracy & Software Crack Portal Rule** (`hasPiracyOrUnverifiedMediaPattern`) | Detects known piracy and software crack portal keywords (`tamilgun`, `moviesda`, `isaimini`, `movierulz`, `getintopc`, `oceanofgames`, `keygen`, `cracked`, `repack`, `fitgirl`, `skidrow`) paired with high-risk TLDs. | Keyword dictionary search combined with high-risk TLD array (`.ninja`, `.mov`, `.film`, `.video`, `.download`, `.xyz`, `.top`, `.click`, `.world`, `.site`, `.online`). | **+60 - +85 pts** |

---

### 2. Trusted Global Top Domain Immunity Engine
*Files: `verity-extension/background/rules.js`, `risk-engine.js`*

To completely eliminate false positives on official global authentication and cloud platforms (`accounts.google.com`, `login.microsoftonline.com`, `apple.com`, `github.com`, `paypal.com`):

- **`isTrustedTopDomain(hostname)` Helper:** Maintains an active whitelist of top 35+ verified global infrastructure domains.
- **OAuth Parameter Exemption:** Automatically exempts official domains from long-path obfuscation penalties and login keyword flags (e.g. `accounts.google.com/v3/signin/...` containing 1,100-character `continue=` OAuth parameters).
- **Spoofed Domain Protection:** Fake domains like `accounts.goog1e.com` or `accounts-google.com` are **NOT** in the trusted whitelist and are **INSTANTLY BLOCKED (85/100 DANGER)**.

---

### 3. Persistent Session Override Memory Engine
*Files: `verity-extension/service_worker.js`, `content-script.js`*

Guarantees seamless user navigation when overriding block screens:

- **`userOverrideTabs` & `userOverrideDomains` Memory:** Tracks approved tab IDs and hostnames in background service worker memory (`Set`).
- **Loop & Re-block Elimination:** When the user clicks **"Proceed to Unsafe Site"**, Verity stores the tab and domain, bypassing future `onBeforeNavigate` and `ANALYZE_URL_ONLY` checks for that browsing session.
- **Full CSS & Asset Restoration:** Executes `window.location.reload()`, causing Chrome to freshly re-fetch all CSS stylesheets, web fonts, and layout assets.

---

### 4. Automatic Pop-up & Pop-under Interceptor & Killer
*Files: `verity-extension/service_worker.js`, `content-script.js`*

Targets intrusive pop-under ad networks, malvertising pop-ups, and fake video player pop-up tabs:

- **`chrome.tabs.onCreated` Interceptor:** Listens for newly spawned pop-up tabs created by opener pages (e.g. clicking anywhere on link-shortener or movie sites like `shrinkme.io`).
- **Instant Termination:** Evaluates target URL. If `riskScore >= 70` or `action === 'block'`, Verity calls **`chrome.tabs.remove(tab.id)`** to kill the pop-up window instantly before it renders!
- **Status Badge Notification Toast:** Displays a mini notification toast next to the top-right status badge (`🚫 VERITY POP-UP BLOCKED: Blocked pop-under to shrinkme.click`) and triggers an active red pulse glow animation.

---

### 5. Advanced Brand Protection & Levenshtein Typosquatting Engine
*Files: `verity-extension/background/brand-detector.js`, `rules.js`, `brands.json`*

Protects over 100+ global and Indian banking, fintech, and tech brands (HDFC Bank, ICICI Bank, SBI, Paytm, PhonePe, Razorpay, PayPal, Stripe, Chase, Apple, Google, Microsoft, Amazon, Netflix):

- **Levenshtein Edit Distance Algorithm:** Computes minimum single-character edits (insertions, deletions, substitutions) required to transform domain label into a protected brand name:
  $$\text{dist}(a, b) = \begin{cases} |a| & \text{if } |b| = 0, \\ |b| & \text{if } |a| = 0, \\ \text{dist}(\text{tail}(a), \text{tail}(b)) & \text{if } a[0] = b[0], \\ 1 + \min \begin{cases} \text{dist}(\text{tail}(a), b) \\ \text{dist}(a, \text{tail}(b)) \\ \text{dist}(\text{tail}(a), \text{tail}(b)) \end{cases} & \text{otherwise.} \end{cases}$$
- **Dynamic Edit Distance Thresholding:**
  - Brands $\le 4$ characters (e.g. `UPS`, `SBI`): Max edit distance = 1.
  - Brands $> 4$ characters (e.g. `PayPal`, `HDFC Bank`): Max edit distance = 2.

---

### 6. Enterprise Redirect & URL Shortener Tracker
*File: `verity-extension/background/redirect-analyzer.js`*

Tracks redirection chains in real time using Chrome's `webNavigation` API:

- **Multi-Hop Tracking:** Records full hop sequence: `Shortener → Tracking Server → Redirect Hop → Final Destination`.
- **Shortener Identification:** Maintained registry of known shorteners (`bit.ly`, `tinyurl.com`, `t.co`, `cutt.ly`, `short.io`, `shrinkme.io`, etc.).
- **Cross-Domain Hop Counter:** Penalizes redirection chains that jump across multiple different top-level domains.
- **Redirect Loop Detection:** Detects circular redirection loops (`A → B → A`) to prevent infinite redirect browser lockup.

---

### 7. DOM Intelligence & Financial Context Engine
*File: `verity-extension/content/content-script.js`*

Scans the page DOM context at `document_start` and `DOMContentLoaded`:

- **Sensitive Input Detector:** Identifies forms requesting passwords, credit card numbers, CVV (`cc-csc`), OTP, or UPI VPA without storing user input.
- **Financial Keyword Scanner:** Checks for high-confidence financial terminology (`upi`, `netbanking`, `bank account`, `account number`, `cvv`, `otp`, `kyc`, `atm pin`, `ifsc`).
- **Scam Language Heuristics:** Detects high-pressure scam phrases (`act now`, `your account will be suspended`, `pay with gift card`).

---

### 8. Payment Protection Suite
*Files: `verity-extension/background/payment-detector.js`, `content-script.js`*

Specifically targets fake checkout portals and payment phishing:

- **Payment Field Analysis:** Scans for complete card checkout forms (Card Number + CVV + Expiry + OTP/PIN).
- **Claimed Provider Engine:** Detects when a page visually or textually claims to be a payment gateway (PayPal, Razorpay, PhonePe, Google Pay, Paytm, Visa, Mastercard) but is hosted on an unverified domain.
- **Critical Payment Phishing Flag:** If a domain mismatch occurs on a payment form, Verity immediately triggers an **Instant Block** with an explicit red warning: `💳 Critical Payment Risk: Do NOT enter any card, UPI, CVV or OTP details on this website.`

---

### 9. On-Device Download Security & Malware Defense Suite
*Files: `verity-extension/background/download/` (`downloadMonitor.js`, `fileTypeAnalyzer.js`, `filenameAnalyzer.js`, `downloadAnalyzer.js`, `downloadPolicy.js`)*

Provides comprehensive protection for local file downloads:

- **Double Extension Detection:** Flags deceptive filenames like `invoice.pdf.exe` or `document.txt.vbs`.
- **High-Risk File Type Risk Matrix:**
  - **DANGER:** `.exe`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`, `.scr`, `.iso`, `.img`, `.chm`, `.hta`, `.app`, `.dmg`, `.pkg`.
  - **CAUTION:** `.zip`, `.rar`, `.7z`, `.tar.gz`, `.docm`, `.xlsm`.
- **Shortener Origin Penalty:** Applies a risk penalty if an executable file download originated from a URL shortener or redirect chain.
- **Automatic Download Cancellation:** Calls `chrome.downloads.cancel()` for high-risk files.
- **Shadow DOM Toast Warning:** Displays an isolated, sleek slide-in notification toast allowing the user to view details or dismiss.

---

### 10. Network & Security Error Interceptor
*File: `verity-extension/service_worker.js`*

Handles socket-level network errors and certificate failures:

- **`onErrorOccurred` Listener:** Intercepts connections terminated due to untrusted SSL certificates (`NET::ERR_CERT_AUTHORITY_INVALID`) or network blocks.
- **Session Storage Persistence:** Stores an explicit **90/100 DANGER** verdict in session storage for the tab so the extension popup and block overlay accurately reflect the security error.

---

### 11. Shadow DOM Security Overlay & Redirection Neutralizer
*File: `verity-extension/content/content-script.js`*

Renders the full-screen block screen when `Risk Score >= 70`:

- **CSS & DOM Isolation:** Uses a closed `ShadowRoot` to prevent host page CSS/JS from hiding or tampering with the block screen.
- **Strict Execution Neutralization:**
  1. Calls `window.stop()` immediately to halt network loading.
  2. Clears active `setTimeout` and `setInterval` timers to kill delayed JS redirects.
  3. Removes `<meta http-equiv="refresh">` tags from the DOM.
  4. Sets `window.onbeforeunload` to prevent automatic navigation away.
- **Page Scrolling Restoration:** `removeOverlay()` explicitly invokes `.style.removeProperty('overflow')` on `document.documentElement` and `document.body` so page scrolling is instantly restored when a user clicks "Visit anyway".

---

### 12. Adaptive Risk Engine (Scoring Matrix)
*File: `verity-extension/background/risk-engine.js`*

Aggregates all independent signals into a single score between **0 and 100**:

$$\text{Final Risk Score} = \min\left(100, \sum \text{URL Signals} + \text{Malvertising Signals} + \text{DOM Signals} + \text{Synergy Penalties} + \text{Download Signals}\right)$$

#### Score Thresholds:
- **0 – 34 (SAFE):** Green badge / Allowed.
- **35 – 69 (CAUTION):** Yellow badge / Warning in popup.
- **70 – 100 (DANGER):** Red badge / Full-screen Block Overlay.

#### Key Synergy Penalties:
- **Impersonation + Credentials:** Impersonating a trusted brand while requesting passwords = **+30 pts**.
- **Financial Terms + Password Form:** Unverified domain with financial terms and password input = **+35 pts**.
- **Multi-Hop Shortener + Credentials:** Redirecting via shortener to a credential form = **+30 pts**.

---

## ⚙️ Technology Stack Summary

| Layer | Technologies Used |
| :--- | :--- |
| **Manifest Version** | Chrome Extension Manifest V3 |
| **Core Languages** | JavaScript (ES6+ Modules), HTML5, CSS3 |
| **UI & Styling** | Vanilla CSS, Shadow DOM (Closed encapsulation), Glassmorphism, CSS Custom Properties |
| **Algorithms** | Levenshtein Edit Distance Matrix, RegEx Token Bounding, DGA Consonantal Ratio Analysis, Recursive Path Parsing |
| **Chrome APIs Used** | `chrome.webNavigation`, `chrome.tabs`, `chrome.downloads`, `chrome.storage.session`, `chrome.runtime`, `chrome.action` |

---

## 🚀 How to Run & Present Verity to Judges

1. Open Chrome and navigate to `chrome://extensions`.
2. Enable **Developer mode** (top right toggle).
3. Click **Load unpacked** and select the `verity-extension` folder (`e:\Finebehaviour - Copy\verity-extension`).
4. Run the local test server by executing `node test_server.js` in the root folder.
5. Open `http://localhost:3000` to test all real-time redirect, shortener, and fake bank scenarios!
