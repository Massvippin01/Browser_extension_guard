<div align="center">
  <img src="verity-extension/icons/safe_128.png" alt="Verity Logo" width="128" height="128">
  <h1>Verity Web Protection — Feature Summary 🛡️</h1>
</div>

Verity is an enterprise-grade, privacy-first security extension designed to stop credential theft, financial fraud, and phishing in real-time. Below is a comprehensive breakdown of the major modules and features actively running in the extension.

---

## 1. Real-Time Payment Protection 💳
*(Implements: VERITY_PAYMENT_PROTECTION)*

A specialized module designed to stop credential theft and financial fraud on fake payment pages.

- **Granular Payment Field Detection:** Instead of just looking for standard passwords, Verity actively scans the page (in a privacy-safe way without reading values) for `Card Number`, `CVV`, `Expiry Date`, `UPI`, `OTP`, and `Payment PINs`.
- **Provider Impersonation Detection:** It reads the visible text on the page to determine if the site claims to be one of 30+ major payment gateways (e.g., Razorpay, PayPal, PayU, Stripe, Paytm, HDFC).
- **Official Domain Cross-Check:** If a site claims to be "PayPal" and asks for a CVV, Verity instantly cross-checks the current URL against the official domain whitelist (e.g., `paypal.com`).
- **Critical Override Block:** If there is a domain mismatch *and* payment credentials are being requested, Verity triggers a massive 80+ point penalty and throws up a specialized, un-dismissable red **"💳 Payment Phishing Blocked"** overlay to stop the user from entering their card details.

---

## 2. Search Result Safety Protection 🔍
*(Implements: VERITY_SEARCH_RESULT_PROTECTION)*

An early-warning system that analyzes links *before* you even click them.

- **Google & Bing Integration:** Seamlessly injects `🟢 SAFE`, `🟡 SUSPICIOUS`, or `🔴 DANGEROUS` badges directly next to organic search result titles.
- **Pre-Click Analysis:** Sends the URLs from your search results to the background engine for a blazing-fast rules and reputation check, entirely bypassing the heavy DOM/ML analysis to preserve CPU and bandwidth.
- **Smart SPA & Mutation Handling:** Works flawlessly with Google's modern "Infinite Scroll" and Single Page Application (SPA) architecture. As you type new searches or scroll down, new badges appear instantly.
- **Hover Explainability:** Hovering over any badge reveals a beautiful, non-destructive tooltip detailing the exact reasons for the score (e.g., "✓ Official Domain", "▸ Known phishing domain").

---

## 3. The Core Verity Risk Engine 🧠

The orchestrator that ties all the data together to make a final block/allow decision.

- **URL Heuristics:** Flags suspicious TLDs (`.xyz`, `.top`), excessive subdomains, long random strings, and sneaky Punycode (IDN homograph attacks).
- **Global Brand Typosquatting:** Contains a massive database of global and Indian banks/brands. It detects if a URL looks *almost* identical to a real brand (e.g., `hdfc-bank-secure.com` instead of `hdfcbank.com`).
- **Financial Context Engine:** Scans the page text for high-risk urgency language or financial keywords (Crypto, Banking, Refunds, KYC).
- **Local-First Privacy:** All rule parsing, brand matching, and DOM scanning happens entirely locally on your machine.
- **Synergy Penalties:** The engine combines weak signals to form strong convictions (e.g., an unknown domain + financial keywords + a password field = High Risk block).

---

## 4. The Enforcement Overlay 🚫

The ultimate line of defense when a user navigates to a dangerous site.

- **Un-bypassable Block:** If a site scores above a certain threshold (or triggers a critical rule like Payment Phishing), Verity freezes the page layout and injects an isolated Shadow DOM full-screen overlay.
- **Transparent Reasoning:** It clearly explains *why* the site was blocked (e.g., "Domain mismatch", "Lookalike domain") so you can make an informed decision, rather than just throwing a generic "Warning" screen.
- **User Override:** If the user explicitly chooses to proceed (and it's not a critical payment theft attempt), the site is added to a temporary safe list for the session.

---

*Built by Antigravity*
