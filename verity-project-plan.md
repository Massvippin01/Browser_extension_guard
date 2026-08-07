# Verity — Real-Time Site Authenticity Engine
### Full Build Plan (Free MVP · Judge-Proof Demo)

---

## 0. Quick Verdict

Your original idea (AI Chrome extension for financial phishing) is the **right idea** — it's specific, demoable, and maps cleanly to a real harm. It just wasn't yet built to survive your actual bar: free, provably accurate, provably real-time, and interactive for judges. This plan keeps your architecture's skeleton (rule layer → AI layer → verdict layer) but rebuilds each layer so every claim is backed by a number you can show live, at zero cost.

Rename recommendation: **Verity** (Latin root "truth") — one word, premium, memorable, literally describes what the product measures. Use this or swap freely; the plan doesn't depend on the name.

---

## 1. The Problem Statement (Final Wording)

> Financial phishing pages are now visually identical to the real thing, but browser protection still relies on blocklists that lag hours to days behind new lookalike domains — leaving users to enter banking and payment credentials on fake sites before any warning appears. Verity closes that gap by scoring every page's authenticity **locally, the instant it loads**, with an explainable AI verdict — no configuration, no cost, no data ever leaving the device.

If your hackathon gave you a fixed list of problem statements to choose from, pick whichever one contains **"real-time," "AI-based fraud/security,"** or **"financial protection"** — this build satisfies all three simultaneously, so it should out-score narrower statements (e.g., pure "blocklist tool" or generic "cybersecurity awareness" prompts) on Impact and Technical Excellence.

---

## 2. Requirement → Feature Mapping

Every constraint you gave maps to a specific, built feature — nothing here is decorative.

| Your Requirement | Feature That Delivers It |
|---|---|
| MVP completely free | 100% on-device inference (ONNX model + JS heuristics), free public datasets, free static hosting for threat feed, no paid API in the critical path |
| ~100% accuracy for defined scope | Scope narrowed to "Top 100 impersonated financial brands" — string/visual similarity within that closed set is near-deterministic and independently testable |
| Real-world impact | Solves a problem people actually hit (fake bank/payment pages); zero setup means real adoption odds, not just a demo toy |
| Extremely low user effort | Zero-click, passive badge; no scans to trigger, no settings to touch |
| Luxury experience | Fintech-security visual language (Stripe Radar / Coinbase-alert aesthetic), motion design, no generic red-triangle browser-warning look |
| Judge interaction critical | **Live Attack Simulator** — judges generate a fake phishing page themselves and watch Verity catch it in real time |
| AI/ML proof | Real trained classifier (not a wrapper around an LLM prompt), with a visible Model Card: confusion matrix, precision/recall, feature weights |
| Accuracy proof/measurement | In-popup "Benchmark Mode" runs the model against a labeled test set live and shows the score updating in real time |
| Real-time proof | On-screen millisecond timer on every verdict; stress-test button scores 50 URLs live with a running latency chart |
| Business-safe / real-time adaptation | All processing local (no browsing data leaves device — enterprise-safe by default); brand/threat list is a hot-reloadable JSON pulled from free static hosting, so it updates without a new extension release |

---

## 3. Product Snapshot

**One-line pitch:** A Chrome extension that scores every page's authenticity the instant it loads, using a real trained model running entirely on-device — free, private, and provably accurate for the brands it protects.

**Core promise to judges:** "Watch me build a fake bank login page right now, and watch Verity catch it before I finish typing the URL."

---

## 4. Why This Beats a Generic "AI Phishing Detector"

- **Scope discipline, not scope creep.** Instead of claiming to catch "all phishing" (impossible to prove accuracy on live, in a demo), Verity explicitly protects a *named, visible* set of top financial brands. This is what lets you say "near 100% accurate" and mean it — the claim is scoped, tested, and shown, not asserted.
- **Real ML, not an LLM wrapper.** A prompt like "is this a phishing site? Answer yes/no" calling a hosted LLM is (a) not free at scale, (b) not explainable beyond "the model said so," and (c) a network dependency during a live demo. A small trained classifier with visible coefficients is free, instant, offline, and — critically — judges can ask "why" and you can point at real numbers.
- **The interaction is the pitch.** Most hackathon security tools show a slide of "would detect X." Verity lets a judge attack it live and lose.

---

## 5. System Architecture — 100% Free Stack

```
┌─────────────────────────────────────────────────────────┐
│  chrome.webNavigation fires → background service worker  │
└───────────────────────────┬───────────────────────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼                              ▼
   LAYER 1: Rule Pre-Filter        LAYER 2: Local ML Scorer
   (instant, <5ms, offline)        (ONNX model, <50ms, offline)
   - IP-based URL                  - Trained on UCI/Kaggle
   - Brand-in-wrong-domain            phishing dataset (free)
   - No HTTPS                      - Runs via onnxruntime-web
   - Excess subdomains             - Outputs 0–100 risk score
              │                              │
              └──────────────┬──────────────┘
                             ▼
                LAYER 3: Brand Similarity Engine
                (deterministic, curated 100-brand list)
                - Levenshtein / Jaro-Winkler domain match
                - Logo/text-vs-domain DOM scan
                             │
                             ▼
                   LAYER 4: Verdict Combiner
              → badge state + explainability payload
                             │
              ┌──────────────┴──────────────┐
              ▼                              ▼
     Content script: block overlay    Popup: risk breakdown +
     (if danger threshold crossed)    Model Card + Benchmark Mode
```

**Optional Layer 5 (stretch, still free):** Chrome's built-in **Prompt API / Gemini Nano** — now shipped in Chrome stable and free, fully on-device — to turn the structured signals into a natural-language explanation sentence ("This page copies PayPal's login form but submits to a domain registered 3 days ago"). Treat this as a polish layer only: it requires Chrome to have already downloaded the ~2–4GB Nano model, which you can't guarantee on a judge's laptop, so always keep the deterministic feature-weight explanation as the default and let Nano upgrade it opportunistically (`LanguageModel.availability()` check, silent fallback).

---

## 6. The Three Detection Layers, In Detail

**Layer 1 — Rule Pre-Filter (client-side, zero dependencies)**
URL structure checks: IP-literal URLs, punycode/homoglyph domains, excessive subdomain depth, missing HTTPS, brand keyword sitting outside the registrable domain (e.g. `paypal.com.verify-login.ru`).

**Layer 2 — Local ML Classifier (the real "AI")**
Train offline (once, before the hackathon) on a free, well-known dataset — see Section 15 — using engineered URL/page features. Export to ONNX. Ship the ~100KB–1MB model file inside the extension. Run inference with `onnxruntime-web`, entirely in the background service worker. No network call, no API key, no cost, no latency variance.

**Layer 3 — Brand Similarity Engine (the "near-100%" scope)**
A curated JSON of the ~100 most-impersonated financial/e-commerce brands (name + real domain + logo hash). For any page, compute string distance between the visited domain and each brand name; flag DOM text/logo mentions of a brand that don't match its real domain. Because this list is closed and curated, you can build a matching test set of synthetic typosquats and get a **real, reproducible, near-100% accuracy number** — this is the number you put on the slide.

**Layer 4 — Verdict Combiner**
Weighted combination of the three signals into a 0–100 score → badge state (safe / caution / danger) and a structured explanation object consumed by the popup and the block overlay.

---

## 7. Accuracy Proof System

Don't say "high accuracy" — show three separate, real numbers, each tied to a specific, honest claim:

| Claim | How You Prove It | Where Judges See It |
|---|---|---|
| "Our classifier generalizes to phishing patterns broadly" | Held-out test split (80/20) on the public dataset, with confusion matrix, precision, recall, F1, ROC-AUC | **Model Card** tab in the popup — real numbers, not marketing copy |
| "Within our defined brand scope, we're effectively 100%" | A self-built test set of synthetic typosquats of the 100 protected brands, scored live | **Benchmark Mode** button — runs all test cases in front of the judge, shows a live pass count ticking up |
| "It works on brand-new, never-seen attacks" | The Live Attack Simulator (Section 9) — a phishing page the judge invents on the spot, which by definition isn't in any training set | Live, in person — the strongest proof you have |

This structure matters: it separates "general phishing detection" (honestly ~95–97%, matching published academic baselines on this dataset) from "financial-brand impersonation" (your actual narrow, provable near-100% scope) — so no claim you make is exaggerated, and every claim is falsifiable on the spot, which is exactly what makes it convincing to judges.

---

## 8. Real-Time Proof System

- **Millisecond badge:** every verdict shows its own scoring time ("Scored in 38ms") directly in the popup — not a claim, a stopwatch.
- **Stress Test button:** scores a batch of 50 preloaded URLs (mix of safe/phishing) in the popup, rendering a live-updating latency chart and running accuracy counter as it goes. This single button demonstrates real-time *and* accuracy *and* gives judges something to click.
- **Split-second badge transition:** rule layer updates the badge in <5ms (provisional), ML layer confirms/upgrades it within ~50ms — visibly two-stage, so judges see the "instant response even before AI returns" claim happen, not just hear it.

---

## 9. Judge Interaction — The Live Attack Simulator (Flagship Feature)

This is the single highest-leverage feature for your "judge interaction is critical" requirement, and it doubles as your best accuracy and real-time proof.

**What it is:** A small local page bundled with the extension (`verity://simulate` or a bundled `simulator.html` opened from the popup) where a judge:
1. Picks any brand from the protected list (or types a new one).
2. Clicks "Generate fake login page" — the tool locally builds a convincing clone (logo, layout, login form) served from `localhost`, submitting to a fake domain.
3. Navigates to it in the same browser.
4. Watches Verity's badge flip to danger and the block overlay appear, in real time, with the specific reason named ("mimics [Brand] — registered 0 minutes ago, submits to a different domain").

Why this beats a "type a URL to test" box: the judge is creating the attack themselves, on an artifact that didn't exist ten seconds earlier, so there is no possible accusation of a rigged demo or a hardcoded lookup. It is the most convincing possible proof of both "real-time" and "AI, not blocklist."

**Safety note:** never navigate to real live malicious sites during a demo — legally and ethically risky, and unreliable (site may go down mid-demo). The self-generated local simulator avoids this entirely while being more impressive.

---

## 10. Luxury UX Spec

Avoid the generic browser-warning look (red triangle, Comic-Sans-adjacent system alert). Target a fintech-security aesthetic — think Stripe Radar / Coinbase security alerts, not "Your PC is infected" pop-ups.

- **Palette:** deep charcoal/navy base, single accent color per state — emerald (safe), amber (caution), crimson (danger). No gradients-for-the-sake-of-gradients.
- **Motion:** badge pulses once on state change (200ms ease), popup risk score animates a count-up rather than snapping to the final number, block overlay fades the page behind a blur rather than hard-cutting to a warning screen.
- **Block overlay content:** a centered glass card with a *side-by-side visual*: "What you're looking at" (screenshot thumbnail of the current page) vs. "The real [Brand] site" (thumbnail of the legitimate domain) — this single visual does more convincing than any paragraph of text.
- **Typography:** one clean sans-serif, generous whitespace, numbers given real visual weight (the risk score should look like a stat, not a label).
- **Popup structure:** three tabs — *Verdict* (score + reason), *Model Card* (the real ML numbers), *Benchmark* (the live stress test).

---

## 11. Zero-Effort UX

- No install-time configuration, no account, no toggles required to get protection.
- Badge is passive and ambient — users only act when danger fires.
- Popup is optional depth, never required reading.
- Override ("proceed anyway") is one click, logged locally only, never blocks the user's agency.

---

## 12. Business-Safe & Real-Time Adaptation

- **Privacy-by-architecture:** all scoring happens on-device; no page content, URL, or browsing history is ever transmitted anywhere. This is a genuine enterprise-adoption argument, not a compliance checkbox — say this explicitly to judges, it's a real differentiator versus any cloud-scored competitor.
- **Adapts without a new release:** the protected-brand list and any blocklist entries live in a small JSON file hosted for free (GitHub raw / GitHub Pages / jsDelivr CDN off a public repo — all free, no server to maintain) and refreshed periodically by the background worker. New brands or confirmed phishing domains can be added by editing that file — no extension resubmission, no user update required.
- **False-positive safety net:** an allowlist of major legitimate domains (free Tranco Top-1M list) is checked before any block, so Verity structurally cannot flag a real major business — this is your direct answer to "what stops this from breaking legitimate sites," which judges will ask.

---

## 13. Full Feature List

**MVP (must build for demo):**
- Rule pre-filter (URL structure heuristics)
- Trained ONNX classifier running on-device
- Brand similarity engine (curated 100-brand list)
- Live badge (3-state, animated)
- Block overlay with side-by-side "real vs. fake" visual
- Popup: Verdict tab, Model Card tab, Benchmark Mode tab
- Live Attack Simulator
- Millisecond timing display on every verdict

**Stretch (only if MVP is solid with time to spare):**
- Gemini Nano–generated natural-language explanation (Layer 5, with fallback)
- Hot-reloadable brand/threat list from free static hosting
- "Report a miss" button that logs locally for a post-hoc accuracy story
- Dark/light theme toggle for the popup

Do not start stretch items until every MVP item works end-to-end and the Simulator demo is reliable — a flawless narrow demo beats a broad shaky one.

---

## 14. Tech Stack (All Free, With No Hidden Costs)

| Component | Choice | Why It's Actually Free |
|---|---|---|
| Extension shell | Chrome Extension, Manifest V3 | No cost, no account needed |
| Model inference | `onnxruntime-web` (WASM) | Open-source, runs client-side, no API key |
| Model training | Python (scikit-learn / XGBoost) offline, once | Runs on your own laptop or free Colab/Kaggle compute |
| Model export | `skl2onnx` / `onnxmltools` | Open-source |
| Dataset | UCI/Kaggle "Phishing Websites" dataset | Public, free, no license blocker |
| Brand/threat list hosting | GitHub raw file or GitHub Pages | Free static hosting, no server |
| Legit-domain allowlist | Tranco Top-1M list | Free, academically maintained |
| Optional NL explanation | Chrome built-in Prompt API (Gemini Nano) | Free, on-device, no API key — confirmed shipped in Chrome stable as of 2026 |
| Popup UI | Plain HTML/CSS/JS or a tiny React build | No hosting cost — bundled into the extension |

Nothing here has a paid tier in the critical demo path. The only "cost" is local disk space if you use the optional Gemini Nano layer (a few GB, downloaded once by Chrome itself, no charge).

---

## 15. Data & Model — How You Train It, For Free

1. Pull the public phishing-websites dataset (~11k labeled rows, 30 pre-engineered features — URL length, IP-address use, `@` symbol presence, HTTPS state, domain age, subdomain count, etc.).
2. Train a small classifier (start with logistic regression for pure interpretability — coefficients directly become your "explainability" numbers; try Random Forest/XGBoost if you want a few extra points of accuracy and can still extract feature importances).
3. Hold out 20% for testing. Record confusion matrix, precision, recall, F1, ROC-AUC — these go straight into the Model Card, verbatim, no rounding up.
4. Export to ONNX; confirm the exported model's predictions match the Python model's predictions on a few sample rows (sanity check before demo day).
5. Separately, hand-build the 100-brand list (name, canonical domain, a short logo/text fingerprint) and a matching synthetic typosquat test set (e.g., `paypa1.com`, `arnaz0n-support.com`) to produce the narrow-scope near-100% number.

---

## 16. Demo Script (Aim for 4–5 Minutes)

| Time | Beat | What You Show |
|---|---|---|
| 0:00–0:30 | Hook | State the problem in one sentence; badge already live in the browser bar during setup |
| 0:30–1:15 | Normal browsing | Visit a real bank site → badge stays calm/safe, near-instant, no user action taken |
| 1:15–2:30 | **Live Attack Simulator** | Judge (or you, inviting a judge to pick the brand) builds a fake login page live; Verity catches it in real time; overlay shows the side-by-side real-vs-fake visual |
| 2:30–3:15 | Explainability | Open the popup, walk through the Model Card — real confusion matrix, real precision/recall |
| 3:15–4:00 | Benchmark Mode | Click stress test → 50 URLs score live, latency chart fills in, accuracy count ticks up |
| 4:00–4:30 | Business-safe pitch | One line: "Nothing leaves the device — this is deployable inside a company today, not just a prototype" |

---

## 17. Numbers To Have Memorized for Q&A

- Test-set accuracy / precision / recall / F1 / ROC-AUC on the public dataset (from your own training run — write the real numbers here once trained, don't estimate).
- Number of brands in the protected set, and accuracy on your synthetic typosquat test set.
- Median and p95 scoring latency from the Benchmark Mode run.
- Size of the shipped ONNX model file (proves it's genuinely lightweight/on-device, not a thin wrapper).

---

## 18. Build Order (Time-Boxed)

1. Train + export the ONNX model and confirm predictions match Python (do this first — everything else depends on it).
2. Wire the background service worker: rule layer → ONNX inference → verdict combiner → badge.
3. Build the block overlay with the real-vs-fake visual.
4. Build the popup: Verdict tab first, then Model Card, then Benchmark Mode.
5. Build the Live Attack Simulator page — this is your differentiator, budget real time for it, don't leave it for the last hour.
6. Polish pass: motion, color states, typography — only after every functional piece works.
7. Full run-through of the demo script, twice, on a clean Chrome profile.

---

## 19. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| ONNX model doesn't load in the extension sandbox | Test this on day one, not the night before — it's the highest-risk integration point |
| Gemini Nano not downloaded on judge's machine | Keep it strictly optional with a silent, tested fallback to the deterministic explanation |
| Judge picks a brand not in your curated list during the Simulator | Pre-load the 10–15 most recognizable brands (major banks, PayPal, Amazon) so any reasonable pick works |
| Live demo network hiccup | Nothing in the critical path needs network — the whole demo works offline by design |
| "Near 100%" sounds like an exaggerated claim | Always state it scoped ("100% on our protected-brand test set," not "100% at phishing detection") — this is both more honest and more credible to judges |

---

*This plan assumes you have flexibility on branding/scope wording to match whatever exact problem statement your hackathon issues — swap in their exact language in Section 1 while keeping the architecture and proof systems as-is.*
