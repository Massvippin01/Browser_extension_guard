/**
 * shared/messages.en.js — Structured Reason Catalog and Translation System
 * 
 * Classic script compatible (loaded in extension content scripts)
 * and ES module compatible (loaded in Node.js test suites).
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node.js CommonJS
    module.exports = factory();
  } else if (typeof define === 'function' && define.amd) {
    // AMD
    define(factory);
  } else {
    // Browser global (Classic Script) or ES Module environment
    const exp = factory();
    root.VerityMessages = exp;
    root.t = exp.t;
    root.MESSAGES = exp.MESSAGES;
    root.SIGNAL_CATEGORY_MAP = exp.SIGNAL_CATEGORY_MAP;
    root.CATEGORY_CAPS = exp.CATEGORY_CAPS;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {

  /**
   * Message Catalog — maps Reason ID to a templating function.
   * Every emitted ID must have a matching entry.
   */
  const MESSAGES = {
    // ── URL Rules ─────────────────────────────────────────────────────────────
    RULE_IP_BASED_URL: (p) => 'The URL uses a raw IP address instead of a domain name.',
    RULE_MISSING_HTTPS: (p) => 'The connection is not secure (HTTP instead of HTTPS).',
    RULE_EXCESSIVE_SUBDOMAINS: (p) => `The URL uses an unusually high number of subdomains (${p?.count || 'excessive'}).`,
    RULE_BRAND_NAME_WRONG_DOMAIN: (p) => `The URL contains the name "${p?.brand || 'Brand'}" but does not belong to its official domain.`,
    RULE_BRAND_VARIANT_MATCH: (p) => `Hostname matches a known typosquat variant of "${p?.brand || 'Brand'}".`,
    RULE_FINANCIAL_KEYWORD_HOSTNAME: (p) => `Hostname contains financial keyword "${p?.keyword || 'banking'}" on an unverified domain.`,
    RULE_PUNYCODE_OR_KEYWORDS: (p) => `The URL contains punycode or suspicious keywords: ${p?.keywords || 'suspicious'}.`,
    RULE_RANDOM_LOOKING_HOSTNAME: (p) => `Hostname appears randomly generated or suspicious (${p?.entropy || 'high entropy'}).`,
    RULE_SUSPICIOUS_URL_PATTERN: (p) => 'Suspicious URL characteristics detected (@ symbol or excessive hyphens).',
    RULE_AFFILIATE_TRACKER: (p) => 'Suspicious affiliate or ad-tracker parameter sequence detected.',
    RULE_MALVERTISING_REDIRECT: (p) => 'High-risk malvertising redirect or obfuscated pattern detected.',
    RULE_PIRACY_MEDIA: (p) => 'Unverified streaming or piracy media pattern detected.',

    // ── Brand Detector ────────────────────────────────────────────────────────
    BRAND_TYPOSQUATTING: (p) => `Hostname is a visual typosquat of "${p?.brand || 'Brand'}" (distance: ${p?.distance || 1}).`,

    // ── Risk Engine Signals ───────────────────────────────────────────────────
    SIG_URL_SUSPICIOUS: (p) => `URL structure exhibits suspicious patterns (${p?.details || 'heuristic signals'}).`,
    SIG_IP_HOST: (p) => 'Raw IP address host detected.',
    SIG_MALVERTISING: (p) => 'Malvertising or suspicious traffic redirection detected.',
    SIG_POPUNDER_SPAWN: (p) => `High risk: Pop-under tab automatically spawned to a different unverified domain (${p?.targetDomain || 'external'}).`,
    SIG_ML_PHISHING: (p) => `On-device ML model flagged structural phishing characteristics (${p?.confidence || 0}% confidence).`,
    SIG_BRAND_IMPERSONATION: (p) => `Brand impersonation detected: claims to be "${p?.brand || 'Brand'}".`,
    SIG_CONTENT_BRAND_IMPERSONATION: (p) => `Page claims to be "${p?.brand || 'Brand'}" while requesting login credentials on an unverified domain.`,
    SIG_CREDENTIAL_COLLECTION: (p) => 'Page requests sensitive credentials or payment information.',
    SIG_PASSWORD_REQUEST: (p) => 'Page requests a password.',
    SIG_LOGIN_FORM: (p) => 'Login form detected.',
    SIG_SCAM_LANGUAGE: (p) => `Matches scam language: "${p?.phrase || 'urgent notice'}".`,
    SIG_CLICKFIX_CLIPBOARD_ATTACK: (p) => `Critical risk: ClickFix fake verification lure attempting clipboard command execution (PowerShell/Run-box). ${p?.phrase || ''}`.trim(),
    SIG_SCAM_BONUS_LURE: (p) => `Deceptive bonus, prize claim, or fake reward lure detected: "${p?.phrase || 'Bonus claim'}".`,
    SIG_PUP: (p) => `Potentially unwanted script or hidden iframes detected (${p?.details || 'obfuscation'}).`,
    SIG_FINANCIAL_CONTEXT: (p) => `Financial terminology detected: ${p?.terms || 'banking keywords'}.`,
    SIG_SYNERGY_IMPERSONATION_CREDENTIALS: (p) => 'High risk: Impersonating a trusted brand while requesting sensitive credentials.',
    SIG_SYNERGY_FINANCIAL_CREDENTIALS: (p) => 'High risk: Unverified site requesting financial credentials.',
    SIG_SYNERGY_REDIRECT_CREDENTIALS: (p) => 'Critical risk: Suspicious redirect routing to a credential collection page.',
    SIG_DIGITAL_ARREST_SCAM: (p) => 'High risk: Digital arrest or utility disconnection scam pattern detected on an unverified domain.',
    SIG_UPI_DEBIT_TRAP: (p) => 'High risk: UPI cashback or debit trap detected hiding a payment request.',
    SIG_PAYMENT_PHISHING: (p) => 'High risk: Unverified domain requesting payment credentials (Card/CVV/OTP).',
    SIG_CROSS_DOMAIN_CREDENTIAL_EXFIL: (p) => `Critical risk: Form transmits sensitive credentials to an untrusted external domain (${p?.targetDomain || 'unverified'}).`,

    // ── Payment Protection Signals ────────────────────────────────────────────
    PAYMENT_FAKE_PROVIDER: (p) => `Page claims to be "${p?.claimedProvider || 'Provider'}" but domain "${p?.hostname || ''}" is not its official domain.`,
    PAYMENT_DOMAIN_MISMATCH: (p) => `Official domain mismatch: "${p?.hostname || ''}" is not a verified "${p?.claimedProvider || 'Provider'}" domain.`,
    PAYMENT_CARD_CVV_UNVERIFIED: (p) => 'Card/CVV information requested on unverified payment domain.',
    PAYMENT_CARD_CVV_GENERIC: (p) => 'Card number and CVV fields detected.',
    PAYMENT_OTP_UNVERIFIED: (p) => 'OTP collection on unverified payment domain.',
    PAYMENT_UNKNOWN_PROVIDER: (p) => 'Payment page from unrecognized or unverified payment provider.',
    PAYMENT_FORM_DETECTED: (p) => 'Payment form detected on page.',
    SIG_PAYMENT_BRAND_MISMATCH: (p) => `Brand mismatch: Page claims to be "${p?.claimedProvider || p?.claimedBrand || 'Bank/Payment Gateway'}" but domain "${p?.hostname || ''}" is not its official domain.`,
    SIG_ILLEGAL_WEB_PIN_COLLECTION: (p) => `Critical financial fraud: Illegal in-browser UPI PIN or ATM PIN collection detected (${p?.phrase || 'UPI PIN'}). Legitimate UPI payments never ask for PIN in web browsers.`,
    SIG_UNVERIFIED_UPI_COLLECTION: (p) => 'Unverified UPI collect request, deep-link, or fake QR code detected on an untrusted domain.',
    SIG_KYC_CYBER_FRAUD: (p) => `Critical cyber fraud: Fake KYC/PAN/Aadhaar verification lure combined with account suspension or penalty threat (${p?.phrase || 'KYC suspension lure'}).`,
    SIG_PHISHING_KIT_WEBHOOK_EXFIL: (p) => `Critical threat: Phishing kit exfiltration endpoint detected (${p?.endpoint || 'Telegram/Discord webhook'}) on credential collection page.`,
    SIG_HIGH_PRESSURE_PAYMENT_TIMER: (p) => 'Artificial high-pressure countdown timer detected on unverified payment page.',
    SIG_BRAND_ASSET_HOTLINK_SPOOF: (p) => `Brand asset hotlinking detected: Page hotlinks official logo or favicon from "${p?.brand || p?.assetHost || 'official brand'}" on an unverified domain.`,
    SIG_REMOTE_ACCESS_SCAM_DOWNLOAD: (p) => `Critical cyber fraud: Remote desktop access tool (${p?.tool || p?.filename || 'remote access software'}) download initiated from an unverified domain.`,
    SIG_TECH_SUPPORT_REMOTE_SCAM: (p) => `Critical cyber fraud: Remote desktop support lure detected (${p?.tool || 'AnyDesk/TeamViewer'}) paired with fake customer support or KYC helpline.`,
    SIG_UNTRUSTED_SCREEN_SHARE: (p) => 'Critical threat: Untrusted screen sharing attempt detected on suspicious domain (Digital Arrest / Tech-Support scam).',

    // ── Download Interceptor Signals ──────────────────────────────────────────
    DOWNLOAD_CHROME_DANGEROUS: (p) => 'Chrome identified this file as dangerous.',
    SIG_HTML_SMUGGLING_DOWNLOAD: (p) => `High risk: HTML smuggling detected (blob/data URI download from unverified origin "${p?.source || 'external'}").`,
    DOWNLOAD_EXECUTABLE: (p) => `Executable file (.exe/.com/.scr) download: "${p?.filename || ''}".`,
    DOWNLOAD_SCRIPT: (p) => `Script file (${p?.extension || 'script'}) download: "${p?.filename || ''}".`,
    DOWNLOAD_INSTALLER: (p) => `Installer or mobile package (${p?.extension || 'package'}) download: "${p?.filename || ''}".`,
    DOWNLOAD_ARCHIVE: (p) => 'Archive file — may contain executables.',
    DOWNLOAD_DOUBLE_EXTENSION: (p) => `Double extension detected: "${p?.apparentExtension || ''}" hidden by "${p?.extension || ''}".`,
    DOWNLOAD_CONTENT_DISPOSITION_SPOOF: (p) => 'Content-Disposition header spoofed document URL to executable or container.',
    DOWNLOAD_MISLEADING_NAME: (p) => `Misleading filename keyword: "${p?.keyword || ''}".`,
    DOWNLOAD_BRAND_IMPERSONATION: (p) => `Download impersonates: "${p?.brand || 'Brand'}".`,
    DOWNLOAD_SOURCE_MALICIOUS: (p) => 'Source domain flagged as malicious.',
    DOWNLOAD_SUSPICIOUS_TLD: (p) => 'Source domain uses suspicious TLD.',
    DOWNLOAD_SHORTENER: (p) => 'URL shortener in download chain.',
    DOWNLOAD_REDIRECT_HOPS: (p) => `${p?.hops || 2} cross-domain redirects before download.`,
    DOWNLOAD_UNICODE: (p) => 'Filename contains Unicode or confusable characters.',

    // ── Threat Intel & Overrides ──────────────────────────────────────────────
    THREAT_INTEL_MALWARE: (p) => `Threat intelligence: known malware site (${p?.source || 'URLhaus'}).`,
    SECURITY_ERROR_ABORTED: (p) => 'Security Error: Connection terminated due to untrusted security certificate or network block.',
    USER_OVERRIDE_ACTIVE: (p) => 'User override active for this domain.',

    // ── Popup & Options UI Strings ───────────────────────────────────────────
    UI_POPUP_TITLE: () => 'VERITY',
    UI_POPUP_SUBTITLE: () => 'Web Protection',
    UI_STATUS_SAFE: () => 'Safe',
    UI_STATUS_CAUTION: () => 'Suspicious',
    UI_STATUS_DANGER: () => 'Dangerous',
    UI_STATUS_UNKNOWN: () => 'Unscannable',
    UI_STATUS_ANALYZING: () => 'Analyzing...',
    UI_VERDICT_SAFE: () => 'Safe to browse',
    UI_VERDICT_CAUTION: () => 'Suspicious activity flagged',
    UI_VERDICT_DANGER: () => 'High-risk threat blocked',
    UI_VERDICT_UNSCANNABLE: () => 'System or local page',
    UI_SCORE_LABEL: () => 'Risk Score',
    UI_WHY_TITLE: () => 'Why we flagged this',
    UI_NO_SIGNALS: () => 'No suspicious signals detected.',
    UI_ACTION_SAFE: () => 'This site is safe',
    UI_ACTION_COPY: () => 'Copy domain',
    UI_ACTION_SETTINGS: () => 'Settings',
    UI_FOOTER_PROTECTION: () => 'Real-time Protection',
    UI_FOOTER_VERSION: () => 'v2.0.0 · On-device ML',
    UI_SW_ERROR: () => 'Service worker unreachable',
    UI_SW_ERROR_DESC: () => 'Could not connect to background protection service.',
    UI_RETRY: () => 'Retry connection',
    UI_COPIED: () => 'Copied!',
    UI_CONFIRM_SAFE_TITLE: () => 'Confirm Trust',
    UI_CONFIRM_SAFE_DESC: (p) => `Are you sure you want to trust "${p?.domain || 'this domain'}"? High-risk protections will be bypassed for this site.`,
    UI_CONFIRM_PROCEED: () => 'Yes, trust site',
    UI_CONFIRM_CANCEL: () => 'Cancel',

    OPT_TITLE: () => 'VERITY Settings',
    OPT_SUBTITLE: () => 'On-device web protection and security preferences',
    OPT_NAV_GENERAL: () => 'General',
    OPT_NAV_PROTECTION: () => 'Protection Levels',
    OPT_NAV_ALLOWLIST: () => 'Allowlist',
    OPT_NAV_ABOUT: () => 'About',
    OPT_SAVED: () => 'Saved',
    OPT_THEME_TITLE: () => 'Interface Theme',
    OPT_THEME_DESC: () => 'Select visual theme for popups and notification overlays',
    OPT_THEME_SYSTEM: () => 'System',
    OPT_THEME_LIGHT: () => 'Light',
    OPT_THEME_DARK: () => 'Dark',
    OPT_REALTIME_TITLE: () => 'Real-time Web Protection',
    OPT_REALTIME_DESC: () => 'Active background inspection of URLs, redirects, and DOM phishing lures',
    OPT_LEVEL_PHISHING_TITLE: () => 'Phishing & Impersonation Shield',
    OPT_LEVEL_PHISHING_DESC: () => 'Blocks lookalike hostnames, brand typosquatting, and credential harvesting forms',
    OPT_LEVEL_PAYMENT_TITLE: () => 'Financial & Payment Defense',
    OPT_LEVEL_PAYMENT_DESC: () => 'Detects unverified gateways collecting cards, CVV, OTPs, and UPI debit traps',
    OPT_LEVEL_DOWNLOAD_TITLE: () => 'Malicious Download Interceptor',
    OPT_LEVEL_DOWNLOAD_DESC: () => 'Scans executables, hidden extensions, and untrusted APK payloads before launch',
    OPT_LEVEL_POPUP_TITLE: () => 'Aggressive Pop-up Killer',
    OPT_LEVEL_POPUP_DESC: () => 'Automatically terminates unprompted new windows and malicious ad-redirects',
    OPT_ALLOWLIST_TITLE: () => 'Trusted Domains Allowlist',
    OPT_ALLOWLIST_DESC: () => 'Domains you have explicitly marked as safe or bypassed past warning screens',
    OPT_ALLOWLIST_ADD: () => 'Add Domain',
    OPT_ALLOWLIST_PLACEHOLDER: () => 'e.g. portal.internal-company.net',
    OPT_ALLOWLIST_EMPTY: () => 'No custom domains in your allowlist.',
    OPT_ALLOWLIST_EMPTY_DESC: () => 'Bypassed sites and explicitly allowed domains will appear here.',
    OPT_ALLOWLIST_REMOVE: () => 'Remove',
    OPT_ALLOWLIST_UNDO: () => 'Undo',
    OPT_ABOUT_TITLE: () => 'About VERITY',
    OPT_ABOUT_DESC: () => 'Next-generation private web protection powered by on-device ML.',
    OPT_ABOUT_VERSION: () => 'Version',
    OPT_ABOUT_BUILD: () => 'Build Target',
    OPT_ABOUT_PRIVACY: () => 'Zero-Telemetry Architecture',
    OPT_ABOUT_PRIVACY_DESC: () => 'Verity processes all URL signals, DOM features, and heuristic models strictly on your device. Your browsing history is never transmitted to any external server.',

    // ── Warning Overlay Strings (Phase UI-1.1) ────────────────────────────────
    OVERLAY_TITLE_BLOCK: () => 'This site looks dangerous',
    OVERLAY_TITLE_CAUTION: () => 'Be careful on this site',
    OVERLAY_TITLE_BLOCK_PRE: () => 'This site looks ',
    OVERLAY_TITLE_BLOCK_WORD: () => 'dangerous',
    OVERLAY_TITLE_CAUTION_WORD: () => 'Be careful',
    OVERLAY_TITLE_CAUTION_POST: () => ' on this site',

    OVERLAY_SUMMARY_PAYMENT: () => 'This site appears to be impersonating a payment provider or financial institution to capture sensitive credentials.',
    OVERLAY_SUMMARY_PHISHING: () => 'This site mimics a trusted service or requests credentials that could compromise your security.',
    OVERLAY_SUMMARY_THREAT_INTEL: () => 'This site is listed on verified threat intelligence feeds as hosting malicious content.',
    OVERLAY_SUMMARY_MALVERTISING: () => 'This site was launched through deceptive advertising redirects commonly associated with unwanted software.',
    OVERLAY_SUMMARY_NEUTRAL: () => 'This site showed warning signs that are common on unsafe pages.',
    OVERLAY_SUMMARY_CAUTION: () => 'This site exhibits unusual patterns or unconfirmed security details. Exercise caution before interacting with it.',

    OVERLAY_BTN_SAFETY: () => 'Take me to safety',
    OVERLAY_BTN_PROCEED: () => 'Continue anyway',
    OVERLAY_WHY_FLAGGED: (p) => `Why we flagged this (${p?.count || 0})`,
    OVERLAY_RISK_SCORE_LABEL: () => 'Risk score',
    OVERLAY_PROTECTED_BY: () => 'Protected by VERITY Web Protection',
    OVERLAY_REPORT_ISSUE: () => 'Report an issue',
    OVERLAY_CONFIRM_TITLE: () => 'Are you sure you want to proceed?',
    OVERLAY_CONFIRM_BADGE: () => 'High Risk Confirmation',
    OVERLAY_CONFIRM_DESC: (p) => `This site is classified as ${p?.state || 'dangerous'}. Bypassing protection exposes you to potential credential theft, phishing, or financial risk.`,
    OVERLAY_CONFIRM_CANCEL: () => 'Return to safety',
    OVERLAY_CONFIRM_PROCEED: () => 'I understand the risks, proceed',
    OVERLAY_CONFIRM_WAIT: (p) => `Please wait (${p?.seconds || '1.5'}s)...`,

    // ── Search Result Badges & Tooltips (Phase UI-1.2) ─────────────────────────
    SEARCH_BADGE_SAFE: () => 'Safe',
    SEARCH_BADGE_SUSPICIOUS: () => 'Suspicious',
    SEARCH_BADGE_DANGEROUS: () => 'Dangerous',
    SEARCH_BADGE_CHECKING: () => 'Checking',
    SEARCH_BADGE_ARIA: (p) => `Verity security rating: ${p?.state || 'Safe'}`,

    SEARCH_POPOVER_TITLE_SAFE: () => 'Looks safe',
    SEARCH_POPOVER_TITLE_CAUTION: () => 'Be careful with this link',
    SEARCH_POPOVER_TITLE_BLOCK: () => 'Dangerous link',
    SEARCH_POPOVER_TITLE_CHECKING: () => 'Checking link safety...',

    SEARCH_POPOVER_SAFE_DESC: () => 'No warning signs found by on-device checks.',
    SEARCH_POPOVER_CHECKING_DESC: () => 'Analyzing URL reputation and characteristics...',
    SEARCH_POPOVER_MORE_REASONS: (p) => `+${p?.count || 1} more`,

    SEARCH_POPOVER_RISK_SCORE: () => 'Risk score',
    SEARCH_POPOVER_SCORE_VALUE: (p) => `${p?.score ?? 0} / 100`,
    SEARCH_POPOVER_FOOTER_BRAND: () => 'Protected by VERITY'
  };

  /**
   * Explicit Category Mapping:
   * Maps each signal ID strictly to its assigned risk category.
   * Guaranteed: No signal lands in two risk categories unless explicitly declared.
   */
  const SIGNAL_CATEGORY_MAP = {
    // Category: url
    RULE_MISSING_HTTPS: 'url',
    RULE_EXCESSIVE_SUBDOMAINS: 'url',
    RULE_FINANCIAL_KEYWORD_HOSTNAME: 'url',
    RULE_PUNYCODE_OR_KEYWORDS: 'url',
    RULE_RANDOM_LOOKING_HOSTNAME: 'url',
    RULE_SUSPICIOUS_URL_PATTERN: 'url',
    RULE_AFFILIATE_TRACKER: 'url',
    RULE_PIRACY_MEDIA: 'url',
    SIG_URL_SUSPICIOUS: 'url',

    // Category: ip_host (high-confidence network track)
    RULE_IP_BASED_URL: 'ip_host',
    SIG_IP_HOST: 'ip_host',

    // Category: malvertising
    RULE_MALVERTISING_REDIRECT: 'malvertising',
    SIG_MALVERTISING: 'malvertising',
    SIG_POPUNDER_SPAWN: 'malvertising',

    // Category: brand_impersonation
    RULE_BRAND_NAME_WRONG_DOMAIN: 'brand_impersonation',
    RULE_BRAND_VARIANT_MATCH: 'brand_impersonation',
    BRAND_TYPOSQUATTING: 'brand_impersonation',
    SIG_BRAND_IMPERSONATION: 'brand_impersonation',
    SIG_BRAND_ASSET_HOTLINK_SPOOF: 'brand_impersonation',
    SIG_CONTENT_BRAND_IMPERSONATION: 'brand_impersonation',

    // Category: ml
    SIG_ML_PHISHING: 'ml',

    // Category: dom_credentials
    SIG_CREDENTIAL_COLLECTION: 'dom_credentials',
    SIG_PASSWORD_REQUEST: 'dom_credentials',
    SIG_LOGIN_FORM: 'dom_credentials',
    PAYMENT_CARD_CVV_UNVERIFIED: 'dom_credentials',
    PAYMENT_CARD_CVV_GENERIC: 'dom_credentials',
    PAYMENT_OTP_UNVERIFIED: 'dom_credentials',

    // Category: scam_language
    SIG_SCAM_LANGUAGE: 'scam_language',
    SIG_SCAM_BONUS_LURE: 'scam_language',
    SIG_CLICKFIX_CLIPBOARD_ATTACK: 'scam_language',
    SIG_PUP: 'scam_language',
    SIG_FINANCIAL_CONTEXT: 'scam_language',
    SIG_DIGITAL_ARREST_SCAM: 'scam_language',
    SIG_UPI_DEBIT_TRAP: 'scam_language',
    PAYMENT_UNKNOWN_PROVIDER: 'scam_language',
    PAYMENT_FORM_DETECTED: 'scam_language',
    SIG_KYC_CYBER_FRAUD: 'scam_language',
    SIG_TECH_SUPPORT_REMOTE_SCAM: 'scam_language',

    // Category: payment_phishing
    PAYMENT_FAKE_PROVIDER: 'payment_phishing',
    PAYMENT_DOMAIN_MISMATCH: 'payment_phishing',
    SIG_PAYMENT_PHISHING: 'payment_phishing',
    SIG_PAYMENT_BRAND_MISMATCH: 'payment_phishing',
    SIG_ILLEGAL_WEB_PIN_COLLECTION: 'payment_phishing',
    SIG_UNVERIFIED_UPI_COLLECTION: 'payment_phishing',
    SIG_HIGH_PRESSURE_PAYMENT_TIMER: 'payment_phishing',

    // Category: synergy
    SIG_SYNERGY_IMPERSONATION_CREDENTIALS: 'synergy',
    SIG_SYNERGY_FINANCIAL_CREDENTIALS: 'synergy',
    SIG_SYNERGY_REDIRECT_CREDENTIALS: 'synergy',

    // Category: download
    DOWNLOAD_CHROME_DANGEROUS: 'download',
    SIG_REMOTE_ACCESS_SCAM_DOWNLOAD: 'download',
    SIG_HTML_SMUGGLING_DOWNLOAD: 'download',
    DOWNLOAD_EXECUTABLE: 'download',
    DOWNLOAD_SCRIPT: 'download',
    DOWNLOAD_INSTALLER: 'download',
    DOWNLOAD_ARCHIVE: 'download',
    DOWNLOAD_DOUBLE_EXTENSION: 'download',
    DOWNLOAD_CONTENT_DISPOSITION_SPOOF: 'download',
    DOWNLOAD_MISLEADING_NAME: 'download',
    DOWNLOAD_BRAND_IMPERSONATION: 'download',
    DOWNLOAD_SOURCE_MALICIOUS: 'download',
    DOWNLOAD_SUSPICIOUS_TLD: 'download',
    DOWNLOAD_SHORTENER: 'download',
    DOWNLOAD_REDIRECT_HOPS: 'download',
    DOWNLOAD_UNICODE: 'download',

    // Category: threat_intel
    THREAT_INTEL_MALWARE: 'threat_intel',
    SECURITY_ERROR_ABORTED: 'threat_intel',
    USER_OVERRIDE_ACTIVE: 'threat_intel',
    SIG_CROSS_DOMAIN_CREDENTIAL_EXFIL: 'threat_intel',
    SIG_PHISHING_KIT_WEBHOOK_EXFIL: 'threat_intel',
    SIG_UNTRUSTED_SCREEN_SHARE: 'threat_intel'
  };

  /**
   * Documented Category Caps:
   * Maximum points allowable per category before combining.
   * Hard Invariant: No single category cap can reach the Block threshold (70) alone.
   * Multi-signal convergence is strictly required to achieve a Block verdict.
   */
  const CATEGORY_CAPS = {
    url: 40,
    ip_host: 60,
    malvertising: 85,
    brand_impersonation: 55,
    ml: 35,
    dom_credentials: 50,
    scam_language: 75,
    payment_phishing: 65,
    synergy: 40,
    download: 60,
    threat_intel: 65
  };

  /**
   * Translate Reason ID to English user text.
   * @param {string} id - The structured Reason ID
   * @param {object} [params] - Dynamic parameters
   * @returns {string} Human-readable reason string
   */
  function t(id, params) {
    if (!id) return '';
    const fn = MESSAGES[id];
    if (typeof fn === 'function') {
      try {
        return fn(params || {});
      } catch (e) {
        return id;
      }
    }
    // Fallback: if string was already pre-translated or unknown ID
    return String(id);
  }

  return {
    MESSAGES,
    SIGNAL_CATEGORY_MAP,
    CATEGORY_CAPS,
    t
  };
});
