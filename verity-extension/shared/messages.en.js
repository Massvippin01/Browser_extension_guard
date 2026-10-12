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
    SIG_ML_PHISHING: (p) => `On-device ML model flagged structural phishing characteristics (${p?.confidence || 0}% confidence).`,
    SIG_BRAND_IMPERSONATION: (p) => `Brand impersonation detected: claims to be "${p?.brand || 'Brand'}".`,
    SIG_CONTENT_BRAND_IMPERSONATION: (p) => `Page claims to be "${p?.brand || 'Brand'}" while requesting login credentials on an unverified domain.`,
    SIG_CREDENTIAL_COLLECTION: (p) => 'Page requests sensitive credentials or payment information.',
    SIG_PASSWORD_REQUEST: (p) => 'Page requests a password.',
    SIG_LOGIN_FORM: (p) => 'Login form detected.',
    SIG_SCAM_LANGUAGE: (p) => `Matches scam language: "${p?.phrase || 'urgent notice'}".`,
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

    // ── Download Interceptor Signals ──────────────────────────────────────────
    DOWNLOAD_CHROME_DANGEROUS: (p) => 'Chrome identified this file as dangerous.',
    DOWNLOAD_EXECUTABLE: (p) => `Executable file (.exe/.com/.scr) download: "${p?.filename || ''}".`,
    DOWNLOAD_SCRIPT: (p) => `Script file (${p?.extension || 'script'}) download: "${p?.filename || ''}".`,
    DOWNLOAD_INSTALLER: (p) => `Installer or mobile package (${p?.extension || 'package'}) download: "${p?.filename || ''}".`,
    DOWNLOAD_ARCHIVE: (p) => 'Archive file — may contain executables.',
    DOWNLOAD_DOUBLE_EXTENSION: (p) => `Double extension detected: "${p?.apparentExtension || ''}" hidden by "${p?.extension || ''}".`,
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
    USER_OVERRIDE_ACTIVE: (p) => 'User override active for this domain.'
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

    // Category: brand_impersonation
    RULE_BRAND_NAME_WRONG_DOMAIN: 'brand_impersonation',
    RULE_BRAND_VARIANT_MATCH: 'brand_impersonation',
    BRAND_TYPOSQUATTING: 'brand_impersonation',
    SIG_BRAND_IMPERSONATION: 'brand_impersonation',
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
    SIG_PUP: 'scam_language',
    SIG_FINANCIAL_CONTEXT: 'scam_language',
    SIG_DIGITAL_ARREST_SCAM: 'scam_language',
    SIG_UPI_DEBIT_TRAP: 'scam_language',
    PAYMENT_UNKNOWN_PROVIDER: 'scam_language',
    PAYMENT_FORM_DETECTED: 'scam_language',

    // Category: payment_phishing
    PAYMENT_FAKE_PROVIDER: 'payment_phishing',
    PAYMENT_DOMAIN_MISMATCH: 'payment_phishing',
    SIG_PAYMENT_PHISHING: 'payment_phishing',

    // Category: synergy
    SIG_SYNERGY_IMPERSONATION_CREDENTIALS: 'synergy',
    SIG_SYNERGY_FINANCIAL_CREDENTIALS: 'synergy',
    SIG_SYNERGY_REDIRECT_CREDENTIALS: 'synergy',

    // Category: download
    DOWNLOAD_CHROME_DANGEROUS: 'download',
    DOWNLOAD_EXECUTABLE: 'download',
    DOWNLOAD_SCRIPT: 'download',
    DOWNLOAD_INSTALLER: 'download',
    DOWNLOAD_ARCHIVE: 'download',
    DOWNLOAD_DOUBLE_EXTENSION: 'download',
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
    SIG_CROSS_DOMAIN_CREDENTIAL_EXFIL: 'threat_intel'
  };

  /**
   * Documented Category Caps:
   * Maximum points allowable per category before combining.
   * Hard Invariant: No single category cap can reach the Block threshold (70) alone.
   * Multi-signal convergence is strictly required to achieve a Block verdict.
   */
  const CATEGORY_CAPS = {
    url: 30,
    ip_host: 60,
    malvertising: 60,
    brand_impersonation: 60,
    ml: 25,
    dom_credentials: 25,
    scam_language: 20,
    payment_phishing: 60,
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
