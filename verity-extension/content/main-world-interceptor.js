/**
 * content/main-world-interceptor.js - Verity 2.0 MAIN World Runtime Interceptor
 *
 * Runs in the webpage's main execution context (MAIN world) at document_start.
 * Intercepts dynamic/obfuscated network exfiltration (fetch/XHR/sendBeacon),
 * live ClickFix clipboard command injection (navigator.clipboard.writeText),
 * and rogue screen capture attempts (getDisplayMedia) before page scripts can execute.
 */

(function () {
  'use strict';

  // Prevent multiple injections
  if (window.__VERITY_MAIN_INTERCEPTOR_ACTIVE__) return;
  Object.defineProperty(window, '__VERITY_MAIN_INTERCEPTOR_ACTIVE__', {
    value: true,
    writable: false,
    configurable: false
  });

  let hasTypedSensitiveData = false;

  const EXFIL_ENDPOINTS = Object.freeze([
    'api.telegram.org/bot',
    'discord.com/api/webhooks',
    'discordapp.com/api/webhooks',
    'webhook.site',
    'pipedream.net',
    'ngrok-free.app',
    'trycloudflare.com',
    'formspree.io',
    'getform.io',
    'script.google.com/macros/s/'
  ]);

  const CLICKFIX_EXEC_PAYLOADS = Object.freeze([
    'powershell', 'mshta', 'cmd.exe', 'iex(', 'invoke-webrequest',
    'curl ', 'wget ', '-enc ', 'bypass', 'hidden'
  ]);

  function isExfilEndpoint(urlStr) {
    if (!urlStr || typeof urlStr !== 'string') return null;
    const lower = urlStr.toLowerCase();
    return EXFIL_ENDPOINTS.find(ep => lower.includes(ep)) || null;
  }

  function getBaseDomain(hostname) {
    if (!hostname) return '';
    const parts = hostname.toLowerCase().split('.').filter(Boolean);
    if (parts.length <= 2) return hostname.toLowerCase();
    return parts.slice(-2).join('.');
  }

  function isCrossOriginExfil(targetUrl) {
    if (!targetUrl || typeof targetUrl !== 'string') return false;
    try {
      const parsed = new URL(targetUrl, window.location.href);
      const targetHost = parsed.hostname.toLowerCase();
      const currentHost = window.location.hostname.toLowerCase();
      if (!targetHost || targetHost === currentHost) return false;
      const targetBase = getBaseDomain(targetHost);
      const currentBase = getBaseDomain(currentHost);
      return targetBase !== currentBase;
    } catch (_) {
      return false;
    }
  }

  function notifyThreat(signal, detail = {}) {
    try {
      window.dispatchEvent(new CustomEvent('__VERITY_RUNTIME_THREAT__', {
        detail: { signal, ...detail }
      }));
    } catch (_) {}
  }

  // ── 1. Dirty Sensitive Input Monitor ───────────────────────────────────────
  function markSensitive() {
    hasTypedSensitiveData = true;
  }

  const sensitiveSelectors = 'input[type="password"], input[name*="otp" i], input[id*="otp" i], input[name*="cvv" i], input[id*="cvv" i], input[name*="card" i], input[id*="card" i], input[name*="pin" i], input[id*="pin" i], input[name*="pan" i], input[id*="pan" i], input[name*="aadhaar" i], input[id*="aadhaar" i]';

  document.addEventListener('input', (e) => {
    const el = e.target;
    if (el && el.matches && el.matches(sensitiveSelectors)) {
      markSensitive();
    }
  }, true);

  document.addEventListener('change', (e) => {
    const el = e.target;
    if (el && el.matches && el.matches(sensitiveSelectors)) {
      markSensitive();
    }
  }, true);

  // ── 2. Intercept window.fetch ──────────────────────────────────────────────
  if (typeof window.fetch === 'function') {
    const originalFetch = window.fetch;
    window.fetch = function (resource, init) {
      let targetUrl = '';
      if (typeof resource === 'string') {
        targetUrl = resource;
      } else if (resource && typeof resource.url === 'string') {
        targetUrl = resource.url;
      }

      const matchedExfil = isExfilEndpoint(targetUrl);
      if (matchedExfil) {
        notifyThreat('SIG_PHISHING_KIT_WEBHOOK_EXFIL', { endpoint: targetUrl });
        return Promise.reject(new TypeError('Blocked by Verity Security Shield: Phishing exfiltration endpoint'));
      }

      const method = (init && init.method ? init.method : 'GET').toUpperCase();
      if (hasTypedSensitiveData && (method === 'POST' || method === 'PUT') && isCrossOriginExfil(targetUrl)) {
        notifyThreat('SIG_CROSS_DOMAIN_CREDENTIAL_EXFIL', { targetUrl });
        return Promise.reject(new TypeError('Blocked by Verity Security Shield: Cross-domain credential exfiltration'));
      }

      return originalFetch.apply(this, arguments);
    };
  }

  // ── 3. Intercept XMLHttpRequest ────────────────────────────────────────────
  if (typeof window.XMLHttpRequest === 'function' && window.XMLHttpRequest.prototype) {
    const origOpen = window.XMLHttpRequest.prototype.open;
    const origSend = window.XMLHttpRequest.prototype.send;

    window.XMLHttpRequest.prototype.open = function (method, url) {
      this.__verityMethod = (method || 'GET').toUpperCase();
      this.__verityUrl = url;
      return origOpen.apply(this, arguments);
    };

    window.XMLHttpRequest.prototype.send = function (body) {
      const targetUrl = this.__verityUrl || '';
      const matchedExfil = isExfilEndpoint(targetUrl);
      if (matchedExfil) {
        notifyThreat('SIG_PHISHING_KIT_WEBHOOK_EXFIL', { endpoint: targetUrl });
        throw new DOMException('Blocked by Verity Security Shield: Phishing exfiltration endpoint', 'NetworkError');
      }

      if (hasTypedSensitiveData && (this.__verityMethod === 'POST' || this.__verityMethod === 'PUT') && isCrossOriginExfil(targetUrl)) {
        notifyThreat('SIG_CROSS_DOMAIN_CREDENTIAL_EXFIL', { targetUrl });
        throw new DOMException('Blocked by Verity Security Shield: Cross-domain credential exfiltration', 'NetworkError');
      }

      return origSend.apply(this, arguments);
    };
  }

  // ── 4. Intercept navigator.sendBeacon ──────────────────────────────────────
  if (navigator && typeof navigator.sendBeacon === 'function') {
    const origSendBeacon = navigator.sendBeacon;
    navigator.sendBeacon = function (url, data) {
      const targetUrl = String(url || '');
      const matchedExfil = isExfilEndpoint(targetUrl);
      if (matchedExfil) {
        notifyThreat('SIG_PHISHING_KIT_WEBHOOK_EXFIL', { endpoint: targetUrl });
        return false;
      }
      if (hasTypedSensitiveData && isCrossOriginExfil(targetUrl)) {
        notifyThreat('SIG_CROSS_DOMAIN_CREDENTIAL_EXFIL', { targetUrl });
        return false;
      }
      return origSendBeacon.apply(this, arguments);
    };
  }

  // ── 5. Intercept navigator.clipboard.writeText (Live ClickFix Blocker) ──────
  if (navigator && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
    const origWriteText = navigator.clipboard.writeText.bind(navigator.clipboard);
    navigator.clipboard.writeText = function (text) {
      if (typeof text === 'string') {
        const lower = text.toLowerCase();
        const hasPayload = CLICKFIX_EXEC_PAYLOADS.some(p => lower.includes(p));
        if (hasPayload) {
          notifyThreat('SIG_CLICKFIX_CLIPBOARD_ATTACK', { payload: text.slice(0, 100) });
          // Overwrite with empty string to defuse malicious clipboard injection
          return origWriteText('');
        }
      }
      return origWriteText(text);
    };
  }

  // ── 6. Intercept navigator.mediaDevices.getDisplayMedia (Screen-Share Blocker)
  if (navigator && navigator.mediaDevices && typeof navigator.mediaDevices.getDisplayMedia === 'function') {
    const origGetDisplayMedia = navigator.mediaDevices.getDisplayMedia.bind(navigator.mediaDevices);
    navigator.mediaDevices.getDisplayMedia = function () {
      const pageText = (document.body ? (document.body.innerText || '') : '').toLowerCase();
      const isScamContext = pageText.includes('kyc') || pageText.includes('digital arrest') ||
                            pageText.includes('bank account') || pageText.includes('police') ||
                            pageText.includes('customs') || pageText.includes('cbi');
      if (isScamContext) {
        notifyThreat('SIG_UNTRUSTED_SCREEN_SHARE');
        return Promise.reject(new DOMException('Screen sharing blocked on unverified domain by Verity Security Shield', 'NotAllowedError'));
      }
      return origGetDisplayMedia.apply(this, arguments);
    };
  }

})();
