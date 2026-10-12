/**
 * popup/popup.js - Production-Grade Popup Logic for VERITY
 * Calm, precise, reliable. All UI strings rendered via t().
 */

const getIcon = (name, opts) => {
  if (typeof window.VerityIcons?.getIconSvg === 'function') {
    return window.VerityIcons.getIconSvg(name, opts);
  }
  return '';
};

const translate = (id, params) => {
  if (typeof window.t === 'function') {
    return window.t(id, params);
  }
  return String(id);
};

let currentTab = null;
let currentVerdict = null;

// ─── Theme Management ───────────────────────────────────────────────────────
function applyTheme(theme) {
  const root = document.documentElement;
  if (!theme || theme === 'system') {
    root.removeAttribute('data-theme');
  } else {
    root.setAttribute('data-theme', theme);
  }

  document.querySelectorAll('.p-theme-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.themeVal === (theme || 'system'));
  });
}

async function initTheme() {
  chrome.storage.local.get(['theme'], res => {
    applyTheme(res?.theme || 'system');
  });

  document.querySelectorAll('.p-theme-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const themeVal = btn.dataset.themeVal;
      chrome.storage.local.set({ theme: themeVal }, () => {
        applyTheme(themeVal);
      });
    });
  });
}

// ─── Real-Time Protection Master Toggle ─────────────────────────────────────
function initProtectionToggle() {
  const toggle = document.getElementById('switch-protection');
  chrome.storage.local.get(['protectionEnabled'], res => {
    toggle.checked = res?.protectionEnabled !== false;
  });

  toggle.addEventListener('change', () => {
    chrome.storage.local.set({ protectionEnabled: toggle.checked });
  });
}

// ─── Domain Parsing Helper ──────────────────────────────────────────────────
function parseDomain(rawUrl) {
  try {
    const url = new URL(rawUrl);
    const host = url.hostname.toLowerCase();
    const parts = host.split('.');
    if (parts.length > 2) {
      const reg = parts.slice(-2).join('.');
      const sub = parts.slice(0, -2).join('.') + '.';
      return { host, sub, reg };
    }
    return { host, sub: '', reg: host };
  } catch (e) {
    return { host: rawUrl, sub: '', reg: rawUrl };
  }
}

// ─── Render States ──────────────────────────────────────────────────────────
function showState(stateName) {
  const states = ['state-loading', 'state-unscannable', 'state-error', 'state-verdict'];
  states.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.classList.toggle('hidden', id !== stateName);
  });
}

function renderUnscannable(url) {
  showState('state-unscannable');
  const chip = document.getElementById('unscannable-url-chip');
  let display = url;
  try {
    const u = new URL(url);
    display = u.protocol + (u.hostname ? '//' + u.hostname : '');
  } catch (e) {}
  chip.textContent = display;

  const headerPill = document.getElementById('p-header-pill');
  headerPill.className = 'v-badge v-badge-neutral p-status-pill';
  headerPill.textContent = translate('UI_STATUS_UNKNOWN');

  const emptyIcon = document.getElementById('unscannable-icon');
  emptyIcon.innerHTML = getIcon('globe', { size: 20 });
}

function renderError(errTitle, errDesc) {
  showState('state-error');
  if (errTitle) document.getElementById('txt-err-title').textContent = errTitle;
  if (errDesc) document.getElementById('txt-err-desc').textContent = errDesc;

  document.getElementById('error-alert-icon').innerHTML = getIcon('octagon-x', { size: 18, color: 'var(--destructive)' });
  document.getElementById('retry-icon').innerHTML = getIcon('history', { size: 14 });

  const headerPill = document.getElementById('p-header-pill');
  headerPill.className = 'v-badge v-badge-danger p-status-pill';
  headerPill.textContent = 'Offline';
}

function renderVerdict(verdict, tab) {
  currentVerdict = verdict;
  showState('state-verdict');

  const state = verdict.severity || verdict.state || (verdict.action === 'block' ? 'danger' : (verdict.score >= 35 ? 'caution' : 'safe'));
  const score = Math.max(0, Math.min(100, verdict.score !== undefined ? verdict.score : (verdict.riskScore || 0)));

  // 1. Header Pill
  const headerPill = document.getElementById('p-header-pill');
  if (state === 'safe') {
    headerPill.className = 'v-badge v-badge-safe p-status-pill';
    headerPill.textContent = translate('UI_STATUS_SAFE');
  } else if (state === 'caution') {
    headerPill.className = 'v-badge v-badge-caution p-status-pill';
    headerPill.textContent = translate('UI_STATUS_CAUTION');
  } else {
    headerPill.className = 'v-badge v-badge-danger p-status-pill';
    headerPill.textContent = translate('UI_STATUS_DANGER');
  }

  // 2. Hero Icon and Circle
  const iconCircle = document.getElementById('p-verdict-icon-circle');
  const verdictIcon = document.getElementById('p-verdict-icon');
  iconCircle.className = `p-icon-circle ${state}`;
  if (state === 'safe') {
    verdictIcon.innerHTML = getIcon('shield-check', { size: 24, strokeWidth: 1.8 });
  } else if (state === 'caution') {
    verdictIcon.innerHTML = getIcon('triangle-alert', { size: 24, strokeWidth: 1.8 });
  } else {
    verdictIcon.innerHTML = getIcon('shield-x', { size: 24, strokeWidth: 1.8 });
  }

  // 3. Headline
  const headline = document.getElementById('p-verdict-text');
  if (state === 'safe') {
    headline.textContent = translate('UI_VERDICT_SAFE');
  } else if (state === 'caution') {
    headline.textContent = translate('UI_VERDICT_CAUTION');
  } else {
    headline.textContent = translate('UI_VERDICT_DANGER');
  }

  // 4. Domain Chip
  const parsed = parseDomain(tab.url || verdict.url || '');
  document.getElementById('p-domain-sub').textContent = parsed.sub;
  document.getElementById('p-domain-reg').textContent = parsed.reg;

  // 5. Circular Ring Gauge
  const meter = document.getElementById('p-gauge-meter');
  const numEl = document.getElementById('p-gauge-num');
  meter.className = `p-gauge-meter ${state}`;

  const circumference = 144.51; // 2 * PI * 23
  const isReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  if (isReduced) {
    const offset = circumference * (1 - score / 100);
    meter.style.strokeDashoffset = offset;
    numEl.textContent = String(score);
  } else {
    meter.style.strokeDashoffset = circumference;
    numEl.textContent = '0';
    requestAnimationFrame(() => {
      const offset = circumference * (1 - score / 100);
      meter.style.strokeDashoffset = offset;
    });

    // Count-up animation
    const startTime = performance.now();
    const duration = 600;
    function updateCounter(now) {
      const progress = Math.min((now - startTime) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      numEl.textContent = String(Math.round(eased * score));
      if (progress < 1) requestAnimationFrame(updateCounter);
    }
    requestAnimationFrame(updateCounter);
  }

  // 6. Reasons Accordion
  let reasons = [];
  if (verdict.signals && verdict.signals.length > 0) {
    reasons = verdict.signals.map(s => {
      if (s.id) return translate(s.id, s.params);
      return s.reason || '';
    }).filter(Boolean);
  } else if (verdict.reasons && verdict.reasons.length > 0) {
    reasons = verdict.reasons.map(r => translate(r)).filter(Boolean);
  }

  const badgeCount = document.getElementById('p-reasons-badge');
  badgeCount.textContent = String(reasons.length);
  const reasonsList = document.getElementById('p-reasons-list');
  reasonsList.innerHTML = '';

  if (reasons.length === 0) {
    const emptyRow = document.createElement('div');
    emptyRow.className = 'p-reason-row';
    emptyRow.style.color = 'var(--muted-foreground)';
    emptyRow.textContent = translate('UI_NO_SIGNALS');
    reasonsList.appendChild(emptyRow);
  } else {
    reasons.forEach(text => {
      const row = document.createElement('div');
      row.className = 'p-reason-row';
      row.innerHTML = `
        <span class="p-reason-dot ${state}"></span>
        <span style="flex:1;">${escapeHtml(text)}</span>
      `;
      reasonsList.appendChild(row);
    });
  }

  // Setup icons for static actions
  document.getElementById('why-icon').innerHTML = getIcon('info', { size: 14 });
  document.getElementById('icon-copy').innerHTML = getIcon('copy', { size: 13 });
  document.getElementById('icon-check').innerHTML = getIcon('check', { size: 13 });
  document.getElementById('icon-settings').innerHTML = getIcon('settings', { size: 15 });
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ─── Fetch Tab & Verdict ────────────────────────────────────────────────────
async function loadPopupData() {
  showState('state-loading');

  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tabs || tabs.length === 0) {
      renderError(translate('UI_SW_ERROR'), 'No active browser tab found.');
      return;
    }

    currentTab = tabs[0];
    const url = currentTab.url || '';

    // Check for internal / unscannable URLs
    if (!url || url.startsWith('chrome://') || url.startsWith('edge://') || url.startsWith('about:') || url.startsWith('chrome-extension://') || url.startsWith('file://')) {
      renderUnscannable(url);
      return;
    }

    // Try storage.session first
    let verdict = null;
    try {
      const sessionRes = await chrome.storage.session.get(currentTab.id.toString());
      if (sessionRes && sessionRes[currentTab.id.toString()]) {
        verdict = sessionRes[currentTab.id.toString()];
      }
    } catch (e) {}

    // Fallback: ask background service worker
    if (!verdict) {
      verdict = await new Promise((resolve) => {
        const timeout = setTimeout(() => resolve(null), 1200);
        chrome.runtime.sendMessage({ action: 'GET_VERDICT', tabId: currentTab.id }, res => {
          clearTimeout(timeout);
          resolve(res);
        });
      });
    }

    if (verdict) {
      renderVerdict(verdict, currentTab);
    } else {
      // Clean baseline verdict when page has clean evaluation
      renderVerdict({
        action: 'allow',
        severity: 'safe',
        score: 0,
        riskScore: 0,
        signals: []
      }, currentTab);
    }
  } catch (err) {
    console.error('[Verity Popup] Error:', err);
    renderError(translate('UI_SW_ERROR'), err.message || 'Service worker unreachable.');
  }
}

// ─── Event Handlers ─────────────────────────────────────────────────────────
function initEventListeners() {
  // Retry button
  document.getElementById('btn-retry-sw')?.addEventListener('click', () => {
    loadPopupData();
  });

  // Accordion Toggle
  const accordionBtn = document.getElementById('btn-why-accordion');
  const reasonsContainer = document.getElementById('p-reasons-container');
  accordionBtn?.addEventListener('click', () => {
    const isExpanded = accordionBtn.getAttribute('aria-expanded') === 'true';
    accordionBtn.setAttribute('aria-expanded', String(!isExpanded));
    reasonsContainer.hidden = isExpanded;
  });

  // Copy Domain
  const copyBtn = document.getElementById('btn-copy-domain');
  const txtCopy = document.getElementById('txt-copy');
  copyBtn?.addEventListener('click', async () => {
    if (!currentTab || !currentTab.url) return;
    try {
      const host = new URL(currentTab.url).hostname;
      await navigator.clipboard.writeText(host);
      const originalText = txtCopy.textContent;
      txtCopy.textContent = translate('UI_COPIED');
      setTimeout(() => {
        txtCopy.textContent = originalText;
      }, 1500);
    } catch (e) {}
  });

  // Open Settings
  document.getElementById('btn-open-settings')?.addEventListener('click', () => {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open(chrome.runtime.getURL('options/options.html'));
    }
  });

  // "This site is safe" Action
  const btnSafe = document.getElementById('btn-site-safe');
  const confirmBox = document.getElementById('p-confirm-box');
  const btnCancelTrust = document.getElementById('btn-cancel-trust');
  const btnProceedTrust = document.getElementById('btn-proceed-trust');

  btnSafe?.addEventListener('click', () => {
    const isDanger = currentVerdict?.action === 'block' || currentVerdict?.severity === 'danger';
    if (isDanger) {
      // Require confirmation for blocked sites
      confirmBox.classList.remove('hidden');
    } else {
      applyTrustOverride();
    }
  });

  btnCancelTrust?.addEventListener('click', () => {
    confirmBox.classList.add('hidden');
  });

  btnProceedTrust?.addEventListener('click', () => {
    confirmBox.classList.add('hidden');
    applyTrustOverride();
  });

  function applyTrustOverride() {
    if (!currentTab) return;
    chrome.runtime.sendMessage({
      action: 'USER_OVERRIDE_ALLOW',
      url: currentTab.url
    }, () => {
      // Re-render as safe
      renderVerdict({
        action: 'allow',
        severity: 'safe',
        score: 0,
        riskScore: 0,
        signals: []
      }, currentTab);
    });
  }
}

// ─── Initialize ─────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initProtectionToggle();
  initEventListeners();
  loadPopupData();
});
