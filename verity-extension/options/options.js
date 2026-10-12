/**
 * options/options.js - Options Page Interactions & State
 * Autosave, theme switching, allowlist management with undo toast.
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

let allowlist = [];
let lastRemovedDomain = null;
let undoTimer = null;
let saveTimer = null;

// ─── Theme Management ───────────────────────────────────────────────────────
function applyTheme(theme) {
  const root = document.documentElement;
  if (!theme || theme === 'system') {
    root.removeAttribute('data-theme');
  } else {
    root.setAttribute('data-theme', theme);
  }

  document.querySelectorAll('.opt-theme-card').forEach(card => {
    card.classList.toggle('active', card.dataset.themeVal === (theme || 'system'));
  });
}

// ─── Autosave Feedback ──────────────────────────────────────────────────────
function triggerSaveFeedback() {
  const badge = document.getElementById('opt-save-badge');
  badge.classList.remove('hidden');
  badge.style.opacity = '1';

  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    badge.style.opacity = '0';
    setTimeout(() => badge.classList.add('hidden'), 200);
  }, 1600);
}

// ─── Save Settings ──────────────────────────────────────────────────────────
function saveSettings() {
  const masterProtection = document.getElementById('switch-master-protection').checked;
  const modPhishing = document.getElementById('switch-mod-phishing').checked;
  const modPayment = document.getElementById('switch-mod-payment').checked;
  const modDownload = document.getElementById('switch-mod-download').checked;
  const modPopup = document.getElementById('switch-mod-popup').checked;

  chrome.storage.local.set({
    protectionEnabled: masterProtection,
    protectionLevels: {
      phishing: modPhishing,
      payment: modPayment,
      download: modDownload,
      popup: modPopup
    },
    userAllowlist: allowlist
  }, () => {
    triggerSaveFeedback();
  });
}

// ─── Load Settings ──────────────────────────────────────────────────────────
function loadSettings() {
  chrome.storage.local.get([
    'theme',
    'protectionEnabled',
    'protectionLevels',
    'userAllowlist'
  ], res => {
    applyTheme(res?.theme || 'system');

    document.getElementById('switch-master-protection').checked = res?.protectionEnabled !== false;

    const levels = res?.protectionLevels || {};
    document.getElementById('switch-mod-phishing').checked = levels.phishing !== false;
    document.getElementById('switch-mod-payment').checked = levels.payment !== false;
    document.getElementById('switch-mod-download').checked = levels.download !== false;
    document.getElementById('switch-mod-popup').checked = levels.popup !== false;

    allowlist = Array.isArray(res?.userAllowlist) ? res.userAllowlist : [];
    renderAllowlist();
  });
}

// ─── Tab Navigation ─────────────────────────────────────────────────────────
function initNavigation() {
  const navBtns = document.querySelectorAll('.opt-nav-item');
  const sections = {
    general: document.getElementById('sec-general'),
    protection: document.getElementById('sec-protection'),
    allowlist: document.getElementById('sec-allowlist'),
    about: document.getElementById('sec-about')
  };

  navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;
      navBtns.forEach(b => b.classList.toggle('active', b === btn));
      Object.entries(sections).forEach(([name, sec]) => {
        if (sec) sec.classList.toggle('hidden', name !== target);
      });
    });
  });

  // Inject Nav Icons
  document.getElementById('icon-nav-general').innerHTML = getIcon('settings', { size: 15 });
  document.getElementById('icon-nav-protection').innerHTML = getIcon('shield', { size: 15 });
  document.getElementById('icon-nav-allowlist').innerHTML = getIcon('check', { size: 15 });
  document.getElementById('icon-nav-about').innerHTML = getIcon('info', { size: 15 });
  document.getElementById('icon-plus').innerHTML = getIcon('check', { size: 13 });
  document.getElementById('empty-table-icon').innerHTML = getIcon('globe', { size: 18 });
  document.getElementById('about-shield-icon').innerHTML = getIcon('shield-check', { size: 20, color: 'var(--success)' });
}

// ─── Allowlist Table Management ─────────────────────────────────────────────
function renderAllowlist(filterText = '') {
  const tbody = document.getElementById('tbody-allowlist');
  const emptyState = document.getElementById('allowlist-empty-state');
  const table = document.getElementById('table-allowlist');

  tbody.innerHTML = '';
  const query = filterText.trim().toLowerCase();
  const filtered = allowlist.filter(item => {
    const domain = typeof item === 'string' ? item : item.domain;
    return domain.toLowerCase().includes(query);
  });

  if (filtered.length === 0) {
    emptyState.classList.remove('hidden');
    table.classList.add('hidden');
    return;
  }

  emptyState.classList.add('hidden');
  table.classList.remove('hidden');

  filtered.forEach((item, index) => {
    const domain = typeof item === 'string' ? item : item.domain;
    const date = (typeof item === 'object' && item.date) ? item.date : 'User added';

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>
        <span class="v-chip-mono">${escapeHtml(domain)}</span>
      </td>
      <td style="color:var(--muted-foreground);font-size:12px;">${escapeHtml(date)}</td>
      <td style="text-align:right;">
        <button type="button" class="v-btn v-btn-ghost v-btn-sm btn-remove-domain" data-domain="${escapeHtml(domain)}" title="Remove ${escapeHtml(domain)}">
          Remove
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  // Bind remove buttons
  tbody.querySelectorAll('.btn-remove-domain').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetDomain = btn.dataset.domain;
      removeDomain(targetDomain);
    });
  });
}

function removeDomain(domain) {
  const removedItem = allowlist.find(i => (typeof i === 'string' ? i : i.domain) === domain);
  lastRemovedDomain = removedItem || domain;

  allowlist = allowlist.filter(i => (typeof i === 'string' ? i : i.domain) !== domain);
  saveSettings();
  renderAllowlist(document.getElementById('input-filter-domains').value);

  // Show inline undo toast
  const undoToast = document.getElementById('opt-undo-toast');
  document.getElementById('opt-undo-msg').textContent = `"${domain}" removed from allowlist.`;
  undoToast.classList.remove('hidden');

  clearTimeout(undoTimer);
  undoTimer = setTimeout(() => {
    undoToast.classList.add('hidden');
    lastRemovedDomain = null;
  }, 6000);
}

function undoRemove() {
  if (!lastRemovedDomain) return;
  allowlist.push(lastRemovedDomain);
  lastRemovedDomain = null;
  document.getElementById('opt-undo-toast').classList.add('hidden');
  saveSettings();
  renderAllowlist(document.getElementById('input-filter-domains').value);
}

function addDomain(domainStr) {
  let clean = domainStr.trim().toLowerCase();
  clean = clean.replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
  if (!clean || !clean.includes('.')) {
    alert('Please enter a valid hostname (e.g. portal.internal.com)');
    return;
  }

  const exists = allowlist.some(i => (typeof i === 'string' ? i : i.domain) === clean);
  if (exists) {
    alert(`"${clean}" is already in the allowlist.`);
    return;
  }

  allowlist.unshift({
    domain: clean,
    date: new Date().toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
  });

  saveSettings();
  renderAllowlist();
  document.getElementById('input-new-domain').value = '';
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

// ─── Initialize Event Listeners ─────────────────────────────────────────────
function initEventListeners() {
  // Theme card pickers
  document.querySelectorAll('.opt-theme-card').forEach(card => {
    card.addEventListener('click', () => {
      const themeVal = card.dataset.themeVal;
      chrome.storage.local.set({ theme: themeVal }, () => {
        applyTheme(themeVal);
        triggerSaveFeedback();
      });
    });
  });

  // Switches
  const switches = [
    'switch-master-protection',
    'switch-mod-phishing',
    'switch-mod-payment',
    'switch-mod-download',
    'switch-mod-popup'
  ];
  switches.forEach(id => {
    document.getElementById(id)?.addEventListener('change', () => {
      saveSettings();
    });
  });

  // Add domain form
  document.getElementById('form-add-allowlist')?.addEventListener('submit', (e) => {
    e.preventDefault();
    const val = document.getElementById('input-new-domain').value;
    addDomain(val);
  });

  // Filter input
  document.getElementById('input-filter-domains')?.addEventListener('input', (e) => {
    renderAllowlist(e.target.value);
  });

  // Undo button
  document.getElementById('btn-undo-remove')?.addEventListener('click', () => {
    undoRemove();
  });
}

// ─── Init ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initEventListeners();
  loadSettings();
});
