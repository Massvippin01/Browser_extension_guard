/**
 * popup.js — Verity Popup
 * Displays current website status, risk score, and detected signals.
 */

async function loadVerdict() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tabs || tabs.length === 0) {
      showError('No active tab found.');
      return;
    }

    const tab = tabs[0];
    const url = tab.url || '';

    // Show domain in header
    try {
      const urlObj = new URL(url);
      document.getElementById('app-domain-text').textContent = urlObj.hostname;
    } catch (e) {
      document.getElementById('app-domain-text').textContent = 'Unknown';
    }

    // Skip internal pages
    if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) {
      showError('Internal Chrome page — no analysis available.');
      return;
    }

    // Try session storage first
    const storageResult = await chrome.storage.session.get(tab.id.toString());
    const verdictData = storageResult[tab.id.toString()];

    if (verdictData) {
      renderVerdict(verdictData);
    } else {
      showError('Analyzing... please wait a moment and reopen.');
    }

  } catch (error) {
    showError('An error occurred while loading data.');
  }
}

function renderVerdict(data) {
  document.getElementById('loading-state').classList.add('hidden');
  document.getElementById('error-state').classList.add('hidden');
  document.getElementById('verdict-state').classList.remove('hidden');

  const state = data.severity || data.state || 'safe';
  const score = data.riskScore !== undefined ? data.riskScore : (data.score || 0);

  // Status badge
  const ring = document.getElementById('status-ring');
  const icon = document.getElementById('verdict-icon');
  const title = document.getElementById('verdict-title');

  ring.className = 'status-ring ' + state;

  if (state === 'safe') {
    icon.textContent = '✓';
    title.textContent = 'Safe';
    title.className = 'verdict-title safe';
  } else if (state === 'caution') {
    icon.textContent = '!';
    title.textContent = 'Suspicious';
    title.className = 'verdict-title caution';
  } else if (state === 'danger') {
    icon.textContent = '!!';
    title.textContent = 'Dangerous';
    title.className = 'verdict-title danger';
  } else {
    icon.textContent = '?';
    title.textContent = 'Unknown';
    title.className = 'verdict-title';
  }

  // Score
  const scoreEl = document.getElementById('risk-score-value');
  const barFill = document.getElementById('score-bar-fill');
  const scoreDesc = document.getElementById('risk-score-text');

  animateScore(scoreEl, score);
  barFill.style.width = score + '%';
  barFill.className = 'score-bar-fill ' + state;

  if (state === 'safe') scoreDesc.textContent = '"Everything looks normal."';
  else if (state === 'caution') scoreDesc.textContent = '"Suspicious indicators detected."';
  else if (state === 'danger') scoreDesc.textContent = '"High-risk threats detected."';

  // Signals list
  const reasonsList = document.getElementById('reasons-list');
  const noReasons = document.getElementById('no-reasons-msg');
  reasonsList.innerHTML = '';

  // Show signals (prefer detailed signals array, fallback to reasons)
  let items = [];
  if (data.signals && data.signals.length > 0) {
    items = data.signals.map(s => s.reason).filter(Boolean);
  } else if (data.reasons && data.reasons.length > 0) {
    items = data.reasons.filter(Boolean);
  }

  if (items.length > 0) {
    items.forEach(reason => {
      const li = document.createElement('li');
      li.className = 'signal-item ' + state;
      li.textContent = reason;
      reasonsList.appendChild(li);
    });
    noReasons.classList.add('hidden');
    reasonsList.classList.remove('hidden');
  } else {
    reasonsList.classList.add('hidden');
    noReasons.classList.remove('hidden');
  }
}

function animateScore(el, target) {
  const duration = 500;
  const start = performance.now();
  const from = 0;

  function step(now) {
    const progress = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
    el.textContent = Math.round(from + eased * (target - from));
    if (progress < 1) requestAnimationFrame(step);
  }

  requestAnimationFrame(step);
}

function showError(msg) {
  document.getElementById('loading-state').classList.add('hidden');
  document.getElementById('verdict-state').classList.add('hidden');
  document.getElementById('error-state').classList.remove('hidden');
  document.getElementById('error-msg').textContent = msg;
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  loadVerdict();
});
