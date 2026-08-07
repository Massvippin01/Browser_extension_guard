/**
 * content-script.js - Injected into all pages.
 * Responsible for collecting basic DOM signals and injecting the overlay when needed.
 */

// 1. Signal Collection (Stage 1)
// We collect characteristics of the page that could inform risk scoring.
// Note: We DO NOT read passwords or input values, only structural data.

function collectSignals() {
  const hasPasswordInput = document.querySelector('input[type="password"]') !== null;
  const loginForms = Array.from(document.querySelectorAll('form')).filter(form => {
    return form.querySelector('input[type="password"]') !== null || 
           form.action.toLowerCase().includes('login') ||
           form.id.toLowerCase().includes('login');
  });
  
  const formActions = loginForms.map(form => form.action).filter(Boolean);

  // Send signals to background if needed (for now we just log them in console for visibility during dev)
  if (loginForms.length > 0) {
    console.log('[Verity] Detected login form(s). Action URLs:', formActions);
  }

  return {
    hasPasswordInput: hasPasswordInput,
    loginFormCount: loginForms.length,
    formActions: formActions
  };
}

// Run collection after DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', collectSignals);
} else {
  collectSignals();
}


// 2. Overlay injection and signals listener
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'show_danger_overlay') {
    injectOverlay(message.verdict);
    sendResponse({ success: true });
  } else if (message.action === 'get_dom_signals') {
    sendResponse(collectSignals());
  }
});

/**
 * Injects the security overlay into the page.
 */
function injectOverlay(verdict) {
  // Prevent duplicate injections
  if (document.getElementById('verity-security-overlay')) {
    return;
  }

  // Construct UI in a Shadow DOM to isolate from host website CSS
  const host = document.createElement('div');
  host.id = 'verity-security-host';
  host.style.position = 'fixed';
  host.style.top = '0';
  host.style.left = '0';
  host.style.width = '100vw';
  host.style.height = '100vh';
  host.style.zIndex = '2147483647';
  
  const shadow = host.attachShadow({ mode: 'closed' });

  // Inject CSS inside shadow root
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.type = 'text/css';
  link.href = cssUrl;
  shadow.appendChild(link);

  const overlay = document.createElement('div');
  overlay.id = 'verity-security-overlay';
  
  const card = document.createElement('div');
  card.className = 'verity-card';

  const header = document.createElement('div');
  header.className = 'verity-header';
  header.innerHTML = `
    <div class="verity-icon">!</div>
    <div class="verity-title">Potential phishing site</div>
  `;
  card.appendChild(header);

  const scoreContainer = document.createElement('div');
  scoreContainer.className = 'verity-score-container';
  scoreContainer.innerHTML = `
    <div class="verity-score-label">Risk Score</div>
    <div class="verity-score-value">${verdict.score} <span class="verity-score-max">/ 100</span></div>
  `;
  card.appendChild(scoreContainer);

  if (verdict.reasons && verdict.reasons.length > 0) {
    const reasonsList = document.createElement('ul');
    reasonsList.className = 'verity-reasons';
    verdict.reasons.forEach(reason => {
      const li = document.createElement('li');
      li.textContent = reason;
      reasonsList.appendChild(li);
    });
    card.appendChild(reasonsList);
  }

  const actions = document.createElement('div');
  actions.className = 'verity-actions';
  
  const backBtn = document.createElement('button');
  backBtn.className = 'verity-btn verity-btn-primary';
  backBtn.id = 'verity-btn-back';
  backBtn.textContent = 'Go back';

  backBtn.addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'about:blank';
    }
  });

  const proceedBtn = document.createElement('button');
  proceedBtn.className = 'verity-btn verity-btn-secondary';
  proceedBtn.id = 'verity-btn-proceed';
  proceedBtn.textContent = 'Proceed anyway';
  
  proceedBtn.addEventListener('click', () => {
    host.style.display = 'none';
  });

  actions.appendChild(backBtn);
  actions.appendChild(proceedBtn);
  card.appendChild(actions);

  // Real-vs-Fake side-by-side visual (Top 10 brands)
  const top10Brands = ['PayPal', 'Chase', 'Amazon', 'Apple', 'Google', 'Microsoft', 'Facebook', 'Netflix', 'Bank of America', 'Wells Fargo'];
  let brandMatch = null;
  if (verdict.reasons) {
    for (const reason of verdict.reasons) {
      const match = reason.match(/contains the name "([^"]+)"/);
      if (match) {
        brandMatch = match[1];
        break;
      }
    }
  }

  if (brandMatch && top10Brands.includes(brandMatch)) {
    const visualContainer = document.createElement('div');
    visualContainer.className = 'verity-visual-comparison';
    visualContainer.style.display = 'flex';
    visualContainer.style.gap = '16px';
    visualContainer.style.marginTop = '24px';
    visualContainer.style.justifyContent = 'center';

    const mockRealSvg = `data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="200" height="150" viewBox="0 0 200 150"><rect width="100%" height="100%" fill="%23f3f4f6"/><rect x="0" y="0" width="100%" height="30" fill="%233b82f6"/><text x="100" y="20" font-family="sans-serif" font-size="14" fill="white" text-anchor="middle">Official ${encodeURIComponent(brandMatch)} Site</text><rect x="40" y="50" width="120" height="80" rx="4" fill="white"/><line x1="50" y1="70" x2="150" y2="70" stroke="%23e2e8f0" stroke-width="2"/><line x1="50" y1="90" x2="150" y2="90" stroke="%23e2e8f0" stroke-width="2"/></svg>`;
    
    // Fallback if screenshot is missing
    const fakeSrc = verdict.screenshot || `data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="200" height="150" viewBox="0 0 200 150"><rect width="100%" height="100%" fill="%23fef2f2"/><text x="100" y="75" font-family="sans-serif" font-size="12" fill="%23ef4444" text-anchor="middle">Screenshot Unavailable</text></svg>`;

    visualContainer.innerHTML = `
      <div style="flex:1; text-align:center;">
        <div style="font-size:12px; color:#10b981; margin-bottom:4px; font-weight:bold;">REAL SITE</div>
        <img src="${mockRealSvg}" style="width:100%; max-width:200px; border:1px solid #e2e8f0; border-radius:4px; box-shadow:0 2px 4px rgba(0,0,0,0.1);">
      </div>
      <div style="flex:1; text-align:center;">
        <div style="font-size:12px; color:#ef4444; margin-bottom:4px; font-weight:bold;">THIS PAGE (FAKE)</div>
        <img src="${fakeSrc}" style="width:100%; max-width:200px; border:1px solid #e2e8f0; border-radius:4px; box-shadow:0 2px 4px rgba(0,0,0,0.1);">
      </div>
    `;
    card.insertBefore(visualContainer, actions);
  }

  shadow.appendChild(overlay);
  document.body.appendChild(host);
}
