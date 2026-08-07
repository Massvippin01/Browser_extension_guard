document.addEventListener('DOMContentLoaded', async () => {
  const urlParams = new URLSearchParams(window.location.search);
  const targetUrl = urlParams.get('url');

  if (!targetUrl) {
    document.getElementById('domainText').textContent = 'No URL provided';
    return;
  }

  const domain = new URL(targetUrl).hostname;
  document.getElementById('domainText').textContent = domain;

  try {
    const data = await chrome.storage.local.get(['verityHistory']);
    const history = data.verityHistory || [];
    
    // Find latest scan for this domain
    const latest = history.find(e => e.domain === domain);
    
    if (latest) {
      document.getElementById('scoreText').textContent = latest.riskScore || 0;
      const scoreElem = document.getElementById('scoreText');
      scoreElem.className = '';
      scoreElem.classList.add(latest.severity || 'safe');
      
      const verdictElem = document.getElementById('verdictText');
      verdictElem.textContent = (latest.severity || 'safe').toUpperCase();
      verdictElem.className = 'verdict ' + (latest.severity || 'safe');
      
      const reasonsList = document.getElementById('reasonsList');
      if (latest.reasons && latest.reasons.length > 0) {
        latest.reasons.forEach(r => {
          const li = document.createElement('li');
          li.textContent = r;
          reasonsList.appendChild(li);
        });
      } else {
        const li = document.createElement('li');
        li.textContent = "No specific threats detected.";
        reasonsList.appendChild(li);
      }

      // Populate signals grid based on reasons (mocking some details for the UI)
      const signalsContainer = document.getElementById('signalsContainer');
      const cats = {
        'Identity': ['brand'],
        'URL': ['url', 'domain', 'IP', 'HTTP'],
        'Page': ['form', 'password', 'financial', 'credential'],
        'Behavior': ['redirect', 'scam', 'script'],
        'Threat Intel': ['malicious']
      };

      for (const [catName, keywords] of Object.entries(cats)) {
        const matchedReasons = latest.reasons.filter(r => keywords.some(k => r.toLowerCase().includes(k.toLowerCase())));
        
        const card = document.createElement('div');
        card.className = 'signal-card';
        card.innerHTML = `<h3>${catName}</h3>`;
        
        if (matchedReasons.length > 0) {
          matchedReasons.forEach(mr => {
            card.innerHTML += `<div class="signal-row"><span class="signal-label">Flagged</span><span class="signal-value" style="color: var(--color-danger); text-align: right; max-width: 60%;">${mr}</span></div>`;
          });
        } else {
           card.innerHTML += `<div class="signal-row"><span class="signal-label">Status</span><span class="signal-value" style="color: var(--color-safe);">Clean</span></div>`;
        }
        signalsContainer.appendChild(card);
      }

    } else {
      document.getElementById('verdictText').textContent = 'NOT SCANNED';
    }
  } catch (err) {
    console.error(err);
  }
});
