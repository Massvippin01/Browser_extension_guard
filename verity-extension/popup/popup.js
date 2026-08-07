// Tab Switching Logic
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
  });
});

// ==========================================
// OVERVIEW TAB
// ==========================================
async function loadVerdict() {
  try {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (!tabs || tabs.length === 0) return;
      const tabId = tabs[0].id;
      const url = tabs[0].url || '';

      try {
        const urlObj = new URL(url);
        document.getElementById('app-domain-text').textContent = urlObj.hostname;
      } catch(e) {}

      // Check if we have a verdict for this tab
      const storageResult = await chrome.storage.session.get(tabId.toString());
      const verdictData = storageResult[tabId.toString()];
      if (verdictData) {
        renderVerdict(verdictData);
      } else {
        showError("No data available for this page.");
      }
    });
  } catch (error) {
    showError("An error occurred while loading data.");
  }
}

function renderVerdict(data) {
  document.getElementById('loading-state').classList.add('hidden');
  document.getElementById('verdict-state').classList.remove('hidden');

  const titleEl = document.getElementById('verdict-title');
  const iconEl = document.getElementById('verdict-icon');
  const scoreValEl = document.getElementById('risk-score-value');
  const scoreTextEl = document.getElementById('risk-score-text');

  const state = data.severity || data.state;
  iconEl.className = 'status-icon ' + state;
  
  if (state === 'safe') {
    titleEl.textContent = 'SAFE';
    iconEl.textContent = '✓';
    scoreTextEl.textContent = '"Everything looks normal."';
  } else if (state === 'caution') {
    titleEl.textContent = 'SUSPICIOUS';
    iconEl.textContent = '!';
    scoreTextEl.textContent = '"Suspicious indicators detected."';
  } else if (state === 'danger') {
    titleEl.textContent = 'DANGEROUS';
    iconEl.textContent = '!';
    scoreTextEl.textContent = '"High-risk threats detected."';
  }

  scoreValEl.innerHTML = `${data.riskScore !== undefined ? data.riskScore : data.score} <span style="font-size: 18px; color: var(--text-secondary);">/ 100</span>`;
  scoreValEl.className = state; // can be used for CSS coloring if desired

  const reasonsListEl = document.getElementById('reasons-list');
  const noReasonsEl = document.getElementById('no-reasons-msg');
  reasonsListEl.innerHTML = '';
  
  if (data.reasons && data.reasons.length > 0) {
    data.reasons.forEach(reason => {
      const li = document.createElement('li');
      li.textContent = reason;
      reasonsListEl.appendChild(li);
    });
    noReasonsEl.classList.add('hidden');
    reasonsListEl.classList.remove('hidden');
  } else {
    reasonsListEl.classList.add('hidden');
    noReasonsEl.classList.remove('hidden');
  }

  // Hook up buttons
  document.getElementById('btn-report').onclick = () => {
    window.open(chrome.runtime.getURL('reports/report.html?url=' + encodeURIComponent(data.url || document.getElementById('app-domain-text').textContent)));
  };
  document.getElementById('btn-history').onclick = () => {
    window.open(chrome.runtime.getURL('dashboard/dashboard.html'));
  };
}

function showError(msg) {
  document.getElementById('loading-state').innerHTML = `<p style="color: #94a3b8; text-align: center; margin-top: 40px;">${msg}</p>`;
}

// ==========================================
// MODEL CARD TAB
// ==========================================
async function loadModelCard() {
  try {
    // Animate numbers
    const animateValue = (id, end, isPercentage = false) => {
      const el = document.getElementById(id);
      if (!el || isNaN(end)) return;
      const duration = 400;
      const startTime = performance.now();
      const animate = (time) => {
        let progress = (time - startTime) / duration;
        if (progress > 1) progress = 1;
        const current = (progress * end).toFixed(1);
        el.textContent = current + (isPercentage ? '%' : '');
        if (progress < 1) {
          requestAnimationFrame(animate);
        } else {
          el.textContent = end + (isPercentage ? '%' : '');
        }
      };
      requestAnimationFrame(animate);
    };

    fetch(chrome.runtime.getURL('training/model_metrics.json'))
      .then(r => r.json())
      .then(data => {
        document.getElementById('mc-dataset-name').textContent = 'Dataset: ' + data.dataset;
        document.getElementById('mc-test-size').textContent = data.test_size_samples;

        // Ensure stats format is e.g. 98.4%
        animateValue('mc-accuracy', (data.accuracy * 100).toFixed(1), true);
        animateValue('mc-precision', (data.precision * 100).toFixed(1), true);
        animateValue('mc-recall', (data.recall * 100).toFixed(1), true);
        animateValue('mc-f1', (data.f1 * 100).toFixed(1), true);
        animateValue('mc-roc', (data.roc_auc * 100).toFixed(1), true);

        document.getElementById('cm-tn').textContent = data.confusion_matrix.tn;
        document.getElementById('cm-fp').textContent = data.confusion_matrix.fp;
        document.getElementById('cm-fn').textContent = data.confusion_matrix.fn;
        document.getElementById('cm-tp').textContent = data.confusion_matrix.tp;
      })
      .catch(() => {
        document.getElementById('mc-dataset-name').textContent = 'Error loading metrics';
      });
  } catch (err) {
    console.warn("Model metrics not generated yet. Run training script.");
  }
}

// ==========================================
// BENCHMARK TAB
// ==========================================
document.getElementById('run-benchmark-btn').addEventListener('click', async () => {
  const btn = document.getElementById('run-benchmark-btn');
  const progContainer = document.getElementById('benchmark-progress');
  const resContainer = document.getElementById('benchmark-results');
  const statusText = document.getElementById('bm-status-text');
  const fill = document.getElementById('bm-progress-fill');
  
  btn.classList.add('hidden');
  progContainer.classList.remove('hidden');
  resContainer.classList.add('hidden');
  
  try {
    const res = await fetch(chrome.runtime.getURL('background/benchmark/test_urls.json'));
    const testCases = await res.json();
    
    let correct = 0;
    let errors = 0;
    const latencies = [];
    
    for (let i = 0; i < testCases.length; i++) {
      const tc = testCases[i];
      statusText.textContent = `${i+1}/${testCases.length} — ${correct} correct`;
      fill.style.width = `${((i+1)/testCases.length)*100}%`;
      
      const start = performance.now();
      
      // We run via background message to execute the REAL pipeline
      const msgRes = await new Promise(resolve => {
        chrome.runtime.sendMessage({ action: 'run_inference', url: tc.url }, resolve);
      });
      
      const latency = performance.now() - start;
      
      if (!msgRes || msgRes.score === null) {
        errors++;
      } else {
        latencies.push(latency);
        // Classification Threshold: >=50 is phishing
        const predicted = msgRes.score >= 50 ? 'phishing' : 'safe';
        if (predicted === tc.label) {
          correct++;
        }
      }
    }
    
    progContainer.classList.add('hidden');
    resContainer.classList.remove('hidden');
    
    const validCases = testCases.length - errors;
    const accuracy = validCases > 0 ? (correct / validCases) * 100 : 0;
    
    document.getElementById('bm-accuracy').textContent = accuracy.toFixed(1) + '%';
    document.getElementById('bm-correct').textContent = `${correct} / ${validCases}`;
    
    if (latencies.length > 0) {
      latencies.sort((a,b)=>a-b);
      document.getElementById('bm-min').textContent = latencies[0].toFixed(1) + ' ms';
      document.getElementById('bm-max').textContent = latencies[latencies.length-1].toFixed(1) + ' ms';
      const mid = Math.floor(latencies.length / 2);
      document.getElementById('bm-median').textContent = latencies[mid].toFixed(1) + ' ms';
    }
    
    if (errors > 0) {
      document.getElementById('bm-errors-text').textContent = `Note: ${errors} test(s) failed inference (ML unavailable).`;
    } else {
      document.getElementById('bm-errors-text').textContent = '';
    }
    
    btn.classList.remove('hidden');
    btn.textContent = 'Run Again';

  } catch (err) {
    console.error(err);
    progContainer.classList.add('hidden');
    btn.classList.remove('hidden');
    alert("Benchmark failed to load test_urls.json");
  }
});

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  loadVerdict();
  loadModelCard();
  
  const simBtn = document.getElementById('open-simulator-btn');
  if (simBtn) {
    simBtn.addEventListener('click', () => {
      chrome.tabs.create({ url: chrome.runtime.getURL('simulator/simulator.html') });
    });
  }
});
