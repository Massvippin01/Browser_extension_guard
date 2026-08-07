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
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) {
      showError("Could not determine active tab.");
      return;
    }
    const storageResult = await chrome.storage.session.get(tab.id.toString());
    const verdictData = storageResult[tab.id.toString()];
    if (verdictData) {
      renderVerdict(verdictData);
    } else {
      showError("No analysis available for this page.");
    }
  } catch (error) {
    showError("An error occurred while loading data.");
  }
}

function renderVerdict(data) {
  document.getElementById('loading-state').classList.add('hidden');
  document.getElementById('verdict-state').classList.remove('hidden');

  const titleEl = document.getElementById('verdict-title');
  const iconEl = document.getElementById('verdict-icon');
  
  document.getElementById('score-value').textContent = data.score;
  document.getElementById('score-rule').textContent = (data.ruleScore !== undefined) ? data.ruleScore : data.score;
  document.getElementById('score-ml').textContent = data.mlAvailable ? data.mlScore : 'Unavailable';

  iconEl.className = 'status-icon ' + data.state;
  document.getElementById('score-value').className = 'score-value ' + data.state;
  
  if (data.scoringTimeMs !== undefined) {
    document.getElementById('scoring-time').textContent = `Scoring took ${data.scoringTimeMs.toFixed(1)} ms`;
  }

  if (data.state === 'safe') {
    titleEl.textContent = 'SAFE';
    iconEl.textContent = '✓';
  } else if (data.state === 'caution') {
    titleEl.textContent = 'CAUTION';
    iconEl.textContent = '!';
  } else if (data.state === 'danger') {
    titleEl.textContent = 'DANGER';
    iconEl.textContent = '!';
  }

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
}

function showError(msg) {
  document.getElementById('loading-state').innerHTML = `<p style="color: #94a3b8; text-align: center; margin-top: 40px;">${msg}</p>`;
}

// ==========================================
// MODEL CARD TAB
// ==========================================
async function loadModelCard() {
  try {
    const res = await fetch(chrome.runtime.getURL('training/model_metrics.json'));
    if (!res.ok) throw new Error("Metrics file missing");
    const data = await res.json();
    
    document.getElementById('mc-dataset-name').textContent = `${data.dataset.name} (${data.dataset.features} features)`;
    document.getElementById('mc-accuracy').textContent = (data.metrics.accuracy * 100).toFixed(1) + '%';
    document.getElementById('mc-precision').textContent = (data.metrics.precision * 100).toFixed(1) + '%';
    document.getElementById('mc-recall').textContent = (data.metrics.recall * 100).toFixed(1) + '%';
    document.getElementById('mc-f1').textContent = (data.metrics.f1 * 100).toFixed(1) + '%';
    document.getElementById('mc-roc').textContent = (data.metrics.roc_auc * 100).toFixed(1) + '%';
    
    document.getElementById('cm-tn').textContent = data.confusion_matrix[0][0];
    document.getElementById('cm-fp').textContent = data.confusion_matrix[0][1];
    document.getElementById('cm-fn').textContent = data.confusion_matrix[1][0];
    document.getElementById('cm-tp').textContent = data.confusion_matrix[1][1];
    
    document.getElementById('mc-test-size').textContent = data.split.test;

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
