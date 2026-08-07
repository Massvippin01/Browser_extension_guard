import { getHistory, getTodayStats } from '../background/history.js';

document.addEventListener('DOMContentLoaded', async () => {
  // Tabs
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
    });
  });

  // Load Stats
  try {
    const stats = await getTodayStats();
    document.getElementById('statScanned').textContent = stats.scanned;
    document.getElementById('statSafe').textContent = stats.safe;
    document.getElementById('statSuspicious').textContent = stats.suspicious;
    document.getElementById('statDangerous').textContent = stats.dangerous;
  } catch (err) {
    console.error('Failed to load stats', err);
  }

  // Load History
  try {
    const history = await getHistory();
    const list = document.getElementById('historyList');
    
    if (history.length === 0) {
      list.innerHTML = '<div style="color:var(--text-secondary);">No detections today.</div>';
      return;
    }

    history.slice(0, 50).forEach(entry => {
      const date = new Date(entry.timestamp);
      const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      
      const el = document.createElement('div');
      el.className = 'history-item';
      
      el.innerHTML = `
        <div>
          <div class="history-domain">${entry.domain}</div>
          <div class="history-meta">${timeStr} &bull; ${entry.severity ? entry.severity.toUpperCase() : 'UNKNOWN'}</div>
        </div>
        <div class="history-score ${entry.severity || 'safe'}">${entry.riskScore !== undefined ? entry.riskScore : 0}</div>
      `;
      list.appendChild(el);
    });
  } catch (err) {
    console.error('Failed to load history', err);
  }
});
