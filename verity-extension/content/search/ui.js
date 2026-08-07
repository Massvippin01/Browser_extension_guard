export class SearchUI {
  constructor() {
    this.badgeStyle = `
      :host {
        display: inline-block;
        margin-left: 8px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        vertical-align: middle;
      }
      .verity-badge {
        display: inline-flex;
        align-items: center;
        padding: 2px 6px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
        cursor: pointer;
        position: relative;
        border: 1px solid transparent;
        transition: all 0.2s ease;
      }
      .verity-badge.safe {
        background-color: #dcfce7;
        color: #166534;
        border-color: #bbf7d0;
      }
      .verity-badge.suspicious {
        background-color: #fef9c3;
        color: #854d0e;
        border-color: #fef08a;
      }
      .verity-badge.danger {
        background-color: #fee2e2;
        color: #991b1b;
        border-color: #fecaca;
      }
      
      .verity-icon {
        margin-right: 4px;
        font-size: 12px;
      }
      
      /* Tooltip */
      .verity-tooltip {
        position: absolute;
        bottom: 125%;
        left: 50%;
        transform: translateX(-50%);
        width: 220px;
        background: #ffffff;
        border: 1px solid #e2e8f0;
        box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -2px rgba(0,0,0,0.05);
        border-radius: 6px;
        padding: 12px;
        z-index: 9999;
        visibility: hidden;
        opacity: 0;
        transition: opacity 0.2s, visibility 0.2s;
        text-align: left;
        color: #1e293b;
        font-weight: normal;
        pointer-events: none;
      }
      .verity-badge:hover .verity-tooltip {
        visibility: visible;
        opacity: 1;
      }
      
      .verity-tooltip-title {
        font-size: 13px;
        font-weight: 600;
        margin-bottom: 6px;
        border-bottom: 1px solid #f1f5f9;
        padding-bottom: 6px;
      }
      .verity-tooltip-reason {
        font-size: 11px;
        margin-bottom: 4px;
        line-height: 1.4;
        display: flex;
        align-items: flex-start;
      }
      .verity-tooltip-reason span {
        margin-right: 4px;
        color: #64748b;
      }
      .verity-tooltip-score {
        margin-top: 8px;
        font-size: 10px;
        color: #94a3b8;
        text-align: right;
      }
    `;
  }

  createBadge(verdict) {
    const host = document.createElement('span');
    host.className = 'verity-search-indicator';
    host.style.all = 'initial'; // Isolate completely
    
    const shadow = host.attachShadow({ mode: 'closed' });
    
    const style = document.createElement('style');
    style.textContent = this.badgeStyle;
    shadow.appendChild(style);

    const badge = document.createElement('div');
    
    // Map states
    const state = verdict.severity || verdict.state || 'safe';
    
    // As per spec: Unknown reputation does NOT mean SAFE automatically.
    // If it's safe but has a score > 0, it might just be "unknown". 
    // We only display SAFE if it's genuinely 0 or very low risk.
    // We'll use the 'state' from risk engine which already handles thresholds.
    // state: safe (score < 35), caution (35-69), danger (70+)
    
    let displayState = 'safe';
    let icon = '🟢';
    let label = 'SAFE';

    if (state === 'danger') {
      displayState = 'danger';
      icon = '🔴';
      label = 'DANGEROUS';
    } else if (state === 'caution') {
      displayState = 'suspicious';
      icon = '🟡';
      label = 'SUSPICIOUS';
    } else if (state === 'safe') {
      // Differentiate between truly known safe and just unknown
      if (verdict.score > 10) {
        // Has some minor flags, maybe just UNKNOWN
        displayState = 'suspicious';
        icon = '⚪';
        label = 'UNKNOWN';
      } else {
        displayState = 'safe';
        icon = '🟢';
        label = 'SAFE';
      }
    }

    badge.className = `verity-badge ${displayState}`;
    
    badge.innerHTML = `
      <span class="verity-icon">${icon}</span>
      ${label}
    `;

    // Tooltip
    const tooltip = document.createElement('div');
    tooltip.className = 'verity-tooltip';
    
    const titleColor = displayState === 'danger' ? '#dc2626' : (displayState === 'suspicious' ? '#d97706' : '#16a34a');
    
    let reasonsHtml = '';
    const reasons = verdict.reasons || [];
    if (reasons.length === 0) {
      if (displayState === 'safe') reasonsHtml = '<div class="verity-tooltip-reason"><span>✓</span> Safe reputation. No suspicious indicators found.</div>';
      else reasonsHtml = '<div class="verity-tooltip-reason"><span>?</span> No specific threat data found. Proceed with care.</div>';
    } else {
      reasonsHtml = reasons.map(r => `<div class="verity-tooltip-reason"><span>▸</span>${r}</div>`).join('');
    }

    tooltip.innerHTML = `
      <div class="verity-tooltip-title" style="color: ${titleColor}">Verity Analysis</div>
      ${reasonsHtml}
      <div class="verity-tooltip-score">Risk Score: ${verdict.score}/100</div>
    `;

    badge.appendChild(tooltip);
    shadow.appendChild(badge);

    return host;
  }
}
