/**
 * content/search/ui.js - Production-Grade Search Result Badges
 * Self-contained pill with SVG icon and clean tooltip. Adapts to light/dark host pages without shifting layout.
 */

export class SearchUI {
  constructor() {
    this.badgeStyle = `
      :host {
        display: inline-block;
        margin-left: 8px;
        vertical-align: middle;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Noto Sans", sans-serif;
        line-height: 1;
      }
      *, *::before, *::after {
        box-sizing: border-box;
      }
      .verity-badge {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 3px 8px;
        border-radius: 9999px;
        font-size: 11px;
        font-weight: 600;
        cursor: pointer;
        position: relative;
        border: 1px solid transparent;
        white-space: nowrap;
        user-select: none;
        transition: transform 120ms ease, box-shadow 120ms ease;
      }
      .verity-badge:hover {
        transform: scale(1.04);
      }
      .verity-badge.safe {
        background-color: #f0fdf4;
        color: #166534;
        border-color: #bbf7d0;
        box-shadow: 0 1px 2px rgba(0,0,0,0.03);
      }
      .verity-badge.suspicious {
        background-color: #fffbeb;
        color: #92400e;
        border-color: #fde68a;
        box-shadow: 0 1px 2px rgba(0,0,0,0.03);
      }
      .verity-badge.danger {
        background-color: #fef2f2;
        color: #991b1b;
        border-color: #fecaca;
        box-shadow: 0 1px 2px rgba(0,0,0,0.03);
      }
      
      .verity-icon-svg {
        display: inline-flex;
        align-items: center;
        flex-shrink: 0;
      }
      
      /* Tooltip */
      .verity-tooltip {
        position: absolute;
        bottom: calc(100% + 8px);
        left: 50%;
        transform: translateX(-50%) translateY(4px);
        width: 240px;
        background: #18181b;
        color: #fafafa;
        border: 1px solid #27272a;
        box-shadow: 0 10px 15px -3px rgba(0,0,0,0.25), 0 4px 6px -4px rgba(0,0,0,0.2);
        border-radius: 8px;
        padding: 12px;
        z-index: 2147483647;
        visibility: hidden;
        opacity: 0;
        transition: opacity 120ms ease, transform 120ms ease, visibility 120ms;
        text-align: left;
        pointer-events: none;
        white-space: normal;
        line-height: 1.45;
      }
      .verity-badge:hover .verity-tooltip {
        visibility: visible;
        opacity: 1;
        transform: translateX(-50%) translateY(0);
      }
      
      .verity-tooltip-title {
        font-size: 12px;
        font-weight: 700;
        margin-bottom: 6px;
        display: flex;
        align-items: center;
        gap: 6px;
        border-bottom: 1px solid #27272a;
        padding-bottom: 6px;
      }
      .verity-tooltip-reason {
        font-size: 11px;
        color: #d4d4d8;
        margin-bottom: 4px;
        display: flex;
        align-items: flex-start;
        gap: 6px;
      }
      .verity-tooltip-score {
        margin-top: 8px;
        font-size: 10px;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        color: #a1a1aa;
        text-align: right;
      }
    `;
  }

  createBadge(verdict) {
    const host = document.createElement('span');
    host.className = 'verity-search-indicator';
    host.style.all = 'initial'; // Complete isolation
    
    const shadow = host.attachShadow({ mode: 'closed' });
    
    const style = document.createElement('style');
    style.textContent = this.badgeStyle;
    shadow.appendChild(style);

    const badge = document.createElement('div');
    const state = verdict.severity || verdict.state || 'safe';
    
    let displayState = 'safe';
    let iconSvg = `<svg class="verity-icon-svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></svg>`;
    let label = 'SAFE';

    if (state === 'danger') {
      displayState = 'danger';
      iconSvg = `<svg class="verity-icon-svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m14.5 9.5-5 5"/><path d="m9.5 9.5 5 5"/></svg>`;
      label = 'DANGEROUS';
    } else if (state === 'caution') {
      displayState = 'suspicious';
      iconSvg = `<svg class="verity-icon-svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>`;
      label = 'SUSPICIOUS';
    } else if (state === 'safe') {
      if (verdict.score > 10) {
        displayState = 'suspicious';
        iconSvg = `<svg class="verity-icon-svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>`;
        label = 'UNKNOWN';
      } else {
        displayState = 'safe';
        iconSvg = `<svg class="verity-icon-svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></svg>`;
        label = 'SAFE';
      }
    }

    badge.className = `verity-badge ${displayState}`;
    badge.innerHTML = `${iconSvg}<span>${label}</span>`;

    // Tooltip
    const tooltip = document.createElement('div');
    tooltip.className = 'verity-tooltip';
    
    const titleEl = document.createElement('div');
    titleEl.className = 'verity-tooltip-title';
    titleEl.innerHTML = `${iconSvg}<span>Verity Security Analysis</span>`;
    tooltip.appendChild(titleEl);

    const reasons = verdict.reasons || [];
    if (reasons.length === 0) {
      const reasonEl = document.createElement('div');
      reasonEl.className = 'verity-tooltip-reason';
      reasonEl.textContent = displayState === 'safe'
        ? '✓ Safe reputation. No suspicious indicators detected.'
        : '• No specific threat reputation found. Proceed with care.';
      tooltip.appendChild(reasonEl);
    } else {
      for (const r of reasons) {
        const reasonEl = document.createElement('div');
        reasonEl.className = 'verity-tooltip-reason';
        reasonEl.textContent = `• ${String(r)}`;
        tooltip.appendChild(reasonEl);
      }
    }

    const scoreEl = document.createElement('div');
    scoreEl.className = 'verity-tooltip-score';
    const scoreVal = verdict.score !== undefined ? verdict.score : (verdict.riskScore !== undefined ? verdict.riskScore : 0);
    scoreEl.textContent = `Risk Score: ${scoreVal}/100`;
    tooltip.appendChild(scoreEl);

    badge.appendChild(tooltip);
    shadow.appendChild(badge);

    return host;
  }
}
