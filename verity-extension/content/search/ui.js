/**
 * content/search/ui.js - Production-Grade Search Result Badges & Popover
 *
 * Implements:
 * 1. shadcn Badge style: 20px height, 8px padding, 6px icon gap, fully rounded,
 *    12px weight 500, sentence-case ("Safe", "Suspicious", "Dangerous", "Checking").
 * 2. Background luminance dark-mode detection with solid base layer under tints.
 * 3. 0px layout-shift inline-flex alignment.
 * 4. Single shared shadow-DOM popover appended to document.body, fixed-positioned,
 *    with 150ms hover-intent, 120ms leave delay, flip detection, and arrow notch.
 * 5. PSL domain extraction and category-mapped SVG icons in reason list.
 */

import '../../shared/ui/icons.js';
import { t, SIGNAL_CATEGORY_MAP } from '../../shared/messages.js';
import { getDomain } from '../../shared/psl.js';

const ICONS = (typeof globalThis !== 'undefined' && globalThis.ICONS) ? globalThis.ICONS : {
  'shield-check': `<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>`,
  'shield-x': `<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m14.5 9.5-5 5"/><path d="m9.5 9.5 5 5"/>`,
  'triangle-alert': `<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>`,
  'logo-mark': `<path fill-rule="evenodd" clip-rule="evenodd" d="M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3zm-1.06 13.54l-3.24-3.24 1.41-1.41 1.83 1.83 4.24-4.24 1.41 1.41-5.65 5.65z" fill="currentColor"/>`,
  'link': `<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>`,
  'globe': `<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>`,
  'key-round': `<path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/>`,
  'download': `<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/>`,
  'shield-alert': `<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="M12 8v4"/><path d="M12 16h.01"/>`,
  'info': `<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>`
};

function getIconSvg(name, { size = 16, className = '', strokeWidth = 1.5, color = 'currentColor' } = {}) {
  if (typeof globalThis !== 'undefined' && typeof globalThis.getIconSvg === 'function') {
    return globalThis.getIconSvg(name, { size, className, strokeWidth, color });
  }
  const inner = ICONS[name] || ICONS['info'];
  return `<svg class="${className}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="${strokeWidth}" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${inner}</svg>`;
}

// Safe helper fallbacks in case of environment differences
const safeT = (id, params) => {
  if (typeof t === 'function') return t(id, params);
  if (typeof globalThis !== 'undefined' && typeof globalThis.t === 'function') {
    return globalThis.t(id, params);
  }
  return id;
};

const safeIcon = (name, opts) => {
  if (typeof getIconSvg === 'function') return getIconSvg(name, opts);
  if (typeof globalThis !== 'undefined' && typeof globalThis.getIconSvg === 'function') {
    return globalThis.getIconSvg(name, opts);
  }
  return '';
};

const safeDomain = (url) => {
  if (typeof getDomain === 'function') {
    const d = getDomain(url);
    if (d) return d;
  }
  if (typeof globalThis !== 'undefined' && typeof globalThis.getDomain === 'function') {
    const d = globalThis.getDomain(url);
    if (d) return d;
  }
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch (_) {
    return '';
  }
};

/**
 * Reusable font loader: loads InterVariable.woff2 via FontFace ArrayBuffer
 * and registers on document.fonts so both badge and popover render in VerityInter.
 */
let fontLoadPromise = null;
export function ensureSearchFontLoaded() {
  if (typeof document === 'undefined' || !('fonts' in document)) {
    return Promise.resolve();
  }
  try {
    if (document.fonts.check('16px VerityInter')) {
      return Promise.resolve();
    }
  } catch (_) {}

  if (typeof globalThis !== 'undefined' && typeof globalThis.ensureVerityFontLoaded === 'function') {
    return globalThis.ensureVerityFontLoaded();
  }

  if (fontLoadPromise) return fontLoadPromise;

  fontLoadPromise = (async () => {
    try {
      const fontUrl = (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL)
        ? chrome.runtime.getURL('shared/fonts/InterVariable.woff2')
        : '/shared/fonts/InterVariable.woff2';
      const res = await fetch(fontUrl);
      if (!res.ok) return;
      const buffer = await res.arrayBuffer();
      const fontFace = new FontFace('VerityInter', buffer, {
        weight: '100 900',
        style: 'normal',
        display: 'swap'
      });
      const loaded = await fontFace.load();
      document.fonts.add(loaded);
    } catch (_) {}
  })();
  return fontLoadPromise;
}

if (typeof document !== 'undefined') {
  ensureSearchFontLoaded().catch(() => {});
}

/**
 * Detects host page dark theme from computed background color luminance.
 * Re-checks on theme / attribute / media query changes.
 */
export function isHostDarkTheme() {
  if (typeof document === 'undefined') return false;

  function getLuminance(rgbStr) {
    if (!rgbStr || rgbStr === 'transparent' || rgbStr === 'rgba(0, 0, 0, 0)') return null;
    const match = rgbStr.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/i);
    if (!match) return null;
    const r = parseInt(match[1], 10) / 255;
    const g = parseInt(match[2], 10) / 255;
    const b = parseInt(match[3], 10) / 255;
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  }

  const elementsToCheck = [
    document.body,
    document.documentElement,
    document.querySelector('#search'),
    document.querySelector('#rso'),
    document.querySelector('.b_results'),
    document.querySelector('#b_content'),
    document.querySelector('article[data-testid="result"]')
  ];

  for (const el of elementsToCheck) {
    if (!el) continue;
    const bg = window.getComputedStyle(el).backgroundColor;
    const lum = getLuminance(bg);
    if (lum !== null) {
      return lum < 0.45;
    }
  }

  const docClass = (document.documentElement.className || '') + ' ' + (document.body?.className || '');
  const docTheme = (document.documentElement.getAttribute('data-theme') || '') + ' ' + (document.body?.getAttribute('data-theme') || '');
  if (/dark|night/i.test(docClass + ' ' + docTheme)) {
    return true;
  }

  if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
    return true;
  }

  return false;
}

/**
 * Single Shared Tooltip / Popover Manager
 * Appends one fixed-position shadow DOM host to document.body.
 */
class SearchPopoverManager {
  constructor() {
    this.host = null;
    this.shadow = null;
    this.card = null;
    this.arrow = null;
    this.currentTarget = null;
    this.currentVerdict = null;
    this.currentUrl = '';
    this.openTimer = null;
    this.closeTimer = null;
    this.isOpen = false;
    this.scrollOriginY = 0;
    this.onScroll = this.onScroll.bind(this);
    this.onResize = this.onResize.bind(this);
    this.onKeyDown = this.onKeyDown.bind(this);
  }

  ensureHost() {
    if (this.host && document.body.contains(this.host)) return;

    this.host = document.createElement('div');
    this.host.id = 'verity-search-popover-host';
    this.host.style.position = 'fixed';
    this.host.style.top = '0';
    this.host.style.left = '0';
    this.host.style.width = '0';
    this.host.style.height = '0';
    this.host.style.zIndex = '2147483647';
    this.host.style.pointerEvents = 'none';

    this.shadow = this.host.attachShadow({ mode: 'open' });

    const style = document.createElement('style');
    style.textContent = `
      *, *::before, *::after {
        box-sizing: border-box;
      }
      .verity-popover {
        position: fixed;
        width: 300px;
        max-width: min(300px, calc(100vw - 16px));
        border-radius: 12px;
        padding: 12px 14px;
        font-family: "VerityInter", system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans", sans-serif;
        font-size: 12px;
        line-height: 1.5;
        z-index: 2147483647;
        pointer-events: auto;
        opacity: 0;
        visibility: hidden;
        transform: translateY(4px);
        transition: opacity 150ms ease-out, transform 150ms ease-out, visibility 150ms;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.15), 0 8px 10px -6px rgba(0, 0, 0, 0.1);
        text-align: left;
      }
      .verity-popover.open {
        opacity: 1;
        visibility: visible;
        transform: translateY(0);
      }
      @media (prefers-reduced-motion: reduce) {
        .verity-popover {
          transition: none !important;
          transform: none !important;
        }
      }

      /* Light Theme */
      .verity-popover.v-light {
        background: #ffffff;
        color: #09090b;
        border: 1px solid #e4e4e7;
      }
      .verity-popover.v-light .v-popover-arrow {
        background: #ffffff;
        border-color: #e4e4e7;
      }
      .verity-popover.v-light .v-sub-mono {
        color: #71717a;
      }
      .verity-popover.v-light .v-reason-row {
        color: #3f3f46;
      }
      .verity-popover.v-light .v-more-row {
        color: #71717a;
      }
      .verity-popover.v-light .v-footer-row {
        border-top: 1px solid #f4f4f5;
        color: #71717a;
      }
      .verity-popover.v-light .v-track {
        background: #f4f4f5;
      }

      /* Dark Theme */
      .verity-popover.v-dark {
        background: #18181b;
        color: #fafafa;
        border: 1px solid #27272a;
        box-shadow: 0 14px 28px -4px rgba(0, 0, 0, 0.5), 0 10px 10px -5px rgba(0, 0, 0, 0.4);
      }
      .verity-popover.v-dark .v-popover-arrow {
        background: #18181b;
        border-color: #27272a;
      }
      .verity-popover.v-dark .v-sub-mono {
        color: #a1a1aa;
      }
      .verity-popover.v-dark .v-reason-row {
        color: #d4d4d8;
      }
      .verity-popover.v-dark .v-more-row {
        color: #a1a1aa;
      }
      .verity-popover.v-dark .v-footer-row {
        border-top: 1px solid #27272a;
        color: #a1a1aa;
      }
      .verity-popover.v-dark .v-track {
        background: #27272a;
      }

      /* Notch Arrow */
      .v-popover-arrow {
        position: absolute;
        width: 10px;
        height: 10px;
        transform: rotate(45deg);
        pointer-events: none;
      }
      .v-popover-arrow.placement-bottom {
        top: -5px;
        border-top: 1px solid;
        border-left: 1px solid;
      }
      .v-popover-arrow.placement-top {
        bottom: -5px;
        border-bottom: 1px solid;
        border-right: 1px solid;
      }

      /* Header */
      .v-header-row {
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 8px;
      }
      .v-icon-circle {
        width: 26px;
        height: 26px;
        border-radius: 9999px;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
      }
      .v-icon-circle.safe {
        background: rgba(34, 197, 94, 0.14);
        color: #16a34a;
      }
      .v-icon-circle.suspicious {
        background: rgba(245, 158, 11, 0.16);
        color: #d97706;
      }
      .v-icon-circle.danger {
        background: rgba(239, 68, 68, 0.16);
        color: #dc2626;
      }
      .v-icon-circle.checking {
        background: rgba(161, 161, 170, 0.16);
        color: #71717a;
      }

      .v-header-text {
        flex: 1;
        min-width: 0;
      }
      .v-title {
        font-size: 13px;
        font-weight: 600;
        line-height: 1.3;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .v-sub-mono {
        font-family: ui-monospace, "SF Mono", "Cascadia Mono", Consolas, monospace;
        font-size: 11px;
        line-height: 1.3;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }

      /* Body */
      .v-body-section {
        display: flex;
        flex-direction: column;
        gap: 6px;
        margin-bottom: 10px;
      }
      .v-reason-row {
        display: flex;
        align-items: flex-start;
        gap: 8px;
        font-size: 11.5px;
        line-height: 1.45;
        word-break: break-word;
      }
      .v-reason-icon {
        flex-shrink: 0;
        margin-top: 2px;
        opacity: 0.85;
      }
      .v-reason-text {
        flex: 1;
      }
      .v-more-row {
        font-size: 11px;
        font-weight: 500;
        padding-left: 20px;
      }

      /* Footer */
      .v-footer-row {
        padding-top: 8px;
        margin-top: 4px;
        display: flex;
        flex-direction: column;
        gap: 6px;
      }
      .v-score-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        font-size: 11px;
      }
      .v-score-num {
        font-variant-numeric: tabular-nums;
        font-weight: 600;
        font-size: 11.5px;
      }
      .v-track {
        height: 4px;
        border-radius: 9999px;
        overflow: hidden;
        position: relative;
        width: 100%;
      }
      .v-fill {
        height: 100%;
        border-radius: 9999px;
        transition: width 200ms ease;
      }
      .v-fill.safe {
        background: #22c55e;
      }
      .v-fill.suspicious {
        background: #f59e0b;
      }
      .v-fill.danger {
        background: #ef4444;
      }
      .v-fill.checking {
        background: #a1a1aa;
      }

      .v-brand-mark {
        font-size: 10px;
        opacity: 0.65;
        display: flex;
        align-items: center;
        justify-content: flex-end;
        gap: 4px;
        margin-top: 2px;
      }
    `;

    this.card = document.createElement('div');
    this.card.className = 'verity-popover';
    this.card.setAttribute('role', 'tooltip');
    this.card.id = 'verity-search-tooltip';

    this.arrow = document.createElement('div');
    this.arrow.className = 'v-popover-arrow';
    this.card.appendChild(this.arrow);

    this.contentContainer = document.createElement('div');
    this.contentContainer.className = 'v-popover-content';
    this.card.appendChild(this.contentContainer);

    this.shadow.appendChild(style);
    this.shadow.appendChild(this.card);
    document.body.appendChild(this.host);

    // Keep open when cursor enters popover card
    this.card.addEventListener('mouseenter', () => {
      clearTimeout(this.closeTimer);
    });
    this.card.addEventListener('mouseleave', () => {
      this.scheduleClose(120);
    });
  }

  scheduleOpen(targetPill, verdict, url, delay = 150) {
    clearTimeout(this.closeTimer);
    clearTimeout(this.openTimer);
    this.openTimer = setTimeout(() => {
      this.open(targetPill, verdict, url);
    }, delay);
  }

  scheduleClose(delay = 120) {
    clearTimeout(this.openTimer);
    clearTimeout(this.closeTimer);
    this.closeTimer = setTimeout(() => {
      this.close();
    }, delay);
  }

  open(targetPill, verdict, url) {
    this.ensureHost();
    this.currentTarget = targetPill;
    this.currentVerdict = verdict;
    this.currentUrl = url;
    this.scrollOriginY = window.scrollY;

    targetPill.setAttribute('aria-expanded', 'true');
    this.renderContent(verdict, url);
    this.card.className = `verity-popover ${isHostDarkTheme() ? 'v-dark' : 'v-light'} open`;
    this.positionPopover();

    window.addEventListener('scroll', this.onScroll, { passive: true });
    window.addEventListener('resize', this.onResize, { passive: true });
    window.addEventListener('keydown', this.onKeyDown);
    this.isOpen = true;
  }

  close() {
    clearTimeout(this.openTimer);
    clearTimeout(this.closeTimer);
    if (!this.isOpen) return;

    if (this.currentTarget) {
      this.currentTarget.setAttribute('aria-expanded', 'false');
    }
    if (this.card) {
      this.card.classList.remove('open');
    }
    this.isOpen = false;
    this.currentTarget = null;

    window.removeEventListener('scroll', this.onScroll);
    window.removeEventListener('resize', this.onResize);
    window.removeEventListener('keydown', this.onKeyDown);
  }

  onScroll() {
    if (!this.isOpen || !this.currentTarget) return;
    // If scrolled more than 60px away, dismiss popover
    if (Math.abs(window.scrollY - this.scrollOriginY) > 60) {
      this.close();
      return;
    }
    window.requestAnimationFrame(() => this.positionPopover());
  }

  onResize() {
    if (!this.isOpen || !this.currentTarget) return;
    window.requestAnimationFrame(() => this.positionPopover());
  }

  onKeyDown(e) {
    if (e.key === 'Escape') {
      this.close();
      if (this.currentTarget && typeof this.currentTarget.focus === 'function') {
        this.currentTarget.focus();
      }
    }
  }

  positionPopover() {
    if (!this.card || !this.currentTarget) return;
    const rect = this.currentTarget.getBoundingClientRect();

    // If trigger element scrolled completely out of view, close
    if (rect.bottom < 0 || rect.top > window.innerHeight) {
      this.close();
      return;
    }

    const popoverWidth = this.card.offsetWidth || 300;
    const popoverHeight = this.card.offsetHeight || 180;
    const margin = 8;
    const gap = 8;

    // Vertical placement: prefer below-right with 8px gap; flip above if not enough room
    const roomBelow = window.innerHeight - rect.bottom - margin;
    const roomAbove = rect.top - margin;
    let top = 0;
    let placement = 'bottom';

    if (roomBelow >= popoverHeight || roomBelow >= roomAbove) {
      top = rect.bottom + gap;
      placement = 'bottom';
    } else {
      top = Math.max(margin, rect.top - popoverHeight - gap);
      placement = 'top';
    }

    // Horizontal placement: align near center of pill, clamp to viewport with 8px margin
    let left = rect.left + rect.width / 2 - popoverWidth / 2;
    const minLeft = margin;
    const maxLeft = window.innerWidth - popoverWidth - margin;
    left = Math.max(minLeft, Math.min(left, maxLeft));

    this.card.style.top = `${Math.round(top)}px`;
    this.card.style.left = `${Math.round(left)}px`;

    // Arrow notch pointing at pill center
    const pillCenterX = rect.left + rect.width / 2;
    let arrowLeft = pillCenterX - left - 5;
    arrowLeft = Math.max(14, Math.min(arrowLeft, popoverWidth - 24));

    this.arrow.className = `v-popover-arrow placement-${placement}`;
    this.arrow.style.left = `${Math.round(arrowLeft)}px`;
  }

  renderContent(verdict, url) {
    const state = verdict.severity || verdict.state || 'safe';
    const score = verdict.score !== undefined ? verdict.score : (verdict.riskScore !== undefined ? verdict.riskScore : 0);
    const domain = safeDomain(url);

    let displayState = 'safe';
    let iconName = 'shield-check';
    let titleText = safeT('SEARCH_POPOVER_TITLE_SAFE');

    if (state === 'danger') {
      displayState = 'danger';
      iconName = 'shield-x';
      titleText = safeT('SEARCH_POPOVER_TITLE_BLOCK');
    } else if (state === 'caution' || (state === 'suspicious')) {
      displayState = 'suspicious';
      iconName = 'triangle-alert';
      titleText = safeT('SEARCH_POPOVER_TITLE_CAUTION');
    } else if (state === 'checking') {
      displayState = 'checking';
      iconName = 'info';
      titleText = safeT('SEARCH_POPOVER_TITLE_CHECKING');
    } else {
      // safe
      if (score > 15) {
        displayState = 'suspicious';
        iconName = 'triangle-alert';
        titleText = safeT('SEARCH_POPOVER_TITLE_CAUTION');
      } else {
        displayState = 'safe';
        iconName = 'shield-check';
        titleText = safeT('SEARCH_POPOVER_TITLE_SAFE');
      }
    }

    // 1. Header
    const headerHtml = `
      <div class="v-header-row">
        <div class="v-icon-circle ${displayState}">
          ${safeIcon(iconName, { size: 14, strokeWidth: 2 })}
        </div>
        <div class="v-header-text">
          <div class="v-title">${escapeHtml(titleText)}</div>
          <div class="v-sub-mono">${escapeHtml(domain || url)}</div>
        </div>
      </div>
    `;

    // 2. Body Reasons
    let bodyHtml = '<div class="v-body-section">';
    if (displayState === 'checking') {
      bodyHtml += `
        <div class="v-reason-row">
          <div class="v-reason-icon">${safeIcon('info', { size: 13, strokeWidth: 1.5 })}</div>
          <div class="v-reason-text">${escapeHtml(safeT('SEARCH_POPOVER_CHECKING_DESC'))}</div>
        </div>
      `;
    } else if (displayState === 'safe') {
      bodyHtml += `
        <div class="v-reason-row">
          <div class="v-reason-icon">${safeIcon('shield-check', { size: 13, strokeWidth: 1.8 })}</div>
          <div class="v-reason-text">${escapeHtml(safeT('SEARCH_POPOVER_SAFE_DESC'))}</div>
        </div>
      `;
    } else {
      const rawReasons = Array.isArray(verdict.reasons) ? verdict.reasons : [];
      const signals = Array.isArray(verdict.signals) ? verdict.signals : [];

      // Combine structured signals and text reasons
      const combined = [];
      signals.forEach(s => {
        if (!s) return;
        const sigId = typeof s === 'string' ? s : s.id;
        const cat = (SIGNAL_CATEGORY_MAP && sigId && SIGNAL_CATEGORY_MAP[sigId]) || 'threat_intel';
        const txt = typeof s === 'string' ? safeT(s) : (s.reason || safeT(s.id, s.params));
        combined.push({ id: sigId, category: cat, text: txt });
      });

      rawReasons.forEach(r => {
        if (typeof r === 'string' && !combined.some(c => c.text === r)) {
          combined.push({ id: 'GENERIC', category: 'threat_intel', text: r });
        }
      });

      if (combined.length === 0) {
        combined.push({
          id: 'SUSPICIOUS_HEURISTIC',
          category: 'url',
          text: safeT('OVERLAY_SUMMARY_NEUTRAL') || 'Heuristic characteristics indicate elevated risk.'
        });
      }

      const visibleReasons = combined.slice(0, 3);
      visibleReasons.forEach(item => {
        const catIcon = mapCategoryToIcon(item.category);
        bodyHtml += `
          <div class="v-reason-row">
            <div class="v-reason-icon">${safeIcon(catIcon, { size: 13, strokeWidth: 1.6 })}</div>
            <div class="v-reason-text">${escapeHtml(item.text)}</div>
          </div>
        `;
      });

      if (combined.length > 3) {
        bodyHtml += `
          <div class="v-more-row">${escapeHtml(safeT('SEARCH_POPOVER_MORE_REASONS', { count: combined.length - 3 }))}</div>
        `;
      }
    }
    bodyHtml += '</div>';

    // 3. Footer
    const pct = Math.min(100, Math.max(0, score));
    const footerHtml = `
      <div class="v-footer-row">
        <div class="v-score-row">
          <span>${escapeHtml(safeT('SEARCH_POPOVER_RISK_SCORE'))}</span>
          <span class="v-score-num">${escapeHtml(safeT('SEARCH_POPOVER_SCORE_VALUE', { score }))}</span>
        </div>
        <div class="v-track">
          <div class="v-fill ${displayState}" style="width: ${pct}%"></div>
        </div>
        <div class="v-brand-mark">
          ${safeIcon('logo-mark', { size: 10 })}
          <span>${escapeHtml(safeT('SEARCH_POPOVER_FOOTER_BRAND'))}</span>
        </div>
      </div>
    `;

    this.contentContainer.innerHTML = headerHtml + bodyHtml + footerHtml;
  }
}

const popoverSingleton = new SearchPopoverManager();

function mapCategoryToIcon(cat) {
  switch (cat) {
    case 'url': return 'link';
    case 'dom_credentials':
    case 'brand_impersonation': return 'key-round';
    case 'download': return 'download';
    case 'ip_host': return 'globe';
    case 'payment_phishing': return 'key-round';
    case 'malvertising': return 'link';
    case 'threat_intel': return 'shield-alert';
    default: return 'info';
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * SearchUI - Generates isolated badge elements using shadow DOM.
 */
export class SearchUI {
  constructor() {
    this.badgeStyle = `
      :host {
        display: inline-flex !important;
        vertical-align: middle !important;
        line-height: 1 !important;
        margin-inline-start: 8px !important;
        white-space: nowrap !important;
      }
      *, *::before, *::after {
        box-sizing: border-box;
      }
      .verity-badge {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        height: 20px;
        line-height: 1;
        padding: 0 8px;
        gap: 6px;
        border-radius: 9999px;
        font-family: "VerityInter", system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans", sans-serif;
        font-size: 12px;
        font-weight: 500;
        letter-spacing: normal;
        cursor: pointer;
        user-select: none;
        white-space: nowrap;
        border: 1px solid transparent;
        transition: transform 120ms ease, filter 120ms ease, box-shadow 120ms ease;
      }
      .verity-badge:hover {
        transform: translateY(-1px);
        filter: brightness(1.04);
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
      }
      .verity-badge:active {
        transform: translateY(0);
        filter: brightness(0.98);
      }
      .verity-badge:focus-visible {
        outline: 2px solid #3b82f6;
        outline-offset: 2px;
      }
      @media (prefers-reduced-motion: reduce) {
        .verity-badge {
          transition: none !important;
          transform: none !important;
        }
      }

      /* LIGHT THEME PILL STYLES (Solid white base under tint) */
      .verity-badge.safe.v-light {
        color: #15803d;
        border-color: rgba(34, 197, 94, 0.28);
        background: linear-gradient(rgba(34, 197, 94, 0.11), rgba(34, 197, 94, 0.11)), #ffffff;
      }
      .verity-badge.suspicious.v-light {
        color: #b45309;
        border-color: rgba(245, 158, 11, 0.32);
        background: linear-gradient(rgba(245, 158, 11, 0.11), rgba(245, 158, 11, 0.11)), #ffffff;
      }
      .verity-badge.danger.v-light {
        color: #b91c1c;
        border-color: rgba(239, 68, 68, 0.30);
        background: linear-gradient(rgba(239, 68, 68, 0.11), rgba(239, 68, 68, 0.11)), #ffffff;
      }
      .verity-badge.checking.v-light {
        color: #71717a;
        border-color: rgba(161, 161, 170, 0.28);
        background: linear-gradient(90deg, #f4f4f5 0%, #e4e4e7 50%, #f4f4f5 100%), #ffffff;
        background-size: 200% 100%;
        animation: v-shimmer 1.5s infinite linear;
      }

      /* DARK THEME PILL STYLES (Solid near-black base under tint) */
      .verity-badge.safe.v-dark {
        color: #4ade80;
        border-color: rgba(74, 222, 128, 0.28);
        background: linear-gradient(rgba(74, 222, 128, 0.14), rgba(74, 222, 128, 0.14)), #09090b;
      }
      .verity-badge.suspicious.v-dark {
        color: #fbbf24;
        border-color: rgba(251, 191, 36, 0.32);
        background: linear-gradient(rgba(251, 191, 36, 0.14), rgba(251, 191, 36, 0.14)), #09090b;
      }
      .verity-badge.danger.v-dark {
        color: #f87171;
        border-color: rgba(248, 113, 113, 0.30);
        background: linear-gradient(rgba(248, 113, 113, 0.14), rgba(248, 113, 113, 0.14)), #09090b;
      }
      .verity-badge.checking.v-dark {
        color: #a1a1aa;
        border-color: rgba(113, 113, 122, 0.30);
        background: linear-gradient(90deg, #18181b 0%, #27272a 50%, #18181b 100%), #09090b;
        background-size: 200% 100%;
        animation: v-shimmer 1.5s infinite linear;
      }

      @keyframes v-shimmer {
        0% { background-position: 200% 0; }
        100% { background-position: -200% 0; }
      }
      @media (prefers-reduced-motion: reduce) {
        .verity-badge.checking.v-light,
        .verity-badge.checking.v-dark {
          animation: none !important;
          background-position: 0 0 !important;
        }
      }

      .v-icon {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
      }
    `;
  }

  createBadge(verdict = { state: 'checking' }, url = '') {
    ensureSearchFontLoaded().catch(() => {});

    const host = document.createElement('span');
    host.className = 'verity-search-indicator';
    host.style.all = 'initial';

    const shadow = host.attachShadow({ mode: 'open' });

    const style = document.createElement('style');
    style.textContent = this.badgeStyle;
    shadow.appendChild(style);

    const badge = document.createElement('div');
    badge.setAttribute('tabindex', '0');
    badge.setAttribute('role', 'button');
    badge.setAttribute('aria-haspopup', 'true');
    badge.setAttribute('aria-expanded', 'false');

    this.applyVerdictToBadge(badge, host, verdict, url);
    shadow.appendChild(badge);

    // Hover-intent and keyboard listeners
    badge.addEventListener('mouseenter', () => {
      popoverSingleton.scheduleOpen(badge, badge.__verityVerdict || verdict, badge.__verityUrl || url, 150);
    });
    badge.addEventListener('mouseleave', () => {
      popoverSingleton.scheduleClose(120);
    });
    badge.addEventListener('focus', () => {
      popoverSingleton.open(badge, badge.__verityVerdict || verdict, badge.__verityUrl || url);
    });
    badge.addEventListener('blur', () => {
      popoverSingleton.scheduleClose(120);
    });
    badge.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        if (popoverSingleton.isOpen && popoverSingleton.currentTarget === badge) {
          popoverSingleton.close();
        } else {
          popoverSingleton.open(badge, badge.__verityVerdict || verdict, badge.__verityUrl || url);
        }
      }
    });

    return host;
  }

  updateBadge(hostEl, verdict, url) {
    if (!hostEl || !hostEl.shadowRoot) return;
    const badge = hostEl.shadowRoot.querySelector('.verity-badge');
    if (!badge) return;
    this.applyVerdictToBadge(badge, hostEl, verdict, url);

    // If popover is actively open on this badge, re-render its content live
    if (popoverSingleton.isOpen && popoverSingleton.currentTarget === badge) {
      popoverSingleton.renderContent(verdict, url);
      popoverSingleton.positionPopover();
    }
  }

  applyVerdictToBadge(badge, host, verdict, url) {
    badge.__verityVerdict = verdict;
    badge.__verityUrl = url;

    const isDark = isHostDarkTheme();
    const themeClass = isDark ? 'v-dark' : 'v-light';
    const state = verdict.severity || verdict.state || 'safe';
    const score = verdict.score !== undefined ? verdict.score : (verdict.riskScore !== undefined ? verdict.riskScore : 0);

    let displayState = 'safe';
    let iconName = 'shield-check';
    let label = safeT('SEARCH_BADGE_SAFE');

    if (state === 'danger') {
      displayState = 'danger';
      iconName = 'shield-x';
      label = safeT('SEARCH_BADGE_DANGEROUS');
    } else if (state === 'caution' || state === 'suspicious') {
      displayState = 'suspicious';
      iconName = 'triangle-alert';
      label = safeT('SEARCH_BADGE_SUSPICIOUS');
    } else if (state === 'checking') {
      displayState = 'checking';
      iconName = 'info';
      label = safeT('SEARCH_BADGE_CHECKING');
    } else {
      // safe state
      if (score > 15) {
        displayState = 'suspicious';
        iconName = 'triangle-alert';
        label = safeT('SEARCH_BADGE_SUSPICIOUS');
      } else {
        displayState = 'safe';
        iconName = 'shield-check';
        label = safeT('SEARCH_BADGE_SAFE');
      }
    }

    badge.className = `verity-badge ${displayState} ${themeClass}`;
    badge.setAttribute('aria-label', safeT('SEARCH_BADGE_ARIA', { state: label }));

    host.setAttribute('data-state', displayState);
    host.setAttribute('data-score', String(score));
    if (url) host.setAttribute('data-url', url);

    badge.innerHTML = `
      <span class="v-icon">${safeIcon(iconName, { size: 14, strokeWidth: 1.8 })}</span>
      <span>${escapeHtml(label)}</span>
    `;
  }
}
