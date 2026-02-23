/**
 * CatchPhish — Popup Logic
 * Fetches analysis results from background and renders the report.
 */

const COLORS = {
  green:  '#22c55e',
  blue:   '#3b82f6',
  yellow: '#eab308',
  orange: '#f97316',
  red:    '#ef4444'
};

const RISK_CLASSES = {
  SAFE:     'risk-safe',
  LOW:      'risk-low',
  MEDIUM:   'risk-medium',
  HIGH:     'risk-high',
  CRITICAL: 'risk-critical'
};

// ── DOM Elements ─────────────────────────────────────────────────────────

const urlEl        = document.getElementById('current-url');
const scoreVal     = document.getElementById('score-value');
const scoreArc     = document.getElementById('score-arc');
const riskBadge    = document.getElementById('risk-badge');
const httpsStatus  = document.getElementById('https-status');
const domainVal    = document.getElementById('domain-value');
const findingsCount= document.getElementById('findings-count');
const findingsList = document.getElementById('findings-list');
const findingsToggle = document.getElementById('findings-toggle');
const toggleArrow  = document.getElementById('toggle-arrow');
const findingEmpty = document.getElementById('finding-empty');

// ── Render Result ────────────────────────────────────────────────────────

function renderResult(result) {
  if (!result) {
    urlEl.textContent = 'Unable to analyze this page';
    return;
  }

  // URL
  const displayUrl = result.url.length > 120 ? result.url.slice(0, 120) + '...' : result.url;
  urlEl.textContent = displayUrl;

  // Domain
  domainVal.textContent = result.domain || '—';

  // Score ring
  const color = COLORS[result.color] || COLORS.green;
  const circumference = 2 * Math.PI * 52; // r=52
  const offset = circumference - (result.score / 100) * circumference;

  scoreArc.style.stroke = color;
  scoreArc.style.strokeDashoffset = offset;
  scoreArc.style.transition = 'stroke-dashoffset 0.8s ease-out, stroke 0.3s';

  scoreVal.textContent = result.score;
  scoreVal.style.color = color;

  // Risk badge
  riskBadge.textContent = result.level;
  riskBadge.className = 'risk-badge ' + (RISK_CLASSES[result.level] || 'risk-safe');

  // HTTPS status
  if (result.isHTTPS) {
    httpsStatus.innerHTML = '<span class="https-icon">&#x2705;</span><span class="https-text">HTTPS Secured</span>';
  } else {
    httpsStatus.innerHTML = '<span class="https-icon">&#x274c;</span><span class="https-text">Not HTTPS</span>';
  }

  // Findings
  findingsCount.textContent = result.findings.length;

  if (result.findings.length === 0) {
    findingEmpty.style.display = 'block';
    findingEmpty.textContent = 'No issues detected.';
  } else {
    findingEmpty.style.display = 'none';

    // Sort findings by score (highest first)
    const sorted = [...result.findings].sort((a, b) => b.score - a.score);

    for (const finding of sorted) {
      const item = document.createElement('div');
      item.className = 'finding-item';

      let scoreClass = 'low';
      if (finding.score >= 20) scoreClass = 'high';
      else if (finding.score >= 10) scoreClass = 'medium';

      item.innerHTML = `
        <span class="finding-desc">${escapeHtml(finding.description)}</span>
        <span class="finding-score ${scoreClass}">+${finding.score}</span>
      `;
      findingsList.appendChild(item);
    }

    // Auto-expand findings if there are issues
    findingsList.classList.add('open');
    toggleArrow.classList.add('open');
  }

  // Update findings count badge color
  if (result.findings.length > 0) {
    findingsCount.style.background = color;
    findingsCount.style.color = '#fff';
  }
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ── Toggle Findings ──────────────────────────────────────────────────────

findingsToggle.addEventListener('click', () => {
  findingsList.classList.toggle('open');
  toggleArrow.classList.toggle('open');
});

// ── Init ─────────────────────────────────────────────────────────────────

async function init() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab || !tab.url) {
      urlEl.textContent = 'No active tab';
      return;
    }

    // Try to get stored result first
    const stored = await chrome.storage.local.get(`result_${tab.id}`);
    let result = stored[`result_${tab.id}`];

    // If no stored result, analyze directly
    if (!result) {
      result = CatchPhish.analyzeURL(tab.url);
    }

    renderResult(result);
  } catch (err) {
    urlEl.textContent = 'Error analyzing page';
    console.error('CatchPhish popup error:', err);
  }
}

init();
