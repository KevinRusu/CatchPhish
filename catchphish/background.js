/**
 * CatchPhish — Background Service Worker
 * Monitors tab navigation, runs URL analysis, updates badge, and notifies content scripts.
 */

importScripts('detector.js');

// ── Badge Color Map ──────────────────────────────────────────────────────

const BADGE_COLORS = {
  green:  '#22c55e',
  blue:   '#3b82f6',
  yellow: '#eab308',
  orange: '#f97316',
  red:    '#ef4444'
};

const BADGE_TEXT = {
  SAFE:     '',
  LOW:      'LOW',
  MEDIUM:   'MED',
  HIGH:     'HIGH',
  CRITICAL: '!!!'
};

// ── Tab Analysis ─────────────────────────────────────────────────────────

async function analyzeTab(tabId, url) {
  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') ||
      url.startsWith('about:') || url.startsWith('edge://') || url.startsWith('brave://')) {
    // Reset badge for internal pages
    chrome.action.setBadgeText({ tabId, text: '' });
    return;
  }

  const result = CatchPhish.analyzeURL(url);

  // Store result so popup and content script can access it
  await chrome.storage.local.set({ [`result_${tabId}`]: result });

  // Update badge
  chrome.action.setBadgeText({ tabId, text: BADGE_TEXT[result.level] || '' });
  chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[result.color] || '#22c55e' });

  // Notify content script to show/hide warning banner
  if (result.level === 'MEDIUM' || result.level === 'HIGH' || result.level === 'CRITICAL') {
    try {
      await chrome.tabs.sendMessage(tabId, {
        type: 'CATCHPHISH_RESULT',
        result
      });
    } catch {
      // Content script may not be ready yet — that's ok
    }
  }
}

// ── Event Listeners ──────────────────────────────────────────────────────

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    analyzeTab(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab.url) {
      analyzeTab(tab.id, tab.url);
    }
  } catch {
    // Tab may have been closed
  }
});

// Listen for requests from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_RESULT') {
    chrome.storage.local.get(`result_${message.tabId}`, (data) => {
      sendResponse(data[`result_${message.tabId}`] || null);
    });
    return true; // async response
  }

  if (message.type === 'ANALYZE_URL') {
    const result = CatchPhish.analyzeURL(message.url);
    sendResponse(result);
    return true;
  }
});

// Clean up stored results when tabs close
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`result_${tabId}`);
});
