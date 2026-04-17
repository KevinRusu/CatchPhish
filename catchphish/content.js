/**
 * CatchPhish — Content Script
 * Injects warning banners into pages when phishing indicators are detected.
 */

(() => {
  let bannerElement = null;
  const BANNER_ID = 'catchphish-warning-banner';

  // ── Styles ───────────────────────────────────────────────────────────

  const STYLES = {
    CRITICAL: {
      bg: 'linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)',
      text: '#ffffff',
      border: '#991b1b',
      icon: '\u26a0\ufe0f',
      shake: true
    },
    HIGH: {
      bg: 'linear-gradient(135deg, #ea580c 0%, #c2410c 100%)',
      text: '#ffffff',
      border: '#9a3412',
      icon: '\u26a0\ufe0f',
      shake: true
    },
    MEDIUM: {
      bg: 'linear-gradient(135deg, #eab308 0%, #ca8a04 100%)',
      text: '#1a1a1a',
      border: '#a16207',
      icon: '\u26a0\ufe0f',
      shake: false
    }
  };

  // ── Banner Creation ──────────────────────────────────────────────────

  function createBanner(result) {
    const style = STYLES[result.level];
    if (!style) return null;

    const banner = document.createElement('div');
    banner.id = BANNER_ID;

    const message = result.level === 'MEDIUM'
      ? 'CatchPhish Alert: This URL has some suspicious characteristics. Be cautious.'
      : 'CatchPhish Warning: This URL has strong phishing indicators! Proceed with extreme caution.';

    banner.innerHTML = `
      <style>
        #${BANNER_ID} {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          z-index: 2147483647;
          background: ${style.bg};
          color: ${style.text};
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
          font-size: 14px;
          line-height: 1.5;
          padding: 12px 20px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
          box-shadow: 0 4px 12px rgba(0,0,0,0.3);
          border-bottom: 2px solid ${style.border};
          transform: translateY(-100%);
          animation: catchphish-slide-down 0.4s ease-out forwards${style.shake ? ', catchphish-shake 0.5s ease-in-out 0.4s' : ''};
          box-sizing: border-box;
        }

        #${BANNER_ID} * {
          box-sizing: border-box;
        }

        @keyframes catchphish-slide-down {
          from { transform: translateY(-100%); }
          to   { transform: translateY(0); }
        }

        @keyframes catchphish-shake {
          0%, 100% { transform: translateX(0); }
          10%, 30%, 50%, 70%, 90% { transform: translateX(-4px); }
          20%, 40%, 60%, 80% { transform: translateX(4px); }
        }

        #${BANNER_ID}-message {
          flex: 1;
          font-weight: 500;
        }

        #${BANNER_ID}-score {
          background: rgba(0,0,0,0.2);
          padding: 2px 10px;
          border-radius: 12px;
          font-weight: 700;
          font-size: 13px;
          white-space: nowrap;
        }

        #${BANNER_ID}-actions {
          display: flex;
          align-items: center;
          gap: 8px;
          flex-shrink: 0;
        }

        #${BANNER_ID}-details-btn {
          background: rgba(255,255,255,0.2);
          color: ${style.text};
          border: 1px solid rgba(255,255,255,0.3);
          padding: 4px 14px;
          border-radius: 6px;
          font-size: 13px;
          font-weight: 600;
          cursor: pointer;
          font-family: inherit;
          transition: background 0.2s;
        }
        #${BANNER_ID}-details-btn:hover {
          background: rgba(255,255,255,0.35);
        }

        #${BANNER_ID}-dismiss-btn {
          background: none;
          border: none;
          color: ${style.text};
          font-size: 20px;
          cursor: pointer;
          padding: 0 4px;
          line-height: 1;
          opacity: 0.8;
          transition: opacity 0.2s;
        }
        #${BANNER_ID}-dismiss-btn:hover {
          opacity: 1;
        }

        @media (max-width: 600px) {
          #${BANNER_ID} {
            flex-wrap: wrap;
            font-size: 13px;
            padding: 10px 14px;
          }
        }
      </style>
      <span id="${BANNER_ID}-message">${style.icon} ${message}</span>
      <span id="${BANNER_ID}-score">Score: ${result.score}/100 \u2022 ${result.level}</span>
      <span id="${BANNER_ID}-actions">
        <button id="${BANNER_ID}-details-btn">View Details</button>
        <button id="${BANNER_ID}-dismiss-btn">\u2715</button>
      </span>
    `;

    return banner;
  }

  // ── Banner Management ────────────────────────────────────────────────

  function removeBanner() {
    const existing = document.getElementById(BANNER_ID);
    if (existing) existing.remove();
    bannerElement = null;
  }

  function getDomainKey() {
    try {
      return new URL(window.location.href).hostname;
    } catch {
      return window.location.href;
    }
  }

  async function isDismissed(domain) {
    return new Promise((resolve) => {
      if (chrome.storage && chrome.storage.session) {
        chrome.storage.session.get(`dismissed_${domain}`, (data) => {
          resolve(!!data[`dismissed_${domain}`]);
        });
      } else {
        // Fallback: use sessionStorage
        resolve(sessionStorage.getItem(`catchphish_dismissed_${domain}`) === '1');
      }
    });
  }

  async function setDismissed(domain) {
    if (chrome.storage && chrome.storage.session) {
      await chrome.storage.session.set({ [`dismissed_${domain}`]: true });
    } else {
      sessionStorage.setItem(`catchphish_dismissed_${domain}`, '1');
    }
  }

  async function showBanner(result) {
    const domain = getDomainKey();

    // Check if already dismissed for this domain
    const dismissed = await isDismissed(domain);
    if (dismissed) return;

    // Remove any existing banner
    removeBanner();

    bannerElement = createBanner(result);
    if (!bannerElement) return;

    // Wait for body to be available
    function inject() {
      if (document.body) {
        document.body.prepend(bannerElement);

        // Bind events
        const dismissBtn = document.getElementById(`${BANNER_ID}-dismiss-btn`);
        if (dismissBtn) {
          dismissBtn.addEventListener('click', async () => {
            removeBanner();
            await setDismissed(domain);
          });
        }

        const detailsBtn = document.getElementById(`${BANNER_ID}-details-btn`);
        if (detailsBtn) {
          detailsBtn.addEventListener('click', () => {
            // Open popup by sending message to background
            chrome.runtime.sendMessage({ type: 'OPEN_POPUP' });
          });
        }
      } else {
        // Retry when body is available
        const observer = new MutationObserver(() => {
          if (document.body) {
            observer.disconnect();
            inject();
          }
        });
        observer.observe(document.documentElement, { childList: true });
      }
    }
    inject();
  }

  // ── Message Listener ─────────────────────────────────────────────────

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'CATCHPHISH_RESULT' && message.result) {
      const r = message.result;
      console.group('[CatchPhish] Warning banner triggered by background result');
      console.log('Domain  :', r.domain);
      console.log('Score   :', `${r.score}/100`);
      console.log('Level   :', r.level);
      console.log('Findings:', r.findings.map(f => f.description));
      console.groupEnd();
      showBanner(r);
    }
  });

  // ── Self-analyze on load ─────────────────────────────────────────────
  // Also run analysis from content script side in case background hasn't sent message yet

  if (typeof CatchPhish !== 'undefined') {
    console.log('[CatchPhish] Content script self-analyzing:', window.location.href);
    const result = CatchPhish.analyzeURL(window.location.href);
    console.log('[CatchPhish] Self-analysis result → level:', result.level, '| score:', result.score);
    if (result.level === 'MEDIUM' || result.level === 'HIGH' || result.level === 'CRITICAL') {
      // Small delay to let page render a bit first
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => showBanner(result));
      } else {
        showBanner(result);
      }
    }
  }

})();
