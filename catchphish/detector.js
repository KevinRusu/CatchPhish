/**
 * CatchPhish — Core Detection Engine
 * 17 heuristic checks for phishing URL detection.
 * No ML, no external APIs — everything runs locally.
 */

const CatchPhish = (() => {

  // ── Constants ──────────────────────────────────────────────────────────

  const SUSPICIOUS_TLDS = new Set([
    '.tk', '.xyz', '.buzz', '.ml', '.ga', '.cf', '.gq',
    '.pw', '.cc', '.icu', '.club', '.top', '.zip', '.mov'
  ]);

  const PHISHING_KEYWORDS = [
    'login', 'signin', 'sign-in', 'verify', 'account', 'password',
    'credential', 'suspend', 'authenticate', 'wallet', 'secure',
    'update', 'confirm', 'banking', 'billing', 'support', 'unlock'
  ];

  const IMPERSONATED_BRANDS = [
    'google', 'apple', 'microsoft', 'amazon', 'netflix', 'paypal',
    'facebook', 'instagram', 'twitter', 'linkedin', 'dropbox',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'yahoo',
    'outlook', 'icloud', 'github', 'steam', 'spotify'
  ];

  const URL_SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'j.mp', 'surl.li', 'rebrand.ly',
    'bl.ink', 'short.io', 'tiny.cc', 'cutt.ly'
  ]);

  const SUSPICIOUS_EXTENSIONS = new Set([
    '.exe', '.scr', '.zip', '.bat', '.cmd', '.ps1',
    '.msi', '.vbs', '.js', '.jar', '.apk'
  ]);

  const TYPOSQUAT_MAP = {
    'g00gle': 'google', 'go0gle': 'google', 'googl3': 'google', 'gooogle': 'google',
    'amaz0n': 'amazon', 'amazom': 'amazon', 'arnazon': 'amazon', 'amazn': 'amazon',
    'paypa1': 'paypal', 'paypai': 'paypal', 'payp4l': 'paypal', 'paypol': 'paypal',
    'faceb00k': 'facebook', 'facebok': 'facebook', 'faceboook': 'facebook',
    'micros0ft': 'microsoft', 'microsft': 'microsoft', 'rnicrosoft': 'microsoft',
    'netfllx': 'netflix', 'netf1ix': 'netflix', 'nettflix': 'netflix',
    'app1e': 'apple', 'appie': 'apple', 'àpple': 'apple',
    'lnstagram': 'instagram', 'instagran': 'instagram', 'instragram': 'instagram',
    'yah00': 'yahoo', 'yaho0': 'yahoo',
    'linkedln': 'linkedin', '1inkedin': 'linkedin',
    'dr0pbox': 'dropbox', 'dropb0x': 'dropbox',
    'twltter': 'twitter', 'tw1tter': 'twitter'
  };

  const REDIRECT_PARAMS = [
    'url', 'redirect', 'next', 'goto', 'return', 'returnto',
    'redir', 'destination', 'target', 'continue', 'forward'
  ];

  // ── Helpers ────────────────────────────────────────────────────────────

  function getDomain(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch {
      return '';
    }
  }

  function getRegistrableDomain(hostname) {
    const parts = hostname.split('.');
    if (parts.length <= 2) return hostname;
    return parts.slice(-2).join('.');
  }

  function shannonEntropy(str) {
    if (!str) return 0;
    const freq = {};
    for (const ch of str) {
      freq[ch] = (freq[ch] || 0) + 1;
    }
    const len = str.length;
    let entropy = 0;
    for (const ch in freq) {
      const p = freq[ch] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  // ── Individual Heuristics ──────────────────────────────────────────────

  function checkIPAddress(parsed) {
    const hostname = parsed.hostname;
    // IPv4
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      return { id: 'ip_address', score: 30, description: 'URL uses a raw IP address instead of a domain name' };
    }
    // IPv6
    if (hostname.startsWith('[') || /^[0-9a-f:]+$/i.test(hostname)) {
      return { id: 'ip_address', score: 30, description: 'URL uses a raw IPv6 address' };
    }
    return null;
  }

  function checkSuspiciousTLD(parsed) {
    const hostname = parsed.hostname.toLowerCase();
    const lastDot = hostname.lastIndexOf('.');
    if (lastDot === -1) return null;
    const tld = hostname.slice(lastDot);
    if (SUSPICIOUS_TLDS.has(tld)) {
      return { id: 'suspicious_tld', score: 15, description: `Suspicious TLD: ${tld}` };
    }
    return null;
  }

  function checkDomainLength(parsed) {
    if (parsed.hostname.length > 50) {
      return { id: 'domain_length', score: 10, description: `Domain is unusually long (${parsed.hostname.length} chars)` };
    }
    return null;
  }

  function checkSubdomainDepth(parsed) {
    const parts = parsed.hostname.split('.');
    const subdomainCount = parts.length - 2; // minus registrable domain parts
    if (subdomainCount > 4) {
      return { id: 'subdomain_depth', score: 15, description: `Excessive subdomain depth (${subdomainCount} levels)` };
    }
    return null;
  }

  function checkAtSymbol(url) {
    // Check for @ before the hostname part (used to obscure real host)
    const withoutProtocol = url.replace(/^https?:\/\//, '');
    const pathStart = withoutProtocol.indexOf('/');
    const hostPart = pathStart > -1 ? withoutProtocol.slice(0, pathStart) : withoutProtocol;
    if (hostPart.includes('@')) {
      return { id: 'at_symbol', score: 25, description: 'URL contains @ symbol to obscure the real host' };
    }
    return null;
  }

  function checkDoubleSlashes(parsed) {
    const path = parsed.pathname;
    if (/\/\//.test(path)) {
      return { id: 'double_slashes', score: 10, description: 'Double slashes in URL path (redirect manipulation)' };
    }
    return null;
  }

  function checkNoHTTPS(parsed) {
    if (parsed.protocol === 'http:') {
      return { id: 'no_https', score: 10, description: 'Connection is not encrypted (HTTP instead of HTTPS)' };
    }
    return null;
  }

  function checkPhishingKeywords(url) {
    const lower = url.toLowerCase();
    const found = [];
    for (const kw of PHISHING_KEYWORDS) {
      if (lower.includes(kw)) {
        found.push(kw);
      }
    }
    if (found.length > 0) {
      const score = Math.min(found.length * 5, 25);
      return { id: 'phishing_keywords', score, description: `Phishing keywords detected: ${found.join(', ')}` };
    }
    return null;
  }

  function checkBrandImpersonation(parsed) {
    const hostname = parsed.hostname.toLowerCase();
    const registrable = getRegistrableDomain(hostname);
    const fullUrl = parsed.href.toLowerCase();

    for (const brand of IMPERSONATED_BRANDS) {
      // Check if brand appears in subdomain or path but NOT as the registrable domain
      const isRealDomain = registrable.startsWith(brand + '.') || registrable === brand + '.' + registrable.split('.').pop();
      if (!isRealDomain && (hostname.includes(brand) || parsed.pathname.toLowerCase().includes(brand))) {
        // Verify it's not the real domain
        const registrableName = registrable.split('.')[0];
        if (registrableName !== brand) {
          return { id: 'brand_impersonation', score: 25, description: `Possible impersonation of "${brand}" — real domain is ${registrable}` };
        }
      }
    }
    return null;
  }

  function checkURLShortener(parsed) {
    const hostname = parsed.hostname.toLowerCase();
    if (URL_SHORTENERS.has(hostname)) {
      return { id: 'url_shortener', score: 20, description: `URL shortener detected: ${hostname}` };
    }
    return null;
  }

  function checkPunycode(parsed) {
    const hostname = parsed.hostname.toLowerCase();
    if (hostname.includes('xn--')) {
      return { id: 'punycode', score: 20, description: 'Punycode/homograph attack — internationalized domain name with xn-- prefix' };
    }
    return null;
  }

  function checkExcessiveLength(url) {
    if (url.length > 200) {
      return { id: 'excessive_length', score: 10, description: `URL is excessively long (${url.length} chars)` };
    }
    return null;
  }

  function checkSuspiciousExtensions(parsed) {
    const path = parsed.pathname.toLowerCase();
    for (const ext of SUSPICIOUS_EXTENSIONS) {
      if (path.endsWith(ext)) {
        return { id: 'suspicious_extension', score: 20, description: `Suspicious file extension in URL: ${ext}` };
      }
    }
    return null;
  }

  function checkShannonEntropy(parsed) {
    // Calculate entropy of the hostname
    const hostname = parsed.hostname;
    const entropy = shannonEntropy(hostname);
    if (entropy > 4.5) {
      return { id: 'high_entropy', score: 10, description: `High Shannon entropy (${entropy.toFixed(2)}) suggests randomized domain` };
    }
    return null;
  }

  function checkDataURI(url) {
    if (url.trim().toLowerCase().startsWith('data:')) {
      return { id: 'data_uri', score: 35, description: 'Data URI scheme detected — can embed malicious content' };
    }
    return null;
  }

  function checkRedirectParams(parsed) {
    const params = parsed.search.toLowerCase();
    const found = [];
    for (const p of REDIRECT_PARAMS) {
      if (params.includes(p + '=')) {
        found.push(p);
      }
    }
    if (found.length > 0) {
      return { id: 'redirect_params', score: 15, description: `Redirect parameters detected: ${found.join(', ')}` };
    }
    return null;
  }

  function checkTyposquatting(parsed) {
    const hostname = parsed.hostname.toLowerCase();
    const path = parsed.pathname.toLowerCase();
    const text = hostname + path;
    for (const [typo, real] of Object.entries(TYPOSQUAT_MAP)) {
      if (text.includes(typo)) {
        return { id: 'typosquatting', score: 20, description: `Possible typosquatting: "${typo}" looks like "${real}"` };
      }
    }
    return null;
  }

  // ── Main Analysis ──────────────────────────────────────────────────────

  function analyzeURL(url) {
    if (!url || typeof url !== 'string') {
      return { url, score: 0, level: 'SAFE', color: 'green', findings: [], isHTTPS: false, domain: '' };
    }

    // Handle data URIs specially
    const dataCheck = checkDataURI(url);
    if (dataCheck) {
      return {
        url,
        score: Math.min(dataCheck.score, 100),
        level: 'CRITICAL',
        color: 'red',
        findings: [dataCheck],
        isHTTPS: false,
        domain: 'data:'
      };
    }

    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return { url, score: 0, level: 'SAFE', color: 'green', findings: [], isHTTPS: false, domain: '' };
    }

    // Skip chrome://, about:, etc.
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { url, score: 0, level: 'SAFE', color: 'green', findings: [], isHTTPS: parsed.protocol === 'https:', domain: parsed.hostname };
    }

    const findings = [];
    const checks = [
      checkIPAddress(parsed),
      checkSuspiciousTLD(parsed),
      checkDomainLength(parsed),
      checkSubdomainDepth(parsed),
      checkAtSymbol(url),
      checkDoubleSlashes(parsed),
      checkNoHTTPS(parsed),
      checkPhishingKeywords(url),
      checkBrandImpersonation(parsed),
      checkURLShortener(parsed),
      checkPunycode(parsed),
      checkExcessiveLength(url),
      checkSuspiciousExtensions(parsed),
      checkShannonEntropy(parsed),
      checkRedirectParams(parsed),
      checkTyposquatting(parsed)
    ];

    for (const result of checks) {
      if (result) findings.push(result);
    }

    const rawScore = findings.reduce((sum, f) => sum + f.score, 0);
    const score = Math.min(rawScore, 100);

    let level, color;
    if (score >= 70)      { level = 'CRITICAL'; color = 'red'; }
    else if (score >= 45) { level = 'HIGH';     color = 'orange'; }
    else if (score >= 25) { level = 'MEDIUM';   color = 'yellow'; }
    else if (score >= 10) { level = 'LOW';      color = 'blue'; }
    else                  { level = 'SAFE';     color = 'green'; }

    return {
      url,
      domain: parsed.hostname,
      isHTTPS: parsed.protocol === 'https:',
      score,
      level,
      color,
      findings
    };
  }

  // ── Public API ─────────────────────────────────────────────────────────

  return { analyzeURL };

})();

// Export for use in service worker (importScripts) and content scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = CatchPhish;
}
