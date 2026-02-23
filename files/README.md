# 🛡️ PhishGuard

**A lightweight, ML-free phishing URL detector using heuristic-based analysis.**

PhishGuard scores URLs against 17 security heuristics to detect phishing attempts — no machine learning, no API keys, no external dependencies. Just pure Python.

## 🎯 Why?

Most phishing detection tools rely on ML models or third-party APIs. PhishGuard takes a different approach: transparent, rule-based analysis that's fast, offline-capable, and easy to understand. Every finding is explainable.

## 🔍 Detection Heuristics

| # | Check | Description |
|---|-------|-------------|
| 1 | IP Address URLs | Flags raw IP addresses instead of domain names |
| 2 | Suspicious TLDs | Detects abuse-prone TLDs (.tk, .xyz, .buzz, etc.) |
| 3 | Domain Length | Flags unusually long domains (>50 chars) |
| 4 | Subdomain Depth | Excessive subdomain nesting (>4 levels) |
| 5 | @ Symbol | Detects URL obfuscation via `@` |
| 6 | Double Slashes | Path-based redirect manipulation |
| 7 | HTTPS Check | Missing TLS encryption |
| 8 | Phishing Keywords | login, verify, account, password, etc. |
| 9 | Brand Impersonation | Detects brand names in suspicious positions |
| 10 | URL Shorteners | Flags bit.ly, tinyurl.com, etc. |
| 11 | Punycode/Homograph | Internationalized domain attacks |
| 12 | URL Length | Excessively long URLs (>200 chars) |
| 13 | Suspicious Extensions | .exe, .scr, .bat in URL paths |
| 14 | Shannon Entropy | Randomized/generated URL detection |
| 15 | Data URIs | Embedded malicious content |
| 16 | Redirect Parameters | Open redirect indicators |
| 17 | Typosquatting | g00gle, amaz0n, paypa1, etc. |

## 🚀 Quick Start

```bash
# Analyze a single URL
python phishguard.py "http://g00gle-login.tk/verify"

# Analyze URLs from a file
python phishguard.py -f sample_urls.txt

# JSON output (for piping to other tools)
python phishguard.py "http://evil.com/login" --json
```

## 📊 Example Output

```
============================================================
  PhishGuard — Phishing URL Analysis Report
============================================================
  URL:     http://g00gle-login.tk/verify-account
  Domain:  g00gle-login.tk
  HTTPS:   ❌ No
  Score:   75/100
  Verdict: 🔴 CRITICAL
------------------------------------------------------------
  Findings:
    1. [suspicious_tld] (+15) Uses suspicious TLD: .tk
    2. [no_https] (+10) URL uses HTTP (no encryption)
    3. [typosquatting] (+30) Possible typosquatting of 'google' (found 'g00gle')
    4. [phishing_keywords] (+10) Contains phishing keywords: verify
    5. [high_entropy] (+10) High entropy (3.85) suggests randomized/generated URL
============================================================
```

## 🧪 Run Tests

```bash
python -m pytest test_phishguard.py -v
```

## 📁 Use as a Module

```python
from phishguard import analyze_url

result = analyze_url("http://paypal.com.evil.xyz/login")

print(result.risk_score)    # 0-100
print(result.risk_level)    # 🔴 CRITICAL / 🟠 HIGH / 🟡 MEDIUM / 🔵 LOW / 🟢 SAFE
print(result.findings)      # List of Finding objects

# Export to dict/JSON
print(result.to_dict())
```

## 🏗️ Project Structure

```
phishguard/
├── phishguard.py        # Core analysis engine (zero dependencies)
├── test_phishguard.py   # Unit tests
├── sample_urls.txt      # Test URLs (mix of phishing + legit)
├── requirements.txt     # No external dependencies!
├── LICENSE              # MIT License
└── README.md
```

## 📌 Risk Scoring

| Score | Level | Meaning |
|-------|-------|---------|
| 0-9 | 🟢 SAFE | No suspicious indicators |
| 10-24 | 🔵 LOW | Minor concerns, likely safe |
| 25-44 | 🟡 MEDIUM | Some red flags, proceed with caution |
| 45-69 | 🟠 HIGH | Multiple indicators, likely phishing |
| 70-100 | 🔴 CRITICAL | Strong phishing signals detected |

## 🔮 Future Ideas

- [ ] Browser extension integration
- [ ] Real-time URL monitoring via clipboard
- [ ] VirusTotal API enrichment (optional)
- [ ] WHOIS age check for newly registered domains
- [ ] Levenshtein distance for smarter typosquatting detection

## 📄 License

MIT — use it, fork it, break it, improve it.
