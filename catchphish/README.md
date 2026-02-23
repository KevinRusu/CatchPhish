# CatchPhish

**Real-time phishing URL detector** — a Chrome extension that passively analyzes every URL you visit using heuristic-based checks. No machine learning, no external APIs, no data leaves your browser.

![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-blue?logo=googlechrome)
![Manifest V3](https://img.shields.io/badge/Manifest-V3-green)
![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow)

<!-- Screenshot placeholder: add a screenshot of the extension popup here -->
<!-- ![CatchPhish Screenshot](screenshot.png) -->

## How It Works

CatchPhish runs **entirely in your browser** as a passive background monitor. When you navigate to any URL, the extension:

1. **Analyzes the URL** against 17 heuristic detection rules
2. **Scores** the URL from 0–100 based on matched indicators
3. **Updates the extension badge** with a color-coded risk level
4. **Injects a warning banner** into the page for medium, high, and critical risk URLs
5. **Shows a detailed report** when you click the extension icon

No data is ever sent to any external server. Everything runs locally using vanilla JavaScript.

## Risk Levels

| Score   | Level      | Badge  | Action                        |
|---------|------------|--------|-------------------------------|
| 0–9     | SAFE       | Green  | No action                     |
| 10–24   | LOW        | Blue   | Badge indicator only          |
| 25–44   | MEDIUM     | Yellow | Yellow warning banner         |
| 45–69   | HIGH       | Orange | Orange banner with shake      |
| 70–100  | CRITICAL   | Red    | Red banner with shake         |

## Detection Rules

| #  | Rule                    | Score  | Description                                              |
|----|-------------------------|--------|----------------------------------------------------------|
| 1  | IP Address URL          | +30    | Raw IP address instead of domain name                    |
| 2  | Suspicious TLD          | +15    | TLDs like .tk, .xyz, .buzz, .ml, .ga, .cf, .zip, etc.   |
| 3  | Domain Length            | +10    | Domain name exceeds 50 characters                        |
| 4  | Subdomain Depth         | +15    | More than 4 subdomain levels                             |
| 5  | @ Symbol                | +25    | URL contains @ to obscure the real host                  |
| 6  | Double Slashes in Path  | +10    | `//` in the URL path (redirect manipulation)             |
| 7  | No HTTPS                | +10    | Missing TLS encryption                                   |
| 8  | Phishing Keywords       | +5 ea  | login, verify, account, password, etc. (max +25)         |
| 9  | Brand Impersonation     | +25    | Known brands in subdomain/path but not the real domain   |
| 10 | URL Shortener           | +20    | bit.ly, tinyurl.com, t.co, goo.gl, etc.                 |
| 11 | Punycode/Homograph      | +20    | xn-- prefix indicating internationalized domain          |
| 12 | Excessive URL Length     | +10    | URL exceeds 200 characters                               |
| 13 | Suspicious Extensions   | +20    | .exe, .scr, .zip, .bat, .cmd, .ps1 in path              |
| 14 | Shannon Entropy         | +10    | High entropy (>4.5) suggests randomized domain           |
| 15 | Data URI                | +35    | data: scheme can embed malicious content                 |
| 16 | Redirect Parameters     | +15    | url=, redirect=, next=, goto= in query string            |
| 17 | Typosquatting           | +20    | g00gle, amaz0n, paypa1, micros0ft, etc.                  |

## Installation

1. Clone or download this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable **Developer mode** (toggle in the top-right corner)
4. Click **Load unpacked**
5. Select the `catchphish/` directory
6. The CatchPhish shield icon will appear in your toolbar

## Features

- **Passive monitoring** — analyzes URLs as you browse, no manual action needed
- **Color-coded badge** — green/blue/yellow/orange/red risk indicator on the extension icon
- **Warning banners** — animated in-page warnings for suspicious URLs
- **Detailed popup report** — score breakdown, HTTPS status, domain info, and all findings
- **Dismissible warnings** — banners can be dismissed per domain for the session
- **Privacy first** — zero external API calls, zero data collection, everything runs locally

## Tech Stack

- **Vanilla JavaScript** — no frameworks, no build step
- **Chrome Manifest V3** — modern extension architecture
- **Zero dependencies** — no npm, no bundlers, nothing external
- **Content Scripts** — for in-page warning banners
- **Service Worker** — for background URL analysis
- **Chrome Storage API** — for results and dismissal state

## Project Structure

```
catchphish/
├── manifest.json      # MV3 manifest
├── background.js      # Service worker — URL analysis on tab updates
├── content.js         # Content script — warning banner injection
├── detector.js        # Core detection engine (17 heuristics)
├── popup.html         # Extension popup UI
├── popup.js           # Popup rendering logic
├── popup.css          # Dark theme styling
├── icons/             # Extension icons
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
└── README.md          # This file
```

## License

MIT License — see [LICENSE](LICENSE) for details.
