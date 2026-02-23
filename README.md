# 🛡️ Phishing Detection Suite

> **Real-time phishing detection tools** — A comprehensive suite for identifying and blocking phishing attacks using heuristic analysis.

[![Under Development](https://img.shields.io/badge/Status-Under%20Development-yellow)](https://github.com/OffensiveSage/CatchPhish)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-green.svg)](https://www.python.org/)
[![Manifest V3](https://img.shields.io/badge/Chrome-Manifest%20V3-brightgreen)](https://developer.chrome.com/docs/extensions/mv3/)

---

## 📦 What's Inside

This repository contains **two complementary phishing detection tools**:

### 1. **PhishGuard** — Python CLI Tool
A command-line phishing URL analyzer powered by 17+ heuristic detection rules. Perfect for security researchers, pentesters, and automated scanning.

**Features:**
- 🔍 **17 heuristic rules** for URL analysis
- 🎯 **Risk scoring** from 0-100 with color-coded output
- 📊 **Detailed reports** showing all matched indicators
- 🚀 **Zero dependencies** — pure Python standard library
- ⚡ **Batch processing** — analyze multiple URLs from file

[→ View PhishGuard Documentation](files/README.md)

### 2. **CatchPhish** — Chrome Extension
A real-time browser extension that passively monitors every URL you visit, with instant visual warnings for suspicious sites.

**Features:**
- 🛡️ **Passive monitoring** — automatic URL analysis as you browse
- 🚨 **Visual warnings** — in-page banners for risky URLs
- 🎨 **Color-coded badges** — green/blue/yellow/orange/red risk levels
- 🔒 **100% local** — no external API calls, complete privacy
- 📊 **Detailed popup** — score breakdown and findings report

[→ View CatchPhish Documentation](catchphish/README.md)

---

## 🚧 Development Status

This project is **currently under active development**. Features being worked on:

- [ ] Machine learning model integration
- [ ] Real-time threat intelligence feeds
- [ ] Firefox extension port
- [ ] API endpoint for programmatic access
- [ ] Browser history scanning utility
- [ ] Improved typosquatting detection

---

## 🚀 Quick Start

### PhishGuard (Python)

```bash
# Navigate to the files directory
cd files

# Install dependencies (minimal)
pip install -r requirements.txt

# Analyze a single URL
python phishguard.py https://example.com

# Batch analyze from file
python phishguard.py sample_urls.txt

# Run tests
python test_phishguard.py
```

### CatchPhish (Chrome Extension)

```bash
# 1. Open Chrome and go to chrome://extensions/
# 2. Enable "Developer mode"
# 3. Click "Load unpacked"
# 4. Select the catchphish/ folder
# 5. Start browsing — the extension monitors automatically
```

---

## 📂 Repository Structure

```
.
├── files/                  # PhishGuard Python CLI tool
│   ├── phishguard.py      # Main detection engine
│   ├── test_phishguard.py # Test suite
│   ├── requirements.txt   # Python dependencies
│   ├── sample_urls.txt    # Sample URLs for testing
│   └── README.md          # PhishGuard documentation
│
├── catchphish/            # CatchPhish Chrome extension
│   ├── manifest.json      # Extension manifest (MV3)
│   ├── background.js      # Service worker
│   ├── detector.js        # Detection engine
│   ├── content.js         # Warning banner injection
│   ├── popup.html/js/css  # Extension popup UI
│   ├── icons/             # Extension icons
│   └── README.md          # CatchPhish documentation
│
└── README.md              # This file
```

---

## 🎯 Detection Rules

Both tools share the same **17 heuristic detection rules**:

| Rule | Score | Description |
|------|-------|-------------|
| IP Address URL | +30 | Raw IP instead of domain |
| Suspicious TLD | +15 | Risky TLDs (.tk, .xyz, .buzz, etc.) |
| Domain Length | +10 | Domain exceeds 50 characters |
| Subdomain Depth | +15 | More than 4 subdomain levels |
| @ Symbol | +25 | URL contains @ to obscure host |
| No HTTPS | +10 | Missing TLS encryption |
| Phishing Keywords | +5 each | login, verify, account, etc. |
| Brand Impersonation | +25 | Known brands in wrong context |
| URL Shortener | +20 | bit.ly, tinyurl.com, etc. |
| Punycode | +20 | Internationalized domain (xn--) |
| High Entropy | +10 | Randomized-looking domain |
| Data URI | +35 | data: scheme (potential malware) |
| Redirect Parameters | +15 | url=, redirect=, next= in query |
| Typosquatting | +20 | g00gle, amaz0n, paypa1, etc. |

---

## 🛠️ Tech Stack

**PhishGuard:**
- Python 3.8+
- Standard library only (urllib, re)
- pytest for testing

**CatchPhish:**
- Vanilla JavaScript
- Chrome Manifest V3
- Chrome Extensions API
- Zero build tools, zero dependencies

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

## 👨‍💻 Author

**Eshwar Desetty**

🔗 GitHub: [@OffensiveSage](https://github.com/OffensiveSage)  
📧 Email: [Your Email Here]  
💼 LinkedIn: [Your LinkedIn URL]  

---

## 🤝 Contributing

This project is under development. Contributions, issues, and feature requests are welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## ⚠️ Disclaimer

This tool is for **educational and research purposes only**. The heuristic detection rules may produce false positives or false negatives. Always verify suspicious URLs through multiple sources before taking action.

---

<div align="center">

**Built with 🛡️ by [Eshwar Desetty](https://github.com/OffensiveSage)**

*Protecting users from phishing attacks, one URL at a time.*

</div>
