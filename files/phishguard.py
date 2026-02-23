"""
PhishGuard - Heuristic-Based Phishing URL Detector
====================================================
A lightweight, ML-free phishing URL classifier that uses
rule-based heuristics to score URLs for phishing risk.

Author: Eshwar
License: MIT
"""

import re
import math
import argparse
import json
import sys
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass, field, asdict
from typing import Optional


# ── Suspicious patterns & data ──────────────────────────────────────────────

TRUSTED_TLDS = {".com", ".org", ".net", ".edu", ".gov", ".mil", ".int"}

SUSPICIOUS_TLDS = {
    ".zip", ".mov", ".top", ".xyz", ".buzz", ".tk", ".ml",
    ".ga", ".cf", ".gq", ".pw", ".cc", ".icu", ".club",
    ".work", ".surf", ".rest", ".fit", ".cam",
}

PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "account", "update",
    "secure", "banking", "confirm", "password", "credential",
    "suspend", "alert", "authenticate", "wallet", "paypal",
    "appleid", "microsoft", "amazon", "netflix", "facebook",
    "instagram", "support", "helpdesk", "recover", "unlock",
]

BRAND_IMPERSONATION = [
    "google", "apple", "microsoft", "amazon", "netflix", "facebook",
    "instagram", "paypal", "chase", "wellsfargo", "bankofamerica",
    "dropbox", "linkedin", "twitter", "whatsapp", "telegram",
    "coinbase", "binance", "metamask",
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "bl.ink", "short.io",
}

SUSPICIOUS_EXTENSIONS = {".exe", ".scr", ".zip", ".js", ".bat", ".cmd", ".ps1", ".vbs"}


# ── Data classes ────────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule: str
    description: str
    score: int  # positive = more suspicious


@dataclass
class AnalysisResult:
    url: str
    risk_score: int = 0
    risk_level: str = "Unknown"
    findings: list = field(default_factory=list)
    parsed_domain: str = ""
    is_https: bool = False

    def to_dict(self):
        return {
            "url": self.url,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "is_https": self.is_https,
            "parsed_domain": self.parsed_domain,
            "findings": [asdict(f) for f in self.findings],
        }


# ── Heuristic checks ───────────────────────────────────────────────────────

def check_ip_address(parsed: urlparse) -> Optional[Finding]:
    """Flag URLs using raw IP addresses instead of domains."""
    hostname = parsed.hostname or ""
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$|"           # IPv4
        r"^0x[0-9a-fA-F]+$|"                    # Hex-encoded IP
        r"^\d+$"                                 # Decimal IP
    )
    if ip_pattern.match(hostname):
        return Finding("ip_address", f"URL uses IP address ({hostname}) instead of domain name", 30)
    return None


def check_suspicious_tld(parsed: urlparse) -> Optional[Finding]:
    """Check for TLDs commonly abused in phishing."""
    hostname = parsed.hostname or ""
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            return Finding("suspicious_tld", f"Uses suspicious TLD: {tld}", 15)
    return None


def check_domain_length(parsed: urlparse) -> Optional[Finding]:
    """Excessively long domains are suspicious."""
    hostname = parsed.hostname or ""
    if len(hostname) > 50:
        return Finding("long_domain", f"Unusually long domain ({len(hostname)} chars)", 10)
    return None


def check_subdomain_depth(parsed: urlparse) -> Optional[Finding]:
    """Too many subdomains can indicate phishing."""
    hostname = parsed.hostname or ""
    parts = hostname.split(".")
    if len(parts) > 4:
        return Finding("deep_subdomains", f"Excessive subdomain depth ({len(parts)} levels)", 15)
    return None


def check_at_symbol(url: str) -> Optional[Finding]:
    """@ in URL can be used to obscure the real destination."""
    if "@" in url:
        return Finding("at_symbol", "URL contains '@' — may redirect to a different host", 25)
    return None


def check_double_slashes(parsed: urlparse) -> Optional[Finding]:
    """Double slashes in path (not protocol) can indicate redirect tricks."""
    path = parsed.path or ""
    if "//" in path:
        return Finding("double_slash", "Path contains '//' — possible redirect manipulation", 10)
    return None


def check_https(parsed: urlparse) -> Optional[Finding]:
    """HTTP without TLS is a minor flag."""
    if parsed.scheme == "http":
        return Finding("no_https", "URL uses HTTP (no encryption)", 10)
    return None


def check_phishing_keywords(parsed: urlparse) -> list[Finding]:
    """Check for phishing-related keywords in the URL."""
    url_lower = (parsed.geturl()).lower()
    findings = []
    matched = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
    if matched:
        findings.append(Finding(
            "phishing_keywords",
            f"Contains phishing keywords: {', '.join(matched[:5])}",
            min(len(matched) * 5, 25)
        ))
    return findings


def check_brand_impersonation(parsed: urlparse) -> list[Finding]:
    """Detect brand names in subdomains or paths (not in the registrable domain)."""
    hostname = parsed.hostname or ""
    path_lower = (parsed.path or "").lower()
    findings = []

    for brand in BRAND_IMPERSONATION:
        # Check if brand appears in subdomain but not as the main domain
        parts = hostname.split(".")
        registrable = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
        subdomain_part = ".".join(parts[:-2]).lower()

        if brand in subdomain_part or (brand in path_lower and brand not in registrable):
            findings.append(Finding(
                "brand_impersonation",
                f"Possible impersonation of '{brand}' in URL",
                25
            ))
            break  # one finding is enough

    return findings


def check_url_shortener(parsed: urlparse) -> Optional[Finding]:
    """Flag known URL shortener services."""
    hostname = parsed.hostname or ""
    if hostname in SHORTENER_DOMAINS:
        return Finding("url_shortener", f"Uses URL shortener ({hostname}) — obscures destination", 20)
    return None


def check_suspicious_characters(url: str) -> Optional[Finding]:
    """Detect homograph attacks and punycode."""
    if "xn--" in url.lower():
        return Finding("punycode", "URL contains punycode (internationalized domain) — possible homograph attack", 20)
    return None


def check_excessive_url_length(url: str) -> Optional[Finding]:
    """Very long URLs are suspicious."""
    if len(url) > 200:
        return Finding("long_url", f"Excessively long URL ({len(url)} chars)", 10)
    return None


def check_suspicious_path_extension(parsed: urlparse) -> Optional[Finding]:
    """Check for dangerous file extensions in path."""
    path = parsed.path.lower()
    for ext in SUSPICIOUS_EXTENSIONS:
        if path.endswith(ext):
            return Finding("suspicious_extension", f"URL points to suspicious file type: {ext}", 20)
    return None


def check_entropy(parsed: urlparse) -> Optional[Finding]:
    """High entropy in domain/path suggests randomized phishing URLs."""
    text = (parsed.hostname or "") + (parsed.path or "")
    if len(text) < 10:
        return None
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = -sum((count / len(text)) * math.log2(count / len(text)) for count in freq.values())
    if entropy > 4.5:
        return Finding("high_entropy", f"High entropy ({entropy:.2f}) suggests randomized/generated URL", 10)
    return None


def check_data_uri(url: str) -> Optional[Finding]:
    """Data URIs can embed phishing pages."""
    if url.strip().lower().startswith("data:"):
        return Finding("data_uri", "Data URI detected — can embed malicious content", 35)
    return None


def check_multiple_redirects(parsed: urlparse) -> Optional[Finding]:
    """Check for redirect parameters in query string."""
    params = parse_qs(parsed.query)
    redirect_params = {"url", "redirect", "next", "redir", "return", "goto", "dest", "target", "link"}
    found = redirect_params.intersection(set(k.lower() for k in params.keys()))
    if found:
        return Finding("redirect_params", f"Contains redirect parameters: {', '.join(found)}", 15)
    return None


def check_typosquatting(parsed: urlparse) -> Optional[Finding]:
    """Basic typosquatting detection for top brands."""
    hostname = (parsed.hostname or "").lower()
    typo_patterns = {
        "g00gle": "google", "gogle": "google",
        "faceb00k": "facebook", "facbook": "facebook",
        "amaz0n": "amazon", "amazn": "amazon",
        "paypa1": "paypal", "paypai": "paypal",
        "micros0ft": "microsoft", "mircosoft": "microsoft",
        "netfllx": "netflix", "netfl1x": "netflix",
        "app1e": "apple", "appie": "apple",
    }
    for typo, brand in typo_patterns.items():
        # Only flag if the typo is present but the real brand is NOT
        if typo in hostname and brand not in hostname:
            return Finding("typosquatting", f"Possible typosquatting of '{brand}' (found '{typo}')", 30)
    return None


# ── Main analysis engine ───────────────────────────────────────────────────

ALL_CHECKS = [
    check_ip_address,
    check_suspicious_tld,
    check_domain_length,
    check_subdomain_depth,
    check_at_symbol,
    check_double_slashes,
    check_https,
    check_url_shortener,
    check_suspicious_characters,
    check_excessive_url_length,
    check_suspicious_path_extension,
    check_entropy,
    check_data_uri,
    check_multiple_redirects,
    check_typosquatting,
]

LIST_CHECKS = [
    check_phishing_keywords,
    check_brand_impersonation,
]


def analyze_url(url: str) -> AnalysisResult:
    """Run all heuristic checks against a URL and return the analysis."""
    result = AnalysisResult(url=url)

    # Normalize
    if not url.startswith(("http://", "https://", "data:")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        result.risk_score = 100
        result.risk_level = "🔴 CRITICAL"
        result.findings.append(Finding("parse_error", "URL could not be parsed", 100))
        return result

    result.parsed_domain = parsed.hostname or "N/A"
    result.is_https = parsed.scheme == "https"

    # Run single-finding checks
    for check_fn in ALL_CHECKS:
        finding = check_fn(parsed) if "parsed" in check_fn.__code__.co_varnames[:1] else check_fn(url) if "url" in check_fn.__code__.co_varnames[:1] else check_fn(parsed)
        if finding:
            result.findings.append(finding)

    # Run list-finding checks
    for check_fn in LIST_CHECKS:
        findings = check_fn(parsed)
        result.findings.extend(findings)

    # Calculate total score (cap at 100)
    result.risk_score = min(sum(f.score for f in result.findings), 100)

    # Assign risk level
    if result.risk_score >= 70:
        result.risk_level = "🔴 CRITICAL"
    elif result.risk_score >= 45:
        result.risk_level = "🟠 HIGH"
    elif result.risk_score >= 25:
        result.risk_level = "🟡 MEDIUM"
    elif result.risk_score >= 10:
        result.risk_level = "🔵 LOW"
    else:
        result.risk_level = "🟢 SAFE"

    return result


# ── CLI interface ──────────────────────────────────────────────────────────

def print_report(result: AnalysisResult):
    """Pretty-print the analysis report."""
    print("\n" + "=" * 60)
    print("  PhishGuard — Phishing URL Analysis Report")
    print("=" * 60)
    print(f"  URL:     {result.url}")
    print(f"  Domain:  {result.parsed_domain}")
    print(f"  HTTPS:   {'✅ Yes' if result.is_https else '❌ No'}")
    print(f"  Score:   {result.risk_score}/100")
    print(f"  Verdict: {result.risk_level}")
    print("-" * 60)

    if result.findings:
        print("  Findings:")
        for i, f in enumerate(result.findings, 1):
            print(f"    {i}. [{f.rule}] (+{f.score}) {f.description}")
    else:
        print("  ✅ No suspicious indicators found.")

    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="PhishGuard — Heuristic-based phishing URL detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python phishguard.py "http://g00gle-login.tk/verify"
  python phishguard.py -f urls.txt
  python phishguard.py "https://bit.ly/3xR7abc" --json
        """,
    )
    parser.add_argument("url", nargs="?", help="URL to analyze")
    parser.add_argument("-f", "--file", help="File with URLs (one per line)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        try:
            with open(args.file) as f:
                urls.extend(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            print(f"Error: File '{args.file}' not found.", file=sys.stderr)
            sys.exit(1)

    if not urls:
        parser.print_help()
        sys.exit(1)

    results = [analyze_url(u) for u in urls]

    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        for r in results:
            print_report(r)


if __name__ == "__main__":
    main()
