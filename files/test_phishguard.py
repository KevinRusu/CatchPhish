"""Tests for PhishGuard heuristic checks."""

import unittest
from phishguard import analyze_url


class TestPhishGuard(unittest.TestCase):

    # ── Clearly malicious URLs ──────────────────────────────────────────

    def test_ip_address_url(self):
        r = analyze_url("http://192.168.1.1/login.php")
        self.assertTrue(any(f.rule == "ip_address" for f in r.findings))
        self.assertGreaterEqual(r.risk_score, 30)

    def test_suspicious_tld(self):
        r = analyze_url("http://secure-bank.tk/account")
        self.assertTrue(any(f.rule == "suspicious_tld" for f in r.findings))

    def test_typosquatting(self):
        r = analyze_url("http://g00gle-login.com/verify")
        self.assertTrue(any(f.rule == "typosquatting" for f in r.findings))

    def test_brand_impersonation_subdomain(self):
        r = analyze_url("http://paypal.secure-login.xyz/verify")
        self.assertTrue(any(f.rule == "brand_impersonation" for f in r.findings))

    def test_at_symbol(self):
        r = analyze_url("http://legit.com@evil.com/steal")
        self.assertTrue(any(f.rule == "at_symbol" for f in r.findings))

    def test_url_shortener(self):
        r = analyze_url("https://bit.ly/3xR7abc")
        self.assertTrue(any(f.rule == "url_shortener" for f in r.findings))

    def test_punycode(self):
        r = analyze_url("http://xn--pple-43d.com/login")
        self.assertTrue(any(f.rule == "punycode" for f in r.findings))

    def test_phishing_keywords(self):
        r = analyze_url("http://example.com/signin/verify-password")
        self.assertTrue(any(f.rule == "phishing_keywords" for f in r.findings))

    def test_suspicious_extension(self):
        r = analyze_url("http://example.com/download/invoice.exe")
        self.assertTrue(any(f.rule == "suspicious_extension" for f in r.findings))

    def test_data_uri(self):
        r = analyze_url("data:text/html,<h1>phishing</h1>")
        self.assertTrue(any(f.rule == "data_uri" for f in r.findings))

    def test_redirect_params(self):
        r = analyze_url("http://example.com/login?redirect=http://evil.com")
        self.assertTrue(any(f.rule == "redirect_params" for f in r.findings))

    def test_deep_subdomains(self):
        r = analyze_url("http://a.b.c.d.e.example.com/login")
        self.assertTrue(any(f.rule == "deep_subdomains" for f in r.findings))

    # ── Combined high-risk URL ──────────────────────────────────────────

    def test_combined_high_risk(self):
        r = analyze_url("http://g00gle-login.tk/signin/verify-password?redirect=http://evil.com")
        self.assertGreaterEqual(r.risk_score, 60)
        self.assertTrue("CRITICAL" in r.risk_level or "HIGH" in r.risk_level)

    # ── Legitimate URLs ─────────────────────────────────────────────────

    def test_safe_google(self):
        r = analyze_url("https://www.google.com")
        self.assertLessEqual(r.risk_score, 10)

    def test_safe_github(self):
        r = analyze_url("https://github.com/user/repo")
        self.assertLessEqual(r.risk_score, 10)

    def test_safe_university(self):
        r = analyze_url("https://www.cmu.edu/homepage")
        self.assertLessEqual(r.risk_score, 10)

    # ── Edge cases ──────────────────────────────────────────────────────

    def test_empty_after_scheme(self):
        r = analyze_url("http://")
        self.assertIsNotNone(r)

    def test_no_scheme(self):
        r = analyze_url("example.com/login")
        self.assertIsNotNone(r)

    # ── JSON output ─────────────────────────────────────────────────────

    def test_to_dict(self):
        r = analyze_url("http://g00gle.tk/login")
        d = r.to_dict()
        self.assertIn("url", d)
        self.assertIn("risk_score", d)
        self.assertIn("findings", d)
        self.assertIsInstance(d["findings"], list)


if __name__ == "__main__":
    unittest.main()
