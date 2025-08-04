# Author: rizul0x01
"""
OWASP Top 10 vulnerability checker module for scopex.
Checks for common web application vulnerabilities based on OWASP Top 10.
"""

import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urljoin

from .utils import ScopexLogger, ScopexRequester, normalize_domain


class OWASPChecker:
    """Checks for vulnerabilities based on OWASP Top 10 categories."""
    
    def __init__(self, logger: ScopexLogger, requester: ScopexRequester):
        self.logger = logger
        self.requester = requester
        self.vulnerabilities = []
    
    def check_owasp_top10(self, domain: str, tech_data: Dict[str, Any] = None,
                          robots_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Perform checks for OWASP Top 10 vulnerabilities.
        
        Args:
            domain: Target domain.
            tech_data: Technology stack data from fingerprinting.
            robots_data: Robots.txt and sitemap analysis data.
        
        Returns:
            Dictionary containing OWASP Top 10 findings.
        """
        self.logger.info(f"Checking OWASP Top 10 vulnerabilities for {domain}")
        
        self.domain = normalize_domain(domain)
        self.tech_data = tech_data if tech_data else {}
        self.robots_data = robots_data if robots_data else {}
        
        # A01:2021-Broken Access Control
        self._check_broken_access_control()
        
        # A02:2021-Cryptographic Failures
        self._check_cryptographic_failures()
        
        # A03:2021-Injection
        self._check_injection()
        
        # A04:2021-Insecure Design (partially covered by other checks)
        # A05:2021-Security Misconfiguration
        self._check_security_misconfiguration()
        
        # A06:2021-Vulnerable and Outdated Components
        self._check_vulnerable_components()
        
        # A07:2021-Identification and Authentication Failures
        self._check_auth_failures()
        
        # A08:2021-Software and Data Integrity Failures
        # A09:2021-Security Logging and Monitoring Failures (requires active testing)
        # A10:2021-Server-Side Request Forgery (SSRF) (requires active testing)
        
        self.logger.info(f"OWASP Top 10 checks completed. Found {len(self.vulnerabilities)} issues.")
        
        return {
            "domain": self.domain,
            "owasp_vulnerabilities": self.vulnerabilities
        }
    
    def _add_vulnerability(self, category: str, description: str, severity: str = "Medium"):
        """
        Adds a vulnerability to the list.
        """
        self.vulnerabilities.append({
            "category": category,
            "description": description,
            "severity": severity
        })
        self.logger.warning(f"OWASP Issue ({category}): {description}")

    # --- OWASP Top 10 Checks ---

    def _check_broken_access_control(self):
        """
        A01:2021-Broken Access Control
        Checks for common admin/sensitive paths exposed via robots.txt or sitemap.
        """
        if self.robots_data:
            admin_paths = self.robots_data.get("admin_paths", [])
            dev_paths = self.robots_data.get("dev_paths", [])
            
            if admin_paths:
                self._add_vulnerability(
                    "A01: Broken Access Control",
                    "Potential admin paths disclosed: {}".format(", ".join(admin_paths[:3])),
                    "High"
                )
            if dev_paths:
                self._add_vulnerability(
                    "A01: Broken Access Control",
                    "Potential development/staging paths disclosed: {}".format(", ".join(dev_paths[:3])),
                    "Medium"
                )
        
        # Check for common sensitive files (e.g., .git, .env) - already in vuln_checker
        # This check is more about *disclosure* than *access control* without active testing

    def _check_cryptographic_failures(self):
        """
        A02:2021-Cryptographic Failures
        Checks for weak SSL/TLS configurations (requires SSL data).
        """
        # This check relies on the cert_inspector module's findings
        # Assuming SSL data is passed or can be retrieved
        # For now, we'll rely on the existing vuln_checker for SSL issues
        pass

    def _check_injection(self):
        """
        A03:2021-Injection
        Checks for common indicators of SQL/XSS/Command Injection in HTML/JS.
        This is a passive check and not an active exploitation attempt.
        """
        # Look for common error messages in response content (from vuln_checker)
        # Look for reflected input (requires active testing, not passive)
        
        # Simplified check for potential XSS in HTML (e.g., unescaped user input)
        # This is very basic and prone to false positives without context
        try:
            response = self.requester.get(f"https://{self.domain}", timeout=10)
            if response and response.status_code == 200 and response.text:
                # Look for common XSS patterns in HTML (e.g., <script>alert(1)</script>)
                # This is a very weak indicator for passive scanning
                if re.search(r"<script>alert\(1\)</script>", response.text, re.IGNORECASE):
                    self._add_vulnerability(
                        "A03: Injection (XSS)",
                        "Potential XSS reflected in page content (passive indicator)",
                        "Low"
                    )
        except Exception as e:
            self.logger.debug(f"Failed to check for XSS indicators: {e}")

    def _check_security_misconfiguration(self):
        """
        A05:2021-Security Misconfiguration
        Checks for missing security headers, directory listing, default pages.
        """
        # This is largely covered by the existing vuln_checker module
        # We can re-use some of its logic or ensure it's run before this.
        
        # Check for missing security headers (re-using logic from vuln_checker)
        try:
            response = self.requester.get(f"https://{self.domain}", timeout=10)
            if response and response.status_code == 200:
                headers = {k.lower(): v for k, v in response.headers.items()}
                
                missing_headers = []
                if "content-security-policy" not in headers:
                    missing_headers.append("Content-Security-Policy")
                if "x-frame-options" not in headers:
                    missing_headers.append("X-Frame-Options")
                if "x-content-type-options" not in headers:
                    missing_headers.append("X-Content-Type-Options")
                if "strict-transport-security" not in headers and "https" in response.url:
                    missing_headers.append("Strict-Transport-Security (HSTS)")
                
                if missing_headers:
                    self._add_vulnerability(
                        "A05: Security Misconfiguration",
                        "Missing security headers: {}".format(", ".join(missing_headers)),
                        "Medium"
                    )
        except Exception as e:
            self.logger.debug(f"Failed to check security headers for OWASP: {e}")

    def _check_vulnerable_components(self):
        """
        A06:2021-Vulnerable and Outdated Components
        Checks for outdated software versions based on tech stack fingerprinting.
        """
        if self.tech_data and self.tech_data.get("outdated_software"):
            for software in self.tech_data["outdated_software"]:
                self._add_vulnerability(
                    "A06: Vulnerable and Outdated Components",
                    f"Outdated software detected: {software}",
                    "High"
                )
        
        # This also relies on the Shodan plugin for CVEs on open ports
        # (if Shodan is integrated and provides vulnerability data)

    def _check_auth_failures(self):
        """
        A07:2021-Identification and Authentication Failures
        Checks for common login page paths, lack of HSTS (partially covered).
        """
        # Check for common login paths (passive, just disclosure)
        common_login_paths = [
            "/admin/login", "/login.php", "/wp-login.php", "/user/login",
            "/auth/login", "/signin", "/dashboard/login"
        ]
        
        for path in common_login_paths:
            url = urljoin(f"https://{self.domain}", path)
            try:
                response = self.requester.get(url, timeout=5, allow_redirects=False)
                if response and response.status_code in [200, 302, 301]:
                    self._add_vulnerability(
                        "A07: Identification and Authentication Failures",
                        f"Common login page found: {url}",
                        "Low"
                    )
            except Exception as e:
                self.logger.debug(f"Failed to check login path {url}: {e}")


def run_owasp_top10_checks(domain: str, logger: ScopexLogger, requester: ScopexRequester,
                           tech_data: Dict[str, Any] = None,
                           robots_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Main function to run OWASP Top 10 checks.
    
    Args:
        domain: Target domain.
        logger: Logger instance.
        requester: HTTP requester instance.
        tech_data: Technology stack data.
        robots_data: Robots.txt and sitemap data.
    
    Returns:
        Dictionary containing OWASP Top 10 findings.
    """
    checker = OWASPChecker(logger, requester)
    return checker.check_owasp_top10(domain, tech_data, robots_data)


