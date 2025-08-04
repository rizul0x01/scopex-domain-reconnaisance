# Author: rizul0x01
"""
Vulnerability checker module for scopex.
Detects common web vulnerabilities and security misconfigurations.
"""

import re
from typing import Dict, List, Any, Tuple
from urllib.parse import urlparse
from .utils import ScopexLogger, ScopexRequester, normalize_domain


class VulnerabilityChecker:
    """Web vulnerability and misconfiguration detection."""
    
    def __init__(self, logger: ScopexLogger, requester: ScopexRequester):
        self.logger = logger
        self.requester = requester
    
    def check_vulnerabilities(self, domain: str, tech_data: Dict[str, Any] = None, 
                            dns_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Check for vulnerabilities and misconfigurations.
        
        Args:
            domain: Target domain
            tech_data: Technology stack data from fingerprinting
            dns_data: DNS resolution data
        
        Returns:
            Dictionary containing vulnerability findings
        """
        domain = normalize_domain(domain)
        self.logger.info(f"Checking vulnerabilities for {domain}")
        
        results = {
            'domain': domain,
            'vulnerabilities': [],
            'security_headers': {},
            'ssl_issues': [],
            'outdated_software': [],
            'misconfigurations': [],
            'information_disclosure': [],
            'risk_level': 'Low'
        }
        
        # Check HTTP response and headers
        response_data = self._analyze_http_response(domain)
        if response_data:
            results['security_headers'] = response_data.get('headers', {})
            results['vulnerabilities'].extend(response_data.get('vulnerabilities', []))
        
        # Check for outdated software
        if tech_data:
            outdated = self._check_outdated_software(tech_data)
            results['outdated_software'] = outdated
            if outdated:
                results['vulnerabilities'].extend([f"Outdated software: {soft}" for soft in outdated])
        
        # Check DNS-related vulnerabilities
        if dns_data:
            dns_vulns = self._check_dns_vulnerabilities(dns_data)
            results['vulnerabilities'].extend(dns_vulns)
        
        # Check for common misconfigurations
        misconfigs = self._check_misconfigurations(domain)
        results['misconfigurations'] = misconfigs
        results['vulnerabilities'].extend(misconfigs)
        
        # Check for information disclosure
        info_disclosure = self._check_information_disclosure(domain)
        results['information_disclosure'] = info_disclosure
        results['vulnerabilities'].extend(info_disclosure)
        
        # Calculate risk level
        results['risk_level'] = self._calculate_risk_level(results['vulnerabilities'])
        
        self.logger.info(f"Found {len(results['vulnerabilities'])} vulnerabilities")
        return results
    
    def _analyze_http_response(self, domain: str) -> Dict[str, Any]:
        """
        Analyze HTTP response for security headers and vulnerabilities.
        
        Args:
            domain: Target domain
        
        Returns:
            Dictionary with HTTP analysis results
        """
        results = {
            'headers': {},
            'vulnerabilities': []
        }
        
        # Try both HTTP and HTTPS
        urls_to_try = [f"https://{domain}", f"http://{domain}"]
        
        for url in urls_to_try:
            try:
                self.logger.debug(f"Analyzing HTTP response from {url}")
                response = self.requester.get(url, timeout=15)
                
                if response and response.status_code == 200:
                    headers = dict(response.headers)
                    results['headers'] = headers
                    
                    # Check security headers
                    security_vulns = self._check_security_headers(headers)
                    results['vulnerabilities'].extend(security_vulns)
                    
                    # Check response content for vulnerabilities
                    content_vulns = self._check_response_content(response.text, headers)
                    results['vulnerabilities'].extend(content_vulns)
                    
                    break
                    
            except Exception as e:
                self.logger.debug(f"Failed to analyze {url}: {e}")
                continue
        
        return results
    
    def _check_security_headers(self, headers: Dict[str, str]) -> List[str]:
        """
        Check for missing or weak security headers.
        
        Args:
            headers: HTTP response headers
        
        Returns:
            List of security header vulnerabilities
        """
        vulnerabilities = []
        
        # Critical security headers
        critical_headers = {
            'Content-Security-Policy': 'Missing Content Security Policy (CSP)',
            'X-Frame-Options': 'Missing X-Frame-Options header - clickjacking possible',
            'X-XSS-Protection': 'Missing X-XSS-Protection header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'Strict-Transport-Security': 'Missing HSTS header - MITM attacks possible'
        }
        
        for header, message in critical_headers.items():
            if header not in headers:
                vulnerabilities.append(message)
        
        # Check for weak CSP
        csp = headers.get('Content-Security-Policy', '')
        if csp:
            if "'unsafe-inline'" in csp:
                vulnerabilities.append("Weak CSP: 'unsafe-inline' directive found")
            if "'unsafe-eval'" in csp:
                vulnerabilities.append("Weak CSP: 'unsafe-eval' directive found")
            if "*" in csp and "script-src" in csp:
                vulnerabilities.append("Weak CSP: wildcard (*) in script-src")
        
        # Check X-Frame-Options
        x_frame = headers.get('X-Frame-Options', '').upper()
        if x_frame and x_frame not in ['DENY', 'SAMEORIGIN']:
            vulnerabilities.append(f"Weak X-Frame-Options: {x_frame}")
        
        # Check for information disclosure in headers
        server_header = headers.get('Server', '')
        if server_header:
            # Check for version disclosure
            if re.search(r'\d+\.\d+', server_header):
                vulnerabilities.append(f"Server version disclosure: {server_header}")
        
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            vulnerabilities.append(f"Technology disclosure in X-Powered-By: {powered_by}")
        
        return vulnerabilities
    
    def _check_response_content(self, content: str, headers: Dict[str, str]) -> List[str]:
        """
        Check response content for vulnerabilities.
        
        Args:
            content: HTTP response content
            headers: HTTP response headers
        
        Returns:
            List of content-based vulnerabilities
        """
        vulnerabilities = []
        
        if not content:
            return vulnerabilities
        
        content_lower = content.lower()
        
        # Check for error messages that disclose information
        error_patterns = [
            (r'mysql.*error', 'MySQL error message disclosure'),
            (r'postgresql.*error', 'PostgreSQL error message disclosure'),
            (r'oracle.*error', 'Oracle error message disclosure'),
            (r'microsoft.*odbc', 'ODBC error message disclosure'),
            (r'warning.*mysql', 'MySQL warning disclosure'),
            (r'fatal error.*php', 'PHP fatal error disclosure'),
            (r'stack trace', 'Stack trace disclosure'),
            (r'exception.*at.*line', 'Exception details disclosure')
        ]
        
        for pattern, message in error_patterns:
            if re.search(pattern, content_lower):
                vulnerabilities.append(message)
        
        # Check for directory listing
        if '<title>index of' in content_lower or 'directory listing for' in content_lower:
            vulnerabilities.append("Directory listing enabled")
        
        # Check for default pages
        default_pages = [
            ('apache.*test page', 'Apache default test page exposed'),
            ('nginx.*welcome', 'Nginx welcome page exposed'),
            ('iis.*welcome', 'IIS welcome page exposed'),
            ('it works!', 'Default web server page exposed')
        ]
        
        for pattern, message in default_pages:
            if re.search(pattern, content_lower):
                vulnerabilities.append(message)
        
        # Check for sensitive file exposure
        if any(keyword in content_lower for keyword in ['.env', 'config.php', 'wp-config']):
            vulnerabilities.append("Potential sensitive file exposure detected")
        
        # Check for admin interfaces
        if any(keyword in content_lower for keyword in ['admin login', 'administrator', 'control panel']):
            vulnerabilities.append("Admin interface potentially exposed")
        
        return vulnerabilities
    
    def _check_outdated_software(self, tech_data: Dict[str, Any]) -> List[str]:
        """
        Check for outdated software versions.
        
        Args:
            tech_data: Technology stack data
        
        Returns:
            List of outdated software
        """
        outdated = []
        
        # Known vulnerable versions (simplified list)
        vulnerable_versions = {
            'php': ['5.6', '7.0', '7.1', '7.2', '7.3'],
            'apache': ['2.2', '2.4.0', '2.4.1', '2.4.2'],
            'nginx': ['1.0', '1.1', '1.2', '1.3', '1.4'],
            'wordpress': ['4.0', '4.1', '4.2', '4.3', '4.4', '4.5', '4.6', '4.7', '4.8', '4.9'],
            'jquery': ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7', '1.8', '1.9', '2.0', '2.1']
        }
        
        technologies = tech_data.get('technologies', [])
        
        for tech in technologies:
            tech_lower = tech.lower()
            
            for software, vuln_versions in vulnerable_versions.items():
                if software in tech_lower:
                    for version in vuln_versions:
                        if version in tech_lower:
                            outdated.append(f"{software.title()} {version}")
                            break
        
        return outdated
    
    def _check_dns_vulnerabilities(self, dns_data: Dict[str, Any]) -> List[str]:
        """
        Check DNS configuration for vulnerabilities.
        
        Args:
            dns_data: DNS resolution data
        
        Returns:
            List of DNS-related vulnerabilities
        """
        vulnerabilities = []
        
        # Check for missing SPF record
        if not dns_data.get('SPF'):
            vulnerabilities.append("Missing SPF record - email spoofing possible")
        
        # Check for missing DMARC record
        if not dns_data.get('DMARC'):
            vulnerabilities.append("Missing DMARC record - email authentication not enforced")
        
        # Check for wildcard DNS
        a_records = dns_data.get('A', [])
        if any('*' in record for record in a_records):
            vulnerabilities.append("Wildcard DNS detected - subdomain takeover risk")
        
        # Check for zone transfer vulnerability (simplified check)
        ns_records = dns_data.get('NS', [])
        if len(ns_records) > 0:
            # This is a simplified check - in practice, you'd attempt zone transfer
            vulnerabilities.append("DNS zone transfer should be tested manually")
        
        return vulnerabilities
    
    def _check_misconfigurations(self, domain: str) -> List[str]:
        """
        Check for common misconfigurations.
        
        Args:
            domain: Target domain
        
        Returns:
            List of misconfigurations
        """
        misconfigurations = []
        
        # Check for common sensitive files
        sensitive_files = [
            '/.env',
            '/config.php',
            '/wp-config.php',
            '/.git/config',
            '/admin',
            '/administrator',
            '/phpmyadmin',
            '/backup.sql',
            '/database.sql'
        ]
        
        base_urls = [f"https://{domain}", f"http://{domain}"]
        
        for base_url in base_urls:
            for file_path in sensitive_files[:5]:  # Limit to first 5 to avoid too many requests
                try:
                    url = base_url + file_path
                    response = self.requester.get(url, timeout=5)
                    
                    if response and response.status_code == 200:
                        misconfigurations.append(f"Sensitive file exposed: {file_path}")
                    elif response and response.status_code == 403:
                        misconfigurations.append(f"Sensitive path exists but forbidden: {file_path}")
                
                except Exception:
                    continue
            
            # Only check one protocol if successful
            if misconfigurations:
                break
        
        return misconfigurations
    
    def _check_information_disclosure(self, domain: str) -> List[str]:
        """
        Check for information disclosure vulnerabilities.
        
        Args:
            domain: Target domain
        
        Returns:
            List of information disclosure issues
        """
        disclosures = []
        
        # Check robots.txt for sensitive paths
        try:
            robots_url = f"https://{domain}/robots.txt"
            response = self.requester.get(robots_url, timeout=10)
            
            if response and response.status_code == 200:
                robots_content = response.text.lower()
                
                # Look for sensitive paths in robots.txt
                sensitive_patterns = [
                    'admin', 'administrator', 'backup', 'config', 'database',
                    'private', 'secret', 'temp', 'test', 'dev', 'staging'
                ]
                
                for pattern in sensitive_patterns:
                    if pattern in robots_content:
                        disclosures.append(f"Sensitive path disclosed in robots.txt: {pattern}")
        
        except Exception:
            pass
        
        # Check for common information disclosure endpoints
        info_endpoints = [
            '/server-status',
            '/server-info',
            '/.well-known/security.txt',
            '/sitemap.xml'
        ]
        
        for endpoint in info_endpoints:
            try:
                url = f"https://{domain}{endpoint}"
                response = self.requester.get(url, timeout=5)
                
                if response and response.status_code == 200:
                    disclosures.append(f"Information disclosure endpoint: {endpoint}")
            
            except Exception:
                continue
        
        return disclosures
    
    def _calculate_risk_level(self, vulnerabilities: List[str]) -> str:
        """
        Calculate overall risk level based on vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerabilities
        
        Returns:
            Risk level string
        """
        if not vulnerabilities:
            return 'Low'
        
        high_risk_keywords = [
            'sql injection', 'xss', 'csrf', 'rce', 'lfi', 'rfi',
            'directory traversal', 'command injection'
        ]
        
        medium_risk_keywords = [
            'missing csp', 'missing hsts', 'outdated', 'version disclosure',
            'sensitive file', 'admin interface'
        ]
        
        high_risk_count = sum(1 for vuln in vulnerabilities 
                             if any(keyword in vuln.lower() for keyword in high_risk_keywords))
        
        medium_risk_count = sum(1 for vuln in vulnerabilities 
                               if any(keyword in vuln.lower() for keyword in medium_risk_keywords))
        
        if high_risk_count > 0:
            return 'High'
        elif medium_risk_count > 2 or len(vulnerabilities) > 5:
            return 'Medium'
        else:
            return 'Low'


def run_vulnerability_checking(domain: str, logger: ScopexLogger, requester: ScopexRequester,
                              tech_data: Dict[str, Any] = None, dns_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Main function to run vulnerability checking.
    
    Args:
        domain: Target domain
        logger: Logger instance
        requester: HTTP requester instance
        tech_data: Technology stack data
        dns_data: DNS resolution data
    
    Returns:
        Dictionary containing vulnerability check results
    """
    checker = VulnerabilityChecker(logger, requester)
    return checker.check_vulnerabilities(domain, tech_data, dns_data)

