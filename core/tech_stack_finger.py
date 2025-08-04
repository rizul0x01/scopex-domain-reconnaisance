# Author: rizul0x01
"""
Technology stack fingerprinting module for scopex.
Identifies web technologies, frameworks, and software versions.
"""

import re
import hashlib
from typing import Dict, List, Any, Set
from urllib.parse import urljoin, urlparse
from .utils import ScopexLogger, ScopexRequester, normalize_domain


class TechStackFingerprinter:
    """Web technology stack identification and fingerprinting."""
    
    def __init__(self, logger: ScopexLogger, requester: ScopexRequester):
        self.logger = logger
        self.requester = requester
        self.technologies = []
        self.headers_analyzed = {}
        self.html_content = ""
    
    def fingerprint(self, domain: str) -> Dict[str, Any]:
        """
        Fingerprint technology stack for a domain.
        
        Args:
            domain: Target domain
        
        Returns:
            Dictionary containing identified technologies
        """
        domain = normalize_domain(domain)
        self.logger.info(f"Fingerprinting technology stack for {domain}")
        
        results = {
            'domain': domain,
            'technologies': [],
            'web_server': None,
            'programming_languages': [],
            'frameworks': [],
            'cms': None,
            'javascript_libraries': [],
            'analytics': [],
            'cdn': None,
            'security_headers': {},
            'favicon_hash': None,
            'api_endpoints': [],
            'version_info': {}
        }
        
        # Try both HTTP and HTTPS
        urls_to_try = [f"https://{domain}", f"http://{domain}"]
        
        for url in urls_to_try:
            try:
                self.logger.debug(f"Analyzing {url}")
                response = self.requester.get(url, timeout=15)
                
                if response and response.status_code == 200:
                    self.headers_analyzed = dict(response.headers)
                    self.html_content = response.text
                    
                    # Analyze different aspects
                    results.update(self._analyze_headers())
                    results.update(self._analyze_html_content())
                    results['favicon_hash'] = self._get_favicon_hash(url)
                    results['api_endpoints'] = self._detect_api_endpoints()
                    
                    # Compile all technologies
                    results['technologies'] = self._compile_technologies()
                    
                    self.logger.info(f"Identified {len(results['technologies'])} technologies")
                    break
                    
            except Exception as e:
                self.logger.debug(f"Failed to analyze {url}: {e}")
                continue
        
        return results
    
    def _analyze_headers(self) -> Dict[str, Any]:
        """
        Analyze HTTP headers for technology indicators.
        
        Returns:
            Dictionary with header analysis results
        """
        results = {
            'web_server': None,
            'programming_languages': [],
            'frameworks': [],
            'cdn': None,
            'security_headers': {}
        }
        
        # Web server identification
        server_header = self.headers_analyzed.get('Server', '').lower()
        if server_header:
            if 'apache' in server_header:
                results['web_server'] = f"Apache {self._extract_version(server_header, 'apache')}"
            elif 'nginx' in server_header:
                results['web_server'] = f"Nginx {self._extract_version(server_header, 'nginx')}"
            elif 'iis' in server_header:
                results['web_server'] = f"IIS {self._extract_version(server_header, 'iis')}"
            elif 'cloudflare' in server_header:
                results['cdn'] = 'Cloudflare'
            else:
                results['web_server'] = server_header
        
        # Programming language detection
        powered_by = self.headers_analyzed.get('X-Powered-By', '').lower()
        if powered_by:
            if 'php' in powered_by:
                results['programming_languages'].append(f"PHP {self._extract_version(powered_by, 'php')}")
            elif 'asp.net' in powered_by:
                results['programming_languages'].append(f"ASP.NET {self._extract_version(powered_by, 'asp.net')}")
            elif 'express' in powered_by:
                results['frameworks'].append(f"Express.js {self._extract_version(powered_by, 'express')}")
        
        # Framework detection from headers
        framework_headers = {
            'X-Framework': 'framework',
            'X-Generator': 'generator',
            'X-Drupal-Cache': 'Drupal',
            'X-Pingback': 'WordPress'
        }
        
        for header, tech in framework_headers.items():
            if header in self.headers_analyzed:
                if tech == 'WordPress':
                    results['frameworks'].append('WordPress')
                elif tech == 'Drupal':
                    results['frameworks'].append('Drupal')
                else:
                    results['frameworks'].append(self.headers_analyzed[header])
        
        # CDN detection
        cdn_headers = {
            'CF-RAY': 'Cloudflare',
            'X-Cache': 'Varnish/CDN',
            'X-Served-By': 'Fastly',
            'X-Amz-Cf-Id': 'Amazon CloudFront'
        }
        
        for header, cdn in cdn_headers.items():
            if header in self.headers_analyzed:
                results['cdn'] = cdn
                break
        
        # Security headers analysis
        security_headers = [
            'Content-Security-Policy', 'X-Frame-Options', 'X-XSS-Protection',
            'X-Content-Type-Options', 'Strict-Transport-Security',
            'Referrer-Policy', 'Feature-Policy', 'Permissions-Policy'
        ]
        
        for header in security_headers:
            if header in self.headers_analyzed:
                results['security_headers'][header] = self.headers_analyzed[header]
        
        return results
    
    def _analyze_html_content(self) -> Dict[str, Any]:
        """
        Analyze HTML content for technology indicators.
        
        Returns:
            Dictionary with HTML analysis results
        """
        results = {
            'cms': None,
            'javascript_libraries': [],
            'frameworks': [],
            'analytics': [],
            'version_info': {}
        }
        
        if not self.html_content:
            return results
        
        html_lower = self.html_content.lower()
        
        # CMS detection
        cms_patterns = {
            'WordPress': [
                r'wp-content', r'wp-includes', r'/wp-json/', r'wordpress',
                r'<meta name="generator" content="wordpress'
            ],
            'Drupal': [
                r'drupal', r'/sites/default/', r'drupal.settings',
                r'<meta name="generator" content="drupal'
            ],
            'Joomla': [
                r'joomla', r'/components/', r'/modules/',
                r'<meta name="generator" content="joomla'
            ],
            'Magento': [
                r'magento', r'/skin/frontend/', r'mage/cookies'
            ],
            'Shopify': [
                r'shopify', r'cdn.shopify.com', r'shopify-analytics'
            ]
        }
        
        for cms, patterns in cms_patterns.items():
            if any(re.search(pattern, html_lower) for pattern in patterns):
                results['cms'] = cms
                break
        
        # JavaScript library detection
        js_libraries = {
            'jQuery': [r'jquery', r'/jquery-'],
            'React': [r'react', r'_react'],
            'Angular': [r'angular', r'ng-'],
            'Vue.js': [r'vue\.js', r'vue\.min\.js'],
            'Bootstrap': [r'bootstrap', r'/bootstrap'],
            'D3.js': [r'd3\.js', r'd3\.min\.js'],
            'Lodash': [r'lodash', r'underscore'],
            'Moment.js': [r'moment\.js', r'moment\.min\.js']
        }
        
        for library, patterns in js_libraries.items():
            if any(re.search(pattern, html_lower) for pattern in patterns):
                results['javascript_libraries'].append(library)
        
        # Analytics detection
        analytics_patterns = {
            'Google Analytics': [r'google-analytics', r'gtag\(', r'ga\('],
            'Google Tag Manager': [r'googletagmanager'],
            'Facebook Pixel': [r'facebook\.net/tr', r'fbq\('],
            'Hotjar': [r'hotjar'],
            'Mixpanel': [r'mixpanel']
        }
        
        for analytics, patterns in analytics_patterns.items():
            if any(re.search(pattern, html_lower) for pattern in patterns):
                results['analytics'].append(analytics)
        
        # Framework detection from HTML
        framework_patterns = {
            'Laravel': [r'laravel_session', r'csrf-token'],
            'Django': [r'csrfmiddlewaretoken', r'django'],
            'Rails': [r'csrf-param', r'rails'],
            'Spring': [r'spring', r'jsessionid']
        }
        
        for framework, patterns in framework_patterns.items():
            if any(re.search(pattern, html_lower) for pattern in patterns):
                results['frameworks'].append(framework)
        
        # Version extraction from meta tags
        generator_match = re.search(r'<meta name="generator" content="([^"]+)"', html_lower)
        if generator_match:
            generator = generator_match.group(1)
            results['version_info']['generator'] = generator
        
        return results
    
    def _get_favicon_hash(self, base_url: str) -> str:
        """
        Get favicon hash for fingerprinting.
        
        Args:
            base_url: Base URL of the website
        
        Returns:
            MD5 hash of favicon or None
        """
        try:
            favicon_url = urljoin(base_url, '/favicon.ico')
            response = self.requester.get(favicon_url, timeout=10)
            
            if response and response.status_code == 200:
                favicon_hash = hashlib.md5(response.content).hexdigest()
                self.logger.debug(f"Favicon hash: {favicon_hash}")
                return favicon_hash
        
        except Exception as e:
            self.logger.debug(f"Failed to get favicon hash: {e}")
        
        return None
    
    def _detect_api_endpoints(self) -> List[str]:
        """
        Detect potential API endpoints from HTML content.
        
        Returns:
            List of potential API endpoints
        """
        api_endpoints = []
        
        if not self.html_content:
            return api_endpoints
        
        # Look for API endpoints in JavaScript
        api_patterns = [
            r'["\']([^"\']*(?:api|rest|graphql)[^"\']*)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'\.ajax\(\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, self.html_content, re.IGNORECASE)
            for match in matches:
                if any(indicator in match.lower() for indicator in ['api', 'rest', 'graphql', 'json']):
                    if match not in api_endpoints:
                        api_endpoints.append(match)
        
        return api_endpoints[:10]  # Limit to first 10 endpoints
    
    def _extract_version(self, text: str, software: str) -> str:
        """
        Extract version number from text.
        
        Args:
            text: Text to search for version
            software: Software name to look for
        
        Returns:
            Version string or empty string
        """
        # Common version patterns
        patterns = [
            rf'{software}[/\s]+(\d+\.\d+(?:\.\d+)?)',
            rf'{software}[/\s]+v?(\d+\.\d+(?:\.\d+)?)',
            rf'(\d+\.\d+(?:\.\d+)?)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return ""
    
    def _compile_technologies(self) -> List[str]:
        """
        Compile all identified technologies into a single list.
        
        Returns:
            List of all identified technologies
        """
        technologies = []
        
        # Add web server
        if hasattr(self, 'web_server') and self.web_server:
            technologies.append(self.web_server)
        
        # Add programming languages
        if hasattr(self, 'programming_languages'):
            technologies.extend(self.programming_languages)
        
        # Add frameworks
        if hasattr(self, 'frameworks'):
            technologies.extend(self.frameworks)
        
        # Add CMS
        if hasattr(self, 'cms') and self.cms:
            technologies.append(self.cms)
        
        # Add JavaScript libraries
        if hasattr(self, 'javascript_libraries'):
            technologies.extend(self.javascript_libraries)
        
        # Add analytics
        if hasattr(self, 'analytics'):
            technologies.extend(self.analytics)
        
        # Add CDN
        if hasattr(self, 'cdn') and self.cdn:
            technologies.append(self.cdn)
        
        return list(set(technologies))  # Remove duplicates


def run_tech_stack_fingerprinting(domain: str, logger: ScopexLogger, 
                                 requester: ScopexRequester) -> Dict[str, Any]:
    """
    Main function to run technology stack fingerprinting.
    
    Args:
        domain: Target domain
        logger: Logger instance
        requester: HTTP requester instance
    
    Returns:
        Dictionary containing fingerprinting results
    """
    fingerprinter = TechStackFingerprinter(logger, requester)
    return fingerprinter.fingerprint(domain)

