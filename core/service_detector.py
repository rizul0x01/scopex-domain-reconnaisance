# Author: rizul0x01
"""
Service detection module for scopex.
Detects HTTP/HTTPS services on subdomains and their response codes.
"""

from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from .utils import ScopexLogger, ScopexRequester, normalize_domain


class ServiceDetector:
    """HTTP/HTTPS service detection for subdomains."""
    
    def __init__(self, logger: ScopexLogger, requester: ScopexRequester):
        self.logger = logger
        self.requester = requester
    
    def detect_services(self, subdomains: List[str]) -> Dict[str, Any]:
        """
        Detect HTTP/HTTPS services on subdomains and their response codes.
        
        Args:
            subdomains: List of subdomains to check
        
        Returns:
            Dictionary containing service detection results
        """
        self.logger.info(f"Detecting HTTP/HTTPS services for {len(subdomains)} subdomains")
        
        results = {
            'subdomain_http_status': {},
            'total_http_services_found': 0
        }
        
        for subdomain in subdomains:
            try:
                self.logger.debug(f"Checking HTTP/HTTPS for {subdomain}")
                
                http_info = self._check_http_services(subdomain)
                results['subdomain_http_status'][subdomain] = http_info
                
                if http_info['http']['available'] or http_info['https']['available']:
                    results['total_http_services_found'] += 1
                
            except Exception as e:
                self.logger.error(f"HTTP/HTTPS service detection failed for {subdomain}: {e}")
                continue
        
        self.logger.info(f"Found {results['total_http_services_found']} subdomains with active HTTP/HTTPS services")
        
        return results
    
    def _check_http_services(self, subdomain: str) -> Dict[str, Any]:
        """
        Check HTTP/HTTPS services and response codes.
        
        Args:
            subdomain: Subdomain to check
        
        Returns:
            HTTP service information
        """
        http_info = {
            'http': {'available': False, 'status_code': None, 'server': None, 'title': None, 'redirect_to': None},
            'https': {'available': False, 'status_code': None, 'server': None, 'title': None, 'redirect_to': None}
        }
        
        # Check HTTPS first (more common for modern sites)
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{subdomain}"
                response = self.requester.get(url, timeout=10, allow_redirects=True)
                
                if response:
                    http_info[protocol]['available'] = True
                    http_info[protocol]['status_code'] = response.status_code
                    http_info[protocol]['server'] = response.headers.get('Server', 'Unknown')
                    
                    # Extract title from HTML
                    if response.text:
                        title = self._extract_title(response.text)
                        http_info[protocol]['title'] = title
                    
                    # Check for redirects
                    if response.history:
                        http_info[protocol]['redirect_to'] = response.url
                    
                    self.logger.debug(f"{protocol.upper()} service found on {subdomain}: {response.status_code}")
                
            except Exception as e:
                self.logger.debug(f"Failed to check {protocol} for {subdomain}: {e}")
                continue
        
        return http_info
    
    def _extract_title(self, html_content: str) -> Optional[str]:
        """
        Extract title from HTML content.
        
        Args:
            html_content: HTML content
        
        Returns:
            Page title or None
        """
        try:
            import re
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
            if title_match:
                title = title_match.group(1).strip()
                # Clean up title
                title = re.sub(r'\s+', ' ', title)
                return title[:100] if title else None  # Limit title length
        except Exception:
            pass
        
        return None


def run_service_detection(subdomains: List[str], logger: ScopexLogger, 
                         requester: ScopexRequester) -> Dict[str, Any]:
    """
    Main function to run service detection.
    
    Args:
        subdomains: List of subdomains to check
        logger: Logger instance
        requester: HTTP requester instance
    
    Returns:
        Dictionary containing service detection results
    """
    detector = ServiceDetector(logger, requester)
    return detector.detect_services(subdomains)


