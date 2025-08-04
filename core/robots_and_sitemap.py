# Author: rizul0x01
"""
Robots.txt and sitemap analysis module for scopex.
Fetches and parses robots.txt and sitemap.xml files to discover paths and URLs.
"""

import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Set
from urllib.parse import urljoin, urlparse
from .utils import ScopexLogger, ScopexRequester, normalize_domain


class RobotsAndSitemapAnalyzer:
    """Robots.txt and sitemap.xml analysis for path discovery."""
    
    def __init__(self, logger: ScopexLogger, requester: ScopexRequester):
        self.logger = logger
        self.requester = requester
    
    def analyze(self, domain: str) -> Dict[str, Any]:
        """
        Analyze robots.txt and sitemap.xml for a domain.
        
        Args:
            domain: Target domain
        
        Returns:
            Dictionary containing analysis results
        """
        domain = normalize_domain(domain)
        self.logger.info(f"Analyzing robots.txt and sitemap for {domain}")
        
        results = {
            'domain': domain,
            'robots_txt': {
                'found': False,
                'disallowed_paths': [],
                'allowed_paths': [],
                'crawl_delay': None,
                'sitemaps': [],
                'user_agents': []
            },
            'sitemaps': {
                'found': [],
                'urls': [],
                'total_urls': 0
            },
            'interesting_paths': [],
            'api_endpoints': [],
            'admin_paths': [],
            'dev_paths': []
        }
        
        # Analyze robots.txt
        robots_data = self._analyze_robots_txt(domain)
        results['robots_txt'] = robots_data
        
        # Get sitemap URLs from robots.txt and analyze them
        sitemap_urls = robots_data.get('sitemaps', [])
        
        # Also try common sitemap locations
        common_sitemaps = [
            f"https://{domain}/sitemap.xml",
            f"https://{domain}/sitemap_index.xml",
            f"https://{domain}/sitemaps.xml",
            f"http://{domain}/sitemap.xml"
        ]
        
        all_sitemap_urls = list(set(sitemap_urls + common_sitemaps))
        sitemap_data = self._analyze_sitemaps(all_sitemap_urls)
        results['sitemaps'] = sitemap_data
        
        # Categorize interesting findings
        results['interesting_paths'] = self._categorize_paths(
            robots_data.get('disallowed_paths', []) + sitemap_data.get('urls', [])
        )
        results['api_endpoints'] = self._extract_api_endpoints(results['interesting_paths'])
        results['admin_paths'] = self._extract_admin_paths(results['interesting_paths'])
        results['dev_paths'] = self._extract_dev_paths(results['interesting_paths'])
        
        self.logger.info(f"Found {len(results['interesting_paths'])} interesting paths")
        return results
    
    def _analyze_robots_txt(self, domain: str) -> Dict[str, Any]:
        """
        Analyze robots.txt file.
        
        Args:
            domain: Target domain
        
        Returns:
            Robots.txt analysis results
        """
        robots_data = {
            'found': False,
            'disallowed_paths': [],
            'allowed_paths': [],
            'crawl_delay': None,
            'sitemaps': [],
            'user_agents': []
        }
        
        # Try both HTTP and HTTPS
        urls_to_try = [
            f"https://{domain}/robots.txt",
            f"http://{domain}/robots.txt"
        ]
        
        for url in urls_to_try:
            try:
                self.logger.debug(f"Fetching robots.txt from {url}")
                response = self.requester.get(url, timeout=10)
                
                if response and response.status_code == 200:
                    robots_data['found'] = True
                    robots_content = response.text
                    robots_data.update(self._parse_robots_txt(robots_content))
                    self.logger.debug(f"Successfully parsed robots.txt from {url}")
                    break
                    
            except Exception as e:
                self.logger.debug(f"Failed to fetch robots.txt from {url}: {e}")
                continue
        
        if not robots_data['found']:
            self.logger.debug(f"No robots.txt found for {domain}")
        
        return robots_data
    
    def _parse_robots_txt(self, content: str) -> Dict[str, Any]:
        """
        Parse robots.txt content.
        
        Args:
            content: Raw robots.txt content
        
        Returns:
            Parsed robots.txt data
        """
        parsed = {
            'disallowed_paths': [],
            'allowed_paths': [],
            'crawl_delay': None,
            'sitemaps': [],
            'user_agents': []
        }
        
        current_user_agent = None
        
        for line in content.split('\n'):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Split on first colon
            if ':' not in line:
                continue
            
            directive, value = line.split(':', 1)
            directive = directive.strip().lower()
            value = value.strip()
            
            if directive == 'user-agent':
                current_user_agent = value
                if value not in parsed['user_agents']:
                    parsed['user_agents'].append(value)
            
            elif directive == 'disallow':
                if value and value not in parsed['disallowed_paths']:
                    parsed['disallowed_paths'].append(value)
            
            elif directive == 'allow':
                if value and value not in parsed['allowed_paths']:
                    parsed['allowed_paths'].append(value)
            
            elif directive == 'crawl-delay':
                try:
                    parsed['crawl_delay'] = float(value)
                except ValueError:
                    pass
            
            elif directive == 'sitemap':
                if value and value not in parsed['sitemaps']:
                    parsed['sitemaps'].append(value)
        
        return parsed
    
    def _analyze_sitemaps(self, sitemap_urls: List[str]) -> Dict[str, Any]:
        """
        Analyze sitemap files.
        
        Args:
            sitemap_urls: List of sitemap URLs to analyze
        
        Returns:
            Sitemap analysis results
        """
        sitemap_data = {
            'found': [],
            'urls': [],
            'total_urls': 0
        }
        
        for sitemap_url in sitemap_urls:
            try:
                self.logger.debug(f"Fetching sitemap from {sitemap_url}")
                response = self.requester.get(sitemap_url, timeout=15)
                
                if response and response.status_code == 200:
                    sitemap_data['found'].append(sitemap_url)
                    
                    # Parse XML content
                    urls = self._parse_sitemap_xml(response.text)
                    sitemap_data['urls'].extend(urls)
                    
                    self.logger.debug(f"Found {len(urls)} URLs in {sitemap_url}")
                    
            except Exception as e:
                self.logger.debug(f"Failed to fetch sitemap from {sitemap_url}: {e}")
                continue
        
        # Remove duplicates and count
        sitemap_data['urls'] = list(set(sitemap_data['urls']))
        sitemap_data['total_urls'] = len(sitemap_data['urls'])
        
        return sitemap_data
    
    def _parse_sitemap_xml(self, xml_content: str) -> List[str]:
        """
        Parse sitemap XML content.
        
        Args:
            xml_content: Raw XML content
        
        Returns:
            List of URLs found in sitemap
        """
        urls = []
        
        try:
            root = ET.fromstring(xml_content)
            
            # Handle different sitemap formats
            # Standard sitemap
            for url_elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}url'):
                loc_elem = url_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                if loc_elem is not None and loc_elem.text:
                    urls.append(loc_elem.text.strip())
            
            # Sitemap index
            for sitemap_elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}sitemap'):
                loc_elem = sitemap_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                if loc_elem is not None and loc_elem.text:
                    # Recursively fetch nested sitemaps (limit depth to avoid infinite loops)
                    nested_urls = self._analyze_sitemaps([loc_elem.text.strip()])
                    urls.extend(nested_urls.get('urls', []))
            
            # Try without namespace if no URLs found
            if not urls:
                for url_elem in root.findall('.//url'):
                    loc_elem = url_elem.find('loc')
                    if loc_elem is not None and loc_elem.text:
                        urls.append(loc_elem.text.strip())
        
        except ET.ParseError as e:
            self.logger.debug(f"Failed to parse sitemap XML: {e}")
        except Exception as e:
            self.logger.debug(f"Error parsing sitemap: {e}")
        
        return urls
    
    def _categorize_paths(self, paths: List[str]) -> List[str]:
        """
        Categorize and filter interesting paths.
        
        Args:
            paths: List of paths to categorize
        
        Returns:
            List of interesting paths
        """
        interesting_paths = []
        
        for path in paths:
            # Skip very common/uninteresting paths
            if any(skip in path.lower() for skip in [
                'favicon.ico', 'robots.txt', '.css', '.js', '.png', '.jpg', '.gif',
                'google', 'facebook', 'twitter', 'linkedin'
            ]):
                continue
            
            # Extract path from full URL if needed
            if path.startswith('http'):
                parsed = urlparse(path)
                path = parsed.path
            
            if path and path not in interesting_paths:
                interesting_paths.append(path)
        
        return sorted(list(set(interesting_paths)))
    
    def _extract_api_endpoints(self, paths: List[str]) -> List[str]:
        """
        Extract potential API endpoints from paths.
        
        Args:
            paths: List of paths to analyze
        
        Returns:
            List of potential API endpoints
        """
        api_endpoints = []
        api_indicators = ['api', 'rest', 'graphql', 'json', 'xml', 'v1', 'v2', 'v3']
        
        for path in paths:
            path_lower = path.lower()
            if any(indicator in path_lower for indicator in api_indicators):
                api_endpoints.append(path)
        
        return api_endpoints
    
    def _extract_admin_paths(self, paths: List[str]) -> List[str]:
        """
        Extract potential admin/management paths.
        
        Args:
            paths: List of paths to analyze
        
        Returns:
            List of potential admin paths
        """
        admin_paths = []
        admin_indicators = [
            'admin', 'administrator', 'manage', 'management', 'control',
            'panel', 'dashboard', 'backend', 'cms', 'wp-admin', 'login'
        ]
        
        for path in paths:
            path_lower = path.lower()
            if any(indicator in path_lower for indicator in admin_indicators):
                admin_paths.append(path)
        
        return admin_paths
    
    def _extract_dev_paths(self, paths: List[str]) -> List[str]:
        """
        Extract potential development/staging paths.
        
        Args:
            paths: List of paths to analyze
        
        Returns:
            List of potential development paths
        """
        dev_paths = []
        dev_indicators = [
            'dev', 'development', 'test', 'testing', 'stage', 'staging',
            'beta', 'alpha', 'demo', 'sandbox', 'temp', 'tmp'
        ]
        
        for path in paths:
            path_lower = path.lower()
            if any(indicator in path_lower for indicator in dev_indicators):
                dev_paths.append(path)
        
        return dev_paths


def run_robots_and_sitemap_analysis(domain: str, logger: ScopexLogger, 
                                   requester: ScopexRequester) -> Dict[str, Any]:
    """
    Main function to run robots.txt and sitemap analysis.
    
    Args:
        domain: Target domain
        logger: Logger instance
        requester: HTTP requester instance
    
    Returns:
        Dictionary containing analysis results
    """
    analyzer = RobotsAndSitemapAnalyzer(logger, requester)
    return analyzer.analyze(domain)

