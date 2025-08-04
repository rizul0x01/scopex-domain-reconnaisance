# Author: rizul0x01
"""
Shared utility functions for scopex reconnaissance tool.
Provides common HTTP request handling, logging, and helper functions.
"""

import requests
import logging
import random
import time
import os
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urljoin
import json


class ScopexLogger:
    """Centralized logging for scopex operations."""
    
    def __init__(self, log_file: str = "output/logs/debug.log", verbose: bool = False):
        self.verbose = verbose
        self.log_file = log_file
        
        # Ensure log directory exists
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler() if verbose else logging.NullHandler()
            ]
        )
        
        self.logger = logging.getLogger('scopex')
    
    def info(self, message: str):
        self.logger.info(message)
    
    def warning(self, message: str):
        self.logger.warning(message)
    
    def error(self, message: str):
        self.logger.error(message)
    
    def debug(self, message: str):
        self.logger.debug(message)


import requests
import time
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class ScopexRequester:
    def __init__(self, logger, max_retries=3, backoff_factor=2):
        self.logger = logger
        self.session = requests.Session()
        
        # Retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            raise_on_status=False
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def get(self, url, **kwargs):
        try:
            self.logger.debug(f"Making GET request to {url}")
            response = self.session.get(url, timeout=15, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"Request failed for {url}: {e}")
            return None

def normalize_domain(domain: str) -> str:
    """
    Normalize domain name by removing protocol and trailing slashes.
    
    Args:
        domain: Input domain (may include protocol)
    
    Returns:
        Normalized domain name
    """
    if '://' in domain:
        domain = urlparse(domain).netloc
    
    return domain.lower().strip('/')


def is_valid_domain(domain: str) -> bool:
    """
    Basic domain validation.
    
    Args:
        domain: Domain to validate
    
    Returns:
        True if domain appears valid
    """
    if not domain or len(domain) > 253:
        return False
    
    # Basic regex-like validation
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    
    for part in parts:
        if not part or len(part) > 63:
            return False
        if not part.replace('-', '').replace('_', '').isalnum():
            return False
    
    return True


def extract_domain_from_url(url: str) -> str:
    """
    Extract domain from URL.
    
    Args:
        url: Full URL
    
    Returns:
        Domain name
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except:
        return url


def save_json_report(data: Dict[str, Any], filepath: str) -> bool:
    """
    Save data as JSON report.
    
    Args:
        data: Data to save
        filepath: Output file path
    
    Returns:
        True if successful
    """
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        return True
    except Exception as e:
        print(f"Error saving JSON report: {e}")
        return False


def save_txt_report(data: Dict[str, Any], filepath: str) -> bool:
    """
    Save data as human-readable text report.
    
    Args:
        data: Data to save
        filepath: Output file path
    
    Returns:
        True if successful
    """
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        with open(filepath, 'w') as f:
            f.write(f"SCOPEX RECONNAISSANCE REPORT\n")
            f.write(f"{'=' * 50}\n\n")
            
            # Basic info
            f.write(f"Target Domain: {data.get('domain', 'N/A')}\n")
            f.write(f"Risk Score: {data.get('risk_score', 0)}/100\n")
            f.write(f"Scan Date: {data.get('scan_date', 'N/A')}\n\n")
            
            # Subdomains
            subdomains = data.get('subdomains', [])
            f.write(f"SUBDOMAINS ({len(subdomains)} found):\n")
            f.write("-" * 30 + "\n")
            for subdomain in subdomains:
                f.write(f"  • {subdomain}\n")
            f.write("\n")
            
            # DNS Records
            dns_data = data.get('dns', {})
            if dns_data:
                f.write("DNS RECORDS:\n")
                f.write("-" * 30 + "\n")
                for record_type, records in dns_data.items():
                    if records and record_type not in ['domain', 'security_findings']:
                        if isinstance(records, list):
                            if all(isinstance(r, str) for r in records):
                                f.write(f"  {record_type}: {', '.join(records)}\n")
                            else:
                                f.write(f"  {record_type}:\n")
                                for record in records:
                                    if isinstance(record, dict):
                                        f.write(f"    {record}\n")
                                    else:
                                        f.write(f"    {record}\n")
                        else:
                            f.write(f"  {record_type}: {records}\n")
                f.write("\n")
            
            # SSL Certificate
            ssl_data = data.get('ssl', {})
            if ssl_data:
                f.write("SSL CERTIFICATE:\n")
                f.write("-" * 30 + "\n")
                for key, value in ssl_data.items():
                    f.write(f"  {key.replace('_', ' ').title()}: {value}\n")
                f.write("\n")
            
            # WHOIS
            whois_data = data.get('whois', {})
            if whois_data:
                f.write("WHOIS INFORMATION:\n")
                f.write("-" * 30 + "\n")
                for key, value in whois_data.items():
                    f.write(f"  {key.replace('_', ' ').title()}: {value}\n")
                f.write("\n")
            
            # Technology Stack
            tech_data = data.get('tech', [])
            if tech_data:
                f.write(f"TECHNOLOGY STACK ({len(tech_data)} identified):\n")
                f.write("-" * 30 + "\n")
                for tech in tech_data:
                    f.write(f"  • {tech}\n")
                f.write("\n")
            
            # Robots.txt and Sitemap
            robots_data = data.get('robots', [])
            if robots_data:
                f.write(f"ROBOTS.TXT PATHS ({len(robots_data)} found):\n")
                f.write("-" * 30 + "\n")
                for path in robots_data:
                    f.write(f"  • {path}\n")
                f.write("\n")
            
            # API Endpoints
            api_data = data.get('apis', [])
            if api_data:
                f.write(f"API ENDPOINTS ({len(api_data)} detected):\n")
                f.write("-" * 30 + "\n")
                for api in api_data:
                    f.write(f"  • {api}\n")
                f.write("\n")
            
            # Vulnerabilities
            vulns_data = data.get('vulns', [])
            if vulns_data:
                f.write(f"VULNERABILITIES & MISCONFIGURATIONS ({len(vulns_data)} found):\n")
                f.write("-" * 30 + "\n")
                for vuln in vulns_data:
                    f.write(f"  ⚠ {vuln}\n")
                f.write("\n")
            
            # Plugin Results
            plugins_data = data.get('plugins', {})
            if plugins_data:
                f.write("PLUGIN RESULTS:\n")
                f.write("-" * 30 + "\n")
                for plugin_name, plugin_data in plugins_data.items():
                    f.write(f"  {plugin_name.upper()}:\n")
                    if isinstance(plugin_data, dict):
                        for key, value in plugin_data.items():
                            f.write(f"    {key}: {value}\n")
                    else:
                        f.write(f"    {plugin_data}\n")
                    f.write("\n")
        
        return True
    except Exception as e:
        print(f"Error saving TXT report: {e}")
        return False


def calculate_risk_score(data: Dict[str, Any]) -> int:
    """
    Calculate risk score based on findings.
    
    Args:
        data: Reconnaissance data
    
    Returns:
        Risk score (0-100)
    """
    score = 0
    
    # Base score for having subdomains (more attack surface)
    subdomains = data.get('subdomains', [])
    if len(subdomains) > 10:
        score += 20
    elif len(subdomains) > 5:
        score += 15
    elif len(subdomains) > 0:
        score += 10
    
    # Vulnerabilities add significant risk
    vulns = data.get('vulns', [])
    score += len(vulns) * 15
    
    # Exposed paths from robots.txt
    robots = data.get('robots', [])
    if any('admin' in path.lower() or 'dev' in path.lower() for path in robots):
        score += 10
    
    # Outdated technology
    tech = data.get('tech', [])
    for technology in tech:
        if any(keyword in technology.lower() for keyword in ['php/7', 'apache/2.2', 'nginx/1.1']):
            score += 10
    
    # SSL certificate issues
    ssl = data.get('ssl', {})
    if ssl.get('expired', False):
        score += 25
    
    # Cap at 100
    return min(score, 100)
