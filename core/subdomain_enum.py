# Author: rizul0x01
"""
Subdomain enumeration module for scopex.
Discovers subdomains using passive techniques and public APIs.
"""

import json
import re
import time
from typing import List, Set, Dict, Any
from urllib.parse import urlparse
import dns.resolver
from .utils import ScopexLogger, ScopexRequester, normalize_domain


class SubdomainEnumerator:
    """Passive subdomain enumeration using multiple sources."""
    
    def __init__(self, logger: ScopexLogger, requester: ScopexRequester):
        self.logger = logger
        self.requester = requester
        self.found_subdomains: Set[str] = set()
    
    def enumerate(self, domain: str, deep: bool = False) -> List[str]:
        """
        Main enumeration function.
        
        Args:
            domain: Target domain
            deep: Enable deep enumeration (more sources, slower)
        
        Returns:
            List of discovered subdomains
        """
        domain = normalize_domain(domain)
        self.logger.info(f"Starting subdomain enumeration for {domain}")
        
        # Clear previous results
        self.found_subdomains.clear()
        
        # Run enumeration methods
        self._enumerate_crtsh(domain)
        self._enumerate_virustotal(domain)
        self._enumerate_hackertarget(domain)
        
        if deep:
            self._enumerate_dns_brute(domain)
            self._enumerate_certificate_transparency(domain)
        
        # Convert to sorted list and validate
        subdomains = sorted(list(self.found_subdomains))
        validated_subdomains = self._validate_subdomains(subdomains)
        
        self.logger.info(f"Found {len(validated_subdomains)} valid subdomains for {domain}")
        return validated_subdomains
    
    def _enumerate_crtsh(self, domain: str) -> None:
        """Enumerate subdomains using crt.sh certificate transparency logs."""
        self.logger.debug(f"Querying crt.sh for {domain}")
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = self.requester.get(url, timeout=15)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        # Handle multiple domains in one entry
                        for subdomain in name_value.split('\n'):
                            subdomain = subdomain.strip().lower()
                            if subdomain and domain in subdomain:
                                # Remove wildcards
                                subdomain = subdomain.replace('*.', '')
                                if self._is_valid_subdomain(subdomain, domain):
                                    self.found_subdomains.add(subdomain)
                    
                    self.logger.debug(f"crt.sh found {len([s for s in self.found_subdomains if domain in s])} subdomains")
                except json.JSONDecodeError:
                    self.logger.warning("Failed to parse crt.sh JSON response")
            else:
                self.logger.warning(f"crt.sh request failed with status {response.status_code if response else 'None'}")
        
        except Exception as e:
            self.logger.error(f"Error querying crt.sh: {e}")
    
    def _enumerate_virustotal(self, domain: str) -> None:
        """Enumerate subdomains using VirusTotal public API."""
        self.logger.debug(f"Querying VirusTotal for {domain}")
        
        try:
            # Note: This uses the public interface, not the API key version
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {'domain': domain, 'apikey': 'public'}
            
            response = self.requester.get(url, params=params, timeout=10)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    subdomains = data.get('subdomains', [])
                    for subdomain in subdomains:
                        if self._is_valid_subdomain(subdomain, domain):
                            self.found_subdomains.add(subdomain.lower())
                    
                    self.logger.debug(f"VirusTotal found {len(subdomains)} subdomains")
                except json.JSONDecodeError:
                    self.logger.warning("Failed to parse VirusTotal JSON response")
        
        except Exception as e:
            self.logger.debug(f"VirusTotal enumeration failed (expected for public API): {e}")
    
    def _enumerate_hackertarget(self, domain: str) -> None:
        """Enumerate subdomains using HackerTarget API."""
        self.logger.debug(f"Querying HackerTarget for {domain}")
        
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            response = self.requester.get(url, timeout=10)
            
            if response and response.status_code == 200:
                lines = response.text.strip().split('\n')
                for line in lines:
                    if ',' in line:
                        subdomain = line.split(',')[0].strip().lower()
                        if self._is_valid_subdomain(subdomain, domain):
                            self.found_subdomains.add(subdomain)
                
                self.logger.debug(f"HackerTarget found subdomains in {len(lines)} lines")
        
        except Exception as e:
            self.logger.error(f"Error querying HackerTarget: {e}")
    
    def _enumerate_certificate_transparency(self, domain: str) -> None:
        """Additional certificate transparency sources."""
        self.logger.debug(f"Querying additional CT logs for {domain}")
        
        # Censys CT search (public interface)
        try:
            url = f"https://censys.io/api/v1/search/certificates"
            # This would require API key for full functionality
            # For now, we'll skip this or implement a web scraping approach
            pass
        except Exception as e:
            self.logger.debug(f"Certificate transparency enumeration failed: {e}")
    
    def _enumerate_dns_brute(self, domain: str) -> None:
        """DNS brute force enumeration using common subdomain names."""
        self.logger.debug(f"Starting DNS brute force for {domain}")
        
        # Common subdomain wordlist
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'test', 'staging',
            'dev', 'development', 'prod', 'production', 'admin', 'administrator', 'api',
            'blog', 'shop', 'forum', 'support', 'help', 'docs', 'documentation', 'wiki',
            'mobile', 'm', 'app', 'apps', 'secure', 'ssl', 'vpn', 'remote', 'demo',
            'beta', 'alpha', 'preview', 'cdn', 'static', 'assets', 'media', 'images',
            'img', 'js', 'css', 'files', 'download', 'downloads', 'upload', 'uploads'
        ]
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        for subdomain_name in common_subdomains:
            try:
                full_domain = f"{subdomain_name}.{domain}"
                answers = resolver.resolve(full_domain, 'A')
                if answers:
                    self.found_subdomains.add(full_domain.lower())
                    self.logger.debug(f"DNS brute force found: {full_domain}")
                
                # Small delay to avoid overwhelming DNS servers
                time.sleep(0.1)
                
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                continue
            except Exception as e:
                self.logger.debug(f"DNS resolution error for {subdomain_name}.{domain}: {e}")
        
        self.logger.debug("DNS brute force enumeration completed")
    
    def _is_valid_subdomain(self, subdomain: str, domain: str) -> bool:
        """
        Validate if a subdomain is valid and belongs to the target domain.
        
        Args:
            subdomain: Subdomain to validate
            domain: Target domain
        
        Returns:
            True if valid
        """
        if not subdomain or not domain:
            return False
        
        # Must end with the target domain
        if not subdomain.endswith(domain):
            return False
        
        # Must be longer than the domain (have a subdomain part)
        if len(subdomain) <= len(domain):
            return False
        
        # Must have a dot before the domain
        if not subdomain[:-len(domain)].endswith('.'):
            return False
        
        # Basic format validation
        if not re.match(r'^[a-zA-Z0-9.-]+$', subdomain):
            return False
        
        # Avoid obvious false positives
        if any(char in subdomain for char in ['*', ' ', '\t', '\n']):
            return False
        
        return True
    
    def _validate_subdomains(self, subdomains: List[str]) -> List[str]:
        """
        Validate subdomains by attempting DNS resolution.
        
        Args:
            subdomains: List of subdomains to validate
        
        Returns:
            List of validated subdomains
        """
        validated = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        
        for subdomain in subdomains:
            try:
                # Try to resolve A record
                answers = resolver.resolve(subdomain, 'A')
                if answers:
                    validated.append(subdomain)
                    self.logger.debug(f"Validated subdomain: {subdomain}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                self.logger.debug(f"Could not validate subdomain: {subdomain}")
                continue
            except Exception as e:
                self.logger.debug(f"DNS validation error for {subdomain}: {e}")
                continue
        
        return validated


def run_subdomain_enumeration(domain: str, logger: ScopexLogger, requester: ScopexRequester, 
                             deep: bool = False) -> Dict[str, Any]:
    """
    Main function to run subdomain enumeration.
    
    Args:
        domain: Target domain
        logger: Logger instance
        requester: HTTP requester instance
        deep: Enable deep enumeration
    
    Returns:
        Dictionary containing enumeration results
    """
    enumerator = SubdomainEnumerator(logger, requester)
    subdomains = enumerator.enumerate(domain, deep)
    
    return {
        'subdomains': subdomains,
        'count': len(subdomains),
        'deep_scan': deep
    }

