# Author: rizul0x01
"""
WHOIS lookup module for scopex.
Performs WHOIS lookups to retrieve domain registration information.
"""

import whois
import datetime
from typing import Dict, Any, Optional
from .utils import ScopexLogger, normalize_domain


class WhoisLookup:
    """WHOIS information retrieval and analysis."""
    
    def __init__(self, logger: ScopexLogger):
        self.logger = logger
    
    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """
        Perform WHOIS lookup for a domain.
        
        Args:
            domain: Target domain
        
        Returns:
            Dictionary containing WHOIS information
        """
        domain = normalize_domain(domain)
        self.logger.info(f"Performing WHOIS lookup for {domain}")
        
        results = {
            'domain': domain,
            'whois_found': False,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'name_servers': [],
            'registrant_name': None,
            'registrant_organization': None,
            'registrant_country': None,
            'admin_email': None,
            'tech_email': None,
            'status': [],
            'days_until_expiry': None,
            'domain_age_days': None,
            'privacy_protected': False,
            'security_findings': []
        }
        
        try:
            # Perform WHOIS lookup
            whois_data = whois.whois(domain)
            
            if whois_data:
                results.update(self._parse_whois_data(whois_data))
                results['whois_found'] = True
                
                # Analyze for security issues
                results['security_findings'] = self._analyze_whois_security(results)
                
                self.logger.info(f"WHOIS lookup successful for {domain}")
            else:
                self.logger.warning(f"No WHOIS data found for {domain}")
        
        except Exception as e:
            self.logger.error(f"WHOIS lookup failed for {domain}: {e}")
        
        return results
    
    def _parse_whois_data(self, whois_data) -> Dict[str, Any]:
        """
        Parse WHOIS data into structured format.
        
        Args:
            whois_data: Raw WHOIS data object
        
        Returns:
            Parsed WHOIS information
        """
        parsed = {}
        
        try:
            # Registrar information
            parsed['registrar'] = self._extract_string_field(whois_data.registrar)
            
            # Dates
            creation_date = self._extract_date_field(whois_data.creation_date)
            expiration_date = self._extract_date_field(whois_data.expiration_date)
            updated_date = self._extract_date_field(whois_data.updated_date)
            
            parsed['creation_date'] = creation_date.isoformat() if creation_date else None
            parsed['expiration_date'] = expiration_date.isoformat() if expiration_date else None
            parsed['updated_date'] = updated_date.isoformat() if updated_date else None
            
            # Calculate domain age and days until expiry
            if creation_date:
                domain_age = datetime.datetime.now() - creation_date
                parsed['domain_age_days'] = domain_age.days
            
            if expiration_date:
                days_until_expiry = (expiration_date - datetime.datetime.now()).days
                parsed['days_until_expiry'] = days_until_expiry
            
            # Name servers
            name_servers = whois_data.name_servers
            if name_servers:
                if isinstance(name_servers, list):
                    parsed['name_servers'] = [ns.lower() for ns in name_servers if ns]
                else:
                    parsed['name_servers'] = [name_servers.lower()]
            
            # Registrant information
            parsed['registrant_name'] = self._extract_string_field(whois_data.name)
            parsed['registrant_organization'] = self._extract_string_field(whois_data.org)
            parsed['registrant_country'] = self._extract_string_field(whois_data.country)
            
            # Contact emails
            parsed['admin_email'] = self._extract_string_field(whois_data.admin_email)
            parsed['tech_email'] = self._extract_string_field(whois_data.tech_email)
            
            # Domain status
            status = whois_data.status
            if status:
                if isinstance(status, list):
                    parsed['status'] = status
                else:
                    parsed['status'] = [status]
            
            # Check for privacy protection
            parsed['privacy_protected'] = self._check_privacy_protection(whois_data)
            
        except Exception as e:
            self.logger.error(f"Error parsing WHOIS data: {e}")
        
        return parsed
    
    def _extract_string_field(self, field) -> Optional[str]:
        """
        Extract string value from WHOIS field.
        
        Args:
            field: WHOIS field value
        
        Returns:
            String value or None
        """
        if not field:
            return None
        
        if isinstance(field, list):
            # Return first non-empty value
            for item in field:
                if item and str(item).strip():
                    return str(item).strip()
            return None
        
        return str(field).strip() if str(field).strip() else None
    
    def _extract_date_field(self, field) -> Optional[datetime.datetime]:
        """
        Extract datetime value from WHOIS field.
        
        Args:
            field: WHOIS date field
        
        Returns:
            Datetime object or None
        """
        if not field:
            return None
        
        if isinstance(field, list):
            # Return first valid date
            for item in field:
                if isinstance(item, datetime.datetime):
                    return item
            return None
        
        if isinstance(field, datetime.datetime):
            return field
        
        return None
    
    def _check_privacy_protection(self, whois_data) -> bool:
        """
        Check if domain has privacy protection enabled.
        
        Args:
            whois_data: Raw WHOIS data
        
        Returns:
            True if privacy protection is detected
        """
        privacy_indicators = [
            'privacy', 'protected', 'proxy', 'whoisguard', 'private',
            'redacted', 'contact privacy', 'domains by proxy'
        ]
        
        # Check various fields for privacy indicators
        fields_to_check = [
            whois_data.registrant_name if hasattr(whois_data, 'registrant_name') else whois_data.name,
            whois_data.org,
            whois_data.admin_email,
            whois_data.tech_email
        ]
        
        for field in fields_to_check:
            if field:
                field_str = str(field).lower()
                if any(indicator in field_str for indicator in privacy_indicators):
                    return True
        
        return False
    
    def _analyze_whois_security(self, whois_data: Dict[str, Any]) -> list[str]:
        """
        Analyze WHOIS data for security concerns.
        
        Args:
            whois_data: Parsed WHOIS data
        
        Returns:
            List of security findings
        """
        findings = []
        
        # Check for domain expiry
        days_until_expiry = whois_data.get('days_until_expiry')
        if days_until_expiry is not None:
            if days_until_expiry <= 0:
                findings.append("Domain has expired")
            elif days_until_expiry <= 30:
                findings.append(f"Domain expires in {days_until_expiry} days")
            elif days_until_expiry <= 90:
                findings.append(f"Domain expires in {days_until_expiry} days - consider renewal")
        
        # Check domain age
        domain_age_days = whois_data.get('domain_age_days')
        if domain_age_days is not None and domain_age_days < 30:
            findings.append(f"Very new domain (registered {domain_age_days} days ago)")
        
        # Check for suspicious registrar patterns
        registrar = whois_data.get('registrar', '').lower()
        suspicious_registrars = ['namecheap', 'godaddy']  # Common for malicious domains
        if any(susp in registrar for susp in suspicious_registrars):
            # Note: This is just an example - these are legitimate registrars
            # In practice, you'd check against known malicious registrars
            pass
        
        # Check for missing contact information
        if not whois_data.get('admin_email') and not whois_data.get('tech_email'):
            findings.append("No contact email addresses found")
        
        # Check domain status for locks
        status_list = whois_data.get('status', [])
        if not any('lock' in status.lower() for status in status_list):
            findings.append("Domain not locked - vulnerable to unauthorized transfers")
        
        # Check for privacy protection (not necessarily bad, but worth noting)
        if whois_data.get('privacy_protected'):
            findings.append("Domain has privacy protection enabled")
        
        return findings


def run_whois_lookup(domain: str, logger: ScopexLogger) -> Dict[str, Any]:
    """
    Main function to run WHOIS lookup.
    
    Args:
        domain: Target domain
        logger: Logger instance
    
    Returns:
        Dictionary containing WHOIS lookup results
    """
    whois_lookup = WhoisLookup(logger)
    return whois_lookup.lookup_domain(domain)

