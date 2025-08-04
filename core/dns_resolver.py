# Author: rizul0x01
"""
DNS resolution module for scopex.
Resolves various DNS record types for domains and subdomains.
"""

import dns.resolver
import dns.reversename
from typing import Dict, List, Any, Optional
from .utils import ScopexLogger, normalize_domain


class DNSResolver:
    """DNS record resolution and analysis."""
    
    def __init__(self, logger: ScopexLogger):
        self.logger = logger
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 10
    
    def resolve_all_records(self, domain: str) -> Dict[str, Any]:
        """
        Resolve all common DNS record types for a domain.
        
        Args:
            domain: Target domain
        
        Returns:
            Dictionary containing all DNS records
        """
        domain = normalize_domain(domain)
        self.logger.info(f"Resolving DNS records for {domain}")
        
        results = {
            'domain': domain,
            'A': [],
            'AAAA': [],
            'MX': [],
            'NS': [],
            'TXT': [],
            'CNAME': [],
            'SOA': [],
            'PTR': [],
            'DMARC': [],
            'SPF': []
        }
        
        # Resolve each record type
        results['A'] = self._resolve_record(domain, 'A')
        results['AAAA'] = self._resolve_record(domain, 'AAAA')
        results['MX'] = self._resolve_mx_records(domain)
        results['NS'] = self._resolve_record(domain, 'NS')
        results['TXT'] = self._resolve_txt_records(domain)
        results['CNAME'] = self._resolve_record(domain, 'CNAME')
        results['SOA'] = self._resolve_soa_records(domain)
        
        # Resolve PTR records for A records
        if results['A']:
            results['PTR'] = self._resolve_ptr_records(results['A'])
        
        # Extract DMARC and SPF from TXT records
        results['DMARC'] = self._extract_dmarc_records(domain)
        results['SPF'] = self._extract_spf_records(results['TXT'])
        
        # Count total records found
        total_records = sum(len(records) for records in results.values() if isinstance(records, list))
        self.logger.info(f"Resolved {total_records} DNS records for {domain}")
        
        return results
    
    def _resolve_record(self, domain: str, record_type: str) -> List[str]:
        """
        Resolve a specific DNS record type.
        
        Args:
            domain: Target domain
            record_type: DNS record type (A, AAAA, NS, etc.)
        
        Returns:
            List of record values
        """
        try:
            self.logger.debug(f"Resolving {record_type} records for {domain}")
            answers = self.resolver.resolve(domain, record_type)
            records = [str(answer) for answer in answers]
            self.logger.debug(f"Found {len(records)} {record_type} records for {domain}")
            return records
        
        except dns.resolver.NXDOMAIN:
            self.logger.debug(f"Domain {domain} does not exist")
            return []
        except dns.resolver.NoAnswer:
            self.logger.debug(f"No {record_type} records found for {domain}")
            return []
        except dns.resolver.Timeout:
            self.logger.warning(f"DNS timeout resolving {record_type} for {domain}")
            return []
        except Exception as e:
            self.logger.error(f"Error resolving {record_type} for {domain}: {e}")
            return []
    
    def _resolve_mx_records(self, domain: str) -> List[Dict[str, Any]]:
        """
        Resolve MX records with priority information.
        
        Args:
            domain: Target domain
        
        Returns:
            List of MX record dictionaries
        """
        try:
            self.logger.debug(f"Resolving MX records for {domain}")
            answers = self.resolver.resolve(domain, 'MX')
            
            mx_records = []
            for answer in answers:
                mx_records.append({
                    'priority': answer.preference,
                    'exchange': str(answer.exchange).rstrip('.')
                })
            
            # Sort by priority
            mx_records.sort(key=lambda x: x['priority'])
            self.logger.debug(f"Found {len(mx_records)} MX records for {domain}")
            return mx_records
        
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            self.logger.debug(f"No MX records found for {domain}")
            return []
        except Exception as e:
            self.logger.error(f"Error resolving MX records for {domain}: {e}")
            return []
    
    def _resolve_txt_records(self, domain: str) -> List[str]:
        """
        Resolve TXT records and clean up the output.
        
        Args:
            domain: Target domain
        
        Returns:
            List of TXT record strings
        """
        try:
            self.logger.debug(f"Resolving TXT records for {domain}")
            answers = self.resolver.resolve(domain, 'TXT')
            
            txt_records = []
            for answer in answers:
                # Join multiple strings in TXT record and clean quotes
                txt_value = ''.join([s.decode('utf-8') if isinstance(s, bytes) else str(s) for s in answer.strings])
                txt_records.append(txt_value)
            
            self.logger.debug(f"Found {len(txt_records)} TXT records for {domain}")
            return txt_records
        
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            self.logger.debug(f"No TXT records found for {domain}")
            return []
        except Exception as e:
            self.logger.error(f"Error resolving TXT records for {domain}: {e}")
            return []
    
    def _resolve_soa_records(self, domain: str) -> List[Dict[str, Any]]:
        """
        Resolve SOA records with detailed information.
        
        Args:
            domain: Target domain
        
        Returns:
            List of SOA record dictionaries
        """
        try:
            self.logger.debug(f"Resolving SOA records for {domain}")
            answers = self.resolver.resolve(domain, 'SOA')
            
            soa_records = []
            for answer in answers:
                soa_records.append({
                    'mname': str(answer.mname).rstrip('.'),
                    'rname': str(answer.rname).rstrip('.'),
                    'serial': answer.serial,
                    'refresh': answer.refresh,
                    'retry': answer.retry,
                    'expire': answer.expire,
                    'minimum': answer.minimum
                })
            
            self.logger.debug(f"Found {len(soa_records)} SOA records for {domain}")
            return soa_records
        
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            self.logger.debug(f"No SOA records found for {domain}")
            return []
        except Exception as e:
            self.logger.error(f"Error resolving SOA records for {domain}: {e}")
            return []
    
    def _resolve_ptr_records(self, ip_addresses: List[str]) -> List[Dict[str, str]]:
        """
        Resolve PTR (reverse DNS) records for IP addresses.
        
        Args:
            ip_addresses: List of IP addresses
        
        Returns:
            List of PTR record dictionaries
        """
        ptr_records = []
        
        for ip in ip_addresses:
            try:
                self.logger.debug(f"Resolving PTR record for {ip}")
                reverse_name = dns.reversename.from_address(ip)
                answers = self.resolver.resolve(reverse_name, 'PTR')
                
                for answer in answers:
                    ptr_records.append({
                        'ip': ip,
                        'hostname': str(answer).rstrip('.')
                    })
                
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                self.logger.debug(f"No PTR record found for {ip}")
                continue
            except Exception as e:
                self.logger.debug(f"Error resolving PTR for {ip}: {e}")
                continue
        
        self.logger.debug(f"Found {len(ptr_records)} PTR records")
        return ptr_records
    
    def _extract_dmarc_records(self, domain: str) -> List[str]:
        """
        Extract DMARC records by querying _dmarc subdomain.
        
        Args:
            domain: Target domain
        
        Returns:
            List of DMARC record strings
        """
        dmarc_domain = f"_dmarc.{domain}"
        return self._resolve_txt_records(dmarc_domain)
    
    def _extract_spf_records(self, txt_records: List[str]) -> List[str]:
        """
        Extract SPF records from TXT records.
        
        Args:
            txt_records: List of TXT records
        
        Returns:
            List of SPF record strings
        """
        spf_records = []
        for record in txt_records:
            if record.startswith('v=spf1'):
                spf_records.append(record)
        
        return spf_records
    
    def analyze_dns_security(self, dns_data: Dict[str, Any]) -> List[str]:
        """
        Analyze DNS records for security issues.
        
        Args:
            dns_data: DNS resolution results
        
        Returns:
            List of security findings
        """
        findings = []
        
        # Check for missing SPF record
        if not dns_data.get('SPF'):
            findings.append("Missing SPF record - email spoofing possible")
        
        # Check for missing DMARC record
        if not dns_data.get('DMARC'):
            findings.append("Missing DMARC record - email authentication not enforced")
        
        # Check for wildcard DNS
        if any('*' in record for record in dns_data.get('A', [])):
            findings.append("Wildcard DNS detected - potential subdomain takeover risk")
        
        # Check for multiple MX records without proper priority
        mx_records = dns_data.get('MX', [])
        if len(mx_records) > 1:
            priorities = [mx['priority'] for mx in mx_records]
            if len(set(priorities)) != len(priorities):
                findings.append("Multiple MX records with same priority - mail delivery issues possible")
        
        # Check for suspicious TXT records
        txt_records = dns_data.get('TXT', [])
        for record in txt_records:
            if any(keyword in record.lower() for keyword in ['password', 'key', 'secret', 'token']):
                findings.append(f"Potentially sensitive information in TXT record: {record[:50]}...")
        
        return findings


def run_dns_resolution(domain: str, logger: ScopexLogger) -> Dict[str, Any]:
    """
    Main function to run DNS resolution.
    
    Args:
        domain: Target domain
        logger: Logger instance
    
    Returns:
        Dictionary containing DNS resolution results
    """
    resolver = DNSResolver(logger)
    dns_data = resolver.resolve_all_records(domain)
    
    # Add security analysis
    security_findings = resolver.analyze_dns_security(dns_data)
    dns_data['security_findings'] = security_findings
    
    return dns_data

