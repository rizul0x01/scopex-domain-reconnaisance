# Author: rizul0x01
"""
SSL certificate inspection module for scopex.
Inspects SSL certificates for security issues and gathers certificate information.
"""

import ssl
import socket
import json
import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from .utils import ScopexLogger, ScopexRequester, normalize_domain


class CertificateInspector:
    """SSL certificate inspection and analysis."""
    
    def __init__(self, logger: ScopexLogger, requester: ScopexRequester):
        self.logger = logger
        self.requester = requester
    
    def inspect_certificate(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """
        Inspect SSL certificate for a domain.
        
        Args:
            domain: Target domain
            port: SSL port (default 443)
        
        Returns:
            Dictionary containing certificate information
        """
        domain = normalize_domain(domain)
        self.logger.info(f"Inspecting SSL certificate for {domain}:{port}")
        
        results = {
            'domain': domain,
            'port': port,
            'certificate_found': False,
            'valid': False,
            'expired': False,
            'self_signed': False,
            'weak_signature': False,
            'issuer': None,
            'subject': None,
            'serial_number': None,
            'version': None,
            'not_before': None,
            'not_after': None,
            'days_until_expiry': None,
            'san_domains': [],
            'key_size': None,
            'signature_algorithm': None,
            'vulnerabilities': [],
            'crt_sh_data': []
        }
        
        # Get certificate via direct SSL connection
        cert_data = self._get_certificate_direct(domain, port)
        if cert_data:
            results.update(cert_data)
        
        # Get additional certificate data from crt.sh
        crt_sh_data = self._get_crtsh_data(domain)
        if crt_sh_data:
            results['crt_sh_data'] = crt_sh_data
        
        # Analyze certificate for vulnerabilities
        if results['certificate_found']:
            results['vulnerabilities'] = self._analyze_certificate_security(results)
        
        return results
    
    def _get_certificate_direct(self, domain: str, port: int) -> Optional[Dict[str, Any]]:
        """
        Get certificate information via direct SSL connection.
        
        Args:
            domain: Target domain
            port: SSL port
        
        Returns:
            Certificate information dictionary or None
        """
        try:
            self.logger.debug(f"Connecting to {domain}:{port} for certificate")
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((domain, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cert_der = ssock.getpeercert(binary_form=True)
                    
                    if not cert:
                        self.logger.warning(f"No certificate found for {domain}:{port}")
                        return None
                    
                    return self._parse_certificate_data(cert, cert_der)
        
        except socket.timeout:
            self.logger.warning(f"Connection timeout to {domain}:{port}")
            return None
        except socket.gaierror:
            self.logger.warning(f"DNS resolution failed for {domain}")
            return None
        except ssl.SSLError as e:
            self.logger.warning(f"SSL error connecting to {domain}:{port}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error getting certificate for {domain}:{port}: {e}")
            return None
    
    def _parse_certificate_data(self, cert: Dict, cert_der: bytes) -> Dict[str, Any]:
        """
        Parse certificate data from SSL connection.
        
        Args:
            cert: Certificate dictionary from SSL connection
            cert_der: Certificate in DER format
        
        Returns:
            Parsed certificate information
        """
        try:
            # Parse dates
            not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            now = datetime.datetime.now()
            
            # Calculate days until expiry
            days_until_expiry = (not_after - now).days
            
            # Extract Subject Alternative Names
            san_domains = []
            if 'subjectAltName' in cert:
                for san_type, san_value in cert['subjectAltName']:
                    if san_type == 'DNS':
                        san_domains.append(san_value)
            
            # Parse subject and issuer
            subject = dict(x[0] for x in cert['subject'])
            issuer = dict(x[0] for x in cert['issuer'])
            
            # Determine if certificate is valid
            is_valid = not_before <= now <= not_after
            is_expired = now > not_after
            is_self_signed = subject.get('commonName') == issuer.get('commonName')
            
            return {
                'certificate_found': True,
                'valid': is_valid,
                'expired': is_expired,
                'self_signed': is_self_signed,
                'issuer': issuer.get('organizationName', issuer.get('commonName', 'Unknown')),
                'subject': subject.get('commonName', 'Unknown'),
                'serial_number': cert.get('serialNumber'),
                'version': cert.get('version'),
                'not_before': not_before.isoformat(),
                'not_after': not_after.isoformat(),
                'days_until_expiry': days_until_expiry,
                'san_domains': san_domains,
                'signature_algorithm': cert.get('signatureAlgorithm', 'Unknown')
            }
        
        except Exception as e:
            self.logger.error(f"Error parsing certificate data: {e}")
            return {'certificate_found': False}
    
    def _get_crtsh_data(self, domain: str) -> List[Dict[str, Any]]:
        """
        Get certificate data from crt.sh certificate transparency logs.
        
        Args:
            domain: Target domain
        
        Returns:
            List of certificate entries from crt.sh
        """
        try:
            self.logger.debug(f"Querying crt.sh for certificate data on {domain}")
            
            url = f"https://crt.sh/?q={domain}&output=json"
            response = self.requester.get(url, timeout=15)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    
                    # Process and deduplicate entries
                    processed_certs = []
                    seen_serials = set()
                    
                    for entry in data[:10]:  # Limit to first 10 entries
                        serial = entry.get('serial_number')
                        if serial and serial not in seen_serials:
                            seen_serials.add(serial)
                            
                            processed_certs.append({
                                'id': entry.get('id'),
                                'serial_number': serial,
                                'not_before': entry.get('not_before'),
                                'not_after': entry.get('not_after'),
                                'issuer_name': entry.get('issuer_name'),
                                'common_name': entry.get('common_name'),
                                'name_value': entry.get('name_value')
                            })
                    
                    self.logger.debug(f"Found {len(processed_certs)} unique certificates in crt.sh")
                    return processed_certs
                
                except json.JSONDecodeError:
                    self.logger.warning("Failed to parse crt.sh JSON response")
                    return []
            else:
                self.logger.warning(f"crt.sh request failed with status {response.status_code if response else 'None'}")
                return []
        
        except Exception as e:
            self.logger.error(f"Error querying crt.sh: {e}")
            return []
    
    def _analyze_certificate_security(self, cert_data: Dict[str, Any]) -> List[str]:
        """
        Analyze certificate for security vulnerabilities.
        
        Args:
            cert_data: Certificate information
        
        Returns:
            List of security findings
        """
        vulnerabilities = []
        
        # Check if certificate is expired
        if cert_data.get('expired'):
            vulnerabilities.append("Certificate is expired")
        
        # Check if certificate expires soon
        days_until_expiry = cert_data.get('days_until_expiry', 0)
        if 0 < days_until_expiry <= 30:
            vulnerabilities.append(f"Certificate expires in {days_until_expiry} days")
        
        # Check for self-signed certificate
        if cert_data.get('self_signed'):
            vulnerabilities.append("Self-signed certificate detected")
        
        # Check for weak signature algorithms
        signature_algorithm = cert_data.get('signature_algorithm', '').lower()
        if any(weak_alg in signature_algorithm for weak_alg in ['md5', 'sha1']):
            vulnerabilities.append(f"Weak signature algorithm: {signature_algorithm}")
        
        # Check for missing SAN domains
        san_domains = cert_data.get('san_domains', [])
        if not san_domains:
            vulnerabilities.append("No Subject Alternative Names (SAN) found")
        
        # Check for wildcard certificates
        subject = cert_data.get('subject', '')
        if subject.startswith('*.'):
            vulnerabilities.append("Wildcard certificate detected - potential security risk")
        
        # Check certificate version
        version = cert_data.get('version')
        if version and version < 3:
            vulnerabilities.append(f"Old certificate version: v{version}")
        
        return vulnerabilities
    
    def inspect_multiple_domains(self, domains: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Inspect certificates for multiple domains.
        
        Args:
            domains: List of domains to inspect
        
        Returns:
            Dictionary mapping domains to their certificate data
        """
        results = {}
        
        for domain in domains:
            self.logger.debug(f"Inspecting certificate for {domain}")
            results[domain] = self.inspect_certificate(domain)
        
        return results


def run_certificate_inspection(domain: str, logger: ScopexLogger, requester: ScopexRequester,
                             subdomains: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Main function to run certificate inspection.
    
    Args:
        domain: Target domain
        logger: Logger instance
        requester: HTTP requester instance
        subdomains: Optional list of subdomains to also inspect
    
    Returns:
        Dictionary containing certificate inspection results
    """
    inspector = CertificateInspector(logger, requester)
    
    # Inspect main domain
    main_cert = inspector.inspect_certificate(domain)
    
    results = {
        'main_domain': main_cert,
        'subdomains': {},
        'summary': {
            'total_inspected': 1,
            'certificates_found': 1 if main_cert['certificate_found'] else 0,
            'expired_certificates': 1 if main_cert.get('expired') else 0,
            'self_signed_certificates': 1 if main_cert.get('self_signed') else 0,
            'total_vulnerabilities': len(main_cert.get('vulnerabilities', []))
        }
    }
    
    # Inspect subdomains if provided
    if subdomains:
        # Limit to first 5 subdomains to avoid excessive requests
        limited_subdomains = subdomains[:5]
        subdomain_results = inspector.inspect_multiple_domains(limited_subdomains)
        results['subdomains'] = subdomain_results
        
        # Update summary
        results['summary']['total_inspected'] += len(limited_subdomains)
        for subdomain_cert in subdomain_results.values():
            if subdomain_cert['certificate_found']:
                results['summary']['certificates_found'] += 1
            if subdomain_cert.get('expired'):
                results['summary']['expired_certificates'] += 1
            if subdomain_cert.get('self_signed'):
                results['summary']['self_signed_certificates'] += 1
            results['summary']['total_vulnerabilities'] += len(subdomain_cert.get('vulnerabilities', []))
    
    return results

