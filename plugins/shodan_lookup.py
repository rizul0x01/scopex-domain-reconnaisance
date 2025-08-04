# Author: rizul0x01
"""
Shodan lookup plugin for scopex.
Integrates with Shodan API to gather additional intelligence.
"""

import os
from typing import Dict, Any, List, Optional


def shodan_lookup(domain: str, logger, requester) -> Dict[str, Any]:
    """
    Perform Shodan lookup for domain and associated IPs.
    
    Args:
        domain: Target domain
        logger: Logger instance
        requester: HTTP requester instance
    
    Returns:
        Dictionary containing Shodan lookup results
    """
    logger.info(f"Running Shodan lookup for {domain}")
    
    results = {
        'shodan_available': False,
        'api_key_configured': False,
        'hosts': [],
        'open_ports': [],
        'services': [],
        'vulnerabilities': [],
        'total_results': 0
    }
    
    # Check if Shodan API key is available
    api_key = os.getenv('SHODAN_API_KEY') or _get_api_key_from_config()
    
    if not api_key:
        logger.warning("Shodan API key not configured")
        results['error'] = 'Shodan API key not configured'
        return results
    
    results['api_key_configured'] = True
    
    try:
        import shodan
        results['shodan_available'] = True
        
        # Initialize Shodan API
        api = shodan.Shodan(api_key)
        
        # Search for domain
        try:
            search_results = api.search(f'hostname:{domain}')
            results['total_results'] = search_results['total']
            
            # Process results
            for result in search_results['matches'][:10]:  # Limit to first 10 results
                host_info = _process_shodan_result(result)
                results['hosts'].append(host_info)
                
                # Collect unique ports and services
                if host_info['port'] not in results['open_ports']:
                    results['open_ports'].append(host_info['port'])
                
                if host_info['service'] and host_info['service'] not in results['services']:
                    results['services'].append(host_info['service'])
                
                # Collect vulnerabilities
                if host_info['vulns']:
                    results['vulnerabilities'].extend(host_info['vulns'])
            
            # Remove duplicate vulnerabilities
            results['vulnerabilities'] = list(set(results['vulnerabilities']))
            
            logger.info(f"Shodan found {len(results['hosts'])} hosts for {domain}")
            
        except shodan.APIError as e:
            logger.error(f"Shodan API error: {e}")
            results['error'] = str(e)
        
    except ImportError:
        logger.warning("Shodan library not available")
        results['error'] = 'Shodan library not installed'
    except Exception as e:
        logger.error(f"Shodan lookup failed: {e}")
        results['error'] = str(e)
    
    return results


def _get_api_key_from_config() -> Optional[str]:
    """
    Get Shodan API key from configuration file.
    
    Returns:
        API key or None
    """
    try:
        import yaml
        
        config_path = 'config/settings.yaml'
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                return config.get('api_keys', {}).get('shodan')
    except Exception:
        pass
    
    return None


def _process_shodan_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process a single Shodan search result.
    
    Args:
        result: Raw Shodan result
    
    Returns:
        Processed host information
    """
    host_info = {
        'ip': result.get('ip_str', ''),
        'port': result.get('port', 0),
        'service': result.get('product', ''),
        'version': result.get('version', ''),
        'banner': result.get('data', '').strip()[:200],  # Limit banner length
        'location': {
            'country': result.get('location', {}).get('country_name', ''),
            'city': result.get('location', {}).get('city', ''),
            'org': result.get('org', '')
        },
        'vulns': [],
        'tags': result.get('tags', [])
    }
    
    # Extract vulnerabilities
    vulns = result.get('vulns', {})
    if vulns:
        host_info['vulns'] = list(vulns.keys())
    
    return host_info


def get_ip_info(ip: str, logger, api_key: str) -> Dict[str, Any]:
    """
    Get detailed information for a specific IP address.
    
    Args:
        ip: IP address to lookup
        logger: Logger instance
        api_key: Shodan API key
    
    Returns:
        IP information from Shodan
    """
    try:
        import shodan
        
        api = shodan.Shodan(api_key)
        host = api.host(ip)
        
        return {
            'ip': host['ip_str'],
            'hostnames': host.get('hostnames', []),
            'ports': host.get('ports', []),
            'vulns': list(host.get('vulns', {}).keys()),
            'os': host.get('os'),
            'org': host.get('org', ''),
            'isp': host.get('isp', ''),
            'country': host.get('country_name', ''),
            'city': host.get('city', ''),
            'last_update': host.get('last_update', '')
        }
    
    except Exception as e:
        logger.error(f"Failed to get IP info for {ip}: {e}")
        return {}


# Plugin entry point
def run_plugin(domain: str, logger, requester, **kwargs) -> Dict[str, Any]:
    """
    Plugin entry point for Shodan lookup.
    
    Args:
        domain: Target domain
        logger: Logger instance
        requester: HTTP requester instance
        **kwargs: Additional arguments (may contain DNS data with IPs)
    
    Returns:
        Plugin results
    """
    results = shodan_lookup(domain, logger, requester)
    
    # If DNS data is available, also lookup specific IPs
    dns_data = kwargs.get('dns_data')
    if dns_data and results.get('api_key_configured') and results.get('shodan_available'):
        api_key = os.getenv('SHODAN_API_KEY') or _get_api_key_from_config()
        
        if api_key:
            ip_results = []
            a_records = dns_data.get('A', [])
            
            for ip in a_records[:3]:  # Limit to first 3 IPs
                ip_info = get_ip_info(ip, logger, api_key)
                if ip_info:
                    ip_results.append(ip_info)
            
            if ip_results:
                results['ip_details'] = ip_results
    
    return results

