# Author: rizul0x01
"""
WAF (Web Application Firewall) detector plugin for scopex.
Detects the presence and type of WAF protecting the target.
"""

import re
from typing import Dict, Any, List, Optional


def detect_waf(domain: str, logger, requester) -> Dict[str, Any]:
    """
    Detect WAF presence and type.
    
    Args:
        domain: Target domain
        logger: Logger instance
        requester: HTTP requester instance
    
    Returns:
        Dictionary containing WAF detection results
    """
    logger.info(f"Running WAF detection for {domain}")
    
    results = {
        'waf_detected': False,
        'waf_type': None,
        'confidence': 'Low',
        'detection_methods': [],
        'bypass_suggestions': []
    }
    
    # Test URLs to trigger WAF responses
    test_urls = [
        f"https://{domain}",
        f"https://{domain}/?id=1'",  # SQL injection test
        f"https://{domain}/?q=<script>alert(1)</script>",  # XSS test
        f"https://{domain}/../../../etc/passwd",  # Path traversal test
    ]
    
    waf_signatures = _get_waf_signatures()
    
    for url in test_urls:
        try:
            response = requester.get(url, timeout=10)
            
            if response:
                # Check headers for WAF signatures
                waf_info = _check_headers_for_waf(response.headers, waf_signatures)
                if waf_info:
                    results.update(waf_info)
                    results['detection_methods'].append('HTTP Headers')
                    break
                
                # Check response content for WAF signatures
                if response.status_code in [403, 406, 429, 501, 503]:
                    waf_info = _check_content_for_waf(response.text, waf_signatures)
                    if waf_info:
                        results.update(waf_info)
                        results['detection_methods'].append('Response Content')
                        break
        
        except Exception as e:
            logger.debug(f"WAF detection request failed for {url}: {e}")
            continue
    
    # Add bypass suggestions if WAF detected
    if results['waf_detected']:
        results['bypass_suggestions'] = _get_bypass_suggestions(results['waf_type'])
    
    logger.info(f"WAF detection completed - Detected: {results['waf_detected']}")
    return results


def _get_waf_signatures() -> Dict[str, Dict[str, List[str]]]:
    """
    Get WAF signatures for detection.
    
    Returns:
        Dictionary of WAF signatures
    """
    return {
        'Cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status', '__cfduid'],
            'content': ['cloudflare', 'attention required', 'ray id']
        },
        'AWS WAF': {
            'headers': ['x-amzn-requestid', 'x-amz-cf-id'],
            'content': ['aws', 'request blocked']
        },
        'Akamai': {
            'headers': ['akamai-ghost-ip', 'ak-lb'],
            'content': ['akamai', 'reference #']
        },
        'Incapsula': {
            'headers': ['x-iinfo', 'incap_ses'],
            'content': ['incapsula', 'request unsuccessful']
        },
        'Sucuri': {
            'headers': ['x-sucuri-id', 'x-sucuri-cache'],
            'content': ['sucuri', 'access denied']
        },
        'ModSecurity': {
            'headers': ['mod_security'],
            'content': ['mod_security', 'not acceptable']
        },
        'Barracuda': {
            'headers': ['barra'],
            'content': ['barracuda', 'you have been blocked']
        },
        'F5 BIG-IP': {
            'headers': ['f5-ltm', 'bigipserver'],
            'content': ['f5', 'the requested url was rejected']
        },
        'Fortinet': {
            'headers': ['fortigate'],
            'content': ['fortinet', 'blocked by fortinet']
        },
        'Imperva': {
            'headers': ['x-iinfo'],
            'content': ['imperva', 'request blocked']
        }
    }


def _check_headers_for_waf(headers: Dict[str, str], signatures: Dict[str, Dict[str, List[str]]]) -> Optional[Dict[str, Any]]:
    """
    Check HTTP headers for WAF signatures.
    
    Args:
        headers: HTTP response headers
        signatures: WAF signatures
    
    Returns:
        WAF detection results or None
    """
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    
    for waf_name, waf_sigs in signatures.items():
        for header_sig in waf_sigs['headers']:
            if any(header_sig in header_name or header_sig in header_value 
                   for header_name, header_value in headers_lower.items()):
                return {
                    'waf_detected': True,
                    'waf_type': waf_name,
                    'confidence': 'High'
                }
    
    return None


def _check_content_for_waf(content: str, signatures: Dict[str, Dict[str, List[str]]]) -> Optional[Dict[str, Any]]:
    """
    Check response content for WAF signatures.
    
    Args:
        content: HTTP response content
        signatures: WAF signatures
    
    Returns:
        WAF detection results or None
    """
    content_lower = content.lower()
    
    for waf_name, waf_sigs in signatures.items():
        for content_sig in waf_sigs['content']:
            if content_sig in content_lower:
                return {
                    'waf_detected': True,
                    'waf_type': waf_name,
                    'confidence': 'Medium'
                }
    
    return None


def _get_bypass_suggestions(waf_type: str) -> List[str]:
    """
    Get bypass suggestions for detected WAF.
    
    Args:
        waf_type: Type of WAF detected
    
    Returns:
        List of bypass suggestions
    """
    bypass_suggestions = {
        'Cloudflare': [
            'Try different HTTP methods (PUT, PATCH, DELETE)',
            'Use case variation in payloads',
            'Try encoding payloads (URL, HTML, Unicode)',
            'Use different User-Agent headers'
        ],
        'AWS WAF': [
            'Try parameter pollution',
            'Use different content types',
            'Fragment payloads across parameters',
            'Try HTTP/2 requests'
        ],
        'ModSecurity': [
            'Use comment-based evasion',
            'Try different encoding methods',
            'Use whitespace manipulation',
            'Fragment SQL keywords'
        ],
        'Incapsula': [
            'Try IP rotation',
            'Use different request timing',
            'Try payload obfuscation',
            'Use legitimate traffic patterns'
        ]
    }
    
    return bypass_suggestions.get(waf_type, [
        'Try payload encoding and obfuscation',
        'Use different HTTP methods and headers',
        'Fragment payloads across multiple parameters',
        'Try timing-based evasion techniques'
    ])


# Plugin entry point
def run_plugin(domain: str, logger, requester, **kwargs) -> Dict[str, Any]:
    """
    Plugin entry point for WAF detection.
    
    Args:
        domain: Target domain
        logger: Logger instance
        requester: HTTP requester instance
        **kwargs: Additional arguments
    
    Returns:
        Plugin results
    """
    return detect_waf(domain, logger, requester)

