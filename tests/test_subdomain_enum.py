# Author: rizul0x01
"""
Unit tests for subdomain enumeration module.
"""

import unittest
from unittest.mock import Mock, patch
import sys
import os

# Add core modules to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'core'))

from subdomain_enum import SubdomainEnumerator
from utils import ScopexLogger, ScopexRequester


class TestSubdomainEnumeration(unittest.TestCase):
    """Test cases for subdomain enumeration functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.logger = Mock(spec=ScopexLogger)
        self.requester = Mock(spec=ScopexRequester)
        self.enumerator = SubdomainEnumerator(self.logger, self.requester)
    
    def test_domain_validation(self):
        """Test domain validation logic."""
        # Valid domains
        self.assertTrue(self.enumerator._is_valid_subdomain('www.example.com', 'example.com'))
        self.assertTrue(self.enumerator._is_valid_subdomain('api.example.com', 'example.com'))
        
        # Invalid domains
        self.assertFalse(self.enumerator._is_valid_subdomain('example.com', 'example.com'))
        self.assertFalse(self.enumerator._is_valid_subdomain('notexample.com', 'example.com'))
        self.assertFalse(self.enumerator._is_valid_subdomain('*.example.com', 'example.com'))
    
    @patch('subdomain_enum.dns.resolver.Resolver')
    def test_dns_brute_force(self, mock_resolver):
        """Test DNS brute force functionality."""
        # Mock DNS resolver
        mock_resolver_instance = Mock()
        mock_resolver.return_value = mock_resolver_instance
        mock_resolver_instance.resolve.return_value = ['192.168.1.1']
        
        # Test DNS brute force
        self.enumerator._enumerate_dns_brute('example.com')
        
        # Verify DNS queries were made
        self.assertTrue(mock_resolver_instance.resolve.called)
    
    def test_crtsh_parsing(self):
        """Test crt.sh response parsing."""
        # Mock response data
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {'name_value': 'www.example.com\napi.example.com'},
            {'name_value': '*.example.com'}
        ]
        
        self.requester.get.return_value = mock_response
        
        # Test crt.sh enumeration
        self.enumerator._enumerate_crtsh('example.com')
        
        # Verify subdomains were found
        self.assertIn('www.example.com', self.enumerator.found_subdomains)
        self.assertIn('api.example.com', self.enumerator.found_subdomains)
        self.assertIn('example.com', self.enumerator.found_subdomains)  # Wildcard processed


if __name__ == '__main__':
    unittest.main()

