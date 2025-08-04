#!/usr/bin/env python3
"""
SCOPEX - Advanced Reconnaissance Tool for Red Teams and Penetration Testers
A comprehensive domain reconnaissance tool with multiple modules and plugins.
Author: rizul0x01
"""

import argparse
import sys
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.utils import ScopexLogger, ScopexRequester, normalize_domain, is_valid_domain, save_json_report, save_txt_report, calculate_risk_score
from core.subdomain_enum import SubdomainEnumerator
from core.dns_resolver import DNSResolver
from core.cert_inspector import CertificateInspector
from core.whois_lookup import WhoisLookup
from core.robots_and_sitemap import RobotsAndSitemapAnalyzer
from core.tech_stack_finger import TechStackFingerprinter
from core.vuln_checker import VulnerabilityChecker
from core.service_detector import ServiceDetector
from core.file_extractor import FileExtractor
from core.owasp_checker import OWASPChecker


def print_header():
    """Display the SCOPEX ASCII art header."""
    GREEN = "\033[92m"
    RESET = "\033[0m"
    header = f"""{GREEN}
+-------------------------------------------------------------------+
|                  |S|C|O|P|E|X| |A|D|V|A|N|C|E| |S|C|A|N|N|E|R| |v1.0|     |
+-------------------------------------------------------------------+
|                                               [ by rizul0x01 ]                           |
+-------------------------------------------------------------------+
{RESET}"""
    print(header)


class ScopexRunner:
    """Main application runner for scopex."""
    
    def __init__(self, args):
        self.args = args
        self.domain = normalize_domain(args.domain)
        self.logger = ScopexLogger(
            log_file=args.log_file if hasattr(args, 'log_file') else "output/logs/debug.log",
            verbose=args.verbose
        )
        self.requester = ScopexRequester(self.logger)
        self.results = {}
    
    def run(self) -> Dict[str, Any]:
        """
        Run the complete reconnaissance workflow.
        
        Returns:
            Complete results dictionary
        """
        self.logger.info(f"Starting SCOPEX reconnaissance for {self.domain}")
        
        # Validate domain
        if not is_valid_domain(self.domain):
            self.logger.error(f"Invalid domain: {self.domain}")
            return {}
        
        # Initialize results structure
        self.results = {
            'domain': self.domain,
            'scan_date': datetime.now().isoformat(),
            'scan_options': {
                'deep': self.args.deep,
                'fast': getattr(self.args, 'fast', False),
                'plugins': getattr(self.args, 'plugins', [])
            },
            'subdomains': [],
            'dns': {},
            'ssl': {},
            'whois': {},
            'robots': [],
            'tech': [],
            'apis': [],
            'vulns': [],
            'plugins': {},
            'risk_score': 0
        }
        
        # Run core modules
        self._run_subdomain_enumeration()
        self._run_dns_resolution()
        self._run_certificate_inspection()
        self._run_whois_lookup()
        self._run_service_detection()
        
        # Run additional modules (to be implemented)
        if not getattr(self.args, 'fast', False):
            self._run_robots_and_sitemap()
            self._run_tech_stack_fingerprinting()
            self._run_vulnerability_checking()
            self._run_file_extraction()
            self._run_owasp_checks()
        
        # Load and run plugins
        if hasattr(self.args, 'plugins') and self.args.plugins:
            self._run_plugins()
        
        # Calculate risk score
        self.results['risk_score'] = calculate_risk_score(self.results)
        
        # Generate reports
        self._generate_reports()
        
        self.logger.info(f"SCOPEX reconnaissance completed for {self.domain}")
        return self.results
    
    def _run_subdomain_enumeration(self):
        """Run subdomain enumeration module."""
        try:
            self.logger.info("Running subdomain enumeration...")
            subdomain_enumerator = SubdomainEnumerator(self.logger, self.requester)
            subdomain_results = subdomain_enumerator.run(self.domain, self.args.deep)
            self.results["subdomains"] = subdomain_results.get("subdomains", [])
            self.logger.info(f"Found {len(self.results["subdomains"])} subdomains")
        except Exception as e:
            self.logger.error(f"Subdomain enumeration failed: {e}")
    
    def _run_dns_resolution(self):
        """Run DNS resolution module."""
        try:
            self.logger.info("Running DNS resolution...")
            dns_resolver = DNSResolver(self.logger)
            dns_results = dns_resolver.resolve(self.domain)
            self.results["dns"] = dns_results
            
            # Add DNS security findings to vulnerabilities
            security_findings = dns_results.get("security_findings", [])
            self.results["vulns"].extend(security_findings)
            
            self.logger.info("DNS resolution completed")
        except Exception as e:
            self.logger.error(f"DNS resolution failed: {e}")
    
    def _run_certificate_inspection(self):
        """Run SSL certificate inspection module."""
        try:
            self.logger.info("Running certificate inspection...")
            cert_inspector = CertificateInspector(self.logger, self.requester)
            ssl_results = cert_inspector.inspect_certificate(self.domain)
            self.results["ssl"] = ssl_results
            self.logger.info("Certificate inspection completed")
        except Exception as e:
            self.logger.error(f"Certificate inspection failed: {e}")
      def _run_whois_lookup(self):
        """Run WHOIS lookup module."""
        try:
            self.logger.info("Running WHOIS lookup...")
            whois_lookup = WhoisLookup(self.logger)
            whois_results = whois_lookup.lookup(self.domain)
            self.results["whois"] = whois_results
            self.logger.info("WHOIS lookup completed")
        except Exception as e:
            self.logger.error(f"WHOIS lookup failed: {e}")s', [])
            self.results['vulns'].extend(security_findings)
            
            self.logger.info("WHOIS lookup completed")
        except Exception as e:
            self.logger.error(f"WHOIS lookup failed: {e}")
    
    def _run_service_detection(self):
        """Run service detection for subdomains."""
        try:
            self.logger.info("Running service detection...")
            subdomains_to_check = [self.domain] + self.results.get("subdomains", [])
            service_results = run_service_detection(subdomains_to_check, self.logger, self.requester)
            self.results["service_status"] = service_results
            self.logger.info("Service detection completed")
        except Exception as e:
            self.logger.error(f"Service detection failed: {e}")
    
    def _run_robots_and_sitemap(self):
        """Run robots.txt and sitemap analysis."""
        try:
            self.logger.info("Running robots.txt and sitemap analysis...")
            robots_results = run_robots_and_sitemap_analysis(self.domain, self.logger, self.requester)
            
            # Extract relevant data
            self.results['robots'] = robots_results.get('interesting_paths', [])
            self.results['apis'].extend(robots_results.get('api_endpoints', []))
            
            # Add admin and dev paths to vulnerabilities if found
            admin_paths = robots_results.get('admin_paths', [])
            dev_paths = robots_results.get('dev_paths', [])
            
            if admin_paths:
                self.results['vulns'].append(f"Admin paths exposed: {', '.join(admin_paths[:3])}")
            if dev_paths:
                self.results['vulns'].append(f"Development paths exposed: {', '.join(dev_paths[:3])}")
            
            self.logger.info("Robots.txt and sitemap analysis completed")
        except Exception as e:
            self.logger.error(f"Robots.txt and sitemap analysis failed: {e}")
    
    def _run_tech_stack_fingerprinting(self):
        """Run technology stack fingerprinting."""
        try:
            self.logger.info("Running technology stack fingerprinting...")
            tech_results = run_tech_stack_fingerprinting(self.domain, self.logger, self.requester)
            
            # Store tech stack data
            self.results['tech'] = tech_results.get('technologies', [])
            self.results['apis'].extend(tech_results.get('api_endpoints', []))
            
            # Store the full tech data for vulnerability checking
            self.tech_data = tech_results
            
            self.logger.info("Technology stack fingerprinting completed")
        except Exception as e:
            self.logger.error(f"Technology stack fingerprinting failed: {e}")
    
    def _run_vulnerability_checking(self):
        """Run vulnerability checking."""
        try:
            self.logger.info("Running vulnerability checking...")
            vuln_results = run_vulnerability_checking(
                self.domain, self.logger, self.requester,
                getattr(self, 'tech_data', None), self.results.get('dns', {})
            )
            
            # Add vulnerabilities to main results
            additional_vulns = vuln_results.get('vulnerabilities', [])
            self.results['vulns'].extend(additional_vulns)
            
            self.logger.info("Vulnerability checking completed")
        except Exception as e:
            self.logger.error(f"Vulnerability checking failed: {e}")

    def _run_file_extraction(self):
        """Run file extraction module."""
        if self.args.extract_files:
            try:
                self.logger.info(f"Running file extraction for types: {self.args.extract_files}...")
                file_extraction_results = run_file_extraction(
                    self.domain, self.args.extract_files, self.logger, self.requester
                )
                self.results["extracted_files"] = file_extraction_results
                self.logger.info("File extraction completed")
            except Exception as e:
                self.logger.error(f"File extraction failed: {e}")

    def _run_owasp_checks(self):
        """Run OWASP Top 10 vulnerability checks."""
        if self.args.owasp:
            try:
                self.logger.info("Running OWASP Top 10 checks...")
                owasp_results = run_owasp_top10_checks(
                    self.domain, self.logger, self.requester,
                    tech_data=getattr(self, 'tech_data', {}),
                    robots_data=self.results.get('robots', {})
                )
                self.results["owasp_top10"] = owasp_results.get("owasp_vulnerabilities", [])
                self.results["vulns"].extend(self.results["owasp_top10"])
                self.logger.info("OWASP Top 10 checks completed")
            except Exception as e:
                self.logger.error(f"OWASP Top 10 checks failed: {e}")
    
    def _run_plugins(self):
        """Load and run specified plugins."""
        try:
            self.logger.info(f"Running plugins: {self.args.plugins}")
            
            for plugin_name in self.args.plugins:
                try:
                    self.logger.debug(f"Loading plugin: {plugin_name}")
                    
                    # Import plugin module
                    plugin_module = __import__(f'plugins.{plugin_name}', fromlist=[plugin_name])
                    
                    # Run plugin
                    if hasattr(plugin_module, 'run_plugin'):
                        plugin_results = plugin_module.run_plugin(
                            self.domain, self.logger, self.requester,
                            dns_data=self.results.get('dns', {}),
                            tech_data=getattr(self, 'tech_data', {})
                        )
                        
                        self.results['plugins'][plugin_name] = plugin_results
                        self.logger.info(f"Plugin {plugin_name} completed successfully")
                    else:
                        self.logger.warning(f"Plugin {plugin_name} missing run_plugin function")
                
                except ImportError as e:
                    self.logger.error(f"Failed to import plugin {plugin_name}: {e}")
                except Exception as e:
                    self.logger.error(f"Plugin {plugin_name} execution failed: {e}")
            
            self.logger.info("Plugin execution completed")
        except Exception as e:
            self.logger.error(f"Plugin execution failed: {e}")
    
    def _generate_reports(self):
        """Generate JSON and TXT reports."""
        try:
            # Determine output paths
            if hasattr(self.args, 'out') and self.args.out:
                json_path = self.args.out
                txt_path = self.args.out.replace('.json', '.txt')
            else:
                json_path = f"output/reports/{self.domain}.json"
                txt_path = f"output/reports/{self.domain}.txt"
            
            # Save JSON report
            if save_json_report(self.results, json_path):
                self.logger.info(f"JSON report saved to {json_path}")
                if not self.args.verbose:
                    print(f"JSON report: {json_path}")
            
            # Save TXT report
            if save_txt_report(self.results, txt_path):
                self.logger.info(f"TXT report saved to {txt_path}")
                if not self.args.verbose:
                    print(f"TXT report: {txt_path}")
            
            # Print summary to console
            self._print_summary()
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
    
    def _print_summary(self):
        """Print summary to console."""
        if not self.args.verbose:
            print(f"\nSCOPEX Reconnaissance Summary for {self.domain}")
            print("=" * 50)
            print(f"Risk Score: {self.results['risk_score']}/100")
            print(f"Subdomains: {len(self.results['subdomains'])}")
            print(f"DNS Records: {sum(len(v) if isinstance(v, list) else 1 for v in self.results['dns'].values() if v)}")
            print(f"Vulnerabilities: {len(self.results['vulns'])}")
            
            if self.results['vulns']:
                print("\nKey Vulnerabilities:")
                for vuln in self.results['vulns'][:5]:  # Show first 5
                    print(f"  • {vuln}")
                if len(self.results['vulns']) > 5:
                    print(f"  ... and {len(self.results['vulns']) - 5} more")


def main():
    """Main entry point for scopex."""
    print_header()
    
    parser = argparse.ArgumentParser(
        description="SCOPEX - Advanced Reconnaissance Tool for Red Teams and Penetration Testers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py -d example.com
  python3 main.py -d example.com --deep --verbose
  python3 main.py -d example.com --plugins shodan,waf
  python3 main.py -d example.com --owasp --extract-files pdf,txt
        """
    )  
    # Required arguments
    parser.add_argument(
        '-d', '--domain',
        required=True,
        help='Target domain to reconnaissance'
    )
    
    # Optional arguments
    parser.add_argument(
        '--deep',
        action='store_true',
        help='Enable deep reconnaissance (slower but more comprehensive)'
    )
    
    parser.add_argument(
        '--fast',
        action='store_true',
        help='Fast mode - skip time-consuming modules'
    )
    
    parser.add_argument(
        '--out',
        help='Output file path for JSON report (default: output/reports/{domain}.json)'
    )
    
    parser.add_argument(
        '--plugins',
        help='Comma-separated list of plugins to run (e.g., waf_detector,shodan_lookup)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--log-file',
        default='output/logs/debug.log',
        help='Log file path (default: output/logs/debug.log)'
    )
    
    parser.add_argument(
        '--extract-files',
        help='Comma-separated list of file extensions to extract (e.g., pdf,txt,pptx)'
    )

    parser.add_argument(
        '--owasp',
        action='store_true',
        help='Enable OWASP Top 10 vulnerability checks'
    )
    
    args = parser.parse_args()
    
    # Process plugins argument
    if args.plugins:
        args.plugins = [p.strip() for p in args.plugins.split(",")]
    else:
        args.plugins = []

    # Process extract_files argument
    if args.extract_files:
        args.extract_files = [ext.strip() for ext in args.extract_files.split(",")]
    else:
        args.extract_files = []
    
    # Create output directories
    os.makedirs('output/reports', exist_ok=True)
    os.makedirs('output/logs', exist_ok=True)
    
    try:
        # Run scopex
        runner = ScopexRunner(args)
        results = runner.run()
        
        if results:
            sys.exit(0)
        else:
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

