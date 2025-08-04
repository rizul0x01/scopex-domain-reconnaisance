    def _run_whois_lookup(self):
        """Run WHOIS lookup module."""
        try:
            self.logger.info("Running WHOIS lookup...")
            whois_lookup = WhoisLookup(self.logger)
            whois_results = whois_lookup.lookup_domain(self.domain)
            self.results["whois"] = whois_results
            self.logger.info("WHOIS lookup completed")
        except Exception as e:
            self.logger.error(f"WHOIS lookup failed: {e}")
    
    def _run_service_detection(self):
        """Run service detection module."""
        try:
            self.logger.info("Running service detection...")
            service_detector = ServiceDetector(self.logger, self.requester)
            service_results = service_detector.detect_services(self.domain, self.results.get("subdomains", []))
            self.results["service_status"] = service_results
            self.logger.info("Service detection completed")
        except Exception as e:
            self.logger.error(f"Service detection failed: {e}")

