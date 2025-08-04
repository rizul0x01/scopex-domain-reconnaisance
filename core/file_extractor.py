# Author: rizul0x01
"""
File extractor module for scopex.
Extracts specific file types (e.g., .txt, .pdf, .pptx) from a target domain.
"""

import os
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urljoin
from collections import deque

from .utils import ScopexLogger, ScopexRequester, normalize_domain


class FileExtractor:
    """Extracts files of specified types from a domain by crawling links."""
    
    def __init__(self, logger: ScopexLogger, requester: ScopexRequester, output_dir: str = "output/extracted_files"):
        self.logger = logger
        self.requester = requester
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.extracted_files = []
        self.visited_urls = set()
        self.max_depth = 2  # Limit crawling depth to avoid excessive requests
        self.max_files_per_type = 10 # Limit number of files to extract per type
    
    def extract_files(self, domain: str, file_types: List[str]) -> Dict[str, Any]:
        """
        Extracts files of specified types from the target domain.
        
        Args:
            domain: Target domain.
            file_types: List of file extensions (e.g., ["pdf", "txt"]).
        
        Returns:
            Dictionary containing extracted file information.
        """
        domain = normalize_domain(domain)
        self.logger.info(f"Starting file extraction for {domain} (types: {', '.join(file_types)})")
        
        results = {
            "domain": domain,
            "extracted_files": [],
            "total_extracted": 0,
            "errors": []
        }
        
        # Normalize file types to include dot
        normalized_file_types = [f".{ft.lower()}" for ft in file_types]
        
        # Start crawling from the main domain
        start_url = f"https://{domain}"
        self._crawl_and_extract(start_url, domain, normalized_file_types, 0)
        
        results["extracted_files"] = self.extracted_files
        results["total_extracted"] = len(self.extracted_files)
        
        self.logger.info(f"Finished file extraction. Found {results['total_extracted']} files.")
        return results
    
    def _crawl_and_extract(self, url: str, base_domain: str, file_types: List[str], depth: int):
        """
        Recursively crawls URLs and extracts files.
        """
        if depth > self.max_depth or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        self.logger.debug(f"Crawling: {url} (Depth: {depth})")
        
        try:
            response = self.requester.get(url, timeout=10)
            if not response or response.status_code != 200 or not response.text:
                return
            
            content_type = response.headers.get("Content-Type", "").lower()
            
            # Check if the current URL is a file to be extracted
            file_extension = os.path.splitext(urlparse(url).path)[1].lower()
            if file_extension in file_types:
                self._save_file(url, response.content, file_extension[1:])
                if len([f for f in self.extracted_files if f.endswith(file_extension)]) >= self.max_files_per_type:
                    return # Stop extracting this type if limit reached
            
            # Parse HTML for links to crawl further
            if "text/html" in content_type:
                links = self._extract_links(response.text, url)
                for link in links:
                    # Only follow links within the same base domain
                    if normalize_domain(urlparse(link).netloc) == base_domain:
                        self._crawl_and_extract(link, base_domain, file_types, depth + 1)
        
        except Exception as e:
            self.logger.debug(f"Error crawling {url}: {e}")
    
    def _extract_links(self, html_content: str, base_url: str) -> List[str]:
        """
        Extracts all href links from HTML content.
        """
        from bs4 import BeautifulSoup
        links = []
        soup = BeautifulSoup(html_content, "html.parser")
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            full_url = urljoin(base_url, href)
            links.append(full_url)
        return links
    
    def _save_file(self, url: str, content: bytes, file_type: str):
        """
        Saves the extracted file to the output directory.
        """
        try:
            parsed_url = urlparse(url)
            filename = os.path.basename(parsed_url.path)
            if not filename:
                filename = f"index.{file_type}" # Default filename if path is empty
            
            # Ensure unique filename if it already exists
            base, ext = os.path.splitext(filename)
            counter = 1
            final_filename = filename
            while os.path.exists(os.path.join(self.output_dir, final_filename)):
                final_filename = f"{base}_{counter}{ext}"
                counter += 1

            file_path = os.path.join(self.output_dir, final_filename)
            with open(file_path, "wb") as f:
                f.write(content)
            self.extracted_files.append(file_path)
            self.logger.info(f"Extracted and saved: {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to save file {url}: {e}")


def run_file_extraction(domain: str, file_types: List[str], logger: ScopexLogger, 
                       requester: ScopexRequester, output_dir: str = "output/extracted_files") -> Dict[str, Any]:
    """
    Main function to run file extraction.
    
    Args:
        domain: Target domain.
        file_types: List of file extensions (e.g., ["pdf", "txt"]).
        logger: Logger instance.
        requester: HTTP requester instance.
        output_dir: Directory to save extracted files.
    
    Returns:
        Dictionary containing file extraction results.
    """
    extractor = FileExtractor(logger, requester, output_dir)
    return extractor.extract_files(domain, file_types)


