"""
Watermarking module for SCOPEX reconnaissance tool.
Adds author watermarks to various file types to prevent unauthorized copying.
Author: rizul0x01
"""

import os
import json
import yaml
import configparser
from typing import Dict, Any, Optional


class ScopexWatermark:
    """Watermarking utility for various file types."""
    
    def __init__(self, author: str = "rizul0x01"):
        self.author = author
        self.watermarks = {
            'python': f'# Author: {author}',
            'javascript': f'// Author: {author}',
            'html': f'<!-- Author: {author} -->',
            'css': f'/* Author: {author} */',
            'yaml': f'# Author: {author}',
            'json': f'"_author": "{author}"',
            'markdown': f'<!-- Author: {author} -->',
            'txt': f'Author: {author}',
            'ini': f'; Author: {author}',
            'xml': f'<!-- Author: {author} -->',
            'sql': f'-- Author: {author}',
            'shell': f'# Author: {author}',
            'dockerfile': f'# Author: {author}',
            'gitignore': f'# Author: {author}',
            'license': f'# Author: {author}',
            'readme': f'<!-- Author: {author} -->'
        }
    
    def add_watermark_to_file(self, filepath: str, file_type: Optional[str] = None) -> bool:
        """
        Add watermark to a specific file.
        
        Args:
            filepath: Path to the file
            file_type: Override file type detection
        
        Returns:
            True if watermark was added successfully
        """
        try:
            if not os.path.exists(filepath):
                return False
            
            # Detect file type if not provided
            if not file_type:
                file_type = self._detect_file_type(filepath)
            
            if file_type not in self.watermarks:
                return False
            
            # Read existing content
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check if watermark already exists
            if self.author in content:
                return True  # Already watermarked
            
            # Add watermark based on file type
            watermarked_content = self._add_watermark_by_type(content, file_type)
            
            # Write back to file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(watermarked_content)
            
            return True
            
        except Exception as e:
            print(f"Error watermarking {filepath}: {e}")
            return False
    
    def _detect_file_type(self, filepath: str) -> str:
        """Detect file type based on extension and content."""
        filename = os.path.basename(filepath).lower()
        
        # Extension-based detection
        if filename.endswith('.py'):
            return 'python'
        elif filename.endswith(('.js', '.jsx')):
            return 'javascript'
        elif filename.endswith(('.html', '.htm')):
            return 'html'
        elif filename.endswith('.css'):
            return 'css'
        elif filename.endswith(('.yml', '.yaml')):
            return 'yaml'
        elif filename.endswith('.json'):
            return 'json'
        elif filename.endswith(('.md', '.markdown')):
            return 'markdown'
        elif filename.endswith('.txt'):
            return 'txt'
        elif filename.endswith(('.ini', '.cfg', '.conf')):
            return 'ini'
        elif filename.endswith('.xml'):
            return 'xml'
        elif filename.endswith('.sql'):
            return 'sql'
        elif filename.endswith(('.sh', '.bash')):
            return 'shell'
        elif filename == 'dockerfile':
            return 'dockerfile'
        elif filename == '.gitignore':
            return 'gitignore'
        elif filename.startswith('license'):
            return 'license'
        elif filename.startswith('readme'):
            return 'readme'
        
        # Content-based detection for files without clear extensions
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline().strip()
                if first_line.startswith('#!/usr/bin/env python') or first_line.startswith('#!/usr/bin/python'):
                    return 'python'
                elif first_line.startswith('#!/bin/bash') or first_line.startswith('#!/bin/sh'):
                    return 'shell'
        except:
            pass
        
        return 'txt'  # Default fallback
    
    def _add_watermark_by_type(self, content: str, file_type: str) -> str:
        """Add watermark based on file type."""
        watermark = self.watermarks.get(file_type, self.watermarks['txt'])
        
        if file_type == 'json':
            # Special handling for JSON files
            try:
                data = json.loads(content)
                if isinstance(data, dict):
                    data['_author'] = self.author
                    return json.dumps(data, indent=2)
                else:
                    # If it's not a dict, add comment at the top
                    return f'// Author: {self.author}\n{content}'
            except:
                return f'// Author: {self.author}\n{content}'
        
        elif file_type == 'yaml':
            # Add watermark at the top for YAML
            return f'{watermark}\n{content}'
        
        elif file_type in ['python', 'shell', 'dockerfile']:
            # Check if file starts with shebang
            lines = content.split('\n')
            if lines and lines[0].startswith('#!'):
                # Insert watermark after shebang
                lines.insert(1, watermark)
                return '\n'.join(lines)
            else:
                # Add at the beginning
                return f'{watermark}\n{content}'
        
        elif file_type in ['html', 'xml']:
            # Add watermark after DOCTYPE or at the beginning
            if '<!DOCTYPE' in content:
                parts = content.split('>', 1)
                if len(parts) == 2:
                    return f'{parts[0]}>\n{watermark}\n{parts[1]}'
            return f'{watermark}\n{content}'
        
        elif file_type == 'css':
            # Add watermark at the top
            return f'{watermark}\n{content}'
        
        elif file_type == 'javascript':
            # Add watermark at the top
            return f'{watermark}\n{content}'
        
        elif file_type == 'markdown':
            # Add watermark at the top
            return f'{watermark}\n{content}'
        
        else:
            # Default: add at the beginning
            return f'{watermark}\n{content}'
    
    def watermark_directory(self, directory: str, recursive: bool = True) -> Dict[str, bool]:
        """
        Watermark all supported files in a directory.
        
        Args:
            directory: Directory path
            recursive: Whether to process subdirectories
        
        Returns:
            Dictionary mapping file paths to success status
        """
        results = {}
        
        if not os.path.exists(directory):
            return results
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                
                # Skip binary files and certain directories
                if self._should_skip_file(filepath):
                    continue
                
                results[filepath] = self.add_watermark_to_file(filepath)
            
            if not recursive:
                break
        
        return results
    
    def _should_skip_file(self, filepath: str) -> bool:
        """Check if file should be skipped for watermarking."""
        skip_dirs = {'.git', '__pycache__', 'node_modules', '.venv', 'venv', 'output'}
        skip_extensions = {'.pyc', '.pyo', '.exe', '.bin', '.so', '.dll', '.jpg', '.png', '.gif', '.pdf', '.zip', '.tar', '.gz'}
        
        # Check if file is in a skip directory
        path_parts = filepath.split(os.sep)
        if any(part in skip_dirs for part in path_parts):
            return True
        
        # Check file extension
        _, ext = os.path.splitext(filepath)
        if ext.lower() in skip_extensions:
            return True
        
        # Check if file is binary
        try:
            with open(filepath, 'rb') as f:
                chunk = f.read(1024)
                if b'\x00' in chunk:  # Null bytes indicate binary file
                    return True
        except:
            return True
        
        return False
    
    def remove_watermarks(self, directory: str) -> Dict[str, bool]:
        """
        Remove watermarks from files in a directory.
        
        Args:
            directory: Directory path
        
        Returns:
            Dictionary mapping file paths to success status
        """
        results = {}
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                
                if self._should_skip_file(filepath):
                    continue
                
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Remove lines containing the author watermark
                    lines = content.split('\n')
                    filtered_lines = [line for line in lines if self.author not in line]
                    
                    if len(filtered_lines) != len(lines):
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write('\n'.join(filtered_lines))
                        results[filepath] = True
                    else:
                        results[filepath] = False  # No watermark found
                        
                except Exception as e:
                    results[filepath] = False
        
        return results


def watermark_project(project_dir: str, author: str = "rizul0x01") -> None:
    """
    Convenience function to watermark an entire project.
    
    Args:
        project_dir: Project directory path
        author: Author name for watermarking
    """
    watermarker = ScopexWatermark(author)
    results = watermarker.watermark_directory(project_dir, recursive=True)
    
    success_count = sum(1 for success in results.values() if success)
    total_count = len(results)
    
    print(f"Watermarking completed: {success_count}/{total_count} files processed successfully")
    
    # Show failed files if any
    failed_files = [filepath for filepath, success in results.items() if not success]
    if failed_files:
        print(f"Failed to watermark {len(failed_files)} files:")
        for filepath in failed_files[:5]:  # Show first 5 failed files
            print(f"  - {filepath}")
        if len(failed_files) > 5:
            print(f"  ... and {len(failed_files) - 5} more")


if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) > 1:
        project_path = sys.argv[1]
        author = sys.argv[2] if len(sys.argv) > 2 else "rizul0x01"
        watermark_project(project_path, author)
    else:
        print("Usage: python watermark.py <project_directory> [author_name]")

