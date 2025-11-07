# src/tools/nikto_scanner.py

import asyncio
import subprocess
from typing import Dict
from loguru import logger
import re

class NiktoScanner:
    def __init__(self):
        self.nikto_path = '/usr/local/bin/nikto'
        logger.info("Nikto scanner initialized")
    
    async def scan(
        self,
        url: str,
        scan_depth: str = "standard"
    ) -> Dict:
        """
        Perform web vulnerability scan using Nikto
        
        Args:
            url: Target URL
            scan_depth: Depth of scan (quick, standard, thorough)
        
        Returns:
            Scan results
        """
        try:
            # Build Nikto command
            cmd = [
                self.nikto_path,
                '-h', url,
                '-Format', 'txt',
                '-nossl',  # Don't check SSL (we have separate tool)
            ]
            
            # Add tuning based on scan depth
            if scan_depth == "quick":
                cmd.extend(['-Tuning', '1,2,3'])
            elif scan_depth == "thorough":
                cmd.extend(['-Tuning', 'x'])
            else:  # standard
                cmd.extend(['-Tuning', '1,2,3,4,5,6'])
            
            # Add additional options
            cmd.extend([
                '-timeout', '10',
                '-maxtime', '300',  # 5 minutes max
            ])
            
            logger.info(f"Running Nikto scan on {url} with depth: {scan_depth}")
            
            # Run Nikto
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode()
            
            # Parse results
            results = self._parse_output(output, url)
            
            logger.info(f"Nikto scan completed: {results['vulnerability_count']} issues found")
            
            return results
            
        except Exception as e:
            logger.error(f"Nikto scan error for {url}: {str(e)}")
            return {
                'target': url,
                'error': str(e),
                'vulnerability_count': 0,
                'vulnerabilities': []
            }
    
    def _parse_output(self, output: str, url: str) -> Dict:
        """Parse Nikto scan output"""
        vulnerabilities = []
        
        # Split output into lines
        lines = output.split('\n')
        
        for line in lines:
            # Skip non-finding lines
            if not line.strip() or line.startswith('-') or line.startswith('+'):
                continue
            
            # Parse finding lines (usually start with + and contain OSVDB/CVE)
            if any(indicator in line for indicator in ['OSVDB', 'CVE', 'Cookie', 'Header', 'Method']):
                severity = self._determine_severity(line)
                
                vuln = {
                    'title': self._extract_title(line),
                    'description': line.strip(),
                    'path': self._extract_path(line, url),
                    'severity': severity,
                    'references': self._extract_references(line)
                }
                
                vulnerabilities.append(vuln)
        
        return {
            'target': url,
            'vulnerability_count': len(vulnerabilities),
            'vulnerabilities': vulnerabilities,
            'scan_depth': 'standard'
        }
    
    def _determine_severity(self, line: str) -> str:
        """Determine severity based on content"""
        line_lower = line.lower()
        
        # Critical indicators
        if any(word in line_lower for word in ['remote code execution', 'rce', 'shell', 'backdoor']):
            return 'critical'
        
        # High indicators
        if any(word in line_lower for word in ['sql injection', 'xss', 'csrf', 'authentication bypass', 'admin']):
            return 'high'
        
        # Medium indicators
        if any(word in line_lower for word in ['disclosure', 'exposed', 'misconfiguration', 'weak']):
            return 'medium'
        
        # Default to low
        return 'low'
    
    def _extract_title(self, line: str) -> str:
        """Extract vulnerability title from line"""
        # Try to extract title from common patterns
        
        # Pattern: + OSVDB-xxxx: Title here
        match = re.search(r'OSVDB-\d+:\s*(.+?)(?:\s*http|$)', line)
        if match:
            return match.group(1).strip()
        
        # Pattern: + CVE-xxxx: Title here
        match = re.search(r'CVE-\d+-\d+:\s*(.+?)(?:\s*http|$)', line)
        if match:
            return match.group(1).strip()
        
        # Otherwise, use first 50 chars
        clean_line = line.replace('+', '').strip()
        return clean_line[:50] + ('...' if len(clean_line) > 50 else '')
    
    def _extract_path(self, line: str, base_url: str) -> str:
        """Extract path from line"""
        # Try to find URL in line
        match = re.search(r'(https?://[^\s]+)', line)
        if match:
            return match.group(1)
        
        # Try to find path
        match = re.search(r'(/[^\s]+)', line)
        if match:
            return match.group(1)
        
        return base_url
    
    def _extract_references(self, line: str) -> list:
        """Extract CVE/OSVDB references"""
        references = []
        
        # Find OSVDB references
        osvdb_matches = re.findall(r'OSVDB-(\d+)', line)
        for osvdb in osvdb_matches:
            references.append(f"OSVDB-{osvdb}")
        
        # Find CVE references
        cve_matches = re.findall(r'(CVE-\d+-\d+)', line)
        references.extend(cve_matches)
        
        return references
