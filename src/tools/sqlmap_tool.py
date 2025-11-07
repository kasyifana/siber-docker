# src/tools/sqlmap_tool.py

import asyncio
import subprocess
import json
from typing import Dict
from loguru import logger

class SQLMapTool:
    def __init__(self):
        self.sqlmap_path = '/usr/bin/sqlmap'
        logger.info("SQLMap tool initialized")
    
    async def test(
        self,
        url: str,
        parameters: str = "",
        database: str = "auto"
    ) -> Dict:
        """
        Test for SQL injection vulnerabilities
        
        Args:
            url: Target URL
            parameters: Parameters to test (comma-separated)
            database: Database type
        
        Returns:
            Test results
        """
        try:
            # Build SQLMap command
            cmd = [
                self.sqlmap_path,
                '-u', url,
                '--batch',  # Non-interactive
                '--random-agent',
                '--level=1',
                '--risk=1',
                '--output-dir=/tmp/sqlmap',
                '--flush-session',
                '--fresh-queries'
            ]
            
            if parameters:
                cmd.extend(['-p', parameters])
            
            if database != 'auto':
                cmd.extend(['--dbms', database])
            
            # Run SQLMap
            logger.info(f"Running SQLMap on {url}")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode()
            
            # Parse results
            results = self._parse_output(output, url)
            
            if results['vulnerable']:
                logger.warning(f"SQL injection found on {url}")
            else:
                logger.info(f"No SQL injection found on {url}")
            
            return results
            
        except Exception as e:
            logger.error(f"SQLMap error for {url}: {str(e)}")
            return {
                'url': url,
                'error': str(e),
                'vulnerable': False,
                'vulnerabilities': []
            }
    
    def _parse_output(self, output: str, url: str) -> Dict:
        """Parse SQLMap output"""
        vulnerabilities = []
        vulnerable = False
        
        # Check for vulnerable indicators
        if 'is vulnerable' in output.lower():
            vulnerable = True
            
            # Extract vulnerable parameters
            lines = output.split('\n')
            current_param = None
            
            for line in lines:
                if 'Parameter:' in line:
                    current_param = line.split('Parameter:')[1].strip()
                
                if 'Type:' in line and current_param:
                    injection_type = line.split('Type:')[1].strip()
                    
                if 'Title:' in line and current_param:
                    title = line.split('Title:')[1].strip()
                    
                if 'Payload:' in line and current_param:
                    payload = line.split('Payload:')[1].strip()
                    
                    vulnerabilities.append({
                        'parameter': current_param,
                        'injection_type': injection_type if 'injection_type' in locals() else 'unknown',
                        'title': title if 'title' in locals() else 'SQL Injection',
                        'payload': payload,
                        'database': self._detect_database(output),
                        'risk_level': 'critical'
                    })
                    
                    current_param = None
        
        return {
            'url': url,
            'vulnerable': vulnerable,
            'vulnerabilities': vulnerabilities,
            'raw_output': output[:500]  # First 500 chars for reference
        }
    
    def _detect_database(self, output: str) -> str:
        """Detect database type from output"""
        db_patterns = {
            'mysql': r'MySQL',
            'postgresql': r'PostgreSQL',
            'mssql': r'Microsoft SQL Server',
            'oracle': r'Oracle',
            'sqlite': r'SQLite'
        }
        
        for db_type, pattern in db_patterns.items():
            if pattern in output:
                return db_type
        
        return 'unknown'