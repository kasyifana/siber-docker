# src/tools/zap_tool.py

import asyncio
import subprocess
from typing import Dict, List
from loguru import logger
import json
import time

class ZAPTool:
    def __init__(self):
        self.zap_path = '/opt/ZAP_2.14.0/zap.sh'
        self.api_key = 'changeme'
        self.zap_port = 8090
        logger.info("ZAP tool initialized")
    
    async def scan(
        self,
        url: str,
        scan_type: str = "quick",
        spider: bool = True
    ) -> Dict:
        """
        Perform web application scan using OWASP ZAP
        
        Args:
            url: Target URL
            scan_type: Type of scan (quick, full, api)
            spider: Whether to spider the application first
        
        Returns:
            Scan results
        """
        try:
            logger.info(f"Starting ZAP scan on {url}")
            
            # Start ZAP daemon
            zap_process = await self._start_zap_daemon()
            
            # Wait for ZAP to start
            await asyncio.sleep(10)
            
            # Access target
            await self._access_url(url)
            
            # Spider if requested
            if spider:
                await self._spider(url)
            
            # Active scan
            if scan_type in ['full', 'active']:
                await self._active_scan(url)
            
            # Get alerts
            alerts = await self._get_alerts()
            
            # Stop ZAP
            await self._stop_zap()
            
            # Parse results
            results = self._parse_alerts(alerts, url)
            
            logger.info(f"ZAP scan completed: {len(results['vulnerabilities'])} issues found")
            
            return results
            
        except Exception as e:
            logger.error(f"ZAP scan error for {url}: {str(e)}")
            return {
                'target': url,
                'error': str(e),
                'vulnerabilities': []
            }
    
    async def _start_zap_daemon(self) -> asyncio.subprocess.Process:
        """Start ZAP in daemon mode"""
        try:
            cmd = [
                self.zap_path,
                '-daemon',
                '-port', str(self.zap_port),
                '-config', f'api.key={self.api_key}',
                '-config', 'api.addrs.addr.name=.*',
                '-config', 'api.addrs.addr.regex=true'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            logger.info("ZAP daemon started")
            return process
            
        except Exception as e:
            logger.error(f"Failed to start ZAP: {str(e)}")
            raise
    
    async def _access_url(self, url: str):
        """Access URL through ZAP"""
        cmd = [
            'curl',
            '-x', f'http://localhost:{self.zap_port}',
            url
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        await process.communicate()
    
    async def _spider(self, url: str):
        """Spider the target"""
        try:
            # Start spider using ZAP API
            cmd = [
                'curl',
                f'http://localhost:{self.zap_port}/JSON/spider/action/scan/',
                '-d', f'url={url}',
                '-d', f'apikey={self.api_key}'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await process.communicate()
            
            # Wait for spider to complete
            await asyncio.sleep(30)
            
            logger.info(f"Spider completed for {url}")
            
        except Exception as e:
            logger.error(f"Spider error: {str(e)}")
    
    async def _active_scan(self, url: str):
        """Perform active scan"""
        try:
            # Start active scan using ZAP API
            cmd = [
                'curl',
                f'http://localhost:{self.zap_port}/JSON/ascan/action/scan/',
                '-d', f'url={url}',
                '-d', f'apikey={self.api_key}'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await process.communicate()
            
            # Wait for scan to complete
            await asyncio.sleep(60)
            
            logger.info(f"Active scan completed for {url}")
            
        except Exception as e:
            logger.error(f"Active scan error: {str(e)}")
    
    async def _get_alerts(self) -> List[Dict]:
        """Get alerts from ZAP"""
        try:
            cmd = [
                'curl',
                f'http://localhost:{self.zap_port}/JSON/core/view/alerts/',
                '-d', f'apikey={self.api_key}'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await process.communicate()
            
            data = json.loads(stdout.decode())
            return data.get('alerts', [])
            
        except Exception as e:
            logger.error(f"Failed to get alerts: {str(e)}")
            return []
    
    async def _stop_zap(self):
        """Stop ZAP daemon"""
        try:
            cmd = [
                'curl',
                f'http://localhost:{self.zap_port}/JSON/core/action/shutdown/',
                '-d', f'apikey={self.api_key}'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await process.communicate()
            logger.info("ZAP daemon stopped")
            
        except Exception as e:
            logger.error(f"Failed to stop ZAP: {str(e)}")
    
    def _parse_alerts(self, alerts: List[Dict], url: str) -> Dict:
        """Parse ZAP alerts"""
        vulnerabilities = []
        
        severity_map = {
            '3': 'high',
            '2': 'medium',
            '1': 'low',
            '0': 'info'
        }
        
        for alert in alerts:
            vuln = {
                'title': alert.get('alert', 'Unknown'),
                'description': alert.get('description', ''),
                'severity': severity_map.get(alert.get('risk', '0'), 'low'),
                'confidence': alert.get('confidence', ''),
                'url': alert.get('url', url),
                'parameter': alert.get('param', ''),
                'evidence': alert.get('evidence', ''),
                'solution': alert.get('solution', ''),
                'reference': alert.get('reference', ''),
                'cwe_id': alert.get('cweid', ''),
                'wasc_id': alert.get('wascid', '')
            }
            
            vulnerabilities.append(vuln)
        
        return {
            'target': url,
            'vulnerabilities': vulnerabilities,
            'vulnerability_count': len(vulnerabilities)
        }
