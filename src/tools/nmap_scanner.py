# src/tools/nmap_scanner.py

import asyncio
import subprocess
import json
import xml.etree.ElementTree as ET
from typing import Dict, List
from loguru import logger
from datetime import datetime

class NmapScanner:
    def __init__(self):
        self.nmap_path = '/usr/bin/nmap'
        logger.info("Nmap scanner initialized")
    
    async def scan(
        self,
        target: str,
        ports: str = "1-1000",
        scan_type: str = "quick"
    ) -> Dict:
        """
        Perform port scan
        
        Args:
            target: Target IP or hostname
            ports: Port range or specific ports
            scan_type: Type of scan (quick, full, stealth, version)
        
        Returns:
            Scan results dictionary
        """
        try:
            logger.info(f"Starting {scan_type} scan on {target}")
            
            # Build nmap command based on scan type
            if scan_type == "quick":
                args = ["-T4", "-F", "--open"]
            elif scan_type == "full":
                args = ["-T4", "-p-", "--open"]
            elif scan_type == "stealth":
                args = ["-sS", "-T2", f"-p{ports}", "--open"]
            elif scan_type == "version":
                args = ["-sV", f"-p{ports}", "--open"]
            else:
                args = ["-T4", f"-p{ports}", "--open"]
            
            # Execute nmap
            results = await self._execute_nmap(target, args)
            
            # Parse results
            parsed = self._parse_results(results, target)
            logger.info(f"Scan completed for {target}: {len(parsed['open_ports'])} open ports found")
            
            return parsed
            
        except Exception as e:
            logger.error(f"Scan error for {target}: {str(e)}")
            return {
                'target': target,
                'error': str(e),
                'open_ports': [],
                'scan_time': '0s'
            }
    
    async def _execute_nmap(self, target: str, args: List[str]) -> str:
        """Execute nmap command"""
        cmd = [self.nmap_path] + args + ["-oX", "-", target]
        
        logger.debug(f"Executing: {' '.join(cmd)}")
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            logger.error(f"Nmap error: {stderr.decode()}")
            raise Exception(f"Nmap failed: {stderr.decode()}")
        
        return stdout.decode()
    
    def _parse_results(self, xml_output: str, target: str) -> Dict:
        """Parse Nmap XML output"""
        open_ports = []
        scan_time = "0s"
        
        try:
            root = ET.fromstring(xml_output)
            
            # Get scan time
            runtime = root.get('elapsed')
            if runtime:
                scan_time = f"{runtime}s"
            
            # Parse hosts
            for host in root.findall('.//host'):
                # Check if host is up
                status = host.find('status')
                if status is not None and status.get('state') != 'up':
                    continue
                
                # Parse ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            service = port.find('service')
                            
                            port_info = {
                                'port': port.get('portid'),
                                'protocol': port.get('protocol'),
                                'service': service.get('name') if service is not None else 'unknown',
                                'version': service.get('version', '') if service is not None else '',
                                'product': service.get('product', '') if service is not None else '',
                                'extrainfo': service.get('extrainfo', '') if service is not None else ''
                            }
                            
                            open_ports.append(port_info)
        
        except ET.ParseError as e:
            logger.error(f"XML parse error: {str(e)}")
        
        return {
            'target': target,
            'scan_time': scan_time,
            'open_ports': open_ports,
            'status': 'completed',
            'timestamp': datetime.now().isoformat()
        }
