# src/server.py

from mcp.server.models import InitializationOptions
from mcp.server import Server
from mcp.types import TextContent, Tool
from typing import Any, Dict, List, Sequence
import asyncio
import logging
from loguru import logger

from .tools.nmap_scanner import NmapScanner
from .tools.sqlmap_tool import SQLMapTool
from .tools.nikto_scanner import NiktoScanner
from .tools.zap_tool import ZAPTool
from .tools.xss_tester import XSSTester
from .tools.subdomain_enum import SubdomainEnumerator
from .tools.ssl_checker import SSLChecker
from .tools.header_analyzer import HeaderAnalyzer
from .utils.validator import TargetValidator
from .utils.reporter import ReportGenerator
from .utils.logger import setup_logger
from .config.settings import settings

class SecurityAuditServer:
    def __init__(self):
        # Setup logger
        setup_logger(
            log_level=settings.LOG_LEVEL,
            log_file=settings.LOG_FILE,
            log_format=settings.LOG_FORMAT
        )
        
        self.server = Server("security-audit-server")
        self.validator = TargetValidator()
        self.reporter = ReportGenerator()
        
        # Initialize tools
        self.tools = {
            'nmap': NmapScanner(),
            'sqlmap': SQLMapTool(),
            'nikto': NiktoScanner(),
            'zap': ZAPTool(),
            'xss': XSSTester(),
            'subdomain': SubdomainEnumerator(),
            'ssl': SSLChecker(),
            'headers': HeaderAnalyzer()
        }
        
        self._register_handlers()
        logger.info("Security Audit Server initialized")
    
    def _register_handlers(self):
        """Register MCP handlers"""
        
        # Register list_tools handler
        @self.server.list_tools()
        async def handle_list_tools() -> list[Tool]:
            """Return list of available tools"""
            return [
                Tool(
                    name="port_scan",
                    description="Perform port scanning on target",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "IP address or hostname"},
                            "ports": {"type": "string", "description": "Port range", "default": "1-1000"},
                            "scan_type": {"type": "string", "description": "Scan type", "default": "quick"}
                        },
                        "required": ["target"]
                    }
                ),
                Tool(
                    name="sql_injection_test",
                    description="Test for SQL injection vulnerabilities",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "Target URL"},
                            "parameters": {"type": "string", "description": "Parameters to test", "default": ""},
                            "database": {"type": "string", "description": "Database type", "default": "auto"}
                        },
                        "required": ["url"]
                    }
                ),
                Tool(
                    name="web_vuln_scan",
                    description="Web vulnerability scan using Nikto",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "Target URL"},
                            "scan_depth": {"type": "string", "description": "Scan depth", "default": "standard"}
                        },
                        "required": ["url"]
                    }
                ),
                Tool(
                    name="xss_test",
                    description="Test for XSS vulnerabilities",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "Target URL"},
                            "parameters": {"type": "array", "items": {"type": "string"}},
                            "payload_type": {"type": "string", "default": "all"}
                        },
                        "required": ["url", "parameters"]
                    }
                ),
                Tool(
                    name="enumerate_subdomains",
                    description="Enumerate subdomains",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "domain": {"type": "string", "description": "Target domain"},
                            "method": {"type": "string", "default": "all"}
                        },
                        "required": ["domain"]
                    }
                ),
                Tool(
                    name="analyze_ssl",
                    description="Analyze SSL/TLS configuration",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "hostname": {"type": "string", "description": "Target hostname"},
                            "port": {"type": "integer", "default": 443}
                        },
                        "required": ["hostname"]
                    }
                ),
                Tool(
                    name="check_security_headers",
                    description="Check security headers",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "Target URL"}
                        },
                        "required": ["url"]
                    }
                ),
                Tool(
                    name="full_security_audit",
                    description="Comprehensive security audit",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Target URL or domain"},
                            "scope": {"type": "string", "default": "standard"}
                        },
                        "required": ["target"]
                    }
                ),
                Tool(
                    name="generate_report",
                    description="Generate scan report",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "scan_id": {"type": "string", "description": "Scan ID"},
                            "format": {"type": "string", "default": "markdown"}
                        },
                        "required": ["scan_id"]
                    }
                )
            ]
        
        # Register call_tool handler
        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: dict) -> Sequence[TextContent]:
            """Handle tool calls"""
            
            if name == "port_scan":
                return await self._port_scan(**arguments)
            elif name == "sql_injection_test":
                return await self._sql_injection_test(**arguments)
            elif name == "web_vuln_scan":
                return await self._web_vuln_scan(**arguments)
            elif name == "xss_test":
                return await self._xss_test(**arguments)
            elif name == "enumerate_subdomains":
                return await self._enumerate_subdomains(**arguments)
            elif name == "analyze_ssl":
                return await self._analyze_ssl(**arguments)
            elif name == "check_security_headers":
                return await self._check_security_headers(**arguments)
            elif name == "full_security_audit":
                return await self._full_security_audit(**arguments)
            elif name == "generate_report":
                return await self._generate_report(**arguments)
            else:
                raise ValueError(f"Unknown tool: {name}")
    
    # Tool implementations
    async def _port_scan(self, target: str, ports: str = "1-1000", scan_type: str = "quick") -> Sequence[TextContent]:
        """Port scanning implementation"""
        if not self.validator.validate_target(target):
            return [TextContent(type="text", text=f"Invalid target: {target}")]
        
        logger.info(f"Starting port scan on {target}")
        results = await self.tools['nmap'].scan(target, ports, scan_type)
        
        return [TextContent(type="text", text=self.format_port_scan_results(results))]
    
    async def _sql_injection_test(self, url: str, parameters: str = "", database: str = "auto") -> Sequence[TextContent]:
        """SQL injection testing implementation"""
        if not self.validator.validate_url(url):
            return [TextContent(type="text", text=f"Invalid URL: {url}")]
        
        logger.info(f"Testing SQL injection on {url}")
        results = await self.tools['sqlmap'].test(url, parameters, database)
        
        return [TextContent(type="text", text=self.format_sqli_results(results))]
    
    async def _web_vuln_scan(self, url: str, scan_depth: str = "standard") -> Sequence[TextContent]:
        """Web vulnerability scan implementation"""
        if not self.validator.validate_url(url):
            return [TextContent(type="text", text=f"Invalid URL: {url}")]
        
        logger.info(f"Starting web vulnerability scan on {url}")
        results = await self.tools['nikto'].scan(url, scan_depth)
        
        return [TextContent(type="text", text=self.format_nikto_results(results))]
    
    async def _xss_test(self, url: str, parameters: List[str], payload_type: str = "all") -> Sequence[TextContent]:
        """XSS testing implementation"""
        if not self.validator.validate_url(url):
            return [TextContent(type="text", text=f"Invalid URL: {url}")]
        
        logger.info(f"Testing XSS on {url}")
        results = await self.tools['xss'].test(url, parameters, payload_type)
        
        return [TextContent(type="text", text=self.format_xss_results(results))]
    
    async def _enumerate_subdomains(self, domain: str, method: str = "all") -> Sequence[TextContent]:
        """Subdomain enumeration implementation"""
        if not self.validator.validate_domain(domain):
            return [TextContent(type="text", text=f"Invalid domain: {domain}")]
        
        logger.info(f"Enumerating subdomains for {domain}")
        results = await self.tools['subdomain'].enumerate(domain, method)
        
        return [TextContent(type="text", text=self.format_subdomain_results(results))]
    
    async def _analyze_ssl(self, hostname: str, port: int = 443) -> Sequence[TextContent]:
        """SSL/TLS analysis implementation"""
        if not self.validator.validate_hostname(hostname):
            return [TextContent(type="text", text=f"Invalid hostname: {hostname}")]
        
        logger.info(f"Analyzing SSL/TLS for {hostname}:{port}")
        results = await self.tools['ssl'].analyze(hostname, port)
        
        return [TextContent(type="text", text=self.format_ssl_results(results))]
    
    async def _check_security_headers(self, url: str) -> Sequence[TextContent]:
        """Security headers check implementation"""
        if not self.validator.validate_url(url):
            return [TextContent(type="text", text=f"Invalid URL: {url}")]
        
        logger.info(f"Checking security headers for {url}")
        results = await self.tools['headers'].analyze(url)
        
        return [TextContent(type="text", text=self.format_header_results(results))]
    
    async def _full_security_audit(self, target: str, scope: str = "standard") -> Sequence[TextContent]:
        """Comprehensive audit implementation"""
        logger.info(f"Starting full security audit on {target}")
        
        tasks = [
            self.tools['headers'].analyze(target),
            self.tools['ssl'].analyze(target),
            self.tools['nmap'].scan(target),
            self.tools['nikto'].scan(target),
            self.tools['subdomain'].enumerate(target)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        report = self.reporter.generate_full_report(target=target, results=results, scope=scope)
        
        return [TextContent(type="text", text=report)]
    
    async def _generate_report(self, scan_id: str, format: str = "markdown") -> Sequence[TextContent]:
        """Report generation implementation"""
        logger.info(f"Generating report for scan {scan_id}")
        report = await self.reporter.generate(scan_id, format)
        
        return [TextContent(type="text", text=report)]
    
    # Format helper methods
    def format_port_scan_results(self, results: Dict) -> str:
        """Format port scan results"""
        output = f"# Port Scan Results\n\n"
        output += f"**Target:** {results.get('target', 'N/A')}\n"
        output += f"**Scan Time:** {results.get('scan_time', 'N/A')}\n\n"
        
        if results.get('open_ports'):
            output += "## Open Ports\n\n"
            for port in results['open_ports']:
                output += f"- **Port {port['port']}/{port['protocol']}**\n"
                output += f"  - Service: {port.get('service', 'Unknown')}\n"
                output += f"  - Version: {port.get('version', 'Unknown')}\n"
                if port.get('vulnerabilities'):
                    output += f"  - ⚠️ Known Vulnerabilities: {len(port['vulnerabilities'])}\n"
        else:
            output += "No open ports found.\n"
        
        return output
    
    def format_sqli_results(self, results: Dict) -> str:
        """Format SQL injection results"""
        output = f"# SQL Injection Test Results\n\n"
        output += f"**Target:** {results.get('url', 'N/A')}\n"
        output += f"**Vulnerable:** {'YES ⚠️' if results.get('vulnerable') else 'NO ✓'}\n\n"
        
        if results.get('vulnerable') and results.get('vulnerabilities'):
            output += "## Vulnerabilities Found\n\n"
            for vuln in results['vulnerabilities']:
                output += f"### {vuln.get('parameter', 'Unknown')}\n"
                output += f"- **Type:** {vuln.get('injection_type', 'Unknown')}\n"
                output += f"- **Database:** {vuln.get('database', 'Unknown')}\n"
                output += f"- **Payload:** `{vuln.get('payload', '')}`\n"
                output += f"- **Risk:** {vuln.get('risk_level', 'Unknown')}\n\n"
        
        return output
    
    def format_xss_results(self, results: Dict) -> str:
        """Format XSS test results"""
        output = f"# XSS Test Results\n\n"
        output += f"**Target:** {results.get('url', 'N/A')}\n"
        output += f"**Vulnerable:** {'YES ⚠️' if results.get('vulnerable') else 'NO ✓'}\n\n"
        
        if results.get('vulnerable') and results.get('vulnerabilities'):
            output += "## Vulnerabilities Found\n\n"
            for vuln in results['vulnerabilities']:
                output += f"### {vuln.get('type', 'Unknown')} XSS in {vuln.get('parameter', 'Unknown')}\n"
                output += f"- **Payload:** `{vuln.get('payload', '')}`\n"
                output += f"- **Context:** {vuln.get('context', 'Unknown')}\n"
                output += f"- **Severity:** {vuln.get('severity', 'Unknown')}\n\n"
        
        return output
    
    def format_subdomain_results(self, results: Dict) -> str:
        """Format subdomain enumeration results"""
        output = f"# Subdomain Enumeration Results\n\n"
        output += f"**Domain:** {results.get('domain', 'N/A')}\n"
        output += f"**Subdomains Found:** {len(results.get('subdomains', []))}\n\n"
        
        if results.get('subdomains'):
            output += "## Discovered Subdomains\n\n"
            for subdomain in results['subdomains']:
                output += f"- `{subdomain.get('name', 'Unknown')}`\n"
                output += f"  - IP: {subdomain.get('ip', 'N/A')}\n"
                output += f"  - Status: {subdomain.get('status', 'Unknown')}\n"
        
        return output
    
    def format_ssl_results(self, results: Dict) -> str:
        """Format SSL/TLS analysis results"""
        output = f"# SSL/TLS Analysis Results\n\n"
        output += f"**Hostname:** {results.get('hostname', 'N/A')}\n"
        output += f"**Grade:** {results.get('grade', 'N/A')}\n\n"
        
        if results.get('certificate'):
            output += "## Certificate Information\n"
            cert = results['certificate']
            output += f"- **Issuer:** {cert.get('issuer', 'N/A')}\n"
            output += f"- **Valid Until:** {cert.get('valid_until', 'N/A')}\n"
            output += f"- **Signature Algorithm:** {cert.get('signature_algorithm', 'N/A')}\n\n"
        
        if results.get('protocols'):
            output += "## Supported Protocols\n"
            for protocol in results['protocols']:
                output += f"- {protocol.get('name', 'Unknown')}: {protocol.get('status', 'Unknown')}\n"
        
        output += "\n## Issues Found\n"
        if results.get('issues'):
            for issue in results['issues']:
                output += f"- ⚠️ {issue}\n"
        else:
            output += "No issues found ✓\n"
        
        return output
    
    def format_header_results(self, results: Dict) -> str:
        """Format security headers analysis"""
        output = f"# Security Headers Analysis\n\n"
        output += f"**URL:** {results.get('url', 'N/A')}\n"
        output += f"**Score:** {results.get('score', 0)}/100\n\n"
        
        if results.get('headers'):
            output += "## Headers Status\n\n"
            for header, status in results['headers'].items():
                icon = "✓" if status.get('present') else "❌"
                output += f"{icon} **{header}**\n"
                if status.get('present'):
                    output += f"   Value: `{status.get('value', '')}`\n"
                    output += f"   Status: {status.get('assessment', 'N/A')}\n"
                else:
                    output += f"   Status: Missing\n"
                    output += f"   Impact: {status.get('impact', 'N/A')}\n"
                output += "\n"
        
        return output
    
    def format_nikto_results(self, results: Dict) -> str:
        """Format Nikto scan results"""
        output = f"# Web Vulnerability Scan Results\n\n"
        output += f"**Target:** {results.get('target', 'N/A')}\n"
        output += f"**Vulnerabilities Found:** {results.get('vulnerability_count', 0)}\n\n"
        
        if results.get('vulnerabilities'):
            # Group by severity
            critical = [v for v in results['vulnerabilities'] if v.get('severity') == 'critical']
            high = [v for v in results['vulnerabilities'] if v.get('severity') == 'high']
            medium = [v for v in results['vulnerabilities'] if v.get('severity') == 'medium']
            low = [v for v in results['vulnerabilities'] if v.get('severity') == 'low']
            
            if critical:
                output += "## Critical Issues\n\n"
                for vuln in critical:
                    output += f"- **{vuln.get('title', 'Unknown')}**\n"
                    output += f"  - Path: `{vuln.get('path', '')}`\n"
                    output += f"  - Description: {vuln.get('description', 'N/A')}\n\n"
            
            if high:
                output += "## High Issues\n\n"
                for vuln in high:
                    output += f"- **{vuln.get('title', 'Unknown')}**\n"
                    output += f"  - Path: `{vuln.get('path', '')}`\n\n"
            
            if medium:
                output += "## Medium Issues\n\n"
                for vuln in medium:
                    output += f"- {vuln.get('title', 'Unknown')}\n"
            
            if low:
                output += f"\n## Low Issues\n{len(low)} low severity issues found.\n"
        
        return output
    
    async def run(self):
        """Start the MCP server"""
        from mcp.server.stdio import stdio_server
        
        logger.info(f"Starting MCP Security Audit Server")
        
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="security-audit-server",
                    server_version="1.0.0",
                    capabilities={}
                )
            )

def main():
    """Entry point"""
    server = SecurityAuditServer()
    asyncio.run(server.run())

if __name__ == "__main__":
    main()
