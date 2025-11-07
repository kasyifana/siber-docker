# src/server.py

from mcp.server.models import InitializationOptions
from mcp.server import Server
from mcp.types import TextContent, Tool
from typing import Any, Dict, List
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
        
        self._register_tools()
        logger.info("Security Audit Server initialized")
    
    def _register_tools(self):
        """Register all security tools as MCP tools"""
        
        # Port Scanning Tool
        @self.server.tool()
        async def port_scan(
            target: str,
            ports: str = "1-1000",
            scan_type: str = "quick"
        ) -> List[TextContent]:
            """
            Perform port scanning on target
            
            Args:
                target: IP address or hostname
                ports: Port range (e.g., "1-1000" or "80,443,8080")
                scan_type: Type of scan (quick, full, stealth)
            """
            if not self.validator.validate_target(target):
                return [TextContent(
                    type="text",
                    text=f"Invalid target: {target}"
                )]
            
            logger.info(f"Starting port scan on {target}")
            results = await self.tools['nmap'].scan(target, ports, scan_type)
            
            return [TextContent(
                type="text",
                text=self.format_port_scan_results(results)
            )]
        
        # SQL Injection Testing
        @self.server.tool()
        async def sql_injection_test(
            url: str,
            parameters: str = "",
            database: str = "auto"
        ) -> List[TextContent]:
            """
            Test for SQL injection vulnerabilities
            
            Args:
                url: Target URL
                parameters: Parameters to test (comma-separated)
                database: Database type (auto, mysql, postgres, mssql)
            """
            if not self.validator.validate_url(url):
                return [TextContent(
                    type="text",
                    text=f"Invalid URL: {url}"
                )]
            
            logger.info(f"Testing SQL injection on {url}")
            results = await self.tools['sqlmap'].test(url, parameters, database)
            
            return [TextContent(
                type="text",
                text=self.format_sqli_results(results)
            )]
        
        # Web Vulnerability Scanning
        @self.server.tool()
        async def web_vuln_scan(
            url: str,
            scan_depth: str = "standard"
        ) -> List[TextContent]:
            """
            Comprehensive web vulnerability scan using Nikto
            
            Args:
                url: Target URL
                scan_depth: Depth of scan (quick, standard, thorough)
            """
            if not self.validator.validate_url(url):
                return [TextContent(
                    type="text",
                    text=f"Invalid URL: {url}"
                )]
            
            logger.info(f"Starting web vulnerability scan on {url}")
            results = await self.tools['nikto'].scan(url, scan_depth)
            
            return [TextContent(
                type="text",
                text=self.format_nikto_results(results)
            )]
        
        # XSS Testing
        @self.server.tool()
        async def xss_test(
            url: str,
            parameters: List[str],
            payload_type: str = "all"
        ) -> List[TextContent]:
            """
            Test for Cross-Site Scripting vulnerabilities
            
            Args:
                url: Target URL
                parameters: List of parameters to test
                payload_type: Type of XSS payloads (reflected, stored, dom, all)
            """
            if not self.validator.validate_url(url):
                return [TextContent(
                    type="text",
                    text=f"Invalid URL: {url}"
                )]
            
            logger.info(f"Testing XSS on {url}")
            results = await self.tools['xss'].test(url, parameters, payload_type)
            
            return [TextContent(
                type="text",
                text=self.format_xss_results(results)
            )]
        
        # Subdomain Enumeration
        @self.server.tool()
        async def enumerate_subdomains(
            domain: str,
            method: str = "all"
        ) -> List[TextContent]:
            """
            Enumerate subdomains of target domain
            
            Args:
                domain: Target domain (e.g., example.com)
                method: Enumeration method (dns, certificate, brute, all)
            """
            if not self.validator.validate_domain(domain):
                return [TextContent(
                    type="text",
                    text=f"Invalid domain: {domain}"
                )]
            
            logger.info(f"Enumerating subdomains for {domain}")
            results = await self.tools['subdomain'].enumerate(domain, method)
            
            return [TextContent(
                type="text",
                text=self.format_subdomain_results(results)
            )]
        
        # SSL/TLS Analysis
        @self.server.tool()
        async def analyze_ssl(
            hostname: str,
            port: int = 443
        ) -> List[TextContent]:
            """
            Analyze SSL/TLS configuration
            
            Args:
                hostname: Target hostname
                port: SSL/TLS port (default: 443)
            """
            if not self.validator.validate_hostname(hostname):
                return [TextContent(
                    type="text",
                    text=f"Invalid hostname: {hostname}"
                )]
            
            logger.info(f"Analyzing SSL/TLS for {hostname}:{port}")
            results = await self.tools['ssl'].analyze(hostname, port)
            
            return [TextContent(
                type="text",
                text=self.format_ssl_results(results)
            )]
        
        # Security Headers Check
        @self.server.tool()
        async def check_security_headers(
            url: str
        ) -> List[TextContent]:
            """
            Check security headers of target website
            
            Args:
                url: Target URL
            """
            if not self.validator.validate_url(url):
                return [TextContent(
                    type="text",
                    text=f"Invalid URL: {url}"
                )]
            
            logger.info(f"Checking security headers for {url}")
            results = await self.tools['headers'].analyze(url)
            
            return [TextContent(
                type="text",
                text=self.format_header_results(results)
            )]
        
        # Comprehensive Audit
        @self.server.tool()
        async def full_security_audit(
            target: str,
            scope: str = "standard"
        ) -> List[TextContent]:
            """
            Perform comprehensive security audit
            
            Args:
                target: Target URL or domain
                scope: Audit scope (quick, standard, thorough)
            """
            logger.info(f"Starting full security audit on {target}")
            
            # Run all tests in parallel
            tasks = [
                self.tools['headers'].analyze(target),
                self.tools['ssl'].analyze(target),
                self.tools['nmap'].scan(target),
                self.tools['nikto'].scan(target),
                self.tools['subdomain'].enumerate(target)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Generate comprehensive report
            report = self.reporter.generate_full_report(
                target=target,
                results=results,
                scope=scope
            )
            
            return [TextContent(
                type="text",
                text=report
            )]
        
        # Generate Report
        @self.server.tool()
        async def generate_report(
            scan_id: str,
            format: str = "markdown"
        ) -> List[TextContent]:
            """
            Generate detailed report from scan results
            
            Args:
                scan_id: ID of the scan
                format: Report format (markdown, html, pdf, json)
            """
            logger.info(f"Generating report for scan {scan_id}")
            report = await self.reporter.generate(scan_id, format)
            
            return [TextContent(
                type="text",
                text=report
            )]
    
    # Format helper methods
    def format_port_scan_results(self, results: Dict) -> str:
        """Format port scan results"""
        output = f"# Port Scan Results\n\n"
        output += f"**Target:** {results['target']}\n"
        output += f"**Scan Time:** {results['scan_time']}\n\n"
        
        if results['open_ports']:
            output += "## Open Ports\n\n"
            for port in results['open_ports']:
                output += f"- **Port {port['port']}/{port['protocol']}**\n"
                output += f"  - Service: {port['service']}\n"
                output += f"  - Version: {port.get('version', 'Unknown')}\n"
                if port.get('vulnerabilities'):
                    output += f"  - ⚠️ Known Vulnerabilities: {len(port['vulnerabilities'])}\n"
        else:
            output += "No open ports found.\n"
        
        return output
    
    def format_sqli_results(self, results: Dict) -> str:
        """Format SQL injection results"""
        output = f"# SQL Injection Test Results\n\n"
        output += f"**Target:** {results['url']}\n"
        output += f"**Vulnerable:** {'YES ⚠️' if results['vulnerable'] else 'NO ✓'}\n\n"
        
        if results['vulnerable']:
            output += "## Vulnerabilities Found\n\n"
            for vuln in results['vulnerabilities']:
                output += f"### {vuln['parameter']}\n"
                output += f"- **Type:** {vuln['injection_type']}\n"
                output += f"- **Database:** {vuln['database']}\n"
                output += f"- **Payload:** `{vuln['payload']}`\n"
                output += f"- **Risk:** {vuln['risk_level']}\n\n"
        
        return output
    
    def format_xss_results(self, results: Dict) -> str:
        """Format XSS test results"""
        output = f"# XSS Test Results\n\n"
        output += f"**Target:** {results['url']}\n"
        output += f"**Vulnerable:** {'YES ⚠️' if results['vulnerable'] else 'NO ✓'}\n\n"
        
        if results['vulnerable']:
            output += "## Vulnerabilities Found\n\n"
            for vuln in results['vulnerabilities']:
                output += f"### {vuln['type']} XSS in {vuln['parameter']}\n"
                output += f"- **Payload:** `{vuln['payload']}`\n"
                output += f"- **Context:** {vuln['context']}\n"
                output += f"- **Severity:** {vuln['severity']}\n\n"
        
        return output
    
    def format_subdomain_results(self, results: Dict) -> str:
        """Format subdomain enumeration results"""
        output = f"# Subdomain Enumeration Results\n\n"
        output += f"**Domain:** {results['domain']}\n"
        output += f"**Subdomains Found:** {len(results['subdomains'])}\n\n"
        
        if results['subdomains']:
            output += "## Discovered Subdomains\n\n"
            for subdomain in results['subdomains']:
                output += f"- `{subdomain['name']}`\n"
                output += f"  - IP: {subdomain.get('ip', 'N/A')}\n"
                output += f"  - Status: {subdomain.get('status', 'Unknown')}\n"
        
        return output
    
    def format_ssl_results(self, results: Dict) -> str:
        """Format SSL/TLS analysis results"""
        output = f"# SSL/TLS Analysis Results\n\n"
        output += f"**Hostname:** {results['hostname']}\n"
        output += f"**Grade:** {results['grade']}\n\n"
        
        output += "## Certificate Information\n"
        cert = results['certificate']
        output += f"- **Issuer:** {cert['issuer']}\n"
        output += f"- **Valid Until:** {cert['valid_until']}\n"
        output += f"- **Signature Algorithm:** {cert['signature_algorithm']}\n\n"
        
        output += "## Supported Protocols\n"
        for protocol in results['protocols']:
            output += f"- {protocol['name']}: {protocol['status']}\n"
        
        output += "\n## Issues Found\n"
        if results['issues']:
            for issue in results['issues']:
                output += f"- ⚠️ {issue}\n"
        else:
            output += "No issues found ✓\n"
        
        return output
    
    def format_header_results(self, results: Dict) -> str:
        """Format security headers analysis"""
        output = f"# Security Headers Analysis\n\n"
        output += f"**URL:** {results['url']}\n"
        output += f"**Score:** {results['score']}/100\n\n"
        
        output += "## Headers Status\n\n"
        for header, status in results['headers'].items():
            icon = "✓" if status['present'] else "❌"
            output += f"{icon} **{header}**\n"
            if status['present']:
                output += f"   Value: `{status['value']}`\n"
                output += f"   Status: {status['assessment']}\n"
            else:
                output += f"   Status: Missing\n"
                output += f"   Impact: {status['impact']}\n"
            output += "\n"
        
        return output
    
    def format_nikto_results(self, results: Dict) -> str:
        """Format Nikto scan results"""
        output = f"# Web Vulnerability Scan Results\n\n"
        output += f"**Target:** {results['target']}\n"
        output += f"**Vulnerabilities Found:** {results['vulnerability_count']}\n\n"
        
        if results['vulnerabilities']:
            # Group by severity
            critical = [v for v in results['vulnerabilities'] if v['severity'] == 'critical']
            high = [v for v in results['vulnerabilities'] if v['severity'] == 'high']
            medium = [v for v in results['vulnerabilities'] if v['severity'] == 'medium']
            low = [v for v in results['vulnerabilities'] if v['severity'] == 'low']
            
            if critical:
                output += "## Critical Issues\n\n"
                for vuln in critical:
                    output += f"- **{vuln['title']}**\n"
                    output += f"  - Path: `{vuln['path']}`\n"
                    output += f"  - Description: {vuln['description']}\n\n"
            
            if high:
                output += "## High Issues\n\n"
                for vuln in high:
                    output += f"- **{vuln['title']}**\n"
                    output += f"  - Path: `{vuln['path']}`\n\n"
            
            if medium:
                output += "## Medium Issues\n\n"
                for vuln in medium:
                    output += f"- {vuln['title']}\n"
            
            if low:
                output += f"\n## Low Issues\n{len(low)} low severity issues found.\n"
        
        return output
    
    async def run(self):
        """Start the MCP server"""
        from mcp.server.stdio import stdio_server
        
        logger.info(f"Starting MCP Security Audit Server on {settings.MCP_SERVER_HOST}:{settings.MCP_SERVER_PORT}")
        
        async with stdio_server() as (read_stream, write_stream):
            init_options = InitializationOptions(
                server_name="security-audit-server",
                server_version="1.0.0",
                capabilities=self.server.get_capabilities(
                    notification_options=None,
                    experimental_capabilities={}
                )
            )
            
            await self.server.run(
                read_stream,
                write_stream,
                init_options
            )

def main():
    """Entry point"""
    server = SecurityAuditServer()
    asyncio.run(server.run())

if __name__ == "__main__":
    main()