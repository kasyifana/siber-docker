#!/usr/bin/env python3
"""
MCP Stdio Server
Pure stdio protocol for Docker MCP Gateway compatibility
"""
import sys
import json
import asyncio
from typing import Any, Dict, List
from mcp.server import Server
from mcp.types import Tool, TextContent

# Import all tools
from src.tools.nmap_scanner import NmapScanner
from src.tools.sqlmap_tool import SQLMapTool
from src.tools.nikto_scanner import NiktoScanner
from src.tools.xss_tester import XSSTester
from src.tools.subdomain_enum import SubdomainEnumerator
from src.tools.ssl_checker import SSLChecker
from src.tools.header_analyzer import HeaderAnalyzer
from src.utils.validator import TargetValidator
from src.utils.logger import setup_logger
import logging

# Setup logger - use standard logging if setup_logger returns None
try:
    logger = setup_logger()
    if logger is None:
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger(__name__)
except Exception:
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

# Initialize MCP server
server = Server("mcp-security-audit")

# Initialize tools
nmap = NmapScanner()
sqlmap = SQLMapTool()
nikto = NiktoScanner()
xss = XSSTester()
subdomain = SubdomainEnumerator()
ssl = SSLChecker()
headers = HeaderAnalyzer()
validator = TargetValidator()

@server.list_tools()
async def list_tools() -> List[Tool]:
    """List all available security tools"""
    return [
        Tool(
            name="scan_ports",
            description="Scan network ports using Nmap. Identifies open ports, services, and versions on target host.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname to scan"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port range (e.g., '1-1000' or '80,443,8080')",
                        "default": "1-1000"
                    }
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="test_sql_injection",
            description="Test for SQL injection vulnerabilities using SQLMap. Automatically detects and exploits SQL injection flaws.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to test for SQL injection"
                    },
                    "level": {
                        "type": "integer",
                        "description": "Test level (1-5, higher = more thorough)",
                        "default": 1
                    }
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="scan_web_vulnerabilities",
            description="Scan web server for common vulnerabilities using Nikto. Checks for outdated software, dangerous files, and misconfigurations.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to scan"
                    }
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="test_xss",
            description="Test for Cross-Site Scripting (XSS) vulnerabilities. Tests reflected, stored, and DOM-based XSS.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to test"
                    },
                    "payloads": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Custom XSS payloads (optional)"
                    }
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="enumerate_subdomains",
            description="Enumerate subdomains of a target domain. Discovers additional attack surface.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g., example.com)"
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Wordlist path (optional)"
                    }
                },
                "required": ["domain"]
            }
        ),
        Tool(
            name="check_ssl",
            description="Check SSL/TLS certificate and configuration. Validates certificate chain, expiry, and security settings.",
            inputSchema={
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target hostname"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Port number",
                        "default": 443
                    }
                },
                "required": ["host"]
            }
        ),
        Tool(
            name="check_security_headers",
            description="Analyze HTTP security headers. Checks for missing or misconfigured security headers like CSP, HSTS, X-Frame-Options.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to check"
                    }
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="detect_technologies",
            description="Detect web technologies, CMS, frameworks, and libraries used by target website.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to analyze"
                    }
                },
                "required": ["url"]
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: Any) -> List[TextContent]:
    """Execute security tool"""
    try:
        result = ""
        
        if name == "scan_ports":
            target = arguments["target"]
            ports = arguments.get("ports", "1-1000")
            
            # Validate target
            if not validator.is_valid_target(target):
                result = f"❌ Invalid target: {target}"
            else:
                logger.info(f"Scanning ports on {target}")
                scan_result = await nmap.scan(target, ports)
                result = f"# 🔍 Port Scan Results\n\n{scan_result}"
        
        elif name == "test_sql_injection":
            url = arguments["url"]
            level = arguments.get("level", 1)
            
            if not validator.is_valid_url(url):
                result = f"❌ Invalid URL: {url}"
            else:
                logger.info(f"Testing SQL injection on {url}")
                test_result = await sqlmap.test(url, level)
                result = f"# 💉 SQL Injection Test Results\n\n{test_result}"
        
        elif name == "scan_web_vulnerabilities":
            url = arguments["url"]
            
            if not validator.is_valid_url(url):
                result = f"❌ Invalid URL: {url}"
            else:
                logger.info(f"Scanning web vulnerabilities on {url}")
                scan_result = await nikto.scan(url)
                result = f"# 🔎 Web Vulnerability Scan Results\n\n{scan_result}"
        
        elif name == "test_xss":
            url = arguments["url"]
            payloads = arguments.get("payloads")
            
            if not validator.is_valid_url(url):
                result = f"❌ Invalid URL: {url}"
            else:
                logger.info(f"Testing XSS on {url}")
                test_result = await xss.test(url, payloads)
                result = f"# 🎯 XSS Test Results\n\n{test_result}"
        
        elif name == "enumerate_subdomains":
            domain = arguments["domain"]
            wordlist = arguments.get("wordlist")
            
            if not validator.is_valid_domain(domain):
                result = f"❌ Invalid domain: {domain}"
            else:
                logger.info(f"Enumerating subdomains for {domain}")
                enum_result = await subdomain.enumerate(domain, wordlist)
                result = f"# 🌐 Subdomain Enumeration Results\n\n{enum_result}"
        
        elif name == "check_ssl":
            host = arguments["host"]
            port = arguments.get("port", 443)
            
            logger.info(f"Checking SSL for {host}:{port}")
            ssl_result = await ssl.check(host, port)
            result = f"# 🔒 SSL/TLS Check Results\n\n{ssl_result}"
        
        elif name == "check_security_headers":
            url = arguments["url"]
            
            if not validator.is_valid_url(url):
                result = f"❌ Invalid URL: {url}"
            else:
                logger.info(f"Checking security headers for {url}")
                headers_result = await headers.analyze(url)
                result = f"# 🛡️ Security Headers Analysis\n\n{headers_result}"
        
        elif name == "detect_technologies":
            url = arguments["url"]
            
            if not validator.is_valid_url(url):
                result = f"❌ Invalid URL: {url}"
            else:
                logger.info(f"Detecting technologies for {url}")
                tech_result = await headers.detect_technologies(url)
                result = f"# 🔧 Technology Detection Results\n\n{tech_result}"
        
        else:
            result = f"❌ Unknown tool: {name}"
        
        return [TextContent(type="text", text=result)]
    
    except Exception as e:
        error_msg = f"❌ Error executing {name}: {str(e)}"
        logger.error(error_msg)
        return [TextContent(type="text", text=error_msg)]

async def main():
    """Run stdio server"""
    from mcp.server.stdio import stdio_server
    
    logger.info("Starting MCP Security Audit Server (stdio mode)")
    logger.info("Server ready for Docker MCP Gateway")
    
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())
