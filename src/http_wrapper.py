#!/usr/bin/env python3
"""
HTTP REST API wrapper for MCP stdio server
Allows external access to MCP tools via HTTP
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import json
import asyncio
from typing import Optional, Dict, Any, List
import uvicorn

app = FastAPI(title="MCP Security Audit API", version="1.0.0")

class ToolCallRequest(BaseModel):
    tool: str
    arguments: Dict[str, Any]

class ScanPortsRequest(BaseModel):
    target: str
    ports: Optional[str] = "1-1000"

class TestSQLRequest(BaseModel):
    url: str

class ScanWebRequest(BaseModel):
    url: str

class TestXSSRequest(BaseModel):
    url: str
    payloads: Optional[List[str]] = None

class EnumerateSubdomainsRequest(BaseModel):
    domain: str
    wordlist: Optional[str] = None
    method: Optional[str] = "all"

class CheckSSLRequest(BaseModel):
    host: str
    port: Optional[int] = 443

class CheckHeadersRequest(BaseModel):
    url: str

class DetectTechRequest(BaseModel):
    url: str

class MultiScanRequest(BaseModel):
    target: str
    scans: Optional[List[str]] = ["ports", "web_vuln", "ssl", "headers", "tech"]
    ports: Optional[str] = "80,443,8080,3000,8000"

async def call_mcp_tool(tool_name: str, arguments: dict) -> dict:
    """Call MCP tools directly without subprocess to avoid ClosedResourceError"""
    try:
        # Import tools directly
        from src.tools.nmap_scanner import NmapScanner
        from src.tools.sqlmap_tool import SQLMapTool
        from src.tools.nikto_scanner import NiktoScanner
        from src.tools.xss_tester import XSSTester
        from src.tools.subdomain_enum import SubdomainEnumerator
        from src.tools.ssl_checker import SSLChecker
        from src.tools.header_analyzer import HeaderAnalyzer
        from src.tools.cdn_bypass_scanner import CDNBypassScanner
        from src.utils.validator import TargetValidator
        
        # Initialize tools
        nmap = NmapScanner()
        sqlmap = SQLMapTool()
        nikto = NiktoScanner()
        xss = XSSTester()
        subdomain = SubdomainEnumerator()
        ssl = SSLChecker()
        headers = HeaderAnalyzer()
        cdn_bypass = CDNBypassScanner()
        validator = TargetValidator()
        
        # Call appropriate tool
        result = None
        if tool_name == "scan_ports":
            result = await nmap.scan(arguments["target"], arguments.get("ports", "1-1000"))
        elif tool_name == "test_sql_injection":
            result = await sqlmap.test(arguments["url"])
        elif tool_name == "scan_web_vulnerabilities":
            result = await nikto.scan(arguments["url"])
        elif tool_name == "test_xss":
            result = await xss.test(arguments["url"], arguments.get("payloads"))
        elif tool_name == "enumerate_subdomains":
            # Fix: Pass method correctly, ignore wordlist as it's not supported by the tool instance method
            result = await subdomain.enumerate(
                domain=arguments["domain"], 
                method=arguments.get("method", "all")
            )
        elif tool_name == "check_ssl":
            result = await ssl.analyze(arguments["host"], arguments.get("port", 443))
        elif tool_name == "check_security_headers":
            result = await headers.analyze(arguments["url"])
        elif tool_name == "cdn_bypass_scan":
            result = await cdn_bypass.scan(arguments["url"])
        elif tool_name == "detect_technologies":
            # Simple tech detection
            import re
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(arguments["url"]) as resp:
                    html = await resp.text()
                    tech_report = "# 🔧 Technology Detection Results\n\n"
                    tech_report += f"**Target:** {arguments['url']}\n\n"
                    
                    # Detect common technologies
                    techs = []
                    if 'wp-content' in html or 'wordpress' in html.lower():
                        techs.append("WordPress")
                    if 'react' in html.lower() or '__NEXT_DATA__' in html:
                        techs.append("React/Next.js")
                    if 'ng-' in html or 'angular' in html.lower():
                        techs.append("Angular")
                    if 'vue' in html.lower():
                        techs.append("Vue.js")
                    
                    tech_report += "**Detected Technologies:**\n"
                    for tech in techs if techs else ["Unknown"]:
                        tech_report += f"- {tech}\n"
                    
                    result = tech_report
        elif tool_name == "multi_scan":
            # Multi-scan implementation
            target = arguments["target"]
            scans = arguments.get("scans", ["ports", "ssl", "headers", "tech"])
            ports = arguments.get("ports", "80,443,8080,3000,8000")
            
            # Normalize target
            if not target.startswith("http"):
                url = f"https://{target}"
                hostname = target
            else:
                url = target
                hostname = target.replace("https://", "").replace("http://", "").split("/")[0]
            
            # Run scans concurrently
            scan_tasks = []
            scan_names = []
            
            if "ports" in scans:
                scan_tasks.append(nmap.scan(hostname, ports))
                scan_names.append("Port Scan")
            if "sql" in scans:
                scan_tasks.append(sqlmap.test(url))
                scan_names.append("SQL Injection Test")
            if "web_vuln" in scans:
                scan_tasks.append(nikto.scan(url))
                scan_names.append("Web Vulnerabilities")
            if "xss" in scans:
                scan_tasks.append(xss.test(url))
                scan_names.append("XSS Test")
            if "ssl" in scans:
                scan_tasks.append(ssl.analyze(hostname, 443))
                scan_names.append("SSL Check")
            if "headers" in scans:
                scan_tasks.append(headers.analyze(url))
                scan_names.append("Security Headers")
            
            # Execute all scans
            results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            
            # Consolidate results
            consolidated = f"# 🔒 Multi-Scan Security Audit Report\n\n"
            consolidated += f"**Target:** {target}\n"
            consolidated += f"**Scans Executed:** {len(scan_tasks)}/{len(scans)}\n"
            consolidated += f"**Timestamp:** {asyncio.get_event_loop().time()}\n\n"
            consolidated += "---\n\n"
            
            for scan_name, scan_result in zip(scan_names, results):
                consolidated += f"## {scan_name}\n\n"
                if isinstance(scan_result, Exception):
                    consolidated += f"❌ **Error:** {str(scan_result)}\n\n"
                else:
                    consolidated += f"{scan_result}\n\n"
                consolidated += "---\n\n"
            
            result = consolidated
        else:
            return {
                "success": False,
                "error": f"Unknown tool: {tool_name}"
            }
        
        return {
            "success": True,
            "result": result
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Tool execution error: {str(e)}"
        }

@app.get("/")
async def root():
    """API info"""
    return {
        "name": "MCP Security Audit API",
        "version": "1.0.0",
        "endpoints": {
            "GET /": "This info",
            "GET /health": "Health check",
            "GET /tools": "List available tools",
            "POST /scan/ports": "Scan network ports (Nmap)",
            "POST /scan/sql": "Test SQL injection (SQLMap)",
            "POST /scan/web": "Scan web vulnerabilities (Nikto)",
            "POST /scan/xss": "Test XSS vulnerabilities",
            "POST /scan/subdomains": "Enumerate subdomains",
            "POST /scan/ssl": "Check SSL/TLS certificate",
            "POST /scan/headers": "Check security headers",
            "POST /scan/tech": "Detect technologies",
            "POST /scan/multi": "Run multiple scans",
            "POST /tool/call": "Generic tool call"
        }
    }

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy", "service": "mcp-security-audit"}

@app.get("/tools")
async def list_tools():
    """List all available MCP tools"""
    tools = [
        {"name": "scan_ports", "description": "Scan network ports using Nmap"},
        {"name": "test_sql_injection", "description": "Test for SQL injection vulnerabilities"},
        {"name": "scan_web_vulnerabilities", "description": "Scan web server vulnerabilities"},
        {"name": "test_xss", "description": "Test for XSS vulnerabilities"},
        {"name": "enumerate_subdomains", "description": "Enumerate subdomains"},
        {"name": "check_ssl", "description": "Check SSL/TLS certificate"},
        {"name": "check_security_headers", "description": "Analyze HTTP security headers"},
        {"name": "detect_technologies", "description": "Detect web technologies"},
        {"name": "multi_scan", "description": "Run multiple scans simultaneously"}
    ]
    return {"tools": tools}

@app.post("/scan/ports")
async def scan_ports(req: ScanPortsRequest):
    """Scan network ports using Nmap"""
    result = await call_mcp_tool("scan_ports", {
        "target": req.target,
        "ports": req.ports
    })
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error"))
    return result

@app.post("/scan/sql")
async def test_sql(req: TestSQLRequest):
    """Test for SQL injection vulnerabilities"""
    result = await call_mcp_tool("test_sql_injection", {"url": req.url})
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error"))
    return result

@app.post("/scan/web")
async def scan_web(req: ScanWebRequest):
    """Scan web vulnerabilities using Nikto"""
    result = await call_mcp_tool("scan_web_vulnerabilities", {"url": req.url})
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error"))
    return result

@app.post("/scan/xss")
async def test_xss(req: TestXSSRequest):
    """Test for XSS vulnerabilities"""
    args = {"url": req.url}
    if req.payloads:
        args["payloads"] = req.payloads
    result = await call_mcp_tool("test_xss", args)
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error"))
    return result

@app.post("/scan/subdomains")
async def enumerate_subdomains(req: EnumerateSubdomainsRequest):
    """Enumerate subdomains"""
    args = {"domain": req.domain}
    if req.wordlist:
        args["wordlist"] = req.wordlist
    if req.method:
        args["method"] = req.method
    result = await call_mcp_tool("enumerate_subdomains", args)
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error"))
    return result

@app.post("/scan/ssl")
async def check_ssl(req: CheckSSLRequest):
    """Check SSL/TLS certificate"""
    result = await call_mcp_tool("check_ssl", {
        "host": req.host,
        "port": req.port
    })
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error"))
    return result

@app.post("/scan/headers")
async def check_headers(req: CheckHeadersRequest):
    """Check security headers"""
    result = await call_mcp_tool("check_security_headers", {"url": req.url})
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error"))
    return result

@app.post("/scan/tech")
async def detect_tech(req: DetectTechRequest):
    """Detect technologies"""
    result = await call_mcp_tool("detect_technologies", {"url": req.url})
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error"))
    return result

@app.post("/scan/cdn-bypass")
async def cdn_bypass_scan(req: CheckHeadersRequest):
    """Scan origin server bypassing CDN - detects REAL vulnerabilities"""
    result = await call_mcp_tool("cdn_bypass_scan", {"url": req.url})
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error"))
    return result

@app.post("/scan/multi")
async def multi_scan(req: MultiScanRequest):
    """Run multiple scans simultaneously"""
    result = await call_mcp_tool("multi_scan", {
        "target": req.target,
        "scans": req.scans,
        "ports": req.ports
    })
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error"))
    return result

@app.post("/tool/call")
async def generic_tool_call(req: ToolCallRequest):
    """Generic tool call endpoint"""
    result = await call_mcp_tool(req.tool, req.arguments)
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error"))
    return result

@app.post("/scan/full-json")
async def full_scan_json(req: MultiScanRequest):
    """
    Full scan with JSON-friendly output (no markdown)
    Perfect for frontend parsing - returns structured JSON
    """
    from src.tools.nmap_scanner import NmapScanner
    from src.tools.ssl_checker import SSLChecker
    from src.tools.header_analyzer import HeaderAnalyzer
    from src.tools.cdn_bypass_scanner import CDNBypassScanner
    
    target = req.target
    url = f"https://{target}" if not target.startswith("http") else target
    
    results = {
        "target": target,
        "timestamp": None,
        "scans_completed": 0,
        "scans_failed": 0,
        "total_vulnerabilities": 0,
        "severity_breakdown": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        },
        "scan_results": {}
    }
    
    # Port Scan
    if "ports" in req.scans:
        try:
            nmap = NmapScanner()
            port_result = await nmap.scan(target, req.ports)
            results["scan_results"]["ports"] = {
                "status": "completed",
                "open_ports_count": len(port_result.get("open_ports", [])),
                "open_ports": port_result.get("open_ports", []),
                "vulnerabilities": []
            }
            results["scans_completed"] += 1
        except Exception as e:
            results["scan_results"]["ports"] = {"status": "failed", "error": str(e)}
            results["scans_failed"] += 1
    
    # SSL Check
    if "ssl" in req.scans:
        try:
            ssl = SSLChecker()
            hostname = target.replace("https://", "").replace("http://", "").split("/")[0]
            ssl_result = await ssl.analyze(hostname, 443)
            ssl_issues = ssl_result.get("issues", [])
            results["scan_results"]["ssl"] = {
                "status": "completed",
                "grade": ssl_result.get("grade", "F"),
                "issues_count": len(ssl_issues),
                "issues": ssl_issues,
                "certificate_valid": not ssl_result.get("certificate", {}).get("expired", True)
            }
            results["scans_completed"] += 1
            # Count vulnerabilities
            for issue in ssl_issues:
                if "weak" in issue.lower() or "insecure" in issue.lower():
                    results["severity_breakdown"]["high"] += 1
                    results["total_vulnerabilities"] += 1
        except Exception as e:
            results["scan_results"]["ssl"] = {"status": "failed", "error": str(e)}
            results["scans_failed"] += 1
    
    # Security Headers
    if "headers" in req.scans:
        try:
            headers = HeaderAnalyzer()
            header_result = await headers.analyze(url)
            missing_headers = []
            high_sev = 0
            medium_sev = 0
            low_sev = 0
            
            for header, info in header_result.get("headers", {}).items():
                if not info.get("present", True):
                    severity = info.get("severity", "low")
                    missing_headers.append({
                        "header": header,
                        "severity": severity,
                        "impact": info.get("impact", "")
                    })
                    if severity == "high":
                        high_sev += 1
                    elif severity == "medium":
                        medium_sev += 1
                    else:
                        low_sev += 1
            
            results["scan_results"]["headers"] = {
                "status": "completed",
                "score": header_result.get("score", 0),
                "missing_headers_count": len(missing_headers),
                "missing_headers": missing_headers,
                "issues": header_result.get("issues", []),
                "total_issues": len(header_result.get("issues", []))
            }
            results["scans_completed"] += 1
            results["total_vulnerabilities"] += len(missing_headers)
            results["severity_breakdown"]["high"] += high_sev
            results["severity_breakdown"]["medium"] += medium_sev
            results["severity_breakdown"]["low"] += low_sev
        except Exception as e:
            results["scan_results"]["headers"] = {"status": "failed", "error": str(e)}
            results["scans_failed"] += 1
    
    # CDN Bypass
    if "cdn" in req.scans or "cdn-bypass" in req.scans:
        try:
            cdn = CDNBypassScanner()
            cdn_result = await cdn.scan(url)
            real_vulns = cdn_result.get("real_vulnerabilities", [])
            results["scan_results"]["cdn_bypass"] = {
                "status": "completed",
                "cdn_detected": cdn_result.get("cdn_detected", False),
                "cdn_provider": cdn_result.get("cdn_provider", "NONE"),
                "bypass_possible": cdn_result.get("bypass_possible", False),
                "real_vulnerabilities_count": len(real_vulns),
                "real_vulnerabilities": real_vulns,
                "security_score": cdn_result.get("security_analysis", {}).get("security_score", 0)
            }
            results["scans_completed"] += 1
            results["total_vulnerabilities"] += len(real_vulns)
            for vuln in real_vulns:
                sev = vuln.get("severity", "LOW").lower()
                if sev == "high":
                    results["severity_breakdown"]["high"] += 1
                elif sev == "medium":
                    results["severity_breakdown"]["medium"] += 1
                else:
                    results["severity_breakdown"]["low"] += 1
        except Exception as e:
            results["scan_results"]["cdn_bypass"] = {"status": "failed", "error": str(e)}
            results["scans_failed"] += 1
    
    # Summary
    from datetime import datetime
    results["timestamp"] = datetime.now().isoformat()
    results["overall_status"] = "completed" if results["scans_failed"] == 0 else "partial"
    results["security_grade"] = "F" if results["total_vulnerabilities"] > 10 else ("D" if results["total_vulnerabilities"] > 5 else "C")
    
    return {
        "success": True,
        "result": results
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=3000)
