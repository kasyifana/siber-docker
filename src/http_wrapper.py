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
    """Call MCP stdio server and return result"""
    try:
        # Prepare JSON-RPC messages
        init_msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "http-wrapper", "version": "1.0"}
            }
        }
        
        call_msg = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        }
        
        # Combine messages
        input_data = json.dumps(init_msg) + "\n" + json.dumps(call_msg) + "\n"
        
        # Call MCP server
        process = await asyncio.create_subprocess_exec(
            "python", "-m", "src.stdio_server",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate(input=input_data.encode())
        
        if process.returncode != 0:
            return {
                "success": False,
                "error": f"MCP server error: {stderr.decode()}"
            }
        
        # Parse response (skip logs, get last JSON line)
        lines = stdout.decode().strip().split('\n')
        result_line = None
        for line in reversed(lines):
            if line.strip().startswith('{"jsonrpc"'):
                result_line = line
                break
        
        if not result_line:
            return {
                "success": False,
                "error": "No valid JSON-RPC response found"
            }
        
        response = json.loads(result_line)
        
        if "error" in response:
            return {
                "success": False,
                "error": response["error"]
            }
        
        # Extract result content
        if "result" in response and "content" in response["result"]:
            content = response["result"]["content"]
            if isinstance(content, list) and len(content) > 0:
                return {
                    "success": True,
                    "result": content[0].get("text", str(content))
                }
        
        return {
            "success": True,
            "result": response.get("result", response)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
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

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=3000)
