# src/utils/reporter.py

import json
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path
from loguru import logger

class ReportGenerator:
    """Generate security audit reports"""
    
    def __init__(self):
        self.report_dir = Path("/app/reports")
        self.report_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Report generator initialized")
    
    def generate_full_report(
        self,
        target: str,
        results: List[Any],
        scope: str = "standard"
    ) -> str:
        """
        Generate comprehensive security audit report
        
        Args:
            target: Target URL/domain
            results: List of scan results
            scope: Audit scope
        
        Returns:
            Formatted report in markdown
        """
        report = f"# Security Audit Report\n\n"
        report += f"**Target:** {target}\n"
        report += f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"**Scope:** {scope}\n\n"
        
        report += "---\n\n"
        
        # Executive Summary
        report += "## Executive Summary\n\n"
        report += self._generate_summary(results)
        report += "\n\n"
        
        # Findings by Severity
        report += "## Findings by Severity\n\n"
        report += self._generate_severity_summary(results)
        report += "\n\n"
        
        # Detailed Findings
        report += "## Detailed Findings\n\n"
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                report += f"### Scan {i+1}: Error\n"
                report += f"```\n{str(result)}\n```\n\n"
            elif isinstance(result, dict):
                report += self._format_result(result)
                report += "\n\n"
        
        # Recommendations
        report += "## Recommendations\n\n"
        report += self._generate_recommendations(results)
        
        # Save report
        self._save_report(target, report)
        
        return report
    
    def _generate_summary(self, results: List[Any]) -> str:
        """Generate executive summary"""
        summary = "This security audit assessed the target for common vulnerabilities including:\n\n"
        
        # Count findings
        total_vulns = 0
        critical = 0
        high = 0
        medium = 0
        low = 0
        
        for result in results:
            if isinstance(result, dict):
                if result.get('vulnerable'):
                    vulns = result.get('vulnerabilities', [])
                    total_vulns += len(vulns)
                    
                    for vuln in vulns:
                        severity = vuln.get('severity', 'low').lower()
                        if severity == 'critical':
                            critical += 1
                        elif severity == 'high':
                            high += 1
                        elif severity == 'medium':
                            medium += 1
                        else:
                            low += 1
        
        summary += f"- **Total Vulnerabilities:** {total_vulns}\n"
        summary += f"- **Critical:** {critical}\n"
        summary += f"- **High:** {high}\n"
        summary += f"- **Medium:** {medium}\n"
        summary += f"- **Low:** {low}\n"
        
        return summary
    
    def _generate_severity_summary(self, results: List[Any]) -> str:
        """Generate severity-based summary"""
        summary = ""
        
        # Collect vulnerabilities by severity
        by_severity = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        for result in results:
            if isinstance(result, dict) and result.get('vulnerable'):
                vulns = result.get('vulnerabilities', [])
                for vuln in vulns:
                    severity = vuln.get('severity', 'low').lower()
                    if severity in by_severity:
                        by_severity[severity].append(vuln)
        
        # Format by severity
        for severity, vulns in by_severity.items():
            if vulns:
                icon = "🔴" if severity == "critical" else "🟠" if severity == "high" else "🟡" if severity == "medium" else "🔵"
                summary += f"### {icon} {severity.capitalize()} ({len(vulns)})\n\n"
                
                for vuln in vulns[:5]:  # Show top 5
                    title = vuln.get('title', vuln.get('type', 'Vulnerability'))
                    summary += f"- {title}\n"
                
                if len(vulns) > 5:
                    summary += f"\n*...and {len(vulns) - 5} more*\n"
                
                summary += "\n"
        
        return summary
    
    def _format_result(self, result: Dict) -> str:
        """Format individual scan result"""
        formatted = ""
        
        # Determine scan type
        if 'open_ports' in result:
            formatted += "### Port Scan Results\n\n"
            formatted += f"Open ports: {len(result['open_ports'])}\n"
        
        elif 'headers' in result:
            formatted += "### Security Headers Analysis\n\n"
            formatted += f"Score: {result.get('score', 0)}/100\n"
        
        elif 'certificate' in result:
            formatted += "### SSL/TLS Analysis\n\n"
            formatted += f"Grade: {result.get('grade', 'N/A')}\n"
        
        elif 'subdomains' in result:
            formatted += "### Subdomain Enumeration\n\n"
            formatted += f"Subdomains found: {len(result.get('subdomains', []))}\n"
        
        elif result.get('vulnerable'):
            formatted += "### Vulnerability Found\n\n"
            formatted += f"Type: {result.get('type', 'Unknown')}\n"
            formatted += f"Severity: {result.get('severity', 'Unknown')}\n"
        
        return formatted
    
    def _generate_recommendations(self, results: List[Any]) -> str:
        """Generate security recommendations"""
        recommendations = []
        
        for result in results:
            if isinstance(result, dict):
                # Check for missing security headers
                if 'headers' in result:
                    for header, status in result['headers'].items():
                        if not status.get('present'):
                            recommendations.append(
                                f"- Implement {header} header to prevent {status.get('impact')}"
                            )
                
                # Check for SSL issues
                if 'issues' in result and result['issues']:
                    for issue in result['issues']:
                        recommendations.append(f"- SSL/TLS: {issue}")
                
                # Check for vulnerabilities
                if result.get('vulnerable'):
                    vuln_type = result.get('type', 'vulnerability')
                    recommendations.append(
                        f"- Remediate {vuln_type} vulnerabilities found"
                    )
        
        if not recommendations:
            return "No critical issues found. Continue monitoring and regular security audits."
        
        return "\n".join(list(set(recommendations)))
    
    def _save_report(self, target: str, report: str):
        """Save report to file"""
        try:
            # Create filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_target = target.replace('://', '_').replace('/', '_').replace('.', '_')
            filename = f"report_{safe_target}_{timestamp}.md"
            
            # Save to file
            filepath = self.report_dir / filename
            filepath.write_text(report)
            
            logger.info(f"Report saved to {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to save report: {str(e)}")
    
    async def generate(self, scan_id: str, format: str = "markdown") -> str:
        """
        Generate report for specific scan
        
        Args:
            scan_id: Scan identifier
            format: Report format (markdown, html, json)
        
        Returns:
            Generated report
        """
        # This would typically load scan results from database
        # For now, return a placeholder
        
        report = f"# Scan Report: {scan_id}\n\n"
        report += f"Format: {format}\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        report += "*Report generation from stored scans not yet implemented*\n"
        
        return report
