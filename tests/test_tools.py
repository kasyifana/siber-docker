import pytest
import asyncio
from src.tools.nmap_scanner import NmapScanner
from src.tools.header_analyzer import HeaderAnalyzer
from src.tools.subdomain_enum import SubdomainEnumerator
from src.utils.validator import TargetValidator

class TestTargetValidator:
    def setup_method(self):
        self.validator = TargetValidator()
    
    def test_validate_valid_url(self):
        assert self.validator.validate_url("https://example.com") == True
        assert self.validator.validate_url("http://example.com") == True
    
    def test_validate_invalid_url(self):
        assert self.validator.validate_url("ftp://example.com") == False
        assert self.validator.validate_url("example.com") == False
    
    def test_validate_localhost_blocked(self):
        assert self.validator.validate_url("http://localhost") == False
        assert self.validator.validate_url("http://127.0.0.1") == False
    
    def test_validate_private_ip_blocked(self):
        assert self.validator.validate_ip("192.168.1.1") == False
        assert self.validator.validate_ip("10.0.0.1") == False
        assert self.validator.validate_ip("172.16.0.1") == False
    
    def test_validate_public_ip(self):
        assert self.validator.validate_ip("8.8.8.8") == True
        assert self.validator.validate_ip("1.1.1.1") == True
    
    def test_validate_domain(self):
        assert self.validator.validate_domain("example.com") == True
        assert self.validator.validate_domain("sub.example.com") == True
        assert self.validator.validate_domain("invalid") == False
    
    def test_sanitize_input(self):
        assert self.validator.sanitize_input("test;ls") == "testls"
        assert self.validator.sanitize_input("test|cat") == "testcat"
        assert self.validator.sanitize_input("normal") == "normal"


class TestNmapScanner:
    def setup_method(self):
        self.scanner = NmapScanner()
    
    @pytest.mark.asyncio
    async def test_scanner_initialization(self):
        assert self.scanner.nmap is not None
    
    @pytest.mark.asyncio
    async def test_parse_results_empty(self):
        results = self.scanner._parse_results({}, "example.com")
        assert results['target'] == "example.com"
        assert results['open_ports'] == []


class TestHeaderAnalyzer:
    def setup_method(self):
        self.analyzer = HeaderAnalyzer()
    
    def test_required_headers_defined(self):
        assert 'Strict-Transport-Security' in self.analyzer.required_headers
        assert 'Content-Security-Policy' in self.analyzer.required_headers
        assert 'X-Frame-Options' in self.analyzer.required_headers
    
    def test_assess_hsts_strong(self):
        result = self.analyzer._assess_hsts("max-age=31536000; includeSubDomains")
        assert result == "Strong"
    
    def test_assess_hsts_weak(self):
        result = self.analyzer._assess_hsts("max-age=300")
        assert result == "Adequate"
    
    def test_assess_xfo_strong(self):
        assert self.analyzer._assess_xfo("DENY") == "Strong"
        assert self.analyzer._assess_xfo("SAMEORIGIN") == "Strong"


class TestSubdomainEnumerator:
    def setup_method(self):
        self.enumerator = SubdomainEnumerator()
    
    def test_wordlist_loaded(self):
        assert len(self.enumerator.wordlist) > 0
        assert 'www' in self.enumerator.wordlist
        assert 'api' in self.enumerator.wordlist
    
    @pytest.mark.asyncio
    async def test_enumerate_dns_no_error(self):
        # Should not raise exception even with invalid domain
        try:
            result = await self.enumerator._enumerate_dns("invalid-domain-xyz.com")
            assert isinstance(result, list)
        except Exception as e:
            pytest.fail(f"Should not raise exception: {e}")


# Integration Tests (Optional - requires live targets)
@pytest.mark.skip(reason="Requires live target and permissions")
class TestIntegration:
    @pytest.mark.asyncio
    async def test_full_scan_flow(self):
        # Example: test against a test site like http://testphp.vulnweb.com
        # Only enable if you have permission
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
