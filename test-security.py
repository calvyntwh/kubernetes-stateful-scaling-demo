#!/usr/bin/env python3
"""
Security testing script for the Kubernetes Stateful Scaling Demo
Tests various security aspects of the application
"""

import requests
import html
import time
import sys
import os
from urllib.parse import urljoin

class SecurityTester:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.test_results = []
    
    def log_test(self, test_name, passed, details=""):
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status}: {test_name}")
        if details:
            print(f"    {details}")
        self.test_results.append((test_name, passed, details))
    
    def test_xss_protection(self):
        """Test XSS protection by submitting malicious payloads"""
        test_name = "XSS Protection"
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "';alert('xss');//",
            "<iframe src='javascript:alert(1)'></iframe>",
            "<<SCRIPT>alert('XSS');//<</SCRIPT>",
            "<svg onload=alert('xss')>",
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/*/`/*\\`/*'/*\"/**/(alert('xss'))//'>"
        ]
        
        failed_tests = []
        
        for payload in xss_payloads:
            try:
                # Submit the payload
                response = self.session.post(
                    urljoin(self.base_url, "/add"),
                    data={"message": payload},
                    allow_redirects=True
                )
                
                if response.status_code == 200:
                    # The payload should be HTML-escaped in the response
                    escaped_payload = html.escape(payload)
                    
                    # Check that the raw payload is NOT present (would indicate XSS vulnerability)
                    if payload in response.text:
                        failed_tests.append(f"Raw payload found in response: {payload[:50]}...")
                        continue
                    
                    # Check that escaped version IS present (indicates proper escaping)
                    if escaped_payload not in response.text:
                        # Sometimes double escaping occurs with frameworks
                        double_escaped = html.escape(escaped_payload)
                        if double_escaped not in response.text:
                            failed_tests.append(f"Payload not found escaped in response: {payload[:50]}...")
                            continue
                else:
                    failed_tests.append(f"Unexpected status code {response.status_code} for payload: {payload[:50]}...")
                    
            except Exception as e:
                failed_tests.append(f"Exception for payload '{payload[:50]}...': {str(e)}")
        
        if failed_tests:
            self.log_test(test_name, False, f"XSS protection issues: {'; '.join(failed_tests[:3])}")
        else:
            self.log_test(test_name, True, f"All {len(xss_payloads)} XSS payloads properly escaped")
    
    def test_input_validation(self):
        """Test input validation"""
        test_name = "Input Validation"
        
        invalid_inputs = [
            ("", "empty message"),
            ("   ", "whitespace-only message"),
            ("\t\n\r", "tab/newline only message"),
        ]
        
        all_passed = True
        
        try:
            # Test invalid inputs are rejected
            for test_input, description in invalid_inputs:
                response = self.session.post(
                    urljoin(self.base_url, "/add"),
                    data={"message": test_input},
                    allow_redirects=False
                )
                
                location_header = response.headers.get('location', '')
                if not (response.status_code == 303 and "error=" in location_header):
                    all_passed = False
                    self.log_test(test_name, False, f"{description} not properly rejected")
                    return
            
            # Test that valid messages are accepted
            response = self.session.post(
                urljoin(self.base_url, "/add"),
                data={"message": "Valid test message"},
                allow_redirects=False
            )
            
            location_header = response.headers.get('location', '')
            if not (response.status_code == 303 and "error=" not in location_header):
                all_passed = False
                self.log_test(test_name, False, "Valid messages not accepted")
                return
            
            # Test for potential injection via form field names or other parameters
            response = self.session.post(
                urljoin(self.base_url, "/add"),
                data={"message": "test", "extra_field": "<script>alert('xss')</script>"},
                allow_redirects=False
            )
            
            # Should still work normally (ignore extra fields)
            if response.status_code != 303:
                all_passed = False
                self.log_test(test_name, False, "Extra form fields cause errors")
                return
                
            if all_passed:
                self.log_test(test_name, True, "All input validation tests passed")
        except Exception as e:
            self.log_test(test_name, False, f"Exception during input validation test: {str(e)}")
    
    def test_health_endpoint(self):
        """Test health endpoint security"""
        test_name = "Health Endpoint"
        
        try:
            response = self.session.get(urljoin(self.base_url, "/health"))
            if response.status_code == 200:
                data = response.json()
                if "status" in data and data["status"] == "healthy":
                    self.log_test(test_name, True, "Health endpoint working correctly")
                else:
                    self.log_test(test_name, False, "Health endpoint returned unexpected data")
            else:
                self.log_test(test_name, False, f"Health endpoint returned status {response.status_code}")
        except Exception as e:
            self.log_test(test_name, False, f"Exception accessing health endpoint: {str(e)}")
    
    def test_sql_injection(self):
        """Test SQL injection protection"""
        test_name = "SQL Injection Protection"
        sql_payloads = [
            "'; DROP TABLE guestbookentry; --",
            "' OR '1'='1",
            "' UNION SELECT * FROM config; --",
            "admin'--",
            "admin'/*",
            "' OR 1=1--",
            "'; INSERT INTO guestbookentry (message) VALUES ('injected'); --",
            "' OR EXISTS(SELECT * FROM guestbookentry WHERE message LIKE '%password%') --"
        ]
        
        failed_tests = []
        initial_entries = None
        
        try:
            # Get initial entry count
            response = self.session.get(self.base_url)
            if response.status_code == 200:
                # Count existing entries for comparison
                initial_entries = response.text.count('<div class="message-item">')
        except:
            pass
        
        for payload in sql_payloads:
            try:
                response = self.session.post(
                    urljoin(self.base_url, "/add"),
                    data={"message": payload},
                    allow_redirects=True
                )
                
                # SQL injection should not cause server errors
                if response.status_code >= 500:
                    failed_tests.append(f"Server error (500+) with payload: {payload[:30]}...")
                    continue
                
                # Check that the payload was treated as regular text, not SQL
                if response.status_code == 200 and payload in response.text:
                    # This is good - the payload was stored as text, not executed as SQL
                    continue
                elif response.status_code in [200, 303]:
                    # Also acceptable - request processed normally
                    continue
                else:
                    failed_tests.append(f"Unexpected response {response.status_code} for: {payload[:30]}...")
                    
            except Exception as e:
                # Database errors could indicate SQL injection vulnerability
                if "database" in str(e).lower() or "sql" in str(e).lower():
                    failed_tests.append(f"Database error with payload '{payload[:30]}...': {str(e)}")
                else:
                    # Other exceptions are less concerning but still worth noting
                    failed_tests.append(f"Exception with payload '{payload[:30]}...': {str(e)}")
        
        # Additional check: verify no unexpected data manipulation occurred
        if initial_entries is not None:
            try:
                response = self.session.get(self.base_url)
                if response.status_code == 200:
                    current_entries = response.text.count('<div class="message-item">')
                    # Should have added our test entries, but not unexpected ones
                    if current_entries < initial_entries:
                        failed_tests.append("Entries appear to have been deleted unexpectedly")
            except:
                pass
        
        if failed_tests:
            self.log_test(test_name, False, f"SQL injection issues: {'; '.join(failed_tests[:2])}")
        else:
            self.log_test(test_name, True, f"All {len(sql_payloads)} SQL injection payloads handled safely")
    
    def test_security_headers(self):
        """Test for security headers"""
        test_name = "Security Headers"
        
        try:
            response = self.session.get(self.base_url)
            headers = response.headers
            
            # Check for important security headers
            security_checks = [
                ('X-Content-Type-Options', 'nosniff', "prevents MIME type sniffing"),
                ('X-Frame-Options', ['DENY', 'SAMEORIGIN'], "prevents clickjacking"),
                ('X-XSS-Protection', '1; mode=block', "enables XSS filtering"),
                ('Referrer-Policy', None, "controls referrer information"),
                ('Content-Security-Policy', None, "prevents XSS and injection attacks")
            ]
            
            present_headers = []
            missing_headers = []
            
            for header_name, expected_value, description in security_checks:
                if header_name in headers:
                    header_value = headers[header_name]
                    if expected_value is None:
                        # Just check presence
                        present_headers.append(f"{header_name}: {header_value}")
                    elif isinstance(expected_value, list):
                        # Check if value is in allowed list
                        if any(val in header_value for val in expected_value):
                            present_headers.append(f"{header_name}: {header_value}")
                        else:
                            missing_headers.append(f"{header_name} (incorrect value: {header_value})")
                    else:
                        # Check exact value
                        if expected_value in header_value:
                            present_headers.append(f"{header_name}: {header_value}")
                        else:
                            missing_headers.append(f"{header_name} (incorrect value: {header_value})")
                else:
                    missing_headers.append(f"{header_name} ({description})")
            
            # We need at least basic headers to pass
            required_headers = ['X-Content-Type-Options', 'X-Frame-Options']
            has_required = all(h in headers for h in required_headers)
            
            if has_required and len(present_headers) >= 2:
                details = f"Present: {', '.join(present_headers)}"
                if missing_headers:
                    details += f"; Missing: {', '.join(missing_headers[:3])}"
                self.log_test(test_name, True, details)
            else:
                self.log_test(test_name, False, f"Missing critical headers: {', '.join(missing_headers)}")
                
        except Exception as e:
            self.log_test(test_name, False, f"Exception checking security headers: {str(e)}")
    
    def test_http_methods(self):
        """Test HTTP method restrictions"""
        test_name = "HTTP Method Security"
        
        try:
            # Test that only allowed methods work
            methods_to_test = ['PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
            
            for method in methods_to_test:
                response = self.session.request(method, self.base_url)
                # Should either be 405 (Method Not Allowed) or 501 (Not Implemented)
                if response.status_code not in [405, 501, 404]:
                    self.log_test(test_name, False, f"{method} method unexpectedly allowed")
                    return
            
            # Test that POST to /add works (should be allowed)
            response = self.session.post(
                urljoin(self.base_url, "/add"),
                data={"message": "test"}
            )
            if response.status_code not in [200, 303]:
                self.log_test(test_name, False, "POST method not working for valid endpoint")
                return
            
            self.log_test(test_name, True, "HTTP methods properly restricted")
            
        except Exception as e:
            self.log_test(test_name, False, f"Exception testing HTTP methods: {str(e)}")
    
    def test_path_traversal(self):
        """Test path traversal protection"""
        test_name = "Path Traversal Protection"
        
        path_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",  # URL encoded
            "..%252f..%252f..%252fetc%252fpasswd",  # Double URL encoded
        ]
        
        try:
            for payload in path_traversal_payloads:
                # Try accessing with path traversal in different parts of URL
                test_urls = [
                    f"{self.base_url}/{payload}",
                    f"{self.base_url}/static/{payload}",
                    f"{self.base_url}?file={payload}",
                ]
                
                for test_url in test_urls:
                    response = self.session.get(test_url)
                    
                    # Should not return sensitive files (200 with file content)
                    if (response.status_code == 200 and 
                        any(marker in response.text.lower() for marker in 
                            ['root:', 'administrator', '/bin/bash', 'password', 'SAM file'])):
                        self.log_test(test_name, False, f"Path traversal vulnerability with: {payload}")
                        return
            
            self.log_test(test_name, True, "Path traversal payloads properly blocked")
            
        except Exception as e:
            self.log_test(test_name, False, f"Exception testing path traversal: {str(e)}")
    
    def test_error_handling(self):
        """Test that errors don't leak sensitive information"""
        test_name = "Error Handling Security"
        
        try:
            # Test various error conditions
            error_tests = [
                (f"{self.base_url}/nonexistent", "404 errors"),
                (f"{self.base_url}/add", "POST without data"),
            ]
            
            for test_url, description in error_tests:
                if "POST" in description:
                    response = self.session.post(test_url)
                else:
                    response = self.session.get(test_url)
                
                # Check that error responses don't contain sensitive information
                sensitive_info = [
                    'traceback', 'exception', 'stack trace', 'internal server error',
                    'database', 'sql', 'connection string', 'password', 'secret',
                    'debug', 'dev', 'development', '/app/', '/usr/', '/var/',
                    'python', 'fastapi', 'uvicorn'
                ]
                
                response_lower = response.text.lower()
                found_sensitive = [info for info in sensitive_info if info in response_lower]
                
                if found_sensitive and response.status_code >= 400:
                    self.log_test(test_name, False, f"Error exposes sensitive info: {', '.join(found_sensitive[:3])}")
                    return
            
            self.log_test(test_name, True, "Error handling doesn't leak sensitive information")
            
        except Exception as e:
            self.log_test(test_name, False, f"Exception testing error handling: {str(e)}")
    
    def run_all_tests(self):
        """Run all security tests"""
        print("🔒 Starting Security Tests...")
        print(f"Target: {self.base_url}")
        print("-" * 50)
        
        # Test if application is accessible
        try:
            response = self.session.get(self.base_url, timeout=5)
            if response.status_code != 200:
                print(f"❌ Application not accessible at {self.base_url}")
                return False
        except Exception as e:
            print(f"❌ Cannot connect to application: {str(e)}")
            return False
        
        # Run tests
        self.test_health_endpoint()
        self.test_input_validation()
        self.test_xss_protection()
        self.test_sql_injection()
        self.test_security_headers()
        self.test_http_methods()
        self.test_path_traversal()
        self.test_error_handling()
        
        # Summary
        print("-" * 50)
        passed = sum(1 for _, result, _ in self.test_results if result)
        total = len(self.test_results)
        print(f"Security Tests Summary: {passed}/{total} passed")
        
        if passed == total:
            print("🎉 All security tests passed!")
            return True
        else:
            print("⚠️  Some security tests failed. Please review the issues above.")
            return False

if __name__ == "__main__":
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    tester = SecurityTester(base_url)
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)
