#!/usr/bin/env python3
"""Security testing script for the Kubernetes Stateful Scaling Demo."""

import requests
import html
import time
import sys
import os
import re
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
        """Test XSS protection by submitting malicious payloads."""
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
                    # Check that the raw payload is NOT present in the HTML content
                    # We need to be careful not to match HTML structure elements
                    
                    # Look for the payload within the guestbook entries (inside <li> tags)
                    import re
                    # Extract all list items content
                    li_pattern = r'<li[^>]*>(.*?)</li>'
                    li_matches = re.findall(li_pattern, response.text, re.DOTALL)
                    
                    # Check if any list item contains the raw payload (vulnerability)
                    raw_payload_found = False
                    escaped_payload_found = False
                    
                    for li_content in li_matches:
                        if payload in li_content:
                            raw_payload_found = True
                            break
                        # Check for properly escaped content
                        escaped_payload = html.escape(payload)
                        if escaped_payload in li_content:
                            escaped_payload_found = True
                    
                    if raw_payload_found:
                        failed_tests.append(f"Raw XSS payload found unescaped: {payload[:50]}...")
                        continue
                    
                    # For most payloads, we expect to find them escaped
                    # Exception: payloads that start with "javascript:" might be filtered out entirely
                    if not payload.startswith("javascript:") and not escaped_payload_found:
                        # Check if the message was rejected/filtered (which is also acceptable)
                        if not any(payload[:10] in li for li in li_matches):
                            # Payload completely filtered - this is also secure
                            continue
                        else:
                            failed_tests.append(f"Payload found but not properly escaped: {payload[:50]}...")
                            continue
                
                elif response.status_code == 303:
                    # Redirected - check if it was an error redirect (input validation)
                    location = response.headers.get('location', '')
                    if 'error=' in location:
                        # Input was rejected - this is secure behavior
                        continue
                    else:
                        # Normal redirect after successful submission - check the page
                        follow_response = self.session.get(self.base_url)
                        if follow_response.status_code == 200:
                            # Same checks as above for the followed response
                            import re
                            li_pattern = r'<li[^>]*>(.*?)</li>'
                            li_matches = re.findall(li_pattern, follow_response.text, re.DOTALL)
                            
                            raw_payload_found = any(payload in li for li in li_matches)
                            if raw_payload_found:
                                failed_tests.append(f"Raw XSS payload found unescaped after redirect: {payload[:50]}...")
                                continue
                else:
                    failed_tests.append(f"Unexpected status code {response.status_code} for payload: {payload[:50]}...")
                    
            except Exception as e:
                failed_tests.append(f"Exception for payload '{payload[:50]}...': {str(e)}")
        
        if failed_tests:
            self.log_test(test_name, False, f"XSS protection issues: {'; '.join(failed_tests[:3])}")
        else:
            self.log_test(test_name, True, f"All {len(xss_payloads)} XSS payloads properly handled")
    
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
                # Count existing entries for comparison (entries are in <li> tags)
                import re
                li_pattern = r'<li[^>]*>.*?</li>'
                initial_entries = len(re.findall(li_pattern, response.text, re.DOTALL))
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
                    import re
                    li_pattern = r'<li[^>]*>.*?</li>'
                    current_entries = len(re.findall(li_pattern, response.text, re.DOTALL))
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
        
        vulnerabilities_found = []
        
        try:
            for payload in path_traversal_payloads:
                # Try accessing with path traversal in different parts of URL
                test_urls = [
                    f"{self.base_url}/{payload}",
                    f"{self.base_url}/static/{payload}",
                    f"{self.base_url}?file={payload}",
                ]
                
                for test_url in test_urls:
                    try:
                        response = self.session.get(test_url, timeout=5)
                        
                        # A vulnerable application would return 200 with sensitive file content
                        # We need to be more careful about what constitutes a vulnerability
                        if response.status_code == 200:
                            response_lower = response.text.lower()
                            
                            # Only flag as vulnerability if we get a 200 response that contains
                            # actual file system content indicators, not just normal web content
                            
                            # First, check if this looks like the normal application response
                            # (which would indicate proper handling, not a vulnerability)
                            normal_app_indicators = [
                                'guestbook', 'stateful', 'demo', 'html', 'body',
                                'form', 'submit', 'message', 'entries'
                            ]
                            
                            is_normal_app_response = any(indicator in response_lower for indicator in normal_app_indicators)
                            
                            if is_normal_app_response:
                                # This is just the normal app page, not file contents
                                continue
                            
                            # Check for actual file system content that would indicate real vulnerability
                            file_system_markers = [
                                'root:x:', 'daemon:x:', 'sys:x:', 'adm:x:',  # /etc/passwd format
                                '/bin/bash', '/bin/sh', '/sbin/nologin',     # shell paths
                                'password hash', 'shadow file',              # shadow file indicators
                                'windows registry', 'sam file', 'lm hash',  # Windows files
                                '[boot loader]', 'boot.ini',                # Windows boot files
                            ]
                            
                            found_markers = [marker for marker in file_system_markers if marker in response_lower]
                            
                            if found_markers:
                                vulnerabilities_found.append(f"Path traversal with {payload}: found file system content: {', '.join(found_markers[:2])}")
                                break
                            
                            # Additional check: very large responses with many colons and system-like format
                            elif (len(response.text) > 500 and 
                                  response.text.count(':') > 10 and 
                                  response.text.count('/') > 20 and
                                  not any(html_tag in response_lower for html_tag in ['<html', '<body', '<div', '<script'])):
                                vulnerabilities_found.append(f"Path traversal with {payload}: suspicious file-like content structure")
                                break
                        
                        # 404, 403, 400, etc. are all good - they indicate proper blocking
                        # Even 200 with normal app content is fine (proper error handling)
                        
                    except requests.exceptions.Timeout:
                        # Timeout is not necessarily a vulnerability
                        continue
                    except Exception as e:
                        # Other exceptions are generally not path traversal vulnerabilities
                        if "connection" not in str(e).lower():
                            # Log unexpected exceptions but don't fail the test
                            pass
                
                # If we found a vulnerability with this payload, no need to test more
                if vulnerabilities_found:
                    break
            
            if vulnerabilities_found:
                self.log_test(test_name, False, f"Path traversal vulnerabilities: {'; '.join(vulnerabilities_found[:2])}")
            else:
                self.log_test(test_name, True, "Path traversal payloads properly blocked or handled securely")
            
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
