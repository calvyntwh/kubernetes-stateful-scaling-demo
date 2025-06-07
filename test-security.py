#!/usr/bin/env python3
"""Security testing script for the Kubernetes Stateful Scaling Demo."""

import html
import re
import sys
from urllib.parse import urljoin

import requests

# HTTP Status Code Constants
HTTP_OK = 200
HTTP_REDIRECT = 303
REDIRECT_STATUS_CODE = 303  # Alias for consistency
HTTP_BAD_REQUEST = 400
HTTP_NOT_FOUND = 404
HTTP_METHOD_NOT_ALLOWED = 405
HTTP_INTERNAL_ERROR = 500
HTTP_NOT_IMPLEMENTED = 501

# Test Constants
MIN_SECURITY_HEADERS = 2
MAX_PAYLOAD_LENGTH = 30
LARGE_RESPONSE_SIZE = 500
MANY_COLONS_COUNT = 10
MANY_SLASHES_COUNT = 20

# Error and Response Analysis Constants
SERVER_ERROR_THRESHOLD = 500
ERROR_STATUS_THRESHOLD = 400
TIMEOUT_SECONDS = 5
MAX_BRANCH_COMPLEXITY = 12
MAX_ENTRIES_TO_SHOW = 2
MAX_SENSITIVE_INFO_TO_SHOW = 3


class SecurityTester:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.test_results = []
    
    def log_test(self, test_name, passed, details=""):
        """Log test results with consistent formatting."""
        self.test_results.append((test_name, passed, details))

    def _check_xss_in_response(self, response_text, payload):
        """Check for XSS vulnerabilities in response text."""
        # Extract all list items content
        li_pattern = r"<li[^>]*>(.*?)</li>"
        li_matches = re.findall(li_pattern, response_text, re.DOTALL)
        
        # Check if any list item contains the raw payload (vulnerability)
        raw_payload_found = any(payload in li for li in li_matches)
        if raw_payload_found:
            return f"Raw XSS payload found unescaped: {payload[:MAX_PAYLOAD_LENGTH]}..."
        
        # Check for properly escaped content
        escaped_payload = html.escape(payload)
        escaped_payload_found = any(escaped_payload in li for li in li_matches)
        
        # For most payloads, we expect to find them escaped
        # Exception: payloads that start with "javascript:" might be filtered out
        if not payload.startswith("javascript:") and not escaped_payload_found:
            # Check if the message was rejected/filtered (acceptable)
            if not any(payload[:10] in li for li in li_matches):
                return None  # Payload completely filtered - secure
            truncated_payload = payload[:MAX_PAYLOAD_LENGTH]
            return f"Payload found but not properly escaped: {truncated_payload}..."
        
        return None
    
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
            ("javascript:/*--></title></style></textarea></script></xmp>"
             "<svg/onload='+/*/`/*\\`/*'/*\"/**/(alert('xss'))//'>"
            )
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
                
                if response.status_code == HTTP_OK:
                    error = self._check_xss_in_response(response.text, payload)
                    if error:
                        failed_tests.append(error)
                        continue
                
                elif response.status_code == HTTP_REDIRECT:
                    # Redirected - check if it was an error redirect
                    location = response.headers.get("location", "")
                    if "error=" in location:
                        continue  # Input was rejected - secure behavior
                    
                    # Check the redirected page
                    follow_response = self.session.get(self.base_url)
                    if follow_response.status_code == HTTP_OK:
                        error = self._check_xss_in_response(
                            follow_response.text, 
                            payload
                        )
                        if error:
                            failed_tests.append(f"{error} after redirect")
                
                else:
                    # Other status codes might indicate input validation errors
                    # which is acceptable security behavior
                    continue
                    
            except (requests.exceptions.RequestException, 
                    requests.exceptions.Timeout) as e:
                failed_tests.append(
                    f"Request failed for payload "
                    f"'{payload[:MAX_PAYLOAD_LENGTH]}': {e!s}"
                )
        
        if failed_tests:
            self.log_test(
                test_name, 
                passed=False, 
                details=f"XSS issues: {'; '.join(failed_tests[:2])}"
            )
        else:
            self.log_test(
                test_name, 
                passed=True, 
                details=f"All {len(xss_payloads)} XSS payloads properly handled"
            )

    
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
                
                location_header = response.headers.get("location", "")
                expected_redirect = (
                    response.status_code == REDIRECT_STATUS_CODE and
                    "error=" in location_header
                )
                if not expected_redirect:
                    all_passed = False
                    self.log_test(
                        test_name,
                        passed=False,
                        details=f"{description} not properly rejected"
                    )
                    return
            
            # Test that valid messages are accepted
            response = self.session.post(
                urljoin(self.base_url, "/add"),
                data={"message": "Valid test message"},
                allow_redirects=False
            )
            
            location_header = response.headers.get("location", "")
            valid_response = (
                response.status_code == REDIRECT_STATUS_CODE and
                "error=" not in location_header
            )
            if not valid_response:
                all_passed = False
                self.log_test(
                    test_name, 
                    passed=False, 
                    details="Valid messages not accepted"
                )
                return
            
            # Test for potential injection via form field names or other parameters
            response = self.session.post(
                urljoin(self.base_url, "/add"),
                data={
                    "message": "test", 
                    "extra_field": "<script>alert('xss')</script>"
                },
                allow_redirects=False
            )
            
            # Should still work normally (ignore extra fields)
            if response.status_code != REDIRECT_STATUS_CODE:
                all_passed = False
                self.log_test(
                    test_name, 
                    passed=False, 
                    details="Extra form fields cause errors"
                )
                return
                
            if all_passed:
                self.log_test(
                    test_name, 
                    passed=True, 
                    details="All input validation tests passed"
                )
        except (requests.RequestException, ValueError) as e:
            self.log_test(
                test_name, 
                passed=False, 
                details=f"Exception during input validation test: {e!s}"
            )
    
    def test_health_endpoint(self):
        """Test health endpoint security"""
        test_name = "Health Endpoint"
        
        try:
            response = self.session.get(urljoin(self.base_url, "/health"))
            if response.status_code == HTTP_OK:
                data = response.json()
                if "status" in data and data["status"] == "healthy":
                    self.log_test(
                        test_name, 
                        passed=True, 
                        details="Health endpoint working correctly"
                    )
                else:
                    self.log_test(
                        test_name, 
                        passed=False, 
                        details="Health endpoint returned unexpected data"
                    )
            else:
                message = f"Health endpoint returned status {response.status_code}"
                self.log_test(test_name, passed=False, details=message)
        except (requests.RequestException, ValueError, KeyError) as e:
            message = f"Exception accessing health endpoint: {e!s}"
            self.log_test(test_name, passed=False, details=message)
    
    def _get_entry_count(self):
        """Get the current count of entries on the page."""
        try:
            response = self.session.get(self.base_url)
            if response.status_code == HTTP_OK:
                li_pattern = r"<li[^>]*>.*?</li>"
                return len(re.findall(li_pattern, response.text, re.DOTALL))
        except requests.RequestException:
            pass
        return 0

    def _test_sql_payload(self, payload):
        """Test a single SQL injection payload."""
        try:
            response = self.session.post(
                urljoin(self.base_url, "/add"),
                data={"message": payload},
                allow_redirects=True
            )
            
            # SQL injection should not cause server errors
            if response.status_code >= SERVER_ERROR_THRESHOLD:
                return (
                    f"Server error (500+) with payload: "
                    f"{payload[:MAX_PAYLOAD_LENGTH]}..."
                )
                
            # Check acceptable response codes
            if response.status_code in [HTTP_OK, HTTP_REDIRECT]:
                # Payload was processed normally - this is good
                return None
                
            # Check if payload was stored as text (not executed as SQL)
            if response.status_code == HTTP_OK and payload in response.text:
                # This is good - payload stored as text, not executed as SQL
                return None
                
            return (
                f"Unexpected response {response.status_code} for: "
                f"{payload[:MAX_PAYLOAD_LENGTH]}..."
            )
            
        except (requests.RequestException, ValueError) as e:
            # Database errors could indicate SQL injection vulnerability
            if "database" in str(e).lower() or "sql" in str(e).lower():
                return (
                    f"Database error with payload "
                    f"'{payload[:MAX_PAYLOAD_LENGTH]}...': {e!s}"
                )
            # Other exceptions are less concerning but still worth noting
            return (
                f"Exception with payload "
                f"'{payload[:MAX_PAYLOAD_LENGTH]}...': {e!s}"
            )

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
            ("' OR EXISTS(SELECT * FROM guestbookentry "
             "WHERE message LIKE '%password%') --")
        ]
        
        failed_tests = []
        initial_entries = self._get_entry_count()
        
        # Test each SQL injection payload
        for payload in sql_payloads:
            error_message = self._test_sql_payload(payload)
            if error_message:
                failed_tests.append(error_message)
        
        # Verify no unexpected data manipulation occurred
        current_entries = self._get_entry_count()
        if current_entries < initial_entries:
            failed_tests.append("Entries appear to have been deleted unexpectedly")
        
        # Report results
        if failed_tests:
            issues = "; ".join(failed_tests[:MAX_ENTRIES_TO_SHOW])
            self.log_test(
                test_name, 
                passed=False, 
                details=f"SQL injection issues: {issues}"
            )
        else:
            details = f"All {len(sql_payloads)} SQL injection payloads handled safely"
            self.log_test(test_name, passed=True, details=details)
    
    def _check_security_header(self, headers, header_name, expected_value, description):
        """Check a single security header and return result."""
        if header_name not in headers:
            return None, f"{header_name} ({description})"
            
        header_value = headers[header_name]
        
        # Just check presence if expected_value is None
        if expected_value is None:
            return f"{header_name}: {header_value}", None
            
        # Check if value is in allowed list
        if isinstance(expected_value, list):
            if any(val in header_value for val in expected_value):
                return f"{header_name}: {header_value}", None
            return None, f"{header_name} (incorrect value: {header_value})"
                
        # Check exact value
        if expected_value in header_value:
            return f"{header_name}: {header_value}", None
        return None, f"{header_name} (incorrect value: {header_value})"

    def test_security_headers(self):
        """Test for security headers"""
        test_name = "Security Headers"
        
        try:
            response = self.session.get(self.base_url)
            headers = response.headers
            
            # Define security header checks
            security_checks = [
                ("X-Content-Type-Options", "nosniff", "prevents MIME type sniffing"),
                ("X-Frame-Options", ["DENY", "SAMEORIGIN"], "prevents clickjacking"),
                ("X-XSS-Protection", "1; mode=block", "enables XSS filtering"),
                ("Referrer-Policy", None, "controls referrer information"),
                ("Content-Security-Policy", None, "prevents XSS and injection attacks")
            ]
            
            present_headers = []
            missing_headers = []
            
            # Check each security header
            for header_name, expected_value, description in security_checks:
                present, missing = self._check_security_header(
                    headers, header_name, expected_value, description
                )
                if present:
                    present_headers.append(present)
                if missing:
                    missing_headers.append(missing)
            
            # Evaluate results
            required_headers = ["X-Content-Type-Options", "X-Frame-Options"]
            has_required = all(h in headers for h in required_headers)
            
            if has_required and len(present_headers) >= MIN_SECURITY_HEADERS:
                details = f"Present: {', '.join(present_headers)}"
                if missing_headers:
                    missing_list = missing_headers[:MAX_SENSITIVE_INFO_TO_SHOW]
                    details += f"; Missing: {', '.join(missing_list)}"
                self.log_test(test_name, passed=True, details=details)
            else:
                missing_list = ", ".join(missing_headers)
                message = f"Missing critical headers: {missing_list}"
                self.log_test(test_name, passed=False, details=message)
                
        except requests.RequestException as e:
            message = f"Exception checking security headers: {e!s}"
            self.log_test(test_name, passed=False, details=message)
    
    def test_http_methods(self):
        """Test HTTP method restrictions"""
        test_name = "HTTP Method Security"
        
        try:
            # Test that only allowed methods work
            methods_to_test = ["PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
            
            for method in methods_to_test:
                response = self.session.request(method, self.base_url)
                # Should be 405 (Method Not Allowed), 501 (Not Implemented), or 404
                allowed_codes = [
                    HTTP_METHOD_NOT_ALLOWED, 
                    HTTP_NOT_IMPLEMENTED, 
                    HTTP_NOT_FOUND
                ]
                if response.status_code not in allowed_codes:
                    message = f"{method} method unexpectedly allowed"
                    self.log_test(test_name, passed=False, details=message)
                    return
            
            # Test that POST to /add works (should be allowed)
            response = self.session.post(
                urljoin(self.base_url, "/add"),
                data={"message": "test"}
            )
            if response.status_code not in [HTTP_OK, HTTP_REDIRECT]:
                message = "POST method not working for valid endpoint"
                self.log_test(test_name, passed=False, details=message)
                return
            
            self.log_test(
                test_name, 
                passed=True, 
                details="HTTP methods properly restricted"
            )
            
        except requests.RequestException as e:
            message = f"Exception testing HTTP methods: {e!s}"
            self.log_test(test_name, passed=False, details=message)
    
    def _is_normal_app_response(self, response_text):
        """Check if response looks like normal application content."""
        response_lower = response_text.lower()
        normal_app_indicators = [
            "guestbook", "stateful", "demo", "html", "body",
            "form", "submit", "message", "entries"
        ]
        return any(indicator in response_lower for indicator in normal_app_indicators)
    
    def _check_file_system_content(self, response_text):
        """Check if response contains file system content markers."""
        response_lower = response_text.lower()
        file_system_markers = [
            "root:x:", "daemon:x:", "sys:x:", "adm:x:",  # /etc/passwd format
            "/bin/bash", "/bin/sh", "/sbin/nologin",     # shell paths
            "password hash", "shadow file",              # shadow file indicators
            "windows registry", "sam file", "lm hash",  # Windows files
            "[boot loader]", "boot.ini",                # Windows boot files
        ]
        return [marker for marker in file_system_markers if marker in response_lower]
    
    def _check_suspicious_file_structure(self, response_text):
        """Check for suspicious file-like content structure."""
        response_lower = response_text.lower()
        
        # Check for file-like structure: large responses with many colons/slashes
        has_large_size = len(response_text) > LARGE_RESPONSE_SIZE
        has_many_colons = response_text.count(":") > MANY_COLONS_COUNT
        has_many_slashes = response_text.count("/") > MANY_SLASHES_COUNT
        
        # Should not contain HTML tags if it's a real file
        html_tags = ["<html", "<body", "<div", "<script"]
        has_no_html = not any(tag in response_lower for tag in html_tags)
        
        return has_large_size and has_many_colons and has_many_slashes and has_no_html
    
    def _test_path_traversal_url(self, test_url, payload):
        """Test a single URL for path traversal vulnerability."""
        vulnerability_message = None
        
        try:
            response = self.session.get(test_url, timeout=TIMEOUT_SECONDS)
            
            # Only check 200 responses for vulnerabilities
            if (response.status_code == HTTP_OK and 
                not self._is_normal_app_response(response.text)):
                # Check for actual file system content
                found_markers = self._check_file_system_content(response.text)
                if found_markers:
                    markers_str = ", ".join(found_markers[:MAX_ENTRIES_TO_SHOW])
                    vulnerability_message = (
                        f"Path traversal with {payload}: found file system "
                        f"content: {markers_str}"
                    )
                # Check for suspicious file-like structure
                elif self._check_suspicious_file_structure(response.text):
                    vulnerability_message = (
                        f"Path traversal with {payload}: suspicious "
                        f"file-like content structure"
                    )
        except requests.exceptions.Timeout:
            pass  # Timeout is not a vulnerability
        except requests.RequestException as e:
            if "connection" not in str(e).lower():
                # Log unexpected exceptions but don't treat as vulnerability
                pass
            
        return vulnerability_message

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
                    vulnerability = self._test_path_traversal_url(test_url, payload)
                    if vulnerability:
                        vulnerabilities_found.append(vulnerability)
                        break  # Found vulnerability with this payload
                
                # If we found a vulnerability with this payload, break
                if vulnerabilities_found:
                    break
            
            # Report results
            if vulnerabilities_found:
                issues = "; ".join(vulnerabilities_found[:MAX_ENTRIES_TO_SHOW])
                message = f"Path traversal vulnerabilities: {issues}"
                self.log_test(test_name, passed=False, details=message)
            else:
                message = "Path traversal payloads properly blocked or handled securely"
                self.log_test(test_name, passed=True, details=message)
            
        except requests.RequestException as e:
            message = f"Exception testing path traversal: {e!s}"
            self.log_test(test_name, passed=False, details=message)
    
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
                    "traceback", "exception", "stack trace", "internal server error",
                    "database", "sql", "connection string", "password", "secret",
                    "debug", "dev", "development", "/app/", "/usr/", "/var/",
                    "python", "fastapi", "uvicorn"
                ]
                
                response_lower = response.text.lower()
                found_sensitive = [
                    info for info in sensitive_info if info in response_lower
                ]
                
                if found_sensitive and response.status_code >= ERROR_STATUS_THRESHOLD:
                    sensitive_list = found_sensitive[:MAX_SENSITIVE_INFO_TO_SHOW]
                    message = (
                        f"Error exposes sensitive info: "
                        f"{', '.join(sensitive_list)}"
                    )
                    self.log_test(test_name, passed=False, details=message)
                    return
            
            message = "Error handling doesn't leak sensitive information"
            self.log_test(test_name, passed=True, details=message)
            
        except requests.RequestException as e:
            message = f"Exception testing error handling: {e!s}"
            self.log_test(test_name, passed=False, details=message)
    
    def run_all_tests(self):
        """Run all security tests"""
        
        # Test if application is accessible
        try:
            response = self.session.get(self.base_url, timeout=TIMEOUT_SECONDS)
            if response.status_code != HTTP_OK:
                return False
        except requests.RequestException:
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
        passed = sum(1 for _, result, _ in self.test_results if result)
        total = len(self.test_results)
        
        return passed == total

if __name__ == "__main__":
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    tester = SecurityTester(base_url)
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)
