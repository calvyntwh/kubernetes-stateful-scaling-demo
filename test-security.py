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
            "';alert('xss');//"
        ]
        
        for payload in xss_payloads:
            try:
                response = self.session.post(
                    urljoin(self.base_url, "/add"),
                    data={"message": payload},
                    allow_redirects=True
                )
                
                if response.status_code == 200:
                    # Check if payload was escaped - look for HTML entities
                    escaped_payload = html.escape(payload)
                    # Also check for double-escaped content (FastAPI + Jinja2)
                    double_escaped = escaped_payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    
                    if (escaped_payload in response.text or double_escaped in response.text) and payload not in response.text:
                        continue
                    else:
                        self.log_test(test_name, False, f"XSS payload not properly escaped: {payload}")
                        return
                else:
                    self.log_test(test_name, False, f"Unexpected status code: {response.status_code}")
                    return
            except Exception as e:
                self.log_test(test_name, False, f"Exception during XSS test: {str(e)}")
                return
        
        self.log_test(test_name, True, "All XSS payloads properly escaped")
    
    def test_input_validation(self):
        """Test input validation"""
        test_name = "Input Validation"
        
        # Test empty message
        try:
            response = self.session.post(
                urljoin(self.base_url, "/add"),
                data={"message": ""},
                allow_redirects=False
            )
            
            # Check for proper validation - either 422 status code, error in redirect location, or error message
            location_header = response.headers.get('location', '')
            if (response.status_code == 422 or 
                "Field required" in response.text or 
                "error" in response.url or 
                "Invalid input" in response.text or
                "error=" in location_header or
                (response.status_code == 303 and "error" in location_header)):
                self.log_test(test_name, True, "Empty messages properly rejected")
            else:
                self.log_test(test_name, False, "Empty messages not rejected")
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
        """Test basic SQL injection protection"""
        test_name = "SQL Injection Protection"
        sql_payloads = [
            "'; DROP TABLE guestbookentry; --",
            "' OR '1'='1",
            "' UNION SELECT * FROM config; --"
        ]
        
        for payload in sql_payloads:
            try:
                response = self.session.post(
                    urljoin(self.base_url, "/add"),
                    data={"message": payload},
                    allow_redirects=True
                )
                
                # If we get here without exception, SQLModel is protecting us
                if response.status_code in [200, 303]:
                    continue
                else:
                    self.log_test(test_name, False, f"Unexpected response to SQL injection: {response.status_code}")
                    return
            except Exception as e:
                # Exceptions could indicate SQL injection vulnerability
                self.log_test(test_name, False, f"Exception during SQL injection test: {str(e)}")
                return
        
        self.log_test(test_name, True, "SQL injection payloads handled safely")
    
    def test_security_headers(self):
        """Test for basic security headers"""
        test_name = "Security Headers"
        
        try:
            response = self.session.get(self.base_url)
            headers = response.headers
            
            # Check for basic security headers
            missing_headers = []
            
            if 'X-Content-Type-Options' not in headers:
                missing_headers.append('X-Content-Type-Options')
            
            if 'X-Frame-Options' not in headers:
                missing_headers.append('X-Frame-Options')
            
            if missing_headers:
                self.log_test(test_name, False, f"Missing security headers: {', '.join(missing_headers)}")
            else:
                self.log_test(test_name, True, "Basic security headers present")
                
        except Exception as e:
            self.log_test(test_name, False, f"Exception checking security headers: {str(e)}")
    
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
