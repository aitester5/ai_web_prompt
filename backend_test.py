#!/usr/bin/env python3

import requests
import json
import sys
import time
import websocket
import threading
from datetime import datetime
from typing import Dict, List, Any

class LLMVulnerabilityScannerTester:
    def __init__(self, base_url="https://1ec2d4d4-a7d8-4432-a0ff-a68023692622.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.session_id = None
        self.websocket_messages = []

    def log_test(self, name: str, success: bool, details: str = ""):
        """Log test results"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name} - PASSED {details}")
        else:
            print(f"❌ {name} - FAILED {details}")
        return success

    def make_request(self, method: str, endpoint: str, data: Dict = None, expected_status: int = 200) -> tuple:
        """Make HTTP request and return success status and response"""
        url = f"{self.api_url}/{endpoint}" if not endpoint.startswith('http') else endpoint
        headers = {'Content-Type': 'application/json'}
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=10)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=10)
            elif method == 'PUT':
                response = requests.put(url, json=data, headers=headers, timeout=10)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=10)
            else:
                return False, {}

            success = response.status_code == expected_status
            try:
                response_data = response.json()
            except:
                response_data = {"raw_response": response.text}
                
            return success, response_data, response.status_code
            
        except Exception as e:
            print(f"Request error: {str(e)}")
            return False, {"error": str(e)}, 0

    def test_health_check(self):
        """Test GET /api/ endpoint"""
        success, data, status = self.make_request('GET', '')
        expected_message = "LLM Vulnerability Scanner API"
        
        if success and data.get('message') == expected_message:
            return self.log_test("Health Check", True, f"- Status: {status}")
        else:
            return self.log_test("Health Check", False, f"- Status: {status}, Data: {data}")

    def test_get_environments(self):
        """Test GET /api/environments endpoint"""
        success, data, status = self.make_request('GET', 'environments')
        
        if success and 'environments' in data and isinstance(data['environments'], list):
            env_count = len(data['environments'])
            return self.log_test("Get Environments", True, f"- Found {env_count} environments")
        else:
            return self.log_test("Get Environments", False, f"- Status: {status}, Data: {data}")

    def test_get_models(self):
        """Test GET /api/models endpoint"""
        success, data, status = self.make_request('GET', 'models')
        
        if success and 'models' in data and isinstance(data['models'], list):
            model_count = len(data['models'])
            return self.log_test("Get Models", True, f"- Found {model_count} models")
        else:
            return self.log_test("Get Models", False, f"- Status: {status}, Data: {data}")

    def test_get_probes(self):
        """Test GET /api/probes endpoint"""
        success, data, status = self.make_request('GET', 'probes')
        
        if success and 'probes' in data and isinstance(data['probes'], list):
            probe_count = len(data['probes'])
            expected_probes = ["test.Test", "dan.Dan_11_0", "continuation.ContinueSlursReclaimedSlurs"]
            has_expected = any(probe in data['probes'] for probe in expected_probes)
            return self.log_test("Get Probes", True, f"- Found {probe_count} probes, has expected: {has_expected}")
        else:
            return self.log_test("Get Probes", False, f"- Status: {status}, Data: {data}")

    def test_create_scan(self):
        """Test POST /api/scan endpoint"""
        scan_data = {
            "environment": "test_env",
            "model_name": "test_model",
            "probes": ["test.Test"],
            "tool": "garak"
        }
        
        success, data, status = self.make_request('POST', 'scan', scan_data, 200)
        
        if success and 'session_id' in data and 'status' in data:
            self.session_id = data['session_id']
            return self.log_test("Create Scan", True, f"- Session ID: {self.session_id}")
        else:
            return self.log_test("Create Scan", False, f"- Status: {status}, Data: {data}")

    def test_get_scans(self):
        """Test GET /api/scans endpoint"""
        success, data, status = self.make_request('GET', 'scans')
        
        if success and 'sessions' in data and isinstance(data['sessions'], list):
            session_count = len(data['sessions'])
            return self.log_test("Get Scans", True, f"- Found {session_count} sessions")
        else:
            return self.log_test("Get Scans", False, f"- Status: {status}, Data: {data}")

    def test_get_specific_scan(self):
        """Test GET /api/scan/{session_id} endpoint"""
        if not self.session_id:
            return self.log_test("Get Specific Scan", False, "- No session ID available")
        
        success, data, status = self.make_request('GET', f'scan/{self.session_id}')
        
        if success and 'id' in data and data['id'] == self.session_id:
            return self.log_test("Get Specific Scan", True, f"- Retrieved session: {self.session_id}")
        else:
            return self.log_test("Get Specific Scan", False, f"- Status: {status}, Data: {data}")

    def test_create_status_check(self):
        """Test POST /api/status endpoint"""
        status_data = {
            "client_name": f"test_client_{datetime.now().strftime('%H%M%S')}"
        }
        
        success, data, status = self.make_request('POST', 'status', status_data, 200)
        
        if success and 'id' in data and 'client_name' in data:
            return self.log_test("Create Status Check", True, f"- Created status check: {data['id']}")
        else:
            return self.log_test("Create Status Check", False, f"- Status: {status}, Data: {data}")

    def test_get_status_checks(self):
        """Test GET /api/status endpoint"""
        success, data, status = self.make_request('GET', 'status')
        
        if success and isinstance(data, list):
            status_count = len(data)
            return self.log_test("Get Status Checks", True, f"- Found {status_count} status checks")
        else:
            return self.log_test("Get Status Checks", False, f"- Status: {status}, Data: {data}")

    def on_websocket_message(self, ws, message):
        """WebSocket message handler"""
        self.websocket_messages.append(message)
        print(f"📨 WebSocket message: {message}")

    def on_websocket_error(self, ws, error):
        """WebSocket error handler"""
        print(f"❌ WebSocket error: {error}")

    def on_websocket_close(self, ws, close_status_code, close_msg):
        """WebSocket close handler"""
        print(f"🔌 WebSocket closed: {close_status_code} - {close_msg}")

    def test_websocket_connection(self):
        """Test WebSocket /api/ws/scan/{session_id} endpoint"""
        if not self.session_id:
            return self.log_test("WebSocket Connection", False, "- No session ID available")
        
        try:
            ws_url = f"{self.base_url.replace('https', 'wss')}/api/ws/scan/{self.session_id}"
            print(f"🔌 Connecting to WebSocket: {ws_url}")
            
            ws = websocket.WebSocketApp(
                ws_url,
                on_message=self.on_websocket_message,
                on_error=self.on_websocket_error,
                on_close=self.on_websocket_close
            )
            
            # Run WebSocket in a separate thread
            wst = threading.Thread(target=ws.run_forever)
            wst.daemon = True
            wst.start()
            
            # Wait a bit for connection and messages
            time.sleep(5)
            ws.close()
            
            if len(self.websocket_messages) > 0:
                return self.log_test("WebSocket Connection", True, f"- Received {len(self.websocket_messages)} messages")
            else:
                return self.log_test("WebSocket Connection", False, "- No messages received")
                
        except Exception as e:
            return self.log_test("WebSocket Connection", False, f"- Error: {str(e)}")

    def test_error_handling(self):
        """Test various error scenarios"""
        print("\n🔍 Testing Error Handling...")
        
        # Test invalid endpoint
        success, data, status = self.make_request('GET', 'invalid_endpoint', expected_status=404)
        self.log_test("Invalid Endpoint (404)", status == 404, f"- Status: {status}")
        
        # Test invalid scan data
        invalid_scan_data = {
            "environment": "",  # Empty environment
            "model_name": "",   # Empty model
            "probes": [],       # Empty probes
            "tool": "invalid_tool"
        }
        success, data, status = self.make_request('POST', 'scan', invalid_scan_data, expected_status=422)
        self.log_test("Invalid Scan Data", status in [400, 422, 500], f"- Status: {status}")
        
        # Test non-existent session
        success, data, status = self.make_request('GET', 'scan/non-existent-id', expected_status=404)
        self.log_test("Non-existent Session", status == 404, f"- Status: {status}")

    def run_all_tests(self):
        """Run all API tests"""
        print("🚀 Starting LLM Vulnerability Scanner API Tests")
        print(f"🌐 Base URL: {self.base_url}")
        print("=" * 60)
        
        # Basic API tests
        self.test_health_check()
        self.test_get_environments()
        self.test_get_models()
        self.test_get_probes()
        
        # Scan workflow tests
        self.test_create_scan()
        self.test_get_scans()
        self.test_get_specific_scan()
        
        # Status check tests
        self.test_create_status_check()
        self.test_get_status_checks()
        
        # WebSocket test
        self.test_websocket_connection()
        
        # Error handling tests
        self.test_error_handling()
        
        # Print summary
        print("\n" + "=" * 60)
        print(f"📊 Test Summary: {self.tests_passed}/{self.tests_run} tests passed")
        
        if self.tests_passed == self.tests_run:
            print("🎉 All tests passed!")
            return 0
        else:
            print(f"⚠️  {self.tests_run - self.tests_passed} tests failed")
            return 1

def main():
    """Main test runner"""
    tester = LLMVulnerabilityScannerTester()
    return tester.run_all_tests()

if __name__ == "__main__":
    sys.exit(main())