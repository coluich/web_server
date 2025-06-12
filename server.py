import sys
from http.server import HTTPServer
from server_logger import log_requests
from server_core import BaseRequestHandler
from security import SecurityManager
import json
from datetime import datetime
import urllib.parse

# Initialize security manager
security = SecurityManager()

class AppHandler(BaseRequestHandler):
    def __validate_request(self):
        is_valid, message = security.check_request(self)
        self._security_status = (is_valid, message)
        if not is_valid:
            self._send_error(403, f"Forbidden: {message}")
            return False
        return True
    
    def do_GET(self):
        if not self.__validate_request():
            return
        
        if self.path == '/':
            self._send_html("""
                <h1>Secure HTTP Server</h1>
                <p>Endpoints:</p>
                <ul>
                    <li>GET /testget?param=value</li>
                    <li>POST /testpost</li>
                    <li>GET /clientinfo</li>
                    <li>GET /generate-csrf</li>
                </ul>
            """)
        
        elif self.path.startswith('/testget'):
            self._handle_test_get()
        
        elif self.path == '/clientinfo':
            self._handle_client_info()
        
        elif self.path == '/generate-csrf':
            self._handle_generate_csrf()
        
        else:
            self._send_error(404, "Not Found")
    
    def do_POST(self):
        if not self.__validate_request():
            return
        
        if self.path == '/testpost':
            self._handle_test_post()
        
        elif self.path == '/validate-csrf':
            self._handle_validate_csrf()
        
        else:
            self._send_error(404, "Not Found")
    
    def _handle_test_get(self):
        parsed = urllib.parse.urlparse(self.path)
        response = {
            "status": "success",
            "method": "GET",
            "parameters": urllib.parse.parse_qs(parsed.query),
            "client_info": self._get_client_info(),
            "timestamp": datetime.now().isoformat()
        }
        self._send_json(response)
    
    def _handle_test_post(self):
        response = {
            "status": "success",
            "method": "POST",
            "content_type": self.headers.get('Content-Type', ''),
            "data": self._parse_post_data(),
            "client_info": self._get_client_info(),
            "timestamp": datetime.now().isoformat()
        }
        self._send_json(response)
    
    def _handle_client_info(self):
        self._send_json(self._get_client_info())
    
    def _handle_generate_csrf(self):
        user_id = "user123"  # In a real app, get from session
        token = security.generate_csrf_token(user_id)
        self._send_json({
            "csrf_token": token,
            "message": "Use this token in X-CSRF-Token header"
        })
    
    def _handle_validate_csrf(self):
        csrf_token = self.headers.get('X-CSRF-Token', '')
        is_valid = security.verify_csrf_token(csrf_token)
        self._send_json({
            "valid": is_valid,
            "message": "CSRF validation result"
        })
    
    def _get_client_info(self):
        return {
            "ip_address": self.client_address[0],
            "user_agent": self.headers.get('User-Agent', ''),
            "headers": dict(self.headers),
            "cookies": self._parse_cookies(),
            "jwt_payload": getattr(self, 'jwt_payload', None)
        }

# Configure and start server
HandlerWithLogging = log_requests(AppHandler)

def run_server(port=8000):
    server = HTTPServer(('', port), HandlerWithLogging)
    print(f"Server running on port {port}")
    print("Security configuration loaded from security_config.json")
    server.serve_forever()

if __name__ == '__main__':
    if sys.argv[1:]:
        port = int(sys.argv[1])
    run_server(port)