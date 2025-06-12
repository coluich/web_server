from http.server import BaseHTTPRequestHandler
import json
from datetime import datetime
import urllib.parse

class BaseRequestHandler(BaseHTTPRequestHandler):
    def _send_response(self, content, content_type='text/html', status=200):
        self.send_response(status)
        self.send_header('Content-type', content_type)
        self.end_headers()
        if isinstance(content, (dict, list)):
            content = json.dumps(content)
        if isinstance(content, str):
            content = content.encode()
        self.wfile.write(content)
    
    def _send_html(self, content, status=200):
        self._send_response(content, 'text/html', status)
    
    def _send_json(self, data, status=200):
        self._send_response(data, 'application/json', status)
    
    def _send_error(self, code, message):
        self._send_response(f"{code} {message}", 'text/plain', code)
    
    def _parse_post_data(self):
        if not hasattr(self, '_post_data'):
            return None
        
        content_type = self.headers.get('Content-Type', '')
        try:
            if 'application/json' in content_type:
                return json.loads(self._post_data.decode())
            elif 'application/x-www-form-urlencoded' in content_type:
                return urllib.parse.parse_qs(self._post_data.decode())
            return self._post_data.decode('utf-8', 'replace')
        except Exception:
            return None
    
    def _parse_cookies(self):
        cookies = {}
        cookie_header = self.headers.get('Cookie', '')
        for cookie in cookie_header.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                cookies[name] = value
        return cookies