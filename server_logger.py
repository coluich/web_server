import urllib.parse
import json
import socket
from datetime import datetime
from pprint import pformat
from pathlib import Path

class RequestLogger:
    def __init__(self, handler):
        self.handler = handler
        self._start_time = datetime.now()
    
    def log_request(self):
        log_data = self._collect_log_data()
        self._print_log(log_data)
        return log_data
    
    def _collect_log_data(self):
        return {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'client': self._get_client_info(),
            'method': self.handler.command,
            'path': self.handler.path,
            'duration': f"{(datetime.now() - self._start_time).total_seconds():.3f}s",
            'headers': dict(self.handler.headers),
            'params': self._get_request_params(),
            'security_check': getattr(self.handler, '_security_status', ('N/A', 'No security check'))
        }
    
    def _get_client_info(self):
        client_ip = self.handler.client_address[0]
        try:
            return f"{client_ip} ({socket.gethostbyaddr(client_ip)[0]})"
        except (socket.herror, socket.gaierror):
            return f"{client_ip} (unknown)"
    
    def _get_request_params(self):
        method = self.handler.command
        if method == "GET":
            return self._parse_get_params()
        elif method == "POST":
            return self._parse_post_data()
        return None
    
    def _parse_get_params(self):
        parsed = urllib.parse.urlparse(self.handler.path)
        return urllib.parse.parse_qs(parsed.query)
    
    def _parse_post_data(self):
        if not hasattr(self.handler, '_post_data'):
            return None
            
        content_type = self.handler.headers.get('Content-Type', '')
        try:
            if 'application/json' in content_type:
                return json.loads(self.handler._post_data.decode())
            elif 'application/x-www-form-urlencoded' in content_type:
                return urllib.parse.parse_qs(self.handler._post_data.decode())
            return self.handler._post_data.decode('utf-8', 'replace')
        except Exception as e:
            return f"Parse error: {str(e)}"
    
    def _print_log(self, log_data):
        print(f"\n{'='*60}")
        print(f"[{log_data['timestamp']}] {log_data['client']}")
        print(f"{log_data['method']} {log_data['path']} - {log_data['duration']}")
        print('-'*60)
        print("SECURITY STATUS:", log_data['security_check'][1])
        print('-'*60)
        print("HEADERS:")
        print(pformat(log_data['headers'], width=120))
        
        if log_data['params']:
            print(f"\n{log_data['method']} PARAMETERS:")
            print(pformat(log_data['params'], width=120))
        print('='*60)

def log_requests(handler_class):
    class LoggingHandler(handler_class):
        def __init__(self, *args, **kwargs):
            self.logger = RequestLogger(self)
            super().__init__(*args, **kwargs)
        
        def do_GET(self):
            self.logger.log_request()
            super().do_GET()
        
        def do_POST(self):
            content_length = int(self.headers.get('Content-Length', 0))
            self._post_data = self.rfile.read(content_length) if content_length > 0 else b''
            self.logger.log_request()
            super().do_POST()
    
    return LoggingHandler