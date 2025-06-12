import json
from pathlib import Path
import re
import jwt

class SecurityManager:
    def __init__(self, config_file='security_config.json'):
        self.config_file = Path(config_file)
        self._load_config()
    
    def _load_config(self):
        default_config = {
            "blocked_user_agents": [],
            "allowed_user_agents": [],
            "required_cookies": [],
            "required_headers": {},
            "ip_whitelist": [],
            "ip_blacklist": [],
            "jwt_secret": "",
            "jwt_required": False,
            "csrf_tokens": {},
            "rate_limits": {}
        }
        
        if not self.config_file.exists():
            self.config = default_config
            self._save_config()
        else:
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
    
    def _save_config(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def update_config(self, new_config):
        self.config.update(new_config)
        self._save_config()
    
    def check_request(self, handler):
        client_ip = handler.client_address[0]
        
        # IP checks
        if client_ip in self.config['ip_blacklist']:
            return False, "IP blocked"
        
        if self.config['ip_whitelist'] and client_ip not in self.config['ip_whitelist']:
            return False, "IP not whitelisted"
        
        # User-Agent checks
        user_agent = handler.headers.get('User-Agent', '')
        if any(re.search(pattern, user_agent) for pattern in self.config['blocked_user_agents']):
            return False, "User-Agent blocked"
        
        if (self.config['allowed_user_agents'] and 
            not any(re.search(pattern, user_agent) for pattern in self.config['allowed_user_agents'])):
            return False, "User-Agent not allowed"
        
        # Cookie checks
        cookies = handler._parse_cookies()
        for cookie in self.config['required_cookies']:
            if cookie not in cookies:
                return False, f"Missing cookie: {cookie}"
        
        # Header checks
        for header, pattern in self.config['required_headers'].items():
            if header not in handler.headers:
                return False, f"Missing header: {header}"
            if pattern and not re.search(pattern, handler.headers[header]):
                return False, f"Invalid {header} format"
        
        # JWT verification
        if self.config['jwt_required']:
            auth_header = handler.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return False, "Missing JWT"
            
            try:
                token = auth_header[7:]
                handler.jwt_payload = jwt.decode(
                    token, 
                    self.config['jwt_secret'], 
                    algorithms=['HS256']
                )
            except jwt.ExpiredSignatureError:
                return False, "JWT expired"
            except jwt.InvalidTokenError:
                return False, "Invalid JWT"
        
        return True, "Access granted"
    
    def generate_csrf_token(self, user_id):
        token = jwt.encode(
            {'user_id': user_id, 'type': 'csrf'},
            self.config['jwt_secret'],
            algorithm='HS256'
        )
        self.config['csrf_tokens'][user_id] = token
        self._save_config()
        return token
    
    def verify_csrf_token(self, token):
        try:
            payload = jwt.decode(token, self.config['jwt_secret'], algorithms=['HS256'])
            return (payload.get('user_id') == self.config['csrf_tokens'].get(payload.get('user_id')))
        except:
            return False