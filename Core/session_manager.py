# core/session_manager.py
"""
User session manager
"""
import secrets
import time
import threading
import json
from datetime import datetime

class SessionManager:
    """Manages user sessions"""
    
    def __init__(self, session_timeout=3600):
        self.session_timeout = session_timeout
        self.sessions = {}
        self.lock = threading.Lock()
        self.session_log = []
    
    def create_session(self, username, ip, user_agent=''):
        """Create a new session"""
        session_id = secrets.token_hex(32)
        current_time = time.time()
        
        session = {
            'id': session_id,
            'username': username,
            'ip': ip,
            'user_agent': user_agent,
            'created': current_time,
            'expiry': current_time + self.session_timeout,
            'active': True
        }
        
        with self.lock:
            self.sessions[session_id] = session
            
            # Log session creation
            self.session_log.append({
                'session_id': session_id,
                'username': username,
                'ip': ip,
                'time': datetime.now().isoformat(),
                'action': 'login'
            })
        
        return session_id
    
    def get_session(self, session_id):
        """Get session by ID"""
        with self.lock:
            session = self.sessions.get(session_id)
            
            if session:
                # Check expiration
                if time.time() > session['expiry']:
                    del self.sessions[session_id]
                    return None
                
                return session
        
        return None
    
    def delete_session(self, session_id):
        """Delete a session"""
        with self.lock:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                
                # Log logout
                self.session_log.append({
                    'session_id': session_id,
                    'username': session['username'],
                    'ip': session['ip'],
                    'time': datetime.now().isoformat(),
                    'action': 'logout'
                })
                
                del self.sessions[session_id]
                return True
        
        return False
    
    def renew_session(self, session_id):
        """Renew session expiration time"""
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id]['expiry'] = time.time() + self.session_timeout
                return True
        
        return False
    
    def cleanup_expired_sessions(self):
        """Delete expired sessions and return affected IPs"""
        current_time = time.time()
        expired_sessions = []
        
        with self.lock:
            for session_id, session in list(self.sessions.items()):
                if current_time > session['expiry']:
                    expired_sessions.append(session['ip'])
                    del self.sessions[session_id]
                    
                    # Log expiration
                    self.session_log.append({
                        'session_id': session_id,
                        'username': session['username'],
                        'ip': session['ip'],
                        'time': datetime.now().isoformat(),
                        'action': 'expired'
                    })
        
        return expired_sessions
    
    def get_active_sessions(self):
        """Return all active sessions"""
        with self.lock:
            return list(self.sessions.values())
    
    def get_statistics(self):
        """Get session statistics"""
        with self.lock:
            total_sessions = len(self.session_log)
            active_sessions = len(self.sessions)
            
            # Count logins today
            today = datetime.now().date()
            logins_today = sum(
                1 for record in self.session_log
                if datetime.fromisoformat(record['time']).date() == today
                and record['action'] == 'login'
            )
            
            return {
                'active_sessions': active_sessions,
                'total_sessions': total_sessions,
                'logins_today': logins_today,
                'session_timeout': self.session_timeout
            }
    
    def save_log(self, path='data/logs/sessions.json'):
        """Save session log to a file"""
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self.session_log, f, indent=2)
        except Exception:
            pass
    
    def load_log(self, path='data/logs/sessions.json'):
        """Load session log from a file"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                self.session_log = json.load(f)
        except Exception:
            self.session_log = []