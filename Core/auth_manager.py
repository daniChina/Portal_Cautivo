# core/auth_manager.py
"""
User authentication manager
"""
import hashlib
import os
import json
import time

class AuthManager:
    """Handles user authentication"""
    
    def __init__(self, users_path='data/users.json'):
        self.users_path = users_path
        self.users = self.load_users()
        self.failed_attempts = {}
    
    def load_users(self):
        """Load users from JSON file"""
        try:
            with open(self.users_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            # Create file with default admin user
            default_users = {
                'admin': self.create_password_hash('admin123')
            }
            self.save_users(default_users)
            return default_users
        except json.JSONDecodeError:
            return {}
    
    def save_users(self, users=None):
        """Save users to JSON file"""
        if users is None:
            users = self.users
        
        with open(self.users_path, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2)
    
    def create_password_hash(self, password):
        """Create password hash with salt"""
        salt = os.urandom(16).hex()
        password_hash = hashlib.sha256((salt + password).encode()).hexdigest()
        return {
            'salt': salt,
            'hash': password_hash,
            'created': time.time()
        }
    
    def verify_password(self, password, user_data):
        """Verify if password matches"""
        if 'salt' not in user_data or 'hash' not in user_data:
            return False
        
        calculated_hash = hashlib.sha256(
            (user_data['salt'] + password).encode()
        ).hexdigest()
        
        return calculated_hash == user_data['hash']
    
    def authenticate(self, username, password):
        """Authenticate a user"""
        # Check if user is blocked
        if self.is_blocked(username):
            return False
        
        # Check if user exists
        if username not in self.users:
            self.register_failed_attempt(username)
            return False
        
        # Verify password
        if self.verify_password(password, self.users[username]):
            # Reset failed attempts
            if username in self.failed_attempts:
                del self.failed_attempts[username]
            return True
        else:
            self.register_failed_attempt(username)
            return False
    
    def register_failed_attempt(self, username):
        """Register a failed login attempt"""
        if username not in self.failed_attempts:
            self.failed_attempts[username] = {
                'attempts': 0,
                'last_attempt': time.time()
            }
        
        self.failed_attempts[username]['attempts'] += 1
        self.failed_attempts[username]['last_attempt'] = time.time()
    
    def is_blocked(self, username):
        """Check if a user is blocked"""
        if username not in self.failed_attempts:
            return False
        
        data = self.failed_attempts[username]
        
        # If more than 15 minutes have passed, reset
        if time.time() - data['last_attempt'] > 900:  # 15 minutes
            del self.failed_attempts[username]
            return False
        
        # Block after 5 failed attempts
        return data['attempts'] >= 5
    
    def create_user(self, username, password):
        """Create a new user"""
        if username in self.users:
            return False
        
        self.users[username] = self.create_password_hash(password)
        self.save_users()
        return True
    
    def delete_user(self, username):
        """Delete a user"""
        if username in self.users:
            del self.users[username]
            self.save_users()
            return True
        return False
    
    def change_password(self, username, new_password):
        """Change user password"""
        if username not in self.users:
            return False
        
        self.users[username] = self.create_password_hash(new_password)
        self.save_users()
        return True