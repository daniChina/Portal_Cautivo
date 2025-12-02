#!/usr/bin/env python3
"""
Gestión de usuarios y autenticación
"""

import json
import hashlib
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple

class UserManager:
    """Gestión completa de usuarios"""
    
    def __init__(self, db_path: str = "data/users.db"):
        self.db_path = db_path
        self.users = self._load_users()
        
        # Crear usuarios por defecto si no existen
        if not self.users:
            self._create_default_users()
    
    def _load_users(self) -> Dict:
        """Carga usuarios desde archivo JSON"""
        try:
            if os.path.exists(self.db_path):
                with open(self.db_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error cargando usuarios: {e}")
        
        return {}
    
    def _save_users(self):
        """Guarda usuarios en archivo JSON"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            with open(self.db_path, 'w') as f:
                json.dump(self.users, f, indent=2)
            return True
        except Exception as e:
            print(f"Error guardando usuarios: {e}")
            return False
    
    def _hash_password(self, password: str) -> str:
        """Genera hash SHA-256 de la contraseña"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _create_default_users(self):
        """Crea usuarios por defecto"""
        default_users = {
            "admin": {
                "password_hash": self._hash_password("admin123"),
                "email": "admin@red.local",
                "role": "admin",
                "created_at": datetime.now().isoformat(),
                "active": True
            },
            "usuario": {
                "password_hash": self._hash_password("usuario123"),
                "email": "usuario@red.local",
                "role": "user",
                "created_at": datetime.now().isoformat(),
                "active": True
            }
        }
        
        self.users = default_users
        self._save_users()
        print("Usuarios por defecto creados:")
        print("   - admin / admin123")
        print("   - usuario / usuario123")
    
    def authenticate(self, username: str, password: str) -> bool:
        """Autentica un usuario"""
        if username not in self.users:
            return False
        
        user = self.users[username]
        
        # Verificar si el usuario está activo
        if not user.get("active", True):
            return False
        
        # Verificar contraseña
        password_hash = self._hash_password(password)
        return user["password_hash"] == password_hash
    
    def add_user(self, username: str, password: str, email: str = "", role: str = "user") -> bool:
        """Añade un nuevo usuario"""
        if username in self.users:
            return False
        
        self.users[username] = {
            "password_hash": self._hash_password(password),
            "email": email or f"{username}@red.local",
            "role": role,
            "created_at": datetime.now().isoformat(),
            "active": True
        }
        
        return self._save_users()
    
    def update_user(self, username: str, **kwargs) -> bool:
        """Actualiza información de usuario"""
        if username not in self.users:
            return False
        
        user = self.users[username]
        
        # Actualizar campos permitidos
        allowed_fields = ["email", "role", "active"]
        for key, value in kwargs.items():
            if key in allowed_fields:
                user[key] = value
        
        return self._save_users()
    
    def change_password(self, username: str, new_password: str) -> bool:
        """Cambia la contraseña de un usuario"""
        if username not in self.users:
            return False
        
        self.users[username]["password_hash"] = self._hash_password(new_password)
        return self._save_users()
    
    def delete_user(self, username: str) -> bool:
        """Elimina un usuario"""
        if username not in self.users:
            return False
        
        del self.users[username]
        return self._save_users()
    
    def list_users(self) -> List[Dict]:
        """Lista todos los usuarios"""
        users_list = []
        for username, data in self.users.items():
            users_list.append({
                "username": username,
                "email": data.get("email", ""),
                "role": data.get("role", "user"),
                "created_at": data.get("created_at", ""),
                "active": data.get("active", True)
            })
        
        return users_list
    
    def get_user(self, username: str) -> Optional[Dict]:
        """Obtiene información de un usuario"""
        if username not in self.users:
            return None
        
        user_data = self.users[username].copy()
        user_data["username"] = username
        return user_data
    
    def user_exists(self, username: str) -> bool:
        """Verifica si un usuario existe"""
        return username in self.users
    
    def validate_credentials(self, username: str, password: str) -> Tuple[bool, str]:
        """Valida credenciales y retorna (éxito, mensaje)"""
        if not self.user_exists(username):
            return False, "Usuario no encontrado"
        
        if not self.authenticate(username, password):
            return False, "Contraseña incorrecta"
        
        user = self.users[username]
        if not user.get("active", True):
            return False, "Usuario desactivado"
        
        return True, "Autenticación exitosa"