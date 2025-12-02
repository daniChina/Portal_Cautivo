#!/usr/bin/env python3
"""
Gestión de sesiones de usuario
"""

import json
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from threading import Lock

class SessionManager:
    """Gestión de sesiones de autenticación"""
    
    def __init__(self, db_path: str = "data/sessions.db", session_timeout: int = 28800):
        """
        Args:
            db_path: Ruta al archivo de sesiones
            session_timeout: Tiempo de sesión en segundos (8 horas por defecto)
        """
        self.db_path = db_path
        self.session_timeout = session_timeout  # 8 horas en segundos
        self.sessions: Dict[str, Dict] = {}
        self.lock = Lock()
        
        # Cargar sesiones existentes
        self._load_sessions()
        
        # Iniciar limpieza periódica
        self._cleanup_thread = None
        self.running = True
    
    def _load_sessions(self):
        """Carga sesiones desde archivo"""
        try:
            if os.path.exists(self.db_path):
                with open(self.db_path, 'r') as f:
                    self.sessions = json.load(f)
        except Exception as e:
            print(f"Error cargando sesiones: {e}")
            self.sessions = {}
    
    def _save_sessions(self):
        """Guarda sesiones en archivo"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            with open(self.db_path, 'w') as f:
                json.dump(self.sessions, f, indent=2)
        except Exception as e:
            print(f"Error guardando sesiones: {e}")
    
    def create_session(self, client_ip: str, username: str) -> str:
        """Crea una nueva sesión"""
        with self.lock:
            session_id = self._generate_session_id(client_ip, username)
            current_time = datetime.now().isoformat()
            expiry_time = (datetime.now() + timedelta(seconds=self.session_timeout)).isoformat()
            
            self.sessions[client_ip] = {
                "session_id": session_id,
                "username": username,
                "client_ip": client_ip,
                "created_at": current_time,
                "last_activity": current_time,
                "expires_at": expiry_time,
                "active": True
            }
            
            self._save_sessions()
            return session_id
    
    def _generate_session_id(self, client_ip: str, username: str) -> str:
        """Genera un ID único de sesión"""
        import hashlib
        timestamp = str(time.time())
        data = f"{client_ip}:{username}:{timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()[:32]
    
    def validate_session(self, client_ip: str) -> bool:
        """Valida si una sesión es activa"""
        with self.lock:
            if client_ip not in self.sessions:
                return False
            
            session = self.sessions[client_ip]
            
            # Verificar si la sesión está activa
            if not session.get("active", True):
                return False
            
            # Verificar expiración
            try:
                expires_at = datetime.fromisoformat(session["expires_at"])
                if datetime.now() > expires_at:
                    # Sesión expirada
                    del self.sessions[client_ip]
                    self._save_sessions()
                    return False
            except:
                # Error en fecha, eliminar sesión
                del self.sessions[client_ip]
                self._save_sessions()
                return False
            
            # Actualizar última actividad
            session["last_activity"] = datetime.now().isoformat()
            self._save_sessions()
            
            return True
    
    def get_session_info(self, client_ip: str) -> Optional[Dict]:
        """Obtiene información de la sesión"""
        with self.lock:
            if client_ip in self.sessions:
                return self.sessions[client_ip].copy()
            return None
    
    def end_session(self, client_ip: str) -> bool:
        """Termina una sesión"""
        with self.lock:
            if client_ip in self.sessions:
                del self.sessions[client_ip]
                self._save_sessions()
                return True
            return False
    
    def get_active_sessions(self) -> List[Dict]:
        """Obtiene todas las sesiones activas"""
        with self.lock:
            active_sessions = []
            now = datetime.now()
            
            for client_ip, session in self.sessions.items():
                try:
                    expires_at = datetime.fromisoformat(session["expires_at"])
                    if now <= expires_at and session.get("active", True):
                        active_sessions.append(session.copy())
                except:
                    continue
            
            return active_sessions
    
    def get_active_count(self) -> int:
        """Obtiene el número de sesiones activas"""
        return len(self.get_active_sessions())
    
    def cleanup_expired_sessions(self):
        """Limpia sesiones expiradas"""
        with self.lock:
            now = datetime.now()
            expired_ips = []
            
            for client_ip, session in self.sessions.items():
                try:
                    expires_at = datetime.fromisoformat(session["expires_at"])
                    if now > expires_at:
                        expired_ips.append(client_ip)
                except:
                    expired_ips.append(client_ip)
            
            # Eliminar sesiones expiradas
            for ip in expired_ips:
                del self.sessions[ip]
            
            if expired_ips:
                self._save_sessions()
                print(f"🧹 Sesiones expiradas limpiadas: {len(expired_ips)}")
    
    def start_cleanup_daemon(self, interval: int = 300):
        """Inicia un demonio de limpieza periódica"""
        import threading
        
        def cleanup_loop():
            while self.running:
                time.sleep(interval)
                self.cleanup_expired_sessions()
        
        self._cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        self._cleanup_thread.start()
    
    def stop_cleanup_daemon(self):
        """Detiene el demonio de limpieza"""
        self.running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=2)
    
    def log_access(self, client_ip: str, username: str, action: str):
        """Registra un acceso en el log"""
        log_path = "data/logs/access.log"
        try:
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            with open(log_path, 'a') as f:
                timestamp = datetime.now().isoformat()
                f.write(f"{timestamp} | {client_ip} | {username} | {action}\n")
        except Exception as e:
            print(f"Error escribiendo en log: {e}")