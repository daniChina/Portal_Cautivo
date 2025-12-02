#!/usr/bin/env python3
"""
Constantes del sistema Portal Cautivo
"""

class PortalConstants:
    """Constantes utilizadas en todo el sistema"""
    
    # Red
    DEFAULT_GATEWAY_IP = "192.168.100.1"
    DEFAULT_SUBNET = "192.168.100.0/24"
    DEFAULT_NETMASK = "255.255.255.0"
    
    # Puertos
    DNS_PORT = 53
    HTTP_PORT = 80
    
    # Autenticación
    SESSION_TIMEOUT_HOURS = 8
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_LOCKOUT_MINUTES = 15
    
    # Rutas de archivos
    DEFAULT_USERS_DB = "data/users.db"
    DEFAULT_SESSIONS_DB = "data/sessions.db"
    DEFAULT_LOG_FILE = "data/logs/portal.log"
    
    # Usuarios por defecto
    DEFAULT_USERS = {
        "admin": {
            "password": "admin123",
            "email": "admin@red.local",
            "role": "admin"
        },
        "usuario": {
            "password": "usuario123",
            "email": "usuario@red.local",
            "role": "user"
        }
    }
    
    # Configuración de logging
    LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    DEFAULT_LOG_LEVEL = "INFO"
    LOG_MAX_SIZE_MB = 10
    LOG_BACKUP_COUNT = 5