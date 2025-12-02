import yaml
import os
from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class PortalConfig:
    """Configuración centralizada del portal"""
    # Red
    internal_interface: str = "eth1"
    external_interface: str = "eth0"
    gateway_ip: str = "192.168.100.1"
    subnet: str = "192.168.100.0/24"
    
    # Servidores
    http_port: int = 80
    dns_port: int = 53
    http_host: str = "0.0.0.0"
    
    # Autenticación
    session_timeout_hours: int = 8
    max_login_attempts: int = 3
    
    # Rutas
    users_db_path: str = "data/users.db"
    sessions_db_path: str = "data/sessions.db"
    log_path: str = "data/logs/portal.log"
    
    @classmethod
    def from_yaml(cls, path: str = "config/default.yaml"):
        """Carga configuración desde YAML"""
        if os.path.exists(path):
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
                return cls(**data)
        return cls()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario"""
        return self.__dict__