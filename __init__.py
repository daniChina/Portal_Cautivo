""""
Portal Cautivo - Sistema completo de autenticación de red
"""

__version__ = "1.0.0"
__author__ = "Portal Cautivo Team"
__description__ = "Sistema completo de portal cautivo con hotspot WiFi"


"""Módulos principales:
- core: Configuración y clases principales
- network: Servidores DNS y configuración de red
- http: Servidor HTTP y páginas web
- auth: Autenticación y gestión de usuarios
- utils: Utilidades y logging
"""

# Exportar módulos principales para acceso fácil
from Core.portal import CaptivePortal
from Core.config import PortalConfig
from Http.http_server import HTTPServer
from Auth.user_manager import UserManager
from Auth.session_manager import SessionManager
from Network.network_config import NetworkConfig
from Network.hotspot_manager import HotspotManager

# Variables globales de configuración
default_config = {
    'portal_subnet': '192.168.100.0/24',
    'portal_gateway': '192.168.100.1',
    'dns_port': 53,
    'http_port': 80,
    'session_timeout_hours': 8
}

__all__ = [
    'CaptivePortal',
    'PortalConfig',
    'default_config'
]


__all__ = [
    'CaptivePortal',
    'PortalConfig',
    'HTTPServer',
    'UserManager', 
    'SessionManager',
    'NetworkConfig',
    'HotspotManager'
]