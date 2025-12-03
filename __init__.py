"""
Portal Cautivo - Sistema completo de autenticación de red

Módulos principales:
- core: Configuración y clases principales
- network: Servidores DNS y configuración de red
- http: Servidor HTTP y páginas web
- auth: Autenticación y gestión de usuarios
- utils: Utilidades y logging
"""

__version__ = "1.0.0"
__author__ = "Tu Nombre"
__description__ = "Portal cautivo implementado completamente en Python sin dependencias externas"

# Importaciones principales para acceso fácil
from Core.portal import CaptivePortal
from Core.config import PortalConfig

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