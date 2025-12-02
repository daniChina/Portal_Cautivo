"""
Módulo core del Portal Cautivo
Contiene las clases principales y configuración
"""

from .portal import CaptivePortal
from .config import PortalConfig
from .constants import PortalConstants

__all__ = [
    'CaptivePortal',
    'PortalConfig', 
    'PortalConstants'
]