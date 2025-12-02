#!/usr/bin/env python3
"""
Punto de entrada principal del Portal Cautivo
Ejecutar como: sudo python3 main.py
"""

import os
import sys
import signal
import time 
from core.portal import CaptivePortal
from utils.logger import Logger

def check_root():
    """Verifica que se ejecute como root"""
    if os.geteuid() != 0:
        print("""
        ERROR: Se requieren permisos de root
         Ejecuta con: sudo python3 main.py
        
        Razón: El portal necesita:
          - Configurar interfaces de red
          - Modificar reglas de firewall (iptables)
          - Escuchar en puertos bajos (53, 80)
        """)
        sys.exit(1)

def setup_signal_handlers(portal):
    """Configura manejo de señales del sistema"""
    def signal_handler(sig, frame):
        print(f" Señal {sig} recibida, deteniendo portal...")
        portal.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def print_banner():
    """Muestra banner informativo"""
    banner = """
    ╔═══════════════════════════════════════════╗
    ║       PORTAL CAUTIVO COMPLETO          ║
    ║                                           ║
    ║  • DNS Server implementado desde cero    ║
    ║  • Configuración automática de red       ║
    ║  • Sin dependencias externas             ║
    ║  • Independiente del diseño de red       ║
    ╚═══════════════════════════════════════════╝
    """
    print(banner)

def main():
    """Función principal"""
    try:
        print_banner()
        check_root()
        
        # Configuración (puede cargarse desde archivo YAML/JSON)
        config = {
            'portal_subnet': '192.168.100.0/24',
            'portal_gateway': '192.168.100.1',
            'dns_port': 53,
            'http_port': 80,
            'session_timeout_hours': 8,
            'log_level': 'INFO'
        }
        
        # Crear e iniciar portal
        portal = CaptivePortal(config)
        setup_signal_handlers(portal)
        
        print(" Configuración detectada:")
        print(f"   • Red portal: {config['portal_subnet']}")
        print(f"   • Gateway: {config['portal_gateway']}")
        print(f"   • DNS: puerto {config['dns_port']}")
        print(f"   • HTTP: puerto {config['http_port']}")
        print("\n⚡ Iniciando en 3 segundos...")
        
        time.sleep(3)
        
        # Iniciar portal
        portal.start()
        
    except KeyboardInterrupt:
        print("Interrupción por usuario")
        if 'portal' in locals():
            portal.stop()
    except Exception as e:
        print(f"\n Error fatal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()