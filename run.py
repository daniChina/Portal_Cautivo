#!/usr/bin/env python3
"""
Script de inicio simplificado para el Portal Cautivo
Uso: sudo python3 run.py
"""

import os
import sys
import time

# Añadir src al path de Python
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def main():
    """Función principal"""
    # Verificar que estamos como root
    if os.geteuid() != 0:
        print("""
        ERROR: Se requieren permisos de administrador (root)
        
        El portal cautivo necesita:
        • Configurar interfaces de red
        • Modificar reglas de firewall
        • Escuchar en puertos privilegiados (53, 80)
        
         Ejecuta con: sudo python3 run.py
        """)
        sys.exit(1)
    
    # Banner
    print("""
    ╔══════════════════════════════════════════════╗
    ║        🚀 PORTAL CAUTIVO COMPLETO           ║
    ║                                              ║
    ║  • Servidor DNS implementado desde cero     ║
    ║  • Servidor HTTP con autenticación          ║
    ║  • Configuración automática de red          ║
    ║  • Sistema completo de usuarios y sesiones  ║
    ║  • Sin dependencias externas                ║
    ╚══════════════════════════════════════════════╝
    """)
    
    # Crear estructura de directorios
    os.makedirs("data/logs", exist_ok=True)
    os.makedirs("config", exist_ok=True)
    
    print(" Directorios creados: data/, data/logs/, config/")
    print(" Iniciando en 3 segundos...")
    time.sleep(3)
    
    try:
        # Importar y ejecutar el portal principal
        from main_modify import main as portal_main
        portal_main()
    except KeyboardInterrupt:
        print(" Portal detenido por el usuario")
    except Exception as e:
        print(f" Error crítico: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()