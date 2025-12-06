#!/usr/bin/env python3
"""
Portal Cautivo Principal - Integra todos los componentes
"""

import threading
import time
import signal
import sys
from typing import Dict

from Network.network_config import NetworkConfig
from Network.dns_server import DnsmasqManager  
from Http.http_server import HTTPServer
from Auth.user_manager import UserManager
from Auth.session_manager import SessionManager
from Utils.utils_loggers import Logger
from Network.hotspot_manager import HotspotManager

class CaptivePortal:
    """Portal cautivo completo e independiente"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.logger = Logger(__name__)
        
        # Componentes
        self.network = NetworkConfig(config)
        self.dns_server = DnsmasqManager(config)  
        self.http_server = HTTPServer(config)
        self.user_manager = UserManager()
        self.session_manager = SessionManager()
        self.hotspot = HotspotManager(config)  # Inicializar hotspot
        
        # Estado
        self.running = False
        self.topology = None
        self.threads = []

    def start(self):
        """Inicia el portal cautivo completo"""
        try:
            self.logger.info("Iniciando Portal Cautivo...")
            
            # 1. Iniciar Hotspot WiFi
            self.logger.info(" Iniciando Hotspot WiFi...")
            self.hotspot = HotspotManager(self.config) 
            if not self.hotspot.start():
                raise Exception("No se pudo iniciar el hotspot WiFi")
            
            # 2. Detectar y configurar red
            self.topology = self.network.detect_network_topology()
            if not self.topology:
                self.logger.warning("No se detectó topología, usando configuración manual")
                self.topology = {
                    'internal_interface': self.config.get('interface', 'wlan0'),
                    'external_interface': self.config.get('external_interface', 'eth0'),
                    'gateway': self.config.get('portal_gateway', '192.168.100.1')
                }
            
            # 3. Iniciar DNS/DHCP Server
            self.logger.info("Iniciando servidor DNS/DHCP...")
            if not self.dns_server.start():
                raise Exception("No se pudo iniciar el servidor DNS/DHCP")
            
            # 4. Iniciar servidores en threads separados
            self.running = True
            
            # Configurar servidor HTTP ANTES de iniciarlo
            self.http_server.set_auth_callbacks(
                self._get_client_auth_status, 
                self._authenticate_client
            )
            self.http_server.on_login_success = self._handle_login_success
            self.http_server.on_logout = self._handle_logout
            
            # Servidor HTTP
            http_thread = threading.Thread(target=self.http_server.start)
            http_thread.daemon = True
            http_thread.start()
            self.threads.append(http_thread)
            
            self.logger.info("Portal cautivo iniciado correctamente")
            self.logger.info(f"   SSID: {self.hotspot.defaults['ssid']}")
            self.logger.info(f"   Password: {self.hotspot.defaults['password']}")
            self.logger.info(f"   Gateway: {self.topology.get('gateway', '192.168.100.1')}")
            
            # Mantener proceso principal activo
            while self.running:
                time.sleep(1)
                self._monitor_status()
                
        except Exception as e:
            self.logger.error(f"Error iniciando portal: {e}")
            self.stop()

    def _get_client_auth_status(self, client_ip: str) -> bool:
        """Obtiene estado de autenticación de un cliente"""
        return self.session_manager.validate_session(client_ip)  
    
    def _authenticate_client(self, username: str, password: str, client_ip: str) -> bool:
        """Autentica un cliente"""
        success, message = self.user_manager.validate_credentials(username, password)
        
        if success:
            # Crear sesión
            self.session_manager.create_session(client_ip, username)
            
            # Permitir acceso del firewall
            if self.topology:
                self.network.allow_client_traffic(
                    client_ip,
                    self.topology.get('internal_interface', 'wlan0'),
                    self.topology.get('external_interface', 'eth0')
                )
            
            return True
        return False
    
    def _handle_login_success(self, client_ip: str, username: str):
        """Manejador para login exitoso"""
        self.logger.info(f" Cliente autenticado: {client_ip} ({username})")
        self.session_manager.log_access(client_ip, username, "LOGIN")
    
    def _handle_logout(self, client_ip: str):
        """Manejador para logout"""
        if self.topology:
            #bloquear cliente a traves del firewall 
            self.network.block_client_traffic(
                client_ip,
                self.topology.get('internal_interface', 'wlan0')
            )
        
        self.session_manager.end_session(client_ip)
        self.logger.info(f" Cliente desconectado: {client_ip}")
    
    def _monitor_status(self):
        """Monitorea el estado del sistema"""
        if not self.running:
            return
        
        # Cada 30 segundos, mostrar estadísticas
        if int(time.time()) % 30 == 0:
            active_sessions = len(self.session_manager.get_active_sessions())
            self.logger.info(f"Estadísticas - Sesiones activas: {active_sessions}")
    
    def stop(self):
        """Detiene el portal cautivo"""
        self.logger.info(" Deteniendo portal...")
        self.running = False
        
        # Detener componentes
        self.hotspot.stop()
        self.dns_server.stop()
        self.http_server.stop()
        
        # Limpiar configuración de red
        if self.topology:
            self.network.cleanup(self.topology)
        
        # Esperar a que los threads terminen
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2)
        
        self.logger.info("Portal detenido")
    
    # Métodos de gestión de usuarios (mantener igual)
    def add_user(self, username: str, password: str) -> bool:
        return self.user_manager.add_user(username, password)
    
    def remove_user(self, username: str) -> bool:
        return self.user_manager.delete_user(username)
    
    def list_users(self):
        return self.user_manager.list_users()
    
    def list_sessions(self):
        return self.session_manager.get_active_sessions()