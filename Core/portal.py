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
from Network.dns_server import DNSServer
from http.server import HTTPServer
from Auth.user_manager import UserManager
from Auth.session_manager import SessionManager
from Utils.utils_loggers import Logger

class CaptivePortal:
    """Portal cautivo completo e independiente"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.logger = Logger(__name__)
        
        # Componentes
        self.network = NetworkConfig(config)
        self.dns_server = DNSServer()
        self.http_server = HTTPServer(config)
        self.user_manager = UserManager()
        self.session_manager = SessionManager()
        
        # Estado
        self.running = False
        self.topology = None
        
        # Threads
        self.threads = []
    
    def start(self):
        """Inicia el portal cautivo completo"""
        try:
            self.logger.info("🚀 Iniciando Portal Cautivo...")
            
            # 1. Detectar y configurar red
            self.topology = self.network.detect_network_topology()
            if not self.network.setup_portal_network(self.topology):
                raise Exception("No se pudo configurar la red")
            
            # 2. Configurar servidor DNS
            gateway_ip = self.network.defaults['portal_gateway']
            self.dns_server.gateway_ip = gateway_ip
            self.dns_server.set_logger(self.logger)
            
            # 3. Iniciar servidores en threads separados
            self.running = True
            
            # Servidor DNS
            dns_thread = threading.Thread(target=self.dns_server.start)
            dns_thread.daemon = True
            dns_thread.start()
            self.threads.append(dns_thread)
            
            # Servidor HTTP
            http_thread = threading.Thread(
                target=self.http_server.start,
                args=(self._get_client_auth_status, self._authenticate_client)
            )
            http_thread.daemon = True
            http_thread.start()
            self.threads.append(http_thread)
            
            # Configurar callbacks
            self.http_server.on_login_success = self._handle_login_success
            self.http_server.on_logout = self._handle_logout
            
            self.logger.info("Portal cautivo iniciado correctamente")
            self.logger.info(f"   Gateway: {gateway_ip}")
            self.logger.info(f"   DNS Server: :{self.network.defaults['dns_port']}")
            self.logger.info(f"   HTTP Server: :{self.network.defaults['http_port']}")
            
            # Mantener proceso principal activo
            while self.running:
                time.sleep(1)
                
                # Monitorear estado
                self._monitor_status()
            
        except Exception as e:
            self.logger.error(f"Error iniciando portal: {e}")
            self.stop()
    
    def stop(self):
        """Detiene el portal cautivo"""
        self.logger.info(" Deteniendo portal...")
        self.running = False
        
        # Detener servidores
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
    
    def _get_client_auth_status(self, client_ip: str) -> bool:
        """Obtiene estado de autenticación de un cliente"""
        return self.session_manager.is_authenticated(client_ip)
    
    def _authenticate_client(self, username: str, password: str, client_ip: str) -> bool:
        """Autentica un cliente"""
        if self.user_manager.authenticate(username, password):
            # Crear sesión
            self.session_manager.create_session(client_ip, username)
            
            # Permitir acceso de red
            if self.topology:
                self.network.allow_client_traffic(
                    client_ip,
                    self.topology['internal_interface'],
                    self.topology['external_interface']
                )
            
            # Permitir resolución DNS normal
            self.dns_server.allow_client(client_ip)
            
            return True
        return False
    
    def _handle_login_success(self, client_ip: str, username: str):
        """Manejador para login exitoso"""
        self.logger.info(f"✅ Cliente autenticado: {client_ip} ({username})")
        
        # Registrar en logs
        self.session_manager.log_access(client_ip, username, "LOGIN")
    
    def _handle_logout(self, client_ip: str):
        """Manejador para logout"""
        if self.topology:
            self.network.block_client_traffic(
                client_ip,
                self.topology['internal_interface']
            )
        
        self.dns_server.block_client(client_ip)
        self.session_manager.end_session(client_ip)
        
        self.logger.info(f"Cliente desconectado: {client_ip}")
    
    def _monitor_status(self):
        """Monitorea el estado del sistema"""
        if not self.running:
            return
        
        # Cada 30 segundos, mostrar estadísticas
        if int(time.time()) % 30 == 0:
            stats = self.dns_server.get_stats()
            active_sessions = self.session_manager.get_active_count()
            
            self.logger.info(f"Estadísticas - DNS: {stats}, Sesiones: {active_sessions}")
    
    def add_user(self, username: str, password: str) -> bool:
        """Añade un nuevo usuario"""
        return self.user_manager.add_user(username, password)
    
    def remove_user(self, username: str) -> bool:
        """Elimina un usuario"""
        return self.user_manager.remove_user(username)
    
    def list_users(self):
        """Lista todos los usuarios"""
        return self.user_manager.list_users()
    
    def list_sessions(self):
        """Lista sesiones activas"""
        return self.session_manager.get_active_sessions()