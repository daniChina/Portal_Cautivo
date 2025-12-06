import subprocess
import threading
from typing import List, Optional
from Utils.utils_loggers import Logger

class FirewallManager:
    """Gestión segura y desacoplada del firewall"""
    
    def __init__(self, config):
        self.config = config
        self.logger = Logger(__name__)
        self.lock = threading.Lock()
    
    def _run_command(self, command: str) -> bool:
        """Ejecuta comando de forma segura"""
        try:
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                self.logger.warning(f"Comando falló: {command}")
                self.logger.warning(f"Error: {result.stderr}")
                return False
            return True
        except Exception as e:
            self.logger.error(f"Error ejecutando comando: {e}")
            return False
    
    def setup_firewall(self):
        """Configura el firewall inicial"""
        with self.lock:
            self.logger.info("Configurando firewall...")
            
            commands = [
                # Limpiar reglas existentes
                "iptables -F",
                "iptables -X",
                "iptables -t nat -F",
                "iptables -t nat -X",
                
                # Políticas por defecto
                "iptables -P INPUT DROP",
                "iptables -P FORWARD DROP",
                "iptables -P OUTPUT ACCEPT",
                
                # Permitir localhost
                "iptables -A INPUT -i lo -j ACCEPT",
                "iptables -A OUTPUT -o lo -j ACCEPT",
                
                # Conexiones establecidas
                "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
                "iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT",
                
                # Permitir portal HTTP
                f"iptables -A INPUT -i {self.config.internal_interface} "
                f"-p tcp --dport {self.config.http_port} -j ACCEPT",
                
                # Permitir DNS
                f"iptables -A INPUT -i {self.config.internal_interface} "
                f"-p udp --dport {self.config.dns_port} -j ACCEPT",
                
                # Configurar NAT
                f"iptables -t nat -A POSTROUTING "
                f"-o {self.config.external_interface} -j MASQUERADE",
                
                # Redirigir HTTP al portal
                f"iptables -t nat -A PREROUTING "
                f"-i {self.config.internal_interface} "
                f"-p tcp --dport 80 "
                f"-j DNAT --to-destination {self.config.gateway_ip}:{self.config.http_port}",
            ]
            
            success = 0
            for cmd in commands:
                if self._run_command(cmd):
                    success += 1
                else:
                    self.logger.error(f"Falló: {cmd}")
            
            self.logger.info(f"Firewall configurado: {success}/{len(commands)}")
    
    def allow_client(self, client_ip: str):
        """Permite acceso a un cliente"""
        with self.lock:
            commands = [
                f"iptables -I FORWARD 1 "
                f"-s {client_ip} "
                f"-o {self.config.external_interface} -j ACCEPT",
                
                f"iptables -I FORWARD 1 "
                f"-d {client_ip} "
                f"-i {self.config.external_interface} -j ACCEPT"
            ]
            
            for cmd in commands:
                self._run_command(cmd)
            
            self.logger.info(f"Acceso concedido para {client_ip}")
    
    def block_client(self, client_ip: str):
        """Bloquea acceso a un cliente"""
        with self.lock:
            # Intentar eliminar reglas si existen
            commands = [
                f"iptables -D FORWARD -s {client_ip} -o {self.config.external_interface} -j ACCEPT",
                f"iptables -D FORWARD -d {client_ip} -i {self.config.external_interface} -j ACCEPT"
            ]
            
            for cmd in commands:
                self._run_command(cmd)
            
            self.logger.info(f"Acceso bloqueado para {client_ip}")
    

    
    def allow_client_dns(self, client_ip: str, internal_interface: str):
        """Permite que un cliente use DNS externo"""
        commands = [
            f'iptables -t nat -I PREROUTING 1 -i {internal_interface} '
            f'-s {client_ip} -p udp --dport 53 -j ACCEPT',
            f'iptables -t nat -I PREROUTING 1 -i {internal_interface} '
            f'-s {client_ip} -p tcp --dport 53 -j ACCEPT'
        ]
        
        for cmd in commands:
            self._run_command(cmd)
        
        self.logger.info(f"DNS permitido para {client_ip}")
    
    def block_client_dns(self, client_ip: str, internal_interface: str):
        """Revoca permisos DNS para un cliente"""
        commands = [
            f'iptables -t nat -D PREROUTING -i {internal_interface} '
            f'-s {client_ip} -p udp --dport 53 -j ACCEPT 2>/dev/null || true',
            f'iptables -t nat -D PREROUTING -i {internal_interface} '
            f'-s {client_ip} -p tcp --dport 53 -j ACCEPT 2>/dev/null || true'
        ]
        
        for cmd in commands:
            self._run_command(cmd)
        
        self.logger.info(f"DNS bloqueado para {client_ip}")


    def cleanup(self):
        """Limpia las reglas del firewall"""
        commands = [
            "iptables -F",
            "iptables -X",
            "iptables -t nat -F",
            "iptables -t nat -X",
            "iptables -P INPUT ACCEPT",
            "iptables -P FORWARD ACCEPT",
            "iptables -P OUTPUT ACCEPT"
        ]
        
        for cmd in commands:
            self._run_command(cmd)
        
        self.logger.info("Firewall limpiado")