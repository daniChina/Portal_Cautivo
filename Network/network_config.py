#!/usr/bin/env python3
"""
Configuración automática de red independiente del diseño de red.
Detecta y configura interfaces automáticamente.
"""

import subprocess
import socket
import netifaces
import os
import re
import time
from typing import Dict, List, Optional, Tuple
import json

class NetworkConfig:
    """Configuración automática y gestión de red"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.interfaces = {}
        self.detected_gateway = None
        self.detected_dns = []
        
        # Configuración por defecto
        self.defaults = {
            'portal_subnet': '192.168.100.0/24',
            'portal_gateway': '192.168.100.1',
            'portal_netmask': '255.255.255.0',
            'dhcp_range_start': '192.168.100.100',
            'dhcp_range_end': '192.168.100.200',
            'dns_port': 53,
            'http_port': 80
        }
        
        # Actualizar con configuración proporcionada
        self.defaults.update(self.config)
    
    def detect_network_topology(self) -> Dict:
        """
        Detecta automáticamente la topología de red
        Retorna: {
            'external_interface': str,
            'internal_interface': str,
            'external_ip': str,
            'gateway': str,
            'dns_servers': list
        }
        """
        self.log(" Detectando topología de red...")
        
        interfaces = netifaces.interfaces()
        topology = {
            'external_interface': None,
            'internal_interface': None,
            'external_ip': None,
            'gateway': None,
            'dns_servers': []
        }
        
        # Excluir interfaces especiales
        exclude_patterns = ['lo', 'docker', 'virbr', 'veth', 'br-']
        
        for iface in interfaces:
            # Verificar si es una interfaz válida
            if any(pattern in iface for pattern in exclude_patterns):
                continue
            
            try:
                addrs = netifaces.ifaddresses(iface)
                
                # Buscar IPv4
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    ip_addr = ip_info['addr']
                    netmask = ip_info.get('netmask', '255.255.255.0')
                    
                    # Determinar si es IP privada o pública
                    if self._is_private_ip(ip_addr):
                        topology['internal_interface'] = iface
                        topology['internal_ip'] = ip_addr
                        self.log(f"  Interfaz interna detectada: {iface} ({ip_addr})")
                    else:
                        topology['external_interface'] = iface
                        topology['external_ip'] = ip_addr
                        self.log(f"  Interfaz externa detectada: {iface} ({ip_addr})")
                        
                        # Intentar obtener gateway por defecto
                        if netifaces.AF_INET in addrs:
                            gateways = netifaces.gateways()
                            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                                gw_info = gateways['default'][netifaces.AF_INET]
                                if gw_info[1] == iface:
                                    topology['gateway'] = gw_info[0]
                
                # Buscar IPv6
                if netifaces.AF_INET6 in addrs:
                    ip6_info = addrs[netifaces.AF_INET6][0]
                    # Puedes usar esto para IPv6 si es necesario
                    
            except Exception as e:
                self.log(f"  Error analizando interfaz {iface}: {e}", "WARN")
        
        # Si no detectamos interfaces, crear una virtual
        if not topology['internal_interface']:
            topology['internal_interface'] = self._create_virtual_interface()
        
        # Si no hay interfaz externa, usar la primera disponible
        if not topology['external_interface'] and interfaces:
            for iface in interfaces:
                if iface != 'lo' and iface != topology.get('internal_interface'):
                    topology['external_interface'] = iface
                    break
        
        # Obtener servidores DNS del sistema
        topology['dns_servers'] = self._get_system_dns()
        
        self.log(f"Topología detectada:")
        self.log(f"   Externa: {topology['external_interface']} ({topology.get('external_ip', 'N/A')})")
        self.log(f"   Interna: {topology['internal_interface']} ({topology.get('internal_ip', 'N/A')})")
        self.log(f"   Gateway: {topology.get('gateway', 'N/A')}")
        self.log(f"   DNS: {topology['dns_servers']}")
        
        return topology
    
    def _is_private_ip(self, ip: str) -> bool:
        """Determina si una IP es privada"""
        private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
            ('169.254.0.0', '169.254.255.255')  # Link-local
        ]
        
        try:
            ip_num = self._ip_to_int(ip)
            for start, end in private_ranges:
                if self._ip_to_int(start) <= ip_num <= self._ip_to_int(end):
                    return True
        except:
            pass
        
        return False
    
    def _ip_to_int(self, ip: str) -> int:
        """Convierte IP a entero"""
        parts = ip.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    
    def _create_virtual_interface(self) -> str:
        """Crea una interfaz virtual para el portal"""
        base_iface = "portal0"
        index = 0
        
        while True:
            iface_name = f"{base_iface}{index}" if index > 0 else base_iface
            if iface_name not in netifaces.interfaces():
                try:
                    # Crear interfaz virtual (requiere root)
                    subprocess.run(['ip', 'link', 'add', iface_name, 'type', 'dummy'], 
                                 check=True, capture_output=True)
                    self.log(f"  Interfaz virtual creada: {iface_name}")
                    return iface_name
                except Exception as e:
                    self.log(f"  Error creando interfaz virtual: {e}", "ERROR")
                    return "eth1"  # Fallback
            index += 1
    
    def _get_system_dns(self) -> List[str]:
        """Obtiene servidores DNS del sistema"""
        dns_servers = []
        
        try:
            # Intentar leer desde resolv.conf
            if os.path.exists('/etc/resolv.conf'):
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            dns = line.split()[1].strip()
                            if dns not in ['127.0.0.1', '::1']:
                                dns_servers.append(dns)
            
            # Si no hay DNS, usar unos por defecto
            if not dns_servers:
                dns_servers = ['8.8.8.8', '8.8.4.4']  # Google DNS
        
        except Exception as e:
            self.log(f"Error obteniendo DNS: {e}", "WARN")
            dns_servers = ['8.8.8.8']
        
        return dns_servers
    
    def setup_portal_network(self, topology: Dict) -> bool:
        """
        Configura la red del portal cautivo
        """
        try:
            internal_iface = topology['internal_interface']
            external_iface = topology['external_interface']
            portal_ip = self.defaults['portal_gateway']
            
            self.log("🔧 Configurando red del portal...")
            
            # 1. Configurar interfaz interna
            self._setup_interface(internal_iface, portal_ip, self.defaults['portal_netmask'])
            
            # 2. Habilitar IP forwarding
            self._enable_ip_forwarding()
            
            # 3. Configurar NAT
            self._setup_nat(external_iface)
            
            # 4. Configurar redirección DNS
            self._setup_dns_redirect(internal_iface, portal_ip)
            
            # 5. Configurar redirección HTTP
            self._setup_http_redirect(internal_iface, portal_ip)
            
            # 6. Bloquear tráfico inicial
            self._setup_initial_block(internal_iface)
            
            self.log("Red del portal configurada exitosamente")
            return True
            
        except Exception as e:
            self.log(f" Error configurando red: {e}", "ERROR")
            return False
    
    def _setup_interface(self, interface: str, ip: str, netmask: str):
        """Configura una interfaz de red"""
        commands = [
            ['ip', 'link', 'set', interface, 'up'],
            ['ip', 'addr', 'flush', 'dev', interface],
            ['ip', 'addr', 'add', f'{ip}/{self._netmask_to_cidr(netmask)}', 'dev', interface]
        ]
        
        for cmd in commands:
            subprocess.run(cmd, check=True, capture_output=True)
        
        self.log(f"  Interfaz {interface} configurada con {ip}")
    
    def _netmask_to_cidr(self, netmask: str) -> int:
        """Convierte máscara de red a notación CIDR"""
        bits = sum(bin(int(x)).count('1') for x in netmask.split('.'))
        return bits
    
    def _enable_ip_forwarding(self):
        """Habilita el forwarding de IP en el kernel"""
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')
        
        # Hacerlo persistente
        subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], 
                      check=True, capture_output=True)
        self.log("  IP forwarding habilitado")
    
    def _setup_nat(self, external_iface: str):
        """Configura NAT para salida a Internet"""
        commands = [
            # Limpiar reglas NAT existentes
            'iptables -t nat -F',
            
            # NAT para tráfico saliente
            f'iptables -t nat -A POSTROUTING -o {external_iface} -j MASQUERADE',
            
            # Permitir forward de tráfico autorizado
            f'iptables -A FORWARD -i {external_iface} -o {external_iface} -j ACCEPT'
        ]
        
        for cmd in commands:
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
        
        self.log(f"  NAT configurado para {external_iface}")
    
    def _setup_dns_redirect(self, internal_iface: str, portal_ip: str):
        """Redirige tráfico DNS al servidor DNS del portal"""
        commands = [
            # Redirigir DNS UDP al portal
            f'iptables -t nat -A PREROUTING -i {internal_iface} '
            f'-p udp --dport 53 -j DNAT --to-destination {portal_ip}:53',
            
            # Redirigir DNS TCP al portal
            f'iptables -t nat -A PREROUTING -i {internal_iface} '
            f'-p tcp --dport 53 -j DNAT --to-destination {portal_ip}:53',
            
            # Aceptar DNS en el portal
            f'iptables -A INPUT -i {internal_iface} -p udp --dport 53 -j ACCEPT',
            f'iptables -A INPUT -i {internal_iface} -p tcp --dport 53 -j ACCEPT'
        ]
        
        for cmd in commands:
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
        
        self.log("  Redirección DNS configurada")
    
    def _setup_http_redirect(self, internal_iface: str, portal_ip: str):
        """Redirige tráfico HTTP/HTTPS al portal"""
        commands = [
            # Redirigir HTTP al portal
            f'iptables -t nat -A PREROUTING -i {internal_iface} '
            f'-p tcp --dport 80 -j DNAT --to-destination {portal_ip}:80',
            
            # Redirigir HTTPS al portal (opcional, para capturar intentos HTTPS)
            f'iptables -t nat -A PREROUTING -i {internal_iface} '
            f'-p tcp --dport 443 -j DNAT --to-destination {portal_ip}:80',
            
            # Aceptar HTTP en el portal
            f'iptables -A INPUT -i {internal_iface} -p tcp --dport 80 -j ACCEPT'
        ]
        
        for cmd in commands:
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
        
        self.log("  Redirección HTTP/HTTPS configurada")
    
    def _setup_initial_block(self, internal_iface: str):
        """Configura bloqueo inicial de todo el tráfico"""
        commands = [
            # Política por defecto DROP para forward
            'iptables -P FORWARD DROP',
            
            # Permitir sólo tráfico relacionado/establecido
            'iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT',
            
            # Bloquear todo el tráfico saliente de clientes no autenticados
            f'iptables -A FORWARD -i {internal_iface} ! -o {internal_iface} -j DROP'
        ]
        
        for cmd in commands:
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
        
        self.log("  Bloqueo inicial configurado")
    
    def allow_client_traffic(self, client_ip: str, internal_iface: str, external_iface: str):
        """Permite tráfico para un cliente autenticado"""
        commands = [
            # Permitir tráfico desde el cliente hacia Internet
            f'iptables -I FORWARD 1 -s {client_ip} -i {internal_iface} '
            f'-o {external_iface} -j ACCEPT',
            
            # Permitir tráfico de Internet hacia el cliente
            f'iptables -I FORWARD 1 -d {client_ip} -i {external_iface} '
            f'-o {internal_iface} -m state --state ESTABLISHED,RELATED -j ACCEPT'
        ]
        
        for cmd in commands:
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
        
        self.log(f"  Tráfico permitido para {client_ip}")
    
    def block_client_traffic(self, client_ip: str, internal_iface: str):
        """Bloquea tráfico para un cliente"""
        # Eliminar reglas de permiso si existen
        commands = [
            f'iptables -D FORWARD -s {client_ip} -i {internal_iface} -j ACCEPT 2>/dev/null || true',
            f'iptables -D FORWARD -d {client_ip} -j ACCEPT 2>/dev/null || true'
        ]
        
        for cmd in commands:
            subprocess.run(cmd, shell=True, capture_output=True)
        
        # Añadir regla de bloqueo explícito
        block_cmd = f'iptables -A FORWARD -s {client_ip} -j DROP'
        subprocess.run(block_cmd, shell=True, capture_output=True)
        
        self.log(f"  Tráfico bloqueado para {client_ip}")
    
    def cleanup(self, topology: Dict):
        """Limpia la configuración de red"""
        try:
            internal_iface = topology.get('internal_interface')
            
            commands = [
                # Restaurar políticas por defecto
                'iptables -P INPUT ACCEPT',
                'iptables -P FORWARD ACCEPT',
                'iptables -P OUTPUT ACCEPT',
                
                # Limpiar todas las reglas
                'iptables -F',
                'iptables -X',
                'iptables -t nat -F',
                'iptables -t nat -X',
                
                # Deshabilitar IP forwarding
                'sysctl -w net.ipv4.ip_forward=0'
            ]
            
            for cmd in commands:
                subprocess.run(cmd, shell=True, capture_output=True)
            
            # Limpiar interfaz interna si es virtual
            if internal_iface and internal_iface.startswith('portal'):
                subprocess.run(['ip', 'link', 'delete', internal_iface], 
                             capture_output=True)
            
            self.log(" Configuración de red limpiada")
            
        except Exception as e:
            self.log(f"Error limpiando red: {e}", "WARN")
    
    def log(self, message: str, level: str = "INFO"):
        """Registra un mensaje"""
        print(f"[NetworkConfig] {message}")