"""
Gestión de dnsmasq integrado con el portal cautivo
DNS  con redirección solo para dominios de detección de portal
"""

import subprocess
import os
import time
import threading
from typing import Dict, List, Optional
import ipaddress

class DnsmasqManager:
    """Gestor de dnsmasq para DHCP y DNS normal con portal cautivo"""
    
    def __init__(self, config: dict):
        self.config = config
        self.process = None
        self.conf_path = "/tmp/dnsmasq-portal.conf"
        self.leases_file = "/tmp/dnsmasq.leases"
        
        # Configuración por defecto
        self.default_config = {
            'interface': 'wlan0',
            'gateway': '192.168.100.1',
            'subnet': '192.168.100.0/24',
            'dhcp_start': '192.168.100.100',
            'dhcp_end': '192.168.100.200',
            'netmask': '255.255.255.0',
            'lease_time': '12h',
            'dns_server': '192.168.100.1',
            'external_dns': ['8.8.8.8', '8.8.4.4'],
            'portal_ip': '192.168.100.1'
        }
        
        # Actualizar con configuración proporcionada
        self.default_config.update(config)
        
        # Dominios de detección de portal cautivo que deben redirigirse al portal
        self.captive_portal_domains = [
            'captive.apple.com',
            'connectivitycheck.android.com',
            'connectivitycheck.gstatic.com',
            'clients3.google.com',
            'detectportal.firefox.com',
            'www.appleiphonecell.com',
            'www.msftconnecttest.com',
            'www.msftncsi.com',
            'network-test.debian.org',
            'nmcheck.gnome.org',
            'connectivitycheck.captiveportal.com'
        ]
        
        # Estadísticas
        self.stats = {
            'started': False,
            'leases_active': 0,
            'last_reload': None
        }
    
    def generate_config(self) -> str:
        """Genera configuración dnsmasq dinámicamente"""
        config_lines = [
            "# Configuración generada por Portal Cautivo",
            f"interface={self.default_config['interface']}",
            f"listen-address={self.default_config['gateway']}",
            "bind-interfaces",
            "",
            "# DHCP Server",
            f"dhcp-range={self.default_config['dhcp_start']},{self.default_config['dhcp_end']},{self.default_config['netmask']},{self.default_config['lease_time']}",
            f"dhcp-option=3,{self.default_config['gateway']}  # Gateway",
            f"dhcp-option=6,{self.default_config['gateway']}  # DNS Server (este mismo servidor)",
            f"dhcp-leasefile={self.leases_file}",
            "",
            "# DNS Server - Funciona normalmente",
            "no-resolv",
            "no-poll",
            "",
            "# Servidores DNS externos"
        ]
        
        # Agregar servidores DNS externos
        for dns in self.default_config['external_dns']:
            config_lines.append(f"server={dns}")
        
        config_lines.append("")
        config_lines.append("# Redirección de dominios de detección de portal cautivo")
        
        # Agregar redirecciones para dominios de portal cautivo
        for domain in self.captive_portal_domains:
            config_lines.append(f"address=/{domain}/{self.default_config['portal_ip']}")
        
        config_lines.extend([
            "",
            "# Logging",
            "log-dhcp",
            "log-queries",
            f"log-facility=/tmp/dnsmasq.log",
            "",
            "# Rendimiento",
            "cache-size=100",
            "stop-dns-rebind",
            "bogus-priv",
            "expand-hosts",
            f"domain={self.default_config.get('domain', 'portal.local')}",
            "",
            "# Opciones de seguridad",
            "no-dhcp-interface=lo",
            "dhcp-authoritative",
            "local-ttl=300"
        ])
        
        return "\n".join(config_lines)
    
    def start(self) -> bool:
        """Inicia dnsmasq"""
        try:
            # Parar dnsmasq si ya está corriendo
            self._stop_existing_dnsmasq()
            
            # Generar configuración
            config_content = self.generate_config()
            
            # Guardar archivo de configuración
            with open(self.conf_path, 'w') as f:
                f.write(config_content)
            
            # Crear directorio para logs si no existe
            os.makedirs(os.path.dirname("/tmp/dnsmasq.log"), exist_ok=True)
            
            # Iniciar dnsmasq en modo no-daemon
            cmd = [
                'dnsmasq',
                '-C', self.conf_path,
                '--no-daemon',
                '--log-queries',
                '--log-dhcp'
            ]
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Verificar que se inició correctamente
            time.sleep(2)
            if self.process.poll() is not None:
                # Error al iniciar
                stderr = self.process.stderr.read() if self.process.stderr else "Unknown error"
                raise Exception(f"dnsmasq no pudo iniciar: {stderr}")
            
            self.stats['started'] = True
            self.stats['last_reload'] = time.time()
            
            # Iniciar thread para leer logs
            log_thread = threading.Thread(target=self._read_logs, daemon=True)
            log_thread.start()
            
            # Iniciar thread para monitorear leases
            monitor_thread = threading.Thread(target=self._monitor_leases, daemon=True)
            monitor_thread.start()
            
            print(f"[dnsmasq] ✅ Servidor iniciado en {self.default_config['interface']}")
            print(f"[dnsmasq] DHCP: {self.default_config['dhcp_start']} - {self.default_config['dhcp_end']}")
            print(f"[dnsmasq] Gateway: {self.default_config['gateway']}")
            print(f"[dnsmasq] DNS externos: {', '.join(self.default_config['external_dns'])}")
            print(f"[dnsmasq] Dominios de portal: {len(self.captive_portal_domains)} configurados")
            
            return True
            
        except Exception as e:
            print(f"[dnsmasq] ❌ Error iniciando: {e}")
            return False
    
    def _stop_existing_dnsmasq(self):
        """Detiene instancias existentes de dnsmasq"""
        try:
            subprocess.run(['pkill', '-9', 'dnsmasq'], 
                         capture_output=True, timeout=5)
            time.sleep(1)
        except:
            pass
    
    def stop(self):
        """Detiene dnsmasq"""
        print("[dnsmasq] Deteniendo servidor...")
        
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            
            self.process = None
        
        self.stats['started'] = False
        print("[dnsmasq] Servidor detenido")
    
    def _read_logs(self):
        """Lee y procesa logs de dnsmasq"""
        while self.process and self.process.poll() is None:
            try:
                if self.process.stdout:
                    line = self.process.stdout.readline()
                    if line:
                        self._process_log_line(line.strip())
            except Exception as e:
                if self.stats['started']:
                    print(f"[dnsmasq] Error leyendo logs: {e}")
                break
    
    def _process_log_line(self, line: str):
        """Procesa una línea de log"""
        if "DHCPDISCOVER" in line:
            mac = self._extract_mac(line)
            print(f"[dnsmasq] Cliente descubierto: {mac}")
        elif "DHCPOFFER" in line:
            ip = self._extract_ip(line)
            mac = self._extract_mac(line)
            print(f"[dnsmasq] Oferta enviada: {mac} -> {ip}")
        elif "DHCPACK" in line:
            ip = self._extract_ip(line)
            mac = self._extract_mac(line)
            hostname = self._extract_hostname(line)
            print(f"[dnsmasq] IP asignada: {mac} -> {ip} ({hostname})")
        elif "query[A]" in line:
            # Log de consultas DNS
            parts = line.split()
            if len(parts) > 5:
                domain = parts[5]
                if any(captive_domain in domain for captive_domain in self.captive_portal_domains):
                    print(f"[dnsmasq] Consulta portal: {domain} -> {self.default_config['portal_ip']}")
    
    def _monitor_leases(self):
        """Monitorea leases DHCP periódicamente"""
        while self.stats['started'] and self.process and self.process.poll() is None:
            time.sleep(30)
            leases = self.get_active_leases()
            self.stats['leases_active'] = len(leases)
            
            if leases:
                print(f"[dnsmasq] Leases activos: {len(leases)} clientes")
    
    def _extract_mac(self, line: str) -> str:
        """Extrae MAC address de línea de log"""
        import re
        match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
        return match.group(0) if match else "unknown"
    
    def _extract_ip(self, line: str) -> str:
        """Extrae IP address de línea de log"""
        import re
        match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        return match.group(0) if match else "unknown"
    
    def _extract_hostname(self, line: str) -> str:
        """Extrae hostname de línea de log"""
        parts = line.split()
        for i, part in enumerate(parts):
            if part == "to" and i + 1 < len(parts):
                return parts[i + 1]
        return "unknown"
    
    def get_active_leases(self) -> List[Dict]:
        """Obtiene leases activos desde archivo"""
        leases = []
        
        if os.path.exists(self.leases_file):
            with open(self.leases_file, 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        lease_time = int(parts[0])
                        mac = parts[1]
                        ip = parts[2]
                        hostname = parts[3] if len(parts) > 3 else ''
                        client_id = parts[4] if len(parts) > 4 else ''
                        
                        # Verificar si el lease aún es válido (basado en tiempo)
                        current_time = int(time.time())
                        lease_end = lease_time
                        
                        # Calcular duración del lease (12h = 43200 segundos)
                        lease_duration = 12 * 3600  # 12 horas
                        
                        if current_time <= lease_end + lease_duration:
                            leases.append({
                                'expiry': lease_time,
                                'mac': mac,
                                'ip': ip,
                                'hostname': hostname,
                                'client_id': client_id,
                                'remaining': max(0, (lease_time + lease_duration) - current_time)
                            })
        
        return leases
    
    def add_static_lease(self, mac: str, ip: str, hostname: str = "") -> bool:
        """Añade una reserva estática de DHCP"""
        try:
            # Verificar que la IP esté en el rango correcto
            subnet = ipaddress.ip_network(self.default_config['subnet'], strict=False)
            if ipaddress.ip_address(ip) not in subnet:
                print(f"[dnsmasq] ❌ IP {ip} no está en la subred {subnet}")
                return False
            
            # Verificar que la IP no esté ya en uso
            leases = self.get_active_leases()
            for lease in leases:
                if lease['ip'] == ip:
                    print(f"[dnsmasq] ❌ IP {ip} ya está asignada a {lease['mac']}")
                    return False
            
            # Agregar la reserva al archivo de configuración
            config_line = f"dhcp-host={mac},{ip}"
            if hostname:
                config_line += f",{hostname}"
            
            with open(self.conf_path, 'a') as f:
                f.write(f"\n{config_line}\n")
            
            # Recargar configuración
            self.reload()
            
            print(f"[dnsmasq] ✅ Reserva estática añadida: {mac} -> {ip}")
            return True
            
        except Exception as e:
            print(f"[dnsmasq] ❌ Error añadiendo reserva: {e}")
            return False
    
    def reload(self):
        """Recarga configuración de dnsmasq"""
        if self.process:
            try:
                self.process.send_signal(subprocess.signal.SIGHUP)
                self.stats['last_reload'] = time.time()
                print("[dnsmasq] Configuración recargada")
            except Exception as e:
                print(f"[dnsmasq] Error recargando configuración: {e}")
    
    def block_client(self, client_ip: str):
        """Método vacío - ya no se usa para bloquear DNS"""
        # Este método se mantiene por compatibilidad, pero no hace nada
        # El bloqueo ahora se maneja a través del firewall
        print(f"[dnsmasq] Nota: El bloqueo de {client_ip} ahora se maneja por firewall")
    
    def allow_client(self, client_ip: str):
        """Método vacío - ya no se usa para permitir DNS"""
        # Este método se mantiene por compatibilidad, pero no hace nada
        # El permiso ahora se maneja a través del firewall
        print(f"[dnsmasq] Nota: El permiso de {client_ip} ahora se maneja por firewall")
    
    def add_captive_domain(self, domain: str) -> bool:
        """Añade un dominio adicional para redirección al portal"""
        if domain not in self.captive_portal_domains:
            self.captive_portal_domains.append(domain)
            
            # Recargar configuración
            if self.stats['started']:
                config_content = self.generate_config()
                with open(self.conf_path, 'w') as f:
                    f.write(config_content)
                self.reload()
                print(f"[dnsmasq] Dominio añadido para redirección: {domain}")
                return True
        
        return False
    
    def get_config_summary(self) -> Dict:
        """Obtiene un resumen de la configuración actual"""
        return {
            'interface': self.default_config['interface'],
            'gateway': self.default_config['gateway'],
            'dhcp_range': f"{self.default_config['dhcp_start']} - {self.default_config['dhcp_end']}",
            'dns_servers': self.default_config['external_dns'],
            'captive_domains': len(self.captive_portal_domains),
            'leases_active': self.stats['leases_active'],
            'started': self.stats['started']
        }
    
    def is_running(self) -> bool:
        """Verifica si dnsmasq está en ejecución"""
        return self.stats['started'] and self.process and self.process.poll() is None