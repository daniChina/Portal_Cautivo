#!/usr/bin/env python3
"""
Creador de Hotspot WiFi para el portal cautivo
"""

import subprocess
import os
import time
import threading

class HotspotManager:
    """Gestiona la creación de un hotspot WiFi usando hostapd"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.hostapd_process = None
        self.dnsmasq_process = None
        
        # Configuración por defecto
        self.defaults = {
            'interface': 'wlan0',
            'ssid': 'Portal-Cautivo',
            'password': 'portal12345',
            'channel': 6,
            'driver': 'nl80211',
            'hw_mode': 'g',
            'country_code': 'US',
            'ip': '192.168.100.1',
            'subnet': '255.255.255.0',
            'dhcp_start': '192.168.100.100',
            'dhcp_end': '192.168.100.200'
        }
        self.defaults.update(config)
    
    def start(self):
        """Inicia el hotspot WiFi"""
        try:
            print(f"[Hotspot] Configurando interfaz {self.defaults['interface']}...")
            
            # 1. Parar servicios que puedan interferir
            self._stop_interfering_services()
            
            # 2. Configurar interfaz WiFi
            self._setup_wifi_interface()
            
            # 3. Iniciar hostapd (punto de acceso)
            self._start_hostapd()
            
            # 4. Iniciar dnsmasq (DHCP + DNS)
            self._start_dnsmasq()
            
            # 5. Configurar NAT e iptables
            self._setup_nat()
            
            print(f"[Hotspot] ✅ Hotspot activo: {self.defaults['ssid']}")
            print(f"[Hotspot] 📶 Contraseña: {self.defaults['password']}")
            print(f"[Hotspot] 🌐 IP del portal: {self.defaults['ip']}")
            
            return True
            
        except Exception as e:
            print(f"[Hotspot] ❌ Error iniciando hotspot: {e}")
            return False
    
    def _stop_interfering_services(self):
        """Detiene servicios que puedan interferir"""
        services = ['NetworkManager', 'wpa_supplicant', 'systemd-networkd']
        
        for service in services:
            try:
                subprocess.run(['systemctl', 'stop', service], 
                             capture_output=True, timeout=5)
            except:
                pass
        
        # Matar procesos relacionados
        subprocess.run(['pkill', 'hostapd'], capture_output=True)
        subprocess.run(['pkill', 'dnsmasq'], capture_output=True)
        
        time.sleep(2)
    
    def _setup_wifi_interface(self):
        """Configura la interfaz WiFi"""
        interface = self.defaults['interface']
        
        # Activar modo AP
        subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True)
        subprocess.run(['iw', 'dev', interface, 'set', 'type', '__ap'], check=True)
        subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True)
        
        # Asignar IP
        subprocess.run(['ip', 'addr', 'flush', 'dev', interface], check=True)
        subprocess.run(['ip', 'addr', 'add', f"{self.defaults['ip']}/24", 
                       'dev', interface], check=True)
        
        print(f"[Hotspot] Interfaz {interface} configurada como AP")
    
    def _start_hostapd(self):
        """Inicia hostapd para crear el hotspot"""
        config = f"""interface={self.defaults['interface']}
driver={self.defaults['driver']}
ssid={self.defaults['ssid']}
hw_mode={self.defaults['hw_mode']}
channel={self.defaults['channel']}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={self.defaults['password']}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
country_code={self.defaults['country_code']}
"""
        
        # Guardar configuración
        with open('/tmp/hostapd.conf', 'w') as f:
            f.write(config)
        
        # Iniciar hostapd
        self.hostapd_process = subprocess.Popen(
            ['hostapd', '/tmp/hostapd.conf'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Esperar a que inicie
        time.sleep(3)
        if self.hostapd_process.poll() is not None:
            raise Exception("hostapd no pudo iniciar")
        
        print("[Hotspot] hostapd iniciado")
    
    def _start_dnsmasq(self):
        """Inicia dnsmasq para DHCP y DNS"""
        config = f"""interface={self.defaults['interface']}
        bind-interfaces
        dhcp-range={self.defaults['dhcp_start']},{self.defaults['dhcp_end']},12h
        dhcp-option=3,{self.defaults['ip']}
        dhcp-option=6,{self.defaults['ip']}
        log-dhcp
        log-queries
        log-facility=/tmp/dnsmasq.log
        """
        
        # Guardar configuración
        with open('/tmp/dnsmasq.conf', 'w') as f:
            f.write(config)
        
        # Iniciar dnsmasq
        self.dnsmasq_process = subprocess.Popen(
            ['dnsmasq', '-C', '/tmp/dnsmasq.conf', '--no-daemon'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        time.sleep(2)
        print("[Hotspot] dnsmasq iniciado (DHCP + DNS)")
    
    def _setup_nat(self):
        """Configura NAT para compartir Internet"""
        external_iface = self._get_external_interface()
        
        if not external_iface:
            print("[Hotspot] ⚠️  No hay interfaz externa (sin Internet)")
            return
        
        commands = [
            # Habilitar IP forwarding
            'sysctl -w net.ipv4.ip_forward=1',
            
            # Limpiar reglas anteriores
            'iptables -F',
            'iptables -t nat -F',
            'iptables -X',
            
            # NAT para compartir Internet
            f'iptables -t nat -A POSTROUTING -o {external_iface} -j MASQUERADE',
            
            # Permitir tráfico forward
            f'iptables -A FORWARD -i {self.defaults["interface"]} -o {external_iface} -j ACCEPT',
            f'iptables -A FORWARD -i {external_iface} -o {self.defaults["interface"]} -m state --state RELATED,ESTABLISHED -j ACCEPT',
            
            # Bloquear todo hasta autenticación
            f'iptables -A FORWARD -i {self.defaults["interface"]} ! -o {self.defaults["interface"]} -j DROP'
        ]
        
        for cmd in commands:
            subprocess.run(cmd, shell=True, check=True)
        
        print(f"[Hotspot] NAT configurado con interfaz externa: {external_iface}")
    
    def _get_external_interface(self):
        """Obtiene la interfaz con acceso a Internet"""
        try:
            # Buscar interfaz con gateway por defecto
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.split('\n'):
                    if 'default via' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            return parts[4]  # Interfaz
        except:
            pass
        
        # Fallback: buscar eth0, wlan1, etc.
        interfaces = ['eth0', 'wlan1', 'enp0s3', 'enp0s8']
        for iface in interfaces:
            try:
                subprocess.run(['ip', 'link', 'show', iface], 
                             capture_output=True, check=True)
                return iface
            except:
                continue
        
        return None
    
    def stop(self):
        """Detiene el hotspot"""
        print("[Hotspot] Deteniendo hotspot...")
        
        if self.hostapd_process:
            self.hostapd_process.terminate()
        
        if self.dnsmasq_process:
            self.dnsmasq_process.terminate()
        
        # Limpiar iptables
        subprocess.run(['iptables', '-F'], capture_output=True)
        subprocess.run(['iptables', '-t', 'nat', '-F'], capture_output=True)
        
        print("[Hotspot] Hotspot detenido")