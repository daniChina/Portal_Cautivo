#!/usr/bin/env python3
"""
Servidor DHCP completo integrado en el portal cautivo
RFC 2131 - Dynamic Host Configuration Protocol
"""

import socket
import struct
import threading
import time
import ipaddress
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass
class DHCPLease:
    """Información de concesión DHCP"""
    ip_address: str
    mac_address: str
    hostname: str
    lease_start: datetime
    lease_end: datetime
    state: str  # "offered", "leased", "expired", "reserved"
    client_id: str

class DHCPServer:
    """Servidor DHCP completo"""
    
    # Puertos DHCP
    DHCP_SERVER_PORT = 67
    DHCP_CLIENT_PORT = 68
    
    # Tipos de mensaje DHCP
    DHCP_DISCOVER = 1
    DHCP_OFFER = 2
    DHCP_REQUEST = 3
    DHCP_ACK = 5
    DHCP_NAK = 6
    DHCP_RELEASE = 7
    DHCP_INFORM = 8
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.interface = self.config.get('interface', 'eth1')
        self.subnet = self.config.get('subnet', '192.168.100.0/24')
        self.gateway = self.config.get('gateway', '192.168.100.1')
        self.dns_server = self.config.get('dns_server', '192.168.100.1')
        self.domain_name = self.config.get('domain_name', 'portal.local')
        
        # Pool de direcciones
        self.pool_start = self.config.get('pool_start', '192.168.100.100')
        self.pool_end = self.config.get('pool_end', '192.168.100.200')
        self.lease_time = self.config.get('lease_time', 7200)  # 2 horas por defecto
        
        # Concesiones activas
        self.leases: Dict[str, DHCPLease] = {}  # MAC -> Lease
        self.ip_to_mac: Dict[str, str] = {}  # IP -> MAC
        
        # Socket
        self.socket = None
        self.running = False
        self.thread = None
        
        # Bloqueo para concurrencia
        self.lock = threading.Lock()
        
        # Estadísticas
        self.stats = {
            'discover': 0,
            'offer': 0,
            'request': 0,
            'ack': 0,
            'nak': 0,
            'leases_active': 0
        }
        
        # Reservas estáticas (opcional)
        self.static_reservations = {
            # "AA:BB:CC:DD:EE:FF": "192.168.100.50"
        }
        
        print(f"[DHCP] Inicializado en {self.interface}")
        print(f"[DHCP] Pool: {self.pool_start} - {self.pool_end}")
        print(f"[DHCP] Gateway: {self.gateway}, DNS: {self.dns_server}")
    
    def start(self):
        """Inicia el servidor DHCP"""
        try:
            # Crear socket raw para DHCP
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            # Enlazar a la interfaz específica (requiere SO_BINDTODEVICE)
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, 
                                      self.interface.encode())
            except:
                # En sistemas sin SO_BINDTODEVICE, usar bind a IP específica
                pass
            
            self.socket.bind(('0.0.0.0', self.DHCP_SERVER_PORT))
            
            self.running = True
            self.thread = threading.Thread(target=self._listen, daemon=True)
            self.thread.start()
            
            # Iniciar thread de limpieza de leases expirados
            cleaner = threading.Thread(target=self._lease_cleaner, daemon=True)
            cleaner.start()
            
            print(f"[DHCP] Servidor iniciado en puerto {self.DHCP_SERVER_PORT}")
            return True
            
        except Exception as e:
            print(f"[DHCP] Error iniciando servidor: {e}")
            return False
    
    def stop(self):
        """Detiene el servidor DHCP"""
        self.running = False
        if self.socket:
            self.socket.close()
        print("[DHCP] Servidor detenido")
    
    def _listen(self):
        """Escucha peticiones DHCP"""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(1024)
                client_ip = addr[0]
                
                # Procesar en thread separado
                thread = threading.Thread(
                    target=self._handle_dhcp_packet,
                    args=(data, client_ip)
                )
                thread.daemon = True
                thread.start()
                
            except Exception as e:
                if self.running:
                    print(f"[DHCP] Error recibiendo paquete: {e}")
    
    def _handle_dhcp_packet(self, data: bytes, client_ip: str):
        """Procesa un paquete DHCP"""
        try:
            # Parsear header DHCP básico
            if len(data) < 240:
                return
            
            # Extraer campos principales
            op = data[0]  # Opcode (1=request, 2=reply)
            htype = data[1]  # Hardware type (1=Ethernet)
            hlen = data[2]   # Hardware address length (6)
            hops = data[3]   # Hops
            
            # Transaction ID (xid)
            xid = data[4:8]
            
            # Seconds elapsed
            secs = data[8:10]
            
            # Flags
            flags = data[10:12]
            
            # Client IP (ciaddr)
            ciaddr = data[12:16]
            
            # Your IP (yiaddr) - asignada por servidor
            yiaddr = data[16:20]
            
            # Server IP (siaddr)
            siaddr = data[20:24]
            
            # Gateway IP (giaddr)
            giaddr = data[24:28]
            
            # Client hardware address (chaddr)
            chaddr = data[28:44]  # 16 bytes, pero sólo usamos los primeros 'hlen'
            
            # Extraer MAC address
            mac_bytes = chaddr[:hlen]
            mac = ':'.join(f'{b:02x}' for b in mac_bytes).upper()
            
            # Parsear opciones DHCP
            options = self._parse_dhcp_options(data[240:])
            
            # Obtener tipo de mensaje
            msg_type = options.get(53, b'\x00')[0] if 53 in options else 0
            
            # Procesar según tipo
            if msg_type == self.DHCP_DISCOVER:
                self.stats['discover'] += 1
                self._handle_discover(mac, xid, options)
                
            elif msg_type == self.DHCP_REQUEST:
                self.stats['request'] += 1
                self._handle_request(mac, xid, ciaddr, options)
                
            elif msg_type == self.DHCP_RELEASE:
                self._handle_release(mac)
                
            elif msg_type == self.DHCP_INFORM:
                self._handle_inform(mac, xid, ciaddr, options)
                
        except Exception as e:
            print(f"[DHCP] Error procesando paquete: {e}")
    
    def _parse_dhcp_options(self, data: bytes) -> Dict[int, bytes]:
        """Parsea las opciones DHCP"""
        options = {}
        i = 0
        
        while i < len(data):
            code = data[i]
            
            if code == 0:  # Padding
                i += 1
                continue
            elif code == 255:  # End
                break
            
            if i + 1 >= len(data):
                break
            
            length = data[i + 1]
            if i + 2 + length > len(data):
                break
            
            value = data[i+2:i+2+length]
            options[code] = value
            
            i += 2 + length
        
        return options
    
    def _handle_discover(self, mac: str, xid: bytes, options: Dict):
        """Maneja mensaje DHCPDISCOVER"""
        with self.lock:
            # Verificar si ya tiene lease activo
            if mac in self.leases:
                lease = self.leases[mac]
                if lease.state == "leased" and datetime.now() < lease.lease_end:
                    # Renovar lease existente
                    ip = lease.ip_address
                else:
                    # Asignar nueva IP
                    ip = self._allocate_ip(mac)
            else:
                # Asignar nueva IP
                ip = self._allocate_ip(mac)
            
            if ip:
                # Crear DHCPOFFER
                self._send_offer(mac, xid, ip, options)
    
    def _handle_request(self, mac: str, xid: bytes, ciaddr: bytes, options: Dict):
        """Maneja mensaje DHCPREQUEST"""
        with self.lock:
            # Extraer IP solicitada
            requested_ip = None
            if 50 in options:  # Option 50: Requested IP Address
                ip_bytes = options[50]
                if len(ip_bytes) == 4:
                    requested_ip = socket.inet_ntoa(ip_bytes)
            
            # Verificar lease
            if mac in self.leases:
                lease = self.leases[mac]
                
                if requested_ip and requested_ip != lease.ip_address:
                    # IP diferente a la asignada - enviar NAK
                    self._send_nak(mac, xid, "IP address mismatch")
                    return
                
                # Confirmar lease
                lease.state = "leased"
                lease.lease_start = datetime.now()
                lease.lease_end = datetime.now() + timedelta(seconds=self.lease_time)
                
                # Enviar ACK
                self._send_ack(mac, xid, lease.ip_address, options)
                
                self.stats['leases_active'] = len([l for l in self.leases.values() 
                                                  if l.state == "leased"])
                self.stats['ack'] += 1
            else:
                # No hay lease - enviar NAK
                self._send_nak(mac, xid, "No lease found")
    
    def _handle_release(self, mac: str):
        """Maneja mensaje DHCPRELEASE"""
        with self.lock:
            if mac in self.leases:
                # Liberar IP
                lease = self.leases[mac]
                ip = lease.ip_address
                
                # Eliminar del mapeo
                if ip in self.ip_to_mac:
                    del self.ip_to_mac[ip]
                
                # Eliminar lease
                del self.leases[mac]
                
                print(f"[DHCP] Lease liberado: {mac} -> {ip}")
    
    def _handle_inform(self, mac: str, xid: bytes, ciaddr: bytes, options: Dict):
        """Maneja mensaje DHCPINFORM (solo información)"""
        # El cliente ya tiene IP, solo necesita configuración
        ciaddr_str = socket.inet_ntoa(ciaddr)
        self._send_ack(mac, xid, ciaddr_str, options, inform=True)
    
    def _allocate_ip(self, mac: str) -> Optional[str]:
        """Asigna una IP del pool"""
        # Verificar reserva estática primero
        if mac in self.static_reservations:
            ip = self.static_reservations[mac]
            if self._is_ip_available(ip):
                return ip
        
        # Convertir IPs a enteros para comparación
        start_int = self._ip_to_int(self.pool_start)
        end_int = self._ip_to_int(self.pool_end)
        
        # Buscar IP disponible
        for ip_int in range(start_int, end_int + 1):
            ip = self._int_to_ip(ip_int)
            
            # Saltar gateway y broadcast
            if ip == self.gateway or ip.endswith('.255'):
                continue
            
            # Verificar si está disponible
            if self._is_ip_available(ip):
                # Crear lease temporal (ofrecido)
                lease = DHCPLease(
                    ip_address=ip,
                    mac_address=mac,
                    hostname="",
                    lease_start=datetime.now(),
                    lease_end=datetime.now() + timedelta(seconds=300),  # 5 min para aceptar
                    state="offered",
                    client_id=mac
                )
                
                self.leases[mac] = lease
                self.ip_to_mac[ip] = mac
                
                return ip
        
        return None
    
    def _is_ip_available(self, ip: str) -> bool:
        """Verifica si una IP está disponible"""
        # Verificar si está en uso
        if ip in self.ip_to_mac:
            mac = self.ip_to_mac[ip]
            if mac in self.leases:
                lease = self.leases[mac]
                # Verificar si el lease sigue activo
                if lease.state == "leased" and datetime.now() < lease.lease_end:
                    return False
                elif lease.state == "offered":
                    # Verificar si la oferta expiró
                    if datetime.now() < lease.lease_end:
                        return False
        return True
    
    def _send_offer(self, mac: str, xid: bytes, ip: str, options: Dict):
        """Envía DHCPOFFER"""
        self._send_dhcp_reply(mac, xid, ip, self.DHCP_OFFER, options)
        self.stats['offer'] += 1
        print(f"[DHCP] Oferta enviada: {mac} -> {ip}")
    
    def _send_ack(self, mac: str, xid: bytes, ip: str, options: Dict, inform: bool = False):
        """Envía DHCPACK"""
        self._send_dhcp_reply(mac, xid, ip, self.DHCP_ACK, options, inform)
        print(f"[DHCP] ACK enviado: {mac} -> {ip}")
    
    def _send_nak(self, mac: str, xid: bytes, reason: str):
        """Envía DHCPNAK"""
        self._send_dhcp_reply(mac, xid, "0.0.0.0", self.DHCP_NAK, {})
        print(f"[DHCP] NAK enviado a {mac}: {reason}")
        self.stats['nak'] += 1
    
    def _send_dhcp_reply(self, mac: str, xid: bytes, ip: str, 
                        msg_type: int, options: Dict, inform: bool = False):
        """Construye y envía respuesta DHCP"""
        try:
            # Construir respuesta DHCP
            response = bytearray()
            
            # Opcode (2 = reply from server)
            response.append(2)
            
            # Hardware type (1 = Ethernet)
            response.append(1)
            
            # Hardware address length
            response.append(6)
            
            # Hops
            response.append(0)
            
            # Transaction ID
            response.extend(xid)
            
            # Seconds elapsed
            response.extend(b'\x00\x00')
            
            # Flags
            response.extend(b'\x00\x00')
            
            # Client IP address (ciaddr)
            response.extend(b'\x00\x00\x00\x00')
            
            # Your IP address (yiaddr)
            response.extend(socket.inet_aton(ip))
            
            # Server IP address (siaddr)
            response.extend(socket.inet_aton(self.gateway))
            
            # Gateway IP address (giaddr)
            response.extend(b'\x00\x00\x00\x00')
            
            # Client hardware address (chaddr)
            mac_bytes = bytes.fromhex(mac.replace(':', ''))
            response.extend(mac_bytes)
            response.extend(b'\x00' * (16 - len(mac_bytes)))  # Padding
            
            # Server name (64 bytes)
            response.extend(b'\x00' * 64)
            
            # Boot file name (128 bytes)
            response.extend(b'\x00' * 128)
            
            # Magic cookie (99.130.83.99)
            response.extend(b'\x63\x82\x53\x63')
            
            # Opciones DHCP
            # Message Type
            response.extend(b'\x35\x01' + bytes([msg_type]))
            
            # Server Identifier
            response.extend(b'\x36\x04' + socket.inet_aton(self.gateway))
            
            # Lease Time
            lease_bytes = struct.pack('!I', self.lease_time)
            response.extend(b'\x33\x04' + lease_bytes)
            
            # Renewal Time (T1) - 50% del lease time
            t1_bytes = struct.pack('!I', self.lease_time // 2)
            response.extend(b'\x3a\x04' + t1_bytes)
            
            # Rebinding Time (T2) - 87.5% del lease time
            t2_bytes = struct.pack('!I', int(self.lease_time * 0.875))
            response.extend(b'\x3b\x04' + t2_bytes)
            
            # Subnet Mask
            subnet_obj = ipaddress.ip_network(self.subnet, strict=False)
            mask_bytes = socket.inet_aton(str(subnet_obj.netmask))
            response.extend(b'\x01\x04' + mask_bytes)
            
            # Router (Gateway)
            response.extend(b'\x03\x04' + socket.inet_aton(self.gateway))
            
            # DNS Server
            response.extend(b'\x06\x04' + socket.inet_aton(self.dns_server))
            
            # Domain Name
            domain_bytes = self.domain_name.encode()
            response.extend(b'\x0f' + bytes([len(domain_bytes)]) + domain_bytes)
            
            # End option
            response.append(255)
            
            # Enviar paquete
            self.socket.sendto(bytes(response), ('<broadcast>', self.DHCP_CLIENT_PORT))
            
        except Exception as e:
            print(f"[DHCP] Error enviando respuesta: {e}")
    
    def _lease_cleaner(self):
        """Limpia leases expirados periódicamente"""
        while self.running:
            time.sleep(60)  # Verificar cada minuto
            
            with self.lock:
                now = datetime.now()
                expired = []
                
                for mac, lease in self.leases.items():
                    if lease.state == "offered" and now > lease.lease_end:
                        # Oferta expirada
                        expired.append(mac)
                    elif lease.state == "leased" and now > lease.lease_end:
                        # Lease expirado
                        expired.append(mac)
                
                for mac in expired:
                    if mac in self.leases:
                        lease = self.leases[mac]
                        ip = lease.ip_address
                        
                        # Eliminar del mapeo
                        if ip in self.ip_to_mac:
                            del self.ip_to_mac[ip]
                        
                        # Eliminar lease
                        del self.leases[mac]
                        
                        print(f"[DHCP] Lease expirado limpiado: {mac} -> {ip}")
    
    def _ip_to_int(self, ip: str) -> int:
        """Convierte IP a entero"""
        return struct.unpack('!I', socket.inet_aton(ip))[0]
    
    def _int_to_ip(self, ip_int: int) -> str:
        """Convierte entero a IP"""
        return socket.inet_ntoa(struct.pack('!I', ip_int))
    
    def get_stats(self) -> Dict:
        """Obtiene estadísticas del servidor"""
        with self.lock:
            stats = self.stats.copy()
            stats['total_leases'] = len(self.leases)
            stats['active_leases'] = len([l for l in self.leases.values() 
                                         if l.state == "leased"])
            return stats
    
    def get_active_leases(self) -> List[Dict]:
        """Obtiene leases activos"""
        with self.lock:
            active = []
            now = datetime.now()
            
            for mac, lease in self.leases.items():
                if lease.state == "leased" and now < lease.lease_end:
                    active.append({
                        'mac': mac,
                        'ip': lease.ip_address,
                        'hostname': lease.hostname,
                        'lease_start': lease.lease_start.isoformat(),
                        'lease_end': lease.lease_end.isoformat(),
                        'remaining': int((lease.lease_end - now).total_seconds())
                    })
            
            return active