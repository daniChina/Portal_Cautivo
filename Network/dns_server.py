#!/usr/bin/env python3
"""
Servidor DNS implementado manualmente sin librerías externas.
RFC 1035 - Domain names - implementation and specification
"""

import socket
import struct
import threading
import time
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import ipaddress

@dataclass
class DNSQuestion:
    """Representa una pregunta DNS"""
    name: str      # Nombre de dominio (ej: "google.com")
    qtype: int     # Tipo de consulta (1=A, 28=AAAA)
    qclass: int    # Clase (1=IN)

@dataclass
class DNSResourceRecord:
    """Representa un registro de recurso DNS"""
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdlength: int
    rdata: bytes

class DNSServer:
    """Servidor DNS completo implementado manualmente"""
    
    # Constantes DNS
    TYPE_A = 1      # IPv4 address
    TYPE_NS = 2     # Name server
    TYPE_CNAME = 5  # Canonical name
    TYPE_SOA = 6    # Start of authority
    TYPE_PTR = 12   # Domain name pointer
    TYPE_MX = 15    # Mail exchange
    TYPE_TXT = 16   # Text strings
    TYPE_AAAA = 28  # IPv6 address
    TYPE_ANY = 255  # Any type
    
    CLASS_IN = 1    # Internet class
    
    # Opcodes
    OPCODE_QUERY = 0
    OPCODE_IQUERY = 1
    OPCODE_STATUS = 2
    
    # Response codes
    RCODE_NO_ERROR = 0
    RCODE_FORMAT_ERROR = 1
    RCODE_SERVER_FAILURE = 2
    RCODE_NAME_ERROR = 3
    RCODE_NOT_IMPLEMENTED = 4
    RCODE_REFUSED = 5
    
    def __init__(self, gateway_ip: str = "192.168.100.1", port: int = 53):
        self.gateway_ip = gateway_ip
        self.port = port
        self.running = False
        self.socket = None
        self.logger = None
        
        # Zonas DNS configuradas
        self.zones: Dict[str, List[DNSResourceRecord]] = {
            # Redirigir todos los dominios comunes al portal
            ".": [],  # Root - para redirección universal
        }
        
        # Cache DNS simple
        self.cache: Dict[str, Tuple[float, List[DNSResourceRecord]]] = {}
        self.cache_ttl = 300  # 5 minutos
        
        # Dominios permitidos después de autenticación
        self.allowed_domains: Dict[str, List[str]] = {}  # client_ip -> [domains]
        
        # Estadísticas
        self.stats = {
            'queries': 0,
            'redirected': 0,
            'allowed': 0,
            'errors': 0
        }
    
    def set_logger(self, logger):
        """Establece el logger para mensajes"""
        self.logger = logger
    
    def log(self, message: str, level: str = "INFO"):
        """Registra un mensaje"""
        if self.logger:
            self.logger.log(f"[DNS] {message}", level)
        else:
            print(f"[DNS] {message}")
    
    def encode_domain_name(self, domain: str) -> bytes:
        """
        Codifica un nombre de dominio según RFC 1035
        Ejemplo: "google.com" -> b'\x06google\x03com\x00'
        """
        encoded = b''
        for part in domain.split('.'):
            if part:  # Ignorar partes vacías
                encoded += struct.pack('B', len(part))  # Longitud
                encoded += part.encode('ascii')         # Contenido
        encoded += b'\x00'  # Terminador
        return encoded
    
    def decode_domain_name(self, data: bytes, offset: int) -> Tuple[str, int]:
        """
        Decodifica un nombre de dominio desde datos binarios
        Maneja compresión DNS (punteros)
        """
        labels = []
        original_offset = offset
        jumped = False
        max_jumps = 10  # Prevenir loops infinitos
        jumps = 0
        
        while jumps < max_jumps:
            if offset >= len(data):
                break
            
            length = data[offset]
            offset += 1
            
            if length == 0:
                # Fin del nombre
                break
            elif (length & 0xC0) == 0xC0:
                # Puntero de compresión
                if not jumped:
                    original_offset = offset + 1
                pointer = ((length & 0x3F) << 8) | data[offset]
                offset = pointer
                jumped = True
                jumps += 1
                continue
            else:
                # Etiqueta normal
                labels.append(data[offset:offset + length].decode('ascii', errors='ignore'))
                offset += length
        
        if jumped:
            offset = original_offset
        
        return '.'.join(labels), offset
    
    def parse_dns_query(self, data: bytes) -> Tuple[Dict, List[DNSQuestion]]:
        """
        Parsea un paquete DNS completo
        Retorna: (header_dict, questions_list)
        """
        if len(data) < 12:  # Tamaño mínimo del header DNS
            raise ValueError("Paquete DNS demasiado pequeño")
        
        # Parsear header (12 bytes)
        header = struct.unpack('!HHHHHH', data[:12])
        
        header_dict = {
            'id': header[0],
            'qr': (header[1] >> 15) & 0x1,      # Query/Response
            'opcode': (header[1] >> 11) & 0xF,  # Opcode
            'aa': (header[1] >> 10) & 0x1,      # Authoritative Answer
            'tc': (header[1] >> 9) & 0x1,       # Truncated
            'rd': (header[1] >> 8) & 0x1,       # Recursion Desired
            'ra': (header[1] >> 7) & 0x1,       # Recursion Available
            'z': (header[1] >> 4) & 0x7,        # Reserved
            'rcode': header[1] & 0xF,           # Response Code
            'qdcount': header[2],               # Question Count
            'ancount': header[3],               # Answer Count
            'nscount': header[4],               # Authority Count
            'arcount': header[5]                # Additional Count
        }
        
        questions = []
        offset = 12
        
        # Parsear preguntas
        for _ in range(header_dict['qdcount']):
            if offset >= len(data):
                break
            
            qname, offset = self.decode_domain_name(data, offset)
            
            if offset + 4 > len(data):
                break
            
            qtype, qclass = struct.unpack('!HH', data[offset:offset + 4])
            offset += 4
            
            questions.append(DNSQuestion(
                name=qname.lower(),  # DNS es case-insensitive
                qtype=qtype,
                qclass=qclass
            ))
        
        return header_dict, questions
    
    def create_dns_response(self, query_header: Dict, questions: List[DNSQuestion], 
                           answers: List[DNSResourceRecord]) -> bytes:
        """
        Crea una respuesta DNS
        """
        # Construir header de respuesta
        flags = 0
        flags |= (1 << 15)  # QR = 1 (Response)
        flags |= (query_header['opcode'] << 11)  # Mismo opcode
        flags |= (1 << 10)  # AA = 1 (Authoritative Answer)
        flags |= (query_header['rd'] << 8)  # Recursion Desired
        flags |= (1 << 7)   # RA = 1 (Recursion Available)
        flags |= query_header['rcode']  # Response Code
        
        header = struct.pack('!HHHHHH',
            query_header['id'],           # Transaction ID
            flags,                        # Flags
            len(questions),               # QDCOUNT
            len(answers),                 # ANCOUNT
            0,                            # NSCOUNT
            0                             # ARCOUNT
        )
        
        # Construir sección de preguntas
        questions_section = b''
        for question in questions:
            questions_section += self.encode_domain_name(question.name)
            questions_section += struct.pack('!HH', question.qtype, question.qclass)
        
        # Construir sección de respuestas
        answers_section = b''
        for answer in answers:
            answers_section += self.encode_domain_name(answer.name)
            answers_section += struct.pack('!HHIH', 
                answer.rtype, 
                answer.rclass,
                answer.ttl,
                answer.rdlength
            )
            answers_section += answer.rdata
        
        return header + questions_section + answers_section
    
    def ip_to_bytes(self, ip: str) -> bytes:
        """Convierte una dirección IP a bytes para DNS"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version == 4:
                return ip_obj.packed
            elif ip_obj.version == 6:
                return ip_obj.packed
        except:
            # Si falla, usar IPv4 por defecto
            return socket.inet_aton(ip)
    
    def create_a_record(self, domain: str, ip: str, ttl: int = 300) -> DNSResourceRecord:
        """Crea un registro A (IPv4)"""
        return DNSResourceRecord(
            name=domain,
            rtype=self.TYPE_A,
            rclass=self.CLASS_IN,
            ttl=ttl,
            rdlength=4,
            rdata=self.ip_to_bytes(ip)
        )
    
    def handle_query(self, query_data: bytes, client_ip: str) -> Optional[bytes]:
        """
        Maneja una consulta DNS y retorna la respuesta
        """
        try:
            self.stats['queries'] += 1
            
            # Parsear consulta
            header, questions = self.parse_dns_query(query_data)
            
            if not questions:
                self.log(f"Consulta sin preguntas de {client_ip}", "WARN")
                return None
            
            # Registrar consulta
            for question in questions:
                self.log(f"Consulta de {client_ip}: {question.name} (Tipo: {question.qtype})", "DEBUG")
            
            # Preparar respuestas
            answers = []
            
            for question in questions:
                domain = question.name
                
                # Verificar si el cliente está autenticado
                if client_ip in self.allowed_domains:
                    # Cliente autenticado - resolver DNS normalmente
                    self.stats['allowed'] += 1
                    
                    # Intentar resolución real (si está implementada)
                    # Por ahora, redirigir al gateway para que resuelva
                    answer = self.create_a_record(domain, self.gateway_ip, ttl=60)
                    answers.append(answer)
                    
                else:
                    # Cliente NO autenticado - redirigir todo al portal
                    self.stats['redirected'] += 1
                    
                    # Redirigir al portal cautivo
                    answer = self.create_a_record(domain, self.gateway_ip, ttl=60)
                    answers.append(answer)
                    
                    # También responder con wildcard para subdominios
                    if domain.count('.') > 1:
                        wildcard_domain = f"*.{'.'.join(domain.split('.')[-2:])}"
                        if wildcard_domain not in [a.name for a in answers]:
                            wildcard_answer = self.create_a_record(wildcard_domain, self.gateway_ip, ttl=60)
                            answers.append(wildcard_answer)
            
            # Crear respuesta DNS
            response = self.create_dns_response(header, questions, answers)
            
            self.log(f"Respuesta enviada a {client_ip}: {len(answers)} registros", "DEBUG")
            return response
            
        except Exception as e:
            self.stats['errors'] += 1
            self.log(f"Error manejando consulta DNS: {e}", "ERROR")
            return None
    
    def allow_client(self, client_ip: str):
        """Permite resolución DNS normal para un cliente autenticado"""
        self.allowed_domains[client_ip] = []
        self.log(f"Cliente {client_ip} autorizado para DNS", "INFO")
    
    def block_client(self, client_ip: str):
        """Bloquea cliente, redirige todo al portal"""
        if client_ip in self.allowed_domains:
            del self.allowed_domains[client_ip]
            self.log(f"Cliente {client_ip} bloqueado de DNS", "INFO")
    
    def start(self):
        """Inicia el servidor DNS"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            self.socket.settimeout(1.0)  # Timeout para poder verificar running
            
            self.running = True
            self.log(f"Servidor DNS iniciado en puerto {self.port}")
            self.log(f"Gateway IP: {self.gateway_ip}")
            
            while self.running:
                try:
                    # Esperar paquete DNS
                    data, addr = self.socket.recvfrom(512)  # Max tamaño DNS UDP
                    client_ip = addr[0]
                    
                    # Manejar en hilo separado para concurrencia
                    thread = threading.Thread(
                        target=self._handle_dns_packet,
                        args=(data, client_ip, addr)
                    )
                    thread.daemon = True
                    thread.start()
                    
                except socket.timeout:
                    # Timeout normal, verificar si seguimos running
                    continue
                except Exception as e:
                    if self.running:
                        self.log(f"Error en socket DNS: {e}", "ERROR")
                    
        except Exception as e:
            self.log(f"Error iniciando servidor DNS: {e}", "ERROR")
        finally:
            if self.socket:
                self.socket.close()
            self.log("Servidor DNS detenido")
    
    def _handle_dns_packet(self, data: bytes, client_ip: str, addr: Tuple[str, int]):
        """Maneja un paquete DNS individual"""
        try:
            response = self.handle_query(data, client_ip)
            if response:
                self.socket.sendto(response, addr)
        except Exception as e:
            self.log(f"Error procesando paquete DNS: {e}", "ERROR")
    
    def stop(self):
        """Detiene el servidor DNS"""
        self.running = False
        if self.socket:
            self.socket.close()
    
    def get_stats(self) -> Dict:
        """Obtiene estadísticas del servidor DNS"""
        return self.stats.copy()