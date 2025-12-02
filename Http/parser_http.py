from typing import Dict, Optional
from dataclasses import dataclass
import re

@dataclass
class HTTPRequest:
    """Representa una petición HTTP parseada"""
    method: str
    path: str
    version: str
    headers: Dict[str, str]
    body: str
    client_ip: str
    
    @classmethod
    def from_raw_data(cls, raw_data: bytes, client_ip: str) -> Optional['HTTPRequest']:
        """Parsea datos HTTP crudos"""
        try:
            # Decodificar datos
            text = raw_data.decode('utf-8', errors='ignore')
            
            # Separar headers y body
            parts = text.split('\r\n\r\n', 1)
            headers_text = parts[0]
            body = parts[1] if len(parts) > 1 else ''
            
            # Parsear línea de petición
            lines = headers_text.split('\r\n')
            if not lines:
                return None
                
            request_line = lines[0].split()
            if len(request_line) < 3:
                return None
                
            method, path, version = request_line
            
            # Parsear headers
            headers = {}
            for line in lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key.strip().lower()] = value.strip()
            
            return cls(
                method=method.upper(),
                path=path,
                version=version,
                headers=headers,
                body=body,
                client_ip=client_ip
            )
        except Exception as e:
            return None
    
    def get_content_length(self) -> int:
        """Obtiene Content-Length de headers"""
        length = self.headers.get('content-length', '0')
        try:
            return int(length)
        except ValueError:
            return 0
    
    def is_authenticated_request(self) -> bool:
        """Verifica si es una petición de autenticación"""
        return self.path == '/login' and self.method == 'POST'
    
    def get_form_data(self) -> Dict[str, str]:
        """Extrae datos de formulario URL-encoded"""
        if not self.body or 'application/x-www-form-urlencoded' not in \
           self.headers.get('content-type', ''):
            return {}
        
        params = {}
        pairs = self.body.split('&')
        
        for pair in pairs:
            if '=' in pair:
                key, value = pair.split('=', 1)
                # Decodificar URL encoding básico
                key = self._url_decode(key)
                value = self._url_decode(value.replace('+', ' '))
                params[key] = value
        
        return params
    
    @staticmethod
    def _url_decode(s: str) -> str:
        """Decodifica URL encoding"""
        result = []
        i = 0
        while i < len(s):
            if s[i] == '%' and i + 2 < len(s):
                try:
                    hex_val = s[i+1:i+3]
                    char = chr(int(hex_val, 16))
                    result.append(char)
                    i += 3
                except:
                    result.append(s[i])
                    i += 1
            else:
                result.append(s[i])
                i += 1
        return ''.join(result)