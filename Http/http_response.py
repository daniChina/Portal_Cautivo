#!/usr/bin/env python3
"""
Constructor de respuestas HTTP
"""

from typing import Dict, Optional
from datetime import datetime

class HTTPResponse:
    """Clase para construir respuestas HTTP manualmente"""
    
    def __init__(self, status_code: int = 200, status_text: str = "OK"):
        self.status_code = status_code
        self.status_text = status_text
        self.headers: Dict[str, str] = {}
        self.body: bytes = b""
        self.cookies: Dict[str, Dict] = {}
        
        # Headers por defecto
        self.set_default_headers()
    
    def set_default_headers(self):
        """Establece headers por defecto"""
        self.headers = {
            "Server": "PortalCautivo/1.0",
            "Date": datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
            "Connection": "close",
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache"
        }
    
    def set_header(self, key: str, value: str):
        """Establece un header"""
        self.headers[key] = value
    
    def set_body(self, body: str, content_type: str = "text/html; charset=utf-8"):
        """Establece el cuerpo de la respuesta"""
        self.body = body.encode('utf-8')
        self.set_header("Content-Type", content_type)
        self.set_header("Content-Length", str(len(self.body)))
    
    def set_json(self, data: dict):
        """Establece el cuerpo como JSON"""
        import json
        json_str = json.dumps(data)
        self.set_body(json_str, "application/json")
    
    def set_cookie(self, name: str, value: str, **kwargs):
        """Establece una cookie"""
        cookie_str = f"{name}={value}"
        
        # Opciones de cookie
        if "max_age" in kwargs:
            cookie_str += f"; Max-Age={kwargs['max_age']}"
        if "expires" in kwargs:
            cookie_str += f"; Expires={kwargs['expires']}"
        if "path" in kwargs:
            cookie_str += f"; Path={kwargs['path']}"
        if "domain" in kwargs:
            cookie_str += f"; Domain={kwargs['domain']}"
        if kwargs.get("secure"):
            cookie_str += "; Secure"
        if kwargs.get("http_only"):
            cookie_str += "; HttpOnly"
        
        # Añadir cookie a headers
        if "Set-Cookie" in self.headers:
            self.headers["Set-Cookie"] += f", {cookie_str}"
        else:
            self.headers["Set-Cookie"] = cookie_str
    
    def redirect(self, url: str, permanent: bool = False):
        """Crea una respuesta de redirección"""
        self.status_code = 301 if permanent else 302
        self.status_text = "Moved Permanently" if permanent else "Found"
        self.set_header("Location", url)
        self.set_body(f"<a href='{url}'>Redirecting...</a>")
    
    def build(self) -> bytes:
        """Construye la respuesta HTTP completa en bytes"""
        # Status line
        response = f"HTTP/1.1 {self.status_code} {self.status_text}\r\n"
        
        # Headers
        for key, value in self.headers.items():
            response += f"{key}: {value}\r\n"
        
        # Línea en blanco separadora
        response += "\r\n"
        
        # Convertir a bytes
        response_bytes = response.encode('utf-8')
        
        # Añadir body si existe
        if self.body:
            response_bytes += self.body
        
        return response_bytes
    
    @classmethod
    def error(cls, status_code: int, message: str = "") -> 'HTTPResponse':
        """Crea una respuesta de error"""
        common_errors = {
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            500: "Internal Server Error",
            503: "Service Unavailable"
        }
        
        status_text = common_errors.get(status_code, "Error")
        response = cls(status_code, status_text)
        
        if not message:
            message = f"<h1>{status_code} {status_text}</h1>"
        
        response.set_body(message)
        return response
    
    @classmethod
    def html(cls, html_content: str, status_code: int = 200) -> 'HTTPResponse':
        """Crea una respuesta HTML"""
        response = cls(status_code)
        response.set_body(html_content)
        return response
    
    @classmethod
    def json_response(cls, data: dict, status_code: int = 200) -> 'HTTPResponse':
        """Crea una respuesta JSON"""
        response = cls(status_code)
        response.set_json(data)
        return response