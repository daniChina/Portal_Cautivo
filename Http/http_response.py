#!/usr/bin/env python3
"""
Constructor de respuestas HTTP - Clase utilitaria
"""

from typing import Dict, Optional
from datetime import datetime
from .templates import get_error_template

class HTTPResponse:
    """Clase helper para construir respuestas HTTP"""
    
    @staticmethod
    def create(status_code: int, body: str, content_type: str = "text/html", 
               headers: Optional[Dict] = None) -> bytes:
        """Crea una respuesta HTTP estándar"""
        status_texts = {
            200: "OK",
            302: "Found",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error"
        }
        
        status_text = status_texts.get(status_code, "Unknown")
        
        response = f"HTTP/1.1 {status_code} {status_text}\r\n"
        response += f"Content-Type: {content_type}; charset=utf-8\r\n"
        response += f"Content-Length: {len(body.encode('utf-8'))}\r\n"
        response += "Connection: close\r\n"
        response += f"Date: {datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}\r\n"
        
        if headers:
            for key, value in headers.items():
                response += f"{key}: {value}\r\n"
        
        response += "\r\n"
        response += body
        
        return response.encode('utf-8')
    
    @staticmethod
    def redirect(url: str, permanent: bool = False) -> bytes:
        """Crea una respuesta de redirección"""
        status_code = 301 if permanent else 302
        html = f'<html><head><meta http-equiv="refresh" content="0;url={url}"></head><body>Redirecting...</body></html>'
        
        response = f"HTTP/1.1 {status_code} {'Moved Permanently' if permanent else 'Found'}\r\n"
        response += f"Location: {url}\r\n"
        response += f"Content-Type: text/html; charset=utf-8\r\n"
        response += f"Content-Length: {len(html.encode('utf-8'))}\r\n"
        response += "Connection: close\r\n\r\n"
        response += html
        
        return response.encode('utf-8')
    
    @staticmethod
    def error(status_code: int, message: str = "") -> bytes:
        """Crea una respuesta de error"""
        from .templates import get_error_template
        html = get_error_template(status_code, message)
        return HTTPResponse.create(status_code, html)
    
    @staticmethod
    def html(content: str, status_code: int = 200) -> bytes:
        """Crea una respuesta HTML"""
        return HTTPResponse.create(status_code, content, "text/html")
    
    @staticmethod
    def json(data: dict, status_code: int = 200) -> bytes:
        """Crea una respuesta JSON"""
        import json
        json_str = json.dumps(data)
        return HTTPResponse.create(status_code, json_str, "application/json")