#!/usr/bin/env python3
"""
Servidor HTTP implementado manualmente con sistema de autenticación
"""

import socket
import threading
import time
from typing import Callable, Optional, Dict, Tuple
from Http.parser_http import HTTPRequest
from Http.templates import get_login_template, get_success_template, get_error_template

class HTTPServer:
    """Servidor HTTP completo con gestión de sesiones"""
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.host = self.config.get('http_host', '0.0.0.0')
        self.port = self.config.get('http_port', 80)
        self.running = False
        self.server_socket = None
        
        # Callbacks de autenticación
        self.auth_check_callback = None
        self.auth_verify_callback = None
        self.on_login_success = None
        self.on_logout = None
        
        # Contadores
        self.stats = {
            'connections': 0,
            'logins_success': 0,
            'logins_failed': 0,
            'pages_served': 0
        }
        
        # Intentos de login por IP (para protección básica)
        self.login_attempts: Dict[str, Tuple[int, float]] = {}
    
    def set_auth_callbacks(self, auth_check: Callable, auth_verify: Callable):
        """Establece los callbacks de autenticación"""
        self.auth_check_callback = auth_check
        self.auth_verify_callback = auth_verify
    
    def start(self):
        """Inicia el servidor HTTP"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            
            self.running = True
            print(f"🌐 Servidor HTTP iniciado en http://{self.host}:{self.port}")
            print(f"   Portal disponible en: http://{self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    client_ip = addr[0]
                    
                    # Manejar cada cliente en un hilo separado
                    thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_ip)
                    )
                    thread.daemon = True
                    thread.start()
                    
                except Exception as e:
                    if self.running:
                        print(f"Error aceptando conexión: {e}")
        
        except Exception as e:
            print(f"Error iniciando servidor HTTP: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
    
    def stop(self):
        """Detiene el servidor HTTP"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
    
    def _handle_client(self, client_socket: socket.socket, client_ip: str):
        """Maneja una conexión de cliente"""
        try:
            # Recibir datos del cliente
            request_data = b''
            client_socket.settimeout(5.0)
            
            while True:
                try:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    request_data += chunk
                    
                    # Verificar si ya tenemos todos los headers
                    if b'\r\n\r\n' in request_data:
                        # Verificar si hay body pendiente
                        headers_part = request_data.split(b'\r\n\r\n')[0]
                        content_length = 0
                        
                        # Buscar Content-Length
                        lines = headers_part.decode('utf-8', errors='ignore').split('\r\n')
                        for line in lines:
                            if line.lower().startswith('content-length:'):
                                content_length = int(line.split(':', 1)[1].strip())
                                break
                        
                        # Verificar si ya recibimos todo el body
                        body_received = len(request_data.split(b'\r\n\r\n', 1)[1])
                        if body_received >= content_length:
                            break
                        
                except socket.timeout:
                    break
            
            if not request_data:
                return
            
            # Parsear la petición
            request = HTTPRequest.from_raw_data(request_data, client_ip)
            if not request:
                # Respuesta de error básica
                error_response = self._create_http_response(400, "Bad Request", get_error_template(400))
                client_socket.send(error_response)
                return
            
            # Procesar la petición
            response = self._handle_request(request)
            
            # Enviar respuesta
            client_socket.send(response)
            
            # Actualizar estadísticas
            self.stats['connections'] += 1
            if '/login' in request.path and request.method == 'POST':
                self.stats['pages_served'] += 1
            
        except Exception as e:
            print(f"Error manejando cliente {client_ip}: {e}")
        finally:
            client_socket.close()
    
    def _handle_request(self, request: HTTPRequest) -> bytes:
        """Procesa una petición HTTP y genera respuesta"""
        # Verificar autenticación
        is_authenticated = False
        if self.auth_check_callback:
            is_authenticated = self.auth_check_callback(request.client_ip)
        
        # Ruta: Página principal
        if request.path == '/' and request.method == 'GET':
            if is_authenticated:
                return self._create_success_response(request.client_ip)
            else:
                return self._create_login_response()
        
        # Ruta: Procesar login
        elif request.path == '/login' and request.method == 'POST':
            return self._handle_login(request)
        
        # Ruta: Logout
        elif request.path == '/logout' and request.method == 'GET':
            return self._handle_logout(request.client_ip)
        
        # Ruta: Estado del sistema (para debugging)
        elif request.path == '/status' and request.method == 'GET':
            return self._create_status_response()
        
        # Ruta: Cualquier otra ruta - redirigir al login si no autenticado
        else:
            if is_authenticated:
                # Para usuarios autenticados, redirigir a Google
                return self._create_redirect_response("https://www.google.com")
            else:
                return self._create_login_response("Para acceder a esta página, primero inicie sesión")
    
    def _handle_login(self, request: HTTPRequest) -> bytes:
        """Maneja el proceso de login"""
        client_ip = request.client_ip
        
        # Protección básica contra fuerza bruta
        now = time.time()
        attempts, last_attempt = self.login_attempts.get(client_ip, (0, 0))
        
        # Resetear intentos después de 15 minutos
        if now - last_attempt > 900:  # 15 minutos
            attempts = 0
        
        # Bloquear después de 5 intentos fallidos
        if attempts >= 5:
            return self._create_login_response("Demasiados intentos fallidos. Espere 15 minutos.")
        
        # Extraer credenciales del formulario
        form_data = request.get_form_data()
        username = form_data.get('username', '').strip()
        password = form_data.get('password', '').strip()
        
        # Validar campos
        if not username or not password:
            return self._create_login_response("Por favor, complete todos los campos")
        
        # Verificar credenciales
        if self.auth_verify_callback and self.auth_verify_callback(username, password, client_ip):
            # Login exitoso
            self.login_attempts[client_ip] = (0, now)  # Resetear intentos
            self.stats['logins_success'] += 1
            
            # Ejecutar callback de éxito
            if self.on_login_success:
                self.on_login_success(client_ip, username)
            
            return self._create_success_response(client_ip, username)
        else:
            # Login fallido
            attempts += 1
            self.login_attempts[client_ip] = (attempts, now)
            self.stats['logins_failed'] += 1
            
            return self._create_login_response("Usuario o contraseña incorrectos")
    
    def _handle_logout(self, client_ip: str) -> bytes:
        """Maneja el logout"""
        if self.on_logout:
            self.on_logout(client_ip)
        
        # Limpiar intentos de login
        if client_ip in self.login_attempts:
            del self.login_attempts[client_ip]
        
        return self._create_login_response("Sesión cerrada exitosamente")
    
    def _create_http_response(self, status_code: int, status_text: str, body: str, 
                             content_type: str = "text/html", headers: dict = None) -> bytes:
        """Crea una respuesta HTTP completa"""
        response = f"HTTP/1.1 {status_code} {status_text}\r\n"
        response += f"Content-Type: {content_type}; charset=utf-8\r\n"
        response += f"Content-Length: {len(body.encode('utf-8'))}\r\n"
        response += "Connection: close\r\n"
        
        if headers:
            for key, value in headers.items():
                response += f"{key}: {value}\r\n"
        
        response += "\r\n"
        response += body
        
        return response.encode('utf-8')
    
    def _create_login_response(self, error_message: str = "") -> bytes:
        """Crea respuesta con página de login"""
        html_content = get_login_template(error_message)
        return self._create_http_response(200, "OK", html_content)
    
    def _create_success_response(self, client_ip: str, username: str = "Usuario") -> bytes:
        """Crea respuesta con página de éxito"""
        html_content = get_success_template(client_ip, username)
        return self._create_http_response(200, "OK", html_content)
    
    def _create_error_response(self, status_code: int, message: str = "") -> bytes:
        """Crea respuesta de error"""
        html_content = get_error_template(status_code, message)
        return self._create_http_response(status_code, "Error", html_content)
    
    def _create_redirect_response(self, url: str) -> bytes:
        """Crea una respuesta de redirección"""
        html = f'<html><head><meta http-equiv="refresh" content="0;url={url}"></head><body>Redirecting...</body></html>'
        response = f"HTTP/1.1 302 Found\r\n"
        response += f"Location: {url}\r\n"
        response += f"Content-Type: text/html; charset=utf-8\r\n"
        response += f"Content-Length: {len(html.encode('utf-8'))}\r\n"
        response += "Connection: close\r\n\r\n"
        response += html
        return response.encode('utf-8')
    
    def _create_status_response(self) -> bytes:
        """Crea respuesta con estado del sistema (para debugging)"""
        status_html = f"""
        <!DOCTYPE html>
        <html>
        <head><title>Estado del Portal</title>
        <style>
            body {{ font-family: monospace; padding: 20px; }}
            .stats {{ background: #f5f5f5; padding: 20px; border-radius: 5px; }}
            .stat-item {{ margin: 5px 0; }}
            .stat-value {{ font-weight: bold; color: #007bff; }}
        </style>
        </head>
        <body>
            <h1>Estado del Portal Cautivo</h1>
            <div class="stats">
                <div class="stat-item">Conexiones totales: <span class="stat-value">{self.stats['connections']}</span></div>
                <div class="stat-item">Logins exitosos: <span class="stat-value">{self.stats['logins_success']}</span></div>
                <div class="stat-item">Logins fallidos: <span class="stat-value">{self.stats['logins_failed']}</span></div>
                <div class="stat-item">Páginas servidas: <span class="stat-value">{self.stats['pages_served']}</span></div>
                <div class="stat-item">IPs bloqueadas (intentos): <span class="stat-value">{len(self.login_attempts)}</span></div>
            </div>
            <p><a href="/">Volver al portal</a></p>
        </body>
        </html>
        """
        return self._create_http_response(200, "OK", status_html)
    
    def get_stats(self) -> dict:
        """Obtiene estadísticas del servidor HTTP"""
        return self.stats.copy()