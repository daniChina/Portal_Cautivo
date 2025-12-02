#!/usr/bin/env python3
"""
Servidor HTTP implementado manualmente con sistema de autenticación
"""

import socket
import threading
import time
from typing import Callable, Optional, Dict, Tuple
from .parser_http import HTTPRequest

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
                error_response = self._create_http_response(400, "Bad Request", "Bad Request")
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
        
        # Página principal
        if request.path == '/' and request.method == 'GET':
            if is_authenticated:
                return self._create_success_page(request.client_ip)
            else:
                return self._create_login_page()
        
        # Procesar login
        elif request.path == '/login' and request.method == 'POST':
            return self._handle_login(request)
        
        # Logout
        elif request.path == '/logout' and request.method == 'GET':
            return self._handle_logout(request.client_ip)
        
        # Cualquier otra ruta
        else:
            if is_authenticated:
                return self._create_success_page(request.client_ip)
            else:
                return self._create_login_page("Para acceder a esta página, primero inicie sesión")
    
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
            return self._create_login_page("Demasiados intentos fallidos. Espere 15 minutos.")
        
        # Extraer credenciales del formulario
        form_data = request.get_form_data()
        username = form_data.get('username', '')
        password = form_data.get('password', '')
        
        # Verificar credenciales
        if self.auth_verify_callback and self.auth_verify_callback(username, password, client_ip):
            # Login exitoso
            self.login_attempts[client_ip] = (0, now)  # Resetear intentos
            self.stats['logins_success'] += 1
            
            # Ejecutar callback de éxito
            if self.on_login_success:
                self.on_login_success(client_ip, username)
            
            return self._create_success_page(client_ip, username)
        else:
            # Login fallido
            attempts += 1
            self.login_attempts[client_ip] = (attempts, now)
            self.stats['logins_failed'] += 1
            
            return self._create_login_page("Usuario o contraseña incorrectos")
    
    def _handle_logout(self, client_ip: str) -> bytes:
        """Maneja el logout"""
        if self.on_logout:
            self.on_logout(client_ip)
        
        return self._create_login_page("Sesión cerrada exitosamente")
    
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
    
    def _create_login_page(self, error_message: str = "") -> bytes:
        """Genera la página de login HTML"""
        error_html = ""
        if error_message:
            error_html = f'''
            <div class="error-message">
                <div class="error-icon">⚠</div>
                <div class="error-text">{error_message}</div>
            </div>
            '''
        
        html = f'''
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Portal Cautivo - Autenticación</title>
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}
                
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    padding: 20px;
                }}
                
                .login-container {{
                    background: white;
                    border-radius: 20px;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                    width: 100%;
                    max-width: 400px;
                    overflow: hidden;
                }}
                
                .login-header {{
                    background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
                    color: white;
                    padding: 40px 30px;
                    text-align: center;
                }}
                
                .login-header h1 {{
                    font-size: 28px;
                    margin-bottom: 10px;
                    font-weight: 600;
                }}
                
                .login-header p {{
                    opacity: 0.9;
                    font-size: 14px;
                }}
                
                .login-content {{
                    padding: 40px 30px;
                }}
                
                {error_html and '''
                .error-message {{
                    background: #fee;
                    border: 1px solid #f99;
                    border-radius: 10px;
                    padding: 15px;
                    margin-bottom: 25px;
                    display: flex;
                    align-items: center;
                    animation: shake 0.5s;
                }}
                
                .error-icon {{
                    font-size: 24px;
                    margin-right: 12px;
                    color: #e53e3e;
                }}
                
                .error-text {{
                    color: #c53030;
                    font-size: 14px;
                }}
                
                @keyframes shake {{
                    0%, 100% {{ transform: translateX(0); }}
                    10%, 30%, 50%, 70%, 90% {{ transform: translateX(-5px); }}
                    20%, 40%, 60%, 80% {{ transform: translateX(5px); }}
                }}
                ''' or ''}
                
                .form-group {{
                    margin-bottom: 25px;
                }}
                
                .form-group label {{
                    display: block;
                    margin-bottom: 8px;
                    color: #4a5568;
                    font-weight: 500;
                    font-size: 14px;
                }}
                
                .form-group input {{
                    width: 100%;
                    padding: 15px;
                    border: 2px solid #e2e8f0;
                    border-radius: 10px;
                    font-size: 16px;
                    transition: all 0.3s;
                }}
                
                .form-group input:focus {{
                    outline: none;
                    border-color: #667eea;
                    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
                }}
                
                .login-button {{
                    width: 100%;
                    padding: 16px;
                    background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
                    color: white;
                    border: none;
                    border-radius: 10px;
                    font-size: 16px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: transform 0.2s, box-shadow 0.2s;
                }}
                
                .login-button:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
                }}
                
                .login-button:active {{
                    transform: translateY(0);
                }}
                
                .login-footer {{
                    text-align: center;
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #e2e8f0;
                    color: #718096;
                    font-size: 12px;
                }}
                
                @media (max-width: 480px) {{
                    .login-container {{
                        max-width: 100%;
                    }}
                    
                    .login-header, .login-content {{
                        padding: 30px 20px;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="login-container">
                <div class="login-header">
                    <h1>🔐 Portal Cautivo</h1>
                    <p>Autenticación requerida para acceder a Internet</p>
                </div>
                
                <div class="login-content">
                    {error_html}
                    
                    <form method="POST" action="/login">
                        <div class="form-group">
                            <label for="username">Usuario</label>
                            <input type="text" id="username" name="username" 
                                   placeholder="usuario@empresa.com" required autofocus>
                        </div>
                        
                        <div class="form-group">
                            <label for="password">Contraseña</label>
                            <input type="password" id="password" name="password" 
                                   placeholder="Ingrese su contraseña" required>
                        </div>
                        
                        <button type="submit" class="login-button">Iniciar Sesión</button>
                    </form>
                    
                    <div class="login-footer">
                        <p>Sistema de Portal Cautivo v1.0</p>
                        <p>© 2024 - Todos los derechos reservados</p>
                    </div>
                </div>
            </div>
            
            <script>
                // Auto-focus en el campo de usuario
                document.getElementById('username').focus();
                
                // Validación básica del formulario
                document.querySelector('form').addEventListener('submit', function(e) {{
                    const username = document.getElementById('username').value.trim();
                    const password = document.getElementById('password').value.trim();
                    
                    if (!username || !password) {{
                        e.preventDefault();
                        alert('Por favor, complete todos los campos');
                        return false;
                    }}
                    
                    // Muestra un indicador de carga
                    const button = this.querySelector('button[type="submit"]');
                    const originalText = button.textContent;
                    button.textContent = 'Autenticando...';
                    button.disabled = true;
                    
                    // Restaurar después de 3 segundos (por si hay error)
                    setTimeout(() => {{
                        button.textContent = originalText;
                        button.disabled = false;
                    }}, 3000);
                }});
            </script>
        </body>
        </html>
        '''
        
        return self._create_http_response(200, "OK", html)
    
    def _create_success_page(self, client_ip: str, username: str = "Usuario") -> bytes:
        """Genera la página de éxito después del login"""
        html = f'''
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Acceso Concedido</title>
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}
                
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #10b981 0%, #34d399 100%);
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    padding: 20px;
                }}
                
                .success-container {{
                    background: white;
                    border-radius: 20px;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                    width: 100%;
                    max-width: 450px;
                    overflow: hidden;
                    text-align: center;
                    animation: fadeIn 0.5s ease-out;
                }}
                
                .success-header {{
                    background: linear-gradient(135deg, #059669 0%, #10b981 100%);
                    color: white;
                    padding: 50px 30px;
                }}
                
                .success-icon {{
                    font-size: 80px;
                    margin-bottom: 20px;
                    animation: bounce 1s;
                }}
                
                .success-header h1 {{
                    font-size: 32px;
                    margin-bottom: 10px;
                    font-weight: 600;
                }}
                
                .success-header p {{
                    opacity: 0.9;
                    font-size: 16px;
                }}
                
                .success-content {{
                    padding: 40px 30px;
                }}
                
                .user-info {{
                    background: #f0f9ff;
                    border-radius: 10px;
                    padding: 20px;
                    margin-bottom: 30px;
                }}
                
                .user-info p {{
                    margin: 8px 0;
                    color: #4a5568;
                }}
                
                .highlight {{
                    color: #059669;
                    font-weight: 600;
                    font-size: 18px;
                }}
                
                .instructions {{
                    background: #f7fafc;
                    border-radius: 10px;
                    padding: 20px;
                    margin-bottom: 30px;
                    text-align: left;
                }}
                
                .instructions h3 {{
                    color: #4a5568;
                    margin-bottom: 15px;
                    font-size: 16px;
                }}
                
                .instructions ul {{
                    list-style: none;
                    padding-left: 0;
                }}
                
                .instructions li {{
                    padding: 8px 0;
                    color: #718096;
                    position: relative;
                    padding-left: 25px;
                }}
                
                .instructions li:before {{
                    content: "✓";
                    color: #10b981;
                    font-weight: bold;
                    position: absolute;
                    left: 0;
                }}
                
                .countdown {{
                    background: linear-gradient(135deg, #f59e0b 0%, #fbbf24 100%);
                    color: white;
                    padding: 15px;
                    border-radius: 10px;
                    margin-top: 20px;
                    font-size: 14px;
                }}
                
                @keyframes fadeIn {{
                    from {{ opacity: 0; transform: translateY(20px); }}
                    to {{ opacity: 1; transform: translateY(0); }}
                }}
                
                @keyframes bounce {{
                    0%, 20%, 50%, 80%, 100% {{ transform: translateY(0); }}
                    40% {{ transform: translateY(-20px); }}
                    60% {{ transform: translateY(-10px); }}
                }}
                
                @media (max-width: 480px) {{
                    .success-container {{
                        max-width: 100%;
                    }}
                    
                    .success-header, .success-content {{
                        padding: 30px 20px;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="success-container">
                <div class="success-header">
                    <div class="success-icon">✅</div>
                    <h1>¡Acceso Concedido!</h1>
                    <p>Autenticación exitosa</p>
                </div>
                
                <div class="success-content">
                    <div class="user-info">
                        <p>Bienvenido, <span class="highlight">{username}</span></p>
                        <p>Dirección IP: <span class="highlight">{client_ip}</span></p>
                        <p>Hora de acceso: <span class="highlight" id="access-time"></span></p>
                    </div>
                    
                    <div class="instructions">
                        <h3>Ahora puede:</h3>
                        <ul>
                            <li>Navegar libremente por Internet</li>
                            <li>Acceder a cualquier sitio web</li>
                            <li>Usar servicios en línea</li>
                            <li>Descargar contenido</li>
                        </ul>
                    </div>
                    
                    <div class="countdown" id="countdown">
                        Redirigiendo a Internet en <span id="seconds">5</span> segundos...
                    </div>
                    
                    <p style="margin-top: 20px; color: #718096; font-size: 12px;">
                        Puede cerrar esta ventana y continuar navegando normalmente.
                    </p>
                </div>
            </div>
            
            <script>
                // Mostrar hora actual
                const now = new Date();
                document.getElementById('access-time').textContent = 
                    now.toLocaleTimeString() + ' - ' + now.toLocaleDateString();
                
                // Contador regresivo y redirección
                let seconds = 5;
                const countdownElement = document.getElementById('seconds');
                
                function updateCountdown() {{
                    seconds--;
                    countdownElement.textContent = seconds;
                    
                    if (seconds <= 0) {{
                        // Redirigir a Google
                        window.location.href = 'https://www.google.com';
                    }} else {{
                        setTimeout(updateCountdown, 1000);
                    }}
                }}
                
                // Iniciar contador
                setTimeout(updateCountdown, 1000);
                
                // Permitir redirección manual con clic en cualquier parte
                document.body.addEventListener('click', function() {{
                    window.location.href = 'https://www.google.com';
                }});
            </script>
        </body>
        </html>
        '''
        
        return self._create_http_response(200, "OK", html)
    
    def get_stats(self) -> dict:
        """Obtiene estadísticas del servidor HTTP"""
        return self.stats.copy()