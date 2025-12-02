#!/usr/bin/env python3
"""
Manejadores de rutas HTTP para el portal
Puede extenderse fácilmente para agregar nuevas rutas
"""

from typing import Callable, Dict, Any
from .parser_http import HTTPRequest

class RouteHandler:
    """Manejador de rutas HTTP"""
    
    def __init__(self):
        self.routes: Dict[str, Dict[str, Callable]] = {
            'GET': {},
            'POST': {},
            'PUT': {},
            'DELETE': {},
            'PATCH': {}
        }
    
    def add_route(self, method: str, path: str, handler: Callable):
        """Añade una nueva ruta"""
        if method.upper() in self.routes:
            self.routes[method.upper()][path] = handler
    
    def get_handler(self, method: str, path: str) -> Callable:
        """Obtiene el manejador para una ruta"""
        method = method.upper()
        if method in self.routes:
            # Buscar coincidencia exacta
            if path in self.routes[method]:
                return self.routes[method][path]
            
            # Buscar coincidencias con parámetros (simple)
            for route_path, handler in self.routes[method].items():
                if '<' in route_path and '>' in route_path:
                    # Ruta con parámetros simple (ej: /user/<id>)
                    route_parts = route_path.split('/')
                    request_parts = path.split('/')
                    
                    if len(route_parts) == len(request_parts):
                        params = {}
                        match = True
                        
                        for i in range(len(route_parts)):
                            if route_parts[i].startswith('<') and route_parts[i].endswith('>'):
                                param_name = route_parts[i][1:-1]
                                params[param_name] = request_parts[i]
                            elif route_parts[i] != request_parts[i]:
                                match = False
                                break
                        
                        if match:
                            # Crear un wrapper que inyecte los parámetros
                            def wrapper_handler(request: HTTPRequest, **kwargs):
                                return handler(request, **kwargs)
                            return lambda req: wrapper_handler(req, **params)
        
        # Si no encuentra, retorna None
        return None
    
    def handle_request(self, request: HTTPRequest) -> Any:
        """Maneja una petición usando las rutas registradas"""
        handler = self.get_handler(request.method, request.path)
        if handler:
            return handler(request)
        else:
            # Ruta no encontrada
            return None

# Ejemplo de uso:
def create_default_routes(auth_check_callback: Callable, 
                         auth_verify_callback: Callable) -> RouteHandler:
    """Crea las rutas por defecto del portal"""
    from .templates import get_login_template, get_success_template
    from .http_response import HTTPResponse
    
    handler = RouteHandler()
    
    # Ruta: GET /
    def home_handler(request: HTTPRequest):
        if auth_check_callback(request.client_ip):
            return HTTPResponse.html(get_success_template(request.client_ip))
        else:
            return HTTPResponse.html(get_login_template())
    
    # Ruta: POST /login
    def login_handler(request: HTTPRequest):
        # Extraer datos del formulario
        form_data = request.get_form_data()
        username = form_data.get('username', '')
        password = form_data.get('password', '')
        
        if auth_verify_callback(username, password, request.client_ip):
            return HTTPResponse.html(get_success_template(request.client_ip, username))
        else:
            return HTTPResponse.html(get_login_template("Credenciales incorrectas"))
    
    # Ruta: GET /status
    def status_handler(request: HTTPRequest):
        html = "<h1>Estado del sistema</h1><p>Portal funcionando correctamente</p>"
        return HTTPResponse.html(html)
    
    # Registrar rutas
    handler.add_route('GET', '/', home_handler)
    handler.add_route('POST', '/login', login_handler)
    handler.add_route('GET', '/status', status_handler)
    
    return handler