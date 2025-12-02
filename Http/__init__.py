"""
Módulo HTTP del Portal Cautivo
Servidor web, plantillas y manejadores de rutas
"""

from .http_server import HTTPServer
from .parser_http import HTTPRequest
from .templates import (
    get_login_template,
    get_success_template,
    get_error_template
)
from .http_response import HTTPResponse
from .handlers import RouteHandler, create_default_routes

__all__ = [
    'HTTPServer',
    'HTTPRequest',
    'HTTPResponse',
    'RouteHandler',
    'create_default_routes',
    'get_login_template',
    'get_success_template',
    'get_error_template'
]