"""
Módulo HTTP del Portal Cautivo
Servidor web, plantillas y manejadores de rutas
"""

from Http.http_server import HTTPServer
from Http.parser_http import HTTPRequest
from Http.templates import (
    get_login_template,
    get_success_template,
    get_error_template
)
from Http.http_response import HTTPResponse
from Http.handlers import RouteHandler, create_default_routes

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