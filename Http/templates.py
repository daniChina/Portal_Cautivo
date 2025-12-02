#!/usr/bin/env python3
"""
Plantillas HTML para el portal cautivo
Separadas del servidor para mejor mantenimiento
"""

def get_login_template(error_message: str = "") -> str:
    """Genera la plantilla de login HTML"""
    error_html = ""
    if error_message:
        error_html = f'''
        <div class="error-message">
            <div class="error-icon">⚠</div>
            <div class="error-text">{error_message}</div>
        </div>
        '''
    
    return f'''
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


def get_success_template(client_ip: str, username: str = "Usuario") -> str:
    """Genera la plantilla de éxito después del login"""
    return f'''
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


def get_error_template(status_code: int, message: str = "") -> str:
    """Genera plantilla de error HTTP"""
    status_messages = {
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        500: "Internal Server Error"
    }
    
    status_text = status_messages.get(status_code, "Error")
    
    return f'''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{status_code} - {status_text}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                text-align: center;
                padding: 50px;
                background: #f8f9fa;
            }}
            .error-container {{
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
                display: inline-block;
            }}
            .error-code {{
                font-size: 72px;
                color: #dc3545;
                margin: 0;
            }}
            .error-message {{
                font-size: 24px;
                margin: 20px 0;
                color: #343a40;
            }}
            .details {{
                color: #6c757d;
                margin-top: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="error-container">
            <h1 class="error-code">{status_code}</h1>
            <h2 class="error-message">{status_text}</h2>
            {f'<p class="details">{message}</p>' if message else ''}
            <p><a href="/">Volver al portal</a></p>
        </div>
    </body>
    </html>
    '''