# core/http_server.py
"""
Enhanced HTTP server for captive portal with better OS detection
"""
import socket
import threading
import select
import re
import time
import os
import urllib.parse
import http.cookies
from datetime import datetime

from Utils.logger import get_logger
from Utils.config import GATEWAY_IP, SERVER_PORT, PORTAL_NAME, WELCOME_MESSAGE
from Core.auth_manager import AuthManager
from Core.session_manager import SessionManager
from Core.firewall_manager import FirewallManager

logger=get_logger()

class CaptivePortalHandler:
    """Handles captive portal HTTP requests"""
    
    def __init__(self, auth_manager, session_manager, firewall_manager):
        self.auth_manager = auth_manager
        self.session_manager = session_manager
        self.firewall_manager = firewall_manager
        
        # OS Detection endpoints
        self.os_detection_endpoints = {
            # Android - Google Connectivity Check
            '/generate_204': self.handle_android_detection,
            '/gen_204': self.handle_android_detection,
            
            # iOS/macOS - Apple Captive Portal
            '/hotspot-detect.html': self.handle_apple_detection,
            '/library/test/success.html': self.handle_apple_detection,
            
            # Windows - Microsoft Connect Test
            '/connecttest.txt': self.handle_windows_detection,
            '/ncsi.txt': self.handle_windows_detection,
            
            # Firefox - Mozilla Connectivity
            '/success.txt': self.handle_firefox_detection,
        }
    
    def handle_request(self, client_socket, client_address):
        """Handle a client request"""
        try:
            # Set socket timeout to prevent hanging
            client_socket.settimeout(30.0)  # 30 second timeout
            
            data = b''
            headers_complete = False
            
            # Read headers
            while not headers_complete:
                try:
                    part = client_socket.recv(1024)
                    if not part:
                        break
                    data += part
                    if b'\r\n\r\n' in data:  # End of headers
                        headers_complete = True
                        break
                except socket.timeout:
                    logger.warning(f"Timeout reading from {client_address}")
                    break
                except OSError as e:
                    if e.errno == 11:  # Resource temporarily unavailable (EAGAIN)
                        # This shouldn't happen in blocking mode, but handle it anyway
                        import time
                        time.sleep(0.1)
                        continue
                    else:
                        raise
            
            if not data:
                return
            
            # Parse headers to get Content-Length for POST requests
            header_text = data.split(b'\r\n\r\n', 1)[0].decode('utf-8', errors='ignore')
            headers = {}
            for line in header_text.split('\r\n')[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key.lower()] = value
            
            # Read body if Content-Length is specified
            if 'content-length' in headers:
                try:
                    content_length = int(headers['content-length'].strip())
                    logger.debug(f"Content-Length: {content_length}")
                    
                    # Get body already in data
                    if b'\r\n\r\n' in data:
                        existing_body = data.split(b'\r\n\r\n', 1)[1]
                        body_received = len(existing_body)
                    else:
                        existing_body = b''
                        body_received = 0
                    
                    logger.debug(f"Body already received: {body_received} bytes")
                    
                    # Read remaining body data if needed
                    if body_received < content_length:
                        remaining = content_length - body_received
                        logger.debug(f"Reading {remaining} more bytes")
                        
                        while body_received < content_length:
                            try:
                                remaining = content_length - body_received
                                part = client_socket.recv(min(remaining, 4096))
                                if not part:
                                    logger.warning(f"No more data available, expected {remaining} more bytes")
                                    break
                                existing_body += part
                                body_received += len(part)
                            except socket.timeout:
                                logger.warning(f"Timeout reading body from {client_address}")
                                break
                            except OSError as e:
                                if e.errno == 11:  # Resource temporarily unavailable
                                    import time
                                    time.sleep(0.1)
                                    continue
                                else:
                                    raise
                    
                    # Limit body to Content-Length to avoid reading extra data
                    if len(existing_body) > content_length:
                        logger.warning(f"Body longer than Content-Length: {len(existing_body)} > {content_length}")
                        existing_body = existing_body[:content_length]
                    
                    # Combine header and body data
                    if b'\r\n\r\n' in data:
                        data = data.split(b'\r\n\r\n', 1)[0] + b'\r\n\r\n' + existing_body
                    else:
                        data = data + b'\r\n\r\n' + existing_body
                    
                    logger.debug(f"Final body length: {len(existing_body)} bytes")
                except (ValueError, KeyError) as e:
                    logger.warning(f"Error parsing Content-Length: {e}")
                    pass
            
            if data:
                self.process_request(client_socket, client_address, data)
                
        except Exception as e:
            logger.error(f"Error with client {client_address}: {str(e)}")
        finally:
            client_socket.close()
    
    def process_request(self, client_socket, client_address, data):
        """Process an HTTP request"""
        try:
            # Split headers and body
            if b'\r\n\r\n' not in data:
                logger.warning(f"No header-body separator found from {client_address}")
                self.send_error(client_socket, 400, "Invalid request")
                return
            
            header_bytes, body_bytes = data.split(b'\r\n\r\n', 1)
            
            # Decode headers
            try:
                header_text = header_bytes.decode('utf-8', errors='replace')
            except Exception:
                header_text = header_bytes.decode('latin-1', errors='replace')
            
            lines = header_text.split('\r\n')
            
            if not lines:
                logger.warning(f"Empty request from {client_address}")
                self.send_error(client_socket, 400, "Invalid request")
                return
            
            first_line = lines[0].split()
            if len(first_line) < 2:
                logger.warning(f"Invalid first line from {client_address}: {lines[0]}")
                self.send_error(client_socket, 400, "Invalid request")
                return
            
            method = first_line[0]
            path = first_line[1]
            
            # Parse path (remove query string and fragment)
            if '?' in path:
                path = path.split('?')[0]
            if '#' in path:
                path = path.split('#')[0]
            
            logger.debug(f"Request: {method} {path} from {client_address[0]}")
            
            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key.lower()] = value.strip()
            
            # Decode body as text for form data
            body = ''
            if body_bytes:
                # Log raw body bytes (hex) for debugging
                logger.debug(f"Body bytes (hex, first 100): {body_bytes[:100].hex()}")
                try:
                    # Try UTF-8 first, fallback to latin-1 for form data
                    body = body_bytes.decode('utf-8', errors='replace')
                except Exception:
                    body = body_bytes.decode('latin-1', errors='replace')
                logger.debug(f"Body decoded length: {len(body)} chars")
            
            if method == 'GET':
                self.handle_get(client_socket, client_address, path, headers)
            elif method == 'POST':
                self.handle_post(client_socket, client_address, path, headers, body)
            else:
                self.send_error(client_socket, 405, "Method not allowed")
                
        except Exception as e:
            logger.error(f"Error processing request: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            self.send_error(client_socket, 500, "Internal server error")
    
    def handle_get(self, client_socket, client_address, path, headers):
        """Handle GET requests"""
        client_ip = client_address[0]
        logger.info(f"GET request from {client_ip}: {path}")
        
        # Captive portal detection
        if path in self.os_detection_endpoints:
            logger.info(f"Captive portal detection: {path}")
            self.os_detection_endpoints[path](client_socket, client_ip)
            return
        
        # Special pages
        if path == '/logout':
            self.handle_logout(client_socket, headers)
            return
        
        if path == '/success':
            self.serve_success_page(client_socket, headers)
            return
        
        if path == '/status':
            self.serve_status_page(client_socket)
            return
        
        # Static files
        if path.startswith('/static/'):
            logger.info(f"Serving static file: {path}")
            self.serve_static_file(client_socket, path)
            return
        
        # Check for valid session
        session_id = self.get_session_id(headers)
        has_valid_session = False
        
        if session_id:
            session = self.session_manager.get_session(session_id)
            if session and session.get('ip') == client_ip:
                has_valid_session = True
                logger.info(f"Valid session found for {client_ip}")
        
        # Redirect to login if no valid session and trying to access non-root
        if not has_valid_session and path != '/':
            logger.info(f"No valid session, redirecting to login: {path}")
            self.redirect_to_login(client_socket)
            return
        
        # Serve login page
        logger.info(f"Serving login page for {client_ip}")
        self.serve_login_page(client_socket)
    
    def handle_post(self, client_socket, client_address, path, headers, body):
        """Handle POST requests (login)"""
        logger.info(f"POST request to {path} from {client_address[0]}")
        
        # Accept login requests to /, /login, or /api
        if path not in ['/', '/login', '/api']:
            logger.warning(f"POST to unknown path: {path}")
            self.send_error(client_socket, 404, "Not found")
            return
        
        # Check Content-Type - only process form data
        content_type = headers.get('content-type', '').lower()
        if 'application/x-www-form-urlencoded' not in content_type:
            logger.warning(f"POST with unsupported Content-Type: {content_type}")
            self.send_error(client_socket, 400, "Unsupported content type")
            return
        
        # Parse form data - clean up the body
        body = body.strip()
        
        # Check if body looks like form data (should contain = and &)
        # If it's mostly binary/non-printable, reject it
        printable_chars = sum(1 for c in body[:100] if 32 <= ord(c) < 127)
        if len(body) > 0 and printable_chars < len(body[:100]) * 0.5:
            logger.warning(f"POST body appears to be binary/corrupt data, rejecting")
            logger.debug(f"Printable ratio: {printable_chars}/{min(100, len(body))}")
            self.send_error(client_socket, 400, "Invalid request data")
            return
        
        # Remove any trailing null bytes or control characters (but keep = and &)
        body = ''.join(c for c in body if ord(c) >= 32 or c in '\r\n\t=&')
        body = body.strip()
        
        # Handle empty body
        if not body:
            logger.warning("Empty POST body received")
            self.send_error(client_socket, 400, "Empty request body")
            return
        
        # Check if body contains form field indicators
        if '=' not in body:
            logger.warning("POST body does not contain form data (no '=' found)")
            self.send_error(client_socket, 400, "Invalid form data")
            return
        
        # Log raw body for debugging (first 100 chars, safe)
        safe_body_preview = ''.join(c if 32 <= ord(c) < 127 else '.' for c in body[:100])
        logger.debug(f"Body preview (safe): {safe_body_preview}")
        
        try:
            parsed_body = urllib.parse.parse_qs(body, keep_blank_values=True)
            logger.debug(f"Parsed body keys: {list(parsed_body.keys())}")
        except Exception as e:
            logger.error(f"Error parsing body: {e}")
            self.send_error(client_socket, 400, "Invalid request format")
            return
        
        # Check if we have username and password fields
        if 'username' not in parsed_body and 'password' not in parsed_body:
            logger.warning(f"POST body does not contain username/password fields. Keys: {list(parsed_body.keys())}")
            # For /api, silently ignore invalid requests (might be automatic browser requests)
            if path == '/api':
                logger.debug("Ignoring invalid /api request (likely automatic browser request)")
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    '{"status": "ok"}\r\n'
                )
                client_socket.sendall(response.encode())
                return
            else:
                self.send_error(client_socket, 400, "Missing username or password")
                return
        
        username = parsed_body.get('username', [''])[0]
        password = parsed_body.get('password', [''])[0]
        
        logger.info(f"Login attempt - Username: {username[:10]}... (length: {len(username)})")
        
        # Validate input
        if not self.validate_input(username, password):
            logger.warning(f"Invalid input - username: '{username}', password length: {len(password)}")
            self.serve_error_page(client_socket, username, client_address[0])
            return
        
        # Authenticate
        if self.auth_manager.authenticate(username, password):
            # Create session
            session_id = self.session_manager.create_session(
                username=username,
                ip=client_address[0],
                user_agent=headers.get('user-agent', '')
            )
            
            # Allow firewall access
            self.firewall_manager.allow_access(client_address[0])
            
            # Set cookie and redirect
            response = (
                "HTTP/1.1 302 Found\r\n"
                f"Location: /success\r\n"
                f"Set-Cookie: session_id={session_id}; HttpOnly; Path=/; Max-Age=3600\r\n"
                "Cache-Control: no-cache, no-store\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            client_socket.sendall(response.encode())
            
            logger.info(f"Successful login: {username} from {client_address[0]}")
        else:
            # Show login error
            self.serve_error_page(client_socket, username, client_address[0])
    
    def handle_android_detection(self, client_socket, client_ip):
        """Handle Android captive portal detection"""
        response = (
            "HTTP/1.1 302 Found\r\n"
            f"Location: http://{GATEWAY_IP}:{SERVER_PORT}/\r\n"
            "Cache-Control: no-cache, no-store\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        client_socket.sendall(response.encode())
    
    def handle_apple_detection(self, client_socket, client_ip):
        """Handle Apple captive portal detection"""
        logger.info(f"Apple detection from {client_ip}")
        # Try redirect first (some Apple devices prefer this)
        redirect_url = f"http://{GATEWAY_IP}:{SERVER_PORT}/"
        response = (
            "HTTP/1.1 302 Found\r\n"
            f"Location: {redirect_url}\r\n"
            "Cache-Control: no-cache, no-store\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        client_socket.sendall(response.encode())
        logger.info(f"Redirected Apple device to {redirect_url}")
    
    def handle_windows_detection(self, client_socket, client_ip):
        """Handle Windows captive portal detection"""
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Cache-Control: no-cache, no-store\r\n"
            "Connection: close\r\n"
            "\r\n"
            "captive"
        )
        client_socket.sendall(response.encode())
    
    def handle_firefox_detection(self, client_socket, client_ip):
        """Handle Firefox captive portal detection"""
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Cache-Control: no-cache, no-store\r\n"
            "Connection: close\r\n"
            "\r\n"
            "captive"
        )
        client_socket.sendall(response.encode())
    
    def handle_logout(self, client_socket, headers):
        """Handle logout"""
        session_id = self.get_session_id(headers)
        
        if session_id:
            session = self.session_manager.get_session(session_id)
            if session:
                ip = session.get('ip')
                self.firewall_manager.revoke_access(ip)
            
            self.session_manager.delete_session(session_id)
        
        # Redirect to login with expired cookie
        response = (
            "HTTP/1.1 302 Found\r\n"
            "Location: /\r\n"
            "Set-Cookie: session_id=; expires=Thu, 01 Jan 1970 00:00:00 GMT\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        client_socket.sendall(response.encode())
    
    def serve_login_page(self, client_socket):
        """Serve login page"""
        try:
            logger.info("Serving login page")
            with open('Web/Templates/login.html', 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Replace template variables
            content = content.replace('{{portal_name}}', PORTAL_NAME)
            content = content.replace('{{welcome_message}}', WELCOME_MESSAGE)
            
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(content.encode('utf-8'))}\r\n"
                "Cache-Control: no-cache, no-store\r\n"
                "Connection: close\r\n"
                "\r\n"
                f"{content}"
            )
            
            client_socket.sendall(response.encode('utf-8'))
            logger.info("Login page sent successfully")
            
        except FileNotFoundError as e:
            logger.error(f"Login page file not found: {e}")
            self.send_error(client_socket, 404, "Login page not found")
        except Exception as e:
            logger.error(f"Error serving login page: {e}")
            import traceback
            logger.error(traceback.format_exc())
            self.send_error(client_socket, 500, "Internal error")
    
    def serve_success_page(self, client_socket, headers):
        """Serve success page after login"""
        session_id = self.get_session_id(headers)
        session = None
        
        if session_id:
            session = self.session_manager.get_session(session_id)
        
        if not session:
            self.redirect_to_login(client_socket)
            return
        
        try:
            with open('Web/Templates/success.html', 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Format creation time
            created_time = datetime.fromtimestamp(session.get('created', time.time()))
            formatted_time = created_time.strftime('%Y-%m-%d %H:%M:%S')
            
            # Replace template variables
            content = content.replace('{{username}}', session.get('username', 'User'))
            content = content.replace('{{ip}}', session.get('ip', 'Unknown'))
            content = content.replace('{{time}}', formatted_time)
            
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(content)}\r\n"
                "Connection: close\r\n"
                "\r\n"
                f"{content}"
            )
            
            client_socket.sendall(response.encode())
            
        except FileNotFoundError:
            self.send_error(client_socket, 404, "Success page not found")
    
    def serve_error_page(self, client_socket, username, ip):
        """Serve login error page"""
        try:
            with open('Web/Templates/error.html', 'r', encoding='utf-8') as f:
                content = f.read()
            
            content = content.replace('{{username}}', username)
            content = content.replace('{{ip}}', ip)
            
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(content)}\r\n"
                "Connection: close\r\n"
                "\r\n"
                f"{content}"
            )
            
            client_socket.sendall(response.encode())
            
        except FileNotFoundError:
            self.send_error(client_socket, 404, "Error page not found")
    
    def serve_status_page(self, client_socket):
        """Serve system status page"""
        status = self.session_manager.get_statistics()
        
        content = f"""<html>
        <head><title>Portal Status</title></head>
        <body>
            <h1>Portal Status</h1>
            <p><strong>Active Sessions:</strong> {status['active_sessions']}</p>
            <p><strong>Logins Today:</strong> {status['logins_today']}</p>
            <p><strong>Total Sessions:</strong> {status['total_sessions']}</p>
            <p><strong>Session Timeout:</strong> {status['session_timeout']} seconds</p>
        </body>
        </html>"""
        
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            f"Content-Length: {len(content)}\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{content}"
        )
        
        client_socket.sendall(response.encode())
    
    def serve_static_file(self, client_socket, path):
        """Serve static files (CSS, images)"""
        try:
            # Security check
            if '..' in path or not path.startswith('/static/'):
                self.send_error(client_socket, 403, "Access denied")
                return
            
            # Map /static/styles.css to Web/Static/portal.css
            if path == '/static/styles.css':
                file_path = 'Web/Static/portal.css'
            else:
                file_path = path[1:]  # Remove leading slash
            
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Determine content type
            if path.endswith('.css'):
                content_type = 'text/css'
            elif path.endswith('.js'):
                content_type = 'application/javascript'
            elif path.endswith('.png'):
                content_type = 'image/png'
            elif path.endswith('.jpg') or path.endswith('.jpeg'):
                content_type = 'image/jpeg'
            elif path.endswith('.ico'):
                content_type = 'image/x-icon'
            else:
                content_type = 'text/plain'
            
            response = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: {content_type}\r\n"
                f"Content-Length: {len(content)}\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            
            client_socket.sendall(response.encode() + content)
            
        except FileNotFoundError:
            self.send_error(client_socket, 404, "File not found")
        except Exception as e:
            self.send_error(client_socket, 500, "Internal error")
    
    def redirect_to_login(self, client_socket):
        """Redirect to login page"""
        response = (
            "HTTP/1.1 302 Found\r\n"
            "Location: /\r\n"
            "Cache-Control: no-cache, no-store\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        client_socket.sendall(response.encode())
    
    def send_error(self, client_socket, code, message):
        """Send an error response"""
        error_page = f"""<html>
        <head><title>Error {code}</title></head>
        <body>
            <h1>Error {code}</h1>
            <p>{message}</p>
        </body>
        </html>"""
        
        response = (
            f"HTTP/1.1 {code} Error\r\n"
            "Content-Type: text/html\r\n"
            f"Content-Length: {len(error_page)}\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{error_page}"
        )
        
        client_socket.sendall(response.encode())
    
    def get_session_id(self, headers):
        """Extract session_id from headers"""
        cookie_header = headers.get('cookie', '')
        if not cookie_header:
            return None
        
        # Parse cookies
        cookie = http.cookies.SimpleCookie(cookie_header)
        if 'session_id' in cookie:
            return cookie['session_id'].value
        
        return None
    
    def validate_input(self, username, password):
        """Validate user input"""
        if not username or not password:
            return False
        
        # Validate username format
        if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
            return False
        
        # Validate password format
        if len(password) < 6 or len(password) > 50:
            return False
        
        return True

class CaptivePortalServer:
    """HTTP server for captive portal"""
    
    def __init__(self, host='0.0.0.0', port=8080, 
                 auth_manager=None, session_manager=None, firewall_manager=None):
        self.host = host
        self.port = port
        self.auth_manager = auth_manager
        self.session_manager = session_manager
        self.firewall_manager = firewall_manager
        self.server_socket = None
        self.running = False
        self.client_threads = []
        
        self.handler = CaptivePortalHandler(auth_manager, session_manager, firewall_manager)
    
    def start(self):
        """Start the web server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.setblocking(0)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            self.running = True
            
            logger.info(f"Server started on {self.host}:{self.port}")
            logger.info(f"Access: http://{self.host}:{self.port}")
            logger.info("Waiting for connections...\n")
            
            self.main_loop()
            
        except OSError as e:
            if e.errno == 98:  # Address already in use
                logger.error(f"Port {self.port} is already in use!")
                logger.error("This usually means another instance of the portal is running.")
                logger.error(f"\nTo find what's using port {self.port}, run:")
                logger.error(f"  sudo lsof -i :{self.port}")
                logger.error(f"  or")
                logger.error(f"  sudo netstat -tulpn | grep :{self.port}")
                logger.error(f"\nTo kill the process using the port:")
                logger.error(f"  sudo kill -9 <PID>")
                logger.error(f"\nOr change the port in data/config.json")
            else:
                logger.error(f"Error binding to {self.host}:{self.port}: {e}")
            self.stop()
        except Exception as e:
            logger.error(f"Error starting server: {e}")
            self.stop()
    
    def main_loop(self):
        """Main server loop"""
        inputs = [self.server_socket]
        
        while self.running:
            try:
                readable, _, exceptional = select.select(inputs, [], inputs, 1)
                
                for s in readable:
                    if s is self.server_socket:
                        client, address = s.accept()
                        # Set to blocking mode for reading client data
                        client.setblocking(1)
                        
                        thread = threading.Thread(
                            target=self.handler.handle_request,
                            args=(client, address),
                            daemon=True
                        )
                        thread.start()
                        self.client_threads.append(thread)
                
                # Clean up finished threads
                self.client_threads = [t for t in self.client_threads if t.is_alive()]
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
    
    def stop(self):
        """Stop the server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        
        logger.info("Server stopped")