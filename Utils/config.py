# utils/config.py
"""
Configuration module
"""
import json

def load_config(config_path='data/config.json'):
    """Load configuration from JSON file"""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        # Default configuration
        return {
            'portal_name': 'Captive Portal',
            'welcome_message': 'Please log in to access the Internet',
            'gateway_ip': '10.42.0.1',
            'server_port': 8080,
            'outgoing_interface': 'eth0',
            'wifi_interface': 'wlan0',
            'hotspot_ssid': 'CaptivePortal',
            'hotspot_password': 'portal123456',
            'session_timeout': 3600,
            'max_login_attempts': 5,
            'block_time': 900,
            'enable_logging': True,
            'version': '1.0.0'
        }

# Load configuration
CONFIG = load_config()

# Export commonly used values
PORTAL_NAME = CONFIG['portal_name']
WELCOME_MESSAGE = CONFIG['welcome_message']
GATEWAY_IP = CONFIG['gateway_ip']
SERVER_PORT = CONFIG['server_port']
OUTGOING_INTERFACE = CONFIG['outgoing_interface']
WIFI_INTERFACE = CONFIG['wifi_interface']
HOTSPOT_SSID = CONFIG['hotspot_ssid']
HOTSPOT_PASSWORD = CONFIG['hotspot_password']
SESSION_TIMEOUT = CONFIG['session_timeout']
MAX_LOGIN_ATTEMPTS = CONFIG['max_login_attempts']
BLOCK_TIME = CONFIG['block_time']
ENABLE_LOGGING = CONFIG['enable_logging']
VERSION = CONFIG['version']