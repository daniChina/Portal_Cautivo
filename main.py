# main.py
#!/usr/bin/env python3
"""
Captive Portal - Main Application
"""
import os
import sys
import signal
import threading
import time

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from Core.http_server import CaptivePortalServer
from Core.session_manager import SessionManager
from Core.auth_manager import AuthManager
from Core.firewall_manager import FirewallManager
from Utils.logger import get_logger
from Utils.config import CONFIG, SERVER_PORT, GATEWAY_IP, OUTGOING_INTERFACE, SESSION_TIMEOUT

logger = get_logger()

class CaptivePortal:
    """Main captive portal class"""
    
    def __init__(self):
        self.running = True
        self.server = None
        self.session_manager = SessionManager(session_timeout=SESSION_TIMEOUT)
        self.auth_manager = AuthManager()
        self.firewall_manager = FirewallManager(
            outgoing_interface=OUTGOING_INTERFACE,
            gateway_ip=GATEWAY_IP
        )
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Handle termination signals"""
        logger.info(f"Received signal {signum}, terminating...")
        self.stop()
    
    def maintenance_task(self):
        """Perform periodic maintenance tasks"""
        while self.running:
            time.sleep(300)  # 5 minutes
            try:
                expired = self.session_manager.cleanup_expired_sessions()
                if expired:
                    for ip in expired:
                        self.firewall_manager.revoke_access(ip)
                    logger.info(f"Cleanup: {len(expired)} expired sessions")
            except Exception as e:
                logger.error(f"Error in maintenance: {e}")
    
    def start(self):
        """Start the captive portal"""
        try:
            self.verify_directories()
            
            # Display system information
            self.show_banner()
            
            # Configure firewall
            logger.info("Configuring firewall rules...")
            if not self.firewall_manager.initialize():
                logger.warning("Failed to configure firewall")
            
            # Start maintenance thread
            maintenance_thread = threading.Thread(target=self.maintenance_task, daemon=True)
            maintenance_thread.start()
            
            # Start web server
            logger.info("Starting web server...")
            self.server = CaptivePortalServer(
                host='0.0.0.0',
                port=SERVER_PORT,
                auth_manager=self.auth_manager,
                session_manager=self.session_manager,
                firewall_manager=self.firewall_manager
            )
            self.server.start()
            
        except Exception as e:
            logger.error(f"Error starting: {e}")
            self.stop()
            sys.exit(1)
    
    def stop(self):
        """Stop the captive portal"""
        logger.info("Stopping captive portal...")
        self.running = False
        
        if self.server:
            self.server.stop()
        
        # Clean up firewall rules
        self.firewall_manager.cleanup()
        
        logger.info("Portal stopped successfully")
    
    def verify_directories(self):
        """Verify necessary directories exist"""
        directories = [
            'data',
            'data/logs',
            'static',
            'Web/Templates',
            'Web/Static',
            'Core',
            'Utils',
            'firewall'
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def show_banner(self):
        """Display system banner"""
        banner = f"""
        ╔══════════════════════════════════════════════════════╗
        ║          CAPTIVE PORTAL - ACCESS SYSTEM             ║
        ║               Version {CONFIG['version']}                          ║
        ╚══════════════════════════════════════════════════════╝
        
        Portal Name: {CONFIG['portal_name']}
        Gateway IP:  {CONFIG['gateway_ip']}
        Server Port: {CONFIG['server_port']}
        """
        print(banner)

def main():
    """Main execution function"""
    # Check operating system
    if not sys.platform.startswith('linux'):
        print("❌ This system only works on Linux")
        sys.exit(1)
    
    # Check Python version
    if sys.version_info < (3, 6):
        print("❌ Python 3.6 or higher required")
        sys.exit(1)
    
    # Create and start portal
    portal = CaptivePortal()
    
    try:
        portal.start()
    except KeyboardInterrupt:
        portal.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        portal.stop()
        sys.exit(1)

if __name__ == "__main__":
    main()