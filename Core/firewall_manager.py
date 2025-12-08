# firewall/firewall_manager.py
"""
Firewall controller using iptables
"""
import subprocess
import re

from Utils.logger import get_logger

logger=get_logger()  

class FirewallManager:
    """Controls firewall rules using iptables"""
    
    def __init__(self, outgoing_interface='eth0', gateway_ip='10.42.0.1'):
        self.outgoing_interface = outgoing_interface
        self.gateway_ip = gateway_ip
        self.active_rules = set()
  
    
    def execute_command(self, command):
        """Execute a system command"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            success = result.returncode == 0
            if not success:
                logger.debug(f"Command failed: {command}")
                if result.stderr:
                    logger.debug(f"Error output: {result.stderr.strip()}")
            return success, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            logger.error(f"Command timeout: {command}")
            return False, '', "Timeout"
        except Exception as error:
            logger.error(f"Command exception: {command} - {str(error)}")
            return False, '', str(error)
    
    def initialize(self):
        """Initialize firewall rules"""
        import os
        
        logger.info("Initializing firewall...")
        
        # Check if running as root
        if os.geteuid() != 0:
            logger.error("Firewall requires root privileges. Please run with sudo.")
            logger.error("Example: sudo python3 main.py")
            return False
        
        # Check if iptables is available
        success, stdout, stderr = self.execute_command('which iptables')
        if not success:
            logger.error("iptables not found. Please install iptables.")
            logger.error("On Debian/Ubuntu: sudo apt-get install iptables")
            return False
        
        # Enable IP forwarding
        success, stdout, stderr = self.execute_command('sysctl -w net.ipv4.ip_forward=1')
        if not success:
            logger.warning(f"Failed to enable IP forwarding: {stderr.strip()}")
        else:
            logger.info("IP forwarding enabled")
        
        # Flush existing rules
        self.execute_command('iptables -F')
        self.execute_command('iptables -t nat -F')
        logger.info("Existing firewall rules flushed")
        
        # Set default policies
        self.execute_command('iptables -P INPUT ACCEPT')
        self.execute_command('iptables -P FORWARD DROP')  # Block forwarding by default
        self.execute_command('iptables -P OUTPUT ACCEPT')
        
        # Allow local traffic
        self.execute_command('iptables -A INPUT -i lo -j ACCEPT')
        
        # Allow established traffic
        self.execute_command('iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT')
        self.execute_command('iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT')
        
        # Allow DNS
        self.execute_command('iptables -A INPUT -p udp --dport 53 -j ACCEPT')
        self.execute_command('iptables -A INPUT -p tcp --dport 53 -j ACCEPT')
        
        # Allow DHCP
        self.execute_command('iptables -A INPUT -p udp --dport 67:68 -j ACCEPT')
        
        # Redirect HTTP to portal (port 80 to 8080)
        success, stdout, stderr = self.execute_command(
            f'iptables -t nat -A PREROUTING -p tcp --dport 80 '
            f'-j REDIRECT --to-port 8080'
        )
        
        if success:
            self.active_rules.add('REDIRECT_HTTP')
            logger.info("HTTP redirect to port 8080 configured")
        else:
            logger.error(f"Failed to configure HTTP redirect: {stderr.strip()}")
        
        # Allow inbound HTTP to portal
        self.execute_command('iptables -A INPUT -p tcp --dport 8080 -j ACCEPT')
        self.execute_command('iptables -A INPUT -p tcp --dport 80 -j ACCEPT')
        
        # Configure NAT for internet access
        success, stdout, stderr = self.execute_command(
            f'iptables -t nat -A POSTROUTING -o {self.outgoing_interface} -j MASQUERADE'
        )
        
        if success:
            self.active_rules.add('NAT_MASQUERADE')
            logger.info(f"NAT configured on {self.outgoing_interface}")
        else:
            logger.error(f"Failed to configure NAT on {self.outgoing_interface}: {stderr.strip()}")
            logger.error(f"Please verify that interface '{self.outgoing_interface}' exists")
            logger.error("You can check interfaces with: ip link show")
        
        if len(self.active_rules) == 0:
            logger.error("No firewall rules were configured successfully!")
            logger.error("Check the errors above for details.")
        else:
            logger.info(f"Firewall initialized with {len(self.active_rules)} active rules")
        
        return len(self.active_rules) > 0
    
    def allow_access(self, client_ip):
        """Allow internet access for a specific IP"""
        # Allow forwarding from the IP
        success, stdout, stderr = self.execute_command(
            f'iptables -I FORWARD 1 -s {client_ip} -j ACCEPT'
        )
        
        if success:
            self.active_rules.add(f'ALLOW_{client_ip}')
            logger.info(f"Access allowed for IP: {client_ip}")
            return True
        else:
            logger.error(f"Failed to allow access for {client_ip}: {stderr}")
            return False
    
    def revoke_access(self, client_ip):
        """Revoke internet access for a specific IP"""
        # Remove forwarding rule
        self.execute_command(f'iptables -D FORWARD -s {client_ip} -j ACCEPT')
        
        # Remove from active rules
        rule = f'ALLOW_{client_ip}'
        if rule in self.active_rules:
            self.active_rules.remove(rule)
        
        logger.info(f"Access revoked for IP: {client_ip}")
        return True
    
    def list_rules(self):
        """List active iptables rules"""
        success, stdout, stderr = self.execute_command('iptables -L -n -v')
        if success:
            return stdout
        return stderr
    
    def cleanup(self):
        """Clean up all firewall rules"""
        self.execute_command('iptables -F')
        self.execute_command('iptables -t nat -F')
        self.execute_command('iptables -X')
        self.active_rules.clear()
        
        # Restore default policies
        self.execute_command('iptables -P INPUT ACCEPT')
        self.execute_command('iptables -P FORWARD ACCEPT')
        self.execute_command('iptables -P OUTPUT ACCEPT')
        
        logger.info("Firewall rules cleaned up")
        return True
    
    def get_status(self):
        """Get firewall status"""
        return {
            'active_rules': list(self.active_rules),
            'outgoing_interface': self.outgoing_interface,
            'gateway_ip': self.gateway_ip,
            'total_rules': len(self.active_rules)
        }