#!/usr/bin/env python3
"""
Setup WiFi hotspot for captive portal
"""
import sys
import os
import subprocess
import time

# Add main directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Utils.data_handler import load_json
from Utils.logger import get_logger

def run_command(command):
    """Run a system command"""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, '', str(e)

def check_root():
    """Check if running as root"""
    return os.geteuid() == 0

def setup_hotspot():
    """Setup WiFi hotspot"""
    print("\n" + "="*60)
    print("WI-FI HOTSPOT CONFIGURATION")
    print("="*60)
    
    if not check_root():
        print("\n❌ This script must be run as root")
        print("   Run: sudo python setup.py\n")
        sys.exit(1)
    
    # Load configuration
    config = load_json('data/config.json')
    
    wifi_interface = config.get('wifi_interface', 'wlan0')
    ssid = config.get('hotspot_ssid', 'CaptivePortal')
    password = config.get('hotspot_password', 'portal123456')
    gateway_ip = config.get('gateway_ip', '10.42.0.1')
    
    print(f"\n📶 Configuring hotspot:")
    print(f"   Interface: {wifi_interface}")
    print(f"   SSID: {ssid}")
    print(f"   Password: {password}")
    print(f"   Gateway: {gateway_ip}")
    
    # Stop interfering services
    print("\n🛑 Stopping network services...")
    run_command('systemctl stop NetworkManager 2>/dev/null || true')
    run_command('systemctl stop wpa_supplicant 2>/dev/null || true')
    time.sleep(2)
    
    # Configure interface
    print(f"\n🔧 Configuring interface {wifi_interface}...")
    
    # Bring interface down
    run_command(f'ip link set {wifi_interface} down')
    
    # Change to AP mode
    run_command(f'iw dev {wifi_interface} set type __ap 2>/dev/null || iw dev {wifi_interface} set type ap')
    
    # Set static IP
    run_command(f'ip addr add {gateway_ip}/24 dev {wifi_interface}')
    
    # Bring interface up
    run_command(f'ip link set {wifi_interface} up')
    
    # Configure hostapd
    print("\n📡 Configuring hostapd...")
    hostapd_config = f"""interface={wifi_interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""
    
    with open('/tmp/hostapd.conf', 'w') as f:
        f.write(hostapd_config)
    
    # Configure dnsmasq
    print("🌐 Configuring dnsmasq...")
    dnsmasq_config = f"""interface={wifi_interface}
dhcp-range={gateway_ip.replace('.1', '.100')},{gateway_ip.replace('.1', '.200')},12h
dhcp-option=3,{gateway_ip}
dhcp-option=6,{gateway_ip}
address=/#/{gateway_ip}
"""
    
    with open('/tmp/dnsmasq.conf', 'w') as f:
        f.write(dnsmasq_config)
    
    # Enable IP forwarding
    print("🔗 Enabling IP forwarding...")
    run_command('sysctl -w net.ipv4.ip_forward=1')
    run_command('echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf')
    
    # Start services
    print("\n🚀 Starting services...")
    
    # Stop dnsmasq if running
    run_command('pkill dnsmasq 2>/dev/null || true')
    run_command('pkill hostapd 2>/dev/null || true')
    time.sleep(1)
    
    # Start dnsmasq
    success, output, error = run_command('dnsmasq -C /tmp/dnsmasq.conf')
    if success:
        print("✅ dnsmasq started")
    else:
        print(f"❌ dnsmasq error: {error}")
    
    # Start hostapd
    success, output, error = run_command(f'hostapd /tmp/hostapd.conf -B')
    if success:
        print("✅ hostapd started")
    else:
        print(f"❌ hostapd error: {error}")
    
    # Configure NAT
    print("\n🌍 Configuring NAT...")
    outgoing_interface = config.get('outgoing_interface', 'eth0')
    
    nat_command = (
        f'iptables -t nat -A POSTROUTING -o {outgoing_interface} -j MASQUERADE && '
        f'iptables -A FORWARD -i {wifi_interface} -o {outgoing_interface} -j ACCEPT && '
        f'iptables -A FORWARD -i {outgoing_interface} -o {wifi_interface} -m state --state RELATED,ESTABLISHED -j ACCEPT'
    )
    
    success, output, error = run_command(nat_command)
    if success:
        print("✅ NAT configured")
    else:
        print(f"❌ NAT error: {error}")
    
    # Show summary
    print("\n" + "="*60)
    print("✅ HOTSPOT CONFIGURED SUCCESSFULLY")
    print("="*60)
    print(f"\n📶 WiFi Network: {ssid}")
    print(f"🔐 Password: {password}")
    print(f"🌐 Gateway: {gateway_ip}")
    print(f"🔧 Interface: {wifi_interface}")
    print("\n📱 To connect:")
    print(f"   1. Look for network '{ssid}' on your device")
    print(f"   2. Connect with password '{password}'")
    print(f"   3. Open any webpage to access the portal")
    print("\n🛑 To stop: sudo python restore_network.py")
    print("="*60)
    
    # Log
    logger = get_logger()
    logger.log(f"Hotspot configured: {ssid} on {wifi_interface}", level='SUCCESS')
    
    return True

if __name__ == "__main__":
    try:
        setup_hotspot()
    except KeyboardInterrupt:
        print("\n\n❌ Configuration cancelled")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)