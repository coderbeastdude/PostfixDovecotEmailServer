#!/bin/bash

# Script to set up WireGuard VPN for secure administrative access
# Part of the email server setup automation

set -euo pipefail

# Load configuration
source ../email-server-config.conf

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if VPN is enabled
check_vpn_enabled() {
    if [[ "$ENABLE_VPN" != "true" ]]; then
        print_warning "VPN is not enabled in configuration. Skipping WireGuard setup."
        exit 0
    fi
}

# Function to install WireGuard
install_wireguard() {
    print_info "Installing WireGuard..."
    
    # Check if already installed
    if command -v wg &> /dev/null; then
        print_info "WireGuard is already installed"
        return 0
    fi
    
    # Install WireGuard
    apt-get update
    apt-get install -y wireguard wireguard-tools
    
    # Enable IP forwarding
    sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    sed -i 's/#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=1/' /etc/sysctl.conf
    sysctl -p
    
    print_info "WireGuard installed successfully"
}

# Function to generate server keys
generate_server_keys() {
    print_info "Generating WireGuard server keys..."
    
    # Create WireGuard directory if it doesn't exist
    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard
    
    # Generate private and public keys
    wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key
    
    # Set proper permissions
    chmod 600 /etc/wireguard/private.key
    chmod 644 /etc/wireguard/public.key
    
    # Read keys for later use
    SERVER_PRIVATE_KEY=$(cat /etc/wireguard/private.key)
    SERVER_PUBLIC_KEY=$(cat /etc/wireguard/public.key)
    
    print_info "Server keys generated successfully"
}

# Function to generate client keys
generate_client_keys() {
    print_info "Generating client keys..."
    
    # Create client directory
    mkdir -p /etc/wireguard/clients
    chmod 700 /etc/wireguard/clients
    
    # Generate client1 keys
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
    
    # Save client keys
    echo "$CLIENT_PRIVATE_KEY" > /etc/wireguard/clients/client1.key
    echo "$CLIENT_PUBLIC_KEY" > /etc/wireguard/clients/client1.pub
    
    chmod 600 /etc/wireguard/clients/client1.key
    chmod 644 /etc/wireguard/clients/client1.pub
    
    print_info "Client keys generated successfully"
}

# Function to create server configuration
create_server_config() {
    print_info "Creating WireGuard server configuration..."
    
    # Determine network interface
    NET_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    # Create server configuration
    cat << EOF > /etc/wireguard/wg0.conf
[Interface]
Address = $VPN_SERVER_IP/24
ListenPort = 51820
PrivateKey = $SERVER_PRIVATE_KEY
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $NET_INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $NET_INTERFACE -j MASQUERADE
SaveConfig = true

# Client 1 (Admin)
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = 10.0.0.2/32
EOF
    
    chmod 600 /etc/wireguard/wg0.conf
    
    print_info "Server configuration created"
}

# Function to create client configuration
create_client_config() {
    print_info "Creating client configuration..."
    
    # Create client configuration directory
    mkdir -p /etc/email-server/wireguard-clients
    
    # Create client configuration file
    cat << EOF > /etc/email-server/wireguard-clients/client1.conf
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = 10.0.0.2/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $SERVER_IP:51820
PersistentKeepalive = 25
EOF
    
    chmod 600 /etc/email-server/wireguard-clients/client1.conf
    
    # Also create a QR code version
    qrencode -t ansiutf8 < /etc/email-server/wireguard-clients/client1.conf > /etc/email-server/wireguard-clients/client1-qr.txt
    
    print_info "Client configuration created"
}

# Function to configure firewall for WireGuard
configure_wireguard_firewall() {
    print_info "Configuring firewall for WireGuard..."
    
    # Add WireGuard rules to UFW
    ufw allow 51820/udp comment 'WireGuard'
    
    # Add NAT rules
    cat << EOF > /etc/ufw/before.rules.wireguard
# WireGuard NAT rules
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s $VPN_NETWORK -o eth0 -j MASQUERADE
COMMIT

# Don't delete the 'COMMIT' line or these rules won't be processed
*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]

# Allow VPN traffic forwarding
-A ufw-before-forward -i wg0 -j ACCEPT
-A ufw-before-forward -o wg0 -j ACCEPT

# Allow SSH from VPN network only
-A ufw-before-input -s $VPN_NETWORK -p tcp --dport 22 -j ACCEPT

EOF
    
    # Backup and update UFW before.rules
    cp /etc/ufw/before.rules /etc/ufw/before.rules.bak
    
    # Insert WireGuard rules
    sed -i '/^# End required lines/r /etc/ufw/before.rules.wireguard' /etc/ufw/before.rules
    
    # Remove temporary file
    rm /etc/ufw/before.rules.wireguard
    
    print_info "Firewall configured for WireGuard"
}

# Function to restrict SSH to VPN
restrict_ssh_to_vpn() {
    print_info "Restricting SSH access to VPN only..."
    
    # Backup SSH configuration
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
    # Add VPN-only SSH configuration
    cat << EOF >> /etc/ssh/sshd_config

# Restrict SSH to VPN network only
ListenAddress $VPN_SERVER_IP
AllowUsers admin@$VPN_NETWORK
EOF
    
    # Apply new SSH configuration
    systemctl restart sshd
    
    # Update UFW to remove general SSH access
    ufw delete allow 22/tcp 2>/dev/null || true
    ufw allow from $VPN_NETWORK to any port 22 comment 'SSH from VPN'
    
    print_info "SSH access restricted to VPN"
}

# Function to create management scripts
create_management_scripts() {
    print_info "Creating WireGuard management scripts..."
    
    # Create add-client script
    cat << 'EOF' > /usr/local/bin/wireguard-add-client.sh
#!/bin/bash

# Script to add a new WireGuard client
# Usage: wireguard-add-client.sh <client-name>

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <client-name>"
    exit 1
fi

CLIENT_NAME="$1"
CONFIG_FILE="/etc/wireguard/wg0.conf"
CLIENT_DIR="/etc/email-server/wireguard-clients"

# Generate client keys
CLIENT_PRIVATE_KEY=$(wg genkey)
CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)

# Find next available IP
NEXT_IP=$(grep "AllowedIPs" "$CONFIG_FILE" | awk -F'[./]' '{print $1}' | awk '{print $NF}' | sort -n | tail -1)
NEXT_IP=$((NEXT_IP + 1))
CLIENT_IP="10.0.0.$NEXT_IP"

# Add peer to server config
cat >> "$CONFIG_FILE" << EOC

# Client: $CLIENT_NAME
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $CLIENT_IP/32
EOC

# Create client config
mkdir -p "$CLIENT_DIR"
cat > "$CLIENT_DIR/$CLIENT_NAME.conf" << EOC
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = $(cat /etc/wireguard/public.key)
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $(curl -s ipinfo.io/ip):51820
PersistentKeepalive = 25
EOC

# Generate QR code
qrencode -t ansiutf8 < "$CLIENT_DIR/$CLIENT_NAME.conf" > "$CLIENT_DIR/$CLIENT_NAME-qr.txt"

# Restart WireGuard
systemctl restart wg-quick@wg0

echo "Client $CLIENT_NAME added successfully!"
echo "Configuration file: $CLIENT_DIR/$CLIENT_NAME.conf"
echo "QR code: $CLIENT_DIR/$CLIENT_NAME-qr.txt"
EOF
    
    chmod +x /usr/local/bin/wireguard-add-client.sh
    
    # Create remove-client script
    cat << 'EOF' > /usr/local/bin/wireguard-remove-client.sh
#!/bin/bash

# Script to remove a WireGuard client
# Usage: wireguard-remove-client.sh <client-name>

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <client-name>"
    exit 1
fi

CLIENT_NAME="$1"
CONFIG_FILE="/etc/wireguard/wg0.conf"
CLIENT_DIR="/etc/email-server/wireguard-clients"

# Get client public key
if [[ -f "$CLIENT_DIR/$CLIENT_NAME.conf" ]]; then
    CLIENT_PUBLIC_KEY=$(grep "PublicKey" "$CLIENT_DIR/$CLIENT_NAME.conf" | awk '{print $3}')
    
    # Remove peer from server config
    sed -i "/# Client: $CLIENT_NAME/,/^$/d" "$CONFIG_FILE"
    sed -i "/PublicKey = $CLIENT_PUBLIC_KEY/,/^$/d" "$CONFIG_FILE"
    
    # Remove client files
    rm -f "$CLIENT_DIR/$CLIENT_NAME.conf"
    rm -f "$CLIENT_DIR/$CLIENT_NAME-qr.txt"
    
    # Restart WireGuard
    systemctl restart wg-quick@wg0
    
    echo "Client $CLIENT_NAME removed successfully!"
else
    echo "Client $CLIENT_NAME not found!"
    exit 1
fi
EOF
    
    chmod +x /usr/local/bin/wireguard-remove-client.sh
    
    # Create status script
    cat << 'EOF' > /usr/local/bin/wireguard-status.sh
#!/bin/bash

# Script to show WireGuard status
# Usage: wireguard-status.sh

set -euo pipefail

echo "WireGuard Status:"
echo "================="
wg show

echo -e "\nActive Clients:"
echo "==============="
grep -E "# Client:|PublicKey" /etc/wireguard/wg0.conf | grep -B1 "PublicKey" | grep "# Client:" | awk '{print $3}'

echo -e "\nFirewall Rules:"
echo "=============="
ufw status | grep -E "(wireguard|51820)"

echo -e "\nService Status:"
echo "=============="
systemctl status wg-quick@wg0 --no-pager
EOF
    
    chmod +x /usr/local/bin/wireguard-status.sh
    
    print_info "Management scripts created"
}

# Function to start WireGuard
start_wireguard() {
    print_info "Starting WireGuard..."
    
    # Start and enable WireGuard
    systemctl start wg-quick@wg0
    systemctl enable wg-quick@wg0
    
    # Check status
    if systemctl is-active --quiet wg-quick@wg0; then
        print_info "✓ WireGuard is running"
    else
        print_error "✗ WireGuard failed to start"
        systemctl status wg-quick@wg0
        return 1
    fi
    
    print_info "WireGuard started successfully"
}

# Function to create installation report
create_wireguard_report() {
    print_info "Creating WireGuard installation report..."
    
    cat << EOF > /etc/email-server/wireguard-report.txt
WireGuard VPN Installation Report
Generated on: $(date)

Server Configuration:
--------------------
- Server IP: $VPN_SERVER_IP
- VPN Network: $VPN_NETWORK
- Listen Port: 51820
- Server Public Key: $SERVER_PUBLIC_KEY

Client Configuration:
--------------------
- Client1 IP: 10.0.0.2/32
- Client Public Key: $CLIENT_PUBLIC_KEY

Client Connection Instructions:
-------------------------------
1. Install WireGuard on your device
2. Use the configuration file:
   $CLIENT_CONFIG_FILE
3. Or scan the QR code:
   $CLIENT_QR_FILE

Server Status:
--------------
$(systemctl status wg-quick@wg0 --no-pager)

Firewall Rules:
---------------
$(ufw status | grep -E "(wireguard|51820)")

Management Commands:
-------------------
- Add client: wireguard-add-client.sh <name>
- Remove client: wireguard-remove-client.sh <name>
- Show status: wireguard-status.sh
- Show logs: journalctl -u wg-quick@wg0

Security Notes:
---------------
1. SSH is now restricted to VPN clients only
2. VPN clients have full access to the email server
3. Keep client configuration files secure
4. Regularly audit active connections
EOF
    
    # Create a summary with client config for easy access
    cat << EOF > /etc/email-server/wireguard-client-config-summary.txt
WireGuard Client Configuration Summary
=====================================

Client1 Configuration File:
$(cat /etc/email-server/wireguard-clients/client1.conf)

QR Code (scan with WireGuard mobile app):
$(cat /etc/email-server/wireguard-clients/client1-qr.txt)

To connect:
1. Save the configuration to a file (e.g., client1.conf)
2. Import in WireGuard client application
3. Or scan the QR code above

Server: $SERVER_IP:51820
VPN IP: 10.0.0.2
EOF
    
    print_info "Installation report created"
}

# Main execution
print_info "Starting WireGuard VPN setup..."

# Check if VPN is enabled
check_vpn_enabled

# Install WireGuard
install_wireguard

# Generate keys
generate_server_keys
generate_client_keys

# Create configurations
create_server_config
create_client_config

# Configure firewall
configure_wireguard_firewall

# Restrict SSH to VPN
restrict_ssh_to_vpn

# Create management scripts
create_management_scripts

# Start WireGuard
start_wireguard

# Create installation report
create_wireguard_report

print_info "WireGuard VPN setup complete!"
print_info "Important files:"
echo "  - Server config: /etc/wireguard/wg0.conf"
echo "  - Client config: /etc/email-server/wireguard-clients/client1.conf"
echo "  - Client QR code: /etc/email-server/wireguard-clients/client1-qr.txt"
echo "  - Installation report: /etc/email-server/wireguard-report.txt"
echo "  - Client config summary: /etc/email-server/wireguard-client-config-summary.txt"

print_warning "IMPORTANT:"
echo "1. SSH is now restricted to VPN clients only"
echo "2. Save the client configuration before disconnecting"
echo "3. Use the management scripts to add/remove clients"
echo "4. Client config file: /etc/email-server/wireguard-clients/client1.conf"
echo "5. Connect to VPN before accessing the server via SSH"

if command -v cat &> /dev/null; then
    echo
    echo "Client configuration for copy/paste:"
    echo "===================================="
    cat /etc/email-server/wireguard-clients/client1.conf
fi