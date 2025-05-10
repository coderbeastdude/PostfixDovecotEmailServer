#!/bin/bash

# Script to configure firewall for the email server
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

# Function to backup current UFW rules
backup_ufw_rules() {
    print_info "Backing up current UFW rules..."
    
    if [[ -d /etc/ufw ]]; then
        cp -r /etc/ufw "$BACKUP_DIR/config/ufw-$(date +%Y%m%d-%H%M%S)"
        print_info "UFW backup created in $BACKUP_DIR/config/"
    fi
}

# Function to set up basic firewall rules
setup_basic_rules() {
    print_info "Setting up basic firewall rules..."
    
    # Reset UFW to default
    ufw --force reset
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (will be restricted later if VPN is enabled)
    ufw allow 22/tcp comment 'SSH'
    
    # Allow email server ports
    ufw allow 25/tcp comment 'SMTP'
    ufw allow 587/tcp comment 'SMTP Submission'
    ufw allow 465/tcp comment 'SMTPS (legacy)'
    ufw allow 993/tcp comment 'IMAPS'
    ufw allow 995/tcp comment 'POP3S'
    
    # Allow HTTP and HTTPS for Let's Encrypt and web services
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # Allow DNS for DNSSEC if needed
    ufw allow 53/tcp comment 'DNS'
    ufw allow 53/udp comment 'DNS'
    
    print_info "Basic firewall rules configured"
}

# Function to set up rate limiting
setup_rate_limiting() {
    print_info "Setting up rate limiting rules..."
    
    # Limit SSH connections
    ufw limit ssh comment 'Rate limit SSH'
    
    # Create rate limiting rules for email
    cat << 'EOF' > /etc/ufw/applications.d/email-server
[SMTP]
title=SMTP
description=Simple Mail Transfer Protocol
ports=25/tcp

[SMTP-Submission]
title=SMTP Submission
description=SMTP Submission Port
ports=587/tcp

[IMAPS]
title=IMAPS
description=Internet Message Access Protocol Secure
ports=993/tcp

[POP3S]
title=POP3S
description=Post Office Protocol 3 Secure
ports=995/tcp
EOF
    
    # Apply rate limiting to email ports
    ufw limit in on eth0 to any port 25 proto tcp
    ufw limit in on eth0 to any port 587 proto tcp
    ufw limit in on eth0 to any port 993 proto tcp
    ufw limit in on eth0 to any port 995 proto tcp
    
    print_info "Rate limiting configured"
}

# Function to set up VPN rules
setup_vpn_rules() {
    if [[ "$ENABLE_VPN" == "true" ]]; then
        print_info "Setting up VPN firewall rules..."
        
        # Allow WireGuard
        ufw allow 51820/udp comment 'WireGuard VPN'
        
        # Allow forwarding for VPN
        sed -i 's/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
        sysctl -p
        
        # Set up masquerading for VPN
        sed -i '/^# End required lines/i\
# NAT table rules\
*nat\
:POSTROUTING ACCEPT [0:0]\
-A POSTROUTING -s '"$VPN_NETWORK"' -o eth0 -j MASQUERADE\
COMMIT' /etc/ufw/before.rules
        
        print_info "VPN firewall rules configured"
    fi
}

# Function to create custom rules
create_custom_rules() {
    print_info "Creating custom firewall rules..."
    
    # Block known malicious IPs (example - you can expand this)
    cat << 'EOF' > /etc/ufw/custom-rules.sh
#!/bin/bash
# Custom UFW rules for email server

# Block connections from specific countries (example - adjust as needed)
# Requires xtables-addons for geoip blocking
# iptables -I INPUT -m geoip --src-cc CN,RU,KP -j DROP

# Log and drop invalid packets
iptables -A INPUT -m state --state INVALID -j LOG --log-prefix "DROP INVALID "
iptables -A INPUT -m state --state INVALID -j DROP

# Limit ICMP pings
iptables -A INPUT -p icmp -m limit --limit 5/min -j ACCEPT
iptables -A INPUT -p icmp -j DROP
EOF
    
    chmod +x /etc/ufw/custom-rules.sh
    
    print_info "Custom rules created"
}

# Function to set up fail2ban integration
setup_fail2ban_integration() {
    print_info "Setting up Fail2Ban integration with UFW..."
    
    # Create UFW action for fail2ban
    cat << 'EOF' > /etc/fail2ban/action.d/ufw.conf
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = ufw insert 1 deny from <ip> to any comment "Fail2Ban: %(name)s"
actionunban = ufw delete deny from <ip> to any
EOF
    
    print_info "Fail2Ban integration configured"
}

# Function to create firewall monitoring script
create_monitoring_script() {
    print_info "Creating firewall monitoring script..."
    
    cat << 'EOF' > /usr/local/bin/ufw-monitor.sh
#!/bin/bash
# UFW monitoring script for email server

LOG_FILE="/var/log/ufw-monitor.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Log current UFW status
{
    echo "=== UFW Status Check - $DATE ==="
    ufw status verbose
    echo
    echo "=== Recent UFW Logs ==="
    tail -n 20 /var/log/ufw.log
    echo
    echo "=== Active Connections ==="
    netstat -tulnp | grep -E ':(25|587|993|995|443|80|22)\s'
    echo "=================================="
} >> "$LOG_FILE"

# Check for suspicious activity
SUSPICIOUS=$(grep -i "denied" /var/log/ufw.log | tail -n 50 | awk '{print $11}' | sort | uniq -c | sort -nr | head -10)

if [[ -n "$SUSPICIOUS" ]]; then
    {
        echo "=== Suspicious Activity Detected - $DATE ==="
        echo "$SUSPICIOUS"
        echo "=================================="
    } >> "$LOG_FILE"
fi

# Rotate log file if it gets too large
if [[ $(stat -c%s "$LOG_FILE") -gt 10485760 ]]; then
    mv "$LOG_FILE" "${LOG_FILE}.$(date +%Y%m%d)"
    gzip "${LOG_FILE}.$(date +%Y%m%d)"
fi
EOF
    
    chmod +x /usr/local/bin/ufw-monitor.sh
    
    # Add to crontab for regular monitoring
    (crontab -l 2>/dev/null; echo "*/30 * * * * /usr/local/bin/ufw-monitor.sh") | crontab -
    
    print_info "Firewall monitoring configured"
}

# Function to enable logging
enable_firewall_logging() {
    print_info "Enabling firewall logging..."
    
    ufw logging medium
    
    # Configure rsyslog for better UFW log handling
    cat << 'EOF' > /etc/rsyslog.d/50-ufw.conf
# UFW logging configuration
:msg,contains,"[UFW " /var/log/ufw.log
& stop
EOF
    
    systemctl restart rsyslog
    
    print_info "Firewall logging enabled"
}

# Main execution
print_info "Starting firewall configuration..."

# Backup current rules
backup_ufw_rules

# Set up basic rules
setup_basic_rules

# Set up rate limiting
setup_rate_limiting

# Set up VPN rules if enabled
setup_vpn_rules

# Create custom rules
create_custom_rules

# Set up fail2ban integration
setup_fail2ban_integration

# Create monitoring script
create_monitoring_script

# Enable logging
enable_firewall_logging

# Apply custom rules
/etc/ufw/custom-rules.sh

# Enable UFW
ufw --force enable

# Display final status
print_info "Firewall configuration complete!"
print_info "Current UFW status:"
ufw status verbose

# Save the current rules
ufw status numbered > /etc/email-server/ufw-rules.txt

print_warning "Important notes:"
echo "1. SSH is currently open on port 22"
echo "2. If VPN is enabled, SSH will be restricted to VPN clients only"
echo "3. All email ports (25, 587, 993, 995) are open"
echo "4. Web ports (80, 443) are open for Let's Encrypt and autodiscovery"
echo "5. Firewall logs are available in /var/log/ufw.log"
echo "6. Monitoring script runs every 30 minutes"
