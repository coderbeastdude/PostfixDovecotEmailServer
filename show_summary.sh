#!/bin/bash

# Script to show installation summary and next steps
# Part of the email server setup automation

set -euo pipefail

# Load configuration
source ../email-server-config.conf

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE}   EMAIL SERVER SETUP COMPLETE!${NC}"
    echo -e "${BLUE}======================================${NC}"
    echo
}

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_highlight() {
    echo -e "${CYAN}$1${NC}"
}

# Function to check service status
show_service_status() {
    echo -e "${YELLOW}Service Status:${NC}"
    echo "----------------------------------------"
    
    SERVICES=("postfix" "dovecot" "postgresql" "opendkim" "spamassassin" "fail2ban" "apache2")
    
    if [[ "$ENABLE_VPN" == "true" ]]; then
        SERVICES+=("wg-quick@wg0")
    fi
    
    for service in "${SERVICES[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo -e "✓ ${service}: ${GREEN}Running${NC}"
        else
            echo -e "✗ ${service}: ${RED}Not Running${NC}"
        fi
    done
    echo
}

# Function to show DNS requirements
show_dns_requirements() {
    echo -e "${YELLOW}DNS Configuration Required:${NC}"
    echo "----------------------------------------"
    
    if [[ -f /etc/email-server/dns-records.txt ]]; then
        cat /etc/email-server/dns-records.txt | grep -E "(IN\s+A|IN\s+MX|IN\s+TXT|IN\s+SRV|IN\s+CNAME)" | head -10
        echo "..."
        echo "Full DNS records available at: /etc/email-server/dns-records.txt"
    else
        echo "DNS configuration file not found"
    fi
    echo
}

# Function to show important credentials
show_credentials() {
    echo -e "${YELLOW}Important Credentials:${NC}"
    echo "----------------------------------------"
    
    if [[ -f /etc/email-server/postmaster-password.txt ]]; then
        POSTMASTER_PASS=$(cat /etc/email-server/postmaster-password.txt | grep "password:" | cut -d: -f2 | tr -d ' ')
        echo "Postmaster Email: postmaster@$DOMAIN"
        echo "Postmaster Password: $POSTMASTER_PASS"
    fi
    
    if [[ -f /etc/email-server/postgres-root-password.txt ]]; then
        POSTGRES_PASS=$(head -n1 /etc/email-server/postgres-root-password.txt | cut -d: -f2 | tr -d ' ')
        echo "PostgreSQL Root Password: $POSTGRES_PASS"
    fi
    
    if [[ -f /etc/email-server/admin-ssh-key ]]; then
        echo "Admin SSH Key: /etc/email-server/admin-ssh-key"
    fi
    
    echo
    print_warning "Please save these credentials in a secure location!"
    echo
}

# Function to show VPN configuration
show_vpn_config() {
    if [[ "$ENABLE_VPN" == "true" ]]; then
        echo -e "${YELLOW}VPN Configuration:${NC}"
        echo "----------------------------------------"
        
        if [[ -f /etc/email-server/wireguard-client-config-summary.txt ]]; then
            echo "Client configuration available at:"
            echo "/etc/email-server/wireguard-client-config-summary.txt"
            echo
            echo "Quick setup:"
            echo "1. Copy the client configuration from the file above"
            echo "2. Save it as 'client1.conf' on your device"
            echo "3. Import into WireGuard client"
            echo "4. Connect before accessing the server"
        fi
        echo
        print_warning "SSH is now restricted to VPN clients only!"
        echo
    fi
}

# Function to show email client setup
show_email_client_setup() {
    echo -e "${YELLOW}Email Client Configuration:${NC}"
    echo "----------------------------------------"
    echo "IMAP Settings:"
    echo "  Server: mail.$DOMAIN"
    echo "  Port: 993"
    echo "  Security: SSL/TLS"
    echo
    echo "SMTP Settings:"
    echo "  Server: mail.$DOMAIN"
    echo "  Port: 587"
    echo "  Security: STARTTLS"
    echo "  Auth: Username/Password"
    echo
    
    if [[ "$ENABLE_AUTODISCOVERY" == "true" ]]; then
        echo "Autodiscovery available at:"
        echo "  - https://$DOMAIN/mail-setup/"
        echo "  - https://$DOMAIN/autodiscover/autodiscover.xml"
        echo "  - https://$DOMAIN/.well-known/autoconfig/mail/config-v1.1.xml"
    fi
    echo
}

# Function to show monitoring information
show_monitoring_info() {
    echo -e "${YELLOW}Monitoring & Management:${NC}"
    echo "----------------------------------------"
    echo "Dashboard: email-server-dashboard.sh"
    echo "Security Dashboard: email-security-dashboard.sh"
    echo "Backup Management: email-server-backup.sh"
    echo "Fail2Ban Management: manage-fail2ban.sh"
    echo
    echo "Daily Reports sent to: $ADMIN_EMAIL"
    echo "Log Directory: /var/log/email-server-setup/"
    echo
}

# Function to show verification steps
show_verification_steps() {
    echo -e "${YELLOW}Verification Steps:${NC}"
    echo "----------------------------------------"
    echo "1. Complete DNS configuration"
    echo "2. Test email sending and receiving"
    echo "3. Verify SSL certificates"
    echo "4. Check DKIM, SPF, and DMARC"
    echo "5. Test spam filtering"
    echo "6. Configure backup strategy"
    echo
    echo "Run comprehensive tests with:"
    echo "  ./scripts/13-test-server.sh"
    echo
}

# Function to show helpful commands
show_helpful_commands() {
    echo -e "${YELLOW}Helpful Commands:${NC}"
    echo "----------------------------------------"
    echo "Service Management:"
    echo "  systemctl status postfix dovecot"
    echo "  systemctl restart postfix"
    echo
    echo "Mail Queue:"
    echo "  postqueue -p"
    echo "  postqueue -f"
    echo
    echo "Logs:"
    echo "  tail -f /var/log/mail.log"
    echo "  tail -f /var/log/fail2ban.log"
    echo
    echo "Testing:"
    echo "  echo 'Test' | mail -s 'Test Subject' user@$DOMAIN"
    echo "  openssl s_client -connect mail.$DOMAIN:993"
    echo
}

# Function to show important files
show_important_files() {
    echo -e "${YELLOW}Important Files & Directories:${NC}"
    echo "----------------------------------------"
    echo "Configuration:"
    echo "  /etc/email-server-config.conf"
    echo "  /etc/postfix/main.cf"
    echo "  /etc/dovecot/dovecot.conf"
    echo
    echo "Logs:"
    echo "  /var/log/mail.log"
    echo "  /var/log/email-server-setup/"
    echo
    echo "Backups:"
    echo "  $BACKUP_DIR"
    echo
    echo "Web Interface:"
    if [[ "$ENABLE_AUTODISCOVERY" == "true" ]]; then
        echo "  /var/www/html/"
        echo "  https://$DOMAIN/mail-setup/"
    else
        echo "  Not enabled"
    fi
    echo
}

# Function to show next steps
show_next_steps() {
    echo -e "${GREEN}Next Steps:${NC}"
    echo "----------------------------------------"
    echo "1. ${CYAN}Configure DNS records${NC} (required for email delivery)"
    echo "2. ${CYAN}Test email functionality${NC} (send/receive test emails)"
    echo "3. ${CYAN}Set up email clients${NC} (use autodiscovery or manual config)"
    echo "4. ${CYAN}Review security settings${NC} (check Fail2Ban, SSL, etc.)"
    echo "5. ${CYAN}Configure monitoring${NC} (review daily reports)"
    echo "6. ${CYAN}Test backup/restore${NC} (ensure data protection)"
    echo "7. ${CYAN}Document your setup${NC} (save credentials and procedures)"
    echo
    print_warning "Don't forget to:"
    echo "- Add all DNS records before testing"
    echo "- Save important credentials securely"
    echo "- Subscribe to security mailing lists"
    echo "- Plan regular maintenance windows"
    echo
}

# Function to show support information
show_support_info() {
    echo -e "${YELLOW}Support Information:${NC}"
    echo "----------------------------------------"
    echo "Documentation:"
    echo "  - Full Guide: /etc/email-server/INSTALL-GUIDE.md"
    echo "  - Security Guide: /etc/email-server/SECURITY-GUIDE.md"
    echo "  - Restore Guide: $BACKUP_DIR/RESTORE-GUIDE.md"
    echo
    echo "Troubleshooting:"
    echo "  - Check logs in /var/log/"
    echo "  - Review service status"
    echo "  - Run diagnostic scripts"
    echo
    echo "Contact:"
    echo "  - Administrator: $ADMIN_EMAIL"
    echo "  - Server: $(hostname)"
    echo "  - Domain: $DOMAIN"
    echo
}

# Main execution
clear
print_header

# Show current status
echo "Installation completed at: $(date)"
echo "Domain: $DOMAIN"
echo "Server IP: $SERVER_IP"
echo

# Display all sections
show_service_status
show_dns_requirements
show_credentials
show_vpn_config
show_email_client_setup
show_monitoring_info
show_verification_steps
show_helpful_commands
show_important_files
show_next_steps
show_support_info

# Final message
echo -e "${GREEN}${YELLOW}----------------------------------------${NC}"
echo -e "${GREEN}  EMAIL SERVER SETUP COMPLETED${NC}"
echo -e "${GREEN}  Thank you for using this installer!${NC}"
echo -e "${YELLOW}----------------------------------------${NC}"
echo
echo "All configuration files and credentials have been"
echo "saved in /etc/email-server/ for your reference."
echo
print_warning "Remember to configure DNS records before testing!"
echo

# Create a summary file
SUMMARY_FILE="/etc/email-server/installation-summary-$(date +%Y%m%d-%H%M%S).txt"
{
    echo "Email Server Installation Summary"
    echo "================================"
    echo "Date: $(date)"
    echo "Domain: $DOMAIN"
    echo "Server: $(hostname)"
    echo "IP Address: $SERVER_IP"
    echo
    echo "Services Installed:"
    echo "-------------------"
    systemctl list-unit-files | grep -E "(postfix|dovecot|postgresql|opendkim|spamassassin|fail2ban)" | grep enabled
    echo
    echo "Configuration Files:"
    echo "--------------------"
    find /etc/email-server -type f -name "*.txt" -o -name "*.md" | sort
    echo
    echo "Next Steps:"
    echo "-----------"
    echo "1. Configure DNS records"
    echo "2. Test email functionality"
    echo "3. Set up email clients"
    echo "4. Review security settings"
    echo "5. Configure monitoring"
    echo
} > "$SUMMARY_FILE"

echo "Installation summary saved to: $SUMMARY_FILE"
echo
