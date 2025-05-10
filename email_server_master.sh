#!/bin/bash

# Email Server Setup Master Script
# This script orchestrates the setup of a complete email server
# Usage: sudo ./email-server-setup.sh

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration file
CONFIG_FILE="email-server-config.conf"

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        echo "Usage: sudo ./email-server-setup.sh"
        exit 1
    fi
}

# Function to check Ubuntu version
check_ubuntu_version() {
    if [[ ! -f /etc/os-release ]]; then
        print_error "Cannot detect OS version"
        exit 1
    fi
    
    . /etc/os-release
    if [[ "$ID" != "ubuntu" ]] || [[ "${VERSION_ID%%.*}" -lt 20 ]]; then
        print_error "This script requires Ubuntu 20.04 or later"
        exit 1
    fi
    
    print_info "Detected Ubuntu $VERSION_ID"
}

# Function to create configuration file if it doesn't exist
create_config_file() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        print_info "Creating configuration file: $CONFIG_FILE"
        cat > "$CONFIG_FILE" << 'EOF'
# Email Server Configuration
# Edit these values according to your setup

# Domain settings (REQUIRED)
DOMAIN=""
SERVER_IP=""
ADMIN_EMAIL=""

# Database settings
POSTGRES_USER="mailuser"
POSTGRES_PASSWORD=""

# WireGuard VPN settings (OPTIONAL - set ENABLE_VPN=false to skip)
ENABLE_VPN=true
VPN_NETWORK="10.0.0.0/24"
VPN_SERVER_IP="10.0.0.1"

# Email client autodiscovery
ENABLE_AUTODISCOVERY=true

# Backup directory
BACKUP_DIR="/backups"

# SSL/TLS settings
FORCE_SSL=true
EOF
        
        print_warning "Please edit $CONFIG_FILE with your settings before running this script again"
        exit 0
    fi
}

# Function to validate configuration
validate_config() {
    print_info "Validating configuration..."
    
    if [[ -z "$DOMAIN" ]] || [[ -z "$SERVER_IP" ]] || [[ -z "$ADMIN_EMAIL" ]]; then
        print_error "DOMAIN, SERVER_IP, and ADMIN_EMAIL must be set in $CONFIG_FILE"
        exit 1
    fi
    
    if [[ -z "$POSTGRES_PASSWORD" ]]; then
        print_error "POSTGRES_PASSWORD must be set in $CONFIG_FILE"
        exit 1
    fi
    
    print_info "Configuration validation passed"
}

# Function to show installation menu
show_menu() {
    echo
    echo "Email Server Setup - Choose installation options:"
    echo "1. Complete installation (all components)"
    echo "2. Core email server only (Postfix + Dovecot + PostgreSQL)"
    echo "3. Add security components (DKIM + SpamAssassin + Fail2Ban)"
    echo "4. Add optional components (VPN + Monitoring + Autodiscovery)"
    echo "5. Custom installation (choose components)"
    echo "6. Exit"
    echo
    read -p "Select option [1-6]: " choice
    
    case $choice in
        1) install_complete ;;
        2) install_core ;;
        3) install_security ;;
        4) install_optional ;;
        5) install_custom ;;
        6) exit 0 ;;
        *) print_error "Invalid option"; show_menu ;;
    esac
}

# Function for complete installation
install_complete() {
    print_info "Starting complete email server installation..."
    
    # Source configuration
    source "$CONFIG_FILE"
    validate_config
    
    # Make all scripts executable
    chmod +x scripts/*.sh
    
    # Make management scripts executable
    chmod +x scripts/manage-email-users.sh
    
    # Install management script to system
    cp scripts/manage-email-users.sh /usr/local/bin/manage-email-users
    
    # Run installation scripts in order
    print_info "Step 1: Installing system dependencies..."
    ./scripts/01-install-dependencies.sh
    
    print_info "Step 2: Configuring DNS records..."
    ./scripts/02-configure-dns.sh
    
    print_info "Step 3: Setting up firewall..."
    ./scripts/03-setup-firewall.sh
    
    print_info "Step 4: Installing SSL certificate..."
    ./scripts/04-install-ssl.sh
    
    print_info "Step 5: Setting up PostgreSQL..."
    ./scripts/05-setup-postgresql.sh
    
    print_info "Step 6: Configuring Postfix..."
    ./scripts/06-configure-postfix.sh
    
    print_info "Step 7: Configuring Dovecot..."
    ./scripts/07-configure-dovecot.sh
    
    if [[ "$ENABLE_VPN" == "true" ]]; then
        print_info "Step 8: Setting up WireGuard VPN..."
        ./scripts/08-setup-wireguard.sh
    fi
    
    print_info "Step 9: Configuring DKIM..."
    ./scripts/09-configure-dkim.sh
    
    print_info "Step 10: Setting up SpamAssassin..."
    ./scripts/10-setup-spamassassin.sh
    
    print_info "Step 11: Configuring Fail2Ban..."
    ./scripts/11-configure-fail2ban.sh
    
    print_info "Step 12: Setting up monitoring..."
    ./scripts/12-setup-monitoring.sh
    
    print_info "Step 13: Testing email server..."
    ./scripts/13-test-server.sh
    
    if [[ "$ENABLE_AUTODISCOVERY" == "true" ]]; then
        print_info "Step 14: Configuring autodiscovery..."
        ./scripts/14-configure-autodiscovery.sh
    fi
    
    print_info "Step 15: Creating backups..."
    ./scripts/15-create-backups.sh
    
    print_info "Step 16: Final security hardening..."
    ./scripts/16-security-hardening.sh
    
    print_info "Installation complete!"
    print_info "Please check the logs in /var/log/email-server-setup.log for any issues"
    
    # Show summary
    ./scripts/show-summary.sh
}

# Function for core installation
install_core() {
    print_info "Installing core email server components..."
    
    source "$CONFIG_FILE"
    validate_config
    
    chmod +x scripts/*.sh
    
    ./scripts/01-install-dependencies.sh
    ./scripts/03-setup-firewall.sh
    ./scripts/04-install-ssl.sh
    ./scripts/05-setup-postgresql.sh
    ./scripts/06-configure-postfix.sh
    ./scripts/07-configure-dovecot.sh
    ./scripts/13-test-server.sh
    
    print_info "Core installation complete!"
}

# Function for security components
install_security() {
    print_info "Installing security components..."
    
    source "$CONFIG_FILE"
    validate_config
    
    chmod +x scripts/*.sh
    
    ./scripts/09-configure-dkim.sh
    ./scripts/10-setup-spamassassin.sh
    ./scripts/11-configure-fail2ban.sh
    ./scripts/16-security-hardening.sh
    
    print_info "Security components installed!"
}

# Function for optional components
install_optional() {
    print_info "Installing optional components..."
    
    source "$CONFIG_FILE"
    validate_config
    
    chmod +x scripts/*.sh
    
    if [[ "$ENABLE_VPN" == "true" ]]; then
        ./scripts/08-setup-wireguard.sh
    fi
    
    ./scripts/12-setup-monitoring.sh
    
    if [[ "$ENABLE_AUTODISCOVERY" == "true" ]]; then
        ./scripts/14-configure-autodiscovery.sh
    fi
    
    ./scripts/15-create-backups.sh
    
    print_info "Optional components installed!"
}

# Function for custom installation
install_custom() {
    print_info "Custom installation - choose components:"
    
    source "$CONFIG_FILE"
    validate_config
    
    chmod +x scripts/*.sh
    
    components=(
        "Install Dependencies"
        "Configure DNS"
        "Setup Firewall"
        "Install SSL"
        "Setup PostgreSQL"
        "Configure Postfix"
        "Configure Dovecot"
        "Setup WireGuard VPN"
        "Configure DKIM"
        "Setup SpamAssassin"
        "Configure Fail2Ban"
        "Setup Monitoring"
        "Configure Autodiscovery"
        "Create Backups"
        "Security Hardening"
        "Test Server"
        "Done"
    )
    
    selected_components=()
    
    for i in "${!components[@]}"; do
        echo "$((i+1)). ${components[$i]}"
    done
    
    echo
    read -p "Enter component numbers separated by spaces (e.g., 1 3 5): " choices
    
    for choice in $choices; do
        case $choice in
            1) selected_components+=("./scripts/01-install-dependencies.sh") ;;
            2) selected_components+=("./scripts/02-configure-dns.sh") ;;
            3) selected_components+=("./scripts/03-setup-firewall.sh") ;;
            4) selected_components+=("./scripts/04-install-ssl.sh") ;;
            5) selected_components+=("./scripts/05-setup-postgresql.sh") ;;
            6) selected_components+=("./scripts/06-configure-postfix.sh") ;;
            7) selected_components+=("./scripts/07-configure-dovecot.sh") ;;
            8) selected_components+=("./scripts/08-setup-wireguard.sh") ;;
            9) selected_components+=("./scripts/09-configure-dkim.sh") ;;
            10) selected_components+=("./scripts/10-setup-spamassassin.sh") ;;
            11) selected_components+=("./scripts/11-configure-fail2ban.sh") ;;
            12) selected_components+=("./scripts/12-setup-monitoring.sh") ;;
            13) selected_components+=("./scripts/14-configure-autodiscovery.sh") ;;
            14) selected_components+=("./scripts/15-create-backups.sh") ;;
            15) selected_components+=("./scripts/16-security-hardening.sh") ;;
            16) selected_components+=("./scripts/13-test-server.sh") ;;
            17) break ;;
            *) print_error "Invalid choice: $choice" ;;
        esac
    done
    
    # Execute selected components
    for script in "${selected_components[@]}"; do
        print_info "Running $script..."
        $script
    done
    
    print_info "Custom installation complete!"
}

# Main execution
main() {
    check_root
    check_ubuntu_version
    
    # Create scripts directory if it doesn't exist
    mkdir -p scripts
    
    # Create log directory
    mkdir -p /var/log/email-server-setup
    
    # Start logging
    exec 1> >(tee -a /var/log/email-server-setup/installation.log)
    exec 2>&1
    
    print_info "Email Server Setup Script - Started at $(date)"
    
    # Create configuration file if needed
    create_config_file
    
    # Show main menu
    show_menu
}

# Run main function
main "$@"
