#!/bin/bash

# Script to install all dependencies for the email server
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

# Update system
print_info "Updating system packages..."
apt-get update
apt-get upgrade -y

# Install core email server packages
print_info "Installing core email server packages..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    postfix \
    postfix-pgsql \
    dovecot-core \
    dovecot-imapd \
    dovecot-pop3d \
    dovecot-lmtpd \
    dovecot-pgsql \
    postgresql \
    postgresql-contrib \
    postgresql-client

# Install security packages
print_info "Installing security packages..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    opendkim \
    opendkim-tools \
    spamassassin \
    spamc \
    fail2ban \
    ufw

# Install essential utilities
print_info "Installing essential utilities..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    mailutils \
    certbot \
    python3-certbot-apache \
    logwatch \
    netcat \
    dnsutils \
    telnet \
    wget \
    curl \
    vim \
    htop \
    rsync \
    unzip \
    zip

# Install WireGuard if enabled
if [[ "$ENABLE_VPN" == "true" ]]; then
    print_info "Installing WireGuard VPN..."
    apt-get install -y wireguard
fi

# Install web server for autodiscovery
if [[ "$ENABLE_AUTODISCOVERY" == "true" ]]; then
    print_info "Installing Apache web server for autodiscovery..."
    apt-get install -y apache2
fi

# Install additional monitoring tools
print_info "Installing monitoring tools..."
apt-get install -y \
    iotop \
    iftop \
    nethogs \
    mailgraph

# Clean up package cache
print_info "Cleaning up package cache..."
apt-get autoremove -y
apt-get autoclean

# Set up Postfix configuration during installation
print_info "Configuring Postfix basic settings..."
# Preseed Postfix configuration
echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
echo "postfix postfix/mailname string $DOMAIN" | debconf-set-selections

# Reconfigure Postfix with preseeded values
dpkg-reconfigure -f noninteractive postfix

# Create necessary directories
print_info "Creating necessary directories..."
mkdir -p /var/log/email-server-setup
mkdir -p /etc/email-server
mkdir -p "$BACKUP_DIR"
mkdir -p "$BACKUP_DIR/config"
mkdir -p "$BACKUP_DIR/mail"
mkdir -p "$BACKUP_DIR/database"

# Set proper permissions
chmod 755 /var/log/email-server-setup
chmod 755 /etc/email-server
chmod 700 "$BACKUP_DIR"

# Create log file for this installation
touch /var/log/email-server-setup/dependencies.log
chmod 644 /var/log/email-server-setup/dependencies.log

print_info "All dependencies installed successfully!"
print_info "Installation log: /var/log/email-server-setup/dependencies.log"
