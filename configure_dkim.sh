#!/bin/bash

# Script to configure DKIM (DomainKeys Identified Mail) for the email server
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

# Function to install OpenDKIM
install_opendkim() {
    print_info "Installing OpenDKIM..."
    
    # Check if already installed
    if command -v opendkim &> /dev/null; then
        print_info "OpenDKIM is already installed"
        return 0
    fi
    
    # Install OpenDKIM and tools
    apt-get update
    apt-get install -y opendkim opendkim-tools
    
    print_info "OpenDKIM installed successfully"
}

# Function to backup OpenDKIM configuration
backup_opendkim_config() {
    print_info "Backing up OpenDKIM configuration..."
    
    BACKUP_DIR_DKIM="$BACKUP_DIR/config/opendkim-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR_DKIM"
    
    # Backup existing configuration if it exists
    if [[ -d /etc/opendkim ]]; then
        cp -r /etc/opendkim "$BACKUP_DIR_DKIM/"
    fi
    
    print_info "OpenDKIM configuration backed up to $BACKUP_DIR_DKIM"
}

# Function to create OpenDKIM directory structure
create_opendkim_directories() {
    print_info "Creating OpenDKIM directory structure..."
    
    # Create directories
    mkdir -p /etc/opendkim/keys
    mkdir -p /etc/opendkim/conf
    
    # Set permissions
    chown -R opendkim:opendkim /etc/opendkim
    chmod 750 /etc/opendkim
    chmod 750 /etc/opendkim/keys
    
    print_info "Directory structure created"
}

# Function to configure OpenDKIM main configuration
configure_opendkim_conf() {
    print_info "Configuring OpenDKIM main configuration..."
    
    # Create main configuration file
    cat << EOF > /etc/opendkim.conf
# OpenDKIM Configuration for $DOMAIN

# Log to syslog
Syslog                  yes
SyslogSuccess           yes

# Required to use local socket with MTAs that access the socket as a non-
# privileged user (e.g. Postfix)
UMask                   002

# Sign for example.com with key in /etc/opendkim/keys/example.com/default.private
# using selector "default" and with relaxed/simple canonicalization.
Domain                  $DOMAIN
KeyFile                 /etc/opendkim/keys/$DOMAIN/default.private
Selector                default

# Mode (s = sign, v = verify, sv = sign and verify)
Mode                    sv

# OpenDKIM user
UserID                  opendkim

# Commonly-used options; the commented-out versions show the defaults.
#Canonicalization       simple
Canonicalization        relaxed/simple

# Always oversign From (sign using actual From and a null From to prevent
# malicious signatures header fields (From and/or others) between the signer
# and the verifier.  From is oversigned by default in the Debian package
# because it is often the identity key used by reputation systems and thus
# somewhat security sensitive.
OversignHeaders         From

# List trusted hosts for authentication
TrustedHosts            /etc/opendkim/trusted.hosts

# List domains to use for domains with multiple subdomains
SigningTable            /etc/opendkim/signing.table
KeyTable                /etc/opendkim/key.table

# List external signing keys
#ExternalIgnoreList refile:/etc/opendkim/external_ignore_list
#InternalHosts refile:/etc/opendkim/trusted_hosts

# Socket for Postfix communication
Socket                  inet:12345@localhost

# Keep temporary files for debugging
TemporaryDirectory      /var/tmp

# Other settings
LogWhy                  yes
SignatureAlgorithm      rsa-sha256
MinimumKeyBits          2048
Minimum                 none

# Additional security settings
RequiredHeaders         Date,From,To,Subject
ReportAddress           postmaster@$DOMAIN
SendADSPReports         yes
SendReports             yes

# Add status updates
StatusSendTo            postmaster@$DOMAIN

# Background mode
Background              yes

# Process ID file
PidFile                 /var/run/opendkim/opendkim.pid
EOF
    
    # Set permissions
    chown opendkim:opendkim /etc/opendkim.conf
    chmod 644 /etc/opendkim.conf
    
    print_info "Main configuration created"
}

# Function to create DKIM keys
create_dkim_keys() {
    print_info "Creating DKIM keys for $DOMAIN..."
    
    # Create domain directory
    mkdir -p /etc/opendkim/keys/$DOMAIN
    
    # Generate DKIM key pair
    cd /etc/opendkim/keys/$DOMAIN
    opendkim-genkey -b 2048 -d $DOMAIN -h rsa-sha256 -r -s default -v
    
    # Rename files
    mv default.private default.private
    mv default.txt default.txt
    
    # Set proper permissions
    chown -R opendkim:opendkim /etc/opendkim/keys/$DOMAIN
    chmod 600 /etc/opendkim/keys/$DOMAIN/default.private
    chmod 644 /etc/opendkim/keys/$DOMAIN/default.txt
    
    print_info "DKIM keys generated successfully"
}

# Function to create trusted hosts file
create_trusted_hosts() {
    print_info "Creating trusted hosts file..."
    
    cat << EOF > /etc/opendkim/trusted.hosts
# Trusted hosts for OpenDKIM

# Local addresses
127.0.0.1
127.0.0.0/8
::1

# Our domain
$DOMAIN
.$DOMAIN

# Server IP
$SERVER_IP

# VPN network (if enabled)
EOF
    if [[ "$ENABLE_VPN" == "true" ]]; then
        echo "$VPN_NETWORK" >> /etc/opendkim/trusted.hosts
    fi
    
    # Set permissions
    chown opendkim:opendkim /etc/opendkim/trusted.hosts
    chmod 644 /etc/opendkim/trusted.hosts
    
    print_info "Trusted hosts file created"
}

# Function to create signing table
create_signing_table() {
    print_info "Creating signing table..."
    
    cat << EOF > /etc/opendkim/signing.table
# Signing table for OpenDKIM

# Domain pattern to key selector mapping
*@$DOMAIN    default._domainkey.$DOMAIN

# Subdomains
*@*.$DOMAIN  default._domainkey.$DOMAIN
EOF
    
    # Set permissions
    chown opendkim:opendkim /etc/opendkim/signing.table
    chmod 644 /etc/opendkim/signing.table
    
    print_info "Signing table created"
}

# Function to create key table
create_key_table() {
    print_info "Creating key table..."
    
    cat << EOF > /etc/opendkim/key.table
# Key table for OpenDKIM

# selector._domainkey.domain    domain:selector:path_to_private_key
default._domainkey.$DOMAIN      $DOMAIN:default:/etc/opendkim/keys/$DOMAIN/default.private
EOF
    
    # Set permissions
    chown opendkim:opendkim /etc/opendkim/key.table
    chmod 644 /etc/opendkim/key.table
    
    print_info "Key table created"
}

# Function to configure Postfix for OpenDKIM
configure_postfix_dkim() {
    print_info "Configuring Postfix to use OpenDKIM..."
    
    # Add milter configuration to Postfix
    if ! grep -q "smtpd_milters" /etc/postfix/main.cf; then
        echo "" >> /etc/postfix/main.cf
        echo "# OpenDKIM settings" >> /etc/postfix/main.cf
        echo "milter_default_action = accept" >> /etc/postfix/main.cf
        echo "milter_protocol = 6" >> /etc/postfix/main.cf
        echo "smtpd_milters = inet:127.0.0.1:12345" >> /etc/postfix/main.cf
        echo "non_smtpd_milters = \$smtpd_milters" >> /etc/postfix/main.cf
    else
        # Update existing configuration
        sed -i 's/^smtpd_milters.*/smtpd_milters = inet:127.0.0.1:12345/' /etc/postfix/main.cf
        sed -i 's/^non_smtpd_milters.*/non_smtpd_milters = $smtpd_milters/' /etc/postfix/main.cf
    fi
    
    # Reload Postfix
    systemctl reload postfix
    
    print_info "Postfix configured for OpenDKIM"
}

# Function to create systemd service configuration
configure_systemd_service() {
    print_info "Configuring OpenDKIM systemd service..."
    
    # Create systemd override directory
    mkdir -p /etc/systemd/system/opendkim.service.d
    
    # Create override configuration
    cat << EOF > /etc/systemd/system/opendkim.service.d/override.conf
[Service]
# Run as opendkim user
User=opendkim
Group=opendkim

# Limit resource usage
MemoryLimit=256M
TasksMax=10

# Security settings
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID

# Ensure pid file directory exists
RuntimeDirectory=opendkim
RuntimeDirectoryMode=755
EOF
    
    # Reload systemd
    systemctl daemon-reload
    
    print_info "Systemd service configured"
}

# Function to create DKIM DNS record template
create_dns_record_template() {
    print_info "Creating DKIM DNS record template..."
    
    # Extract DKIM public key
    DKIM_PUBLIC_KEY=$(cat /etc/opendkim/keys/$DOMAIN/default.txt | grep -v "default._domainkey" | tr -d "\n\t \"" | sed 's/p=//')
    
    # Create DNS record template
    cat << EOF > /etc/email-server/dkim-dns-record.txt
DKIM DNS Record Configuration
============================

Add this TXT record to your DNS zone:

Record Type: TXT
Hostname: default._domainkey.$DOMAIN
Value: "v=DKIM1; h=sha256; k=rsa; p=$DKIM_PUBLIC_KEY"
TTL: 3600

Full DNS record format:
default._domainkey.$DOMAIN.    3600    IN    TXT    "v=DKIM1; h=sha256; k=rsa; p=$DKIM_PUBLIC_KEY"

Testing your DKIM record:
------------------------
dig TXT default._domainkey.$DOMAIN
nslookup -type=TXT default._domainkey.$DOMAIN

Verification tools:
------------------
- https://mxtoolbox.com/dkim.aspx
- https://www.mail-tester.com/
- Send test email to: check-auth2@verifier.port25.com

Notes:
------
1. DNS propagation may take up to 48 hours
2. Verify the record is properly formatted
3. Test with DKIM verification tools
4. Check mail logs for DKIM signing status
EOF
    
    print_info "DNS record template created: /etc/email-server/dkim-dns-record.txt"
}

# Function to test DKIM configuration
test_dkim_configuration() {
    print_info "Testing DKIM configuration..."
    
    # Test key loading
    print_info "Testing DKIM key validation..."
    if opendkim-testkey -d $DOMAIN -s default -vvv; then
        print_info "✓ DKIM key validation successful"
    else
        print_error "✗ DKIM key validation failed"
    fi
    
    # Create test report
    cat << EOF > /etc/email-server/dkim-test-report.txt
DKIM Configuration Test Report
==============================
Generated on: $(date)

Domain: $DOMAIN
Selector: default
Key File: /etc/opendkim/keys/$DOMAIN/default.private

Configuration Status:
--------------------
- OpenDKIM Service: $(systemctl is-active opendkim)
- Postfix Integration: $(grep -q "smtpd_milters" /etc/postfix/main.cf && echo "Configured" || echo "Missing")
- Socket: inet:127.0.0.1:12345
- Key Validation: $(opendkim-testkey -d $DOMAIN -s default &>/dev/null && echo "PASS" || echo "FAIL")

Key Information:
----------------
$(cat /etc/opendkim/keys/$DOMAIN/default.txt)

Current DNS Status:
-------------------
$(dig TXT default._domainkey.$DOMAIN +short || echo "DNS record not found - needs to be added")

Service Status:
---------------
$(systemctl status opendkim --no-pager)

Log Sample:
-----------
$(tail -n 10 /var/log/mail.log | grep -i dkim || echo "No recent DKIM logs")
EOF
    
    print_info "Test report created: /etc/email-server/dkim-test-report.txt"
}

# Function to start and enable OpenDKIM
start_opendkim() {
    print_info "Starting and enabling OpenDKIM..."
    
    # Start OpenDKIM
    systemctl start opendkim
    
    # Enable OpenDKIM to start on boot
    systemctl enable opendkim
    
    # Check status
    if systemctl is-active --quiet opendkim; then
        print_info "✓ OpenDKIM is running"
    else
        print_error "✗ OpenDKIM failed to start"
        systemctl status opendkim
        return 1
    fi
    
    print_info "OpenDKIM started and enabled successfully"
}

# Function to create monitoring script
create_dkim_monitoring() {
    print_info "Creating DKIM monitoring script..."
    
    cat << 'EOF' > /usr/local/bin/monitor-dkim.sh
#!/bin/bash

# DKIM monitoring script
# Part of email server setup automation

set -euo pipefail

LOG_FILE="/var/log/email-server-setup/dkim-monitor.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Function to log messages
log_message() {
    echo "[$DATE] $1" | tee -a "$LOG_FILE"
}

# Check OpenDKIM service status
if systemctl is-active --quiet opendkim; then
    log_message "OpenDKIM service is running"
else
    log_message "ERROR: OpenDKIM service is not running"
    systemctl status opendkim >> "$LOG_FILE"
fi

# Check DKIM key validation
DOMAIN=$(grep "^Domain" /etc/opendkim.conf | awk '{print $2}')
if opendkim-testkey -d "$DOMAIN" -s default -vvv &>/dev/null; then
    log_message "DKIM key validation successful"
else
    log_message "WARNING: DKIM key validation failed"
fi

# Check DNS record
DNS_CHECK=$(dig TXT default._domainkey.$DOMAIN +short)
if [[ -n "$DNS_CHECK" ]]; then
    log_message "DNS record found: $DNS_CHECK"
else
    log_message "WARNING: DNS record not found"
fi

# Check recent DKIM activity
RECENT_DKIM=$(grep -i dkim /var/log/mail.log | tail -n 5)
if [[ -n "$RECENT_DKIM" ]]; then
    log_message "Recent DKIM activity:"
    echo "$RECENT_DKIM" >> "$LOG_FILE"
else
    log_message "No recent DKIM activity"
fi

# Check socket connectivity
if timeout 3 bash -c "echo > /dev/tcp/127.0.0.1/12345"; then
    log_message "DKIM socket is accessible"
else
    log_message "ERROR: DKIM socket is not accessible"
fi

log_message "DKIM monitoring check completed"
echo "----------------------------------------" >> "$LOG_FILE"
EOF
    
    chmod +x /usr/local/bin/monitor-dkim.sh
    
    # Add to crontab for hourly monitoring
    (crontab -l 2>/dev/null; echo "0 * * * * /usr/local/bin/monitor-dkim.sh") | crontab -
    
    print_info "DKIM monitoring script created and scheduled"
}

# Main execution
print_info "Starting DKIM configuration..."

# Install OpenDKIM
install_opendkim

# Backup existing configuration
backup_opendkim_config

# Create directory structure
create_opendkim_directories

# Configure OpenDKIM
configure_opendkim_conf

# Create DKIM keys
create_dkim_keys

# Create configuration files
create_trusted_hosts
create_signing_table
create_key_table

# Configure Postfix integration
configure_postfix_dkim

# Configure systemd service
configure_systemd_service

# Start and enable OpenDKIM
start_opendkim

# Create DNS record template
create_dns_record_template

# Test configuration
test_dkim_configuration

# Create monitoring
create_dkim_monitoring

print_info "DKIM configuration complete!"
print_info "Important files:"
echo "  - Configuration: /etc/opendkim.conf"
echo "  - Private key: /etc/opendkim/keys/$DOMAIN/default.private"
echo "  - Public key: /etc/opendkim/keys/$DOMAIN/default.txt"
echo "  - DNS record template: /etc/email-server/dkim-dns-record.txt"
echo "  - Test report: /etc/email-server/dkim-test-report.txt"

print_warning "Next steps:"
echo "1. Add the DKIM DNS record to your domain"
echo "2. Wait for DNS propagation (up to 48 hours)"
echo "3. Test DKIM with: opendkim-testkey -d $DOMAIN -s default -vvv"
echo "4. Send test email to check-auth2@verifier.port25.com"
echo "5. Monitor logs: tail -f /var/log/mail.log | grep -i dkim"

# Display DNS record
echo
echo "DKIM DNS Record to Add:"
echo "======================="
cat /etc/email-server/dkim-dns-record.txt | grep -A1 -B1 "^default._domainkey"
