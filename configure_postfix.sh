#!/bin/bash

# Script to configure Postfix for the email server
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

# Function to backup Postfix configuration
backup_postfix_config() {
    print_info "Backing up Postfix configuration..."
    
    BACKUP_DIR_POSTFIX="$BACKUP_DIR/config/postfix-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR_POSTFIX"
    
    # Backup main configuration files
    cp /etc/postfix/main.cf "$BACKUP_DIR_POSTFIX/"
    cp /etc/postfix/master.cf "$BACKUP_DIR_POSTFIX/"
    
    # Backup entire postfix directory
    cp -r /etc/postfix "$BACKUP_DIR_POSTFIX/"
    
    print_info "Postfix configuration backed up to $BACKUP_DIR_POSTFIX"
}

# Function to configure main.cf
configure_main_cf() {
    print_info "Configuring Postfix main.cf..."
    
    # Create new main.cf
    cat << EOF > /etc/postfix/main.cf
# See /usr/share/postfix/main.cf.dist for a commented, more complete version

# Debian specific:  Specifying a file name will cause the first
# line of that file to be used as the name.  The Debian default
# is /etc/mailname.
#myorigin = /etc/mailname

smtpd_banner = \$myhostname ESMTP \$mail_name
biff = no

# appending .domain is the MUA's job.
append_dot_mydomain = no

# Uncomment the next line to generate "delayed mail" warnings
#delay_warning_time = 4h

readme_directory = no

# See http://www.postfix.org/COMPATIBILITY_README.html -- default to 3.6 on
# fresh installs.
compatibility_level = 3.6

# TLS parameters
smtpd_tls_cert_file=/etc/letsencrypt/live/mail.$DOMAIN/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/mail.$DOMAIN/privkey.pem
smtpd_use_tls=yes
smtpd_tls_auth_only = yes
smtpd_tls_security_level=may
smtpd_sasl_security_options = noanonymous, noplaintext
smtpd_sasl_tls_security_options = noanonymous
smtpd_sasl_local_domain = \$myhostname
broken_sasl_auth_clients = yes

# Outgoing TLS
smtp_tls_CApath=/etc/ssl/certs
smtp_tls_security_level=may
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache

# SASL Authentication
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes

# Network settings
myhostname = mail.$DOMAIN
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
mydomain = $DOMAIN
myorigin = \$mydomain
mydestination = localhost
relayhost = 
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all

# Virtual domains
virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_mailbox_domains = pgsql:/etc/postfix/pgsql/virtual-mailbox-domains.cf
virtual_mailbox_maps = pgsql:/etc/postfix/pgsql/virtual-mailbox-maps.cf
virtual_alias_maps = pgsql:/etc/postfix/pgsql/virtual-alias-maps.cf, pgsql:/etc/postfix/pgsql/virtual-email2email.cf

# SMTP restrictions
smtpd_helo_restrictions = 
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_invalid_helo_hostname,
    reject_non_fqdn_helo_hostname,
    reject_unauth_destination

smtpd_recipient_restrictions = 
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_non_fqdn_recipient,
    reject_unknown_recipient_domain,
    reject_unlisted_recipient,
    reject_unauth_destination,
    check_policy_service inet:127.0.0.1:10023

smtpd_sender_restrictions = 
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_non_fqdn_sender,
    reject_unknown_sender_domain,
    reject_unauthenticated_sender_login_mismatch

smtpd_relay_restrictions = 
    permit_mynetworks,
    permit_sasl_authenticated,
    defer_unauth_destination

# Rate limiting
smtpd_client_connection_rate_limit = 50
smtpd_client_message_rate_limit = 20
anvil_rate_time_unit = 60s

# Additional security settings
disable_vrfy_command = yes
strict_rfc821_envelopes = yes
smtpd_delay_reject = yes
smtpd_helo_required = yes
smtp_always_send_ehlo = yes
smtpd_timeout = 60s
smtp_helo_timeout = 40s
smtp_rcpt_timeout = 15s
smtpd_recipient_limit = 40
minimal_backoff_time = 180s
maximal_backoff_time = 3h

# Rejection response codes
invalid_hostname_reject_code = 550
non_fqdn_reject_code = 550
unknown_address_reject_code = 550
unknown_client_reject_code = 550
unknown_hostname_reject_code = 550
unverified_recipient_reject_code = 550
unverified_sender_reject_code = 550

# Message size limit (25MB)
message_size_limit = 26214400

# Milter for OpenDKIM
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:localhost:12345
non_smtpd_milters = inet:localhost:12345

# Header cleanup
header_checks = regexp:/etc/postfix/header_checks

# Content filter for SpamAssassin
content_filter = spamassassin

# Logging
smtpd_tls_loglevel = 1
smtpd_sasl_loglevel = 1
EOF
    
    print_info "main.cf configured successfully"
}

# Function to configure master.cf
configure_master_cf() {
    print_info "Configuring Postfix master.cf..."
    
    # Backup original
    cp /etc/postfix/master.cf /etc/postfix/master.cf.bak
    
    # Create new master.cf
    cat << 'EOF' > /etc/postfix/master.cf
#
# Postfix master process configuration file.
#
# ==========================================================================
# service type  private unpriv  chroot  wakeup  maxproc command + args
#               (yes)   (yes)   (no)    (never) (100)
# ==========================================================================
smtp      inet  n       -       n       -       -       smtpd
#smtp      inet  n       -       n       -       1       postscreen
#smtpd     pass  -       -       n       -       -       smtpd
#dnsblog   unix  -       -       n       -       0       dnsblog
#tlsproxy  unix  -       -       n       -       0       tlsproxy

# Choose one: enable submission for port 587, smtps for port 465
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_helo_restrictions=permit_sasl_authenticated
  -o smtpd_sender_restrictions=permit_sasl_authenticated
  -o smtpd_relay_restrictions=permit_sasl_authenticated
  -o milter_macro_daemon_name=ORIGINATING

smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING

#628       inet  n       -       y       -       -       qmqpd
pickup    unix  n       -       y       60      1       pickup
cleanup   unix  n       -       y       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
#qmgr     unix  n       -       n       300     1       oqmgr
tlsmgr    unix  -       -       y       1000?   1       tlsmgr
rewrite   unix  -       -       y       -       -       trivial-rewrite
bounce    unix  -       -       y       -       0       bounce
defer     unix  -       -       y       -       0       bounce
trace     unix  -       -       y       -       0       bounce
verify    unix  -       -       y       -       1       verify
flush     unix  n       -       y       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       y       -       -       smtp
relay     unix  -       -       y       -       -       smtp
        -o syslog_name=postfix/$service_name
#       -o smtp_helo_timeout=5 -o smtp_connect_timeout=5
showq     unix  n       -       y       -       -       showq
error     unix  -       -       y       -       -       error
retry     unix  -       -       y       -       -       error
discard   unix  -       -       y       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       y       -       -       lmtp
anvil     unix  -       -       y       -       1       anvil
scache    unix  -       -       y       -       1       scache
postlog   unix-dgram n  -       n       -       1       postlogd

# SpamAssassin filter
spamassassin unix -     n       n       -       -       pipe
  user=spamd argv=/usr/bin/spamc -f -e /usr/sbin/sendmail -oi -f ${sender} ${recipient}

# Maildrop delivery agent
maildrop  unix  -       n       n       -       -       pipe
  flags=DRhu user=vmail argv=/usr/bin/maildrop -d ${recipient}

# The Cyrus deliver program has changed incompatibly, multiple times.
# old cyrus     unix  -       n       n       -       -       pipe
# flags=R user=cyrus argv=/cyrus/bin/deliver -e -m ${extension} ${user}
EOF
    
    print_info "master.cf configured successfully"
}

# Function to create header checks
create_header_checks() {
    print_info "Creating header checks..."
    
    cat << 'EOF' > /etc/postfix/header_checks
# Header checks for Postfix
# Remove unwanted headers

# Remove X-Mailer header
/^X-Mailer:/            IGNORE

# Remove X-Originating-IP header
/^X-Originating-IP:/    IGNORE

# Remove User-Agent header
/^User-Agent:/          IGNORE

# Remove sensitive headers from internal users
/^X-PHP-Script:/        IGNORE

# Reject empty MIME structures
/^Content-Type:\s*$/    REJECT Missing content type

# Reject malformed MIME
/boundary.*\n\s*.*/     REJECT Malformed MIME boundary
EOF
    
    # Compile header checks
    postmap /etc/postfix/header_checks
    
    print_info "Header checks created"
}

# Function to create aliases
create_aliases() {
    print_info "Creating email aliases..."
    
    # Create basic aliases
    cat << EOF > /etc/aliases
# See man 5 aliases for format
postmaster:    root
abuse:         root
webmaster:     root
hostmaster:    root
security:      root
noc:           root
root:          admin@$DOMAIN
EOF
    
    # Create mail routing for postmaster
    echo "postmaster: postmaster@$DOMAIN" >> /etc/aliases
    
    # Rebuild aliases database
    newaliases
    
    print_info "Aliases created and database updated"
}

# Function to configure SASL authentication
configure_sasl() {
    print_info "Configuring SASL authentication..."
    
    # Create SASL configuration for Postfix
    mkdir -p /etc/postfix/sasl
    
    cat << EOF > /etc/postfix/sasl/smtpd.conf
pwcheck_method: saslauthd
auxprop_plugin: sql
mech_list: PLAIN LOGIN CRAM-MD5 DIGEST-MD5
sql_engine: pgsql
sql_hostnames: localhost
sql_user: $POSTGRES_USER
sql_passwd: $POSTGRES_PASSWORD
sql_database: mailbox
sql_select: SELECT password FROM mailbox.users WHERE email='%u@%r' AND active=TRUE
EOF
    
    chmod 640 /etc/postfix/sasl/smtpd.conf
    chown root:postfix /etc/postfix/sasl/smtpd.conf
    
    print_info "SASL authentication configured"
}

# Function to create lookup tables
create_lookup_tables() {
    print_info "Creating Postfix lookup tables..."
    
    # Ensure the query files exist
    for file in virtual-mailbox-domains.cf virtual-mailbox-maps.cf virtual-alias-maps.cf virtual-email2email.cf; do
        if [[ ! -f /etc/postfix/pgsql/$file ]]; then
            print_error "Missing query file: /etc/postfix/pgsql/$file"
            return 1
        fi
    done
    
    # Set proper permissions
    chown -R root:postfix /etc/postfix/pgsql/
    chmod 640 /etc/postfix/pgsql/*
    
    print_info "Lookup tables configured"
}

# Function to create mailname
create_mailname() {
    print_info "Creating mailname..."
    
    echo "mail.$DOMAIN" > /etc/mailname
    
    print_info "Mailname set to mail.$DOMAIN"
}

# Function to set proper permissions
set_permissions() {
    print_info "Setting proper permissions..."
    
    # Set Postfix permissions
    chmod -R o-rwx /etc/postfix
    chown -R root:postfix /etc/postfix
    
    # Ensure virtual mail directory exists
    mkdir -p /var/mail/vhosts/$DOMAIN
    chown -R vmail:vmail /var/mail/vhosts
    chmod 750 /var/mail/vhosts
    
    print_info "Permissions set successfully"
}

# Function to test Postfix configuration
test_postfix_config() {
    print_info "Testing Postfix configuration..."
    
    # Check main.cf syntax
    print_info "Checking main.cf syntax..."
    if postfix check; then
        print_info "✓ main.cf syntax OK"
    else
        print_error "✗ main.cf syntax errors found"
        return 1
    fi
    
    # Test virtual domain lookup
    print_info "Testing virtual domain lookup..."
    DOMAIN_TEST=$(postmap -q "$DOMAIN" pgsql:/etc/postfix/pgsql/virtual-mailbox-domains.cf)
    if [[ "$DOMAIN_TEST" == "1" ]]; then
        print_info "✓ Virtual domain lookup successful"
    else
        print_error "✗ Virtual domain lookup failed"
    fi
    
    # Test virtual user lookup
    print_info "Testing virtual user lookup..."
    USER_TEST=$(postmap -q "postmaster@$DOMAIN" pgsql:/etc/postfix/pgsql/virtual-mailbox-maps.cf)
    if [[ "$USER_TEST" == "1" ]]; then
        print_info "✓ Virtual user lookup successful"
    else
        print_error "✗ Virtual user lookup failed"
    fi
    
    # Test alias lookup
    print_info "Testing alias lookup..."
    ALIAS_TEST=$(postmap -q "admin@$DOMAIN" pgsql:/etc/postfix/pgsql/virtual-alias-maps.cf)
    if [[ -n "$ALIAS_TEST" ]]; then
        print_info "✓ Alias lookup successful (maps to: $ALIAS_TEST)"
    else
        print_warning "No alias found for admin@$DOMAIN"
    fi
    
    # Create test report
    cat << EOF > /etc/email-server/postfix-test-report.txt
Postfix Configuration Test Report
Generated on: $(date)

Configuration Status:
- main.cf syntax: $(if postfix check 2>/dev/null; then echo "OK"; else echo "ERROR"; fi)
- Virtual domain lookup: $(if [[ "$DOMAIN_TEST" == "1" ]]; then echo "OK"; else echo "FAILED"; fi)
- Virtual user lookup: $(if [[ "$USER_TEST" == "1" ]]; then echo "OK"; else echo "FAILED"; fi)
- Alias lookup: $(if [[ -n "$ALIAS_TEST" ]]; then echo "OK"; else echo "NO ALIASES"; fi)

Server Details:
- Hostname: $(postconf -h myhostname)
- Domain: $(postconf -h mydomain)
- SSL Certificate: /etc/letsencrypt/live/mail.$DOMAIN/fullchain.pem
- Virtual Transport: $(postconf -h virtual_transport)

Listening Ports:
$(netstat -tlnp | grep master)

Active Queue:
$(postqueue -p)
EOF
    
    print_info "Test report created: /etc/email-server/postfix-test-report.txt"
}

# Function to start and enable Postfix
start_postfix() {
    print_info "Starting and enabling Postfix..."
    
    # Reload systemd
    systemctl daemon-reload
    
    # Start Postfix
    systemctl start postfix
    
    # Enable Postfix to start on boot
    systemctl enable postfix
    
    # Check status
    if systemctl is-active --quiet postfix; then
        print_info "✓ Postfix is running"
    else
        print_error "✗ Postfix failed to start"
        systemctl status postfix
        return 1
    fi
    
    print_info "Postfix started and enabled successfully"
}

# Main execution
print_info "Starting Postfix configuration..."

# Backup existing configuration
backup_postfix_config

# Configure main.cf
configure_main_cf

# Configure master.cf
configure_master_cf

# Create header checks
create_header_checks

# Create aliases
create_aliases

# Configure SASL
configure_sasl

# Create lookup tables
create_lookup_tables

# Create mailname
create_mailname

# Set proper permissions
set_permissions

# Test configuration
test_postfix_config

# Start Postfix
start_postfix

print_info "Postfix configuration complete!"
print_info "Important files:"
echo "  - Configuration: /etc/postfix/main.cf"
echo "  - Master process: /etc/postfix/master.cf"
echo "  - Virtual queries: /etc/postfix/pgsql/"
echo "  - Header checks: /etc/postfix/header_checks"
echo "  - Test report: /etc/email-server/postfix-test-report.txt"

print_warning "Next steps:"
echo "1. Verify Postfix is listening on ports 25, 587"
echo "2. Test email sending/receiving"
echo "3. Check logs: /var/log/mail.log"
echo "4. Configure Dovecot for local delivery"
