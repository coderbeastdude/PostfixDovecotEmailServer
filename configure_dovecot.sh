#!/bin/bash

# Script to configure Dovecot for the email server
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

# Function to backup Dovecot configuration
backup_dovecot_config() {
    print_info "Backing up Dovecot configuration..."
    
    BACKUP_DIR_DOVECOT="$BACKUP_DIR/config/dovecot-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR_DOVECOT"
    
    # Backup entire dovecot directory
    cp -r /etc/dovecot "$BACKUP_DIR_DOVECOT/"
    
    print_info "Dovecot configuration backed up to $BACKUP_DIR_DOVECOT"
}

# Function to create vmail user and group
create_vmail_user() {
    print_info "Creating vmail user and group..."
    
    # Check if vmail group exists
    if ! getent group vmail >/dev/null; then
        groupadd -g 5000 vmail
        print_info "Created vmail group with GID 5000"
    fi
    
    # Check if vmail user exists
    if ! getent passwd vmail >/dev/null; then
        useradd -g vmail -u 5000 vmail -d /var/mail
        print_info "Created vmail user with UID 5000"
    fi
    
    # Create mail directory structure
    mkdir -p /var/mail/vhosts/$DOMAIN
    chown -R vmail:vmail /var/mail
    chmod 750 /var/mail/vhosts
    
    print_info "Mail directory structure created"
}

# Function to configure main Dovecot file
configure_dovecot_conf() {
    print_info "Configuring Dovecot main configuration..."
    
    # Create main dovecot.conf
    cat << EOF > /etc/dovecot/dovecot.conf
## Dovecot configuration file for email server
## Generated automatically by email server setup script

# Enable protocols
protocols = imap pop3 lmtp

# Enable auth debugging
#auth_debug = yes
#auth_debug_passwords = yes

# Log file
log_path = /var/log/dovecot/dovecot.log
info_log_path = /var/log/dovecot/dovecot-info.log
debug_log_path = /var/log/dovecot/dovecot-debug.log

# Include configuration files
!include conf.d/*.conf

# Uncomment to enable auth-socket
!include_try /usr/local/share/dovecot/conf.d/*.conf

# Postmaster address
postmaster_address = postmaster@$DOMAIN

# Set the default shell for virtual users
default_shell = /bin/bash

# Set mail privileges group
mail_privileged_group = mail
EOF
    
    print_info "Main Dovecot configuration created"
}

# Function to configure mail settings
configure_mail_conf() {
    print_info "Configuring Dovecot mail settings..."
    
    # Update 10-mail.conf
    cat << EOF > /etc/dovecot/conf.d/10-mail.conf
##
## Mailbox locations and namespaces
##

# Location for users' mailboxes
mail_location = maildir:/var/mail/vhosts/%d/%n/

# System user privileges group
mail_privileged_group = mail

# Valid chars in username
valid_chars =

# Default mail access groups
#mail_access_groups =

# Enable mail process to drop root privileges
#mail_always_have_user_group = no

# Enable quota plugins
mail_plugins =

##
## Mail processes
##

# Don't use mmap() at all, it's not needed for maildir
mmap_disable = yes

# Don't use mlock() to store buffers in RAM
#lock_method = fcntl

# Maximum number of mail processes
#mail_max_userip_connections = 10

##
## Mailbox handling optimizations
##

# Space separated list of plugins to load for all services
mail_plugins = \$mail_plugins quota

##
## Maildir-specific settings
##

# By default LIST command returns all entries in ~/Maildir and
# ~/Maildir/.*/ directories. Delete this line to make LIST show
# hidden directories
namespace inbox {
  # Namespace type: private, shared or public
  type = private

  # Hierarchy separator to use
  separator = /

  # Prefix required to access this namespace
  prefix =

  # Physical location of the mailbox
  location =

  # There can be only one INBOX, and this setting defines which namespace
  # has it.
  inbox = yes

  # These mailboxes are widely used and should always be created:
  mailbox Drafts {
    special_use = \Drafts
    auto = create
  }
  mailbox Junk {
    special_use = \Junk
    auto = create
  }
  mailbox Trash {
    special_use = \Trash
    auto = create
  }

  # For \Sent mailboxes there are two widely used names:
  mailbox Sent {
    special_use = \Sent
    auto = create
  }
}

# Example shared namespace configuration
#namespace {
#  type = shared
#  separator = /
#  prefix = shared/%%u/
#  location = maildir:%%h/Maildir:INDEX=~/Maildir/shared/%%u
#  subscriptions = no
#  list = children
#}
EOF
    
    print_info "Mail configuration updated"
}

# Function to configure authentication
configure_auth_conf() {
    print_info "Configuring Dovecot authentication..."
    
    # Update 10-auth.conf
    cat << EOF > /etc/dovecot/conf.d/10-auth.conf
##
## Authentication processes
##

# Disable LOGIN command and all other plaintext authentications unless
# SSL/TLS is used (LOGINDISABLED capability). Note that if the remote IP
# matches the local IP (ie. you're connecting from the same computer), the
# connection is considered secure and plaintext authentication is allowed.
disable_plaintext_auth = yes

# Space separated list of wanted authentication mechanisms:
#   plain login digest-md5 cram-md5 ntlm rpa apop anonymous gssapi otp
#   gss-spnego
# NOTE: See also disable_plaintext_auth setting.
auth_mechanisms = plain login

# Number of login attempts allowed before disconnecting
auth_failure_delay = 2 secs

##
## Password and user databases
##

#!include auth-deny.conf.ext
#!include auth-master.conf.ext

!include auth-system.conf.ext
!include auth-sql.conf.ext
#!include auth-ldap.conf.ext
#!include auth-passwdfile.conf.ext
#!include auth-checkpassword.conf.ext
#!include auth-static.conf.ext

# Default realm
auth_default_realm = $DOMAIN

# Authentication policy
auth_policy_server_url =
auth_policy_server_api_header =
auth_policy_server_timeout_msecs = 2000

# Enable debugging
#auth_debug = yes
#auth_debug_passwords = yes
EOF
    
    # Configure SQL authentication
    cat << EOF > /etc/dovecot/conf.d/auth-sql.conf.ext
# Authentication for SQL users
# Included from 10-auth.conf

passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}

userdb {
  driver = static
  args = uid=5000 gid=5000 home=/var/mail/vhosts/%d/%n
}

# Prefetch (so user's mailbox can be accessed right after login):
userdb {
  driver = prefetch
}
EOF
    
    print_info "Authentication configuration updated"
}

# Function to configure SQL settings
configure_sql_conf() {
    print_info "Configuring Dovecot SQL settings..."
    
    # Create SQL configuration
    cat << EOF > /etc/dovecot/dovecot-sql.conf.ext
# Database driver: mysql, pgsql, sqlite
driver = pgsql

# Database connection string
connect = host=127.0.0.1 dbname=mailbox user=$POSTGRES_USER password=$POSTGRES_PASSWORD

# Default password scheme
default_pass_scheme = SHA512-CRYPT

# Password query
password_query = SELECT email as user, password FROM mailbox.users WHERE email='%u' AND active=TRUE

# User query
user_query = SELECT \
  email, \
  5000 AS uid, \
  5000 AS gid, \
  CONCAT('/var/mail/vhosts/', '%d', '/', SUBSTRING_INDEX('%u', '@', 1)) AS home, \
  'maildir:~/Maildir' AS mail, \
  CONCAT('*:bytes=', quota, 'M') AS quota_rule \
FROM mailbox.users \
WHERE email = '%u' AND active = TRUE

# If using quota
iterate_query = SELECT email as username FROM mailbox.users WHERE active=TRUE

# Password reset query (for IMAP RESETPASSWORD extension)
#password_reset_query = UPDATE mailbox.users SET password=%w WHERE email='%u'
EOF
    
    # Set proper permissions
    chown root:dovecot /etc/dovecot/dovecot-sql.conf.ext
    chmod 640 /etc/dovecot/dovecot-sql.conf.ext
    
    print_info "SQL configuration created"
}

# Function to configure SSL settings
configure_ssl_conf() {
    print_info "Configuring Dovecot SSL settings..."
    
    # Update 10-ssl.conf
    cat << EOF > /etc/dovecot/conf.d/10-ssl.conf
##
## SSL settings
##

# SSL/TLS support: yes, no, required. <doc/wiki/SSL.txt>
ssl = required

# PEM encoded X.509 SSL/TLS certificate and private key
ssl_cert = </etc/letsencrypt/live/mail.$DOMAIN/fullchain.pem
ssl_key = </etc/letsencrypt/live/mail.$DOMAIN/privkey.pem

# If key file is password protected, give the password here
#ssl_key_password =

# Colon separated list of valid ciphers
# DH parameters length to use.
ssl_dh = </etc/ssl/certs/dhparam.pem

# SSL protocols to use
ssl_protocols = !SSLv2 !SSLv3 !TLSv1 !TLSv1.1 TLSv1.2 TLSv1.3

# SSL ciphers to use
ssl_cipher_list = ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS

# Prefer the server's order of ciphers over client's.
ssl_prefer_cipher_order = yes

# SSL extra options. Currently supported options are:
#   no_compression - Disable compression.
ssl_options = no_compression

# Minimum SSL protocol version to accept
ssl_min_protocol = TLSv1.2
EOF
    
    print_info "SSL configuration updated"
}

# Function to configure master service
configure_master_conf() {
    print_info "Configuring Dovecot master service..."
    
    # Update 10-master.conf
    cat << EOF > /etc/dovecot/conf.d/10-master.conf
#default_process_limit = 100
#default_client_limit = 1000

# Default VSZ (virtual memory size) limit for service processes
default_vsz_limit = 256M

# Login processes
service imap-login {
  inet_listener imap {
    port = 0
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }

  # Number of connections to handle before starting a new process
  service_count = 1

  # Number of processes to always keep waiting for more connections
  process_min_avail = 0

  # If you set service_count=0, you probably need to grow this.
  vsz_limit = \$default_vsz_limit
}

service pop3-login {
  inet_listener pop3 {
    port = 0
    ssl = yes
  }
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}

service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }

  # Create inet listener only if you can't use the above UNIX socket
  #inet_listener lmtp {
    # Avoid making LMTP visible for the entire internet
    #address =
    #port = 
  #}
}

service imap {
  # Most of the memory goes to mmap()ing files. You may need to increase this
  # limit if you have huge mailboxes.
  vsz_limit = \$default_vsz_limit

  # Max. number of IMAP processes (connections)
  process_limit = 1024
}

service pop3 {
  # Max. number of POP3 processes (connections)
  process_limit = 1024
}

service auth {
  # auth_socket_path points to this userdb socket by default. It's typically
  # used by dovecot-lda, doveadm, possibly imap process, etc. Its default
  # permissions make it readable only by root, but you may need to relax these
  # permissions. Users that have access to this socket are able to get a list
  # of all usernames and get results of everyone's userdb lookups.
  unix_listener auth-userdb {
    mode = 0600
    user = vmail
    #group = 
  }

  # Postfix smtp-auth
  unix_listener /var/spool/postfix/private/auth {
    mode = 0666
    user = postfix
    group = postfix
  }

  # Auth process is run as this user.
  user = dovecot
}

service auth-worker {
  # Auth worker process is run as root by default, so that it can access
  # /etc/shadow. If this isn't necessary, the user should be changed to
  # \$default_internal_user.
  user = vmail
}

service dict {
  # If dict proxy is used, this limits the number of active connections.
  process_limit = 128

  # If dict proxy is used, mail processes should have access to its socket.
  unix_listener dict {
    mode = 0600
    user = vmail
    #group = 
  }
}
EOF
    
    print_info "Master service configuration updated"
}

# Function to configure Sieve settings
configure_sieve_conf() {
    print_info "Configuring Sieve settings..."
    
    # Install Sieve if not already installed
    apt-get install -y dovecot-sieve dovecot-managesieved
    
    # Create Sieve configuration
    cat << EOF > /etc/dovecot/conf.d/90-sieve.conf
##
## Settings for the Sieve interpreter
##

# Do not forget to enable the Sieve plugin in 15-lda.conf and 20-lmtp.conf
# by adding it to the respective mail_plugins= settings.

# The Sieve interpreter can retrieve Sieve scripts from several types of
# locations.
plugin {
  # The location of a global script that is executed for each user that
  # runs a script.
  #sieve_global_script_dir =

  # A location that marks the default script that is executed when the user
  # has no active script.
  sieve_default = /var/mail/vhosts/%d/%n/.dovecot.sieve

  # The location of the user's main active script.
  sieve = file:~/sieve;active=~/.dovecot.sieve

  # The location where the user stores Sieve filters.
  #sieve_dir = ~/sieve

  # Notifications
  #sieve_notify = mailto
  #sieve_notify_mailto_envelope_from = sieve-notify@<domain>

  # If you use Sieve vacation, check these settings
  sieve_vacation_default_period = 1d
  sieve_vacation_max_period = 30d
  sieve_vacation_min_period = 10m
}

# The following plugin is only compiled when building against
# Dovecot v2.1.10 or later and configures the ManageSieve protocol
plugin {
  # The ManageSieve service primarily acts as a proxy to the Sieve plugin
  # below, but has a few additional settings.
  
  # To fool ManageSieve clients that are focused on Cyrus:
  #managesieve_sieve_capability = "fileinto reject envelope encoded-character vacation subaddress comparator-i;ascii-numeric relational regex imap4flags copy include variables body enotify environment mailbox date"
  
  # Quota for all sieve scripts (count).
  sieve_max_script_count = 20
  
  # Quota for all sieve scripts (in bytes).
  sieve_max_script_size = 1M
}

# Add ManageSieve service
service managesieve-login {
  inet_listener sieve {
    port = 4190
  }
}

service managesieve {
  # Limit the number of ManageSieve connections per IP address
  process_limit = 1024
}
EOF
    
    # Update LDA configuration to include Sieve
    if [[ -f /etc/dovecot/conf.d/15-lda.conf ]]; then
        sed -i 's/^#mail_plugins = \$mail_plugins$/mail_plugins = \$mail_plugins sieve/' /etc/dovecot/conf.d/15-lda.conf
    fi
    
    # Update LMTP configuration to include Sieve
    if [[ -f /etc/dovecot/conf.d/20-lmtp.conf ]]; then
        sed -i 's/^#mail_plugins = \$mail_plugins$/mail_plugins = \$mail_plugins sieve/' /etc/dovecot/conf.d/20-lmtp.conf
    fi
    
    print_info "Sieve configuration completed"
}

# Function to configure quota settings
configure_quota_conf() {
    print_info "Configuring quota settings..."
    
    # Create quota configuration
    cat << EOF > /etc/dovecot/conf.d/90-quota.conf
##
## Quota configuration
##

# Note that you also have to enable quota plugin in mail_plugins setting
# for the quota to work.

plugin {
  # Quota limits are set using "quota_rule" parameters. To get per-user quota
  # limits, you can set/override them by returning "quota_rule" extra field
  # from userdb.
  
  # Backend for the quota calculation. Can be "count", "dirsize" or "maildir".
  quota = count:User quota

  # Default quota rule
  quota_rule = *:storage=1000M

  # You can also include messages by pattern:
  #quota_rule2 = Trash:storage=+100M
  #quota_rule3 = SPAM:ignore

  # Grace period for going over quota.
  #quota_grace = 1M

  # Quota warning messages. 0 means unlimited.
  quota_warning = storage=95%% quota-warning 95 %u
  quota_warning2 = storage=80%% quota-warning 80 %u

  # Quota return message
  quota_exceeded_message = Quota exceeded, please try again later.
}

# Execute the quota exceeded hook when the quota is exceeded
service quota-warning {
  executable = script /usr/local/bin/quota-warning.sh
  user = vmail
  unix_listener quota-warning {
    user = vmail
  }
}

# Quota dict for maintaining quota database
dict {
  #quota = mysql:/etc/dovecot/dovecot-dict-sql.conf.ext
  #expire = sqlite:/etc/dovecot/dovecot-dict-sql.conf.ext
}

# Quota status
service quota-status {
  executable = quota-status -p postfix
  inet_listener {
    port = 12340
  }
  client_limit = 1
}
EOF
    
    # Create quota warning script
    cat << 'EOF' > /usr/local/bin/quota-warning.sh
#!/bin/bash

PERCENT=$1
USER=$2
cat << END_OF_MESSAGE | /usr/lib/dovecot/dovecot-lda -d "$USER" -o "plugin/quota=count:User quota"
From: postmaster@$DOMAIN
Subject: Quota warning - $PERCENT% exceeded
Content-Type: text/plain; charset=UTF-8

Your mailbox is now $PERCENT% full. Please remove some emails to avoid exceeding your quota.

--
Automated message - do not reply
END_OF_MESSAGE
EOF
    
    chmod +x /usr/local/bin/quota-warning.sh
    
    # Enable quota plugin
    sed -i 's/^mail_plugins =/mail_plugins = quota/' /etc/dovecot/conf.d/10-mail.conf
    
    print_info "Quota configuration completed"
}

# Function to create log directories
create_log_directories() {
    print_info "Creating Dovecot log directories..."
    
    mkdir -p /var/log/dovecot
    chown syslog:adm /var/log/dovecot
    chmod 750 /var/log/dovecot
    
    # Create logrotate configuration
    cat << EOF > /etc/logrotate.d/dovecot
/var/log/dovecot/*.log {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    postrotate
        /bin/kill -USR1 \`cat /var/run/dovecot/master.pid 2>/dev/null\` 2> /dev/null || true
    endscript
}
EOF
    
    print_info "Log directories and rotation configured"
}

# Function to set proper permissions
set_dovecot_permissions() {
    print_info "Setting Dovecot permissions..."
    
    # Set ownership and permissions
    chown -R root:root /etc/dovecot
    chmod -R o-rwx /etc/dovecot
    chmod 640 /etc/dovecot/dovecot-sql.conf.ext
    
    # Mail directory permissions
    chown -R vmail:vmail /var/mail/vhosts
    chmod 750 /var/mail/vhosts
    
    print_info "Permissions set successfully"
}

# Function to test Dovecot configuration
test_dovecot_config() {
    print_info "Testing Dovecot configuration..."
    
    # Test configuration syntax
    if doveconf -n > /dev/null 2>&1; then
        print_info "✓ Dovecot configuration syntax OK"
    else
        print_error "✗ Dovecot configuration has errors"
        doveconf -n
        return 1
    fi
    
    # Test SQL connectivity
    print_info "Testing SQL connectivity..."
    if doveadm auth test postmaster@$DOMAIN $(cat /etc/email-server/postmaster-password.txt) >/dev/null 2>&1; then
        print_info "✓ SQL authentication test successful"
    else
        print_warning "! SQL authentication test failed - verify database setup"
    fi
    
    # Create test report
    cat << EOF > /etc/email-server/dovecot-test-report.txt
Dovecot Configuration Test Report
Generated on: $(date)

Configuration Status:
- Syntax check: $(if doveconf -n > /dev/null 2>&1; then echo "OK"; else echo "ERROR"; fi)
- SQL connectivity: $(if doveadm auth test postmaster@$DOMAIN $(cat /etc/email-server/postmaster-password.txt) >/dev/null 2>&1; then echo "OK"; else echo "FAILED"; fi)

Listening Services:
$(netstat -tlnp | grep -E "(dovecot|993|995|4190)")

Active Configuration:
$(doveconf -n)

SSL Certificate:
- Path: $(doveconf -h ssl_cert)
- Protocols: $(doveconf -h ssl_protocols)
- Ciphers: $(doveconf -h ssl_cipher_list)

Mail Location:
- Type: $(doveconf -h mail_location | cut -d: -f1)
- Location: $(doveconf -h mail_location | cut -d: -f2-)
EOF
    
    print_info "Test report created: /etc/email-server/dovecot-test-report.txt"
}

# Function to start and enable Dovecot
start_dovecot() {
    print_info "Starting and enabling Dovecot..."
    
    # Reload systemd
    systemctl daemon-reload
    
    # Start Dovecot
    systemctl start dovecot
    
    # Enable Dovecot to start on boot
    systemctl enable dovecot
    
    # Check status
    if systemctl is-active --quiet dovecot; then
        print_info "✓ Dovecot is running"
    else
        print_error "✗ Dovecot failed to start"
        systemctl status dovecot
        return 1
    fi
    
    print_info "Dovecot started and enabled successfully"
}

# Main execution
print_info "Starting Dovecot configuration..."

# Backup existing configuration
backup_dovecot_config

# Create vmail user
create_vmail_user

# Configure Dovecot
configure_dovecot_conf
configure_mail_conf
configure_auth_conf
configure_sql_conf
configure_ssl_conf
configure_master_conf
configure_sieve_conf
configure_quota_conf

# Create log directories
create_log_directories

# Set permissions
set_dovecot_permissions

# Test configuration
test_dovecot_config

# Start Dovecot
start_dovecot

print_info "Dovecot configuration complete!"
print_info "Important files:"
echo "  - Main config: /etc/dovecot/dovecot.conf"
echo "  - SQL config: /etc/dovecot/dovecot-sql.conf.ext"
echo "  - SSL certificates: $(doveconf -h ssl_cert)"
echo "  - Mail location: /var/mail/vhosts/$DOMAIN"
echo "  - Test report: /etc/email-server/dovecot-test-report.txt"

print_warning "Next steps:"
echo "1. Verify Dovecot is listening on ports 993, 995"
echo "2. Test IMAP/POP3 authentication"
echo "3. Check logs: /var/log/dovecot/"
echo "4. Test email delivery with Postfix"
