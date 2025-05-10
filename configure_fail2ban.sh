#!/bin/bash

# Script to configure Fail2Ban for the email server
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

# Function to install Fail2Ban
install_fail2ban() {
    print_info "Installing Fail2Ban..."
    
    # Check if already installed
    if command -v fail2ban-server &> /dev/null; then
        print_info "Fail2Ban is already installed"
        return 0
    fi
    
    # Install Fail2Ban
    apt-get update
    apt-get install -y fail2ban fail2ban-firewalld
    
    print_info "Fail2Ban installed successfully"
}

# Function to backup Fail2Ban configuration
backup_fail2ban_config() {
    print_info "Backing up Fail2Ban configuration..."
    
    BACKUP_DIR_F2B="$BACKUP_DIR/config/fail2ban-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR_F2B"
    
    # Backup existing configuration if it exists
    if [[ -d /etc/fail2ban ]]; then
        cp -r /etc/fail2ban "$BACKUP_DIR_F2B/"
    fi
    
    print_info "Fail2Ban configuration backed up to $BACKUP_DIR_F2B"
}

# Function to create Fail2Ban local configuration
create_fail2ban_local() {
    print_info "Creating Fail2Ban local configuration..."
    
    # Create jail.local file
    cat << EOF > /etc/fail2ban/jail.local
# Fail2Ban configuration for email server
# Custom settings for mail server protection

[DEFAULT]
# Ban hosts for one hour:
bantime = 3600

# A host is banned if it has generated "maxretry" during the last "findtime"
findtime = 600
maxretry = 5

# "backend" specifies the backend used to get files modification.
backend = %(syslog_backend)s

# Email notification settings
sender = fail2ban@$DOMAIN
destemail = $ADMIN_EMAIL
mta = sendmail
action = %(action_mwl)s

# Whitelist IPs
ignoreip = 127.0.0.1/8 ::1
EOF

    # Add VPN network to whitelist if enabled
    if [[ "$ENABLE_VPN" == "true" ]]; then
        echo "# VPN network whitelist" >> /etc/fail2ban/jail.local
        echo "ignoreip = 127.0.0.1/8 ::1 $VPN_NETWORK" >> /etc/fail2ban/jail.local
    fi
    
    cat << EOF >> /etc/fail2ban/jail.local

# SSH jail
[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s

# Postfix jails
[postfix]
enabled = true
port = smtp,ssmtp,submission
logpath = /var/log/mail.log
backend = %(postfix_backend)s

[postfix-auth]
enabled = true
port = smtp,ssmtp,submission
logpath = /var/log/mail.log
backend = %(postfix_backend)s

[postfix-sasl]
enabled = true
port = smtp,ssmtp,submission
logpath = /var/log/mail.log
mode = more
backend = %(postfix_backend)s
filter = postfix[mode=auth]

# Dovecot jails
[dovecot]
enabled = true
port = pop3,pop3s,imap,imaps,submission,submissions
logpath = /var/log/mail.log
backend = %(dovecot_backend)s

[dovecot-auth]
enabled = true
port = pop3,pop3s,imap,imaps,submission,submissions
logpath = /var/log/mail.log
backend = %(dovecot_backend)s

# SpamAssassin jail
[spamassassin]
enabled = true
port = submission,submissions
logpath = /var/log/mail.log
backend = %(spamd_backend)s

# Apache jail (if web server is installed)
[apache-badbots]
enabled = true
port = http,https
logpath = %(apache_error_log)s
maxretry = 3

[apache-auth]
enabled = true
port = http,https
logpath = %(apache_error_log)s

# Custom email-specific jails
[email-flood]
enabled = true
filter = email-flood
logpath = /var/log/mail.log
maxretry = 10
findtime = 120
bantime = 7200
action = %(action_mwl)s

[email-spam]
enabled = true
filter = email-spam
logpath = /var/log/mail.log
maxretry = 5
findtime = 300
bantime = 86400
action = %(action_mwl)s
EOF
    
    print_info "jail.local configuration created"
}

# Function to create custom filters
create_custom_filters() {
    print_info "Creating custom Fail2Ban filters..."
    
    # Create email flood filter
    cat << 'EOF' > /etc/fail2ban/filter.d/email-flood.conf
# Fail2Ban filter for email flooding
[Definition]
failregex = ^<HOST>.*reject: RCPT from.*too many recipients
            ^<HOST>.*blocked using.*;.*blacklisted
            ^<HOST>.*: Helo command rejected: need fully-qualified hostname

ignoreregex =
EOF
    
    # Create spam filter
    cat << 'EOF' > /etc/fail2ban/filter.d/email-spam.conf
# Fail2Ban filter for spam detection
[Definition]
failregex = ^<HOST>.*reject: RCPT from.*Spam detected
            ^<HOST>.*reject: Message rejected due to spam content
            ^<HOST>.*Greylisting in action.*deferring message
            ^<HOST>.*SpamAssassin identified this incoming email as possible spam

ignoreregex =
EOF
    
    # Create custom Postfix reject filter
    cat << 'EOF' > /etc/fail2ban/filter.d/postfix-reject.conf
# Fail2Ban filter for additional Postfix rejections
[Definition]
failregex = ^<HOST>.*reject: RCPT from.*: 554.*rejected
            ^<HOST>.*reject: RCPT from.*: 550.*rejecting
            ^<HOST>.*reject: unknown user
            ^<HOST>.*reject: authentication failure
            ^<HOST>.*reject: improper command pipelining
            ^<HOST>.*reject: too many errors

ignoreregex =
EOF
    
    # Create advanced Dovecot filter
    cat << 'EOF' > /etc/fail2ban/filter.d/dovecot-advanced.conf
# Advanced Dovecot filter for email server
[Definition]
_daemon = (imap|pop3|managesieve|submission)(-login)?
failregex = ^%(__prefix_line)s(pam_\w+\(\1\[\d+\]\): )?authentication failure; logname=\S* uid=\S* euid=\S* tty=dovecot ruser=\S* rhost=<HOST>(\s+user=\S*)?\s*$
            ^%(__prefix_line)sauth-worker\(\d+\): pam_\w+\(\1:[^)]+\): authentication error for \S+ from <HOST>: \S+$
            ^%(__prefix_line)sdisconnected \(auth failed, \d+ attempts in \d+ secs\): user=\S+, method=\S+, rip=<HOST>, lip=\S+, TLS, session=\S+$
            ^%(__prefix_line)saborted login \(auth failed, \d+ attempts in \d+ secs\): user=\S+, method=\S+, rip=<HOST>, lip=\S+$

ignoreregex =

[Init]
# Author: Daniel Black and others
# Refined by email server administrators
journalmatch = _SYSTEMD_UNIT=dovecot.service SYSLOG_IDENTIFIER=dovecot
datepattern = {^LN-BEG}%%Y-%%m-%%d %%H:%%M:%%S
EOF
    
    print_info "Custom filters created"
}

# Function to create custom actions
create_custom_actions() {
    print_info "Creating custom Fail2Ban actions..."
    
    # Create email notification action
    cat << 'EOF' > /etc/fail2ban/action.d/email-notify.conf
# Custom email notification action for Fail2Ban
[Definition]
actionstart = printf %%b "Fail2Ban on <fq-hostname> has started.\nBanned services: <name>" | mail -s "[Fail2Ban] Service Started: <name>" <dest>

actionstop = printf %%b "Fail2Ban on <fq-hostname> has stopped.\n" | mail -s "[Fail2Ban] Service Stopped: <name>" <dest>

actioncheck =

actionban = printf %%b "The IP <ip> has just been banned by Fail2Ban for <bantime> seconds after <failures> attempts against <name>.\n\nDetails:\n- IP: <ip>\n- Failures: <failures>\n- Time: <time>\n- Service: <name>\n- Protocol: <protocol>\n- Port: <port>\n\nLog lines:\n<matches>" | mail -s "[Fail2Ban] Banned IP: <ip> on <name>" <dest>

actionunban = printf %%b "The IP <ip> has been unbanned for service <name>.\n" | mail -s "[Fail2Ban] Unbanned IP: <ip> on <name>" <dest>

[Init]
name = default
dest = root@localhost
protocol = tcp
chain = <known/chain>
port = 0
bantime = 3600
EOF
    
    # Create detailed log action
    cat << 'EOF' > /etc/fail2ban/action.d/log-detail.conf
# Detailed logging action for Fail2Ban
[Definition]
actionstart = printf %%b "Subject: [Fail2Ban] Service Started: <name>\n\nFail2Ban service <name> has started on <fq-hostname>.\nService: <name>\nTime: <time>\nTotal banned IPs: $(f2b_banned_count <name>)" | /usr/sbin/sendmail <dest>

actionstop = printf %%b "Subject: [Fail2Ban] Service Stopped: <name>\n\nFail2Ban service <name> has stopped on <fq-hostname>.\nService: <name>\nTime: <time>" | /usr/sbin/sendmail <dest>

actioncheck =

actionban = (
    # Log ban to detailed log file
    echo "[$(date)] BAN: IP <ip> banned for <bantime>s after <failures> attempts on <name> service" >> /var/log/fail2ban/detailed.log
    
    # Send email notification
    printf %%b "Subject: [Fail2Ban] IP BANNED: <ip> on <name>\n\nIP Address: <ip>\nService: <name>\nPort: <port>\nFailures: <failures>\nBan Duration: <bantime> seconds\nTime: <time>\nHostname: <fq-hostname>\n\nMatches:\n<matches>\n\nTotal current bans for <name>: $(fail2ban-client status <name> | grep "Currently banned" | cut -f2)" | /usr/sbin/sendmail <dest>
)

actionunban = (
    # Log unban to detailed log file
    echo "[$(date)] UNBAN: IP <ip> unbanned from <name> service" >> /var/log/fail2ban/detailed.log
    
    # Send email notification
    printf %%b "Subject: [Fail2Ban] IP UNBANNED: <ip> on <name>\n\nIP Address: <ip>\nService: <name>\nTime: <time>\nHostname: <fq-hostname>" | /usr/sbin/sendmail <dest>
)

[Init]
name = default
dest = root@localhost
EOF
    
    print_info "Custom actions created"
}

# Function to configure UFW integration
configure_ufw_integration() {
    print_info "Configuring UFW integration with Fail2Ban..."
    
    # Create UFW action for Fail2Ban
    cat << 'EOF' > /etc/fail2ban/action.d/ufw.conf
# UFW action for Fail2Ban
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = ufw insert 1 deny from <ip> to any comment "Fail2Ban: %(name)s"
actionunban = ufw delete deny from <ip> to any
EOF
    
    # Update jail.local to use UFW action
    sed -i 's/action = %(action_mwl)s/action = %(action_mwl)s\n    ufw/' /etc/fail2ban/jail.local
    
    print_info "UFW integration configured"
}

# Function to create monitoring script
create_fail2ban_monitoring() {
    print_info "Creating Fail2Ban monitoring script..."
    
    cat << 'EOF' > /usr/local/bin/monitor-fail2ban.sh
#!/bin/bash

# Fail2Ban monitoring script
# Part of email server setup automation

set -euo pipefail

LOG_FILE="/var/log/email-server-setup/fail2ban-monitor.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Function to log messages
log_message() {
    echo "[$DATE] $1" | tee -a "$LOG_FILE"
}

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Check Fail2Ban service status
if systemctl is-active --quiet fail2ban; then
    log_message "Fail2Ban service is running"
else
    log_message "ERROR: Fail2Ban service is not running"
    systemctl status fail2ban >> "$LOG_FILE"
fi

# Get overall status
status_output=$(fail2ban-client status)
log_message "Fail2Ban status:"
echo "$status_output" >> "$LOG_FILE"

# Check each jail
jails=$(fail2ban-client status | grep "Jail list:" | cut -f2- | tr -d '\t' | tr ',' '\n')
for jail in $jails; do
    jail_status=$(fail2ban-client status $jail)
    banned_count=$(echo "$jail_status" | grep "Currently banned" | cut -f2)
    total_banned=$(echo "$jail_status" | grep "Total banned" | cut -f2)
    
    log_message "Jail: $jail - Currently banned: $banned_count, Total banned: $total_banned"
    
    # List currently banned IPs for this jail
    if [[ $banned_count -gt 0 ]]; then
        banned_ips=$(echo "$jail_status" | grep "Banned IP list" | cut -f2-)
        log_message "  Banned IPs: $banned_ips"
    fi
done

# Check for recent bans (last 24 hours)
recent_bans=$(grep -i "ban" /var/log/fail2ban.log | grep "$(date -d '1 day ago' +%Y-%m-%d)" | wc -l)
log_message "Bans in last 24 hours: $recent_bans"

# Check for errors in Fail2Ban log
error_count=$(grep -i error /var/log/fail2ban.log | grep "$(date +%Y-%m-%d)" | wc -l)
if [[ $error_count -gt 0 ]]; then
    log_message "WARNING: $error_count errors found in Fail2Ban log today"
    echo "Recent errors:" >> "$LOG_FILE"
    grep -i error /var/log/fail2ban.log | grep "$(date +%Y-%m-%d)" | tail -5 >> "$LOG_FILE"
fi

# Create summary report
cat << SUMMARY >> "$LOG_FILE"

Daily Fail2Ban Summary for $(date +%Y-%m-%d)
============================================
Active jails: $(echo "$jails" | wc -l)
Total current bans: $(fail2ban-client status | grep "Currently banned" | awk '{sum+=$NF} END {print sum}')
Total bans (all time): $(fail2ban-client status | grep "Total banned" | awk '{sum+=$NF} END {print sum}')
Bans in last 24h: $recent_bans
Errors today: $error_count

Top banned IPs (last 7 days):
$(grep -i "ban" /var/log/fail2ban.log | grep -P "$(date -d '7 days ago' +%Y-%m-%d)|$(date +%Y-%m-%d)" | awk '{print $7}' | sort | uniq -c | sort -nr | head -10)

SUMMARY

log_message "Fail2Ban monitoring check completed"
echo "----------------------------------------" >> "$LOG_FILE"
EOF
    
    chmod +x /usr/local/bin/monitor-fail2ban.sh
    
    # Add to crontab for daily monitoring
    (crontab -l 2>/dev/null; echo "0 5 * * * /usr/local/bin/monitor-fail2ban.sh") | crontab -
    
    print_info "Fail2Ban monitoring configured"
}

# Function to create management script
create_fail2ban_management() {
    print_info "Creating Fail2Ban management script..."
    
    cat << 'EOF' > /usr/local/bin/manage-fail2ban.sh
#!/bin/bash

# Fail2Ban management script
# Usage: manage-fail2ban.sh <command> [options]

set -euo pipefail

# Function to display help
show_help() {
    cat << HELP
Fail2Ban Management Script
=========================

Usage: $0 <command> [options]

Commands:
  status              Show overall Fail2Ban status
  list                List all active jails
  banned <jail>       Show banned IPs for a specific jail
  unban <ip> <jail>   Unban an IP from a specific jail
  test <jail>         Test a jail configuration
  reload              Reload Fail2Ban configuration
  stats               Show detailed statistics
  top                 Show most banned IPs
  help                Show this help message

Examples:
  $0 status
  $0 banned postfix
  $0 unban 192.168.1.100 ssh
  $0 test sshd
  $0 stats
HELP
}

# Function to show status
show_status() {
    echo "Fail2Ban Service Status:"
    echo "======================="
    systemctl status fail2ban --no-pager
    echo
    echo "Overall Status:"
    echo "=============="
    fail2ban-client status
}

# Function to list jails
list_jails() {
    echo "Active Jails:"
    echo "============"
    jails=$(fail2ban-client status | grep "Jail list:" | cut -f2- | tr -d '\t' | tr ',' '\n')
    for jail in $jails; do
        status=$(fail2ban-client status $jail)
        banned=$(echo "$status" | grep "Currently banned" | cut -f2)
        total=$(echo "$status" | grep "Total banned" | cut -f2)
        echo "- $jail: $banned currently banned, $total total banned"
    done
}

# Function to show banned IPs
show_banned() {
    if [[ $# -ne 1 ]]; then
        echo "Usage: $0 banned <jail>"
        exit 1
    fi
    
    jail="$1"
    echo "Banned IPs for jail '$jail':"
    echo "=========================="
    fail2ban-client status "$jail"
}

# Function to unban IP
unban_ip() {
    if [[ $# -ne 2 ]]; then
        echo "Usage: $0 unban <ip> <jail>"
        exit 1
    fi
    
    ip="$1"
    jail="$2"
    echo "Unbanning $ip from jail '$jail'..."
    fail2ban-client set "$jail" unbanip "$ip"
    echo "Successfully unbanned $ip from $jail"
}

# Function to test jail
test_jail() {
    if [[ $# -ne 1 ]]; then
        echo "Usage: $0 test <jail>"
        exit 1
    fi
    
    jail="$1"
    echo "Testing jail '$jail'..."
    fail2ban-client --test start "$jail"
}

# Function to reload configuration
reload_config() {
    echo "Reloading Fail2Ban configuration..."
    fail2ban-client reload
    echo "Configuration reloaded successfully"
}

# Function to show statistics
show_statistics() {
    echo "Fail2Ban Statistics:"
    echo "==================="
    
    # Overall stats
    total_current=$(fail2ban-client status | grep "Currently banned" | awk '{sum+=$NF} END {print sum}')
    total_all_time=$(fail2ban-client status | grep "Total banned" | awk '{sum+=$NF} END {print sum}')
    
    echo "Total current bans: $total_current"
    echo "Total all-time bans: $total_all_time"
    echo
    
    # Per-jail stats
    echo "Per-jail statistics:"
    echo "-------------------"
    jails=$(fail2ban-client status | grep "Jail list:" | cut -f2- | tr -d '\t' | tr ',' '\n')
    for jail in $jails; do
        status=$(fail2ban-client status "$jail")
        files=$(echo "$status" | grep "Files" | cut -f2-)
        currently_failed=$(echo "$status" | grep "Currently failed" | cut -f2)
        total_failed=$(echo "$status" | grep "Total failed" | cut -f2)
        currently_banned=$(echo "$status" | grep "Currently banned" | cut -f2)
        total_banned=$(echo "$status" | grep "Total banned" | cut -f2)
        
        echo "$jail:"
        echo "  Files: $files"
        echo "  Currently failed: $currently_failed"
        echo "  Total failed: $total_failed"
        echo "  Currently banned: $currently_banned"
        echo "  Total banned: $total_banned"
        echo
    done
}

# Function to show top banned IPs
show_top_banned() {
    echo "Top Banned IPs (last 7 days):"
    echo "============================="
    if [[ -f /var/log/fail2ban.log ]]; then
        grep -i "ban" /var/log/fail2ban.log | \
            grep -P "$(date -d '7 days ago' +%Y-%m-%d)|$(date +%Y-%m-%d)" | \
            grep -oP 'Ban \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
            sort | uniq -c | sort -nr | head -20 | \
            awk '{printf "%-20s %s\n", $2, "(" $1 " bans)"}'
    else
        echo "No log file found"
    fi
}

# Main execution
case "${1:-}" in
    status)
        show_status
        ;;
    list)
        list_jails
        ;;
    banned)
        show_banned "${@:2}"
        ;;
    unban)
        unban_ip "${@:2}"
        ;;
    test)
        test_jail "${@:2}"
        ;;
    reload)
        reload_config
        ;;
    stats)
        show_statistics
        ;;
    top)
        show_top_banned
        ;;
    help|"")
        show_help
        ;;
    *)
        echo "Error: Unknown command '$1'"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/manage-fail2ban.sh
    
    print_info "Fail2Ban management script created"
}

# Function to configure log rotation
configure_log_rotation() {
    print_info "Configuring log rotation for Fail2Ban..."
    
    # Create logrotate configuration
    cat << EOF > /etc/logrotate.d/fail2ban-custom
/var/log/fail2ban.log {
    daily
    rotate 30
    missingok
    notifempty
    compress
    delaycompress
    postrotate
        fail2ban-client flushlogs 1>/dev/null
    endscript
}

/var/log/fail2ban/detailed.log {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
}

/var/log/email-server-setup/fail2ban-monitor.log {
    weekly
    rotate 8
    missingok
    notifempty
    compress
    delaycompress
}
EOF
    
    print_info "Log rotation configured"
}

# Function to test Fail2Ban configuration
test_fail2ban_configuration() {
    print_info "Testing Fail2Ban configuration..."
    
    # Test configuration
    if fail2ban-client --test start; then
        print_info "✓ Fail2Ban configuration is valid"
    else
        print_error "✗ Fail2Ban configuration has errors"
        return 1
    fi
    
    # Create test report
    cat << EOF > /etc/email-server/fail2ban-test-report.txt
Fail2Ban Configuration Test Report
==================================
Generated on: $(date)

Service Status:
---------------
- Fail2Ban daemon: $(systemctl is-active fail2ban)
- UFW integration: Enabled

Configuration:
--------------
- Main config: /etc/fail2ban/jail.local
- Custom filters: /etc/fail2ban/filter.d/
- Custom actions: /etc/fail2ban/action.d/

Active Jails:
-------------
$(fail2ban-client status | grep "Jail list:" | cut -f2-)

Current Statistics:
-------------------
$(fail2ban-client status)

Log Files:
----------
- Main log: /var/log/fail2ban.log
- Detailed log: /var/log/fail2ban/detailed.log
- Monitor log: /var/log/email-server-setup/fail2ban-monitor.log

Recent Activity:
----------------
$(tail -n 10 /var/log/fail2ban.log)
EOF
    
    print_info "Test report created: /etc/email-server/fail2ban-test-report.txt"
}

# Function to start and enable Fail2Ban
start_fail2ban() {
    print_info "Starting and enabling Fail2Ban..."
    
    # Start Fail2Ban
    systemctl start fail2ban
    
    # Enable Fail2Ban to start on boot
    systemctl enable fail2ban
    
    # Check status
    if systemctl is-active --quiet fail2ban; then
        print_info "✓ Fail2Ban is running"
    else
        print_error "✗ Fail2Ban failed to start"
        systemctl status fail2ban
        return 1
    fi
    
    print_info "Fail2Ban started and enabled successfully"
}

# Main execution
print_info "Starting Fail2Ban configuration..."

# Install Fail2Ban
install_fail2ban

# Backup existing configuration
backup_fail2ban_config

# Create configuration
create_fail2ban_local
create_custom_filters
create_custom_actions
configure_ufw_integration

# Create management tools
create_fail2ban_monitoring
create_fail2ban_management

# Configure log rotation
configure_log_rotation

# Test configuration
test_fail2ban_configuration

# Start and enable Fail2Ban
start_fail2ban

print_info "Fail2Ban configuration complete!"
print_info "Important files:"
echo "  - Configuration: /etc/fail2ban/jail.local"
echo "  - Custom filters: /etc/fail2ban/filter.d/"
echo "  - Custom actions: /etc/fail2ban/action.d/"
echo "  - Management script: /usr/local/bin/manage-fail2ban.sh"
echo "  - Monitor script: /usr/local/bin/monitor-fail2ban.sh"
echo "  - Test report: /etc/email-server/fail2ban-test-report.txt"

print_warning "Next steps:"
echo "1. Monitor bans with: fail2ban-client status"
echo "2. Check logs: tail -f /var/log/fail2ban.log"
echo "3. Use management script: manage-fail2ban.sh help"
echo "4. Test with intentional failures"
echo "5. Verify email notifications are working"

# Display current status
echo
echo "Fail2Ban Current Status:"
echo "======================="
fail2ban-client status
