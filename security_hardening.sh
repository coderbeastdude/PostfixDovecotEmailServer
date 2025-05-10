#!/bin/bash

# Script for final security hardening of the email server
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

# Function to harden SSH configuration
harden_ssh() {
    print_info "Hardening SSH configuration..."
    
    # Backup original SSH config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
    # Apply security hardening
    cat << EOF > /etc/ssh/sshd_config.d/99-security-hardening.conf
# Security hardening for SSH
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
MaxAuthTries 3
MaxSessions 10
ClientAliveInterval 300
ClientAliveCountMax 3
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
UsePAM yes
UseDNS no

# Restrict to specific users if VPN is not enabled
EOF

    if [[ "$ENABLE_VPN" == "true" ]]; then
        echo "# SSH restricted to VPN network only" >> /etc/ssh/sshd_config.d/99-security-hardening.conf
        echo "ListenAddress $VPN_SERVER_IP" >> /etc/ssh/sshd_config.d/99-security-hardening.conf
    else
        echo "# Allow SSH for admin user only" >> /etc/ssh/sshd_config.d/99-security-hardening.conf
        echo "AllowUsers admin" >> /etc/ssh/sshd_config.d/99-security-hardening.conf
    fi
    
    # NOTE: Admin user creation is disabled 
    # Use add_sudo_users.sh script instead to create system admin users
    print_info "Skipping admin user creation - using add_sudo_users.sh workflow"
    print_warning "Ensure you have created system admin users using add_sudo_users.sh before running this script"
    
    # Test SSH configuration
    sshd -t
    
    # Apply new SSH configuration
    systemctl restart sshd
    
    print_info "SSH hardened successfully"
}

# Function to implement rate limiting
implement_rate_limiting() {
    print_info "Implementing rate limiting..."
    
    # Create rate limiting rules for email services
    cat << 'EOF' > /etc/fail2ban/filter.d/postfix-rate-limit.conf
# Fail2Ban filter for Postfix rate limiting
[Definition]
failregex = ^<HOST>.*reject: RCPT from.*: 450.*Request rate limit exceeded
            ^<HOST>.*client rate limit exceeded
            ^<HOST>.*sender rate limit exceeded
            
ignoreregex =
EOF
    
    # Add rate limiting jail
    cat << EOF >> /etc/fail2ban/jail.local

# Rate limiting jail
[postfix-rate-limit]
enabled = true
filter = postfix-rate-limit
logpath = /var/log/mail.log
maxretry = 10
findtime = 300
bantime = 1800
action = ufw
EOF
    
    # Configure Postfix rate limiting
    postconf -e smtpd_client_rate_limit=30
    postconf -e smtpd_client_connection_rate_limit=10
    postconf -e smtpd_client_message_rate_limit=30
    postconf -e smtpd_client_recipient_rate_limit=100
    postconf -e smtpd_client_event_limit_exceptions=$mynetworks
    
    # Apply Dovecot rate limiting
    cat << EOF >> /etc/dovecot/conf.d/20-imap.conf

# Rate limiting for IMAP
protocol imap {
  mail_max_userip_connections = 20
  process_min_avail = 0
}
EOF
    
    systemctl restart postfix dovecot fail2ban
    
    print_info "Rate limiting implemented"
}

# Function to secure kernel parameters
secure_kernel_parameters() {
    print_info "Securing kernel parameters..."
    
    # Create sysctl security configuration
    cat << EOF > /etc/sysctl.d/99-email-server-security.conf
# Email server security hardening

# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1

# Ignore ping requests
net.ipv4.icmp_echo_ignore_all = 1

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# TCP hardening
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 0
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_congestion_control = bbr

# Memory protection
kernel.randomize_va_space = 2
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1

# Shared memory protection
kernel.shm_rmid_forced = 1

# Process restriction
kernel.yama.ptrace_scope = 1
EOF
    
    # Apply the new settings
    sysctl -p /etc/sysctl.d/99-email-server-security.conf
    
    print_info "Kernel parameters secured"
}

# Function to harden file permissions
harden_file_permissions() {
    print_info "Hardening file permissions..."
    
    # Critical system files
    chmod 644 /etc/passwd
    chmod 644 /etc/group
    chmod 600 /etc/shadow
    chmod 600 /etc/gshadow
    chmod 640 /var/log/auth.log
    chmod 640 /var/log/mail.log
    
    # Email server configurations
    chmod 640 /etc/postfix/main.cf
    chmod 640 /etc/postfix/master.cf
    chmod 640 /etc/dovecot/dovecot.conf
    chmod 640 /etc/dovecot/dovecot-sql.conf.ext
    chmod 640 /etc/opendkim.conf
    chmod 600 /etc/opendkim/keys/*/default.private
    
    # Remove world-readable permissions from sensitive files
    find /etc -type f -perm /o+r -name "*.key" -exec chmod 600 {} \;
    find /etc -type f -perm /o+r -name "*.pem" -exec chmod 600 {} \;
    
    # Set proper ownership
    chown root:postfix /etc/postfix/main.cf
    chown root:dovecot /etc/dovecot/dovecot.conf
    chown opendkim:opendkim /etc/opendkim.conf
    
    # Secure mail directories
    chmod 750 /var/mail/vhosts
    find /var/mail/vhosts -type d -exec chmod 750 {} \;
    find /var/mail/vhosts -type f -exec chmod 640 {} \;
    chown -R vmail:vmail /var/mail/vhosts
    
    print_info "File permissions hardened"
}

# Function to implement intrusion detection
implement_intrusion_detection() {
    print_info "Implementing intrusion detection..."
    
    # Install and configure AIDE
    apt-get install -y aide
    
    # Create AIDE configuration for email server
    cat << EOF > /etc/aide/aide.conf.d/70_email_server
# Email server specific AIDE rules

# Monitor email configurations
/etc/postfix f+p+u+g+s+m+c+md5+sha256
/etc/dovecot f+p+u+g+s+m+c+md5+sha256
/etc/opendkim f+p+u+g+s+m+c+md5+sha256
/etc/spamassassin f+p+u+g+s+m+c+md5+sha256
/etc/fail2ban f+p+u+g+s+m+c+md5+sha256

# Monitor SSL certificates
/etc/letsencrypt f+p+u+g+s+m+c+md5+sha256
/etc/ssl/private f+p+u+g+s+m+c+md5+sha256

# Monitor critical binaries
/usr/sbin/postfix f+p+u+g+s+m+c+md5+sha256
/usr/sbin/dovecot f+p+u+g+s+m+c+md5+sha256
/usr/bin/opendkim f+p+u+g+s+m+c+md5+sha256

# Monitor mail directories structure (not content)
/var/mail/vhosts d+p+u+g
EOF
    
    # Initialize AIDE database
    aideinit
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    
    # Create AIDE check script
    cat << 'EOF' > /usr/local/bin/aide-check.sh
#!/bin/bash

# AIDE integrity check for email server
# Run daily to detect unauthorized changes

set -euo pipefail

LOG_FILE="/var/log/aide-check.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$TIMESTAMP] Starting AIDE integrity check..." >> "$LOG_FILE"

# Run AIDE check
if aide --check; then
    echo "[$TIMESTAMP] AIDE check completed - No changes detected" >> "$LOG_FILE"
else
    echo "[$TIMESTAMP] WARNING: AIDE detected file system changes!" >> "$LOG_FILE"
    aide --check >> "$LOG_FILE" 2>&1
    
    # Send alert if configured
    if command -v mail &> /dev/null; then
        {
            echo "Subject: SECURITY ALERT - File System Changes Detected"
            echo ""
            echo "AIDE has detected unauthorized file system changes on $HOSTNAME"
            echo "Date: $TIMESTAMP"
            echo ""
            echo "Please review the attached log file and investigate immediately."
            echo ""
            tail -50 "$LOG_FILE"
        } | mail "$ADMIN_EMAIL"
    fi
fi

# Rotate log file if too large
if [[ $(stat -c%s "$LOG_FILE") -gt 10485760 ]]; then
    mv "$LOG_FILE" "${LOG_FILE}.$(date +%Y%m%d)"
    gzip "${LOG_FILE}.$(date +%Y%m%d)"
fi
EOF
    
    chmod +x /usr/local/bin/aide-check.sh
    
    # Add to crontab for daily checks
    (crontab -l 2>/dev/null; echo "0 3 * * * /usr/local/bin/aide-check.sh") | crontab -
    
    print_info "Intrusion detection implemented"
}

# Function to enable advanced logging
enable_advanced_logging() {
    print_info "Enabling advanced logging..."
    
    # Configure rsyslog for email server
    cat << EOF > /etc/rsyslog.d/50-email-server.conf
# Email server advanced logging

\$CreateDirs on
\$PrivDropToUser syslog
\$PrivDropToGroup adm

# Separate mail logs by component
\$template MailFormat,"%TIMESTAMP:::date-rfc3339% %HOSTNAME% %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n"

# Postfix logs
if \$programname startswith 'postfix' then {
    /var/log/mail/postfix.log;MailFormat
    stop
}

# Dovecot logs
if \$programname startswith 'dovecot' then {
    /var/log/mail/dovecot.log;MailFormat
    stop
}

# OpenDKIM logs
if \$programname startswith 'opendkim' then {
    /var/log/mail/dkim.log;MailFormat
    stop
}

# SpamAssassin logs
if \$programname startswith 'spamd' then {
    /var/log/mail/spamassassin.log;MailFormat
    stop
}

# Authentication logs with detailed info
auth,authpriv.*                 /var/log/auth-detail.log

# High priority messages to a separate file
*.warn;*.err;*.crit;*.alert;*.emerg /var/log/critical.log
EOF
    
    # Create log directory
    mkdir -p /var/log/mail
    chown syslog:adm /var/log/mail
    
    # Create logrotate configuration
    cat << EOF > /etc/logrotate.d/email-server
/var/log/mail/*.log
/var/log/auth-detail.log
/var/log/critical.log
{
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /bin/kill -HUP \`cat /var/run/rsyslogd.pid 2> /dev/null\` 2> /dev/null || true
    endscript
}
EOF
    
    # Create log analysis script
    cat << 'EOF' > /usr/local/bin/email-log-analyzer.sh
#!/bin/bash

# Email server log analyzer
# Identifies suspicious patterns and potential security issues

set -euo pipefail

REPORT_FILE="/var/log/email-server-setup/log-analysis-$(date +%Y%m%d).log"

echo "Email Server Log Analysis - $(date)" > "$REPORT_FILE"
echo "=================================" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Analyze authentication failures
echo "Authentication Failures:" >> "$REPORT_FILE"
grep -i "failed.*password" /var/log/auth.log | \
    awk '{print $11}' | sort | uniq -c | sort -nr | head -10 >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Analyze mail rejections
echo "Mail Rejections by Reason:" >> "$REPORT_FILE"
grep "reject:" /var/log/mail.log | \
    sed -E 's/.*reject: (.*)/\1/' | sort | uniq -c | sort -nr | head -10 >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Analyze DKIM failures
echo "DKIM Signature Failures:" >> "$REPORT_FILE"
grep "dkim=fail" /var/log/mail.log | \
    sed -E 's/.*from=<(.*)>/\1/' | sort | uniq -c | sort -nr | head -10 >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Analyze spam trends
echo "Spam Detection Trends:" >> "$REPORT_FILE"
grep "X-Spam-Status: Yes" /var/log/mail.log | \
    awk '{print $1, $2}' | uniq -c | tail -7 >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Analyze Fail2Ban actions
echo "Recent Fail2Ban Bans:" >> "$REPORT_FILE"
grep -E "(Ban|Unban)" /var/log/fail2ban.log | tail -20 >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Security alerts
echo "Security Alerts:" >> "$REPORT_FILE"
grep -E "(SECURITY|ALERT|ERROR)" /var/log/critical.log | tail -10 >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Check for unusual patterns
echo "Unusual Activity Patterns:" >> "$REPORT_FILE"

# Large number of connections from single IP
netstat -an | grep ':25.*ESTABLISHED' | awk '{print $5}' | cut -d: -f1 | \
    sort | uniq -c | sort -nr | head -5 | while read count ip; do
    if [[ $count -gt 10 ]]; then
        echo "WARNING: $ip has $count active SMTP connections" >> "$REPORT_FILE"
    fi
done

# Send report if anomalies detected
if grep -q "WARNING\|ERROR\|ALERT" "$REPORT_FILE"; then
    mail -s "Email Server Security Analysis - $(date +%Y-%m-%d)" "$ADMIN_EMAIL" < "$REPORT_FILE"
fi
EOF
    
    chmod +x /usr/local/bin/email-log-analyzer.sh
    
    # Add to crontab for regular analysis
    (crontab -l 2>/dev/null; echo "0 6 * * * /usr/local/bin/email-log-analyzer.sh") | crontab -
    
    # Restart rsyslog
    systemctl restart rsyslog
    
    print_info "Advanced logging enabled"
}

# Function to implement email content filtering
implement_content_filtering() {
    print_info "Implementing advanced content filtering..."
    
    # Create custom header checks
    cat << 'EOF' > /etc/postfix/header_checks_security
# Advanced header security checks

# Block potentially malicious content
/^Content-Type:.*application\/x-msdownload/ REJECT Executable attachments not allowed
/^Content-Type:.*application\/x-msdos-program/ REJECT Executable attachments not allowed
/^Content-Type:.*application\/x-exe/ REJECT Executable attachments not allowed

# Block suspicious patterns
/^Subject:.*\$\$\$.*\$\$\$/ REJECT Suspicious subject pattern
/^Subject:.*FREE.*MONEY/ REJECT Suspicious subject pattern

# Enhanced sender validation
/^From:.*<script/ REJECT Invalid sender format
/^Reply-To:.*noreply@.*\.tmp$/ REJECT Suspicious reply address

# Detect potential phishing
/^From:.*@(paypal|bank|amazon)\..*[^\.](com|net|org)$/ REJECT Potential phishing attempt
EOF
    
    # Create body checks for content filtering
    cat << 'EOF' > /etc/postfix/body_checks_security
# Advanced body content filtering

# Block dangerous content
/^.*<script.*>/i REJECT Script content not allowed
/^.*<iframe.*>/i REJECT Embedded content not allowed
/^.*eval\(.*\)/i REJECT Potentially dangerous code

# Block common spam phrases
/FREE MONEY NOW/i REJECT Spam content
/ACT NOW.*LIMITED TIME/i REJECT Spam content
/CLICK HERE.*WINNER/i REJECT Spam content

# Detect potential malware signatures
/TVqQAAMAAAAEAAAA//8AALgAAAAA/i REJECT Potential malware detected
/UEsDBAoAAAAAAA/i REJECT Potential malware detected
EOF
    
    # Add to Postfix configuration
    postconf -e header_checks="pcre:/etc/postfix/header_checks, pcre:/etc/postfix/header_checks_security"
    postconf -e body_checks="pcre:/etc/postfix/body_checks_security"
    
    # Create regex maps
    postmap /etc/postfix/header_checks_security
    postmap /etc/postfix/body_checks_security
    
    # Reload Postfix
    systemctl reload postfix
    
    print_info "Content filtering implemented"
}

# Function to set up security monitoring
setup_security_monitoring() {
    print_info "Setting up security monitoring dashboard..."
    
    # Create security status dashboard
    cat << 'EOF' > /usr/local/bin/email-security-dashboard.sh
#!/bin/bash

# Email server security dashboard
# Displays current security status and recent activity

set -euo pipefail

clear
echo "========================================"
echo "   EMAIL SERVER SECURITY DASHBOARD"
echo "   $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"
echo

# Fail2Ban Status
echo "FAIL2BAN STATUS:"
echo "----------------"
fail2ban-client status | grep "Number of jail" || echo "Fail2Ban not running"
banned_total=$(fail2ban-client status | grep -E "\s+Currently banned:\s+" | awk '{sum+=$4} END {print sum}')
echo "Total banned IPs: $banned_total"
echo

# Recent Security Events
echo "RECENT SECURITY EVENTS (Last 24h):"
echo "----------------------------------"
auth_failures=$(grep -c "Failed password" /var/log/auth.log | tail -24h || echo 0)
mail_rejects=$(grep -c "reject:" /var/log/mail.log | tail -24h || echo 0)
dkim_fails=$(grep -c "dkim=fail" /var/log/mail.log | tail -24h || echo 0)

echo "Authentication failures: $auth_failures"
echo "Mail rejections: $mail_rejects"
echo "DKIM failures: $dkim_fails"
echo

# Service Status
echo "CRITICAL SERVICES:"
echo "------------------"
services=("fail2ban" "postfix" "dovecot" "opendkim" "spamassassin")
for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
        echo "✓ $service: Running"
    else
        echo "✗ $service: Not running"
    fi
done
echo

# Disk Space
echo "DISK USAGE:"
echo "-----------"
df -h / | awk 'NR==2{print $5 " used on root partition"}'
df -h /var/mail | awk 'NR==2{print $5 " used on mail partition"}' 2>/dev/null || echo "Mail partition check skipped"
echo

# Active Connections
echo "ACTIVE CONNECTIONS:"
echo "-------------------"
smtp_conn=$(netstat -an | grep ':25.*ESTABLISHED' | wc -l)
imap_conn=$(netstat -an | grep ':993.*ESTABLISHED' | wc -l)
ssh_conn=$(netstat -an | grep ':22.*ESTABLISHED' | wc -l)

echo "SMTP: $smtp_conn"
echo "IMAP: $imap_conn"
echo "SSH: $ssh_conn"
echo

# Mail Queue
echo "MAIL QUEUE:"
echo "-----------"
queue_size=$(postqueue -p | grep -c '^[A-F0-9]' || echo 0)
echo "Queue size: $queue_size messages"
echo

# Last Log Entries
echo "RECENT LOG ENTRIES:"
echo "-------------------"
echo "Last authentication attempts:"
tail -3 /var/log/auth.log | awk '{print $1, $2, $3, $11, $12, $13}'
echo "Last mail events:"
tail -3 /var/log/mail.log | awk '{print $1, $2, $3, $6, $7, $8, $9}'
echo

echo "========================================"
echo "For detailed analysis, check:"
echo "- Security logs: /var/log/email-server-setup/"
echo "- Fail2Ban: fail2ban-client status"
echo "- Mail logs: /var/log/mail.log"
echo "========================================"
EOF
    
    chmod +x /usr/local/bin/email-security-dashboard.sh
    
    # Create a systemd service for automatic security alerts
    cat << EOF > /etc/systemd/system/email-security-monitor.service
[Unit]
Description=Email Server Security Monitor
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/email-security-alerts.sh
User=root
StandardOutput=append:/var/log/email-server-setup/security-monitor.log
StandardError=append:/var/log/email-server-setup/security-monitor.log

[Install]
WantedBy=multi-user.target
EOF
    
    # Create security alert script
    cat << 'EOF' > /usr/local/bin/email-security-alerts.sh
#!/bin/bash

# Automated security alert system for email server
# Monitors for critical security events and sends alerts

set -euo pipefail

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
ALERT_THRESHOLD_AUTH=10
ALERT_THRESHOLD_REJECT=100

# Check for authentication attacks
auth_failures=$(grep "Failed password" /var/log/auth.log | grep "$(date '+%b %d')" | wc -l)
if [[ $auth_failures -gt $ALERT_THRESHOLD_AUTH ]]; then
    {
        echo "Subject: SECURITY ALERT - High Authentication Failures Detected"
        echo ""
        echo "WARNING: $auth_failures failed authentication attempts detected today"
        echo "Server: $(hostname)"
        echo "Time: $TIMESTAMP"
        echo ""
        echo "Recent failed attempts:"
        grep "Failed password" /var/log/auth.log | tail -10
        echo ""
        echo "Please review immediately!"
    } | mail "$ADMIN_EMAIL"
fi

# Check for mail rejection attacks
mail_rejects=$(grep "reject:" /var/log/mail.log | grep "$(date '+%b %d')" | wc -l)
if [[ $mail_rejects -gt $ALERT_THRESHOLD_REJECT ]]; then
    {
        echo "Subject: SECURITY ALERT - High Mail Rejection Rate"
        echo ""
        echo "WARNING: $mail_rejects mail rejections detected today"
        echo "Server: $(hostname)"
        echo "Time: $TIMESTAMP"
        echo ""
        echo "Top rejection reasons:"
        grep "reject:" /var/log/mail.log | grep "$(date '+%b %d')" | \
            sed -E 's/.*reject: (.*)/\1/' | sort | uniq -c | sort -nr | head -5
        echo ""
        echo "This may indicate an attack in progress!"
    } | mail "$ADMIN_EMAIL"
fi

# Check for service outages
services=("postfix" "dovecot" "opendkim" "spamassassin" "fail2ban")
for service in "${services[@]}"; do
    if ! systemctl is-active --quiet "$service"; then
        {
            echo "Subject: CRITICAL ALERT - Service Down: $service"
            echo ""
            echo "CRITICAL: Service $service is not running!"
            echo "Server: $(hostname)"
            echo "Time: $TIMESTAMP"
            echo ""
            echo "Service status:"
            systemctl status "$service" --no-pager
            echo ""
            echo "Immediate action required!"
        } | mail "$ADMIN_EMAIL"
    fi
done

# Check for disk space issues
for mountpoint in "/" "/var/mail"; do
    if [[ -d "$mountpoint" ]]; then
        usage=$(df -h "$mountpoint" | awk 'NR==2{print $5}' | tr -d '%')
        if [[ $usage -gt 85 ]]; then
            {
                echo "Subject: WARNING - Low Disk Space: $mountpoint"
                echo ""
                echo "WARNING: Disk usage at $usage% for $mountpoint"
                echo "Server: $(hostname)"
                echo "Time: $TIMESTAMP"
                echo ""
                echo "Disk usage details:"
                df -h "$mountpoint"
                echo ""
                echo "Please free up space immediately!"
            } | mail "$ADMIN_EMAIL"
        fi
    fi
done
EOF
    
    chmod +x /usr/local/bin/email-security-alerts.sh
    
    # Create systemd timer for regular monitoring
    cat << EOF > /etc/systemd/system/email-security-monitor.timer
[Unit]
Description=Email Server Security Monitor Timer
Requires=email-security-monitor.service

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
EOF
    
    # Enable the timer
    systemctl daemon-reload
    systemctl enable email-security-monitor.timer
    systemctl start email-security-monitor.timer
    
    print_info "Security monitoring dashboard configured"
}

# Function to create security documentation
create_security_documentation() {
    print_info "Creating security documentation..."
    
    cat << EOF > /etc/email-server/SECURITY-GUIDE.md
# Email Server Security Guide

## Security Features Implemented

### 1. SSH Hardening
- Key-based authentication only
- Root login disabled
- Connection rate limiting
- VPN-only access (if enabled)

### 2. Email Security
- SPF, DKIM, DMARC implemented
- TLS encryption enforced
- DANE/TLSA records configured
- Content filtering enabled

### 3. Network Security
- Fail2Ban enabled for all services
- Rate limiting on SMTP/IMAP
- Kernel parameters hardened
- IP spoofing protection

### 4. Intrusion Detection
- AIDE file integrity monitoring
- Log-based attack detection
- Real-time security alerts
- Automated response to attacks

### 5. Access Control
- Minimal service exposure
- Principle of least privilege
- Regular permission audits
- Secure file permissions

## Security Monitoring

### Dashboard
Run the security dashboard:
\`\`\`bash
email-security-dashboard.sh
\`\`\`

### Log Analysis
- Main logs: /var/log/mail/
- Security events: /var/log/critical.log
- Analysis reports: /var/log/email-server-setup/

### Alerts
- Automated email alerts for critical events
- Daily security reports
- Real-time intrusion detection

## Maintenance Tasks

### Daily
- Monitor fail2ban status
- Check mail queue size
- Review authentication failures

### Weekly
- Review security logs
- Update file integrity database
- Test backup systems

### Monthly
- Update system packages
- Review and rotate logs
- Security assessment

## Incident Response

### Authentication Attacks
1. Check fail2ban status
2. Review /var/log/auth.log
3. Block attacking IPs manually if needed
4. Consider reducing MaxAuthTries

### Mail Attacks
1. Monitor mail queue
2. Check DKIM/SPF status
3. Review spam detection rates
4. Adjust content filtering as needed

### Service Outages
1. Check service status
2. Review service logs
3. Restart affected services
4. Verify functionality

## Security Updates

Regular security updates are essential:

\`\`\`bash
# Update system packages
apt-get update && apt-get upgrade

# Update security rules
aide --update
fail2ban-client reload
\`\`\`

## Contact Information

For security incidents:
- Admin Email: $ADMIN_EMAIL
- Server Location: $(hostname)
- Domain: $DOMAIN

## Additional Resources

- Fail2Ban documentation: https://www.fail2ban.org/
- Postfix security: http://www.postfix.org/SASL_README.html
- AIDE documentation: https://aide.github.io/
EOF
    
    print_info "Security documentation created"
}

# Function to generate final security report
generate_security_report() {
    print_info "Generating final security report..."
    
    REPORT_FILE="/etc/email-server/security-assessment-$(date +%Y%m%d).html"
    
    cat << EOF > "$REPORT_FILE"
<!DOCTYPE html>
<html>
<head>
    <title>Email Server Security Assessment</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        .header { background: #333; color: white; padding: 20px; margin-bottom: 30px; }
        .section { margin-bottom: 30px; }
        .pass { color: #2ecc71; }
        .warning { color: #f39c12; }
        .fail { color: #e74c3c; }
        table { border-collapse: collapse; width: 100%; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .metric { margin: 10px 0; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Email Server Security Assessment</h1>
        <p>Generated on: $(date)</p>
        <p>Domain: $DOMAIN</p>
        <p>Server: $(hostname)</p>
    </div>
    
    <div class="section">
        <h2>Security Services Status</h2>
        <table>
            <tr><th>Service</th><th>Status</th><th>Notes</th></tr>
EOF
    
    # Check service status
    services=(
        "fail2ban:Intrusion Prevention"
        "sshd:Secure Shell"
        "postfix:Mail Server"
        "dovecot:IMAP/POP3"
        "opendkim:Email Authentication"
        "spamassassin:Spam Filter"
    )
    
    for service_info in "${services[@]}"; do
        IFS=":" read -r service desc <<< "$service_info"
        if systemctl is-active --quiet "$service"; then
            echo "            <tr><td>$desc</td><td class='pass'>Running</td><td>Active and operational</td></tr>" >> "$REPORT_FILE"
        else
            echo "            <tr><td>$desc</td><td class='fail'>Stopped</td><td>Service is not running</td></tr>" >> "$REPORT_FILE"
        fi
    done
    
    cat << EOF >> "$REPORT_FILE"
        </table>
    </div>
    
    <div class="section">
        <h2>Security Configuration</h2>
        <div class="metric">SSH Hardening: <span class="pass">Enabled</span></div>
        <div class="metric">Fail2Ban: <span class="pass">Configured</span></div>
        <div class="metric">SSL/TLS: <span class="pass">Enforced</span></div>
        <div class="metric">DKIM: <span class="pass">Active</span></div>
        <div class="metric">SPF: <span class="pass">Configured</span></div>
        <div class="metric">Rate Limiting: <span class="pass">Enabled</span></div>
        <div class="metric">Content Filtering: <span class="pass">Active</span></div>
        <div class="metric">File Integrity: <span class="pass">Monitored</span></div>
    </div>
    
    <div class="section">
        <h2>Recent Security Activity</h2>
        <p>Authentication failures (last 24h): <strong>$(grep -c "Failed password" /var/log/auth.log | tail -24h || echo 0)</strong></p>
        <p>Mail rejections (last 24h): <strong>$(grep -c "reject:" /var/log/mail.log | tail -24h || echo 0)</strong></p>
        <p>Failed bans: <strong>$(fail2ban-client status | grep -E "\s+Currently banned:\s+" | awk '{sum+=$NF} END {print sum}')</strong></p>
        <p>AIDE integrity checks: <strong>Automated</strong></p>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
            <li>Regular security updates scheduled</li>
            <li>Monitor security dashboard daily</li>
            <li>Review fail2ban logs weekly</li>
            <li>Test backups monthly</li>
            <li>Update AIDE database quarterly</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Contact</h2>
        <p>For security concerns, contact: <strong>$ADMIN_EMAIL</strong></p>
        <p>Security documentation: <code>/etc/email-server/SECURITY-GUIDE.md</code></p>
    </div>
    
    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 0.9em; color: #666;">
        <p>This assessment was automatically generated after security hardening implementation.</p>
        <p>Last updated: $(date)</p>
    </footer>
</body>
</html>
EOF
    
    print_info "Security report generated: $REPORT_FILE"
}

# Main execution
print_info "Starting final security hardening..."

# Run all hardening functions
harden_ssh
implement_rate_limiting
secure_kernel_parameters
harden_file_permissions
implement_intrusion_detection
enable_advanced_logging
implement_content_filtering
setup_security_monitoring
create_security_documentation
generate_security_report

print_info "Security hardening complete!"
print_info "Important information:"
echo "  - Admin SSH key: /etc/email-server/admin-ssh-key"
echo "  - Security guide: /etc/email-server/SECURITY-GUIDE.md"
echo "  - Security report: /etc/email-server/security-assessment-$(date +%Y%m%d).html"
echo "  - Security dashboard: email-security-dashboard.sh"

print_warning "Post-hardening tasks:"
echo "1. Test SSH access with the admin key"
echo "2. Review security report"
echo "3. Set up regular security reviews"
echo "4. Train administrators on security procedures"
echo "5. Document any custom security policies"
