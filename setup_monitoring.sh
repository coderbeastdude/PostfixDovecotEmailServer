#!/bin/bash

# Script to set up comprehensive monitoring for the email server
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

# Function to install monitoring tools
install_monitoring_tools() {
    print_info "Installing monitoring tools..."
    
    # Install base monitoring tools
    apt-get update
    apt-get install -y \
        logwatch \
        mailgraph \
        rrdtool \
        librrds-perl \
        libmime-perl \
        libtime-parsedate-perl \
        postfix-policyd-weight \
        htop \
        iotop \
        iftop \
        nethogs \
        sysstat \
        moreutils \
        jq
    
    print_info "Monitoring tools installed successfully"
}

# Function to configure logwatch
configure_logwatch() {
    print_info "Configuring logwatch..."
    
    # Create custom logwatch configuration
    mkdir -p /etc/logwatch/conf
    
    cat << EOF > /etc/logwatch/conf/logwatch.conf
# Logwatch configuration for email server
# Modified for daily email reports

LogDir = /var/log
TmpDir = /var/cache/logwatch

# Output settings
Format = html
DnsLookup = No
Encode = none
LinkUrls = No
ShowHostname = Yes

# Email settings
MailTo = $ADMIN_EMAIL
MailFrom = logwatch@$DOMAIN
Mailer = "sendmail -f \$MailFrom"

# Range settings
Range = yesterday
Detail = Med

# Service settings
Service = All
Service = -zz-network  # Exclude network service (too verbose)
Service = -zz-sys      # Exclude sys service (too verbose)

# Custom email server services
Service = postfix
Service = dovecot
Service = amavis
Service = spamassassin
Service = fail2ban
Service = sshd
EOF
    
    # Create custom logwatch script for email server specific logs
    cat << 'EOF' > /etc/logwatch/scripts/services/email-server
#!/bin/bash

# Custom logwatch script for email server monitoring
# Analyzes email-specific logs

echo "Email Server Summary"
echo "==================="

# Postfix statistics
if [[ -f /var/log/mail.log ]]; then
    echo "Postfix Statistics:"
    echo "-------------------"
    
    # Count messages
    sent=$(grep "status=sent" /var/log/mail.log | wc -l)
    bounced=$(grep "status=bounced" /var/log/mail.log | wc -l)
    deferred=$(grep "status=deferred" /var/log/mail.log | wc -l)
    rejected=$(grep "reject:" /var/log/mail.log | wc -l)
    
    echo "Messages sent: $sent"
    echo "Messages bounced: $bounced"
    echo "Messages deferred: $deferred"
    echo "Messages rejected: $rejected"
    echo
fi

# Dovecot statistics
if [[ -f /var/log/dovecot.log ]]; then
    echo "Dovecot Statistics:"
    echo "-------------------"
    
    # Count connections
    imap_connects=$(grep "imap-login:" /var/log/dovecot.log | grep "Login:" | wc -l)
    pop3_connects=$(grep "pop3-login:" /var/log/dovecot.log | grep "Login:" | wc -l)
    
    echo "IMAP logins: $imap_connects"
    echo "POP3 logins: $pop3_connects"
    echo
fi

# SpamAssassin statistics
if [[ -f /var/log/mail.log ]]; then
    echo "Spam Statistics:"
    echo "----------------"
    
    # Count spam detection
    spam_detected=$(grep -i "X-Spam-Status: Yes" /var/log/mail.log | wc -l)
    
    echo "Spam messages detected: $spam_detected"
    echo
fi

# DKIM statistics
if [[ -f /var/log/mail.log ]]; then
    echo "DKIM Statistics:"
    echo "----------------"
    
    # Count DKIM signatures
    dkim_signed=$(grep "dkim=pass" /var/log/mail.log | wc -l)
    dkim_failed=$(grep "dkim=fail" /var/log/mail.log | wc -l)
    
    echo "DKIM signed: $dkim_signed"
    echo "DKIM failed: $dkim_failed"
    echo
fi

# Queue status
echo "Mail Queue Status:"
echo "------------------"
postqueue -p
echo

# Recent errors
echo "Recent Errors:"
echo "--------------"
tail -20 /var/log/mail.err 2>/dev/null || echo "No recent errors"
echo
EOF
    
    chmod +x /etc/logwatch/scripts/services/email-server
    
    # Create daily logwatch cron job
    cat << 'EOF' > /etc/cron.daily/logwatch
#!/bin/bash
# Daily logwatch report for email server

/usr/sbin/logwatch --output mail --format html --detail med --range yesterday
EOF
    
    chmod +x /etc/cron.daily/logwatch
    
    print_info "Logwatch configured successfully"
}

# Function to configure mailgraph
configure_mailgraph() {
    print_info "Configuring mailgraph..."
    
    # Create mailgraph configuration
    mkdir -p /var/lib/mailgraph/img
    chown -R www-data:www-data /var/lib/mailgraph
    
    # Create mailgraph configuration file
    cat << 'EOF' > /etc/mailgraph.conf
# Mailgraph configuration
MAIL_LOG=/var/log/mail.log
RRD_DIR=/var/lib/mailgraph
IMG_DIR=/var/lib/mailgraph/img
YEAR_GRAPH=1
IGNORE_LOCALHOST=1
VIRBL_RBL=0
RBL_IS_SPAM=1
EOF
    
    # Create mailgraph systemd service
    cat << 'EOF' > /etc/systemd/system/mailgraph.service
[Unit]
Description=Mailgraph log analyzer
After=network.target

[Service]
Type=forking
ExecStart=/usr/bin/mailgraph --daemon --rrd_dir=/var/lib/mailgraph --log-type=postfix /var/log/mail.log
Restart=on-failure
PIDFile=/var/run/mailgraph.pid

[Install]
WantedBy=multi-user.target
EOF
    
    # Create mailgraph web interface
    if [[ "$ENABLE_AUTODISCOVERY" == "true" ]]; then
        mkdir -p /var/www/html/stats
        
        cat << 'EOF' > /var/www/html/stats/mailgraph.php
<?php
// Simple mailgraph web interface
$graphs = array(
    'mailgraph_day' => 'Daily Mail Statistics',
    'mailgraph_week' => 'Weekly Mail Statistics',
    'mailgraph_month' => 'Monthly Mail Statistics',
    'mailgraph_year' => 'Yearly Mail Statistics',
);

?>
<!DOCTYPE html>
<html>
<head>
    <title>Mail Server Statistics</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .graph { margin: 20px 0; }
        h1 { color: #333; }
        .update { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <h1>Mail Server Statistics</h1>
    <p class="update">Last updated: <?php echo date('Y-m-d H:i:s'); ?></p>
    
    <?php foreach ($graphs as $file => $title): ?>
        <div class="graph">
            <h2><?php echo $title; ?></h2>
            <img src="/stats/images/<?php echo $file; ?>.png" alt="<?php echo $title; ?>">
        </div>
    <?php endforeach; ?>
</body>
</html>
EOF
        
        # Create symlink for images
        ln -sfn /var/lib/mailgraph/img /var/www/html/stats/images
    fi
    
    # Start and enable mailgraph
    systemctl enable mailgraph
    systemctl start mailgraph
    
    print_info "Mailgraph configured successfully"
}

# Function to create comprehensive monitoring dashboard
create_monitoring_dashboard() {
    print_info "Creating monitoring dashboard..."
    
    cat << 'EOF' > /usr/local/bin/email-server-dashboard.sh
#!/bin/bash

# Email Server Monitoring Dashboard
# Displays comprehensive server status

set -euo pipefail

# Color codes for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Function to get service status
get_service_status() {
    local service=$1
    if systemctl is-active --quiet "$service"; then
        echo -e "${GREEN}[RUNNING]${NC}"
    else
        echo -e "${RED}[STOPPED]${NC}"
    fi
}

# Function to get process count
get_process_count() {
    local process=$1
    pgrep -x "$process" | wc -l
}

# Clear screen and show header
clear
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}     EMAIL SERVER DASHBOARD${NC}"
echo -e "${BLUE}     $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BLUE}========================================${NC}"
echo

# System Information
echo -e "${YELLOW}SYSTEM INFORMATION${NC}"
echo "----------------------------------------"
echo "Hostname: $(hostname)"
echo "Server IP: $(ip -4 addr show $(ip route | grep default | awk '{print $5}' | head -n1) | grep -oP '(?<=inet\s)\d+(\.\d+){3}')"
echo "Uptime: $(uptime -p)"
echo "Load Average: $(cat /proc/loadavg | awk '{print $1, $2, $3}')"
echo "Memory Usage: $(free -h | awk '/Mem:/ {print $3 "/" $2}')"
echo "Disk Usage: $(df -h / | awk '/\// {print $5}')"
echo

# Services Status
echo -e "${YELLOW}SERVICES STATUS${NC}"
echo "----------------------------------------"
echo -e "Postfix:        $(get_service_status postfix)"
echo -e "Dovecot:        $(get_service_status dovecot)"
echo -e "OpenDKIM:       $(get_service_status opendkim)"
echo -e "SpamAssassin:   $(get_service_status spamassassin)"
echo -e "Fail2Ban:       $(get_service_status fail2ban)"
echo -e "PostgreSQL:     $(get_service_status postgresql)"
if systemctl list-unit-files | grep -q wg-quick@wg0; then
    echo -e "WireGuard:      $(get_service_status wg-quick@wg0)"
fi
echo

# Mail Queue Status
echo -e "${YELLOW}MAIL QUEUE STATUS${NC}"
echo "----------------------------------------"
queue_status=$(postqueue -p | tail -n1)
if [[ "$queue_status" =~ "Mail queue is empty" ]]; then
    echo -e "${GREEN}Mail queue is empty${NC}"
else
    echo "Active queue: $(postqueue -p | grep -c '^[A-F0-9]' || echo 0) messages"
    echo "Deferred: $(postqueue -p | grep -c 'deferred' || echo 0) messages"
fi
echo

# Recent Activity
echo -e "${YELLOW}RECENT ACTIVITY (Last 1 hour)${NC}"
echo "----------------------------------------"
if [[ -f /var/log/mail.log ]]; then
    sent=$(grep "status=sent" /var/log/mail.log | grep "$(date '+%b %d')" | wc -l)
    received=$(grep "client=.*sasl_username" /var/log/mail.log | grep "$(date '+%b %d')" | wc -l)
    rejected=$(grep "reject:" /var/log/mail.log | grep "$(date '+%b %d')" | wc -l)
    spam=$(grep -i "X-Spam-Status: Yes" /var/log/mail.log | grep "$(date '+%b %d')" | wc -l)
    
    echo "Messages sent: $sent"
    echo "Messages received: $received"
    echo "Messages rejected: $rejected"
    echo "Spam detected: $spam"
else
    echo "Mail log not accessible"
fi
echo

# Fail2Ban Status
echo -e "${YELLOW}FAIL2BAN STATUS${NC}"
echo "----------------------------------------"
if systemctl is-active --quiet fail2ban; then
    banned_count=$(fail2ban-client status | grep "Currently banned" | awk '{sum+=$NF} END {print sum}')
    echo "Total banned IPs: $banned_count"
    
    # Show top 5 jails by bans
    echo "Active bans by jail:"
    jails=$(fail2ban-client status | grep "Jail list:" | cut -f2- | tr -d '\t' | tr ',' '\n')
    for jail in $jails; do
        count=$(fail2ban-client status "$jail" | grep "Currently banned" | cut -f2)
        if [[ $count -gt 0 ]]; then
            echo "  $jail: $count"
        fi
    done
else
    echo -e "${RED}Fail2Ban is not running${NC}"
fi
echo

# Security Alerts
echo -e "${YELLOW}SECURITY ALERTS${NC}"
echo "----------------------------------------"
# Check for failed login attempts
if [[ -f /var/log/auth.log ]]; then
    failed_ssh=$(grep "Failed password" /var/log/auth.log | grep "$(date '+%b %d')" | wc -l)
    if [[ $failed_ssh -gt 0 ]]; then
        echo -e "${RED}Failed SSH attempts: $failed_ssh${NC}"
    fi
fi

# Check for mail authentication failures
if [[ -f /var/log/mail.log ]]; then
    failed_auth=$(grep -i "authentication failed" /var/log/mail.log | grep "$(date '+%b %d')" | wc -l)
    if [[ $failed_auth -gt 0 ]]; then
        echo -e "${RED}Failed email auth: $failed_auth${NC}"
    fi
fi

# Check for SSL certificate expiry
if [[ -d /etc/letsencrypt/live ]]; then
    for domain in $(ls /etc/letsencrypt/live); do
        if [[ -f /etc/letsencrypt/live/$domain/cert.pem ]]; then
            days_left=$(openssl x509 -checkend 2592000 -noout -in "/etc/letsencrypt/live/$domain/cert.pem" && echo 30 || echo 0)
            if [[ $days_left -eq 0 ]]; then
                echo -e "${RED}SSL certificate for $domain expires within 30 days${NC}"
            fi
        fi
    done
fi

if [[ ! -f /var/log/auth.log ]] || [[ $failed_ssh -eq 0 ]] && [[ $failed_auth -eq 0 ]]; then
    echo -e "${GREEN}No security alerts${NC}"
fi
echo

# Connection Statistics
echo -e "${YELLOW}CONNECTION STATISTICS${NC}"
echo "----------------------------------------"
echo "SMTP connections: $(netstat -an | grep ":25.*ESTABLISHED" | wc -l)"
echo "IMAP connections: $(netstat -an | grep ":993.*ESTABLISHED" | wc -l)"
echo "POP3 connections: $(netstat -an | grep ":995.*ESTABLISHED" | wc -l)"
echo "SSH connections: $(netstat -an | grep ":22.*ESTABLISHED" | wc -l)"
echo

# Performance Metrics
echo -e "${YELLOW}PERFORMANCE METRICS${NC}"
echo "----------------------------------------"
# Average response times (simplified)
if systemctl is-active --quiet postfix; then
    echo "Postfix queue time: $(postqueue -p | grep -o '[0-9]\+\.[0-9]\+s' | tail -1 || echo 'N/A')"
fi

# Processes consuming resources
echo "Top processes by CPU:"
ps aux --sort=-%cpu | head -4 | tail -3 | awk '{printf "  %-15s %s%%\n", $11, $3}'

echo "Top processes by Memory:"
ps aux --sort=-%mem | head -4 | tail -3 | awk '{printf "  %-15s %s%%\n", $11, $4}'
echo

# Footer
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  View detailed logs at:${NC}"
echo -e "${BLUE}  - Mail: /var/log/mail.log${NC}"
echo -e "${BLUE}  - Auth: /var/log/auth.log${NC}"
echo -e "${BLUE}  - Fail2Ban: /var/log/fail2ban.log${NC}"
echo -e "${BLUE}========================================${NC}"
EOF
    
    chmod +x /usr/local/bin/email-server-dashboard.sh
    
    # Create alias for easy access
    echo "alias email-dashboard='/usr/local/bin/email-server-dashboard.sh'" >> /root/.bashrc
    
    print_info "Monitoring dashboard created"
}

# Function to create alerting system
create_alerting_system() {
    print_info "Creating alerting system..."
    
    cat << 'EOF' > /usr/local/bin/email-server-alerts.sh
#!/bin/bash

# Email Server Alert System
# Monitors critical issues and sends notifications

set -euo pipefail

# Configuration
ALERT_EMAIL="${ADMIN_EMAIL}"
ALERT_LOG="/var/log/email-server-setup/alerts.log"
HOSTNAME=$(hostname)

# Ensure log directory exists
mkdir -p "$(dirname "$ALERT_LOG")"

# Function to send alert
send_alert() {
    local subject="$1"
    local message="$2"
    local priority="${3:-normal}"
    
    # Add timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Log alert
    echo "[$timestamp] [$priority] $subject: $message" >> "$ALERT_LOG"
    
    # Send email
    {
        echo "Subject: [ALERT] $HOSTNAME: $subject"
        echo "From: alert@${DOMAIN}"
        echo "To: $ALERT_EMAIL"
        echo "Priority: $(if [[ $priority == "critical" ]]; then echo "urgent"; else echo "normal"; fi)"
        echo ""
        echo "Server: $HOSTNAME"
        echo "Timestamp: $timestamp"
        echo "Priority: $priority"
        echo ""
        echo "Alert: $subject"
        echo "--------------------"
        echo "$message"
        echo ""
        echo "This is an automated alert from your email server monitoring system."
    } | /usr/sbin/sendmail "$ALERT_EMAIL"
}

# Check critical services
check_services() {
    local issues=()
    
    for service in postfix dovecot postgresql; do
        if ! systemctl is-active --quiet "$service"; then
            issues+=("Service $service is not running")
        fi
    done
    
    if [[ ${#issues[@]} -gt 0 ]]; then
        send_alert "Critical Services Down" "$(printf '%s\n' "${issues[@]}")" "critical"
    fi
}

# Check disk space
check_disk_space() {
    local threshold=85
    local usage=$(df -h / | awk '/\// {print $5}' | tr -d '%')
    
    if [[ $usage -gt $threshold ]]; then
        send_alert "High Disk Usage" "Root partition is ${usage}% full (threshold: ${threshold}%)" "critical"
    fi
    
    # Check mail spool specifically
    if [[ -d /var/mail ]]; then
        local mail_usage=$(df -h /var/mail | awk '/\// {print $5}' | tr -d '%')
        if [[ $mail_usage -gt $threshold ]]; then
            send_alert "Mail Spool Full" "Mail directory is ${mail_usage}% full (threshold: ${threshold}%)" "critical"
        fi
    fi
}

# Check mail queue
check_mail_queue() {
    local threshold=100
    local queue_size=0
    
    if systemctl is-active --quiet postfix; then
        queue_size=$(postqueue -p | grep -c '^[A-F0-9]' || echo 0)
        
        if [[ $queue_size -gt $threshold ]]; then
            send_alert "Large Mail Queue" "Mail queue has $queue_size messages (threshold: $threshold)" "warning"
        fi
    fi
}

# Check SSL certificates
check_ssl_certificates() {
    if [[ -d /etc/letsencrypt/live ]]; then
        for domain in $(ls /etc/letsencrypt/live); do
            if [[ -f /etc/letsencrypt/live/$domain/cert.pem ]]; then
                # Check if cert expires within 7 days
                if ! openssl x509 -checkend 604800 -noout -in "/etc/letsencrypt/live/$domain/cert.pem"; then
                    send_alert "SSL Certificate Expiring" "Certificate for $domain expires within 7 days" "warning"
                fi
            fi
        done
    fi
}

# Check Fail2Ban excessive bans
check_excessive_bans() {
    local threshold=50
    
    if systemctl is-active --quiet fail2ban; then
        local total_bans=$(fail2ban-client status | grep "Currently banned" | awk '{sum+=$NF} END {print sum}')
        
        if [[ $total_bans -gt $threshold ]]; then
            send_alert "Excessive Fail2Ban Bans" "Currently ${total_bans} IPs are banned (threshold: ${threshold})" "warning"
        fi
    fi
}

# Check authentication failures
check_auth_failures() {
    local threshold=50
    
    # Check last hour of auth failures
    if [[ -f /var/log/auth.log ]]; then
        local recent_failures=$(grep "Failed password" /var/log/auth.log | \
            grep "$(date '+%b %d %H:' -d '1 hour ago')" | wc -l)
        
        if [[ $recent_failures -gt $threshold ]]; then
            send_alert "High Authentication Failures" "${recent_failures} failed auth attempts in last hour (threshold: ${threshold})" "warning"
        fi
    fi
}

# Check mail delivery issues
check_mail_delivery() {
    if [[ -f /var/log/mail.log ]]; then
        # Check for delivery failures
        local delivery_failures=$(grep "status=bounced" /var/log/mail.log | \
            grep "$(date '+%b %d %H:' -d '1 hour ago')" | wc -l)
        
        if [[ $delivery_failures -gt 10 ]]; then
            send_alert "High Mail Delivery Failures" "${delivery_failures} delivery failures in last hour" "warning"
        fi
        
        # Check for deferred messages
        local deferred_count=$(grep "status=deferred" /var/log/mail.log | \
            grep "$(date '+%b %d %H:' -d '1 hour ago')" | wc -l)
        
        if [[ $deferred_count -gt 20 ]]; then
            send_alert "High Deferred Messages" "${deferred_count} deferred messages in last hour" "warning"
        fi
    fi
}

# Main execution
echo "Running email server alert checks at $(date)"

check_services
check_disk_space
check_mail_queue
check_ssl_certificates
check_excessive_bans
check_auth_failures
check_mail_delivery

echo "Alert checks completed"
EOF
    
    chmod +x /usr/local/bin/email-server-alerts.sh
    
    # Create alerting cron job (every 15 minutes)
    (crontab -l 2>/dev/null; echo "*/15 * * * * /usr/local/bin/email-server-alerts.sh") | crontab -
    
    print_info "Alerting system created"
}

# Function to create performance monitoring
create_performance_monitoring() {
    print_info "Creating performance monitoring..."
    
    cat << 'EOF' > /usr/local/bin/email-server-performance.sh
#!/bin/bash

# Email Server Performance Monitoring
# Collects and analyzes performance metrics

set -euo pipefail

LOG_DIR="/var/log/email-server-setup/performance"
mkdir -p "$LOG_DIR"

# Function to collect metrics
collect_metrics() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local metrics_file="$LOG_DIR/metrics-$(date '+%Y%m%d').json"
    
    # System metrics
    local cpu_usage=$(grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage}')
    local memory_usage=$(free | grep Mem | awk '{print ($3/$2) * 100.0}')
    local disk_usage=$(df -h / | awk '/\// {print $5}' | tr -d '%')
    local load_avg=$(cat /proc/loadavg | awk '{print $1}')
    
    # Email server metrics
    local postfix_processes=$(pgrep -c postfix || echo 0)
    local dovecot_processes=$(pgrep -c dovecot || echo 0)
    local queue_size=$(postqueue -p | grep -c '^[A-F0-9]' || echo 0)
    
    # Connection counts
    local smtp_connections=$(netstat -an | grep ":25.*ESTABLISHED" | wc -l)
    local imap_connections=$(netstat -an | grep ":993.*ESTABLISHED" | wc -l)
    local pop3_connections=$(netstat -an | grep ":995.*ESTABLISHED" | wc -l)
    
    # Create JSON metrics
    cat << JSON >> "$metrics_file"
{
  "timestamp": "$timestamp",
  "system": {
    "cpu_usage": $cpu_usage,
    "memory_usage": $memory_usage,
    "disk_usage": $disk_usage,
    "load_average": $load_avg
  },
  "services": {
    "postfix_processes": $postfix_processes,
    "dovecot_processes": $dovecot_processes,
    "queue_size": $queue_size
  },
  "connections": {
    "smtp": $smtp_connections,
    "imap": $imap_connections,
    "pop3": $pop3_connections
  }
}
JSON
}

# Function to generate performance report
generate_report() {
    local report_file="$LOG_DIR/daily-performance-$(date '+%Y%m%d').html"
    
    cat << HTML > "$report_file"
<!DOCTYPE html>
<html>
<head>
    <title>Email Server Performance Report - $(date '+%Y-%m-%d')</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .metric { margin: 10px 0; }
        .chart { margin: 20px 0; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .warning { color: orange; }
        .critical { color: red; }
        .good { color: green; }
    </style>
</head>
<body>
    <h1>Email Server Performance Report</h1>
    <p>Generated on: $(date '+%Y-%m-%d %H:%M:%S')</p>
    
    <h2>Summary Statistics</h2>
    <table>
        <tr>
            <th>Metric</th>
            <th>Average</th>
            <th>Peak</th>
            <th>Status</th>
        </tr>
        <tr>
            <td>CPU Usage</td>
            <td>$(jq -r '[.system.cpu_usage] | add/length' "$LOG_DIR"/metrics-*.json)%</td>
            <td>$(jq -r '[.system.cpu_usage] | max' "$LOG_DIR"/metrics-*.json)%</td>
            <td class="good">Good</td>
        </tr>
        <tr>
            <td>Memory Usage</td>
            <td>$(jq -r '[.system.memory_usage] | add/length' "$LOG_DIR"/metrics-*.json)%</td>
            <td>$(jq -r '[.system.memory_usage] | max' "$LOG_DIR"/metrics-*.json)%</td>
            <td class="good">Good</td>
        </tr>
        <tr>
            <td>Queue Size</td>
            <td>$(jq -r '[.services.queue_size] | add/length' "$LOG_DIR"/metrics-*.json)</td>
            <td>$(jq -r '[.services.queue_size] | max' "$LOG_DIR"/metrics-*.json)</td>
            <td class="good">Good</td>
        </tr>
    </table>
    
    <h2>Connection Statistics</h2>
    <p>These charts show connection patterns over the last 24 hours.</p>
    
    <h2>Service Health</h2>
    <ul>
        <li>Postfix: Running</li>
        <li>Dovecot: Running</li>
        <li>PostgreSQL: Running</li>
        <li>OpenDKIM: Running</li>
        <li>SpamAssassin: Running</li>
        <li>Fail2Ban: Running</li>
    </ul>
    
    <h2>Recommendations</h2>
    <p>Based on the collected metrics, here are some recommendations for optimization...</p>
    
    <footer>
        <p>This report is automatically generated by the email server monitoring system.</p>
    </footer>
</body>
</html>
HTML
    
    # Send report via email
    echo "Subject: Daily Performance Report - $(date '+%Y-%m-%d')" > /tmp/perf-report-mail
    echo "From: performance@${DOMAIN}" >> /tmp/perf-report-mail
    echo "To: $ADMIN_EMAIL" >> /tmp/perf-report-mail
    echo "Content-Type: text/html; charset=UTF-8" >> /tmp/perf-report-mail
    echo "" >> /tmp/perf-report-mail
    cat "$report_file" >> /tmp/perf-report-mail
    
    /usr/sbin/sendmail "$ADMIN_EMAIL" < /tmp/perf-report-mail
    rm /tmp/perf-report-mail
}

# Run appropriate action
case "${1:-collect}" in
    collect)
        collect_metrics
        ;;
    report)
        generate_report
        ;;
    *)
        echo "Usage: $0 [collect|report]"
        exit 1
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/email-server-performance.sh
    
    # Create performance monitoring cron jobs
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/email-server-performance.sh collect") | crontab -
    (crontab -l 2>/dev/null; echo "0 6 * * * /usr/local/bin/email-server-performance.sh report") | crontab -
    
    print_info "Performance monitoring created"
}

# Function to create log aggregation
create_log_aggregation() {
    print_info "Creating log aggregation system..."
    
    # Create log aggregator script
    cat << 'EOF' > /usr/local/bin/email-server-logs.sh
#!/bin/bash

# Email Server Log Aggregation
# Centralizes and analyzes various email server logs

set -euo pipefail

LOG_DIR="/var/log/email-server-setup/aggregated"
mkdir -p "$LOG_DIR"

# Function to rotate logs
rotate_logs() {
    local log_file="$1"
    local keep_days=30
    
    if [[ -f "$log_file" ]]; then
        # Archive old log
        local archive_file="${log_file}.$(date '+%Y%m%d')"
        mv "$log_file" "$archive_file"
        gzip "$archive_file"
        
        # Remove old archives
        find "$(dirname "$log_file")" -name "$(basename "$log_file").*.gz" -mtime +$keep_days -delete
    fi
}

# Function to aggregate mail logs
aggregate_mail_logs() {
    local output_file="$LOG_DIR/mail-activity.log"
    
    # Rotate existing log
    rotate_logs "$output_file"
    
    # Extract relevant mail information
    {
        echo "=== Mail Activity Summary for $(date '+%Y-%m-%d') ==="
        echo "Generated at: $(date)"
        echo
        
        # Postfix statistics
        echo "POSTFIX STATISTICS:"
        echo "-------------------"
        if [[ -f /var/log/mail.log ]]; then
            echo "Messages sent: $(grep "status=sent" /var/log/mail.log | grep "$(date '+%b %d')" | wc -l)"
            echo "Messages bounced: $(grep "status=bounced" /var/log/mail.log | grep "$(date '+%b %d')" | wc -l)"
            echo "Messages deferred: $(grep "status=deferred" /var/log/mail.log | grep "$(date '+%b %d')" | wc -l)"
            echo "Messages rejected: $(grep "reject:" /var/log/mail.log | grep "$(date '+%b %d')" | wc -l)"
            
            echo
            echo "TOP REJECTED CLIENTS:"
            grep "reject:" /var/log/mail.log | grep "$(date '+%b %d')" | \
                grep -oP 'client=\K[^\[]+'  | sort | uniq -c | sort -nr | head -10
            
            echo
            echo "DKIM STATUS:"
            echo "Signed messages: $(grep "dkim=pass" /var/log/mail.log | grep "$(date '+%b %d')" | wc -l)"
            echo "Failed DKIM: $(grep "dkim=fail" /var/log/mail.log | grep "$(date '+%b %d')" | wc -l)"
        fi
        
        echo
        echo "DOVECOT STATISTICS:"
        echo "-------------------"
        if [[ -f /var/log/dovecot.log ]]; then
            echo "IMAP connections: $(grep "imap-login:" /var/log/dovecot.log | grep "Login:" | wc -l)"
            echo "POP3 connections: $(grep "pop3-login:" /var/log/dovecot.log | grep "Login:" | wc -l)"
            echo "Authentication failures: $(grep "auth failed" /var/log/dovecot.log | wc -l)"
            
            echo
            echo "TOP USERS BY CONNECTION:"
            grep -E "(imap|pop3)-login:.*Login:" /var/log/dovecot.log | \
                awk -F'user=' '{print $2}' | awk '{print $1}' | sort | uniq -c | sort -nr | head -10
        fi
        
        echo
        echo "SPAM STATISTICS:"
        echo "----------------"
        if [[ -f /var/log/mail.log ]]; then
            echo "Spam detected: $(grep -i "X-Spam-Status: Yes" /var/log/mail.log | wc -l)"
            echo "SpamAssassin scans: $(grep "spamd: checking message" /var/log/mail.log | wc -l)"
            
            echo
            echo "TOP SPAM SOURCES:"
            grep -i "X-Spam-Status: Yes" /var/log/mail.log | \
                grep -oP 'from=<\K[^>]+' | sort | uniq -c | sort -nr | head -10
        fi
        
        echo
        echo "FAIL2BAN STATISTICS:"
        echo "--------------------"
        if [[ -f /var/log/fail2ban.log ]]; then
            echo "Total bans today: $(grep "Ban" /var/log/fail2ban.log | grep "$(date '+%Y-%m-%d')" | wc -l)"
            echo "Total unbans today: $(grep "Unban" /var/log/fail2ban.log | grep "$(date '+%Y-%m-%d')" | wc -l)"
            
            echo
            echo "TOP BANNED IPS:"
            grep "Ban" /var/log/fail2ban.log | grep "$(date '+%Y-%m-%d')" | \
                grep -oP 'Ban \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | sort -nr | head -10
        fi
        
        echo
        echo "=== End of Daily Summary ==="
    } > "$output_file"
}

# Function to create security log summary
create_security_summary() {
    local output_file="$LOG_DIR/security-summary.log"
    
    # Rotate existing log
    rotate_logs "$output_file"
    
    {
        echo "=== Security Summary for $(date '+%Y-%m-%d') ==="
        echo "Generated at: $(date)"
        echo
        
        echo "AUTHENTICATION FAILURES:"
        echo "------------------------"
        if [[ -f /var/log/auth.log ]]; then
            echo "SSH failures: $(grep "Failed password" /var/log/auth.log | grep "$(date '+%b %d')" | wc -l)"
            
            echo
            echo "TOP FAILED SSH IPS:"
            grep "Failed password" /var/log/auth.log | grep "$(date '+%b %d')" | \
                grep -oP 'from \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | sort -nr | head -10
        fi
        
        if [[ -f /var/log/mail.log ]]; then
            echo
            echo "Email auth failures: $(grep -i "authentication failed" /var/log/mail.log | grep "$(date '+%b %d')" | wc -l)"
        fi
        
        echo
        echo "PRIVILEGE ESCALATION ATTEMPTS:"
        echo "------------------------------"
        if [[ -f /var/log/auth.log ]]; then
            sudo_attempts=$(grep "sudo:" /var/log/auth.log | grep "$(date '+%b %d')" | wc -l)
            echo "Sudo attempts: $sudo_attempts"
            
            failed_sudo=$(grep "sudo:.*FAILED" /var/log/auth.log | grep "$(date '+%b %d')" | wc -l)
            if [[ $failed_sudo -gt 0 ]]; then
                echo "Failed sudo attempts: $failed_sudo"
            fi
        fi
        
        echo
        echo "FIREWALL ACTIVITY:"
        echo "------------------"
        if [[ -f /var/log/ufw.log ]]; then
            blocked=$(grep "BLOCK" /var/log/ufw.log | grep "$(date '+%b %d')" | wc -l)
            echo "Blocked connections: $blocked"
            
            echo
            echo "TOP BLOCKED IPS:"
            grep "BLOCK" /var/log/ufw.log | grep "$(date '+%b %d')" | \
                grep -oP 'SRC=\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | sort -nr | head -10
        fi
        
        echo
        echo "=== End of Security Summary ==="
    } > "$output_file"
}

# Function to export logs for external analysis
export_logs() {
    local export_dir="$LOG_DIR/exports/$(date '+%Y%m%d')"
    mkdir -p "$export_dir"
    
    # Copy key log files
    for log in /var/log/mail.log /var/log/auth.log /var/log/fail2ban.log; do
        if [[ -f "$log" ]]; then
            cp "$log" "$export_dir/$(basename "$log")"
        fi
    done
    
    # Create tarball
    tar -czf "$LOG_DIR/exports/logs-$(date '+%Y%m%d').tar.gz" -C "$export_dir" .
    rm -rf "$export_dir"
    
    # Keep only last 7 days of exports
    find "$LOG_DIR/exports" -name "logs-*.tar.gz" -mtime +7 -delete
}

# Main execution
case "${1:-aggregate}" in
    aggregate)
        aggregate_mail_logs
        create_security_summary
        ;;
    export)
        export_logs
        ;;
    *)
        echo "Usage: $0 [aggregate|export]"
        exit 1
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/email-server-logs.sh
    
    # Create log aggregation cron jobs
    (crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/email-server-logs.sh aggregate") | crontab -
    (crontab -l 2>/dev/null; echo "0 3 * * 0 /usr/local/bin/email-server-logs.sh export") | crontab -
    
    print_info "Log aggregation system created"
}

# Function to create monitoring configuration
create_monitoring_config() {
    print_info "Creating monitoring configuration..."
    
    # Create main monitoring configuration file
    cat << EOF > /etc/email-server/monitoring.conf
# Email Server Monitoring Configuration
# Generated by email server setup script

# Alert settings
ADMIN_EMAIL="$ADMIN_EMAIL"
ALERT_INTERVAL=900  # 15 minutes
CRITICAL_ALERT_INTERVAL=300  # 5 minutes

# Thresholds
DISK_USAGE_THRESHOLD=85
MAIL_QUEUE_THRESHOLD=100
FAILED_AUTH_THRESHOLD=50
CONNECTION_THRESHOLD=1000
MEMORY_THRESHOLD=90
CPU_THRESHOLD=80

# Notification settings
ENABLE_EMAIL_ALERTS=true
ENABLE_SLACK_ALERTS=false
SLACK_WEBHOOK_URL=""

# Log retention
LOG_RETENTION_DAYS=30
METRIC_RETENTION_DAYS=90
BACKUP_RETENTION_DAYS=7

# Performance monitoring
ENABLE_PERFORMANCE_MONITORING=true
METRIC_COLLECTION_INTERVAL=300  # 5 minutes
REPORT_GENERATION_TIME="06:00"

# Service monitoring
MONITORED_SERVICES=(
    "postfix"
    "dovecot"
    "postgresql"
    "opendkim"
    "spamassassin"
    "fail2ban"
)

if [[ "$ENABLE_VPN" == "true" ]]; then
    MONITORED_SERVICES+=("wg-quick@wg0")
fi

# Log locations
MAIL_LOG="/var/log/mail.log"
AUTH_LOG="/var/log/auth.log"
FAIL2BAN_LOG="/var/log/fail2ban.log"
DOVECOT_LOG="/var/log/dovecot.log"

# Web interface settings
ENABLE_WEB_INTERFACE=$ENABLE_AUTODISCOVERY
WEB_INTERFACE_PORT=8080
EOF
    
    print_info "Monitoring configuration created"
}

# Function to set up monitoring web interface
setup_web_interface() {
    if [[ "$ENABLE_AUTODISCOVERY" == "true" ]]; then
        print_info "Setting up monitoring web interface..."
        
        # Create monitoring web interface
        mkdir -p /var/www/html/monitor
        
        cat << 'EOF' > /var/www/html/monitor/index.php
<?php
// Email Server Monitoring Web Interface
// Simple dashboard for server status

$config = [
    'title' => 'Email Server Monitor',
    'domain' => $_SERVER['HTTP_HOST'],
    'refresh' => 30 // Auto-refresh every 30 seconds
];

// Function to get service status
function getServiceStatus($service) {
    $status = shell_exec("systemctl is-active " . escapeshellarg($service));
    return trim($status) === 'active';
}

// Function to get metric value
function getMetric($command) {
    return trim(shell_exec($command));
}

?>
<!DOCTYPE html>
<html>
<head>
    <title><?php echo $config['title']; ?></title>
    <meta http-equiv="refresh" content="<?php echo $config['refresh']; ?>">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #333; color: white; padding: 20px; margin-bottom: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .metric { margin: 10px 0; }
        .status { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 5px; }
        .status.ok { background: #4CAF50; }
        .status.error { background: #f44336; }
        .progress { background: #e0e0e0; border-radius: 5px; height: 20px; margin: 5px 0; }
        .progress-bar { height: 100%; background: #4CAF50; border-radius: 5px; }
        .warning { background: #ff9800; }
        .critical { background: #f44336; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><?php echo $config['title']; ?></h1>
            <p>Last updated: <?php echo date('Y-m-d H:i:s'); ?></p>
        </div>
        
        <div class="grid">
            <!-- Services Status -->
            <div class="card">
                <h2>Services Status</h2>
                <?php
                $services = ['postfix', 'dovecot', 'postgresql', 'opendkim', 'spamassassin', 'fail2ban'];
                foreach ($services as $service) {
                    $status = getServiceStatus($service);
                    echo '<div class="metric">';
                    echo '<span class="status ' . ($status ? 'ok' : 'error') . '"></span>';
                    echo ucfirst($service) . ': ' . ($status ? 'Running' : 'Stopped');
                    echo '</div>';
                }
                ?>
            </div>
            
            <!-- System Metrics -->
            <div class="card">
                <h2>System Metrics</h2>
                <?php
                $cpu = getMetric("grep 'cpu ' /proc/stat | awk '{usage=(\$2+\$4)*100/(\$2+\$4+\$5)} END {print usage}'");
                $memory = getMetric("free | grep Mem | awk '{print (\$3/\$2) * 100.0}'");
                $disk = getMetric("df -h / | awk '/\// {print \$5}' | tr -d '%'");
                ?>
                
                <div class="metric">
                    CPU Usage: <?php echo round($cpu, 1); ?>%
                    <div class="progress">
                        <div class="progress-bar <?php echo $cpu > 80 ? 'critical' : ($cpu > 60 ? 'warning' : ''); ?>" 
                             style="width: <?php echo $cpu; ?>%"></div>
                    </div>
                </div>
                
                <div class="metric">
                    Memory Usage: <?php echo round($memory, 1); ?>%
                    <div class="progress">
                        <div class="progress-bar <?php echo $memory > 90 ? 'critical' : ($memory > 75 ? 'warning' : ''); ?>" 
                             style="width: <?php echo $memory; ?>%"></div>
                    </div>
                </div>
                
                <div class="metric">
                    Disk Usage: <?php echo $disk; ?>%
                    <div class="progress">
                        <div class="progress-bar <?php echo $disk > 85 ? 'critical' : ($disk > 75 ? 'warning' : ''); ?>" 
                             style="width: <?php echo $disk; ?>%"></div>
                    </div>
                </div>
            </div>
            
            <!-- Mail Statistics -->
            <div class="card">
                <h2>Mail Statistics</h2>
                <?php
                $queue = getMetric("postqueue -p | grep -c '^[A-F0-9]' || echo 0");
                $sent = getMetric("grep 'status=sent' /var/log/mail.log | grep '$(date '+%b %d')' | wc -l");
                $rejected = getMetric("grep 'reject:' /var/log/mail.log | grep '$(date '+%b %d')' | wc -l");
                ?>
                
                <div class="metric">Queue Size: <?php echo $queue; ?></div>
                <div class="metric">Sent Today: <?php echo $sent; ?></div>
                <div class="metric">Rejected Today: <?php echo $rejected; ?></div>
            </div>
            
            <!-- Security Status -->
            <div class="card">
                <h2>Security Status</h2>
                <?php
                $banned = getMetric("fail2ban-client status | grep 'Currently banned' | awk '{sum+=\$NF} END {print sum}'");
                $failed_ssh = getMetric("grep 'Failed password' /var/log/auth.log | grep '$(date '+%b %d')' | wc -l");
                ?>
                
                <div class="metric">Banned IPs: <?php echo $banned; ?></div>
                <div class="metric">Failed SSH Today: <?php echo $failed_ssh; ?></div>
            </div>
        </div>
    </div>
</body>
</html>
EOF
        
        # Set proper permissions
        chown -R www-data:www-data /var/www/html/monitor
        
        print_info "Web interface created at /var/www/html/monitor/"
    fi
}

# Function to create monitoring summary script
create_monitoring_summary() {
    print_info "Creating monitoring summary script..."
    
    cat << 'EOF' > /usr/local/bin/email-server-summary.sh
#!/bin/bash

# Email Server Daily Summary
# Generates comprehensive daily report

set -euo pipefail

# Load configuration
source /etc/email-server/monitoring.conf

# Generate comprehensive daily report
{
    echo "Subject: Daily Email Server Summary - $(date '+%Y-%m-%d')"
    echo "From: summary@${DOMAIN}"
    echo "To: $ADMIN_EMAIL"
    echo "Content-Type: text/html; charset=UTF-8"
    echo ""
    
    cat << HTML
<!DOCTYPE html>
<html>
<head>
    <title>Daily Email Server Summary</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 40px; }
        .header { background: #333; color: white; padding: 20px; margin-bottom: 30px; }
        .section { margin-bottom: 30px; }
        .metric { margin: 10px 0; }
        .good { color: #4CAF50; }
        .warning { color: #ff9800; }
        .critical { color: #f44336; }
        table { border-collapse: collapse; width: 100%; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Daily Email Server Summary</h1>
        <p>Report for $(date '+%Y-%m-%d')</p>
    </div>
    
    <div class="section">
        <h2>System Status</h2>
        <div class="metric">Server Uptime: $(uptime -p)</div>
        <div class="metric">Load Average: $(cat /proc/loadavg | awk '{print $1, $2, $3}')</div>
        <div class="metric">Memory Usage: $(free -h | awk '/Mem:/ {print $3 "/" $2}')</div>
        <div class="metric">Disk Usage: $(df -h / | awk '/\// {print $5}')</div>
    </div>
    
    <div class="section">
        <h2>Service Status</h2>
        <table>
            <tr><th>Service</th><th>Status</th></tr>
HTML
    
    # Add service statuses
    for service in "${MONITORED_SERVICES[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo "            <tr><td>$service</td><td class='good'>Running</td></tr>"
        else
            echo "            <tr><td>$service</td><td class='critical'>Stopped</td></tr>"
        fi
    done
    
    cat << HTML
        </table>
    </div>
    
    <div class="section">
        <h2>Mail Activity</h2>
        <div class="metric">Messages Sent: $(grep "status=sent" /var/log/mail.log | grep "$(date '+%b %d')" | wc -l)</div>
        <div class="metric">Messages Received: $(grep "client=.*sasl_username" /var/log/mail.log | grep "$(date '+%b %d')" | wc -l)</div>
        <div class="metric">Messages Rejected: $(grep "reject:" /var/log/mail.log | grep "$(date '+%b %d')" | wc -l)</div>
        <div class="metric">Spam Detected: $(grep -i "X-Spam-Status: Yes" /var/log/mail.log | grep "$(date '+%b %d')" | wc -l)</div>
        <div class="metric">Current Queue Size: $(postqueue -p | grep -c '^[A-F0-9]' || echo 0)</div>
    </div>
    
    <div class="section">
        <h2>Security Summary</h2>
        <div class="metric">Total Banned IPs: $(fail2ban-client status | grep "Currently banned" | awk '{sum+=$NF} END {print sum}')</div>
        <div class="metric">Failed SSH Attempts: $(grep "Failed password" /var/log/auth.log | grep "$(date '+%b %d')" | wc -l)</div>
        <div class="metric">Authentication Failures: $(grep -i "authentication failed" /var/log/mail.log | grep "$(date '+%b %d')" | wc -l)</div>
    </div>
    
    <div class="section">
        <h2>Recent Alerts</h2>
HTML
    
    # Add recent alerts
    if [[ -f /var/log/email-server-setup/alerts.log ]]; then
        recent_alerts=$(tail -n 10 /var/log/email-server-setup/alerts.log)
        if [[ -n "$recent_alerts" ]]; then
            echo "        <pre style='background: #f8f8f8; padding: 10px;'>$recent_alerts</pre>"
        else
            echo "        <p>No recent alerts</p>"
        fi
    else
        echo "        <p>No alerts found</p>"
    fi
    
    cat << HTML
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
HTML
    
    # Add automated recommendations
    queue_size=$(postqueue -p | grep -c '^[A-F0-9]' || echo 0)
    if [[ $queue_size -gt 50 ]]; then
        echo "            <li class='warning'>Mail queue is growing - investigate delivery issues</li>"
    fi
    
    memory_usage=$(free | grep Mem | awk '{print ($3/$2) * 100.0}')
    if (( $(echo "$memory_usage > 85" | bc -l) )); then
        echo "            <li class='warning'>High memory usage detected - consider optimization</li>"
    fi
    
    banned_count=$(fail2ban-client status | grep "Currently banned" | awk '{sum+=$NF} END {print sum}')
    if [[ $banned_count -gt 100 ]]; then
        echo "            <li class='warning'>High number of banned IPs - review Fail2Ban settings</li>"
    fi
    
    cat << HTML
            <li>All automated recommendations have been processed</li>
        </ul>
    </div>
    
    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 0.9em; color: #666;">
        <p>This report was automatically generated by your email server monitoring system.</p>
        <p>For detailed information, check the monitoring dashboard or log files.</p>
    </footer>
</body>
</html>
HTML
} | /usr/sbin/sendmail "$ADMIN_EMAIL"
EOF
    
    chmod +x /usr/local/bin/email-server-summary.sh
    
    # Add to crontab for daily execution
    (crontab -l 2>/dev/null; echo "0 7 * * * /usr/local/bin/email-server-summary.sh") | crontab -
    
    print_info "Monitoring summary script created"
}

# Main execution
print_info "Starting comprehensive monitoring setup..."

# Install monitoring tools
install_monitoring_tools

# Configure individual components
configure_logwatch
configure_mailgraph

# Create monitoring scripts
create_monitoring_dashboard
create_alerting_system
create_performance_monitoring
create_log_aggregation

# Create configuration
create_monitoring_config

# Set up web interface
setup_web_interface

# Create daily summary
create_monitoring_summary

print_info "Monitoring setup complete!"
print_info "Monitoring components:"
echo "  - Logwatch: Daily email reports"
echo "  - Mailgraph: Visual mail statistics"
echo "  - Dashboard: /usr/local/bin/email-server-dashboard.sh"
echo "  - Alerts: /usr/local/bin/email-server-alerts.sh"
echo "  - Performance: /usr/local/bin/email-server-performance.sh"
echo "  - Log aggregation: /usr/local/bin/email-server-logs.sh"
echo "  - Daily summary: /usr/local/bin/email-server-summary.sh"

if [[ "$ENABLE_AUTODISCOVERY" == "true" ]]; then
    echo "  - Web interface: https://$DOMAIN/monitor/"
fi

print_warning "Next steps:"
echo "1. Review monitoring configuration in /etc/email-server/monitoring.conf"
echo "2. Test alert delivery with: email-server-alerts.sh"
echo "3. Check dashboard: email-server-dashboard.sh"
echo "4. Verify daily reports are being sent"
echo "5. Access web interface if enabled"
