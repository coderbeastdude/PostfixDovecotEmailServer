#!/bin/bash

# Script to create comprehensive backups for the email server
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

# Function to create backup directories
create_backup_directories() {
    print_info "Creating backup directory structure..."
    
    # Main backup directory
    mkdir -p "$BACKUP_DIR"
    
    # Subdirectories for different types of backups
    mkdir -p "$BACKUP_DIR/config"
    mkdir -p "$BACKUP_DIR/database"
    mkdir -p "$BACKUP_DIR/mail"
    mkdir -p "$BACKUP_DIR/ssl"
    mkdir -p "$BACKUP_DIR/logs"
    mkdir -p "$BACKUP_DIR/scripts"
    mkdir -p "$BACKUP_DIR/full"
    
    # Set proper permissions
    chmod 700 "$BACKUP_DIR"
    chmod 750 "$BACKUP_DIR"/{config,database,mail,ssl,logs,scripts,full}
    
    print_info "Backup directories created"
}

# Function to backup configurations
backup_configurations() {
    print_info "Backing up server configurations..."
    
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    CONFIG_BACKUP_DIR="$BACKUP_DIR/config/config-$TIMESTAMP"
    mkdir -p "$CONFIG_BACKUP_DIR"
    
    # Postfix configuration
    if [[ -d /etc/postfix ]]; then
        cp -r /etc/postfix "$CONFIG_BACKUP_DIR/"
        print_info "✓ Postfix configuration backed up"
    fi
    
    # Dovecot configuration
    if [[ -d /etc/dovecot ]]; then
        cp -r /etc/dovecot "$CONFIG_BACKUP_DIR/"
        print_info "✓ Dovecot configuration backed up"
    fi
    
    # OpenDKIM configuration
    if [[ -d /etc/opendkim ]]; then
        cp -r /etc/opendkim "$CONFIG_BACKUP_DIR/"
        print_info "✓ OpenDKIM configuration backed up"
    fi
    
    # SpamAssassin configuration
    if [[ -d /etc/spamassassin ]]; then
        cp -r /etc/spamassassin "$CONFIG_BACKUP_DIR/"
        print_info "✓ SpamAssassin configuration backed up"
    fi
    
    # Fail2Ban configuration
    if [[ -d /etc/fail2ban ]]; then
        cp -r /etc/fail2ban "$CONFIG_BACKUP_DIR/"
        print_info "✓ Fail2Ban configuration backed up"
    fi
    
    # WireGuard configuration
    if [[ -d /etc/wireguard ]]; then
        cp -r /etc/wireguard "$CONFIG_BACKUP_DIR/"
        print_info "✓ WireGuard configuration backed up"
    fi
    
    # Web server configuration
    if [[ -d /etc/apache2 ]]; then
        cp -r /etc/apache2 "$CONFIG_BACKUP_DIR/"
        print_info "✓ Apache configuration backed up"
    fi
    
    # Email server specific configurations
    if [[ -d /etc/email-server ]]; then
        cp -r /etc/email-server "$CONFIG_BACKUP_DIR/"
        print_info "✓ Email server configurations backed up"
    fi
    
    # Create configuration inventory
    cat << EOF > "$CONFIG_BACKUP_DIR/inventory.txt"
Configuration Backup Inventory
Generated on: $(date)
Domain: $DOMAIN
Server IP: $SERVER_IP

Backed up configurations:
------------------------
$(find "$CONFIG_BACKUP_DIR" -type d -name "etc" -o -name "email-server" | sed 's|'"$CONFIG_BACKUP_DIR"'/||' | sort)

File count: $(find "$CONFIG_BACKUP_DIR" -type f | wc -l)
Total size: $(du -sh "$CONFIG_BACKUP_DIR" | cut -f1)
EOF
    
    # Create compressed archive
    tar -czf "$BACKUP_DIR/config/config-$TIMESTAMP.tar.gz" -C "$CONFIG_BACKUP_DIR" .
    rm -rf "$CONFIG_BACKUP_DIR"
    
    print_info "Configuration backup completed"
}

# Function to backup database
backup_database() {
    print_info "Backing up PostgreSQL database..."
    
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    DB_BACKUP_FILE="$BACKUP_DIR/database/mailbox-$TIMESTAMP.sql"
    
    # Set PostgreSQL password
    export PGPASSWORD="$POSTGRES_PASSWORD"
    
    # Create database backup
    if pg_dump -h localhost -U "$POSTGRES_USER" mailbox > "$DB_BACKUP_FILE"; then
        print_info "✓ Database dumped successfully"
        
        # Compress the backup
        gzip "$DB_BACKUP_FILE"
        print_info "✓ Database backup compressed"
        
        # Create backup metadata
        cat << EOF > "$BACKUP_DIR/database/mailbox-$TIMESTAMP.info"
Database Backup Information
===========================
Backup Date: $(date)
Database: mailbox
User: $POSTGRES_USER
Backup File: mailbox-$TIMESTAMP.sql.gz
Backup Size: $(du -sh "$DB_BACKUP_FILE.gz" | cut -f1)

Backup Verification:
-------------------
$(zcat "$DB_BACKUP_FILE.gz" | head -20)

Table Statistics:
-----------------
$(psql -h localhost -U "$POSTGRES_USER" -d mailbox -c "
SELECT schemaname, tablename, 
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables 
WHERE schemaname='public' OR schemaname='mailbox'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
")
EOF
    else
        print_error "✗ Database backup failed"
        return 1
    fi
    
    print_info "Database backup completed"
}

# Function to backup mail data
backup_mail_data() {
    print_info "Backing up mail data..."
    
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    MAIL_BACKUP_DIR="$BACKUP_DIR/mail/mail-$TIMESTAMP"
    mkdir -p "$MAIL_BACKUP_DIR"
    
    # Backup mail directory
    if [[ -d /var/mail/vhosts ]]; then
        # Create incremental backup if previous backup exists
        LAST_BACKUP=$(find "$BACKUP_DIR/mail" -name "mail-*.tar.gz" | sort | tail -1)
        
        if [[ -n "$LAST_BACKUP" ]]; then
            # Incremental backup
            print_info "Creating incremental backup..."
            tar -czf "$BACKUP_DIR/mail/mail-$TIMESTAMP-incremental.tar.gz" \
                --newer-mtime="$(stat -c %y "$LAST_BACKUP")" \
                /var/mail/vhosts
        else
            # Full backup
            print_info "Creating full mail backup..."
            tar -czf "$BACKUP_DIR/mail/mail-$TIMESTAMP-full.tar.gz" /var/mail/vhosts
        fi
        
        # Create backup statistics
        cat << EOF > "$BACKUP_DIR/mail/mail-$TIMESTAMP.stats"
Mail Backup Statistics
======================
Backup Date: $(date)
Backup Type: $(if [[ -n "$LAST_BACKUP" ]]; then echo "Incremental"; else echo "Full"; fi)
Source Directory: /var/mail/vhosts

Directory Structure:
-------------------
$(find /var/mail/vhosts -type d | head -20)

Space Usage:
------------
$(du -sh /var/mail/vhosts/*)

Mailbox Count:
--------------
Domains: $(find /var/mail/vhosts -mindepth 1 -maxdepth 1 -type d | wc -l)
Users: $(find /var/mail/vhosts -mindepth 2 -maxdepth 2 -type d | wc -l)
Total Messages: $(find /var/mail/vhosts -name "*.eml" -o -name "*:2,*" | wc -l)
EOF
        
        print_info "✓ Mail data backed up"
    else
        print_warning "! Mail directory not found, skipping"
    fi
    
    print_info "Mail backup completed"
}

# Function to backup SSL certificates
backup_ssl_certificates() {
    print_info "Backing up SSL certificates..."
    
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    SSL_BACKUP_DIR="$BACKUP_DIR/ssl/ssl-$TIMESTAMP"
    mkdir -p "$SSL_BACKUP_DIR"
    
    # Backup Let's Encrypt certificates
    if [[ -d /etc/letsencrypt ]]; then
        cp -r /etc/letsencrypt "$SSL_BACKUP_DIR/"
        print_info "✓ Let's Encrypt certificates backed up"
    fi
    
    # Backup custom certificates
    if [[ -d /etc/ssl/private ]]; then
        mkdir -p "$SSL_BACKUP_DIR/ssl/private"
        cp /etc/ssl/private/* "$SSL_BACKUP_DIR/ssl/private/" 2>/dev/null || true
    fi
    
    # Create certificate inventory
    cat << EOF > "$SSL_BACKUP_DIR/certificate-inventory.txt"
SSL Certificate Inventory
========================
Generated on: $(date)

Let's Encrypt Certificates:
---------------------------
$(ls -la /etc/letsencrypt/live/ 2>/dev/null || echo "No Let's Encrypt certificates found")

Certificate Details:
--------------------
EOF
    
    # Add certificate details
    for cert in /etc/letsencrypt/live/*/cert.pem; do
        if [[ -f "$cert" ]]; then
            echo "Certificate: $cert" >> "$SSL_BACKUP_DIR/certificate-inventory.txt"
            openssl x509 -in "$cert" -text -noout | grep -E "(Subject:|Issuer:|Not Before|Not After)" >> "$SSL_BACKUP_DIR/certificate-inventory.txt"
            echo "" >> "$SSL_BACKUP_DIR/certificate-inventory.txt"
        fi
    done
    
    # Create compressed archive
    tar -czf "$BACKUP_DIR/ssl/ssl-$TIMESTAMP.tar.gz" -C "$SSL_BACKUP_DIR" .
    rm -rf "$SSL_BACKUP_DIR"
    
    print_info "SSL certificates backup completed"
}

# Function to backup important logs
backup_logs() {
    print_info "Backing up important logs..."
    
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    LOG_BACKUP_DIR="$BACKUP_DIR/logs/logs-$TIMESTAMP"
    mkdir -p "$LOG_BACKUP_DIR"
    
    # Backup key log files
    LOG_FILES=(
        "/var/log/mail.log"
        "/var/log/mail.err"
        "/var/log/auth.log"
        "/var/log/fail2ban.log"
        "/var/log/apache2/access.log"
        "/var/log/apache2/error.log"
        "/var/log/dovecot.log"
        "/var/log/email-server-setup/installation.log"
    )
    
    for log_file in "${LOG_FILES[@]}"; do
        if [[ -f "$log_file" ]]; then
            cp "$log_file" "$LOG_BACKUP_DIR/$(basename "$log_file")"
            print_info "✓ Backed up $(basename "$log_file")"
        fi
    done
    
    # Backup rotated logs (last 7 days)
    for log_pattern in "/var/log/mail.log" "/var/log/auth.log" "/var/log/fail2ban.log"; do
        find "$(dirname "$log_pattern")" -name "$(basename "$log_pattern").*.gz" -mtime -7 -exec cp {} "$LOG_BACKUP_DIR/" \;
    done
    
    # Create log summary
    cat << EOF > "$LOG_BACKUP_DIR/log-summary.txt"
Log Backup Summary
==================
Generated on: $(date)

Log Files Backed Up:
-------------------
$(ls -la "$LOG_BACKUP_DIR")

Recent Log Activity:
-------------------
Recent Mail Activity:
$(tail -20 /var/log/mail.log)

Recent Authentication Attempts:
$(tail -20 /var/log/auth.log | grep -i "failed\|accept")

Recent Fail2Ban Actions:
$(tail -20 /var/log/fail2ban.log | grep -E "(Ban|Unban)")
EOF
    
    # Create compressed archive
    tar -czf "$BACKUP_DIR/logs/logs-$TIMESTAMP.tar.gz" -C "$LOG_BACKUP_DIR" .
    rm -rf "$LOG_BACKUP_DIR"
    
    print_info "Log backup completed"
}

# Function to backup custom scripts
backup_scripts() {
    print_info "Backing up custom scripts..."
    
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    SCRIPT_BACKUP_DIR="$BACKUP_DIR/scripts/scripts-$TIMESTAMP"
    mkdir -p "$SCRIPT_BACKUP_DIR"
    
    # Backup installation scripts
    SCRIPT_DIR="$(dirname "$(dirname "$(realpath "$0")")")"
    if [[ -d "$SCRIPT_DIR" ]]; then
        cp -r "$SCRIPT_DIR" "$SCRIPT_BACKUP_DIR/installation"
        print_info "✓ Installation scripts backed up"
    fi
    
    # Backup custom scripts from various locations
    SCRIPT_LOCATIONS=(
        "/usr/local/bin"
        "/opt/email-server"
        "/root/scripts"
    )
    
    for location in "${SCRIPT_LOCATIONS[@]}"; do
        if [[ -d "$location" ]]; then
            mkdir -p "$SCRIPT_BACKUP_DIR/$(basename "$location")"
            find "$location" -name "*.sh" -o -name "email-*" | while read -r script; do
                if [[ -f "$script" ]]; then
                    cp "$script" "$SCRIPT_BACKUP_DIR/$(basename "$location")/"
                fi
            done
        fi
    done
    
    # Create script inventory
    cat << EOF > "$SCRIPT_BACKUP_DIR/script-inventory.txt"
Script Backup Inventory
=======================
Generated on: $(date)

Backed Up Scripts:
------------------
$(find "$SCRIPT_BACKUP_DIR" -type f -executable | sed "s|$SCRIPT_BACKUP_DIR/||" | sort)

Cron Jobs:
----------
$(crontab -l 2>/dev/null || echo "No cron jobs found")

Systemd Services:
-----------------
$(find /etc/systemd/system -name "*email*" -o -name "*wireguard*" | sort)
EOF
    
    # Create compressed archive
    tar -czf "$BACKUP_DIR/scripts/scripts-$TIMESTAMP.tar.gz" -C "$SCRIPT_BACKUP_DIR" .
    rm -rf "$SCRIPT_BACKUP_DIR"
    
    print_info "Script backup completed"
}

# Function to create full system backup
create_full_backup() {
    print_info "Creating full system backup..."
    
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    FULL_BACKUP_FILE="$BACKUP_DIR/full/full-backup-$TIMESTAMP.tar.gz"
    
    # Create list of files to backup
    cat << EOF > /tmp/backup-includes.txt
/etc/postfix
/etc/dovecot
/etc/opendkim
/etc/spamassassin
/etc/fail2ban
/etc/wireguard
/etc/apache2
/etc/ssl
/etc/letsencrypt
/etc/email-server
/var/www/html
/var/mail/vhosts
/root/.ssh
/root/.bashrc
/root/.profile
EOF
    
    # Create full backup excluding unnecessary files
    tar \
        --exclude='/var/mail/vhosts/*/*/Maildir/dovecot.index*' \
        --exclude='/var/mail/vhosts/*/*/Maildir/dovecot-uidlist*' \
        --exclude='/tmp/*' \
        --exclude='/var/cache/*' \
        --exclude='/var/lib/postgresql' \
        -czf "$FULL_BACKUP_FILE" \
        -T /tmp/backup-includes.txt
    
    # Include database dump
    DB_TEMP="/tmp/mailbox-full-backup-$TIMESTAMP.sql"
    export PGPASSWORD="$POSTGRES_PASSWORD"
    pg_dump -h localhost -U "$POSTGRES_USER" mailbox > "$DB_TEMP"
    tar -rf "${FULL_BACKUP_FILE%%.gz}" "$DB_TEMP"
    gzip -f "${FULL_BACKUP_FILE%%.gz}"
    rm "$DB_TEMP"
    
    # Create backup manifest
    cat << EOF > "$BACKUP_DIR/full/full-backup-$TIMESTAMP.manifest"
Full Backup Manifest
====================
Backup Date: $(date)
Backup File: full-backup-$TIMESTAMP.tar.gz
Backup Size: $(du -sh "$FULL_BACKUP_FILE" | cut -f1)

Included Files:
---------------
$(tar -tzf "$FULL_BACKUP_FILE" | head -50)
...
Total files: $(tar -tzf "$FULL_BACKUP_FILE" | wc -l)

System Information:
-------------------
Hostname: $(hostname)
OS Version: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
Email Server Domain: $DOMAIN
Server IP: $SERVER_IP

Restore Instructions:
---------------------
1. Extract: tar -xzf full-backup-$TIMESTAMP.tar.gz -C /
2. Restore database: psql -h localhost -U $POSTGRES_USER mailbox < mailbox-full-backup-$TIMESTAMP.sql
3. Restart services: systemctl restart postfix dovecot opendkim spamassassin fail2ban
4. Verify configuration with test scripts
EOF
    
    # Clean up
    rm /tmp/backup-includes.txt
    
    print_info "Full backup completed"
}

# Function to manage backup retention
manage_backup_retention() {
    print_info "Managing backup retention..."
    
    # Configuration for retention policies
    RETENTION_DAYS=30
    FULL_BACKUP_RETENTION=7
    
    # Remove old configuration backups
    find "$BACKUP_DIR/config" -name "config-*.tar.gz" -mtime +$RETENTION_DAYS -delete
    
    # Remove old database backups
    find "$BACKUP_DIR/database" -name "mailbox-*.sql.gz" -mtime +$RETENTION_DAYS -delete
    
    # Remove old mail backups
    find "$BACKUP_DIR/mail" -name "mail-*.tar.gz" -mtime +$RETENTION_DAYS -delete
    
    # Remove old SSL backups
    find "$BACKUP_DIR/ssl" -name "ssl-*.tar.gz" -mtime +$RETENTION_DAYS -delete
    
    # Remove old log backups
    find "$BACKUP_DIR/logs" -name "logs-*.tar.gz" -mtime +14 -delete
    
    # Remove old full backups
    find "$BACKUP_DIR/full" -name "full-backup-*.tar.gz" -mtime +$FULL_BACKUP_RETENTION -delete
    
    # Create retention report
    cat << EOF > "$BACKUP_DIR/retention-report.txt"
Backup Retention Report
=======================
Generated on: $(date)
Retention Policies:
- Configuration: $RETENTION_DAYS days
- Database: $RETENTION_DAYS days
- Mail: $RETENTION_DAYS days
- SSL: $RETENTION_DAYS days
- Logs: 14 days
- Full Backups: $FULL_BACKUP_RETENTION days

Current Backup Status:
----------------------
Configuration backups: $(find "$BACKUP_DIR/config" -name "config-*.tar.gz" | wc -l)
Database backups: $(find "$BACKUP_DIR/database" -name "mailbox-*.sql.gz" | wc -l)
Mail backups: $(find "$BACKUP_DIR/mail" -name "mail-*.tar.gz" | wc -l)
SSL backups: $(find "$BACKUP_DIR/ssl" -name "ssl-*.tar.gz" | wc -l)
Log backups: $(find "$BACKUP_DIR/logs" -name "logs-*.tar.gz" | wc -l)
Full backups: $(find "$BACKUP_DIR/full" -name "full-backup-*.tar.gz" | wc -l)

Total Backup Size: $(du -sh "$BACKUP_DIR" | cut -f1)
EOF
    
    print_info "Backup retention managed"
}

# Function to create backup automation
create_backup_automation() {
    print_info "Creating backup automation..."
    
    # Create main backup script
    cat << 'EOF' > /usr/local/bin/email-server-backup.sh
#!/bin/bash

# Automated email server backup script
# Part of the email server setup automation

set -euo pipefail

# Load configuration
source /etc/email-server-config.conf

# Logging
LOG_FILE="/var/log/email-server-setup/backup.log"
exec 1> >(tee -a "$LOG_FILE")
exec 2>&1

echo "=== Email Server Backup Started at $(date) ==="

# Run backup functions
cd "$(dirname "$0")"
./create-backups.sh config
./create-backups.sh database
./create-backups.sh ssl
./create-backups.sh logs
./create-backups.sh scripts

# Weekly tasks (run on Sunday)
if [[ $(date +%u) -eq 7 ]]; then
    ./create-backups.sh mail
    ./create-backups.sh full
    ./create-backups.sh retention
fi

echo "=== Email Server Backup Completed at $(date) ==="

# Send notification
if command -v mail &> /dev/null; then
    {
        echo "Subject: Email Server Backup Completed"
        echo ""
        echo "Backup completed successfully at $(date)"
        echo ""
        echo "Backup Status:"
        tail -20 "$LOG_FILE"
    } | mail "$ADMIN_EMAIL"
fi
EOF
    
    chmod +x /usr/local/bin/email-server-backup.sh
    
    # Create backup component script
    cat << 'EOFCOMP' > /usr/local/bin/email-server-backup-component.sh
#!/bin/bash

# Component backup script for individual backup types
# Usage: email-server-backup-component.sh <component>

set -euo pipefail

COMPONENT="${1:-}"
SCRIPT_DIR="$(dirname "$(dirname "$(realpath "$0")")")/email-server-setup/scripts"

case "$COMPONENT" in
    config|database|mail|ssl|logs|scripts|full|retention)
        source "$SCRIPT_DIR/15-create-backups.sh"
        ;;
    *)
        echo "Usage: $0 <config|database|mail|ssl|logs|scripts|full|retention>"
        exit 1
        ;;
esac
EOFCOMP
    
    chmod +x /usr/local/bin/email-server-backup-component.sh
    
    # Create systemd service for backups
    cat << EOF > /etc/systemd/system/email-server-backup.service
[Unit]
Description=Email Server Backup Service
After=network.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/bin/email-server-backup.sh
StandardOutput=append:/var/log/email-server-setup/backup.log
StandardError=append:/var/log/email-server-setup/backup.log

[Install]
WantedBy=multi-user.target
EOF
    
    # Create systemd timer for daily backups
    cat << EOF > /etc/systemd/system/email-server-backup.timer
[Unit]
Description=Daily Email Server Backup Timer
Requires=email-server-backup.service

[Timer]
OnCalendar=daily
AccuracyNow
Persistent=true

[Install]
WantedBy=timers.target
EOF
    
    # Enable the timer
    systemctl daemon-reload
    systemctl enable email-server-backup.timer
    systemctl start email-server-backup.timer
    
    print_info "Backup automation configured"
}

# Function to create restore documentation
create_restore_documentation() {
    print_info "Creating restore documentation..."
    
    cat << EOF > "$BACKUP_DIR/RESTORE-GUIDE.md"
# Email Server Restore Guide

This guide explains how to restore your email server from backups.

## Before You Begin

1. Ensure you have root access to the server
2. Install the base Ubuntu system if necessary
3. Have your backup files accessible
4. Know your domain name and previous configuration

## Full System Restore

To restore a complete system:

\`\`\`bash
# 1. Install base system (Ubuntu 20.04+)
# 2. Extract full backup
mkdir /restore-temp
cd /restore-temp
tar -xzf /path/to/full-backup-TIMESTAMP.tar.gz

# 3. Copy files to their locations
cp -r etc/* /etc/
cp -r var/mail/vhosts /var/mail/
cp -r var/www/html /var/www/

# 4. Restore database
sudo -u postgres psql -c "CREATE DATABASE mailbox;"
sudo -u postgres psql -c "CREATE USER mailuser WITH ENCRYPTED PASSWORD 'your_password';"
psql -h localhost -U mailuser mailbox < mailbox-full-backup-TIMESTAMP.sql

# 5. Fix permissions
chown -R www-data:www-data /var/www/html
chown -R vmail:vmail /var/mail/vhosts
chown -R postfix:postfix /etc/postfix
chown -R dovecot:dovecot /etc/dovecot

# 6. Restart services
systemctl restart postgresql postfix dovecot opendkim spamassassin fail2ban apache2
\`\`\`

## Component-Specific Restore

### Database Only

\`\`\`bash
# Restore database from backup
sudo -u postgres psql mailbox < mailbox-TIMESTAMP.sql.gz
\`\`\`

### Mail Data Only

\`\`\`bash
# Restore mail directory
tar -xzf mail-TIMESTAMP.tar.gz -C /
chown -R vmail:vmail /var/mail/vhosts
\`\`\`

### Configuration Only

\`\`\`bash
# Restore configurations
tar -xzf config-TIMESTAMP.tar.gz -C /
systemctl restart postfix dovecot opendkim spamassassin fail2ban
\`\`\`

### SSL Certificates Only

\`\`\`bash
# Restore SSL certificates
tar -xzf ssl-TIMESTAMP.tar.gz -C /
systemctl restart apache2 postfix dovecot
\`\`\`

## Post-Restore Verification

After restoring, verify everything is working:

\`\`\`bash
# Run system tests
/path/to/email-server-setup/scripts/13-test-server.sh

# Check service status
systemctl status postfix dovecot postgresql opendkim spamassassin fail2ban

# Test email sending
echo "Test email" | mail -s "Restore Test" test@yourdomain.com

# Check logs
tail -f /var/log/mail.log
\`\`\`

## Troubleshooting

### Common Issues

1. **Database Connection Errors**
   - Verify PostgreSQL is running
   - Check database credentials
   - Ensure database exists

2. **Mail Delivery Issues**
   - Check Postfix configuration
   - Verify DNS records
   - Check SSL certificates

3. **Permission Problems**
   - Run permission fix commands above
   - Check file ownership
   - Verify directory permissions

### Support

For additional help:
- Check logs in /var/log/
- Review configuration files
- Contact: $ADMIN_EMAIL

## Backup Locations

- Configurations: $BACKUP_DIR/config/
- Database: $BACKUP_DIR/database/
- Mail Data: $BACKUP_DIR/mail/
- SSL Certificates: $BACKUP_DIR/ssl/
- Full Backups: $BACKUP_DIR/full/

## Automation

Backups run automatically via systemd timer:
- Daily: Configuration, database, SSL, logs
- Weekly: Mail data, full backup
- Retention: 30 days for most, 7 days for full backups
EOF
    
    print_info "Restore documentation created"
}

# Main execution
case "${1:-all}" in
    all)
        create_backup_directories
        backup_configurations
        backup_database
        backup_mail_data
        backup_ssl_certificates
        backup_logs
        backup_scripts
        create_full_backup
        manage_backup_retention
        create_backup_automation
        create_restore_documentation
        ;;
    config)
        backup_configurations
        ;;
    database)
        backup_database
        ;;
    mail)
        backup_mail_data
        ;;
    ssl)
        backup_ssl_certificates
        ;;
    logs)
        backup_logs
        ;;
    scripts)
        backup_scripts
        ;;
    full)
        create_full_backup
        ;;
    retention)
        manage_backup_retention
        ;;
    automation)
        create_backup_automation
        ;;
    *)
        print_error "Unknown backup component: $1"
        echo "Usage: $0 [all|config|database|mail|ssl|logs|scripts|full|retention|automation]"
        exit 1
        ;;
esac

print_info "Backup operation completed!"
print_info "Backup directory: $BACKUP_DIR"
print_info "Restore guide: $BACKUP_DIR/RESTORE-GUIDE.md"
