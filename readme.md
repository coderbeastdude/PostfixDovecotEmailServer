# Email Server Setup Automation

A comprehensive, production-ready email server installation script for Ubuntu with modern security features, automated configuration, and optional VPN integration.

## Features

### Core Email Services
- **Postfix** - Mail Transfer Agent (MTA)
- **Dovecot** - IMAP/POP3 server with SSL/TLS
- **PostgreSQL** - Database for virtual domains/users
- **OpenDKIM** - DKIM email authentication
- **SpamAssassin** - Advanced spam filtering
- **Let's Encrypt** - Free SSL/TLS certificates

### Security Features
- **WireGuard VPN** - Optional secure administrative access
- **Fail2Ban** - Intrusion prevention and rate limiting
- **UFW Firewall** - Automatic security hardening
- **SSL/TLS** - Enforced encryption for all connections
- **DANE/TLSA** - DNS-based certificate verification
- **Content filtering** - Advanced email security rules

### Automation & Management
- **Automated installation** - One-command deployment
- **Backup system** - Automatic daily/weekly backups
- **Monitoring** - Comprehensive logging and alerting
- **Autodiscovery** - Client auto-configuration
- **Web dashboard** - Browser-based management interface

## Quick Start

### Prerequisites
- Ubuntu 20.04 or later (fresh installation recommended)
- Root or sudo access via SSH with key authentication
- Root SSH keys already configured (for add_sudo_users.sh)
- Registered domain with DNS control
- Static public IP address
- Minimum 2GB RAM, 20GB storage

### Pre-Installation Note
This email server installation assumes you're using the `add_sudo_users.sh` script to manage system administrators. The email server scripts will not create additional system admin users and expect you to have already set up your preferred admin user accounts before installation.

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/your-org/email-server-setup.git
cd email-server-setup
```

2. **Create system admin users:**
```bash
# Before running the email server installation, create your admin users
sudo ./add_sudo_users.sh
```
This script will:
- Create non-root sudo users
- Copy SSH keys from root
- Set up proper permissions
- Allow you to add multiple admin users

3. **Configure your settings:**
```bash
cp email-server-config.conf.example email-server-config.conf
nano email-server-config.conf
```

4. **Run the installer:**
```bash
sudo ./email-server-setup.sh
```

5. **Follow the interactive menu** to choose installation options:
   - Complete installation (all components)
   - Core email server only
   - Add security components
   - Add optional components
   - Custom installation

## Configuration

### Main Configuration File
Edit `email-server-config.conf` with your specific settings:

```bash
# Domain settings (REQUIRED)
DOMAIN="example.org"
SERVER_IP="192.168.1.100"
ADMIN_EMAIL="admin@example.org"

# Database settings
POSTGRES_PASSWORD="secure_random_password"

# VPN settings (optional)
ENABLE_VPN=true
VPN_NETWORK="10.0.0.0/24"

# Optional features
ENABLE_AUTODISCOVERY=true
BACKUP_DIR="/backups"
```

### DNS Configuration
After installation, add these DNS records:

```
# A record for mail server
mail.example.org.    IN    A    192.168.1.100

# MX record
example.org.         IN    MX   10 mail.example.org.

# SPF record
example.org.         IN    TXT  "v=spf1 ip4:192.168.1.100 -all"

# DMARC record
_dmarc.example.org.  IN    TXT  "v=DMARC1; p=quarantine; rua=mailto:postmaster@example.org"

# DKIM record (generated during installation)
default._domainkey.example.org. IN TXT "v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY"
```

## Usage

### Creating Email Users

After installation, you'll need to create email users. There are two methods:

#### Method 1: Using psql (Direct Database)
```bash
# Connect to the database
sudo -u postgres psql mailbox

# Create a new email user
SELECT id FROM domains WHERE name='yourdomain.org';  -- Get domain ID (usually 1)

# Generate password hash
\! doveadm pw -s SHA512-CRYPT

# Add user (replace with actual hash and email)
INSERT INTO users (domain_id, password, email) 
VALUES (1, '$6$hash_here...', 'newuser@yourdomain.org');

# Add email alias (optional)
INSERT INTO aliases (domain_id, source, destination) 
VALUES (1, 'alias@yourdomain.org', 'newuser@yourdomain.org');

# Exit
\q
```

#### Method 2: Using Management Script (Recommended)
```bash
# Create email management script
cat << 'EOF' > /usr/local/bin/manage-email-users.sh
#!/bin/bash
# Email user management script

case "$1" in
    add)
        read -p "Enter email address: " email
        read -s -p "Enter password: " password
        echo
        
        # Get domain from email
        domain=$(echo "$email" | cut -d@ -f2)
        
        # Generate password hash
        hash=$(doveadm pw -s SHA512-CRYPT -p "$password")
        
        # Add to database
        sudo -u postgres psql -d mailbox -c "
            INSERT INTO users (domain_id, password, email) 
            VALUES (
                (SELECT id FROM domains WHERE name='$domain'), 
                '$hash', 
                '$email'
            );"
        echo "User $email created successfully"
        ;;
    list)
        sudo -u postgres psql -d mailbox -c "
            SELECT u.email, d.name as domain 
            FROM users u 
            JOIN domains d ON u.domain_id = d.id 
            WHERE u.active = TRUE;"
        ;;
    delete)
        read -p "Enter email address to delete: " email
        sudo -u postgres psql -d mailbox -c "
            UPDATE users SET active = FALSE WHERE email = '$email';"
        echo "User $email deactivated"
        ;;
    *)
        echo "Usage: $0 {add|list|delete}"
        ;;
esac
EOF

chmod +x /usr/local/bin/manage-email-users.sh

# Then use the script:
manage-email-users.sh add    # Add new user
manage-email-users.sh list   # List all users
manage-email-users.sh delete # Deactivate user
```

### Email Client Configuration
- **Server:** mail.yourdomain.org
- **IMAP Port:** 993 (SSL/TLS)
- **SMTP Port:** 587 (STARTTLS)
- **POP3 Port:** 995 (SSL/TLS)
- **Authentication:** Yes (username/password)
- **Username Format:** Full email address (user@yourdomain.org)
- **Password:** Password set during user creation

### Email Client Setup Examples

#### Thunderbird (Windows/Mac/Linux)
1. Open Thunderbird
2. Go to Settings → Account Actions → Add Account
3. Choose "Email"
4. Enter email address and password
5. Thunderbird will auto-detect settings via autodiscovery
6. If manual setup needed:
   - **IMAP Server:** mail.yourdomain.org (Port 993, SSL/TLS)
   - **SMTP Server:** mail.yourdomain.org (Port 587, STARTTLS)

#### Outlook (Windows)
1. Open Outlook
2. File → Add Account
3. Enter email address
4. Choose "Advanced Options" → "Let me set up my account manually"
5. Select IMAP
6. Configure:
   - **Incoming:** mail.yourdomain.org (Port 993, SSL)
   - **Outgoing:** mail.yourdomain.org (Port 587, STARTTLS)

#### Apple Mail (macOS/iOS)
1. Go to Settings → Mail → Accounts → Add Account
2. Choose "Other"
3. Enter name, email address, and password
4. Automatically configured via autodiscovery
5. If manual setup needed:
   - **IMAP:** mail.yourdomain.org (Port 993, SSL)
   - **SMTP:** mail.yourdomain.org (Port 587, TLS)

#### Gmail App (Android/iOS)
1. Open Gmail app
2. Settings → Add Account → Other
3. Enter email and password
4. Select "Personal (IMAP/POP)"
5. Configure manually:
   - **IMAP:** mail.yourdomain.org (Port 993, SSL)
   - **SMTP:** mail.yourdomain.org (Port 587, STARTTLS)

#### Manual Configuration Template
```
Email Address: user@yourdomain.org
Password: [User's password]

Incoming Server:
  Protocol: IMAP
  Server: mail.yourdomain.org
  Port: 993
  Security: SSL/TLS
  Authentication: Normal Password

Outgoing Server:
  Protocol: SMTP
  Server: mail.yourdomain.org
  Port: 587
  Security: STARTTLS
  Authentication: Normal Password
  Username: user@yourdomain.org
```

### Management Commands
```bash
# Show system dashboard
email-server-dashboard.sh

# Security dashboard
email-security-dashboard.sh

# Manage backups
email-server-backup.sh

# Test server functionality
./scripts/13-test-server.sh

# Manage Fail2Ban
manage-fail2ban.sh help

# Manage email users
manage-email-users.sh add     # Add new email user
manage-email-users.sh list    # List all email users
manage-email-users.sh delete  # Remove email user
```

### SSH Access (System Administration)

The email server uses standard SSH configuration:
- **Port:** 22 (unchanged)
- **Root Login:** Disabled (you must use sudo users)
- **Authentication:** Key-based only (no passwords)
- **Access Control:** 
  - Direct access if VPN disabled
  - VPN-only access if VPN enabled

#### Accessing Your Server
```bash
# Direct SSH (default)
ssh your-admin-user@your-server-ip

# If VPN is enabled, first connect to VPN:
# 1. Install WireGuard client
# 2. Import config from: /etc/email-server/wireguard-client-config-summary.txt
# 3. Connect to VPN
# 4. Then SSH normally
ssh your-admin-user@10.0.0.1  # VPN server IP
```

### VPN Access (if enabled)
1. Download client configuration: `/etc/email-server/wireguard-client-config-summary.txt`
2. Import into WireGuard client
3. Connect before accessing SSH
4. Use VPN server IP (default: 10.0.0.1) for SSH connections

## Directory Structure

```
email-server-setup/
├── email-server-setup.sh          # Main installer script
├── email-server-config.conf       # Configuration file
├── README.md                      # This file
├── scripts/                       # Individual component scripts
│   ├── 01-install-dependencies.sh
│   ├── 02-configure-dns.sh
│   ├── 03-setup-firewall.sh
│   ├── 04-install-ssl.sh
│   ├── 05-setup-postgresql.sh
│   ├── 06-configure-postfix.sh
│   ├── 07-configure-dovecot.sh
│   ├── 08-setup-wireguard.sh
│   ├── 09-configure-dkim.sh
│   ├── 10-setup-spamassassin.sh
│   ├── 11-configure-fail2ban.sh
│   ├── 12-setup-monitoring.sh
│   ├── 13-test-server.sh
│   ├── 14-configure-autodiscovery.sh
│   ├── 15-create-backups.sh
│   ├── 16-security-hardening.sh
│   └── show-summary.sh
└── templates/                     # Configuration templates
```

## Backup and Restore

### Automatic Backups
- **Daily:** Configuration, database, SSL certificates
- **Weekly:** Mail data, full system backup
- **Retention:** 30 days (configurable)

### Manual Backup
```bash
# Full backup
email-server-backup.sh

# Component backup
email-server-backup-component.sh config
email-server-backup-component.sh database
email-server-backup-component.sh mail
```

### Restore
See `/backups/RESTORE-GUIDE.md` for detailed restore instructions.

## Monitoring

### Built-in Monitoring
- Real-time dashboard
- Daily email reports
- Security alerts
- Log aggregation
- Fail2Ban monitoring

### Web Interface
Access monitoring at: `https://yourdomain.org/monitor/`

## Security

### Security Features
- SSH hardening (key-only access)
- Automatic security updates
- Intrusion detection (AIDE)
- Rate limiting on all services
- Content filtering
- Fail2Ban integration

### Security Best Practices
1. Regularly review logs
2. Keep system updated
3. Use strong passwords
4. Enable VPN for administration
5. Regular security audits

## Understanding Users

### System vs Email Users

The email server uses two distinct types of users:

#### System Users (SSH/Administration)
- Purpose: Server administration via SSH
- Authentication: SSH keys
- Access: Can use sudo, manage server
- Created by: `add_sudo_users.sh` script
- Login: SSH on port 22
- Examples: `admin`, `john`, `devops`

#### Email Users (Mail Service)
- Purpose: Sending/receiving email
- Authentication: Email passwords
- Access: IMAP/SMTP/POP3 protocols only
- Created by: Database entries (see email user management)
- Login: Email clients on ports 993/587/995
- Examples: `user@yourdomain.org`, `support@yourdomain.org`

**Important:** These are completely separate! A system user `john` cannot automatically receive email at `john@yourdomain.org` without creating a separate email user entry.

## Troubleshooting

### Common Issues

1. **Cannot SSH into server**
   - Verify you're using the correct admin user (not email user)
   - Check if VPN is required and properly configured
   - Confirm SSH key is properly set up

2. **Email delivery problems**
   - Check DNS records
   - Verify SSL certificates
   - Review /var/log/mail.log
   - Ensure email user exists in database

3. **Service not starting**
   - Check service status: `systemctl status servicename`
   - Review service logs: `journalctl -u servicename`

4. **Cannot login to email client**
   - Verify email user exists: `manage-email-users.sh list`
   - Confirm correct credentials
   - Check port settings (993/587/995)
   - Review /var/log/dovecot.log

5. **Permission denied errors**
   - Verify you're using a system admin user
   - Ensure user is in sudo group

### Getting Help
- Check documentation in `/etc/email-server/`
- Review log files in `/var/log/`
- Run diagnostic scripts in `/scripts/`

## Maintenance

### Regular Maintenance Tasks
- **Daily:** Monitor service status and logs
- **Weekly:** Review fail2ban logs and security reports
- **Monthly:** Update system packages and certificates
- **Quarterly:** Full security audit and backup testing

### Updates
To update the installation:
```bash
cd email-server-setup
git pull
sudo ./email-server-setup.sh
```

## Contributing

We welcome contributions! Please read our contributing guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Postfix](http://www.postfix.org/)
- [Dovecot](https://www.dovecot.org/)
- [PostgreSQL](https://www.postgresql.org/)
- [Let's Encrypt](https://letsencrypt.org/)
- [WireGuard](https://www.wireguard.com/)

## Support

For support:
- Check the documentation in `/etc/email-server/`
- Review the troubleshooting section
- Contact: [your-email@domain.com]

## Changelog

### Version 1.0.0
- Initial release
- Complete email server automation
- VPN integration
- Comprehensive monitoring
- Security hardening

---

Made with ❤️ for secure email communications
