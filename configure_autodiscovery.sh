#!/bin/bash

# Script to configure email client autodiscovery
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

# Check if autodiscovery is enabled
check_autodiscovery_enabled() {
    if [[ "$ENABLE_AUTODISCOVERY" != "true" ]]; then
        print_warning "Autodiscovery is not enabled in configuration. Skipping setup."
        exit 0
    fi
}

# Function to install Apache if needed
install_apache() {
    print_info "Installing Apache web server for autodiscovery..."
    
    # Check if Apache is already installed
    if command -v apache2 &> /dev/null; then
        print_info "Apache is already installed"
        return 0
    fi
    
    # Install Apache
    apt-get update
    apt-get install -y apache2 apache2-utils
    
    # Enable required modules
    a2enmod rewrite
    a2enmod ssl
    a2enmod headers
    
    # Start and enable Apache
    systemctl start apache2
    systemctl enable apache2
    
    print_info "Apache installed and started"
}

# Function to configure SSL for webserver
configure_webserver_ssl() {
    print_info "Configuring SSL for web server..."
    
    # Check if certificate exists
    if [[ ! -f /etc/letsencrypt/live/$DOMAIN/fullchain.pem ]]; then
        print_warning "SSL certificate for $DOMAIN not found, creating one..."
        
        # Stop Apache temporarily
        systemctl stop apache2
        
        # Generate certificate
        certbot certonly \
            --standalone \
            --preferred-challenges http-01 \
            --cert-name $DOMAIN \
            -d $DOMAIN \
            -d autodiscover.$DOMAIN \
            --email $ADMIN_EMAIL \
            --agree-tos \
            --non-interactive
        
        # Start Apache again
        systemctl start apache2
    fi
    
    # Create SSL virtual host
    cat << EOF > /etc/apache2/sites-available/$DOMAIN-ssl.conf
<VirtualHost *:443>
    ServerName $DOMAIN
    ServerAlias autodiscover.$DOMAIN
    DocumentRoot /var/www/html
    
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/$DOMAIN/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/$DOMAIN/privkey.pem
    
    # Modern SSL configuration
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder off
    SSLSessionTickets off
    
    # Security headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    
    # Autodiscovery configuration
    <Directory "/var/www/html/autodiscover">
        Options +FollowSymlinks
        AllowOverride All
        Require all granted
    </Directory>
    
    <Directory "/var/www/html/.well-known">
        Options +FollowSymlinks
        AllowOverride All
        Require all granted
    </Directory>
    
    # Log files
    ErrorLog \${APACHE_LOG_DIR}/$DOMAIN-error.log
    CustomLog \${APACHE_LOG_DIR}/$DOMAIN-access.log combined
</VirtualHost>
EOF
    
    # Enable the SSL site
    a2ensite $DOMAIN-ssl.conf
    systemctl reload apache2
    
    print_info "SSL configured for web server"
}

# Function to create Thunderbird autoconfig
create_thunderbird_autoconfig() {
    print_info "Creating Thunderbird autoconfig..."
    
    mkdir -p /var/www/html/.well-known/autoconfig/mail
    
    cat << EOF > /var/www/html/.well-known/autoconfig/mail/config-v1.1.xml
<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="$DOMAIN">
    <domain>$DOMAIN</domain>
    <displayName>$DOMAIN Mail Server</displayName>
    <displayShortName>$DOMAIN</displayShortName>
    <incomingServer type="imap">
      <hostname>mail.$DOMAIN</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <incomingServer type="pop3">
      <hostname>mail.$DOMAIN</hostname>
      <port>995</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
      <leaveMessagesOnServer>true</leaveMessagesOnServer>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>mail.$DOMAIN</hostname>
      <port>587</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
    <documentation url="https://$DOMAIN/mail-setup">
      <descr lang="en">$DOMAIN Email Setup Guide</descr>
    </documentation>
  </emailProvider>
</clientConfig>
EOF
    
    print_info "Thunderbird autoconfig created"
}

# Function to create Outlook autodiscover
create_outlook_autodiscover() {
    print_info "Creating Outlook autodiscover..."
    
    mkdir -p /var/www/html/autodiscover
    
    # Create main autodiscover XML
    cat << EOF > /var/www/html/autodiscover/autodiscover.xml
<?xml version="1.0" encoding="UTF-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
      <Protocol>
        <Type>IMAP</Type>
        <Server>mail.$DOMAIN</Server>
        <Port>993</Port>
        <DomainRequired>off</DomainRequired>
        <LoginName>%EMAILADDRESS%</LoginName>
        <SPA>off</SPA>
        <SSL>on</SSL>
        <AuthRequired>on</AuthRequired>
      </Protocol>
      <Protocol>
        <Type>SMTP</Type>
        <Server>mail.$DOMAIN</Server>
        <Port>587</Port>
        <DomainRequired>off</DomainRequired>
        <LoginName>%EMAILADDRESS%</LoginName>
        <SPA>off</SPA>
        <Encryption>TLS</Encryption>
        <AuthRequired>on</AuthRequired>
        <UsePOPAuth>on</UsePOPAuth>
        <SMTPLast>off</SMTPLast>
      </Protocol>
    </Account>
  </Response>
</Autodiscover>
EOF
    
    # Create PHP handler for POST requests
    cat << 'EOFphp' > /var/www/html/autodiscover/autodiscover.php
<?php
// Outlook autodiscover handler
header("Content-Type: application/xml; charset=utf-8");

// Get the email address from POST data
$postData = file_get_contents("php://input");
$xml = simplexml_load_string($postData);

if ($xml && isset($xml->Request->EMailAddress)) {
    $email = (string)$xml->Request->EMailAddress;
    
    // Replace placeholder with actual email
    $autodiscoverXml = file_get_contents('/var/www/html/autodiscover/autodiscover.xml');
    $autodiscoverXml = str_replace('%EMAILADDRESS%', $email, $autodiscoverXml);
    
    echo $autodiscoverXml;
} else {
    http_response_code(400);
    echo "Invalid request";
}
EOFphp
    
    # Create .htaccess for proper routing
    cat << EOF > /var/www/html/autodiscover/.htaccess
RewriteEngine On
RewriteCond %{REQUEST_METHOD} ^POST\$
RewriteCond %{REQUEST_URI} ^/autodiscover/autodiscover.xml\$
RewriteRule ^(.*)\$ autodiscover.php [L,QSA]

# Ensure XML content type
<Files "autodiscover.xml">
    AddType application/xml .xml
</Files>

# Security headers
Header set X-Content-Type-Options "nosniff"
Header set X-Frame-Options "DENY"

# Allow POST requests
<Limit GET POST>
    Require all granted
</Limit>
EOF
    
    print_info "Outlook autodiscover created"
}

# Function to create iOS Configuration Profile
create_ios_profile() {
    print_info "Creating iOS configuration profile..."
    
    mkdir -p /var/www/html/profiles/ios
    
    # Install PHP for mobileconfig generation
    apt-get install -y php php-cli php-xml
    
    # Create iOS profile generator
    cat << 'EOFphp' > /var/www/html/profiles/ios/email-profile.php
<?php
// iOS Email Configuration Profile Generator

// Get email from query parameter
$email = isset($_GET['email']) ? $_GET['email'] : '';
$domain = isset($_GET['domain']) ? $_GET['domain'] : '';

if (empty($email) || empty($domain)) {
    die("Email and domain parameters required");
}

// Generate unique identifiers
$uuid = com_create_guid();
$payloadId = "email." . str_replace(".", "-", $domain) . ".config";

// Set headers for download
header('Content-Type: application/x-apple-aspen-config');
header('Content-Disposition: attachment; filename="' . $domain . '-email.mobileconfig"');

// Generate the profile
$profile = '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.mail.managed</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>' . $payloadId . '.email</string>
            <key>PayloadUUID</key>
            <string>' . $uuid . '</string>
            <key>PayloadDisplayName</key>
            <string>' . $domain . ' Email</string>
            <key>PayloadDescription</key>
            <string>Email settings for ' . $domain . '</string>
            <key>EmailAccountType</key>
            <string>EmailTypeIMAP</string>
            <key>EmailAccountDescription</key>
            <string>' . $domain . ' Email</string>
            <key>EmailAccountName</key>
            <string>' . $domain . ' Mail</string>
            <key>EmailAddress</key>
            <string>' . $email . '</string>
            <key>IncomingMailServerAuthentication</key>
            <string>EmailAuthPassword</string>
            <key>IncomingMailServerHostName</key>
            <string>mail.' . $domain . '</string>
            <key>IncomingMailServerPortNumber</key>
            <integer>993</integer>
            <key>IncomingMailServerUseSSL</key>
            <true/>
            <key>IncomingMailServerUsername</key>
            <string>' . $email . '</string>
            <key>OutgoingMailServerAuthentication</key>
            <string>EmailAuthPassword</string>
            <key>OutgoingMailServerHostName</key>
            <string>mail.' . $domain . '</string>
            <key>OutgoingMailServerPortNumber</key>
            <integer>587</integer>
            <key>OutgoingMailServerUseSSL</key>
            <false/>
            <key>OutgoingMailServerUsername</key>
            <string>' . $email . '</string>
            <key>OutgoingPasswordSameAsIncomingPassword</key>
            <true/>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>' . $domain . ' Email Configuration</string>
    <key>PayloadDescription</key>
    <string>Automatically configure email for ' . $domain . '</string>
    <key>PayloadIdentifier</key>
    <string>' . $payloadId . '</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>' . $uuid . '</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>';

echo $profile;

EOFphp
    
    # Create iOS profile landing page
    cat << EOFhtml > /var/www/html/profiles/ios/index.html
<!DOCTYPE html>
<html>
<head>
    <title>iOS Email Configuration - $DOMAIN</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: -apple-system, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; }
        .container { background: #f9f9f9; padding: 30px; border-radius: 10px; }
        .button { display: inline-block; background: #007AFF; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; margin: 10px 0; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
        .note { font-size: 0.9em; color: #666; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Email Configuration for $DOMAIN</h1>
        <p>Download email settings for your iOS device.</p>
        
        <form method="get" action="email-profile.php">
            <input type="hidden" name="domain" value="$DOMAIN">
            <input type="email" name="email" placeholder="Enter your email address" required>
            <input type="submit" value="Download Profile" class="button">
        </form>
        
        <div class="note">
            <p><strong>Instructions:</strong></p>
            <ol>
                <li>Enter your email address above</li>
                <li>Download the configuration profile</li>
                <li>Install the profile on your iOS device</li>
                <li>Enter your password when prompted</li>
            </ol>
        </div>
    </div>
</body>
</html>
EOFhtml
    
    print_info "iOS configuration profile created"
}

# Function to create Android configuration
create_android_config() {
    print_info "Creating Android configuration..."
    
    mkdir -p /var/www/html/profiles/android
    
    # Create Android setup page
    cat << EOFhtml > /var/www/html/profiles/android/index.html
<!DOCTYPE html>
<html>
<head>
    <title>Android Email Setup - $DOMAIN</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: 'Roboto', sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; }
        .container { background: #f9f9f9; padding: 30px; border-radius: 10px; }
        .settings { background: #fff; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .setting { margin: 10px 0; }
        .label { font-weight: bold; color: #555; }
        .value { font-family: monospace; background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
        .tabs { display: flex; margin-bottom: 20px; }
        .tab { flex: 1; text-align: center; padding: 10px; background: #ddd; cursor: pointer; }
        .tab.active { background: #007AFF; color: white; }
        .content { display: none; }
        .content.active { display: block; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Email Configuration for $DOMAIN</h1>
        <p>Manual setup instructions for Android devices.</p>
        
        <div class="tabs">
            <div class="tab active" onclick="showTab('imap')">IMAP Settings</div>
            <div class="tab" onclick="showTab('pop3')">POP3 Settings</div>
        </div>
        
        <div id="imap" class="content active">
            <div class="settings">
                <h3>Incoming Mail (IMAP)</h3>
                <div class="setting">
                    <span class="label">Server:</span>
                    <span class="value">mail.$DOMAIN</span>
                </div>
                <div class="setting">
                    <span class="label">Port:</span>
                    <span class="value">993</span>
                </div>
                <div class="setting">
                    <span class="label">Security:</span>
                    <span class="value">SSL/TLS</span>
                </div>
                <div class="setting">
                    <span class="label">Username:</span>
                    <span class="value">your-email@$DOMAIN</span>
                </div>
                <div class="setting">
                    <span class="label">Password:</span>
                    <span class="value">your-password</span>
                </div>
            </div>
        </div>
        
        <div id="pop3" class="content">
            <div class="settings">
                <h3>Incoming Mail (POP3)</h3>
                <div class="setting">
                    <span class="label">Server:</span>
                    <span class="value">mail.$DOMAIN</span>
                </div>
                <div class="setting">
                    <span class="label">Port:</span>
                    <span class="value">995</span>
                </div>
                <div class="setting">
                    <span class="label">Security:</span>
                    <span class="value">SSL/TLS</span>
                </div>
                <div class="setting">
                    <span class="label">Username:</span>
                    <span class="value">your-email@$DOMAIN</span>
                </div>
                <div class="setting">
                    <span class="label">Password:</span>
                    <span class="value">your-password</span>
                </div>
            </div>
        </div>
        
        <div class="settings">
            <h3>Outgoing Mail (SMTP)</h3>
            <div class="setting">
                <span class="label">Server:</span>
                <span class="value">mail.$DOMAIN</span>
            </div>
            <div class="setting">
                <span class="label">Port:</span>
                <span class="value">587</span>
            </div>
            <div class="setting">
                <span class="label">Security:</span>
                <span class="value">STARTTLS</span>
            </div>
            <div class="setting">
                <span class="label">Username:</span>
                <span class="value">your-email@$DOMAIN</span>
            </div>
            <div class="setting">
                <span class="label">Password:</span>
                <span class="value">your-password</span>
            </div>
            <div class="setting">
                <span class="label">Require Auth:</span>
                <span class="value">Yes</span>
            </div>
        </div>
    </div>
    
    <script>
        function showTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.content').forEach(c => c.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tab).classList.add('active');
        }
    </script>
</body>
</html>
EOFhtml
    
    print_info "Android configuration created"
}

# Function to create main setup landing page
create_setup_landing_page() {
    print_info "Creating main email setup landing page..."
    
    mkdir -p /var/www/html/mail-setup
    
    cat << EOFhtml > /var/www/html/mail-setup/index.html
<!DOCTYPE html>
<html>
<head>
    <title>Email Setup Guide - $DOMAIN</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; background: #f4f4f4; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 40px; }
        .device-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-top: 30px; }
        .device-card { background: #f9f9f9; padding: 20px; border-radius: 8px; text-align: center; }
        .device-card h3 { margin-top: 0; }
        .button { display: inline-block; background: #007AFF; color: white; padding: 10px 20px; border-radius: 5px; text-decoration: none; margin: 10px 0; }
        .manual-settings { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; }
        .setting-group { margin: 20px 0; }
        .setting { display: flex; margin: 10px 0; }
        .setting-label { flex: 1; font-weight: bold; }
        .setting-value { flex: 2; font-family: monospace; background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Email Setup Guide</h1>
            <p>Configure your email client to connect to $DOMAIN</p>
        </div>
        
        <h2>Automatic Configuration</h2>
        <div class="device-grid">
            <div class="device-card">
                <h3>iOS / iPhone</h3>
                <p>Download a configuration profile for automatic setup</p>
                <a href="/profiles/ios/" class="button">iOS Setup</a>
            </div>
            
            <div class="device-card">
                <h3>Android</h3>
                <p>Follow step-by-step instructions for Android devices</p>
                <a href="/profiles/android/" class="button">Android Setup</a>
            </div>
            
            <div class="device-card">
                <h3>Thunderbird</h3>
                <p>Automatic configuration for Mozilla Thunderbird</p>
                <a href="/.well-known/autoconfig/mail/config-v1.1.xml" class="button">Thunderbird Config</a>
            </div>
            
            <div class="device-card">
                <h3>Outlook</h3>
                <p>Microsoft Outlook autodiscovery support</p>
                <a href="/autodiscover/autodiscover.xml" class="button">Outlook Setup</a>
            </div>
        </div>
        
        <div class="manual-settings">
            <h2>Manual Configuration</h2>
            
            <div class="setting-group">
                <h3>Incoming Mail (IMAP)</h3>
                <div class="setting">
                    <span class="setting-label">Server:</span>
                    <span class="setting-value">mail.$DOMAIN</span>
                </div>
                <div class="setting">
                    <span class="setting-label">Port:</span>
                    <span class="setting-value">993</span>
                </div>
                <div class="setting">
                    <span class="setting-label">Security:</span>
                    <span class="setting-value">SSL/TLS</span>
                </div>
                <div class="setting">
                    <span class="setting-label">Username:</span>
                    <span class="setting-value">your-email@$DOMAIN</span>
                </div>
            </div>
            
            <div class="setting-group">
                <h3>Outgoing Mail (SMTP)</h3>
                <div class="setting">
                    <span class="setting-label">Server:</span>
                    <span class="setting-value">mail.$DOMAIN</span>
                </div>
                <div class="setting">
                    <span class="setting-label">Port:</span>
                    <span class="setting-value">587</span>
                </div>
                <div class="setting">
                    <span class="setting-label">Security:</span>
                    <span class="setting-value">STARTTLS</span>
                </div>
                <div class="setting">
                    <span class="setting-label">Auth Required:</span>
                    <span class="setting-value">Yes</span>
                </div>
                <div class="setting">
                    <span class="setting-label">Username:</span>
                    <span class="setting-value">your-email@$DOMAIN</span>
                </div>
            </div>
        </div>
        
        <div style="margin-top: 40px; text-align: center; font-size: 0.9em; color: #666;">
            <p>For support, contact: $ADMIN_EMAIL</p>
        </div>
    </div>
</body>
</html>
EOFhtml
    
    print_info "Main setup landing page created"
}

# Function to configure DNS records for autodiscovery
create_autodiscovery_dns_instructions() {
    print_info "Creating autodiscovery DNS instructions..."
    
    cat << EOF > /etc/email-server/autodiscovery-dns.txt
# DNS Records for Autodiscovery
# Add these records to enable email client autodiscovery

# CNAME Record for Outlook autodiscovery
autodiscover.$DOMAIN.    IN    CNAME    $DOMAIN.

# SRV Records for various services
_imap._tcp.$DOMAIN.          3600 IN SRV 10 1 993  mail.$DOMAIN.
_imaps._tcp.$DOMAIN.         3600 IN SRV 10 1 993  mail.$DOMAIN.
_pop3._tcp.$DOMAIN.          3600 IN SRV 10 1 995  mail.$DOMAIN.
_pop3s._tcp.$DOMAIN.         3600 IN SRV 10 1 995  mail.$DOMAIN.
_submission._tcp.$DOMAIN.    3600 IN SRV 10 1 587  mail.$DOMAIN.
_autodiscover._tcp.$DOMAIN.  3600 IN SRV 10 1 443  autodiscover.$DOMAIN.

# Additional TXT records for autoconfig
_autoconfig.$DOMAIN.    IN    TXT    "https://autoconfig.$DOMAIN/mail/config-v1.1.xml"

# Instructions:
# 1. Add all the above records to your DNS zone
# 2. Wait for DNS propagation (can take up to 48 hours)
# 3. Test with various email clients
# 4. Check the setup guide at https://$DOMAIN/mail-setup/

EOF
    
    print_info "Autodiscovery DNS instructions created: /etc/email-server/autodiscovery-dns.txt"
}

# Function to test autodiscovery configuration
test_autodiscovery() {
    print_info "Testing autodiscovery configuration..."
    
    # Test web server accessibility
    if curl -s -I https://$DOMAIN/autodiscover/autodiscover.xml | grep -q "200 OK"; then
        print_info "✓ Autodiscover endpoint accessible"
    else
        print_error "✗ Autodiscover endpoint not accessible"
    fi
    
    # Test autoconfig endpoint
    if curl -s -I https://$DOMAIN/.well-known/autoconfig/mail/config-v1.1.xml | grep -q "200 OK"; then
        print_info "✓ Autoconfig endpoint accessible"
    else
        print_error "✗ Autoconfig endpoint not accessible"
    fi
    
    # Test SSL
    if openssl s_client -connect $DOMAIN:443 -servername $DOMAIN </dev/null 2>/dev/null | grep -q "Verify return code: 0"; then
        print_info "✓ SSL certificate valid"
    else
        print_error "✗ SSL certificate issues"
    fi
    
    # Create test report
    cat << EOF > /etc/email-server/autodiscovery-test-report.txt
Autodiscovery Test Report
========================
Generated on: $(date)

Endpoint Tests:
--------------
Autodiscover XML: $(curl -s -o /dev/null -w "%{http_code}" https://$DOMAIN/autodiscover/autodiscover.xml)
Autoconfig XML: $(curl -s -o /dev/null -w "%{http_code}" https://$DOMAIN/.well-known/autoconfig/mail/config-v1.1.xml)
iOS Profile Generator: $(curl -s -o /dev/null -w "%{http_code}" https://$DOMAIN/profiles/ios/)
Android Setup: $(curl -s -o /dev/null -w "%{http_code}" https://$DOMAIN/profiles/android/)
Setup Guide: $(curl -s -o /dev/null -w "%{http_code}" https://$DOMAIN/mail-setup/)

SSL Status:
-----------
$(openssl s_client -connect $DOMAIN:443 -servername $DOMAIN </dev/null 2>&1 | grep -E "(subject|issuer|Verify)")

DNS Records (to be added):
------------------------
$(cat /etc/email-server/autodiscovery-dns.txt | grep -E "(CNAME|SRV|TXT)")

Next Steps:
-----------
1. Add DNS records listed above
2. Test with various email clients
3. Share the setup guide URL: https://$DOMAIN/mail-setup/
EOF
    
    print_info "Test report created: /etc/email-server/autodiscovery-test-report.txt"
}

# Function to set proper permissions
set_autodiscovery_permissions() {
    print_info "Setting proper permissions for autodiscovery files..."
    
    # Set ownership
    chown -R www-data:www-data /var/www/html
    
    # Set directory permissions
    find /var/www/html -type d -exec chmod 755 {} \;
    
    # Set file permissions
    find /var/www/html -type f -exec chmod 644 {} \;
    
    # Make PHP files executable
    find /var/www/html -name "*.php" -exec chmod 755 {} \;
    
    print_info "Permissions set successfully"
}

# Main execution
print_info "Starting autodiscovery configuration..."

# Check if autodiscovery is enabled
check_autodiscovery_enabled

# Install Apache if needed
install_apache

# Configure SSL for webserver
configure_webserver_ssl

# Create autodiscovery configurations
create_thunderbird_autoconfig
create_outlook_autodiscover
create_ios_profile
create_android_config
create_setup_landing_page

# Create DNS instructions
create_autodiscovery_dns_instructions

# Set proper permissions
set_autodiscovery_permissions

# Test configuration
test_autodiscovery

print_info "Autodiscovery configuration complete!"
print_info "Important URLs:"
echo "  - Setup Guide: https://$DOMAIN/mail-setup/"
echo "  - iOS Profile: https://$DOMAIN/profiles/ios/"
echo "  - Android Setup: https://$DOMAIN/profiles/android/"
echo "  - Thunderbird Config: https://$DOMAIN/.well-known/autoconfig/mail/config-v1.1.xml"
echo "  - Outlook Autodiscover: https://$DOMAIN/autodiscover/autodiscover.xml"

print_warning "Next steps:"
echo "1. Add the DNS records from /etc/email-server/autodiscovery-dns.txt"
echo "2. Wait for DNS propagation"
echo "3. Test with various email clients"
echo "4. Share the setup guide with your users"
echo "5. Review test report: /etc/email-server/autodiscovery-test-report.txt"
