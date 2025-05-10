#!/bin/bash

# Script to switch from Let's Encrypt to Cloudflare SSL certificates
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

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    exit 1
fi

print_info "Switching from Let's Encrypt to Cloudflare SSL certificates..."

# Ask for Cloudflare certificate method
echo "Choose Cloudflare SSL method:"
echo "1. Use existing Cloudflare Origin Certificate (recommended)"
echo "2. Use Cloudflare API to generate certificate"
echo "3. Upload custom Cloudflare certificates"
read -p "Select option [1-3]: " method

case $method in
    1)
        print_info "Using existing Cloudflare Origin Certificate..."
        
        # Ask for certificate paths
        read -p "Enter path to Cloudflare certificate (.pem file): " cert_path
        read -p "Enter path to Cloudflare private key (.key file): " key_path
        
        # Validate files exist
        if [[ ! -f "$cert_path" ]] || [[ ! -f "$key_path" ]]; then
            print_error "Certificate or key file not found!"
            exit 1
        fi
        
        ;;
    2)
        print_info "Using Cloudflare API to generate certificate..."
        
        # Install acme.sh if not present
        if ! command -v acme.sh &> /dev/null; then
            print_info "Installing acme.sh..."
            curl https://get.acme.sh | sh
            source ~/.acme.sh/acme.sh.env
        fi
        
        # Ask for Cloudflare credentials
        read -p "Enter Cloudflare API Token: " cf_token
        read -p "Enter Cloudflare Account ID: " cf_account_id
        
        # Set up environment
        export CF_Token="$cf_token"
        export CF_Account_ID="$cf_account_id"
        
        # Generate certificate
        print_info "Generating certificate via Cloudflare DNS challenge..."
        acme.sh --issue -d "mail.$DOMAIN" -d "$DOMAIN" --dns dns_cf
        
        # Set paths
        cert_path="/root/.acme.sh/$DOMAIN/fullchain.cer"
        key_path="/root/.acme.sh/$DOMAIN/$DOMAIN.key"
        
        ;;
    3)
        print_info "Upload custom Cloudflare certificates..."
        
        # Create upload directory
        upload_dir="/tmp/cloudflare-ssl-upload"
        mkdir -p "$upload_dir"
        
        echo "Please upload your Cloudflare certificate files to: $upload_dir"
        echo "Expected files:"
        echo "  - certificate.pem (or .crt)"
        echo "  - private.key"
        echo "Press Enter when files are uploaded..."
        read
        
        # Find uploaded files
        cert_path=$(find "$upload_dir" -name "*.pem" -o -name "*.crt" | head -1)
        key_path=$(find "$upload_dir" -name "*.key" | head -1)
        
        if [[ -z "$cert_path" ]] || [[ -z "$key_path" ]]; then
            print_error "Certificate or key file not found in upload directory!"
            exit 1
        fi
        
        ;;
    *)
        print_error "Invalid option"
        exit 1
        ;;
esac

# Create Cloudflare SSL directory
CLOUDFLARE_SSL_DIR="/etc/ssl/cloudflare"
mkdir -p "$CLOUDFLARE_SSL_DIR"

# Copy certificates to standard location
cp "$cert_path" "$CLOUDFLARE_SSL_DIR/fullchain.pem"
cp "$key_path" "$CLOUDFLARE_SSL_DIR/privkey.pem"

# Set proper permissions
chmod 644 "$CLOUDFLARE_SSL_DIR/fullchain.pem"
chmod 600 "$CLOUDFLARE_SSL_DIR/privkey.pem"

# Backup current Let's Encrypt certificates
if [[ -d /etc/letsencrypt ]]; then
    print_info "Backing up Let's Encrypt certificates..."
    cp -r /etc/letsencrypt /etc/letsencrypt.backup-$(date +%Y%m%d)
fi

# Update Postfix configuration
print_info "Updating Postfix configuration..."
postconf -e smtpd_tls_cert_file=$CLOUDFLARE_SSL_DIR/fullchain.pem
postconf -e smtpd_tls_key_file=$CLOUDFLARE_SSL_DIR/privkey.pem

# Update Dovecot configuration
print_info "Updating Dovecot configuration..."
sed -i "s|ssl_cert = <.*|ssl_cert = <$CLOUDFLARE_SSL_DIR/fullchain.pem|" /etc/dovecot/conf.d/10-ssl.conf
sed -i "s|ssl_key = <.*|ssl_key = <$CLOUDFLARE_SSL_DIR/privkey.pem|" /etc/dovecot/conf.d/10-ssl.conf

# Update Apache configuration
if [[ -f /etc/apache2/sites-available/$DOMAIN-ssl.conf ]]; then
    print_info "Updating Apache configuration..."
    sed -i "s|SSLCertificateFile.*|SSLCertificateFile $CLOUDFLARE_SSL_DIR/fullchain.pem|" /etc/apache2/sites-available/$DOMAIN-ssl.conf
    sed -i "s|SSLCertificateKeyFile.*|SSLCertificateKeyFile $CLOUDFLARE_SSL_DIR/privkey.pem|" /etc/apache2/sites-available/$DOMAIN-ssl.conf
fi

# Disable Let's Encrypt auto-renewal
print_info "Disabling Let's Encrypt auto-renewal..."
systemctl disable certbot.timer 2>/dev/null || true
systemctl stop certbot.timer 2>/dev/null || true

# Create Cloudflare renewal script (for API method)
if [[ $method -eq 2 ]]; then
    print_info "Creating Cloudflare renewal script..."
    
    cat << 'RENEWAL_SCRIPT' > /usr/local/bin/renew-cloudflare-ssl.sh
#!/bin/bash

# Cloudflare SSL renewal script
source ~/.acme.sh/acme.sh.env

# Renew certificate
acme.sh --renew -d "mail.$DOMAIN" -d "$DOMAIN"

# Install renewed certificate
acme.sh --install-cert -d "$DOMAIN" \
    --cert-file /etc/ssl/cloudflare/fullchain.pem \
    --key-file /etc/ssl/cloudflare/privkey.pem \
    --reloadcmd "systemctl restart postfix dovecot apache2"

# Log renewal
echo "$(date): Cloudflare SSL renewed successfully" >> /var/log/cloudflare-ssl-renewal.log
RENEWAL_SCRIPT
    
    chmod +x /usr/local/bin/renew-cloudflare-ssl.sh
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "0 3 1 * * /usr/local/bin/renew-cloudflare-ssl.sh") | crontab -
fi

# Update email server configuration
sed -i "s|CUSTOM_SSL_CERT_PATH=.*|CUSTOM_SSL_CERT_PATH=\"$CLOUDFLARE_SSL_DIR/fullchain.pem\"|" /etc/email-server-config.conf
sed -i "s|CUSTOM_SSL_KEY_PATH=.*|CUSTOM_SSL_KEY_PATH=\"$CLOUDFLARE_SSL_DIR/privkey.pem\"|" /etc/email-server-config.conf

# Test certificates
print_info "Testing new certificates..."
openssl x509 -in "$CLOUDFLARE_SSL_DIR/fullchain.pem" -text -noout | grep -E "(Issuer:|Subject:|Not Before|Not After)"

# Restart services
print_info "Restarting services..."
systemctl restart postfix
systemctl restart dovecot
if systemctl is-active --quiet apache2; then
    systemctl restart apache2
fi

# Verify SSL configuration
print_info "Verifying SSL configuration..."
echo | openssl s_client -connect mail.$DOMAIN:993 -servername mail.$DOMAIN 2>&1 | grep -E "(subject|issuer|Verify)"

# Create summary
cat << EOF > /etc/email-server/cloudflare-ssl-summary.txt
Cloudflare SSL Configuration Summary
====================================
Date: $(date)
Method: $method

Certificate Paths:
- Certificate: $CLOUDFLARE_SSL_DIR/fullchain.pem
- Private Key: $CLOUDFLARE_SSL_DIR/privkey.pem

Certificate Details:
$(openssl x509 -in "$CLOUDFLARE_SSL_DIR/fullchain.pem" -subject -issuer -dates -noout)

Services Updated:
- Postfix: ✓
- Dovecot: ✓
- Apache: $(if [[ -f /etc/apache2/sites-available/$DOMAIN-ssl.conf ]]; then echo "✓"; else echo "N/A"; fi)

Let's Encrypt:
- Auto-renewal: Disabled
- Backup: /etc/letsencrypt.backup-$(date +%Y%m%d)

$(if [[ $method -eq 2 ]]; then
echo "Cloudflare Renewal:
- Script: /usr/local/bin/renew-cloudflare-ssl.sh
- Schedule: Monthly via crontab"
fi)

Next Steps:
1. Verify email functionality
2. Test SSL grades with SSL Labs
3. Update DNS records if needed
4. Monitor renewal (if using API method)
EOF

print_info "SSL switch completed successfully!"
print_info "Summary saved to: /etc/email-server/cloudflare-ssl-summary.txt"

# Cleanup
if [[ $method -eq 3 ]]; then
    rm -rf "$upload_dir"
fi

print_warning "Important notes:"
echo "1. Let's Encrypt auto-renewal has been disabled"
echo "2. Test email functionality thoroughly"
echo "3. Monitor Cloudflare certificate expiration"
if [[ $method -eq 1 ]]; then
    echo "4. Set up renewal for Origin Certificates manually"
fi
