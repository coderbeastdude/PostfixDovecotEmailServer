#!/bin/bash

# Script to provide DNS configuration instructions
# Part of the email server setup automation

set -euo pipefail

# Load configuration
source ../email-server-config.conf

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

print_dns() {
    echo -e "${BLUE}[DNS]${NC} $1"
}

# Function to generate DNS records
generate_dns_records() {
    cat << EOF > /etc/email-server/dns-records.txt
# DNS Records for $DOMAIN
# Please add these records to your DNS provider

# A Record (Mail server)
mail.$DOMAIN.    IN    A        $SERVER_IP

# MX Record (Mail exchange)
$DOMAIN.         IN    MX       10 mail.$DOMAIN.

# SPF Record (Sender Policy Framework)
$DOMAIN.         IN    TXT      "v=spf1 ip4:$SERVER_IP -all"

# DMARC Record (Domain-based Message Authentication)
_dmarc.$DOMAIN.  IN    TXT      "v=DMARC1; p=quarantine; rua=mailto:postmaster@$DOMAIN; ruf=mailto:postmaster@$DOMAIN; fo=1;"

# DKIM Record (will be generated later)
# default._domainkey.$DOMAIN.  IN    TXT      "DKIM_KEY_WILL_BE_HERE"

# Autodiscovery SRV Records (if enabled)
_imap._tcp.$DOMAIN.          3600 IN SRV 10 1 993  mail.$DOMAIN.
_submission._tcp.$DOMAIN.    3600 IN SRV 10 1 587  mail.$DOMAIN.
_autodiscover._tcp.$DOMAIN.  3600 IN SRV 10 1 443  $DOMAIN.

# Autodiscovery CNAME (if enabled)
autodiscover.$DOMAIN.    IN    CNAME    $DOMAIN.

# Reverse DNS (PTR Record) - Request from your hosting provider
$SERVER_IP    IN    PTR      mail.$DOMAIN.

# TLSA Record (for DANE) - Will be generated after SSL setup
# _443._tcp.mail.$DOMAIN.    3600 IN TLSA    3 1 1 HASH_WILL_BE_HERE

EOF
}

# Function to check existing DNS records
check_dns_records() {
    print_info "Checking current DNS configuration..."
    
    # Check A record
    print_dns "Checking A record for mail.$DOMAIN..."
    dig +short A mail.$DOMAIN
    
    # Check MX record
    print_dns "Checking MX record for $DOMAIN..."
    dig +short MX $DOMAIN
    
    # Check SPF record
    print_dns "Checking SPF record for $DOMAIN..."
    dig +short TXT $DOMAIN | grep "v=spf1" || echo "No SPF record found"
    
    # Check DMARC record
    print_dns "Checking DMARC record for $DOMAIN..."
    dig +short TXT _dmarc.$DOMAIN | grep "v=DMARC1" || echo "No DMARC record found"
    
    # Check reverse DNS
    print_dns "Checking reverse DNS for $SERVER_IP..."
    dig +short -x $SERVER_IP
    
    echo
}

# Function to generate DANE/TLSA instructions
generate_dane_instructions() {
    cat << 'EOF' > /etc/email-server/dane-instructions.txt
# DANE/TLSA Record Generation Instructions

After SSL certificate is installed, generate TLSA record with:

1. Run this command:
   openssl x509 -in /etc/letsencrypt/live/mail.$DOMAIN/cert.pem -pubkey -noout | \
   openssl pkey -pubin -outform DER | \
   openssl dgst -sha256 -binary | \
   xxd -p -c 32

2. Add this DNS record:
   _443._tcp.mail.$DOMAIN.    3600 IN TLSA    3 1 1 <HASH_FROM_STEP_1>

3. Verify with:
   dig +short TLSA _443._tcp.mail.$DOMAIN
EOF
}

# Function to create DNS zone file template
create_zone_file_template() {
    cat << EOF > /etc/email-server/zone-file-template.txt
; Zone file template for $DOMAIN
; TTL: 3600 seconds (1 hour)

\$TTL 3600
@    IN    SOA    ns1.$DOMAIN. admin.$DOMAIN. (
                    $(date +%Y%m%d)01    ; Serial
                    3600                 ; Refresh
                    600                  ; Retry
                    604800               ; Expire
                    86400 )              ; Minimum

; Name servers
@           IN    NS     ns1.$DOMAIN.
@           IN    NS     ns2.$DOMAIN.

; Mail server
mail        IN    A      $SERVER_IP
@           IN    MX     10 mail.$DOMAIN.

; Email authentication records
@           IN    TXT    "v=spf1 ip4:$SERVER_IP -all"
_dmarc      IN    TXT    "v=DMARC1; p=quarantine; rua=mailto:postmaster@$DOMAIN; ruf=mailto:postmaster@$DOMAIN; fo=1;"

; Autodiscovery records (if using)
_imap._tcp          3600 IN SRV 10 1 993  mail.$DOMAIN.
_submission._tcp    3600 IN SRV 10 1 587  mail.$DOMAIN.
_autodiscover._tcp  3600 IN SRV 10 1 443  $DOMAIN.
autodiscover        IN    CNAME  $DOMAIN.

; DKIM record (to be added after DKIM setup)
; default._domainkey IN TXT "v=DKIM1; h=sha256; k=rsa; p=YOUR_DKIM_PUBLIC_KEY"

; TLSA record (to be added after SSL setup)
; _443._tcp.mail     3600 IN TLSA 3 1 1 YOUR_TLSA_HASH
EOF
}

# Main execution
print_info "Starting DNS configuration process..."

# Generate DNS records
generate_dns_records
print_info "DNS records generated: /etc/email-server/dns-records.txt"

# Create zone file template
create_zone_file_template
print_info "Zone file template created: /etc/email-server/zone-file-template.txt"

# Generate DANE instructions
generate_dane_instructions
print_info "DANE instructions created: /etc/email-server/dane-instructions.txt"

# Check current DNS
check_dns_records

# Display instructions
echo
print_warning "=== DNS CONFIGURATION REQUIRED ==="
echo
echo "Please configure the following DNS records at your DNS provider:"
echo
cat /etc/email-server/dns-records.txt
echo
print_warning "Important notes:"
echo "1. Add all DNS records before proceeding with the installation"
echo "2. DNS propagation can take up to 48 hours"
echo "3. The DKIM record will be added after DKIM key generation"
echo "4. The TLSA record will be added after SSL certificate installation"
echo "5. Request reverse DNS (PTR) record from your hosting provider"
echo
echo "You can use these files for reference:"
echo "- DNS Records: /etc/email-server/dns-records.txt"
echo "- Zone File Template: /etc/email-server/zone-file-template.txt"
echo "- DANE Instructions: /etc/email-server/dane-instructions.txt"
echo
read -p "Press Enter when DNS records are configured and propagated..."

# Verify DNS again
print_info "Verifying DNS configuration..."
check_dns_records

print_info "DNS configuration check complete!"
