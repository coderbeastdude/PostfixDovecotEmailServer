#!/bin/bash

# Script to test the email server configuration
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

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Function to test service status
test_service_status() {
    print_step "Testing service status..."
    
    SERVICES=(
        "postfix:Mail Transfer Agent"
        "dovecot:IMAP/POP3 Server"
        "postgresql:Database Server"
        "opendkim:DKIM Service"
        "spamassassin:Spam Filter"
        "fail2ban:Intrusion Prevention"
    )
    
    if [[ "$ENABLE_VPN" == "true" ]]; then
        SERVICES+=("wg-quick@wg0:VPN Service")
    fi
    
    PASS=0
    FAIL=0
    
    for service_info in "${SERVICES[@]}"; do
        IFS=":" read -r service desc <<< "$service_info"
        if systemctl is-active --quiet "$service"; then
            print_info "✓ $desc ($service): Running"
            ((PASS++))
        else
            print_error "✗ $desc ($service): Not running"
            ((FAIL++))
        fi
    done
    
    echo
    echo "Service Status Summary: $PASS passed, $FAIL failed"
    echo
}

# Function to test network connectivity
test_network_connectivity() {
    print_step "Testing network connectivity..."
    
    PORTS=(
        "25:SMTP"
        "587:SMTP Submission"
        "993:IMAPS"
        "995:POP3S"
        "443:HTTPS"
    )
    
    if [[ "$ENABLE_VPN" == "true" ]]; then
        PORTS+=("51820:WireGuard")
    fi
    
    PASS=0
    FAIL=0
    
    for port_info in "${PORTS[@]}"; do
        IFS=":" read -r port desc <<< "$port_info"
        if netstat -tlnp | grep -q ":$port.*LISTEN"; then
            print_info "✓ $desc (port $port): Listening"
            ((PASS++))
        else
            print_error "✗ $desc (port $port): Not listening"
            ((FAIL++))
        fi
    done
    
    echo
    echo "Network Test Summary: $PASS passed, $FAIL failed"
    echo
}

# Function to test DNS configuration
test_dns_configuration() {
    print_step "Testing DNS configuration..."
    
    PASS=0
    FAIL=0
    
    # Test A record
    print_info "Testing A record for mail.$DOMAIN..."
    if dig +short A mail.$DOMAIN | grep -q "$SERVER_IP"; then
        print_info "✓ A record: mail.$DOMAIN resolves to $SERVER_IP"
        ((PASS++))
    else
        print_error "✗ A record: mail.$DOMAIN does not resolve to $SERVER_IP"
        ((FAIL++))
    fi
    
    # Test MX record
    print_info "Testing MX record for $DOMAIN..."
    if dig +short MX $DOMAIN | grep -q "mail.$DOMAIN"; then
        print_info "✓ MX record: Points to mail.$DOMAIN"
        ((PASS++))
    else
        print_error "✗ MX record: Does not point to mail.$DOMAIN"
        ((FAIL++))
    fi
    
    # Test SPF record
    print_info "Testing SPF record for $DOMAIN..."
    if dig +short TXT $DOMAIN | grep -q "v=spf1.*ip4:$SERVER_IP.*-all"; then
        print_info "✓ SPF record: Configured correctly"
        ((PASS++))
    else
        print_error "✗ SPF record: Missing or incorrect"
        ((FAIL++))
    fi
    
    # Test DMARC record
    print_info "Testing DMARC record for $DOMAIN..."
    if dig +short TXT _dmarc.$DOMAIN | grep -q "v=DMARC1"; then
        print_info "✓ DMARC record: Configured"
        ((PASS++))
    else
        print_error "✗ DMARC record: Missing"
        ((FAIL++))
    fi
    
    # Test reverse DNS
    print_info "Testing reverse DNS for $SERVER_IP..."
    if dig +short -x $SERVER_IP | grep -q "mail.$DOMAIN"; then
        print_info "✓ Reverse DNS: Configured correctly"
        ((PASS++))
    else
        print_error "✗ Reverse DNS: Missing or incorrect"
        ((FAIL++))
    fi
    
    echo
    echo "DNS Test Summary: $PASS passed, $FAIL failed"
    echo
}

# Function to test SSL certificates
test_ssl_certificates() {
    print_step "Testing SSL certificates..."
    
    PASS=0
    FAIL=0
    
    # Test SSL certificate existence
    if [[ -f /etc/letsencrypt/live/mail.$DOMAIN/fullchain.pem ]]; then
        print_info "✓ SSL certificate exists"
        ((PASS++))
        
        # Test certificate validity
        if openssl x509 -checkend 2592000 -noout -in /etc/letsencrypt/live/mail.$DOMAIN/fullchain.pem; then
            print_info "✓ SSL certificate valid for 30+ days"
            ((PASS++))
        else
            print_error "✗ SSL certificate expires within 30 days"
            ((FAIL++))
        fi
        
        # Test certificate chain
        if openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt /etc/letsencrypt/live/mail.$DOMAIN/fullchain.pem | grep -q "OK"; then
            print_info "✓ SSL certificate chain valid"
            ((PASS++))
        else
            print_error "✗ SSL certificate chain invalid"
            ((FAIL++))
        fi
    else
        print_error "✗ SSL certificate not found"
        ((FAIL+=3))
    fi
    
    # Test SMTP SSL
    print_info "Testing SMTP SSL connection..."
    if timeout 5 openssl s_client -connect mail.$DOMAIN:587 -starttls smtp </dev/null 2>/dev/null | grep -q "Verify return code: 0"; then
        print_info "✓ SMTP SSL connection works"
        ((PASS++))
    else
        print_error "✗ SMTP SSL connection failed"
        ((FAIL++))
    fi
    
    # Test IMAP SSL
    print_info "Testing IMAP SSL connection..."
    if timeout 5 openssl s_client -connect mail.$DOMAIN:993 </dev/null 2>/dev/null | grep -q "Verify return code: 0"; then
        print_info "✓ IMAP SSL connection works"
        ((PASS++))
    else
        print_error "✗ IMAP SSL connection failed"
        ((FAIL++))
    fi
    
    echo
    echo "SSL Test Summary: $PASS passed, $FAIL failed"
    echo
}

# Function to test DKIM configuration
test_dkim_configuration() {
    print_step "Testing DKIM configuration..."
    
    PASS=0
    FAIL=0
    
    # Test DKIM key existence
    if [[ -f /etc/opendkim/keys/$DOMAIN/default.private ]]; then
        print_info "✓ DKIM private key exists"
        ((PASS++))
    else
        print_error "✗ DKIM private key not found"
        ((FAIL++))
    fi
    
    # Test DKIM service
    if systemctl is-active --quiet opendkim; then
        print_info "✓ OpenDKIM service running"
        ((PASS++))
        
        # Test DKIM key validation
        if opendkim-testkey -d $DOMAIN -s default -vvv 2>/dev/null | grep -q "key OK"; then
            print_info "✓ DKIM key validation successful"
            ((PASS++))
        else
            print_error "✗ DKIM key validation failed"
            ((FAIL++))
        fi
    else
        print_error "✗ OpenDKIM service not running"
        ((FAIL+=2))
    fi
    
    # Test DKIM DNS record
    print_info "Testing DKIM DNS record..."
    if dig +short TXT default._domainkey.$DOMAIN | grep -q "v=DKIM1"; then
        print_info "✓ DKIM DNS record exists"
        ((PASS++))
    else
        print_error "✗ DKIM DNS record missing"
        ((FAIL++))
    fi
    
    echo
    echo "DKIM Test Summary: $PASS passed, $FAIL failed"
    echo
}

# Function to test database connectivity
test_database_connectivity() {
    print_step "Testing database connectivity..."
    
    PASS=0
    FAIL=0
    
    # Test PostgreSQL service
    if systemctl is-active --quiet postgresql; then
        print_info "✓ PostgreSQL service running"
        ((PASS++))
        
        # Test database connection
        export PGPASSWORD="$POSTGRES_PASSWORD"
        if psql -h localhost -U $POSTGRES_USER -d mailbox -c "SELECT 1;" >/dev/null 2>&1; then
            print_info "✓ Database connection successful"
            ((PASS++))
            
            # Test database structure
            if psql -h localhost -U $POSTGRES_USER -d mailbox -c "\dt" | grep -q "domains"; then
                print_info "✓ Database tables exist"
                ((PASS++))
                
                # Test data
                domain_count=$(psql -h localhost -U $POSTGRES_USER -d mailbox -t -c "SELECT COUNT(*) FROM domains;" | tr -d ' ')
                if [[ $domain_count -gt 0 ]]; then
                    print_info "✓ Domain data exists ($domain_count domains)"
                    ((PASS++))
                else
                    print_error "✗ No domains in database"
                    ((FAIL++))
                fi
            else
                print_error "✗ Database tables missing"
                ((FAIL+=2))
            fi
        else
            print_error "✗ Database connection failed"
            ((FAIL+=3))
        fi
    else
        print_error "✗ PostgreSQL service not running"
        ((FAIL+=4))
    fi
    
    echo
    echo "Database Test Summary: $PASS passed, $FAIL failed"
    echo
}

# Function to test mail delivery
test_mail_delivery() {
    print_step "Testing mail delivery..."
    
    PASS=0
    FAIL=0
    
    # Test queue status
    if postqueue -p | grep -q "Mail queue is empty"; then
        print_info "✓ Mail queue is empty"
        ((PASS++))
    else
        queue_size=$(postqueue -p | grep -c '^[A-F0-9]' || echo 0)
        print_warning "! Mail queue has $queue_size messages"
    fi
    
    # Test local mail delivery
    print_info "Testing local mail delivery..."
    TEST_MESSAGE="Subject: Test email $(date)
To: postmaster@$DOMAIN
From: root@$DOMAIN

This is a test message to verify local mail delivery is working.
"
    
    if echo "$TEST_MESSAGE" | sendmail postmaster@$DOMAIN; then
        print_info "✓ Test email sent to local queue"
        ((PASS++))
        
        # Wait a moment for delivery
        sleep 5
        
        # Check if message was delivered
        if grep -q "status=sent" /var/log/mail.log | tail -20 | grep -q "$(date +%b\ %d)"; then
            print_info "✓ Test email delivered successfully"
            ((PASS++))
        else
            print_error "✗ Test email delivery failed"
            ((FAIL++))
        fi
    else
        print_error "✗ Failed to send test email"
        ((FAIL+=2))
    fi
    
    echo
    echo "Mail Delivery Test Summary: $PASS passed, $FAIL failed"
    echo
}

# Function to test authentication
test_authentication() {
    print_step "Testing authentication..."
    
    PASS=0
    FAIL=0
    
    # Test SASL setup
    if [[ -S /var/spool/postfix/private/auth ]]; then
        print_info "✓ Postfix SASL socket exists"
        ((PASS++))
    else
        print_error "✗ Postfix SASL socket missing"
        ((FAIL++))
    fi
    
    # Test Dovecot auth
    if [[ -S /var/run/dovecot/auth-userdb ]]; then
        print_info "✓ Dovecot auth socket exists"
        ((PASS++))
    else
        print_error "✗ Dovecot auth socket missing"
        ((FAIL++))
    fi
    
    # Test database authentication
    export PGPASSWORD="$POSTGRES_PASSWORD"
    if doveadm auth test postmaster@$DOMAIN "$(cat /etc/email-server/postmaster-password.txt)" 2>/dev/null; then
        print_info "✓ Database authentication works"
        ((PASS++))
    else
        print_error "✗ Database authentication failed"
        ((FAIL++))
    fi
    
    echo
    echo "Authentication Test Summary: $PASS passed, $FAIL failed"
    echo
}

# Function to test spam filtering
test_spam_filtering() {
    print_step "Testing spam filtering..."
    
    PASS=0
    FAIL=0
    
    # Test SpamAssassin service
    if systemctl is-active --quiet spamassassin; then
        print_info "✓ SpamAssassin service running"
        ((PASS++))
        
        # Test SpamAssassin functionality
        SPAM_TEST="Subject: Get Rich Quick!!!
From: spam@example.com
To: postmaster@$DOMAIN

CONGRATULATIONS!!! You have won $1,000,000!!! 
Click here now to claim your prize: http://fake-spam-site.com
XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X
"
        
        if echo "$SPAM_TEST" | spamc | grep -q "X-Spam-Status: Yes"; then
            print_info "✓ SpamAssassin detects spam correctly"
            ((PASS++))
        else
            print_error "✗ SpamAssassin failed to detect test spam"
            ((FAIL++))
        fi
    else
        print_error "✗ SpamAssassin service not running"
        ((FAIL+=2))
    fi
    
    echo
    echo "Spam Filtering Test Summary: $PASS passed, $FAIL failed"
    echo
}

# Function to test security features
test_security_features() {
    print_step "Testing security features..."
    
    PASS=0
    FAIL=0
    
    # Test Fail2Ban
    if systemctl is-active --quiet fail2ban; then
        print_info "✓ Fail2Ban service running"
        ((PASS++))
        
        # Test jail status
        jail_count=$(fail2ban-client status | grep -E "(postfix|dovecot|sshd)" | wc -l)
        if [[ $jail_count -ge 3 ]]; then
            print_info "✓ Main jails configured ($jail_count jails)"
            ((PASS++))
        else
            print_error "✗ Some jails missing (only $jail_count configured)"
            ((FAIL++))
        fi
    else
        print_error "✗ Fail2Ban service not running"
        ((FAIL+=2))
    fi
    
    # Test firewall
    if ufw status | grep -q "Status: active"; then
        print_info "✓ UFW firewall active"
        ((PASS++))
        
        # Test required ports
        required_ports=(25 587 993 995 443)
        for port in "${required_ports[@]}"; do
            if ufw status | grep -q "$port"; then
                print_info "✓ Port $port allowed in firewall"
                ((PASS++))
            else
                print_error "✗ Port $port not found in firewall rules"
                ((FAIL++))
            fi
        done
    else
        print_error "✗ UFW firewall not active"
        ((FAIL+=6))
    fi
    
    echo
    echo "Security Test Summary: $PASS passed, $FAIL failed"
    echo
}

# Function to generate comprehensive test report
generate_test_report() {
    print_step "Generating comprehensive test report..."
    
    REPORT_FILE="/etc/email-server/test-report-$(date +%Y%m%d-%H%M%S).html"
    
    cat << EOF > "$REPORT_FILE"
<!DOCTYPE html>
<html>
<head>
    <title>Email Server Test Report - $(date '+%Y-%m-%d %H:%M:%S')</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 40px; }
        .header { background: #333; color: white; padding: 20px; margin-bottom: 30px; }
        .section { margin-bottom: 30px; border: 1px solid #ddd; padding: 20px; }
        .pass { color: #4CAF50; }
        .fail { color: #f44336; }
        .warning { color: #ff9800; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .summary { background: #f8f9fa; padding: 15px; margin-bottom: 20px; }
        code { background: #f4f4f4; padding: 2px 4px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Email Server Test Report</h1>
        <p>Domain: $DOMAIN</p>
        <p>Server: $SERVER_IP</p>
        <p>Generated: $(date '+%Y-%m-%d %H:%M:%S')</p>
    </div>
    
    <div class="summary">
        <h2>Test Summary</h2>
        <table>
            <tr>
                <th>Test Category</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
EOF
    
    # Add test results to report
    # Note: This is a template - actual results would be populated during test execution
    
    cat << EOF >> "$REPORT_FILE"
        </table>
    </div>
    
    <div class="section">
        <h2>Service Status</h2>
        <p>All critical email services are tested for proper operation.</p>
        <!-- Service status details -->
    </div>
    
    <div class="section">
        <h2>Network Connectivity</h2>
        <p>Network ports and SSL connectivity tests.</p>
        <!-- Network test details -->
    </div>
    
    <div class="section">
        <h2>DNS Configuration</h2>
        <p>DNS records including MX, SPF, DMARC, and reverse DNS.</p>
        <!-- DNS test details -->
    </div>
    
    <div class="section">
        <h2>Security Configuration</h2>
        <p>Security features including SSL, DKIM, SpamAssassin, and Fail2Ban.</p>
        <!-- Security test details -->
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
            <li>Review any failed tests above</li>
            <li>Ensure all DNS records are properly configured</li>
            <li>Monitor mail logs for delivery issues</li>
            <li>Keep SSL certificates up to date</li>
            <li>Regularly review security logs</li>
        </ul>
    </div>
    
    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 0.9em; color: #666;">
        <p>This test report was automatically generated by the email server test suite.</p>
    </footer>
</body>
</html>
EOF
    
    print_info "Test report generated: $REPORT_FILE"
}

# Function to perform all tests
run_all_tests() {
    echo
    echo "=========================================="
    echo "   EMAIL SERVER COMPREHENSIVE TEST"
    echo "   Domain: $DOMAIN"
    echo "   Server: $SERVER_IP" 
    echo "   Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "=========================================="
    echo
    
    # Run all test functions
    test_service_status
    test_network_connectivity
    test_dns_configuration
    test_ssl_certificates
    test_dkim_configuration
    test_database_connectivity
    test_mail_delivery
    test_authentication
    test_spam_filtering
    test_security_features
    
    # Generate report
    generate_test_report
    
    echo
    echo "=========================================="
    echo "   TEST COMPLETED"
    echo "=========================================="
    echo
}

# Function to run specific test
run_specific_test() {
    case "$1" in
        services)
            test_service_status
            ;;
        network)
            test_network_connectivity
            ;;
        dns)
            test_dns_configuration
            ;;
        ssl)
            test_ssl_certificates
            ;;
        dkim)
            test_dkim_configuration
            ;;
        database)
            test_database_connectivity
            ;;
        mail)
            test_mail_delivery
            ;;
        auth)
            test_authentication
            ;;
        spam)
            test_spam_filtering
            ;;
        security)
            test_security_features
            ;;
        *)
            print_error "Unknown test: $1"
            echo "Available tests: services, network, dns, ssl, dkim, database, mail, auth, spam, security"
            exit 1
            ;;
    esac
}

# Main execution
case "${1:-all}" in
    all)
        run_all_tests
        ;;
    *)
        run_specific_test "$1"
        ;;
esac
