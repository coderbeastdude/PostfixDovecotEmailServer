scripts/switch-to-cloudflare-ssl.shCode #!/bin/bash

# Script to switch from Let's Encrypt to Cloudflare SSL certificates
# Part of the email server setup automation

set -euo pipefail

# Load configuration
source ../email-server-config.conf

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32Additional Considerations for Cloudflare SSL:
1. Cloudflare SSL Modes
When using Cloudflare, you have several SSL modes:

Off: No encryption (not recommended)
Flexible: Encrypts between visitor and Cloudflare only
Full: Encrypts end-to-end but allows self-signed certificates
Full (Strict): Requires valid SSL certificate on origin server

For email servers, you'll want Full (Strict) mode.
2. Important Notes

Email ports: Make sure email ports (25, 587, 993, 995) are not proxied through Cloudflare if using Cloudflare proxy
MX records: Point directly to your server IP, not through Cloudflare proxy
Autodiscovery: May need adjustment if using Cloudflare proxy for web traffic

3. Integration with Existing Scripts
The SSL switching script integrates seamlessly with the existing email server setup:
bash# To switch to Cloudflare SSL after initial installation:
./scripts/switch-to-cloudflare-ssl.sh

# To verify the switch worked:
./scripts/13-test-server.sh

# To monitor SSL status:
email-security-dashboard.sh
4. Backup and Rollback
The script automatically:

Backs up Let's Encrypt certificates
Can be reversed by running the original SSL script
Maintains all service configurations

5. Certificate Renewal
Depending on your choice:

Origin Certificates: 15-year validity, manual renewal
API Method: Automated renewal via acme.sh
Manual Upload: You manage renewal schedule

6. Testing After Switch
Always test after switching:
bash# Test SMTP TLS
openssl s_client -connect mail.yourdomain.com:587 -starttls smtp

# Test IMAPS
openssl s_client -connect mail.yourdomain.com:993

# Test web interface
curl -I https://yourdomain.com/autodiscover/autodiscover.xml

# Run comprehensive tests
./scripts/13-test-server.sh
The flexibility built into these scripts makes switching between different SSL providers straightforward while maintaining all email functionality. You can switch to Cloudflare SSL at any time after the initial installation without affecting your email service.
