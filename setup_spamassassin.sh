#!/bin/bash

# Script to set up SpamAssassin for the email server
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

# Function to install SpamAssassin
install_spamassassin() {
    print_info "Installing SpamAssassin..."
    
    # Check if already installed
    if command -v spamassassin &> /dev/null; then
        print_info "SpamAssassin is already installed"
        return 0
    fi
    
    # Install SpamAssassin and related packages
    apt-get update
    apt-get install -y spamassassin spamc spamass-milter
    
    # Create spamd user if it doesn't exist
    if ! id "spamd" &>/dev/null; then
        useradd -r -s /bin/false -d /var/lib/spamassassin spamd
    fi
    
    print_info "SpamAssassin installed successfully"
}

# Function to backup SpamAssassin configuration
backup_spamassassin_config() {
    print_info "Backing up SpamAssassin configuration..."
    
    BACKUP_DIR_SA="$BACKUP_DIR/config/spamassassin-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR_SA"
    
    # Backup existing configuration if it exists
    if [[ -d /etc/spamassassin ]]; then
        cp -r /etc/spamassassin "$BACKUP_DIR_SA/"
    fi
    
    if [[ -f /etc/default/spamassassin ]]; then
        cp /etc/default/spamassassin "$BACKUP_DIR_SA/"
    fi
    
    print_info "SpamAssassin configuration backed up to $BACKUP_DIR_SA"
}

# Function to configure SpamAssassin defaults
configure_spamassassin_defaults() {
    print_info "Configuring SpamAssassin defaults..."
    
    # Create configuration for service
    cat << EOF > /etc/default/spamassassin
# Change to one to enable spamd
ENABLED=1

# Options for spamd
CRON=1
NICE="--nicelevel 15"

# Set spamd PID file
PIDFILE="/var/run/spamd.pid"

# Create the log file
OPTIONS="--create-prefs --max-children 5 --helper-home-dir /var/lib/spamassassin --username spamd -H /var/lib/spamassassin -i 127.0.0.1 -p 783 -A 127.0.0.1 -L --socketpath=/var/run/spamd.sock --socketowner=spamd --socketgroup=spamd --socketmode=0660"

# Enable automatic rule updates
SA_UPDATE_ENABLED=1
EOF
    
    print_info "SpamAssassin defaults configured"
}

# Function to configure SpamAssassin local rules
configure_local_rules() {
    print_info "Configuring SpamAssassin local rules..."
    
    # Create local configuration
    cat << EOF > /etc/spamassassin/local.cf
# SpamAssassin local configuration for $DOMAIN

# Scoring settings
required_score          5.0
report_safe             0
rewrite_header          Subject ***** SPAM _SCORE_ *****

# Bayes settings
use_bayes               1
use_bayes_rules         1
bayes_auto_learn        1
bayes_auto_learn_threshold_nonspam  0.1
bayes_auto_learn_threshold_spam     12.0

# AWL (Auto-WhiteList) settings
use_auto_whitelist      1

# Network checks
skip_rbl_checks         0
dns_available           test

# Trusted Networks
#trusted_networks $SERVER_IP
trusted_networks localhost

# Whitelist our domain
whitelist_from          *@$DOMAIN

# Custom rules for email server
score RCVD_IN_DNSWL_NONE    0.0
score RCVD_IN_DNSWL_LOW     -0.5
score RCVD_IN_DNSWL_MED     -1.0
score RCVD_IN_DNSWL_HI      -2.0

# Custom body rules
body LOCAL_DEMONSTRATION_RULE   /example demonstration rule/
describe LOCAL_DEMONSTRATION_RULE This is a demonstration rule
score LOCAL_DEMONSTRATION_RULE   2.0

# Shortcircuit settings
ifplugin Mail::SpamAssassin::Plugin::Shortcircuit
shortcircuit HAM_PRIORITY_1 on
shortcircuit SPAM_PRIORITY_1 on
priority HAM_PRIORITY_1 -100
priority SPAM_PRIORITY_1 100
endif

# Report settings
report This message is classified as spam.

# DCC settings (if DCC is installed)
ifplugin Mail::SpamAssassin::Plugin::DCC
dcc_timeout 10
endif

# Pyzor settings (if Pyzor is installed)
ifplugin Mail::SpamAssassin::Plugin::Pyzor
pyzor_timeout 10
endif

# Razor2 settings (if Razor2 is installed)
ifplugin Mail::SpamAssassin::Plugin::Razor2
razor_timeout 10
endif

# Custom text at the end of spam reports
clear_report_template
report_template Spam detection software, running on the system "HOSTNAME", has identified this incoming email as possible spam. The original message has been attached to this so you can view it (if it isn't spam) or label similar future email. If you have any questions, see %%CONTACT_ADDRESS%% for details.

Content preview: %%PREVIEW%%

Content analysis details: (%%SCORE%% points, %%REQD%% required)

%%SUMMARY%%

EOF
    
    # Set proper permissions
    chown root:spamd /etc/spamassassin/local.cf
    chmod 644 /etc/spamassassin/local.cf
    
    print_info "Local rules configured"
}

# Function to create custom rules
create_custom_rules() {
    print_info "Creating custom SpamAssassin rules..."
    
    # Create custom rules directory
    mkdir -p /etc/spamassassin/custom.d
    
    # Create custom rules file
    cat << EOF > /etc/spamassassin/custom.d/50_custom_rules.cf
# Custom SpamAssassin rules for $DOMAIN

# Whitelist rules
header __FROM_OUR_DOMAIN    From =~ /\@${DOMAIN//./\\.}\$/
meta   FROM_OUR_DOMAIN      __FROM_OUR_DOMAIN && !__FROM_SPOOFED
score  FROM_OUR_DOMAIN      -5.0

# Suspicious patterns
body   CUSTOM_PHISHING      /urgent.*action.*required/i
score  CUSTOM_PHISHING      3.0

# Common spam patterns
body   CUSTOM_LOTTERY       /congratulations.*you.*won/i
score  CUSTOM_LOTTERY       5.0

# Foreign characters spam
body   CUSTOM_FOREIGN_SPAM  /[\x{0400}-\x{04FF}]+.*[\x{0400}-\x{04FF}]+/i
score  CUSTOM_FOREIGN_SPAM  2.0

# Attachment rules
header CUSTOM_EXE_ATTACHMENT Content-Type =~ /application\/octet-stream.*\.exe/i
score  CUSTOM_EXE_ATTACHMENT 3.0

# Subject line rules
header CUSTOM_SPAMMY_SUBJECT Subject =~ /\bFREE\b.*\bMONEY\b/i
score  CUSTOM_SPAMMY_SUBJECT 2.5

# Multiple recipients (often spam)
header __RCPTS_COUNT        To:raw =~ /,.*,.*,.*,/
describe __RCPTS_COUNT      Many recipients in To: header
score __RCPTS_COUNT         1.5

EOF
    
    # Set permissions
    chown -R root:spamd /etc/spamassassin/custom.d
    chmod 755 /etc/spamassassin/custom.d
    chmod 644 /etc/spamassassin/custom.d/50_custom_rules.cf
    
    print_info "Custom rules created"
}

# Function to configure SpamAssassin with Postfix
configure_postfix_integration() {
    print_info "Configuring Postfix integration with SpamAssassin..."
    
    # Update Postfix main.cf if needed
    if ! grep -q "content_filter.*spamassassin" /etc/postfix/main.cf; then
        echo "" >> /etc/postfix/main.cf
        echo "# SpamAssassin integration" >> /etc/postfix/main.cf
        echo "content_filter = spamassassin" >> /etc/postfix/main.cf
    fi
    
    # Add SpamAssassin service to Postfix master.cf if not already there
    if ! grep -q "spamassassin.*pipe" /etc/postfix/master.cf; then
        cat << 'EOF' >> /etc/postfix/master.cf

# SpamAssassin integration
spamassassin unix -     n       n       -       -       pipe
    user=spamd argv=/usr/bin/spamc -f -e /usr/sbin/sendmail -oi -f ${sender} ${recipient}
EOF
    fi
    
    # Reload Postfix
    systemctl reload postfix
    
    print_info "Postfix integration configured"
}

# Function to configure SpamAssassin for collaborative filtering
configure_collaborative_filtering() {
    print_info "Configuring collaborative filtering tools..."
    
    # Install additional filtering tools
    apt-get install -y pyzor razor
    
    # Configure Pyzor
    if command -v pyzor &> /dev/null; then
        sudo -u spamd pyzor discover || true
    fi
    
    # Configure Razor
    if command -v razor-admin &> /dev/null; then
        sudo -u spamd razor-admin -create || true
        sudo -u spamd razor-admin -register || true
    fi
    
    # Enable collaborative filtering in SpamAssassin
    cat << EOF > /etc/spamassassin/collaborative.cf
# Collaborative filtering settings

# Enable DCC
loadplugin Mail::SpamAssassin::Plugin::DCC

# Enable Pyzor
loadplugin Mail::SpamAssassin::Plugin::Pyzor
pyzor_path /usr/bin/pyzor

# Enable Razor2
loadplugin Mail::SpamAssassin::Plugin::Razor2

# Enable iXhash2
loadplugin Mail::SpamAssassin::Plugin::iXhash2

# Configure scoring
score DCC_CHECK     0.1
score RAZOR2_CHECK  1.5
score PYZOR_CHECK   1.0
score URIBL_BLOCKED 0.1
EOF
    
    print_info "Collaborative filtering configured"
}

# Function to set up Bayes database
setup_bayes_database() {
    print_info "Setting up Bayes database..."
    
    # Create directories for Bayes database
    mkdir -p /var/lib/spamassassin/.spamassassin
    chown -R spamd:spamd /var/lib/spamassassin
    
    # Configure Bayes settings
    cat << EOF > /etc/spamassassin/bayes.cf
# Bayes configuration

# Use SQL for Bayes database
bayes_store_module Mail::SpamAssassin::BayesStore::DBM

# Set Bayes paths
bayes_path /var/lib/spamassassin/.spamassassin/bayes
bayes_file_mode 0644

# Bayes learning settings
bayes_min_ham_num   200
bayes_min_spam_num  200
bayes_learn_during_report  1

# Auto-expire settings
bayes_auto_expire  1
bayes_journal_max_size  102400

# Use AWL (Auto-WhiteList)
use_auto_whitelist  1
auto_whitelist_path /var/lib/spamassassin/.spamassassin/auto-whitelist
auto_whitelist_file_mode 0644
EOF
    
    # Initialize Bayes database
    sudo -u spamd sa-learn --sync
    
    print_info "Bayes database configured"
}

# Function to create training script
create_training_script() {
    print_info "Creating SpamAssassin training script..."
    
    cat << 'EOF' > /usr/local/bin/train-spamassassin.sh
#!/bin/bash

# SpamAssassin training script
# Usage: train-spamassassin.sh <spam|ham> <maildir>

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <spam|ham> <maildir>"
    echo "Example: $0 spam /var/mail/vhosts/example.com/user/Maildir/.Junk"
    exit 1
fi

TYPE="$1"
MAILDIR="$2"

# Validate type
if [[ "$TYPE" != "spam" && "$TYPE" != "ham" ]]; then
    echo "Error: Type must be 'spam' or 'ham'"
    exit 1
fi

# Check if maildir exists
if [[ ! -d "$MAILDIR" ]]; then
    echo "Error: Maildir $MAILDIR does not exist"
    exit 1
fi

# Train SpamAssassin
if [[ "$TYPE" == "spam" ]]; then
    echo "Training SpamAssassin with spam from $MAILDIR..."
    sudo -u spamd sa-learn --spam "$MAILDIR"
else
    echo "Training SpamAssassin with ham from $MAILDIR..."
    sudo -u spamd sa-learn --ham "$MAILDIR"
fi

# Show statistics
echo "Current Bayes statistics:"
sudo -u spamd sa-learn --dump magic

# Sync database
sudo -u spamd sa-learn --sync

echo "Training complete!"
EOF
    
    chmod +x /usr/local/bin/train-spamassassin.sh
    
    print_info "Training script created: /usr/local/bin/train-spamassassin.sh"
}

# Function to create auto-learning configuration
create_auto_learning() {
    print_info "Creating auto-learning configuration..."
    
    # Create auto-learning script
    cat << 'EOF' > /usr/local/bin/auto-learn-spam.sh
#!/bin/bash

# Automatic SpamAssassin learning script
# This script processes emails from user Junk/Spam folders

set -euo pipefail

LOG_FILE="/var/log/spamassassin/auto-learn.log"
MAILDIR_BASE="/var/mail/vhosts"

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"
chown spamd:spamd "$(dirname "$LOG_FILE")"

# Process all users' Junk folders
find "$MAILDIR_BASE" -type d -name ".Junk" -o -name ".Spam" | while read -r junk_dir; do
    if [[ -d "$junk_dir/cur" ]]; then
        email_count=$(find "$junk_dir/cur" -type f | wc -l)
        if [[ $email_count -gt 0 ]]; then
            log_message "Processing $email_count emails from $junk_dir"
            
            # Learn as spam
            sudo -u spamd sa-learn --spam "$junk_dir" 2>> "$LOG_FILE"
            
            # Move processed emails to a backup folder
            backup_dir="$junk_dir/processed/$(date +%Y%m%d)"
            mkdir -p "$backup_dir"
            find "$junk_dir/cur" -type f -exec mv {} "$backup_dir/" \;
        fi
    fi
done

# Process all users' Inbox for ham (optional - be careful with this)
# Uncomment if you want to auto-learn ham from inboxes
# find "$MAILDIR_BASE" -type d -name "cur" | grep -E "/Maildir/cur$" | while read -r inbox_dir; do
#     sample_count=10
#     random_emails=$(find "$inbox_dir" -type f | shuf -n "$sample_count")
#     if [[ -n "$random_emails" ]]; then
#         log_message "Sampling $sample_count emails from $inbox_dir for ham training"
#         echo "$random_emails" | xargs -I {} sudo -u spamd sa-learn --ham "{}" 2>> "$LOG_FILE"
#     fi
# done

# Sync database
sudo -u spamd sa-learn --sync

# Show current statistics
stats=$(sudo -u spamd sa-learn --dump magic)
log_message "Current Bayes statistics: $stats"

log_message "Auto-learning completed"
EOF
    
    chmod +x /usr/local/bin/auto-learn-spam.sh
    
    # Add to crontab for weekly auto-learning
    (crontab -l 2>/dev/null; echo "0 3 * * 1 /usr/local/bin/auto-learn-spam.sh") | crontab -
    
    print_info "Auto-learning configured"
}

# Function to create monitoring script
create_spamassassin_monitoring() {
    print_info "Creating SpamAssassin monitoring script..."
    
    cat << 'EOF' > /usr/local/bin/monitor-spamassassin.sh
#!/bin/bash

# SpamAssassin monitoring script
# Part of email server setup automation

set -euo pipefail

LOG_FILE="/var/log/email-server-setup/spamassassin-monitor.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Function to log messages
log_message() {
    echo "[$DATE] $1" | tee -a "$LOG_FILE"
}

# Check SpamAssassin service status
if systemctl is-active --quiet spamassassin; then
    log_message "SpamAssassin service is running"
else
    log_message "ERROR: SpamAssassin service is not running"
    systemctl status spamassassin >> "$LOG_FILE"
fi

# Check spamd process
if pgrep -x "spamd" > /dev/null; then
    spamd_count=$(pgrep -x "spamd" | wc -l)
    log_message "spamd processes running: $spamd_count"
else
    log_message "ERROR: No spamd processes running"
fi

# Check Bayes statistics
bayes_stats=$(sudo -u spamd sa-learn --dump magic 2>/dev/null || echo "Unable to get Bayes stats")
log_message "Bayes statistics: $bayes_stats"

# Check recent spam processing
recent_spam=$(grep -i "spam" /var/log/mail.log | tail -n 5)
if [[ -n "$recent_spam" ]]; then
    log_message "Recent spam processing:"
    echo "$recent_spam" >> "$LOG_FILE"
else
    log_message "No recent spam processing"
fi

# Check rule updates
last_update=$(ls -lt /var/lib/spamassassin/3.*/updates_spamassassin_org/ 2>/dev/null | head -2 | tail -1 | awk '{print $6, $7, $8}')
if [[ -n "$last_update" ]]; then
    log_message "Last rule update: $last_update"
else
    log_message "No rule updates found"
fi

# Check for errors in log
error_count=$(grep -i error /var/log/mail.log | grep -i spamassassin | tail -n 24h | wc -l)
log_message "SpamAssassin errors in last 24h: $error_count"

log_message "SpamAssassin monitoring check completed"
echo "----------------------------------------" >> "$LOG_FILE"
EOF
    
    chmod +x /usr/local/bin/monitor-spamassassin.sh
    
    # Add to crontab for daily monitoring
    (crontab -l 2>/dev/null; echo "0 4 * * * /usr/local/bin/monitor-spamassassin.sh") | crontab -
    
    print_info "SpamAssassin monitoring configured"
}

# Function to test SpamAssassin configuration
test_spamassassin_configuration() {
    print_info "Testing SpamAssassin configuration..."
    
    # Create test message
    cat << 'EOF' > /tmp/test-spam.txt
From: test@example.com
To: postmaster@localhost
Subject: Test spam message

XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X

This is a test email to verify SpamAssassin is working properly.
EOF
    
    # Test SpamAssassin with test message
    print_info "Testing SpamAssassin detection..."
    if sudo -u spamd spamc < /tmp/test-spam.txt > /tmp/test-result.txt; then
        print_info "✓ SpamAssassin test successful"
        score=$(grep "X-Spam-Level" /tmp/test-result.txt || echo "Score not found")
        print_info "Test result: $score"
    else
        print_error "✗ SpamAssassin test failed"
    fi
    
    # Clean up test files
    rm -f /tmp/test-spam.txt /tmp/test-result.txt
    
    # Create test report
    cat << EOF > /etc/email-server/spamassassin-test-report.txt
SpamAssassin Configuration Test Report
======================================
Generated on: $(date)

Service Status:
---------------
- SpamAssassin daemon: $(systemctl is-active spamassassin)
- Process count: $(pgrep -x "spamd" | wc -l) spamd processes

Configuration:
--------------
- Config file: /etc/spamassassin/local.cf
- Custom rules: /etc/spamassassin/custom.d/
- Required score: $(grep "required_score" /etc/spamassassin/local.cf | awk '{print $2}')

Bayes Database:
---------------
$(sudo -u spamd sa-learn --dump magic 2>/dev/null || echo "Unable to access Bayes database")

Integration:
------------
- Postfix integration: $(grep -q "content_filter.*spamassassin" /etc/postfix/main.cf && echo "Configured" || echo "Missing")
- Socket: 127.0.0.1:783

Rule Updates:
-------------
Last update: $(ls -lt /var/lib/spamassassin/3.*/updates_spamassassin_org/ 2>/dev/null | head -2 | tail -1 | awk '{print $6, $7, $8}' || echo "No updates found")

Recent Activity:
----------------
$(grep -i spam /var/log/mail.log | tail -n 10 || echo "No recent activity")
EOF
    
    print_info "Test report created: /etc/email-server/spamassassin-test-report.txt"
}

# Function to update SpamAssassin rules
update_spamassassin_rules() {
    print_info "Updating SpamAssassin rules..."
    
    # Update rules
    if sa-update --no-gpg; then
        print_info "✓ SpamAssassin rules updated successfully"
        # Restart service to load new rules
        systemctl restart spamassassin
    else
        print_warning "! SpamAssassin rules update failed (this is normal for first run)"
    fi
    
    # Set up automatic updates via cron
    cat << 'EOF' > /etc/cron.daily/sa-update
#!/bin/bash
# Daily SpamAssassin rule updates

if sa-update --no-gpg; then
    systemctl reload spamassassin
fi
EOF
    
    chmod +x /etc/cron.daily/sa-update
    
    print_info "Automatic rule updates configured"
}

# Function to start and enable SpamAssassin
start_spamassassin() {
    print_info "Starting and enabling SpamAssassin..."
    
    # Start SpamAssassin
    systemctl start spamassassin
    
    # Enable SpamAssassin to start on boot
    systemctl enable spamassassin
    
    # Check status
    if systemctl is-active --quiet spamassassin; then
        print_info "✓ SpamAssassin is running"
    else
        print_error "✗ SpamAssassin failed to start"
        systemctl status spamassassin
        return 1
    fi
    
    print_info "