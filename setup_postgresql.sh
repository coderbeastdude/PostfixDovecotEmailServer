#!/bin/bash

# Script to set up PostgreSQL for the email server
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

# Function to secure PostgreSQL installation
secure_postgresql() {
    print_info "Securing PostgreSQL installation..."
    
    # Set postgres user password
    POSTGRES_ROOT_PASSWORD=$(openssl rand -base64 32)
    
    sudo -u postgres psql << EOF
ALTER USER postgres PASSWORD '$POSTGRES_ROOT_PASSWORD';
\q
EOF
    
    # Save root password securely
    echo "PostgreSQL root password: $POSTGRES_ROOT_PASSWORD" > /etc/email-server/postgres-root-password.txt
    chmod 600 /etc/email-server/postgres-root-password.txt
    
    print_info "PostgreSQL root password saved to /etc/email-server/postgres-root-password.txt"
}

# Function to create database and user
create_mail_database() {
    print_info "Creating mail database and user..."
    
    # Create database and user
    sudo -u postgres psql << EOF
-- Create database
CREATE DATABASE mailbox;

-- Create user with encrypted password
CREATE USER $POSTGRES_USER WITH ENCRYPTED PASSWORD '$POSTGRES_PASSWORD';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE mailbox TO $POSTGRES_USER;

-- Connect to mailbox database
\c mailbox

-- Grant schema permissions
GRANT ALL ON SCHEMA public TO $POSTGRES_USER;

-- Enable row level security if needed
-- ALTER DATABASE mailbox SET row_security = on;

\q
EOF
    
    print_info "Database and user created successfully"
}

# Function to create mail tables
create_mail_tables() {
    print_info "Creating mail tables..."
    
    # Create SQL file with table definitions
    cat << 'EOF' > /tmp/create_mail_tables.sql
-- Create mailbox schema
CREATE SCHEMA IF NOT EXISTS mailbox;

-- Create domains table
CREATE TABLE mailbox.domains (
    id SERIAL PRIMARY KEY,
    name VARCHAR(128) NOT NULL UNIQUE,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create users table
CREATE TABLE mailbox.users (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL,
    password VARCHAR(128) NOT NULL,
    email VARCHAR(128) NOT NULL,
    quota INT8 DEFAULT 0,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (email),
    FOREIGN KEY (domain_id) REFERENCES mailbox.domains(id) ON DELETE CASCADE
);

-- Create aliases table
CREATE TABLE mailbox.aliases (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL,
    source VARCHAR(128) NOT NULL,
    destination VARCHAR(128) NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES mailbox.domains(id) ON DELETE CASCADE
);

-- Create indexes for better performance
CREATE INDEX idx_users_email ON mailbox.users(email);
CREATE INDEX idx_users_domain_id ON mailbox.users(domain_id);
CREATE INDEX idx_aliases_source ON mailbox.aliases(source);
CREATE INDEX idx_aliases_domain_id ON mailbox.aliases(domain_id);
CREATE INDEX idx_domains_name ON mailbox.domains(name);

-- Create views for easier queries
CREATE OR REPLACE VIEW mailbox.virtual_domains AS
SELECT name FROM mailbox.domains WHERE active = TRUE;

CREATE OR REPLACE VIEW mailbox.virtual_users AS
SELECT u.email, u.password FROM mailbox.users u
JOIN mailbox.domains d ON u.domain_id = d.id
WHERE u.active = TRUE AND d.active = TRUE;

CREATE OR REPLACE VIEW mailbox.virtual_aliases AS
SELECT a.source, a.destination FROM mailbox.aliases a
JOIN mailbox.domains d ON a.domain_id = d.id
WHERE a.active = TRUE AND d.active = TRUE;

-- Grant permissions on tables and views
GRANT SELECT ON mailbox.domains TO mailuser;
GRANT SELECT ON mailbox.users TO mailuser;
GRANT SELECT ON mailbox.aliases TO mailuser;
GRANT SELECT ON mailbox.virtual_domains TO mailuser;
GRANT SELECT ON mailbox.virtual_users TO mailuser;
GRANT SELECT ON mailbox.virtual_aliases TO mailuser;

-- Insert default domain
INSERT INTO mailbox.domains (name) VALUES ('${DOMAIN}');
EOF
    
    # Execute SQL file
    sudo -u postgres psql -d mailbox -f /tmp/create_mail_tables.sql
    
    # Remove temporary SQL file
    rm /tmp/create_mail_tables.sql
    
    print_info "Mail tables created successfully"
}

# Function to create default users
create_default_users() {
    print_info "Creating default email users..."
    
    # Generate password hash for postmaster
    POSTMASTER_PASSWORD=$(openssl rand -base64 16)
    POSTMASTER_HASH=$(doveadm pw -s SHA512-CRYPT -p "$POSTMASTER_PASSWORD")
    
    # Create default users
    sudo -u postgres psql -d mailbox << EOF
-- Get domain ID
SELECT id INTO @domain_id FROM mailbox.domains WHERE name = '$DOMAIN';

-- Insert postmaster user
INSERT INTO mailbox.users (domain_id, password, email, quota) 
VALUES (1, '$POSTMASTER_HASH', 'postmaster@$DOMAIN', 0);

-- Create some default aliases
INSERT INTO mailbox.aliases (domain_id, source, destination)
VALUES 
(1, 'admin@$DOMAIN', 'postmaster@$DOMAIN'),
(1, 'abuse@$DOMAIN', 'postmaster@$DOMAIN'),
(1, 'noc@$DOMAIN', 'postmaster@$DOMAIN'),
(1, 'hostmaster@$DOMAIN', 'postmaster@$DOMAIN'),
(1, 'security@$DOMAIN', 'postmaster@$DOMAIN');

\q
EOF
    
    # Save postmaster password
    echo "Postmaster password: $POSTMASTER_PASSWORD" > /etc/email-server/postmaster-password.txt
    chmod 600 /etc/email-server/postmaster-password.txt
    
    print_info "Default users created successfully"
    print_info "Postmaster password saved to /etc/email-server/postmaster-password.txt"
}

# Function to configure PostgreSQL security
configure_postgresql_security() {
    print_info "Configuring PostgreSQL security..."
    
    # Find PostgreSQL version
    PG_VERSION=$(sudo -u postgres psql -t -c "SELECT version();" | grep -oP '\d+\.\d+' | head -n1)
    PG_CONF_DIR="/etc/postgresql/$PG_VERSION/main"
    
    # Backup original configuration
    cp "$PG_CONF_DIR/postgresql.conf" "$BACKUP_DIR/config/postgresql.conf.bak"
    cp "$PG_CONF_DIR/pg_hba.conf" "$BACKUP_DIR/config/pg_hba.conf.bak"
    
    # Configure pg_hba.conf for mailuser
    cat << EOF >> "$PG_CONF_DIR/pg_hba.conf"

# Email server configuration
local   mailbox   $POSTGRES_USER   md5
host    mailbox   $POSTGRES_USER   127.0.0.1/32   md5
host    mailbox   $POSTGRES_USER   ::1/128   md5
EOF
    
    # Configure postgresql.conf for better performance
    cat << EOF >> "$PG_CONF_DIR/postgresql.conf"

# Email server optimizations
listen_addresses = 'localhost'
max_connections = 100
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 4MB
maintenance_work_mem = 64MB

# Logging configuration
log_destination = 'stderr'
logging_collector = on
log_directory = 'pg_log'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_rotation_age = 1d
log_rotation_size = 10MB
log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '
log_min_messages = warning
log_min_error_statement = error

# Security settings
ssl = on
ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
ssl_key_file = '/etc/ssl/private/ssl-cert-snakeoil.key'
EOF
    
    # Restart PostgreSQL
    systemctl restart postgresql
    
    print_info "PostgreSQL security configured"
}

# Function to create backup script
create_backup_script() {
    print_info "Creating PostgreSQL backup script..."
    
    cat << 'EOF' > /usr/local/bin/backup-mailbox.sh
#!/bin/bash

# PostgreSQL mailbox backup script
# Part of email server setup automation

set -euo pipefail

# Source configuration
source /etc/email-server-config.conf

BACKUP_DIR="$BACKUP_DIR/database"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="$BACKUP_DIR/mailbox-$TIMESTAMP.sql"

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Perform backup
export PGPASSWORD="$POSTGRES_PASSWORD"
pg_dump -h localhost -U "$POSTGRES_USER" mailbox > "$BACKUP_FILE"

# Compress backup
gzip "$BACKUP_FILE"

# Keep only last 30 days of backups
find "$BACKUP_DIR" -name "mailbox-*.sql.gz" -mtime +30 -delete

# Log backup
echo "$(date): Backup completed: $BACKUP_FILE.gz" >> /var/log/email-server-setup/database-backup.log

# Verify backup
if [[ -f "$BACKUP_FILE.gz" ]]; then
    echo "$(date): Backup verification successful" >> /var/log/email-server-setup/database-backup.log
else
    echo "$(date): ERROR: Backup verification failed" >> /var/log/email-server-setup/database-backup.log
fi
EOF
    
    chmod +x /usr/local/bin/backup-mailbox.sh
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/backup-mailbox.sh") | crontab -
    
    print_info "Backup script created and scheduled"
}

# Function to create database maintenance script
create_maintenance_script() {
    print_info "Creating database maintenance script..."
    
    cat << 'EOF' > /usr/local/bin/maintain-mailbox.sh
#!/bin/bash

# PostgreSQL mailbox maintenance script
# Part of email server setup automation

set -euo pipefail

# Source configuration
source /etc/email-server-config.conf

LOG_FILE="/var/log/email-server-setup/database-maintenance.log"

# Connect to database
export PGPASSWORD="$POSTGRES_PASSWORD"

# Vacuum and analyze
echo "$(date): Starting database maintenance..." >> "$LOG_FILE"

# Clean up old sessions
psql -h localhost -U "$POSTGRES_USER" mailbox << 'EOSQL'
-- Clean up old sessions if you implement them
-- DELETE FROM mailbox.sessions WHERE created_at < NOW() - INTERVAL '30 days';

-- Update statistics
ANALYZE mailbox.users;
ANALYZE mailbox.aliases;
ANALYZE mailbox.domains;

-- Vacuum tables
VACUUM (ANALYZE, VERBOSE) mailbox.users;
VACUUM (ANALYZE, VERBOSE) mailbox.aliases;
VACUUM (ANALYZE, VERBOSE) mailbox.domains;
EOSQL

echo "$(date): Database maintenance completed" >> "$LOG_FILE"

# Check database integrity
INTEGRITY_CHECK=$(psql -h localhost -U "$POSTGRES_USER" -t -c "SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'mailbox';")
echo "$(date): Database integrity check: $INTEGRITY_CHECK tables found" >> "$LOG_FILE"
EOF
    
    chmod +x /usr/local/bin/maintain-mailbox.sh
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "0 3 * * 0 /usr/local/bin/maintain-mailbox.sh") | crontab -
    
    print_info "Maintenance script created and scheduled"
}

# Function to create database monitoring
create_database_monitoring() {
    print_info "Creating database monitoring..."
    
    cat << 'EOF' > /usr/local/bin/monitor-mailbox.sh
#!/bin/bash

# PostgreSQL mailbox monitoring script
# Part of email server setup automation

set -euo pipefail

# Source configuration
source /etc/email-server-config.conf

LOG_FILE="/var/log/email-server-setup/database-monitor.log"

# Connect to database
export PGPASSWORD="$POSTGRES_PASSWORD"

# Get database statistics
STATS=$(psql -h localhost -U "$POSTGRES_USER" mailbox -t << 'EOSQL'
SELECT 
    'Domains: ' || COUNT(*) FROM mailbox.domains WHERE active = TRUE
UNION ALL
SELECT 
    'Users: ' || COUNT(*) FROM mailbox.users WHERE active = TRUE
UNION ALL
SELECT 
    'Aliases: ' || COUNT(*) FROM mailbox.aliases WHERE active = TRUE;
EOSQL
)

echo "$(date): Database Statistics:" >> "$LOG_FILE"
echo "$STATS" >> "$LOG_FILE"

# Check database connections
CONNECTIONS=$(psql -h localhost -U "$POSTGRES_USER" postgres -t -c "SELECT count(*) FROM pg_stat_activity WHERE datname='mailbox';")
echo "$(date): Active connections: $CONNECTIONS" >> "$LOG_FILE"

# Check database size
DB_SIZE=$(psql -h localhost -U "$POSTGRES_USER" postgres -t -c "SELECT pg_size_pretty(pg_database_size('mailbox'));")
echo "$(date): Database size: $DB_SIZE" >> "$LOG_FILE"

# Check for long-running queries
LONG_QUERIES=$(psql -h localhost -U "$POSTGRES_USER" mailbox -t -c "SELECT count(*) FROM pg_stat_activity WHERE state != 'idle' AND query_start < now() - interval '5 minutes';")
if [[ $LONG_QUERIES -gt 0 ]]; then
    echo "$(date): WARNING: $LONG_QUERIES long-running queries detected" >> "$LOG_FILE"
fi

# Check replication status (if configured)
# Add replication monitoring here if needed

echo "$(date): Monitoring completed" >> "$LOG_FILE"
echo "----------------------------------------" >> "$LOG_FILE"
EOF
    
    chmod +x /usr/local/bin/monitor-mailbox.sh
    
    # Add to crontab for hourly monitoring
    (crontab -l 2>/dev/null; echo "0 * * * * /usr/local/bin/monitor-mailbox.sh") | crontab -
    
    print_info "Database monitoring configured"
}

# Function to create Postfix query files
create_postfix_query_files() {
    print_info "Creating Postfix query files..."
    
    mkdir -p /etc/postfix/pgsql
    
    # Virtual domains query
    cat << EOF > /etc/postfix/pgsql/virtual-mailbox-domains.cf
user = $POSTGRES_USER
password = $POSTGRES_PASSWORD
hosts = 127.0.0.1
dbname = mailbox
query = SELECT 1 FROM mailbox.domains WHERE name='%s' AND active=TRUE
EOF
    
    # Virtual mailbox maps query
    cat << EOF > /etc/postfix/pgsql/virtual-mailbox-maps.cf
user = $POSTGRES_USER
password = $POSTGRES_PASSWORD
hosts = 127.0.0.1
dbname = mailbox
query = SELECT 1 FROM mailbox.users WHERE email='%s' AND active=TRUE
EOF
    
    # Virtual alias maps query
    cat << EOF > /etc/postfix/pgsql/virtual-alias-maps.cf
user = $POSTGRES_USER
password = $POSTGRES_PASSWORD
hosts = 127.0.0.1
dbname = mailbox
query = SELECT destination FROM mailbox.aliases WHERE source='%s' AND active=TRUE
EOF
    
    # Email to email query (for existing users)
    cat << EOF > /etc/postfix/pgsql/virtual-email2email.cf
user = $POSTGRES_USER
password = $POSTGRES_PASSWORD
hosts = 127.0.0.1
dbname = mailbox
query = SELECT email FROM mailbox.users WHERE email='%s' AND active=TRUE
EOF
    
    # Set proper permissions
    chown root:postfix /etc/postfix/pgsql/*.cf
    chmod 640 /etc/postfix/pgsql/*.cf
    
    print_info "Postfix query files created"
}

# Function to create Dovecot query file
create_dovecot_query_file() {
    print_info "Creating Dovecot query file..."
    
    # Create Dovecot SQL configuration
    cat << EOF > /etc/dovecot/dovecot-sql.conf.ext
driver = pgsql
connect = host=127.0.0.1 dbname=mailbox user=$POSTGRES_USER password=$POSTGRES_PASSWORD
default_pass_scheme = SHA512-CRYPT

password_query = SELECT email as user, password FROM mailbox.users WHERE email='%u' AND active=TRUE

user_query = SELECT '/var/mail/vhosts/'||domain||'/'||split_part(email,'@',1) as home, \
'maildir:~/Maildir' as mail, 5000 AS uid, 5000 AS gid \
FROM mailbox.users u \
JOIN mailbox.domains d ON u.domain_id = d.id \
WHERE u.email='%u' AND u.active=TRUE AND d.active=TRUE

# Iterator query for all virtual users
iterate_query = SELECT email as username FROM mailbox.users WHERE active=TRUE
EOF
    
    # Set proper permissions
    chown root:dovecot /etc/dovecot/dovecot-sql.conf.ext
    chmod 640 /etc/dovecot/dovecot-sql.conf.ext
    
    print_info "Dovecot query file created"
}

# Function to test database setup
test_database_setup() {
    print_info "Testing database setup..."
    
    # Test connection
    export PGPASSWORD="$POSTGRES_PASSWORD"
    
    # Test queries
    print_info "Testing Postfix queries..."
    
    # Test domain query
    DOMAIN_TEST=$(postmap -q "$DOMAIN" pgsql:/etc/postfix/pgsql/virtual-mailbox-domains.cf)
    if [[ "$DOMAIN_TEST" == "1" ]]; then
        print_info "✓ Domain query successful"
    else
        print_error "✗ Domain query failed"
    fi
    
    # Test user query
    USER_TEST=$(postmap -q "postmaster@$DOMAIN" pgsql:/etc/postfix/pgsql/virtual-mailbox-maps.cf)
    if [[ "$USER_TEST" == "1" ]]; then
        print_info "✓ User query successful"
    else
        print_error "✗ User query failed"
    fi
    
    # Test alias query
    ALIAS_TEST=$(postmap -q "admin@$DOMAIN" pgsql:/etc/postfix/pgsql/virtual-alias-maps.cf)
    if [[ -n "$ALIAS_TEST" ]]; then
        print_info "✓ Alias query successful"
    else
        print_error "✗ Alias query failed"
    fi
    
    # Test database connectivity
    DB_TEST=$(psql -h localhost -U $POSTGRES_USER -d mailbox -c "SELECT COUNT(*) FROM mailbox.domains;" 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        print_info "✓ Database connectivity successful"
    else
        print_error "✗ Database connectivity failed"
    fi
    
    # Create test report
    cat << EOF > /etc/email-server/database-test-report.txt
Database Setup Test Report
Generated on: $(date)

PostgreSQL Version: $(sudo -u postgres psql -t -c "SELECT version();" | head -n1)
Database: mailbox
User: $POSTGRES_USER

Test Results:
- Domain Query: $(if [[ "$DOMAIN_TEST" == "1" ]]; then echo "PASS"; else echo "FAIL"; fi)
- User Query: $(if [[ "$USER_TEST" == "1" ]]; then echo "PASS"; else echo "FAIL"; fi)
- Alias Query: $(if [[ -n "$ALIAS_TEST" ]]; then echo "PASS"; else echo "FAIL"; fi)
- Database Connectivity: $(if [[ $? -eq 0 ]]; then echo "PASS"; else echo "FAIL"; fi)

Statistics:
- Domains: $(psql -h localhost -U $POSTGRES_USER -d mailbox -t -c "SELECT COUNT(*) FROM mailbox.domains;")
- Users: $(psql -h localhost -U $POSTGRES_USER -d mailbox -t -c "SELECT COUNT(*) FROM mailbox.users;")
- Aliases: $(psql -h localhost -U $POSTGRES_USER -d mailbox -t -c "SELECT COUNT(*) FROM mailbox.aliases;")
EOF
    
    print_info "Database test completed. Report: /etc/email-server/database-test-report.txt"
}

# Main execution
print_info "Starting PostgreSQL setup for mail server..."

# Secure PostgreSQL
secure_postgresql

# Create database and user
create_mail_database

# Create mail tables
create_mail_tables

# Create default users
create_default_users

# Configure PostgreSQL security
configure_postgresql_security

# Create Postfix query files
create_postfix_query_files

# Create Dovecot query file
create_dovecot_query_file

# Create backup script
create_backup_script

# Create maintenance script
create_maintenance_script

# Create monitoring script
create_database_monitoring

# Test database setup
test_database_setup

print_info "PostgreSQL setup complete!"
print_info "Important files:"
echo "  - Database credentials: /etc/email-server/postgres-root-password.txt"
echo "  - Postmaster password: /etc/email-server/postmaster-password.txt"
echo "  - Postfix queries: /etc/postfix/pgsql/"
echo "  - Dovecot queries: /etc/dovecot/dovecot-sql.conf.ext"
echo "  - Database backups: $BACKUP_DIR/database/"
echo "  - Test report: /etc/email-server/database-test-report.txt"

print_warning "Next steps:"
echo "1. Review the database credentials"
echo "2. Test Postfix and Dovecot integration"
echo "3. Monitor backup and maintenance scripts"