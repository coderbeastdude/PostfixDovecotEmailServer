#!/bin/bash

# Email User Management Script
# Manages email users in the PostgreSQL database

set -euo pipefail

# Load configuration
if [[ -f /etc/email-server-config.conf ]]; then
    source /etc/email-server-config.conf
else
    echo "Configuration file not found. Using defaults..."
    POSTGRES_USER="mailuser"
fi

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

# Function to check if running as root or with sudo
check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root or with sudo"
        exit 1
    fi
}

# Function to add a new email user
add_user() {
    print_info "Adding new email user..."
    
    read -p "Enter email address: " email
    
    # Validate email format
    if [[ ! "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        print_error "Invalid email format"
        exit 1
    fi
    
    # Get domain from email
    domain=$(echo "$email" | cut -d@ -f2)
    
    # Check if domain exists
    export PGPASSWORD="$POSTGRES_PASSWORD"
    domain_exists=$(psql -h localhost -U "$POSTGRES_USER" -d mailbox -t -c \
        "SELECT COUNT(*) FROM domains WHERE name='$domain';")
    
    if [[ $domain_exists -eq 0 ]]; then
        print_error "Domain $domain does not exist in the database"
        print_info "Available domains:"
        psql -h localhost -U "$POSTGRES_USER" -d mailbox -c \
            "SELECT name FROM domains WHERE active=TRUE;"
        exit 1
    fi
    
    # Check if user already exists
    user_exists=$(psql -h localhost -U "$POSTGRES_USER" -d mailbox -t -c \
        "SELECT COUNT(*) FROM users WHERE email='$email';")
    
    if [[ $user_exists -gt 0 ]]; then
        print_error "User $email already exists"
        exit 1
    fi
    
    # Get password
    while true; do
        read -s -p "Enter password for $email: " password
        echo
        read -s -p "Confirm password: " password_confirm
        echo
        
        if [[ "$password" == "$password_confirm" ]]; then
            break
        else
            print_error "Passwords do not match. Please try again."
        fi
    done
    
    # Generate password hash
    hash=$(doveadm pw -s SHA512-CRYPT -p "$password")
    
    # Add user to database
    psql -h localhost -U "$POSTGRES_USER" -d mailbox -c "
        INSERT INTO users (domain_id, password, email) 
        VALUES (
            (SELECT id FROM domains WHERE name='$domain'), 
            '$hash', 
            '$email'
        );"
    
    print_info "User $email created successfully"
    
    # Ask about quota
    read -p "Set quota for this user? (y/N): " set_quota
    if [[ "$set_quota" =~ ^[Yy]$ ]]; then
        read -p "Enter quota in MB (0 for unlimited): " quota_mb
        quota_bytes=$((quota_mb * 1048576))
        
        psql -h localhost -U "$POSTGRES_USER" -d mailbox -c "
            UPDATE users SET quota=$quota_bytes WHERE email='$email';"
        
        print_info "Quota set to ${quota_mb}MB for $email"
    fi
}

# Function to list all email users
list_users() {
    print_info "Listing all email users..."
    
    export PGPASSWORD="$POSTGRES_PASSWORD"
    psql -h localhost -U "$POSTGRES_USER" -d mailbox -c "
        SELECT 
            u.email, 
            d.name as domain, 
            CASE 
                WHEN u.quota = 0 THEN 'Unlimited'
                ELSE pg_size_pretty(u.quota::bigint)
            END as quota,
            CASE WHEN u.active THEN 'Active' ELSE 'Disabled' END as status
        FROM users u 
        JOIN domains d ON u.domain_id = d.id 
        ORDER BY d.name, u.email;"
}

# Function to delete/disable a user
delete_user() {
    print_info "Deactivating email user..."
    
    read -p "Enter email address to deactivate: " email
    
    # Check if user exists
    export PGPASSWORD="$POSTGRES_PASSWORD"
    user_exists=$(psql -h localhost -U "$POSTGRES_USER" -d mailbox -t -c \
        "SELECT COUNT(*) FROM users WHERE email='$email';")
    
    if [[ $user_exists -eq 0 ]]; then
        print_error "User $email does not exist"
        exit 1
    fi
    
    # Confirm deletion
    read -p "Are you sure you want to deactivate $email? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_info "Operation cancelled"
        exit 0
    fi
    
    # Deactivate user
    psql -h localhost -U "$POSTGRES_USER" -d mailbox -c "
        UPDATE users SET active = FALSE WHERE email = '$email';"
    
    print_info "User $email has been deactivated"
    print_warning "Mail data is preserved. To permanently delete, remove the user's Maildir manually."
}

# Function to reset user password
reset_password() {
    print_info "Resetting password for email user..."
    
    read -p "Enter email address: " email
    
    # Check if user exists
    export PGPASSWORD="$POSTGRES_PASSWORD"
    user_exists=$(psql -h localhost -U "$POSTGRES_USER" -d mailbox -t -c \
        "SELECT COUNT(*) FROM users WHERE email='$email' AND active=TRUE;")
    
    if [[ $user_exists -eq 0 ]]; then
        print_error "Active user $email does not exist"
        exit 1
    fi
    
    # Get new password
    while true; do
        read -s -p "Enter new password for $email: " password
        echo
        read -s -p "Confirm password: " password_confirm
        echo
        
        if [[ "$password" == "$password_confirm" ]]; then
            break
        else
            print_error "Passwords do not match. Please try again."
        fi
    done
    
    # Generate password hash
    hash=$(doveadm pw -s SHA512-CRYPT -p "$password")
    
    # Update password
    psql -h localhost -U "$POSTGRES_USER" -d mailbox -c "
        UPDATE users SET password='$hash' WHERE email='$email';"
    
    print_info "Password updated successfully for $email"
}

# Function to show help
show_help() {
    echo "Email User Management Script"
    echo "=========================="
    echo
    echo "Usage: $0 {add|list|delete|reset|help}"
    echo
    echo "Commands:"
    echo "  add     - Add a new email user"
    echo "  list    - List all email users"
    echo "  delete  - Deactivate an email user"
    echo "  reset   - Reset user password"
    echo "  help    - Show this help message"
    echo
    echo "Examples:"
    echo "  $0 add              # Add a new email user"
    echo "  $0 list             # List all users"
    echo "  $0 delete           # Deactivate a user"
    echo "  $0 reset            # Reset user password"
}

# Main execution
check_privileges

case "${1:-help}" in
    add)
        add_user
        ;;
    list)
        list_users
        ;;
    delete)
        delete_user
        ;;
    reset)
        reset_password
        ;;
    help)
        show_help
        ;;
    *)
        print_error "Invalid command: $1"
        echo
        show_help
        exit 1
        ;;
esac
