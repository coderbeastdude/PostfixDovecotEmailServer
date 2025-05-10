#!/bin/bash

# Script to create users, add them to sudo group, and copy SSH keys from root

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Check if root has SSH keys
ROOT_SSH_KEYS="/root/.ssh/authorized_keys"
if [ ! -f "$ROOT_SSH_KEYS" ]; then
    echo "Warning: No authorized_keys file found for root user."
    echo "SSH key copying will be skipped."
    HAS_ROOT_KEYS=false
else
    HAS_ROOT_KEYS=true
fi

while true; do
    # Ask for username
    read -p "Enter username (or press Enter to finish): " username
    
    # Exit loop if no username is provided
    if [ -z "$username" ]; then
        break
    fi
    
    # Check if user already exists
    if id "$username" &>/dev/null; then
        echo "User '$username' already exists"
    else
        # Create user with home directory
        useradd -m -s /bin/bash "$username"
        echo "User '$username' has been created with home directory"
        
        # Set password for the user
        echo "Setting password for $username"
        passwd "$username"
    fi
    
    # Add user to sudo group
    usermod -aG sudo "$username"
    echo "User '$username' has been added to the sudo group"
    
    # Copy SSH keys from root if available
    if [ "$HAS_ROOT_KEYS" = true ]; then
        # Create .ssh directory if it doesn't exist
        sudo -u "$username" mkdir -p "/home/$username/.ssh"
        
        # Copy the SSH keys from root
        cp "$ROOT_SSH_KEYS" "/home/$username/.ssh/authorized_keys"
        
        # Set proper ownership and permissions
        chown "$username:$username" "/home/$username/.ssh/authorized_keys"
        sudo -u "$username" chmod 700 "/home/$username/.ssh"
        sudo -u "$username" chmod 600 "/home/$username/.ssh/authorized_keys"
        
        echo "SSH keys have been copied from root to user '$username'"
    fi
    
    echo "User setup completed for '$username'"
    echo "----------------------------------------"
done

echo "All operations completed"
