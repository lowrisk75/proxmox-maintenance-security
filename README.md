# Proxmox Maintenance & Security

This repository provides a Bash script that automates a range of system maintenance and security tasks on a Proxmox host. It is designed for users who want to streamline the update process, secure their systems, and receive notifications via Discord webhooks.

## Features

- **Host Maintenance:**  
  Updates the Proxmox host system to the latest packages.

- **LXC Container Updates:**  
  Checks for Internet connectivity and updates LXC containers to ensure they run the latest versions.

- **Docker Container Updates:**  
  Detects Docker and updates Docker containers if present.

- **Security Scans:**  
  Performs system security scans using tools such as:
  - **ClamAV** for malware scanning.
  - **RKHunter** to detect rootkits.
  - **Lynis** for overall system auditing.

- **NPM Vulnerability Checking:**  
  If Node.js and npm are present on the system, and a `package.json` is found or Node projects are detected, the script runs `npm audit` to check for known vulnerabilities in JavaScript dependencies.

- **Discord Notifications:**  
  Sends notifications with update and security scan results through a Discord webhook.  
  **Important:** Do not store sensitive settings (like the Discord webhook URL) directly in the repository. Instead, use a local configuration file that is added to `.gitignore`.

## Configuration

Before running the script, create a configuration file (for example, `$HOME/.proxmox_update_config`) containing your settings:

- **BACKUP_PATH:** Path to store backups.
- **DISCORD_WEBHOOK:** Your Discord webhook URL.
- **Other variables:** Any additional settings you require for maintenance or scanning.

*Remember: All sensitive data must remain local and must never be committed to the repository.*

## Usage

1. **Make the Script Executable:**  
   After cloning or downloading the script, run:
   ```bash
   chmod +x proxmox_update.sh
