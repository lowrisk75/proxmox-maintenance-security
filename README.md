# Proxmox Maintenance & Security

This repository contains a Bash script designed to update the Proxmox host and LXC containers, perform security scans, and send notifications via Discord webhooks.

## Features

- **Host Maintenance:** Update the host system.
- **LXC Container Updates:** Check for Internet connectivity and update LXC containers.
- **Docker Container Updates:** Update Docker containers if Docker is detected.
- **Security Scans:** Run security scans using tools like ClamAV, RKHunter, and Lynis.
- **Discord Notifications:** Sends notifications with update results and security issues.

## Configuration

Before running the script, create a configuration file (for example, at `$HOME/.proxmox_update_config`) that contains your settings like:
- `BACKUP_PATH` – The folder for backups.
- `DISCORD_WEBHOOK` – Your Discord webhook URL.
- (Other configuration variables as needed.)

**Note:** Do not add sensitive data or API keys directly in the repository.

## Usage

Run the script as root or using sudo:

```bash
sudo ./proxmox_update.sh
