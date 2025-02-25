# Proxmox Container Security and Maintenance Script v2.0

A comprehensive security and maintenance tool for Proxmox LXC containers that automates updates, security checks, virus scanning, and network diagnostics.

## 🔍 Overview

This script provides an all-in-one solution for maintaining and securing Proxmox VE containers. It performs system updates, security audits, virus scanning, and network diagnostics on all running containers while providing detailed reports and optional notifications.

## ✨ Features

- **Comprehensive Security Checks**: Scans all containers for security vulnerabilities, suspicious files, and unauthorized access attempts
- **Virus Scanning**: Built-in ClamAV integration for malware detection (uses host-based clamd for efficiency)
- **Smart Network Diagnostics**: Automatically detects and attempts to fix container network issues, including DNS problems
- **Container Updates**: Safely updates all Debian/Ubuntu-based containers using `apt-get dist-upgrade` for proper dependency handling
- **Backup Functionality**: Optional backups of containers before making changes
- **Flexible Execution Modes**: Run full maintenance, security-only checks, or updates-only
- **Notification Options**: Send detailed reports via Discord or email
- **Interactive Setup**: Easy-to-use wizard for first-time configuration
- **Detailed Logging**: Comprehensive logs and summary reports for review
- **Kernel Update Detection**: Identifies when host reboots are needed

## 📋 Requirements

- Proxmox VE 7.0 or higher
- Root access to the Proxmox host
- Internet connectivity for updates and virus definition downloads
- For email notifications: 
  - Configured mail system (mailutils package)
  - SMTP setup for outbound mail

## 🚀 Installation

```bash
# Download the script
wget -O pvesecure https://raw.githubusercontent.com/yourusername/proxmox-tools/main/pvesecure

# Make it executable
chmod +x pvesecure

# Run it
sudo ./pvesecure
```

## 💻 Usage

### Interactive Mode

Simply run the script without arguments to use the interactive setup wizard:

```bash
sudo ./pvesecure
```

The wizard will guide you through selecting:
- Maintenance type (full, updates only, security only, virus scan only)
- Backup options
- Verbosity level
- Notification methods

### Command-line Options

For automated or scheduled runs, use command-line flags:

```bash
Options:
  -v, --verbose         Enable verbose output
  -f, --full            Run full maintenance (updates, security, virus scan)
  -b, --backup          Create backups before making changes
  -u, --update-only     Run only system updates
  -s, --security-only   Run only security checks and virus scan
  -vs, --virus-scan-only Run only virus scan
  -d, --discord         Enable Discord notifications
  -e, --email EMAIL     Send email report to specified address
  -h, --help            Display this help message
```

Examples:

```bash
# Run full maintenance with Discord notifications
sudo ./pvesecure -f -d

# Run only virus scanning with email report
sudo ./pvesecure -vs -e admin@example.com

# Run updates only with verbose output and backups
sudo ./pvesecure -u -v -b
```

## 📢 Notification Setup

### Discord Notifications

1. Create a Discord webhook in your server (Server Settings → Integrations → Webhooks)
2. Run the script with the `-d` flag or select Discord in the interactive menu
3. Enter your webhook URL when prompted (it will be saved for future use)

### Email Notifications

1. Install the required package on your Proxmox host:
   ```bash
   apt-get install mailutils
   ```

2. Configure your mail system (if not already set up):
   ```bash
   dpkg-reconfigure exim4-config
   ```
   
   For simple setups:
   - Choose "internet site" and follow the prompts
   
   For connection through an external provider:
   - Choose "mail sent by smarthost; no local mail"
   - Configure your SMTP server details when prompted

3. Run the script with the email option:
   ```bash
   sudo ./pvesecure -e your-email@example.com
   ```

## 🔒 Security Checks

The script performs the following security checks on each container:

- **Login Attempt Analysis**: Scans auth.log for suspicious login attempts
- **Rootkit Detection**: Basic checks for signs of rootkits
- **Open Ports**: Identifies unexpected open ports and services
- **File Permission Issues**: Detects incorrect permissions on sensitive files
- **Suspicious Processes**: Looks for unusual running processes

## 🦠 Virus Scanning Architecture

The script uses an efficient approach to virus scanning:

1. ClamAV is installed once on the Proxmox host (not on each container)
2. The clamd daemon runs on the host
3. Container filesystems are bind-mounted to the host
4. The host's clamdscan scans the mounted filesystem
5. Results are collected and reported

This architecture provides several advantages:
- Lower resource usage (single virus database in memory)
- Faster updates to virus definitions
- Up-to-date scanning engine for all containers
- No need to modify containers or install software inside them

## 🔄 Update Methodology

For container updates, the script:

1. Uses `apt-get update` to refresh package lists
2. Uses `apt-get dist-upgrade` (not regular upgrade) to properly handle dependency changes
3. This follows Proxmox's official recommendation for system updates

## 📋 Logs and Reports

The script generates two types of logs:

1. **Summary Report**: A high-level overview of the maintenance run, including:
   - Number of containers processed
   - Update successes and failures
   - Network issues detected
   - Virus scan results
   
2. **Detailed Log**: In-depth information about each container, including:
   - Command outputs
   - Error messages
   - Security check details
   - Network diagnostics

Logs are stored in `/var/log/proxmox_maintenance/` with timestamps.

## 📅 Scheduled Maintenance

To run the script automatically, add it to your crontab:

```bash
# Edit crontab
crontab -e

# Add a line to run weekly at 3 AM on Sundays
0 3 * * 0 /path/to/pvesecure -f -d
```

## 🔍 Advanced Configuration

Advanced settings can be modified at the top of the script:

- Log retention period
- Scan exclusion patterns
- Security check severity levels
- Network timeout values

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📜 License

This script is released under the MIT License. See the LICENSE file for details.

## ⚠️ Disclaimer

This script makes changes to your Proxmox system and containers. It's recommended to test it in a non-production environment first and to enable the backup option during initial runs.
