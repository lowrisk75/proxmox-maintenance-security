# Proxmox Container Security and Maintenance Script v2.0

<div align="center">

![PVESecure Logo](https://img.shields.io/badge/PVE-Secure-blue?style=for-the-badge&logo=proxmox&logoColor=white)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Proxmox](https://img.shields.io/badge/Proxmox-7.0+-orange.svg)](https://www.proxmox.com/)
[![ClamAV](https://img.shields.io/badge/ClamAV-Integrated-green.svg)](https://www.clamav.net/)

</div>

<div align="center">
<i>Developed by Kevin Nadjarian - ConnectedSecure</i><br>
<a href="https://www.youtube.com/@connectedsecure">YouTube: @connectedsecure</a> | <a href="https://twitter.com/SecureConnected">Twitter: @SecureConnected</a>
</div>

---

A comprehensive security and maintenance tool for Proxmox LXC containers that automates updates, security checks, virus scanning, and network diagnostics.

## 🔍 Overview

This script provides an all-in-one solution for maintaining and securing Proxmox VE containers. It performs system updates, security audits, virus scanning, and network diagnostics on all running containers while providing detailed reports and optional notifications.

<div align="center">
<img src="https://img.shields.io/badge/Automates-Security%20Checks-blue?style=flat-square" /> 
<img src="https://img.shields.io/badge/Automates-Container%20Updates-blue?style=flat-square" />
<img src="https://img.shields.io/badge/Automates-Virus%20Scans-blue?style=flat-square" />
</div>

## ✨ Features

- **🔒 Comprehensive Security Checks**: Scans all containers for security vulnerabilities, suspicious files, and unauthorized access attempts
- **🦠 Virus Scanning**: Built-in ClamAV integration for malware detection (uses host-based clamd for efficiency)
- **🔍 Smart Network Diagnostics**: Automatically detects and attempts to fix container network issues, including DNS problems
- **📦 Container Updates**: Safely updates all Debian/Ubuntu-based containers using `apt-get dist-upgrade` for proper dependency handling
- **💾 Backup Functionality**: Optional backups of containers before making changes
- **⚙️ Flexible Execution Modes**: Run full maintenance, security-only checks, or updates-only
- **📣 Notification Options**: Send detailed reports via Discord or email
- **🧙‍♂️ Interactive Setup**: Easy-to-use wizard for first-time configuration
- **📋 Detailed Logging**: Comprehensive logs and summary reports for review
- **🔄 Kernel Update Detection**: Identifies when host reboots are needed

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

```
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

<details>
<summary><b>Click to see example commands</b></summary>

```bash
# Run full maintenance with Discord notifications
sudo ./pvesecure -f -d

# Run only virus scanning with email report
sudo ./pvesecure -vs -e admin@example.com

# Run updates only with verbose output and backups
sudo ./pvesecure -u -v -b
```
</details>

## 🔄 Running in Background Sessions

When running security scans that may take a long time to complete, you'll need a way to keep the process running even if you disconnect from your SSH session.

### Recommended Method: Using Tmux (Most Secure)

```bash
# Install tmux if not already present
apt install tmux -y

# Create a named session for the security scan
tmux new-session -s pvesecure_scan

# Now run the script in the tmux session
./pvesecure

# To detach while keeping the process running:
# Press Ctrl+B, then D
```

To reconnect to your session later:

```bash
# List available sessions
tmux list-sessions

# Reattach to your session
tmux attach-session -t pvesecure_scan
```

<details>
<summary><b>Advanced Security Options</b></summary>

For enhanced security in sensitive environments:

```bash
# Create a tmux session with restricted socket permissions
mkdir -p ~/.tmux_sockets
tmux -S ~/.tmux_sockets/pvesecure_socket new-session -s pvesecure_scan
chmod 700 ~/.tmux_sockets/pvesecure_socket

# To reattach later:
tmux -S ~/.tmux_sockets/pvesecure_socket attach-session -t pvesecure_scan
```

Alternative methods (not as secure as tmux):

**Using Screen:**
```bash
apt install screen -y
screen
./pvesecure
# Press Ctrl+A, then D to detach
# To reconnect: screen -r
```

**Using nohup:**
```bash
nohup ./pvesecure > pvesecure_output.log 2>&1 &
# Check status: ps aux | grep pvesecure
# View output: cat pvesecure_output.log
```
</details>

## 📢 Notification Setup

<details>
<summary><b>Discord Notifications</b></summary>

1. Create a Discord webhook in your server (Server Settings → Integrations → Webhooks)
2. Run the script with the `-d` flag or select Discord in the interactive menu
3. Enter your webhook URL when prompted (it will be saved for future use)

</details>

<details>
<summary><b>Email Notifications</b></summary>

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
</details>

## 🔒 Security Features

<details>
<summary><b>Security Checks</b></summary>

The script performs the following security checks on each container:

- **Login Attempt Analysis**: Scans auth.log for suspicious login attempts
- **Rootkit Detection**: Basic checks for signs of rootkits
- **Open Ports**: Identifies unexpected open ports and services
- **File Permission Issues**: Detects incorrect permissions on sensitive files
- **Suspicious Processes**: Looks for unusual running processes
</details>

<details>
<summary><b>Virus Scanning Architecture</b></summary>

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
</details>

<details>
<summary><b>Update Methodology</b></summary>

For container updates, the script:

1. Uses `apt-get update` to refresh package lists
2. Uses `apt-get dist-upgrade` (not regular upgrade) to properly handle dependency changes
3. This follows Proxmox's official recommendation for system updates
</details>

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

<details>
<summary><b>Setting up Cron Jobs</b></summary>

To run the script automatically, add it to your crontab:

```bash
# Edit crontab
crontab -e

# Add a line to run weekly at 3 AM on Sundays
0 3 * * 0 /path/to/pvesecure -f -d
```

**Example schedules:**

- Daily security-only scan at midnight:
  ```
  0 0 * * * /path/to/pvesecure -s -d
  ```

- Weekly full maintenance with backups on Saturday at 2 AM:
  ```
  0 2 * * 6 /path/to/pvesecure -f -b -d
  ```

- Monthly virus scan on the 1st at 4 AM:
  ```
  0 4 1 * * /path/to/pvesecure -vs -e admin@example.com
  ```
</details>

## 🔍 Advanced Configuration

Advanced settings can be modified at the top of the script:

- Log retention period
- Scan exclusion patterns
- Security check severity levels
- Network timeout values

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

<div align="center">

## 📊 Project Status

![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)
![Last Commit](https://img.shields.io/github/last-commit/yourusername/proxmox-tools?style=for-the-badge)
![Open Issues](https://img.shields.io/github/issues-raw/yourusername/proxmox-tools?style=for-the-badge)

</div>

## 📜 License

This script is released under the MIT License. See the LICENSE file for details.

## ⚠️ Disclaimer

This script makes changes to your Proxmox system and containers. It's recommended to test it in a non-production environment first and to enable the backup option during initial runs.

---

<div align="center">
<i>If this tool saved you time, consider starring the repository!</i><br><br>
<a href="https://github.com/yourusername/proxmox-tools/stargazers"><img src="https://img.shields.io/github/stars/yourusername/proxmox-tools?style=social" alt="GitHub stars"></a>
</div>
