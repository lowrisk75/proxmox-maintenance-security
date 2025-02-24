#!/bin/bash
#
# proxmox_update.sh
#
# This script performs host maintenance and (optionally) security scans.
# It updates the host and running LXC (and Docker, if installed) containers.
# For each LXC container, Internet connectivity is checked before updates.
#
# Two Discord notifications are sent using a configured webhook:
#   - An update notification after main tasks complete.
#   - A separate notification when the security scans finish.
#
# Proxmox Maintenance & Security
#      by Kevin Nadjarian - 2025
#

##############################
# CONFIGURATION & GLOBALS
##############################

CONFIG_FILE="$HOME/.proxmox_update_config"
LOGFILE="/var/log/proxmox_update.log"
TEMP_LOG="/tmp/proxmox_update_temp.log"

TOTAL_STEPS=10
STEP=0

# Variables set via configuration
BACKUP_PATH=""
DISCORD_WEBHOOK=""
SECURITY_TOOLS_CHECKED="no"   # Host security tools flag
INSTALL_LXC_SECURITY="no"     # Flag if we want to install security tools in LXC containers

# Operation mode: "yes" means full security, "no" means maintenance only.
RUN_SECURITY="yes"

# Verbose mode (default is "no")
VERBOSE="no"

# Array for warnings when an LXC container lacks Internet connectivity
CONTAINER_NET_WARNINGS=()

# Summary arrays for reporting outcomes
UPDATE_ERRORS=()
DOCKER_SUMMARY=()
SCAN_ERRORS=()
SCAN_SUMMARY=()

# An associative array to hold PIDs for concurrently running scans
declare -A SCAN_PIDS

##############################
# FUNCTIONS
##############################

display_logo() {
    clear
    echo "=========================================="
    echo "      Proxmox Maintenance & Security      "
    echo "          by Kevin Nadjarian - 2025         "
    echo "=========================================="
    echo ""
}

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') : $1" | tee -a "$LOGFILE"
}

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

progress() {
    STEP=$((STEP+1))
    echo -e "\n==> Step $STEP of $TOTAL_STEPS: $1"
    log_message "Starting: $1"
}

setup_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    else
        echo "Configuration file not found. Let's set it up."
        
        read -rp "Enter backup destination folder (full path) [or leave blank]: " BACKUP_PATH
        if [ -n "$BACKUP_PATH" ] && [ ! -d "$BACKUP_PATH" ]; then
            mkdir -p "$BACKUP_PATH" || { echo "Cannot create backup folder! Exiting."; exit 1; }
        fi

        read -rp "Enter your Discord webhook URL (or press Enter to skip): " DISCORD_WEBHOOK

        cat <<EOF > "$CONFIG_FILE"
# Proxmox Maintenance & Security update script configuration
BACKUP_PATH="$BACKUP_PATH"
DISCORD_WEBHOOK="$DISCORD_WEBHOOK"
SECURITY_TOOLS_CHECKED="no"
INSTALL_LXC_SECURITY="no"
EOF
        echo "Configuration saved to $CONFIG_FILE"
    fi

    log_message "Backup Path: $BACKUP_PATH"
    if [ -n "$DISCORD_WEBHOOK" ]; then
        log_message "Discord webhook configured."
    else
        log_message "No Discord webhook configured."
    fi
}

save_config() {
    cat <<EOF > "$CONFIG_FILE"
# Proxmox Maintenance & Security update script configuration
BACKUP_PATH="$BACKUP_PATH"
DISCORD_WEBHOOK="$DISCORD_WEBHOOK"
SECURITY_TOOLS_CHECKED="$SECURITY_TOOLS_CHECKED"
INSTALL_LXC_SECURITY="$INSTALL_LXC_SECURITY"
EOF
}

# Prompts the user to choose verbose output.
# Waits 10 seconds for input and defaults to "n" (non‑verbose) if no input is provided.
choose_verbose() {
    echo
    read -t 10 -rp "Do you want verbose output? [y/N]: " verbose_input
    if [ $? -gt 128 ] || [ -z "$verbose_input" ]; then
        echo ""
        verbose_input="n"
    fi
    if [[ "$verbose_input" =~ ^[Yy]$ ]]; then
        VERBOSE="yes"
    else
        VERBOSE="no"
    fi
    log_message "Verbose mode: $VERBOSE"
}

# Prompts the user to select full (maintenance+security) or maintenance only.
choose_mode() {
    echo
    echo "Select operation mode:"
    echo "  [S] Full Maintenance & Security (default after 10 seconds)"
    echo "  [M] Maintenance Only"
    read -t 10 -rp "Enter your choice [S/M]: " mode
    if [ $? -gt 128 ] || [ -z "$mode" ]; then
        mode="s"
        echo ""
    fi
    mode=$(echo "$mode" | tr '[:upper:]' '[:lower:]')
    if [ "$mode" == "m" ]; then
        RUN_SECURITY="no"
    else
        RUN_SECURITY="yes"
    fi
    echo "Running mode: Maintenance $( [ "$RUN_SECURITY" == "yes" ] && echo "& Security" || echo "Only" )"
    log_message "User selected: RUN_SECURITY = $RUN_SECURITY"
}

# Check if a command exists; if not, prompt to install the package.
check_install_tool() {
    local tool="$1"
    local cmd="$2"
    local pkg="$3"

    if ! command -v "$cmd" &>/dev/null; then
        read -rp "$tool is not installed. Do you want to install it now? [Y/n] " ans
        if [[ $ans =~ ^[Yy]$ ]] || [ -z "$ans" ]; then
            log_message "Installing ${tool}..."
            apt-get install -y "$pkg" &>> "$TEMP_LOG"
            if [ $? -eq 0 ]; then
                log_message "${tool} installed successfully."
            else
                log_message "Error installing ${tool}. Please install it manually."
            fi
        else
            log_message "Skipping installation of ${tool}."
        fi
    else
        log_message "${tool} is already installed."
    fi
}

check_host_security_tools() {
    progress "Checking security tools on host..."
    if [ "$RUN_SECURITY" = "yes" ]; then
        if [ "$SECURITY_TOOLS_CHECKED" = "no" ]; then
            check_install_tool "Trivy" "trivy" "trivy"
            check_install_tool "ClamAV" "clamscan" "clamav"
            check_install_tool "RKHunter" "rkhunter" "rkhunter"
            check_install_tool "Lynis" "lynis" "lynis"
            check_install_tool "Fail2ban" "fail2ban-client" "fail2ban"
            SECURITY_TOOLS_CHECKED="yes"
            save_config
            log_message "Security tools check completed on host."
        else
            log_message "Security tools on host already checked."
        fi
    else
        log_message "Maintenance only mode: skipping host security tools check."
    fi
}

install_security_tools_on_lxc() {
    if [ "$RUN_SECURITY" != "yes" ]; then
        log_message "Maintenance only mode: skipping installation of security tools on LXC containers."
        return
    fi

    progress "Setting up security tools on running LXC containers..."
    if [ "$INSTALL_LXC_SECURITY" = "no" ]; then
        read -rp "Do you want to install security tools (ClamAV, RKHunter, Lynis, Fail2ban) in running LXC containers? [Y/n] " ans_lxc
        if [[ $ans_lxc =~ ^[Yy]$ ]] || [ -z "$ans_lxc" ]; then
            INSTALL_LXC_SECURITY="yes"
        else
            INSTALL_LXC_SECURITY="no"
        fi
        save_config
    fi

    if [ "$INSTALL_LXC_SECURITY" = "yes" ]; then
        CTIDS=$(pct list | awk 'NR>1 && $2=="running" {print $1}')
        if [ -n "$CTIDS" ]; then
            for ctid in $CTIDS; do
                pct exec "$ctid" -- bash -c "command -v clamscan" &>/dev/null
                if [ $? -eq 0 ]; then
                    log_message "Container $ctid already has security tools installed. Skipping installation."
                else
                    log_message "Installing security tools in container $ctid..."
                    install_out=$(pct exec "$ctid" -- bash -c 'if command -v apt-get &>/dev/null; then
                        apt-get update && apt-get install -y clamav rkhunter lynis fail2ban;
                    else
                        echo "apt-get not available in container";
                    fi' 2>&1)
                    ret=$?
                    if [ $ret -eq 0 ]; then
                        log_message "Security tools installed in container $ctid."
                    else
                        log_message "Installation in container $ctid failed or skipped. Output: $install_out"
                    fi
                fi
            done
        else
            log_message "No running LXC containers found for installing security tools."
        fi
    else
        log_message "Skipping installation of security tools on LXC containers."
    fi
}

update_host() {
    progress "Updating host system..."
    {
        apt-get update && \
        apt-get upgrade -y && \
        apt-get dist-upgrade -y && \
        apt-get autoremove -y
    } &>> "$TEMP_LOG" &
    pid=$!
    spinner "$pid"
    wait "$pid"
    if [ $? -eq 0 ]; then
        log_message "Host updates completed successfully."
    else
        log_message "Host updates encountered errors. See $TEMP_LOG."
        UPDATE_ERRORS+=("Host update failure")
    fi
}

# Check Internet connectivity inside an LXC container.
check_container_internet() {
    local ctid=$1
    pct exec "$ctid" -- bash -c "ping -c 1 -W 2 8.8.8.8" &>/dev/null
    return $?
}

update_lxc_containers() {
    progress "Updating running LXC containers..."
    CTIDS=$(pct list | awk 'NR>1 && $2=="running" {print $1}')
    if [ -z "$CTIDS" ]; then
        log_message "No running LXC containers found."
        return
    fi

    for ctid in $CTIDS; do
        log_message "----- Starting update for container $ctid -----"
        echo -e "\n----- Updating container $ctid -----"
        
        if ! check_container_internet "$ctid"; then
            log_message "Container $ctid: No internet connectivity. Skipping update."
            echo "----- Container $ctid update SKIPPED due to no internet connection. -----"
            CONTAINER_NET_WARNINGS+=("Container $ctid lacks internet; update skipped.")
            continue
        fi

        if [ "$VERBOSE" == "yes" ]; then
            pct exec "$ctid" -- bash -c "apt update && apt upgrade -y" 2>&1 | tee -a "$TEMP_LOG"
        else
            pct exec "$ctid" -- bash -c "apt update && apt upgrade -y" &>> "$TEMP_LOG"
        fi

        if [ $? -eq 0 ]; then
            log_message "Container $ctid updated successfully."
            echo "----- Container $ctid update successful. -----"
        else
            log_message "Container $ctid update failed."
            echo "----- Container $ctid update FAILED. -----"
            UPDATE_ERRORS+=("LXC $ctid update failure")
        fi
        log_message "----- Finished update for container $ctid -----"
    done
}

update_docker_containers() {
    progress "Updating Docker containers..."
    if command -v docker &>/dev/null; then
        containers=$(docker ps --format "{{.ID}}")
        if [ -n "$containers" ]; then
            for cid in $containers; do
                image=$(docker inspect --format='{{.Config.Image}}' "$cid")
                log_message "Pulling latest image for container $cid ($image)..."
                docker pull "$image" &>> "$TEMP_LOG"
                if [ $? -eq 0 ]; then
                    msg="Container $cid ($image) updated successfully."
                    log_message "$msg"
                    DOCKER_SUMMARY+=("$msg")
                else
                    msg="Container $cid ($image) update failed."
                    log_message "$msg"
                    DOCKER_SUMMARY+=("$msg")
                    UPDATE_ERRORS+=("Docker $cid update failure")
                fi
            done
        else
            log_message "No running Docker containers found."
            DOCKER_SUMMARY+=("No running Docker containers found.")
        fi

        log_message "Cleaning up Docker system..."
        docker system prune -a -f &>> "$TEMP_LOG"
        if [ $? -eq 0 ]; then
            log_message "Docker cleanup completed successfully."
        else
            log_message "Docker cleanup encountered errors."
            UPDATE_ERRORS+=("Docker cleanup failure")
        fi
    else
        log_message "Docker is not installed. Skipping Docker update."
        DOCKER_SUMMARY+=("Docker not installed.")
    fi
}

clean_journal() {
    progress "Cleaning system journals..."
    journalctl --vacuum-size=100M &>> "$TEMP_LOG"
    if [ $? -eq 0 ]; then
        log_message "Journal cleanup completed."
    else
        log_message "Journal cleanup encountered errors."
        UPDATE_ERRORS+=("Journal cleanup failure")
    fi
}

##############################
# DISCORD NOTIFICATIONS
##############################

send_update_notification() {
    if [ -n "$DISCORD_WEBHOOK" ]; then
        SUMMARY="**Proxmox Update Summary**\n\n"

        if [ ${#UPDATE_ERRORS[@]} -eq 0 ]; then
            SUMMARY+="✅ Host update and system maintenance completed successfully.\n"
        else
            SUMMARY+="⚠️ Host update issues encountered:\n"
            for err in "${UPDATE_ERRORS[@]}"; do
                SUMMARY+=" - $err\n"
            done
        fi

        if [ ${#CONTAINER_NET_WARNINGS[@]} -gt 0 ]; then
            SUMMARY+="\n⚠️ Connectivity issues in some containers:\n"
            for warn in "${CONTAINER_NET_WARNINGS[@]}"; do
                SUMMARY+=" - $warn\n"
            done
        fi

        SUMMARY+="\n**Docker Updates:**\n"
        if [ ${#DOCKER_SUMMARY[@]} -eq 0 ]; then
            SUMMARY+=" - No Docker updates processed.\n"
        else
            for dmsg in "${DOCKER_SUMMARY[@]}"; do
                SUMMARY+=" - $dmsg\n"
            done
        fi

        payload=$(cat <<EOF
{
  "content": "$SUMMARY"
}
EOF
)
        curl -H "Content-Type: application/json" -X POST -d "$payload" "$DISCORD_WEBHOOK" &>> "$TEMP_LOG"

        if [ $? -eq 0 ]; then
            log_message "Update Discord notification sent successfully."
        else
            log_message "Failed to send update Discord notification."
        fi
    else
        log_message "No Discord webhook configured. Update notification skipped."
    fi
}

send_security_notification() {
    if [ -n "$DISCORD_WEBHOOK" ]; then
        SUMMARY="**Proxmox Security Scan Summary**\n\n"

        for smsg in "${SCAN_SUMMARY[@]}"; do
            SUMMARY+=" - $smsg\n"
        done

        if [ ${#SCAN_ERRORS[@]} -gt 0 ]; then
            SUMMARY+="\n⚠️ Some security scans reported issues:\n"
            for err in "${SCAN_ERRORS[@]}"; do
                SUMMARY+=" - $err\n"
            done
        else
            SUMMARY+="\n✅ All security scans completed without errors.\n"
        fi

        payload=$(cat <<EOF
{
  "content": "$SUMMARY"
}
EOF
)
        curl -H "Content-Type: application/json" -X POST -d "$payload" "$DISCORD_WEBHOOK" &>> "$TEMP_LOG"
        if [ $? -eq 0 ]; then
            log_message "Security Discord notification sent successfully."
        else
            log_message "Failed to send security Discord notification."
        fi
    else
        log_message "No Discord webhook configured. Security notification skipped."
    fi
}

##############################
# SECURITY SCANS (ASYNC)
##############################

perform_security_scans() {
    if [ "$RUN_SECURITY" != "yes" ]; then
        log_message "Maintenance only mode: skipping security scans."
        return
    fi

    log_message "Launching security scans on host..."

    if command -v trivy &>/dev/null; then
        log_message "Starting Trivy vulnerability scan..."
        trivy fs / &>> "$TEMP_LOG" &
        SCAN_PIDS[trivy]=$!
    else
        log_message "Trivy not installed. Skipping vulnerability scan."
        SCAN_SUMMARY+=("Trivy scan: Not installed")
    fi

    if command -v clamscan &>/dev/null; then
        log_message "Starting ClamAV scan..."
        clamscan -r / &>> "$TEMP_LOG" &
        SCAN_PIDS[clamav]=$!
    else
        log_message "ClamAV not installed. Skipping antivirus scan."
        SCAN_SUMMARY+=("ClamAV scan: Not installed")
    fi

    if command -v rkhunter &>/dev/null; then
        log_message "Starting RKHunter rootkit detection..."
        rkhunter --check --sk --disable-keypress &>> "$TEMP_LOG" &
        SCAN_PIDS[rkhunter]=$!
    else
        log_message "RKHunter not installed. Skipping rootkit detection."
        SCAN_SUMMARY+=("RKHunter: Not installed")
    fi

    if command -v lynis &>/dev/null; then
        log_message "Starting Lynis security audit..."
        lynis audit system --quick &>> "$TEMP_LOG" &
        SCAN_PIDS[lynis]=$!
    else
        log_message "Lynis not installed. Skipping security audit."
        SCAN_SUMMARY+=("Lynis audit: Not installed")
    fi

    if command -v docker &>/dev/null && docker info &>/dev/null; then
        if [ -x "./docker-bench-security.sh" ]; then
            log_message "Starting Docker Security Benchmark..."
            ./docker-bench-security.sh &>> "$TEMP_LOG" &
            SCAN_PIDS[dockerBench]=$!
        else
            log_message "docker-bench-security.sh not found/executable. Skipping Docker benchmark."
            SCAN_SUMMARY+=("Docker Sec Benchmark: Not executed")
        fi
    else
        log_message "Docker not available for security benchmarking."
        SCAN_SUMMARY+=("Docker Sec Benchmark: Docker not available")
    fi

    if command -v fail2ban-client &>/dev/null; then
        log_message "Checking Fail2ban status..."
        fail2ban-client status &>> "$TEMP_LOG"
        if [ $? -ne 0 ]; then
            log_message "Fail2ban status encountered errors."
            SCAN_SUMMARY+=("Fail2ban check: ERROR")
            SCAN_ERRORS+=("Fail2ban status failure")
        else
            log_message "Fail2ban appears to be running normally."
            SCAN_SUMMARY+=("Fail2ban check: OK")
        fi
    else
        log_message "Fail2ban not installed. Skipping intrusion prevention check."
        SCAN_SUMMARY+=("Fail2ban check: Not installed")
    fi

    CTIDS=$(pct list | awk 'NR>1 && $2=="running" {print $1}')
    if [ -z "$CTIDS" ]; then
        log_message "No running LXC containers for npm vulnerability scanning."
        SCAN_SUMMARY+=("No LXC containers for npm vulnerability scans.")
    else
        for ctid in $CTIDS; do
            pct exec "$ctid" -- bash -c "command -v npm" &>/dev/null
            if [ $? -eq 0 ]; then
                log_message "Container $ctid has npm installed. Running npm audit..."
                pct exec "$ctid" -- bash -c "npm audit --json" &>> "$TEMP_LOG"
                if [ $? -eq 0 ]; then
                    log_message "Container $ctid: npm audit completed."
                    SCAN_SUMMARY+=("Container $ctid: npm audit: OK")
                else
                    log_message "Container $ctid: npm audit encountered issues."
                    SCAN_SUMMARY+=("Container $ctid: npm audit: Issues found")
                    SCAN_ERRORS+=("Container $ctid: npm audit failure")
                fi
            else
                log_message "Container $ctid does not have npm. Skipping npm audit."
                SCAN_SUMMARY+=("Container $ctid: npm not installed, audit skipped.")
            fi
        done
    fi

    # Wait for all launched scan processes.
    for scan in "${!SCAN_PIDS[@]}"; do
        wait "${SCAN_PIDS[$scan]}"
        exit_code=$?
        if [ $exit_code -ne 0 ]; then
            log_message "$scan scan encountered errors (exit code $exit_code)."
            SCAN_SUMMARY+=("$scan scan: ERROR")
            SCAN_ERRORS+=("$scan scan failure")
        else
            log_message "$scan scan completed successfully."
            SCAN_SUMMARY+=("$scan scan: OK")
        fi
    done
}

# Wrapper that runs security scans and then sends a Discord security notification.
do_security_scans_bg() {
    perform_security_scans
    send_security_notification
}

##############################
# MISCELLANEOUS TASKS
##############################

check_internet() {
    progress "Checking Internet connectivity..."
    if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
        log_message "Internet connection OK."
    else
        log_message "Internet connection failed. Exiting."
        exit 1
    fi
}

##############################
# MAIN SCRIPT EXECUTION
##############################

if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root (or via sudo)." >&2
    exit 1
fi

display_logo
setup_config
choose_verbose
choose_mode
touch "$LOGFILE" || { echo "Cannot write to log file $LOGFILE"; exit 1; }
: > "$TEMP_LOG"

check_internet
update_host
update_lxc_containers
update_docker_containers
clean_journal

check_host_security_tools
install_security_tools_on_lxc

# Send an update summary notification.
send_update_notification

# Launch security scans (and send security notification when complete) in background.
if [ "$RUN_SECURITY" = "yes" ]; then
    do_security_scans_bg &
    log_message "Security scans launched in background. Security notification will be sent upon completion."
fi

progress "All tasks completed!"
log_message "Script finished. Please review $LOGFILE and $TEMP_LOG for details."

exit 0
