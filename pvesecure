#!/bin/bash
# Proxmox Container Security and Maintenance Script

VERSION="2.0"
DEBUG=false
TIMEOUT_DURATION=10
TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)

# Log file locations
LOG_DIR="/var/log/proxmox_maintenance"
LOG_FILE="$LOG_DIR/maintenance_${TIMESTAMP}.log"
DETAILED_LOG="$LOG_DIR/maintenance_${TIMESTAMP}_detailed.log"
SUMMARY_FILE="$LOG_DIR/maintenance_${TIMESTAMP}_summary.txt"

# Initialize arrays for container status tracking
declare -A CONTAINER_STATUS
declare -A CONTAINER_IPS
declare -A CONTAINER_PING_TIMES
declare -A CONTAINER_UPDATES
declare -A CONTAINER_SCAN_RESULTS
UPDATED_CONTAINERS=()
FAILED_CONTAINERS=()
SKIPPED_CONTAINERS=()
NETWORK_ISSUES=()
INFECTED_CONTAINERS=()
TOTAL_CONTAINERS=0
CURRENT_CONTAINER=0

# Default settings
VERBOSE=false
RUN_SECURITY=true
RUN_VIRUS_SCAN=true
RUN_UPDATES=true
MAX_PARALLEL=5
CURRENT_PARALLEL=0
AUTO_INSTALL_TOOLS=false
DISCORD_NOTIFICATION=false
FULL_MAINTENANCE=false
CREATE_BACKUPS=false  # Disabled by default
EMAIL_RECIPIENT=""

# ClamAV configuration
USE_CLAMD=true

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Create log directory
mkdir -p "$LOG_DIR"

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root${NC}"
        exit 1
    fi
}

# Function to get Discord webhook
get_discord_webhook() {
    if [ "$DISCORD_NOTIFICATION" = true ] && [ ! -f "${LOG_DIR}/discord_webhook.txt" ]; then
        read -p "Enter Discord webhook URL: " webhook
        echo "$webhook" > "${LOG_DIR}/discord_webhook.txt"
    fi
}

# Function to send Discord notifications
send_discord_notification() {
    if [ "$DISCORD_NOTIFICATION" = true ] && [ -f "${LOG_DIR}/discord_webhook.txt" ]; then
        local webhook_url
        webhook_url=$(cat "${LOG_DIR}/discord_webhook.txt")
        local message="$1"
        curl -H "Content-Type: application/json" \
             -d "{\"content\":\"$message\"}" \
             "$webhook_url" >/dev/null 2>&1
    fi
}

# Logging functions
log_message() {
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "$timestamp : $1" | tee -a "$LOG_FILE"
    [ "$DISCORD_NOTIFICATION" = true ] && send_discord_notification "$1"
}

log_detailed() {
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "$timestamp : $1" >> "$DETAILED_LOG"
    if [ "$VERBOSE" = true ]; then
        echo "$timestamp : $1"
    fi
}

log_error() {
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "${RED}$timestamp : ERROR : $1${NC}" | tee -a "$LOG_FILE" "$DETAILED_LOG"
    [ "$DISCORD_NOTIFICATION" = true ] && send_discord_notification "ERROR: $1"
}

log_success() {
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "${GREEN}$timestamp : SUCCESS : $1${NC}" | tee -a "$LOG_FILE"
    [ "$DISCORD_NOTIFICATION" = true ] && send_discord_notification "SUCCESS: $1"
}

log_warning() {
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "${YELLOW}$timestamp : WARNING : $1${NC}" | tee -a "$LOG_FILE"
    [ "$DISCORD_NOTIFICATION" = true ] && send_discord_notification "WARNING: $1"
}

# Progress display
progress() {
    echo -e "\n${BLUE}==> $1${NC}"
    log_message "$1"
}

# Email report function
send_email_report() {
    if [ -z "$EMAIL_RECIPIENT" ]; then
        return 0
    fi
    
    local email_body="/tmp/security_email_body.txt"
    
    {
        echo "Proxmox Container Security and Maintenance Report - $(date)"
        echo "=========================================================="
        echo ""
        echo "Summary:"
        cat "$SUMMARY_FILE"
        echo ""
        echo "For detailed information, check logs in $LOG_DIR on the Proxmox host."
    } > "$email_body"
    
    if command -v mail &> /dev/null; then
        if mail -s "Proxmox Container Security Report - $(date +%F)" "$EMAIL_RECIPIENT" < "$email_body"; then
            log_success "Email report sent to $EMAIL_RECIPIENT"
        else
            log_error "Failed to send email report"
        fi
    else
        log_warning "Mail command not found. Email report not sent. Install with: apt-get install mailutils"
    fi
    
    rm -f "$email_body"
}

# Interactive setup
setup_script() {
    echo -e "\n${BLUE}Proxmox Container Security and Maintenance Script v$VERSION${NC}"
    echo -e "${BLUE}=======================================================${NC}"
    echo -e "\n${BLUE}Starting setup...${NC}"

    # --- Maintenance Type Selection ---
    echo -e "\nSelect maintenance type:"
    PS3="Enter your choice (number): "
    options=("Full maintenance (updates, security, virus scan)" 
             "Basic updates only" 
             "Security and virus scanning only"
             "Virus scanning only")
    select opt in "${options[@]}"
    do
        if [[ -n "$opt" ]]; then
            echo "You selected: $opt"
            case "$REPLY" in
                1)
                    FULL_MAINTENANCE=true
                    RUN_UPDATES=true
                    RUN_SECURITY=true
                    RUN_VIRUS_SCAN=true
                    ;;
                2)
                    FULL_MAINTENANCE=false
                    RUN_UPDATES=true
                    RUN_SECURITY=false
                    RUN_VIRUS_SCAN=false
                    ;;
                3)
                    FULL_MAINTENANCE=false
                    RUN_UPDATES=false
                    RUN_SECURITY=true
                    RUN_VIRUS_SCAN=true
                    ;;
                4)
                    FULL_MAINTENANCE=false
                    RUN_UPDATES=false
                    RUN_SECURITY=false
                    RUN_VIRUS_SCAN=true
                    ;;
            esac
            break
        else
            echo "Invalid selection. Please try again."
        fi
    done

    # --- Backup Selection ---
    echo -e "\nCreate backups before making changes?"
    PS3="Enter your choice (number): "
    options=("Yes" "No")
    select opt in "${options[@]}"
    do
        if [[ -n "$opt" ]]; then
            if [ "$REPLY" -eq 1 ]; then
                CREATE_BACKUPS=true
            else
                CREATE_BACKUPS=false
            fi
            echo "Create backups: $opt"
            break
        else
            echo "Invalid selection. Please try again."
        fi
    done

    # --- Verbose Output Selection ---
    echo -e "\nSelect verbose output:"
    PS3="Enter your choice (number): "
    options=("Yes" "No")
    select opt in "${options[@]}"
    do
        if [[ -n "$opt" ]]; then
            if [ "$REPLY" -eq 1 ]; then
                VERBOSE=true
            else
                VERBOSE=false
            fi
            echo "Verbose output: $opt"
            break
        else
            echo "Invalid selection. Please try again."
        fi
    done

    # --- Notification Options ---
    echo -e "\nSelect notification method:"
    PS3="Enter your choice (number): "
    options=("Discord" "Email" "Both" "None")
    select opt in "${options[@]}"
    do
        if [[ -n "$opt" ]]; then
            case "$REPLY" in
                1)
                    DISCORD_NOTIFICATION=true
                    get_discord_webhook
                    ;;
                2)
                    read -p "Enter email address for reports: " EMAIL_RECIPIENT
                    ;;
                3)
                    DISCORD_NOTIFICATION=true
                    get_discord_webhook
                    read -p "Enter email address for reports: " EMAIL_RECIPIENT
                    ;;
                4)
                    DISCORD_NOTIFICATION=false
                    EMAIL_RECIPIENT=""
                    ;;
            esac
            break
        else
            echo "Invalid selection. Please try again."
        fi
    done
    
    # Show configuration summary and ask for confirmation
    echo -e "\n${BLUE}Configuration Summary:${NC}"
    echo "Maintenance Type: $( [ "$FULL_MAINTENANCE" = true ] && echo "Full" || echo "Basic" )"
    echo "Run Updates: $( [ "$RUN_UPDATES" = true ] && echo "Yes" || echo "No" )"
    echo "Run Security Checks: $( [ "$RUN_SECURITY" = true ] && echo "Yes" || echo "No" )"
    echo "Run Virus Scanning: $( [ "$RUN_VIRUS_SCAN" = true ] && echo "Yes" || echo "No" )"
    echo "Create Backups: $( [ "$CREATE_BACKUPS" = true ] && echo "Yes" || echo "No" )"
    echo "Verbose Output: $( [ "$VERBOSE" = true ] && echo "Yes" || echo "No" )"
    echo "Discord Notifications: $( [ "$DISCORD_NOTIFICATION" = true ] && echo "Yes" || echo "No" )"
    echo "Email Notifications: $( [ -n "$EMAIL_RECIPIENT" ] && echo "Yes ($EMAIL_RECIPIENT)" || echo "No" )"
    
    read -p "Proceed with these settings? (y/N): " confirm
    if [[ ! $confirm =~ ^[Yy] ]]; then
        echo -e "\n${RED}Setup cancelled by user${NC}"
        exit 1
    fi

    echo -e "\n${BLUE}Starting maintenance process...${NC}"
}

# Check system requirements
check_requirements() {
    local required_commands=("pct" "apt-get" "ping" "awk" "grep" "curl")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command '$cmd' not found"
            exit 1
        fi
    done
    
    # If backups are enabled, check for vzdump
    if [ "$CREATE_BACKUPS" = true ]; then
        if ! command -v vzdump &> /dev/null; then
            log_error "vzdump command not found. Required for backups."
            exit 1
        fi
    fi
}

# Check disk space
check_disk_space() {
    local min_space=1000000  # in KB
    local available_space
    available_space=$(df /var/lib/vz | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt "$min_space" ]; then
        log_warning "Low disk space detected: $(($available_space/1024))MB available"
        return 1
    fi
    return 0
}

# Check container tools
check_container_tools() {
    local container_id="$1"
    local name=$(pct config "$container_id" | grep -w "hostname" | cut -d' ' -f2)
    
    if lxc-attach -n "$container_id" -- which apt-get >/dev/null 2>&1; then
        if [ "$VERBOSE" = true ]; then
            log_detailed "Container $container_id is Ubuntu/Debian based"
        fi
        
        if pct exec "$container_id" -- ping -c 1 -W 5 1.1.1.1 >/dev/null 2>&1; then
            if [ "$VERBOSE" = true ]; then
                log_detailed "Container $container_id has network connectivity"
            fi
            return 0
        else
            log_warning "Container $container_id ($name) has network issues"
            if [ "$VERBOSE" = true ]; then
                log_detailed "Network diagnostic for container $container_id:"
                pct exec "$container_id" -- ping -c 1 -W 5 1.1.1.1 2>&1 || true
            fi
            return 1
        fi
    else
        log_warning "Container $container_id may not be a Debian/Ubuntu based system"
        return 1
    fi
}

# Backup container
backup_container() {
    local container_id="$1"
    local backup_dir="/var/lib/vz/dump"
    local backup_name="ct-${container_id}-$(date +%Y%m%d)"
    
    log_message "Creating backup of container $container_id"
    
    # Check backup directory
    if [ ! -d "$backup_dir" ]; then
        mkdir -p "$backup_dir"
    fi
    
    # Check disk space before backup
    local available_space
    available_space=$(df -k "$backup_dir" | awk 'NR==2 {print $4}')
    local required_space=5242880  # 5GB in KB
    
    if [ "$available_space" -lt "$required_space" ]; then
        log_warning "Insufficient disk space for backup of container $container_id"
        return 1
    fi
    
    # Attempt backup with error handling
    if vzdump "$container_id" --compress gzip --dumpdir "$backup_dir" > /dev/null 2>&1; then
        log_success "Backup created for container $container_id"
        return 0
    else
        log_error "Backup failed for container $container_id"
        return 1
    fi
}

# Check container network
check_container_network() {
    local container_id="$1"
    log_message "Running network diagnostics for container $container_id"
    
    # Check DNS configuration
    log_detailed "DNS Configuration:"
    if ! pct exec "$container_id" -- cat /etc/resolv.conf >> "$DETAILED_LOG" 2>&1; then
        log_warning "Cannot read resolv.conf in container $container_id"
    fi
    
    # Check IP configuration
    log_detailed "IP Configuration:"
    if ! pct exec "$container_id" -- ip addr show >> "$DETAILED_LOG" 2>&1; then
        log_warning "Cannot get IP configuration for container $container_id"
    fi
    
    # Check routing
    log_detailed "Routing Table:"
    if ! pct exec "$container_id" -- ip route >> "$DETAILED_LOG" 2>&1; then
        log_warning "Cannot get routing table for container $container_id"
    fi
    
    # Test basic connectivity
    log_detailed "Testing basic connectivity:"
    if pct exec "$container_id" -- ping -c 1 -W 5 1.1.1.1 >> "$DETAILED_LOG" 2>&1; then
        log_detailed "Container $container_id can reach 1.1.1.1"
        
        # Test DNS resolution
        if pct exec "$container_id" -- ping -c 1 -W 5 google.com >> "$DETAILED_LOG" 2>&1; then
            log_detailed "Container $container_id has working DNS resolution"
            return 0
        else
            log_warning "Container $container_id has network but DNS resolution failed"
            # Try to fix DNS
            pct exec "$container_id" -- bash -c '
                echo "nameserver 8.8.8.8" > /etc/resolv.conf
                echo "nameserver 1.1.1.1" >> /etc/resolv.conf
            '
        fi
    else
        log_warning "Container $container_id cannot reach 1.1.1.1"
    fi
    
    # Check if package manager can reach repositories
    log_detailed "Testing package manager:"
    if pct exec "$container_id" -- apt-get update -qq >> "$DETAILED_LOG" 2>&1; then
        log_detailed "Package manager in container $container_id can reach repositories"
        return 0
    else
        log_warning "Package manager in container $container_id cannot reach repositories"
    fi
    
    return 1
}

# Check container status
check_container_status() {
    local container_id="$1"
    local container_name
    
    # Check if container is running
    if ! pct status "$container_id" | grep -q "running"; then
        log_detailed "Container $container_id is not running - skipping"
        CONTAINER_STATUS["$container_id"]="DOWN"
        SKIPPED_CONTAINERS+=("CT$container_id")
        return 1
    fi

    container_name=$(pct config "$container_id" | grep -w "hostname" | cut -d' ' -f2)
    
    # Check DNS configuration
    if [ "$VERBOSE" = true ]; then
        log_detailed "Checking DNS configuration for container $container_id"
        pct exec "$container_id" -- cat /etc/resolv.conf >> "$DETAILED_LOG" 2>&1 || log_detailed "Could not check resolv.conf in container $container_id"
    fi

    # Get container IP
    local container_ip
    container_ip=$(pct exec "$container_id" -- ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1 || echo "N/A")
    CONTAINER_IPS["$container_id"]=$container_ip

    if [ "$container_ip" != "N/A" ]; then
        CONTAINER_STATUS["$container_id"]="UP"
        log_detailed "Container $container_id ($container_name) is up with IP: $container_ip"
        
        # Basic connectivity test
        if pct exec "$container_id" -- ping -c 1 -W 5 1.1.1.1 >/dev/null 2>&1; then
            log_detailed "Container $container_id has network connectivity"
            
            # DNS resolution test
            if pct exec "$container_id" -- ping -c 1 -W 5 google.com >/dev/null 2>&1; then
                log_detailed "Container $container_id has working DNS resolution"
                
                # Test package management (only if we need to run updates)
                if [ "$RUN_UPDATES" = true ]; then
                    if pct exec "$container_id" -- apt-get update -qq >/dev/null 2>&1; then
                        log_detailed "Container $container_id has working package management"
                        return 0
                    else
                        log_warning "Container $container_id has network but package management failed"
                        if [ "$VERBOSE" = true ]; then
                            check_container_network "$container_id"
                        fi
                        # If we're only doing virus scanning, still return success
                        if [ "$RUN_UPDATES" = false ] && [ "$RUN_VIRUS_SCAN" = true ]; then
                            return 0
                        fi
                        return 1
                    fi
                else
                    # We don't need package management for virus scanning only
                    return 0
                fi
            else
                log_warning "Container $container_id has network but DNS is not working"
                # Try to fix DNS
                pct exec "$container_id" -- bash -c '
                    echo "nameserver 8.8.8.8" > /etc/resolv.conf
                    echo "nameserver 1.1.1.1" >> /etc/resolv.conf
                '
                # Verify DNS fix
                if pct exec "$container_id" -- ping -c 1 -W 5 google.com >/dev/null 2>&1; then
                    log_detailed "DNS fixed for container $container_id"
                    return 0
                else
                    if [ "$VERBOSE" = true ]; then
                        check_container_network "$container_id"
                    fi
                    # If we're only doing virus scanning, still return success
                    if [ "$RUN_UPDATES" = false ] && [ "$RUN_VIRUS_SCAN" = true ]; then
                        return 0
                    fi
                fi
            fi
        else
            log_warning "Container $container_id cannot reach 1.1.1.1"
            if [ "$VERBOSE" = true ]; then
                check_container_network "$container_id"
            fi
        fi
    fi

    # If we're only doing virus scanning, we don't need network connectivity
    if [ "$RUN_UPDATES" = false ] && [ "$RUN_VIRUS_SCAN" = true ]; then
        return 0
    fi

    CONTAINER_STATUS["$container_id"]="DOWN"
    NETWORK_ISSUES+=("CT$container_id")
    log_detailed "Container $container_id ($container_name) has network issues"
    return 1
}

# Cleanup function
cleanup() {
    local days_to_keep=7
    find "$LOG_DIR" -type f -name "maintenance_*.log" -mtime +"$days_to_keep" -delete 2>/dev/null
    find "$LOG_DIR" -type f -name "maintenance_*_detailed.log" -mtime +"$days_to_keep" -delete 2>/dev/null
    find "$LOG_DIR" -type f -name "maintenance_*_summary.txt" -mtime +"$days_to_keep" -delete 2>/dev/null
}

# Update container
# Update container
update_container() {
    local container_id="$1"
    
    log_message "Updating container $container_id"
    
    # Update package lists
    if ! pct exec "$container_id" -- apt-get update >> "$DETAILED_LOG" 2>&1; then
        log_error "Failed to update package lists for container $container_id"
        return 1
    fi
    
    # Perform dist-upgrade instead of upgrade to properly handle dependencies
    if ! pct exec "$container_id" -- apt-get dist-upgrade -y >> "$DETAILED_LOG" 2>&1; then
        log_error "Failed to upgrade packages for container $container_id"
        return 1
    fi
    
    return 0
}

# Security checks
security_checks() {
    local container_id="$1"
    [ "$VERBOSE" = true ] && log_message "Running security checks for container $container_id"
    
    # Check if auth.log exists before trying to read it
    if pct exec "$container_id" -- test -f /var/log/auth.log; then
        local failed_logins
        failed_logins=$(pct exec "$container_id" -- grep 'Failed password' /var/log/auth.log 2>/dev/null | wc -l || echo "0")
        if [ "$failed_logins" -gt 10 ]; then
            log_warning "High number of failed login attempts ($failed_logins) in container $container_id"
        fi
    else
        log_detailed "No auth.log found in container $container_id"
    fi
    
    [ "$VERBOSE" = true ] && log_message "Checking running services in container $container_id"
    pct exec "$container_id" -- ss -tulpn >> "$DETAILED_LOG" 2>&1 || log_detailed "Could not check services in container $container_id"
    
    # Check for security updates without requiring syslog
    local security_updates
    security_updates=$(pct exec "$container_id" -- apt-get -s upgrade | grep -i security) || true
    if [ -n "$security_updates" ]; then
        log_warning "Security updates available for container $container_id"
        echo "$security_updates" >> "$DETAILED_LOG"
    fi
}

# Update host system
update_host_system() {
    log_message "Updating host system"
    if ! pveupgrade >> "$DETAILED_LOG" 2>&1; then
        log_error "Host system update failed"
        return 1
    fi
    
    # Check if reboot is needed
    if [ -f /var/run/reboot-required ]; then
        log_warning "System reboot is required after updates"
    fi
    
    log_success "Host system update completed"
    return 0
}

# Setup ClamAV
setup_clamav() {
    if [ "$RUN_VIRUS_SCAN" = true ]; then
        log_message "Setting up ClamAV..."
        
        # Check if ClamAV is installed
        if ! command -v clamdscan &> /dev/null; then
            log_message "Installing ClamAV..."
            apt-get update >> "$DETAILED_LOG" 2>&1
            apt-get install -y clamav clamav-daemon >> "$DETAILED_LOG" 2>&1
        fi
        
        # Update virus definitions if older than 1 day
        if [ ! -f "/var/lib/clamav/daily.cvd" ] || [ $(find /var/lib/clamav/daily.cvd -mtime +1 -print | wc -l) -ne 0 ]; then
            log_message "Updating ClamAV virus definitions..."
            systemctl stop clamav-freshclam >> "$DETAILED_LOG" 2>&1
            freshclam >> "$DETAILED_LOG" 2>&1
            systemctl start clamav-freshclam >> "$DETAILED_LOG" 2>&1
        fi
        
        # Make sure the daemon is running
        if ! systemctl is-active --quiet clamav-daemon; then
            log_message "Starting ClamAV daemon..."
            systemctl restart clamav-daemon >> "$DETAILED_LOG" 2>&1
        fi
        
        # Verify daemon status
        if systemctl is-active --quiet clamav-daemon; then
            log_success "ClamAV setup completed"
            return 0
        else
            log_error "Failed to start ClamAV daemon"
            return 1
        fi
    fi
    return 0
}

# Run virus scan
run_virus_scan() {
    local container_id="$1"
    local container_name=$(pct config "$container_id" | grep -w "hostname" | cut -d' ' -f2)
    local temp_mount="/tmp/clamscan_${container_id}_$(date +%s)"
    
    log_message "Running virus scan for container $container_id ($container_name)"
    
    # Create temporary mount point
    mkdir -p "$temp_mount"
    
    # Determine the container's root filesystem location
    local rootfs_path
    if [ -d "/var/lib/lxc/$container_id/rootfs" ]; then
        # Direct LXC path
        rootfs_path="/var/lib/lxc/$container_id/rootfs"
    elif [ -d "/var/lib/vz/root/$container_id" ]; then
        # Proxmox VE path
        rootfs_path="/var/lib/vz/root/$container_id"
    else
        log_error "Cannot locate root filesystem for container $container_id"
        rmdir "$temp_mount"
        return 1
    fi
    
    # Mount the container's filesystem (read-only for security)
    if ! mount -o bind,ro "$rootfs_path" "$temp_mount"; then
        log_error "Failed to mount container $container_id filesystem"
        rmdir "$temp_mount"
        return 1
    fi
    
    log_message "Scanning container $container_id for viruses..."
    
    # Create a specific log file for this container's scan
    local container_scan_log="${DETAILED_LOG}.${container_id}.scan"
    
    # Perform the scan
    local scan_status=0
    if clamdscan --fdpass "$temp_mount" > "$container_scan_log" 2>&1; then
        log_success "Virus scan completed successfully for container $container_id"
    else
        local exit_code=$?
        if [ $exit_code -eq 1 ]; then
            log_warning "Viruses found in container $container_id!"
            scan_status=1
        else
            log_error "Scan error for container $container_id (exit code: $exit_code)"
            scan_status=2
        fi
    fi
    
    # Extract and log scan statistics
    local infected=$(grep "Infected files:" "$container_scan_log" | tail -1 | awk '{print $3}')
    local scanned=$(grep "Scanned files:" "$container_scan_log" | tail -1 | awk '{print $3}')
    
    # Append container results to the main detailed log
    {
        echo "================================================================"
        echo "=== Container $container_id ($container_name) Virus Scan Details ==="
        echo "================================================================"
        echo "Timestamp: $(date)"
        echo "Files scanned: $scanned"
        echo "Infected files: $infected"
        
        # Add specific infection details if any were found
        if [ "$infected" != "0" ]; then
            echo "--- Infection Details ---"
            grep "FOUND" "$container_scan_log"
            echo "-----------------------"
            INFECTED_CONTAINERS+=("CT$container_id")
        fi
        
        echo "" # Empty line for better readability
    } >> "$DETAILED_LOG"
    
    # Store scan result for summary
    CONTAINER_SCAN_RESULTS["$container_id"]=$infected
    
    # Always cleanup the mount
    umount "$temp_mount"
    rmdir "$temp_mount"
    rm -f "$container_scan_log"
    
    if [ "$infected" != "0" ]; then
        log_warning "Found $infected infected files in container $container_id"
    else
        log_success "No viruses found in container $container_id"
    fi
    
    return $scan_status
}

# Generate summary
generate_summary() {
    # Write summary to file
    {
        echo "=== Maintenance and Security Summary ==="
        echo "Timestamp: $(date)"
        echo "Total Containers: $TOTAL_CONTAINERS"
        
        if [ "$RUN_UPDATES" = true ]; then
            echo "Successfully Updated: ${#UPDATED_CONTAINERS[@]}"
            echo "Failed Updates: ${#FAILED_CONTAINERS[@]}"
        fi
        
        echo "Skipped Containers: ${#SKIPPED_CONTAINERS[@]}"
        echo "Network Issues: ${#NETWORK_ISSUES[@]}"
        
        if [ "$RUN_VIRUS_SCAN" = true ]; then
            echo "Infected Containers: ${#INFECTED_CONTAINERS[@]}"
        fi
        
        if [ "$RUN_UPDATES" = true ] && [ ${#UPDATED_CONTAINERS[@]} -gt 0 ]; then
            echo -e "\nSuccessfully Updated Containers:"
            printf '%s\n' "${UPDATED_CONTAINERS[@]}"
        fi
        
        if [ "$RUN_UPDATES" = true ] && [ ${#FAILED_CONTAINERS[@]} -gt 0 ]; then
            echo -e "\nFailed Containers:"
            printf '%s\n' "${FAILED_CONTAINERS[@]}"
        fi
        
        if [ ${#SKIPPED_CONTAINERS[@]} -gt 0 ]; then
            echo -e "\nSkipped Containers:"
            printf '%s\n' "${SKIPPED_CONTAINERS[@]}"
        fi
        
        if [ ${#NETWORK_ISSUES[@]} -gt 0 ]; then
            echo -e "\nContainers with Network Issues:"
            printf '%s\n' "${NETWORK_ISSUES[@]}"
        fi
        
        if [ "$RUN_VIRUS_SCAN" = true ] && [ ${#INFECTED_CONTAINERS[@]} -gt 0 ]; then
            echo -e "\nContainers with Infections:"
            printf '%s\n' "${INFECTED_CONTAINERS[@]}"
        fi
        
        echo -e "\nDetailed logs available at: $DETAILED_LOG"
    } > "$SUMMARY_FILE" 2>&1

    # Display the summary on the console too
    cat "$SUMMARY_FILE"

    # Send summary to Discord if enabled
    if [ "$DISCORD_NOTIFICATION" = true ]; then
        send_discord_notification "$(cat "$SUMMARY_FILE")"
    fi
    
    # Send email report if configured
    if [ -n "$EMAIL_RECIPIENT" ]; then
        send_email_report
    fi
}

# Main execution function
main() {
    check_root
    check_requirements
    
    # Initialize logs
    echo "=== Proxmox Container Security and Maintenance - $(date) ===" > "$LOG_FILE"
    echo "=== Detailed Log - $(date) ===" > "$DETAILED_LOG"
    
    # Setup ClamAV if virus scanning is enabled
    if [ "$RUN_VIRUS_SCAN" = true ]; then
        setup_clamav
    fi
    
    # Update host system if doing full maintenance
    if [ "$FULL_MAINTENANCE" = true ] || [ "$RUN_UPDATES" = true ]; then
        update_host_system
    fi
    
    # Get list of RUNNING containers only
    local containers
    mapfile -t containers < <(pct list | grep "running" | awk '{print $1}')
    TOTAL_CONTAINERS=${#containers[@]}
    
    if [ $TOTAL_CONTAINERS -eq 0 ]; then
        log_message "No running containers found"
        generate_summary
        cleanup
        exit 0
    fi
    
    # Process each container
    for container_id in "${containers[@]}"; do
        ((CURRENT_CONTAINER++))
        progress "Processing container $container_id ($CURRENT_CONTAINER of $TOTAL_CONTAINERS)"
        
        # Check container status
        if ! check_container_status "$container_id"; then
            if [ "$VERBOSE" = true ]; then
                log_message "Running network diagnostics for container $container_id"
                check_container_network "$container_id" >> "$DETAILED_LOG" 2>&1
            fi
            # For virus scan only, we proceed even if network check fails
            if [ "$RUN_UPDATES" = true ] && [ "$RUN_VIRUS_SCAN" = false ]; then
                continue
            fi
        fi
        
        # Create backup if enabled
        if [ "$CREATE_BACKUPS" = true ]; then
            backup_container "$container_id"
        fi
        
        # Run updates if enabled
        if [ "$RUN_UPDATES" = true ]; then
            if ! check_container_tools "$container_id"; then
                if [ "$VERBOSE" = true ]; then
                    log_message "Container tools check failed, running diagnostics for container $container_id"
                    check_container_network "$container_id" >> "$DETAILED_LOG" 2>&1
                fi
                FAILED_CONTAINERS+=("CT$container_id")
                # Still proceed with virus scan if that's enabled
                if [ "$RUN_VIRUS_SCAN" = false ]; then
                    continue
                fi
            else
                if update_container "$container_id"; then
                    UPDATED_CONTAINERS+=("CT$container_id")
                else
                    FAILED_CONTAINERS+=("CT$container_id")
                    if [ "$VERBOSE" = true ]; then
                        log_message "Update failed, running diagnostics for container $container_id"
                        check_container_network "$container_id" >> "$DETAILED_LOG" 2>&1
                    fi
                fi
            fi
        fi
        
        # Run security checks if enabled
        if [ "$RUN_SECURITY" = true ]; then
            security_checks "$container_id"
        fi
        
        # Run virus scan if enabled
        if [ "$RUN_VIRUS_SCAN" = true ]; then
            run_virus_scan "$container_id"
        fi
    done
    
    # Generate and display summary
    generate_summary
    
    # Cleanup old logs
    cleanup
    
    log_message "Maintenance and security check completed"
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -f|--full)
                FULL_MAINTENANCE=true
                RUN_SECURITY=true
                RUN_VIRUS_SCAN=true
                RUN_UPDATES=true
                shift
                ;;
            -b|--backup)
                CREATE_BACKUPS=true
                shift
                ;;
            -u|--update-only)
                FULL_MAINTENANCE=false
                RUN_SECURITY=false
                RUN_VIRUS_SCAN=false
                RUN_UPDATES=true
                shift
                ;;
            -s|--security-only)
                FULL_MAINTENANCE=false
                RUN_SECURITY=true
                RUN_VIRUS_SCAN=true
                RUN_UPDATES=false
                shift
                ;;
            -vs|--virus-scan-only)
                FULL_MAINTENANCE=false
                RUN_SECURITY=false
                RUN_VIRUS_SCAN=true
                RUN_UPDATES=false
                shift
                ;;
            -d|--discord)
                DISCORD_NOTIFICATION=true
                shift
                ;;
            -e|--email)
                if [[ $# -gt 1 && ! $2 =~ ^- ]]; then
                    EMAIL_RECIPIENT="$2"
                    shift 2
                else
                    log_error "Email address required for -e|--email option"
                    exit 1
                fi
                ;;
            -h|--help)
                echo "Proxmox Container Security and Maintenance Script v$VERSION"
                echo ""
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  -v, --verbose         Enable verbose output"
                echo "  -f, --full            Run full maintenance (updates, security, virus scan)"
                echo "  -b, --backup          Create backups before making changes"
                echo "  -u, --update-only     Run only system updates"
                echo "  -s, --security-only   Run only security checks and virus scan"
                echo "  -vs, --virus-scan-only Run only virus scan"
                echo "  -d, --discord         Enable Discord notifications"
                echo "  -e, --email EMAIL     Send email report to specified address"
                echo "  -h, --help            Display this help message"
                echo ""
                echo "If no options are provided, the script runs in interactive mode."
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use -h or --help to see available options."
                exit 1
                ;;
        esac
    done
}

# Script entry point
if [ $# -eq 0 ]; then
    # No arguments, run in interactive mode
    check_root
    setup_script
else
    # Parse command line arguments
    parse_args "$@"
    # Check root after arg parsing to allow help to work for non-root users
    check_root
    get_discord_webhook
fi

# Run the main function
main
exit_code=$?

exit $exit_code
