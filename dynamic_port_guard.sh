#!/bin/bash

# === CONFIG FILE ===
CONFIG_FILE="/etc/dynamic-port-guard.conf"

# === DEFAULTS (if config file not found) ===
DEFAULT_WHITELIST="tcp:22 tcp:80 tcp:443"
DEFAULT_CHECK_INTERVAL=10
DEFAULT_FIREWALL_TOOL="iptables"
DEFAULT_LOG_FILE="/var/log/dynamic_ports.log"
DEFAULT_IPTABLES_CHAIN="PORTGUARD_ALLOW"

# === LOAD CONFIG ===
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
    # Convert space-separated WHITELIST string to array
    WHITELIST_ARRAY=($WHITELIST)
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: Config file '$CONFIG_FILE' not found. Using defaults." | tee -a "${LOG_FILE:-$DEFAULT_LOG_FILE}"
    WHITELIST_ARRAY=($DEFAULT_WHITELIST)
    CHECK_INTERVAL="${DEFAULT_CHECK_INTERVAL}"
    FIREWALL_TOOL="${DEFAULT_FIREWALL_TOOL}"
    LOG_FILE="${DEFAULT_LOG_FILE}"
    IPTABLES_CHAIN="${DEFAULT_IPTABLES_CHAIN}"
fi

# Ensure log file exists and is writable
touch "$LOG_FILE" || {
    echo "ERROR: Cannot write to log file $LOG_FILE. Exiting." >&2
    exit 1
}
chmod 640 "$LOG_FILE" # Restrict permissions slightly

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# === FIREWALL FUNCTIONS ===

# Function to set up the firewall (create chain, jump rule)
setup_firewall() {
    log "Setting up firewall using $FIREWALL_TOOL..."
    case "$FIREWALL_TOOL" in
    iptables)
        # IPv4
        iptables -N "$IPTABLES_CHAIN" 2>/dev/null || iptables -F "$IPTABLES_CHAIN"
        iptables -C INPUT -j "$IPTABLES_CHAIN" 2>/dev/null || iptables -I INPUT 1 -j "$IPTABLES_CHAIN"
        # IPv6
        ip6tables -N "$IPTABLES_CHAIN" 2>/dev/null || ip6tables -F "$IPTABLES_CHAIN"
        ip6tables -C INPUT -j "$IPTABLES_CHAIN" 2>/dev/null || ip6tables -I INPUT 1 -j "$IPTABLES_CHAIN"
        log "iptables/ip6tables chain '$IPTABLES_CHAIN' ensured and jump rule added to INPUT."
        ;;
    ufw)
        log "WARNING: UFW support is not fully implemented. Manual setup might be required."
        # UFW interaction is complex; might need specific `ufw route` rules or direct manipulation
        # of UFW's underlying chains (e.g., ufw-user-input) which is fragile.
        ;;
    nftables)
        log "WARNING: nftables support is not fully implemented. Manual setup might be required."
        # Example (requires 'inet firewall' table):
        # nft list table inet firewall > /dev/null 2>&1 || nft add table inet firewall
        # nft list chain inet firewall $IPTABLES_CHAIN > /dev/null 2>&1 || nft add chain inet firewall $IPTABLES_CHAIN { type filter hook input priority 0 \; }
        # nft flush chain inet firewall $IPTABLES_CHAIN
        ;;
    *)
        log "ERROR: Unsupported FIREWALL_TOOL '$FIREWALL_TOOL'."
        exit 1
        ;;
    esac
}

# Function to apply rules based on active ports
apply_rules() {
    local active_ports_list=("$@") # Receive array elements as arguments
    local allowed_count=0

    case "$FIREWALL_TOOL" in
    iptables)
        # Flush existing rules in our chain first
        iptables -F "$IPTABLES_CHAIN"
        ip6tables -F "$IPTABLES_CHAIN"

        for entry in "${active_ports_list[@]}"; do
            IFS=':' read -r proto port <<<"$entry"
            if [[ -n "$proto" && -n "$port" ]]; then
                # Add rule for IPv4 and IPv6
                iptables -A "$IPTABLES_CHAIN" -p "$proto" --dport "$port" -j ACCEPT
                ip6tables -A "$IPTABLES_CHAIN" -p "$proto" --dport "$port" -j ACCEPT
                ((allowed_count++))
            else
                log "Skipping invalid entry: $entry"
            fi
        done
        log "Applied $allowed_count ACCEPT rules to $IPTABLES_CHAIN chain."
        ;;
    ufw)
        # This would require a different logic, maybe tracking added rules
        # or completely managing UFW state which is complex.
        log "Skipping rule application: UFW support not implemented."
        ;;
    nftables)
        # Example: Flush and re-add rules
        # nft flush chain inet firewall $IPTABLES_CHAIN
        # for entry in "${active_ports_list[@]}"; do
        #    IFS=':' read -r proto port <<< "$entry"
        #    nft add rule inet firewall $IPTABLES_CHAIN $proto dport $port accept
        # done
        log "Skipping rule application: nftables support not implemented."
        ;;
    esac
}

# Function to clean up firewall rules on exit
cleanup() {
    log "Shutdown signal received. Cleaning up firewall rules..."
    case "$FIREWALL_TOOL" in
    iptables)
        # Remove jump rule
        iptables -D INPUT -j "$IPTABLES_CHAIN" 2>/dev/null || true
        ip6tables -D INPUT -j "$IPTABLES_CHAIN" 2>/dev/null || true
        # Flush our chain
        iptables -F "$IPTABLES_CHAIN" 2>/dev/null || true
        ip6tables -F "$IPTABLES_CHAIN" 2>/dev/null || true
        # Delete our chain (optional, might leave it empty)
        iptables -X "$IPTABLES_CHAIN" 2>/dev/null || true
        ip6tables -X "$IPTABLES_CHAIN" 2>/dev/null || true
        log "iptables/ip6tables jump rules removed, chain '$IPTABLES_CHAIN' flushed and deleted."
        ;;
    ufw)
        log "Cleanup skipped: UFW support not implemented."
        ;;
    nftables)
        # Example: Remove rules or the chain
        # nft flush chain inet firewall $IPTABLES_CHAIN
        # nft delete chain inet firewall $IPTABLES_CHAIN
        log "Cleanup skipped: nftables support not implemented."
        ;;

    esac
    log "Dynamic Port Guard stopped."
    exit 0
}

# Trap signals for cleanup
trap cleanup SIGTERM SIGINT

# === MAIN LOOP ===

log "Dynamic Port Guard started."
setup_firewall

while true; do
    # Get currently listening TCP and UDP ports (IPv4 and IPv6)
    # Format: tcp:port or udp:port
    # Using awk for more robust parsing, handles *:port and specific_ip:port
    current_ports=$(ss -tunlp | awk '
        /LISTEN/ {
            # Extract protocol (tcp/udp)
            proto = $1
            sub(/^tcp6?$/, "tcp", proto);
            sub(/^udp6?$/, "udp", proto);

            # Extract port from Local Address:Port column ($5 for ss)
            # Works for ::%iface:port, 0.0.0.0:port, specific_ip:port etc.
            split($5, addr_port, ":");
            port = addr_port[length(addr_port)];

            # Check if port is numeric
            if (port ~ /^[0-9]+$/) {
                print proto ":" port;
            }
        }')

    # Combine listening ports and whitelist, then sort and unique
    mapfile -t combined_ports < <(echo "$current_ports" && printf "%s\n" "${WHITELIST_ARRAY[@]}" | sort -u)

    # Apply firewall rules for the combined list
    apply_rules "${combined_ports[@]}" # Pass array elements as separate arguments

    # Wait for the next check
    sleep "$CHECK_INTERVAL"
done
