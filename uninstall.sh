#!/bin/bash

set -e # Exit on error

# --- Configuration ---
CORE_SERVICE_NAME="dynamic-port-guard"
CORE_BIN_PATH="/usr/local/bin/dynamic_port_guard.sh"
CORE_SERVICE_FILE="/etc/systemd/system/${CORE_SERVICE_NAME}.service"
CORE_CONFIG_FILE="/etc/dynamic-port-guard.conf"

WEBUI_SERVICE_NAME="dynamic-port-webui"
WEBUI_APP_DIR="/opt/${WEBUI_SERVICE_NAME}"
WEBUI_SERVICE_FILE="/etc/systemd/system/${WEBUI_SERVICE_NAME}.service"

REMOVE_CORE=true
REMOVE_WEBUI=true
REMOVE_CONFIG=false # Ask user about config

# --- Helper Functions ---
log_info() { echo "[*] $1"; }
log_success() { echo "[✓] $1"; }
log_error() { echo "[!] $Error: $1" >&2; }

# --- Argument Parsing ---
while [[ "$#" -gt 0 ]]; do
    case $1 in
    --core-only) REMOVE_WEBUI=false ;;
    --webui-only) REMOVE_CORE=false ;;
    --remove-config) REMOVE_CONFIG=true ;; # Flag to force config removal
    *)
        log_error "Unknown parameter passed: $1"
        exit 1
        ;;
    esac
    shift
done

# --- Root Check ---
if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root. Use sudo."
    exit 1
fi

# --- Core Service Uninstallation ---
if $REMOVE_CORE; then
    log_info "Uninstalling Dynamic Port Guard Core Service..."

    # 1. Stop and disable service
    log_info "Stopping and disabling ${CORE_SERVICE_NAME} service..."
    systemctl stop "$CORE_SERVICE_NAME" || true    # Ignore error if not running
    systemctl disable "$CORE_SERVICE_NAME" || true # Ignore error if not enabled

    # 2. Remove files
    log_info "Removing script: ${CORE_BIN_PATH}"
    rm -f "$CORE_BIN_PATH"
    log_info "Removing service file: ${CORE_SERVICE_FILE}"
    rm -f "$CORE_SERVICE_FILE"

    # 3. Handle config file
    if [ -f "$CORE_CONFIG_FILE" ]; then
        if $REMOVE_CONFIG; then
            log_info "Removing configuration file: ${CORE_CONFIG_FILE}"
            rm -f "$CORE_CONFIG_FILE"
        else
            read -p "Do you want to remove the configuration file ${CORE_CONFIG_FILE}? [y/N] " -r REPLY
            echo # Move to new line
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                log_info "Removing configuration file: ${CORE_CONFIG_FILE}"
                rm -f "$CORE_CONFIG_FILE"
            else
                log_info "Keeping configuration file: ${CORE_CONFIG_FILE}"
            fi
        fi
    fi

    # 4. Run firewall cleanup manually (optional, systemd stop should trigger trap)
    # log_info "Attempting to run firewall cleanup (best effort)..."
    # if [ -f "$CORE_BIN_PATH" ]; then # If script was somehow kept, try running its cleanup
    #    "$CORE_BIN_PATH" cleanup # This needs the script to handle a 'cleanup' argument
    # else # Manually remove chain if script is gone (assuming iptables and default name)
    #    log_info "Running manual iptables cleanup for chain PORTGUARD_ALLOW..."
    #    CHAIN_NAME=$(grep -Po 'IPTABLES_CHAIN="\K[^"]+' "$CORE_CONFIG_FILE" 2>/dev/null || echo "PORTGUARD_ALLOW")
    #    iptables -D INPUT -j "$CHAIN_NAME" 2>/dev/null || true
    #    ip6tables -D INPUT -j "$CHAIN_NAME" 2>/dev/null || true
    #    iptables -F "$CHAIN_NAME" 2>/dev/null || true
    #    ip6tables -F "$CHAIN_NAME" 2>/dev/null || true
    #    iptables -X "$CHAIN_NAME" 2>/dev/null || true
    #    ip6tables -X "$CHAIN_NAME" 2>/dev/null || true
    # fi

    log_success "Dynamic Port Guard Core Service uninstalled."
fi

# --- Web UI Uninstallation ---
if $REMOVE_WEBUI; then
    log_info "Uninstalling Dynamic Port Guard Web UI..."

    # 1. Stop and disable service
    log_info "Stopping and disabling ${WEBUI_SERVICE_NAME} service..."
    systemctl stop "$WEBUI_SERVICE_NAME" || true
    systemctl disable "$WEBUI_SERVICE_NAME" || true

    # 2. Remove files
    log_info "Removing application directory: ${WEBUI_APP_DIR}"
    #     + # This removes the app code AND the venv directory inside it
    rm -rf "$WEBUI_APP_DIR"
    log_info "Removing service file: ${WEBUI_SERVICE_FILE}"
    rm -f "$WEBUI_SERVICE_FILE"

    # 3. Optional: Remove dependencies (tricky, might be used by others)
    # log_info "Note: Python dependencies (Flask) are not automatically removed."
    # log_info "You can remove them manually if desired (e.g., 'sudo apt-get remove python3-flask')."

    log_success "Dynamic Port Guard Web UI uninstalled."
fi

# --- Final Steps ---
log_info "Reloading systemd daemon..."
systemctl daemon-reload

log_success "Uninstallation finished."
