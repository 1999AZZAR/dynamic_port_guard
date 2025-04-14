#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.
# set -x # Uncomment for detailed debugging

# --- Determine Script Directory ---
# This allows running the script from anywhere, assuming source files are relative to it
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
log_info() { echo "[*] $1"; }
log_success() { echo "[✓] $1"; }
log_error() { echo "[!] Error: $1" >&2; }

# --- Configuration ---
CORE_SERVICE_NAME="dynamic-port-guard"
CORE_SCRIPT_SOURCE_NAME="dynamic_port_guard.sh" # Source file name relative to SCRIPT_DIR
CORE_SCRIPT_DEST_NAME="dynamic_port_guard.sh"   # Destination name (can be same)
CORE_BIN_PATH="/usr/local/bin/${CORE_SCRIPT_DEST_NAME}"
CORE_SERVICE_FILE="/etc/systemd/system/${CORE_SERVICE_NAME}.service"
CORE_CONFIG_FILE="/etc/dynamic-port-guard.conf"
CORE_CONFIG_SOURCE_NAME="dynamic-port-guard.conf.example" # Source file name relative to SCRIPT_DIR
DEFAULT_LOG_FILE="/var/log/dynamic_ports.log"             # Default log path used by service/script

WEBUI_SERVICE_NAME="dynamic-port-webui"
WEBUI_APP_DIR="/opt/${WEBUI_SERVICE_NAME}"
WEBUI_SERVICE_FILE="/etc/systemd/system/${WEBUI_SERVICE_NAME}.service"
WEBUI_SOURCE_DIR_NAME="webui" # Source directory name relative to SCRIPT_DIR
WEBUI_VENV_PATH="${WEBUI_APP_DIR}/venv"

INSTALL_CORE=true
INSTALL_WEBUI=true

# --- Argument Parsing ---
while [[ "$#" -gt 0 ]]; do
    case $1 in
    --core-only)
        INSTALL_WEBUI=false
        log_info "Option: Installing Core Service only."
        ;;
    --webui-only)
        INSTALL_CORE=false
        log_info "Option: Installing Web UI only."
        ;;
    *)
        log_error "Unknown parameter passed: $1"
        exit 1
        ;;
    esac
    shift
done

# --- Root Check ---
if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root. Use sudo ./install.sh"
    exit 1
fi

# --- Prerequisite Check Function ---
check_command() {
    if ! command -v "$1" &>/dev/null; then
        log_error "Required command '$1' not found. Please install it."
        exit 1
    fi
}

# --- Core Service Installation ---
if $INSTALL_CORE; then
    log_info "--- Installing Dynamic Port Guard Core Service ---"

    CORE_SCRIPT_SOURCE_PATH="${SCRIPT_DIR}/${CORE_SCRIPT_SOURCE_NAME}"
    CORE_CONFIG_SOURCE_PATH="${SCRIPT_DIR}/${CORE_CONFIG_SOURCE_NAME}"

    if [ ! -f "$CORE_SCRIPT_SOURCE_PATH" ]; then
        log_error "Core script '$CORE_SCRIPT_SOURCE_NAME' not found in script directory ($SCRIPT_DIR)."
        exit 1
    fi

    log_info "Copying script to ${CORE_BIN_PATH}"
    install -m 755 "$CORE_SCRIPT_SOURCE_PATH" "$CORE_BIN_PATH" # install sets permissions

    log_info "Checking configuration file ${CORE_CONFIG_FILE}"
    if [ ! -f "$CORE_CONFIG_FILE" ]; then
        if [ -f "$CORE_CONFIG_SOURCE_PATH" ]; then
            log_info "Creating default configuration file from ${CORE_CONFIG_SOURCE_NAME}."
            install -m 644 "$CORE_CONFIG_SOURCE_PATH" "$CORE_CONFIG_FILE" # root:root 644
        else
            log_info "Warning: Example config file '$CORE_CONFIG_SOURCE_NAME' not found. Service will use internal defaults, which might not be suitable."
        fi
    else
        log_info "Configuration file ${CORE_CONFIG_FILE} already exists. Not overwriting."
    fi

    # Ensure default log file exists and has appropriate permissions (readable by root/adm)
    log_info "Ensuring default log file exists: ${DEFAULT_LOG_FILE}"
    # Ensure log directory exists before touching the file
    log_dir=$(dirname "$DEFAULT_LOG_FILE")
    if [ ! -d "$log_dir" ]; then
        mkdir -p "$log_dir"
        # Set permissions on the new directory if needed (e.g., 750 root:adm)
        chown root:adm "$log_dir" || chown root:root "$log_dir"
        chmod 750 "$log_dir"
    fi
    # Touch the file to ensure it exists
    touch "$DEFAULT_LOG_FILE"
    # Set ownership, prefer adm group for logs if available
    chown root:adm "$DEFAULT_LOG_FILE" || chown root:root "$DEFAULT_LOG_FILE"
    # Set permissions (Owner rw, Group r, Other none)
    chmod 640 "$DEFAULT_LOG_FILE"

    log_info "Creating systemd service file ${CORE_SERVICE_FILE}"
    tee "$CORE_SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=Dynamic Firewall Port Guard Core Service
# Wait for network stack to be fully up, not just the interface
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${CORE_BIN_PATH}
Restart=always
# Wait 5 seconds before restart if it fails
RestartSec=5s
# Logs are handled by the script itself (to file), but capture errors to journal
StandardOutput=null
StandardError=journal
# Consider adding resource limits if needed
# MemoryLimit=100M
# CPUQuota=10%

[Install]
WantedBy=multi-user.target
EOF

    log_info "Reloading systemd daemon..."
    systemctl daemon-reload
    log_info "Enabling ${CORE_SERVICE_NAME} service..."
    systemctl enable "$CORE_SERVICE_NAME"
    log_info "Starting ${CORE_SERVICE_NAME} service..."
    if systemctl start "$CORE_SERVICE_NAME"; then
        log_success "Dynamic Port Guard Core Service installed and started."
    else
        log_error "Failed to start ${CORE_SERVICE_NAME} service. Check status with 'systemctl status ${CORE_SERVICE_NAME}' and logs with 'journalctl -u ${CORE_SERVICE_NAME}' or in '${DEFAULT_LOG_FILE}'."
        # Provide hints
        log_error "Hints: Check if the script ${CORE_BIN_PATH} is executable. Check permissions on ${CORE_CONFIG_FILE} and ${DEFAULT_LOG_FILE}."
    fi
    log_info "Core service status command: systemctl status ${CORE_SERVICE_NAME}"
fi

# --- Web UI Installation ---
if $INSTALL_WEBUI; then
    log_info "--- Installing Dynamic Port Guard Web UI ---"

    WEBUI_SOURCE_PATH="${SCRIPT_DIR}/${WEBUI_SOURCE_DIR_NAME}"

    # Check for source directory and essential files
    if [ ! -d "$WEBUI_SOURCE_PATH" ]; then
        log_error "Web UI source directory '$WEBUI_SOURCE_DIR_NAME' not found in script directory ($SCRIPT_DIR)."
        exit 1
    fi
    if [ ! -f "$WEBUI_SOURCE_PATH/app.py" ] ||
        [ ! -d "$WEBUI_SOURCE_PATH/templates" ] ||
        [ ! -f "$WEBUI_SOURCE_PATH/templates/index.html" ] ||
        [ ! -d "$WEBUI_SOURCE_PATH/static" ] ||
        [ ! -f "$WEBUI_SOURCE_PATH/static/css/styles.css" ]; then
        log_error "Web UI directory '$WEBUI_SOURCE_DIR_NAME' seems incomplete. Missing essential files like app.py, templates/index.html, or static/css/styles.css."
        exit 1
    fi

    # 1. Install necessary system packages (Python, Pip, Venv)
    log_info "Checking/Installing dependencies (python3, python3-pip, python3-venv)..."
    PKG_MANAGER=""
    if command -v apt-get &>/dev/null; then
        PKG_MANAGER="apt-get"
        DEPS="python3 python3-pip python3-venv"
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
        DEPS="python3 python3-pip python3-virtualenv" # May vary, check your distro
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
        DEPS="python3 python3-pip python3-virtualenv" # May vary, check your distro
    else
        log_error "Could not determine package manager (apt, dnf, yum). Please install Python 3, Pip, and Venv/Virtualenv manually."
        exit 1
    fi

    if ! $PKG_MANAGER install -y $DEPS; then
        log_error "Failed to install dependencies using $PKG_MANAGER. Please check package names for your distribution and install manually."
        exit 1
    fi
    check_command python3
    check_command pip3

    # 2. Create application directory and copy files
    log_info "Creating Web UI directory ${WEBUI_APP_DIR}"
    mkdir -p "$WEBUI_APP_DIR"
    log_info "Copying Web UI files from ${WEBUI_SOURCE_PATH} to ${WEBUI_APP_DIR}"
    # Use -a to preserve attributes, Source/. copies contents into Target
    if cp -a "$WEBUI_SOURCE_PATH/." "$WEBUI_APP_DIR/"; then
        log_info "Web UI files copied successfully."
    else
        log_error "Failed to copy Web UI files."
        exit 1
    fi

    # 3. Create the virtual environment
    log_info "Creating Python virtual environment in ${WEBUI_VENV_PATH}..."
    # Use python3 -m venv which is the standard way
    if ! python3 -m venv "$WEBUI_VENV_PATH"; then
        log_error "Failed to create virtual environment at ${WEBUI_VENV_PATH}. Check permissions and python3-venv package."
        exit 1
    fi

    # 4. Install Flask into the virtual environment
    log_info "Activating virtual environment and installing Flask..."
    # Source the activate script to use the venv's pip directly and easily
    # Running pip directly is also fine: "$WEBUI_VENV_PATH/bin/pip" install Flask
    source "$WEBUI_VENV_PATH/bin/activate"
    if pip install Flask; then
        log_info "Flask installed successfully into virtual environment."
    else
        # Deactivate venv before exiting on error
        deactivate &>/dev/null || true
        log_error "Failed to install Flask using virtual environment pip."
        log_error "Check permissions for ${WEBUI_VENV_PATH} and network connectivity."
        exit 1
    fi
    # Deactivate after installation is done
    deactivate &>/dev/null || true

    # 5. Set ownership and permissions for the Web UI directory
    log_info "Setting ownership and permissions for ${WEBUI_APP_DIR}"
    # Run service as root for simplicity, but ensure files are owned by root
    chown -R root:root "$WEBUI_APP_DIR"
    # Set directories readable/executable by owner/group, files readable by owner/group
    find "$WEBUI_APP_DIR" -type d -exec chmod 750 {} \;
    find "$WEBUI_APP_DIR" -type f -exec chmod 640 {} \;
    # Ensure the venv python is executable by root
    VENV_PYTHON_BIN="${WEBUI_VENV_PATH}/bin/python"
    if [ -f "$VENV_PYTHON_BIN" ]; then
        chmod 750 "$VENV_PYTHON_BIN" # Owner rwx, Group rx
    else
        log_error "Virtual environment python binary not found at ${VENV_PYTHON_BIN}!"
        exit 1
    fi

    # 6. Create systemd service file pointing to the venv python
    log_info "Creating systemd service file ${WEBUI_SERVICE_FILE}"
    tee "$WEBUI_SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=Dynamic Port Guard Web UI (Flask App)
# Start after networking is up and potentially after the core service (optional)
After=network-online.target ${CORE_SERVICE_NAME}.service
Wants=network-online.target

[Service]
# Running as root is necessary to:
# - Read/Write /etc/dynamic-port-guard.conf
# - Execute systemctl commands for the core service
# - Execute ss, ps, tail commands
User=root
Group=root
WorkingDirectory=${WEBUI_APP_DIR}
# Use the python from the virtual environment and provide full path to app.py
ExecStart=${VENV_PYTHON_BIN} ${WEBUI_APP_DIR}/app.py
Restart=always
RestartSec=5
# Consider redirecting stdout/stderr to journald for Flask logs
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # 7. Reload systemd, enable and start service
    log_info "Reloading systemd daemon..."
    systemctl daemon-reload
    log_info "Enabling ${WEBUI_SERVICE_NAME} service..."
    systemctl enable "$WEBUI_SERVICE_NAME"
    log_info "Starting ${WEBUI_SERVICE_NAME} service..."
    if systemctl start "$WEBUI_SERVICE_NAME"; then
        log_success "${WEBUI_SERVICE_NAME} service started."
    else
        log_error "Failed to start ${WEBUI_SERVICE_NAME} service. Check status with 'systemctl status ${WEBUI_SERVICE_NAME}' and logs with 'journalctl -u ${WEBUI_SERVICE_NAME}'."
        log_error "Hints: Check file permissions in ${WEBUI_APP_DIR}. Ensure Flask is installed in ${WEBUI_VENV_PATH}. Verify ${VENV_PYTHON_BIN} is executable."
    fi

    # --- Add Alias ---
    # Determine user who invoked sudo, default to 'whoami' if not found
    INSTALLER_USER="${SUDO_USER:-$(whoami)}"
    INSTALLER_USER_HOME=$(getent passwd "$INSTALLER_USER" | cut -d: -f6)

    if [ -n "$INSTALLER_USER_HOME" ] && [ -d "$INSTALLER_USER_HOME" ]; then
        BASHRC_PATH="${INSTALLER_USER_HOME}/.bashrc"
        ZSHRC_PATH="${INSTALLER_USER_HOME}/.zshrc" # Also check zshrc
        ALIAS_CMD="alias portguard='echo \"[*] Dynamic Port Guard Status:\"; sudo systemctl status ${CORE_SERVICE_NAME} --no-pager; echo; sudo systemctl status ${WEBUI_SERVICE_NAME} --no-pager; echo; echo \"[*] Opening Web UI (http://localhost:6060)...\"; xdg-open http://localhost:6060 &>/dev/null &'"
        ALIAS_COMMENT="# Dynamic Port Guard Alias (added by install script)"
        ALIAS_MARKER="alias portguard=" # Used to check existence

        # Function to add alias if not present
        add_alias_if_needed() {
            local rc_file="$1"
            if [ -f "$rc_file" ] && ! grep -q "$ALIAS_MARKER" "$rc_file"; then
                log_info "Adding 'portguard' alias to ${rc_file}..."
                echo "" >>"$rc_file" # Add newline for separation
                echo "$ALIAS_COMMENT" >>"$rc_file"
                echo "$ALIAS_CMD" >>"$rc_file"
                # Set ownership back to the user
                chown "${INSTALLER_USER}:${INSTALLER_USER}" "$rc_file" || log_info "Warning: Could not chown ${rc_file}"
                log_info "Alias added to ${rc_file}. Please run 'source ${rc_file}' or open a new terminal."
            elif grep -q "$ALIAS_MARKER" "$rc_file"; then
                log_info "'portguard' alias already exists in ${rc_file}."
            else
                log_info "Could not find ${rc_file} to add alias."
            fi
        }

        add_alias_if_needed "$BASHRC_PATH"
        add_alias_if_needed "$ZSHRC_PATH"

    else
        log_info "Could not determine home directory for user '$INSTALLER_USER' to add shell alias."
    fi
    # --- End Add Alias ---

    # Get primary IP address for the final message
    IP_ADDR=$(hostname -I | awk '{print $1}')
    log_success "Dynamic Port Guard Web UI installed."
    log_info "Access it locally at: http://localhost:6060"
    if [ -n "$IP_ADDR" ] && [ "$IP_ADDR" != "127.0.0.1" ]; then
        log_info "Or potentially via network at: http://${IP_ADDR}:6060 (Ensure firewall permits port 6060 if needed)"
    fi
    log_info "Web UI status command: systemctl status ${WEBUI_SERVICE_NAME}"

fi

log_success "--- Installation Finished ---"
exit 0
