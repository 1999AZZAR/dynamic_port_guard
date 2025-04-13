#!/bin/bash

set -e # Exit on error

# --- Configuration ---
CORE_SERVICE_NAME="dynamic-port-guard"
CORE_SCRIPT_NAME="dynamic_port_guard.sh"
CORE_BIN_PATH="/usr/local/bin/${CORE_SCRIPT_NAME}"
CORE_SERVICE_FILE="/etc/systemd/system/${CORE_SERVICE_NAME}.service"
CORE_CONFIG_FILE="/etc/dynamic-port-guard.conf"
CORE_CONFIG_SOURCE="dynamic-port-guard.conf.example"

WEBUI_SERVICE_NAME="dynamic-port-webui"
WEBUI_APP_DIR="/opt/${WEBUI_SERVICE_NAME}"
WEBUI_SERVICE_FILE="/etc/systemd/system/${WEBUI_SERVICE_NAME}.service"
WEBUI_SOURCE_DIR="webui"
# Define path for the virtual environment
WEBUI_VENV_PATH="${WEBUI_APP_DIR}/venv"

INSTALL_CORE=true
INSTALL_WEBUI=true

# --- Helper Functions ---
log_info() { echo "[*] $1"; }
log_success() { echo "[✓] $1"; }
log_error() { echo "[!] Error: $1" >&2; }

# --- Argument Parsing ---
while [[ "$#" -gt 0 ]]; do
    case $1 in
    --core-only) INSTALL_WEBUI=false ;;
    --webui-only) INSTALL_CORE=false ;;
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

# --- Core Service Installation ---
if $INSTALL_CORE; then
    # (Core service installation logic remains the same)
    log_info "Installing Dynamic Port Guard Core Service..."

    if [ ! -f "$CORE_SCRIPT_NAME" ]; then
        log_error "Core script '$CORE_SCRIPT_NAME' not found in current directory."
        exit 1
    fi

    log_info "Copying script to ${CORE_BIN_PATH}"
    install -m 755 "$CORE_SCRIPT_NAME" "$CORE_BIN_PATH"

    log_info "Checking configuration file ${CORE_CONFIG_FILE}"
    if [ -f "$CORE_CONFIG_SOURCE" ]; then
        if [ ! -f "$CORE_CONFIG_FILE" ]; then
            log_info "Creating default configuration file from ${CORE_CONFIG_SOURCE}."
            install -m 644 "$CORE_CONFIG_SOURCE" "$CORE_CONFIG_FILE"
        else
            log_info "Configuration file ${CORE_CONFIG_FILE} already exists. Not overwriting."
        fi
    else
        log_info "Warning: Example config file '$CORE_CONFIG_SOURCE' not found. Service will use internal defaults."
    fi

    log_info "Creating systemd service file ${CORE_SERVICE_FILE}"
    tee "$CORE_SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=Dynamic Firewall Port Guard Core Service
# Wait for network to be up
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=${CORE_BIN_PATH}
Restart=always
# Wait 5 seconds before restart
RestartSec=5s
# Logs are handled by the script itself
StandardOutput=null
# Log errors to system journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    log_info "Reloading systemd daemon..."
    systemctl daemon-reload
    log_info "Enabling and starting ${CORE_SERVICE_NAME} service..."
    systemctl enable "$CORE_SERVICE_NAME"
    if systemctl start "$CORE_SERVICE_NAME"; then
        log_success "Dynamic Port Guard Core Service installed and started."
    else
        log_error "Failed to start ${CORE_SERVICE_NAME} service. Check status with 'systemctl status ${CORE_SERVICE_NAME}' and logs with 'journalctl -u ${CORE_SERVICE_NAME}'."
    fi
    log_info "Check status with: systemctl status ${CORE_SERVICE_NAME}"
    log_info "Logs are typically in /var/log/dynamic_ports.log (or as configured)."
fi

# --- Web UI Installation ---
if $INSTALL_WEBUI; then
    log_info "Installing Dynamic Port Guard Web UI..."

    # Check for source directory
    if [ ! -d "$WEBUI_SOURCE_DIR" ]; then
        log_error "Web UI source directory '$WEBUI_SOURCE_DIR' not found."
        exit 1
    fi
    if [ ! -f "$WEBUI_SOURCE_DIR/app.py" ] || [ ! -d "$WEBUI_SOURCE_DIR/templates" ]; then
        log_error "Web UI directory '$WEBUI_SOURCE_DIR' seems incomplete (missing app.py or templates/)."
        exit 1
    fi

    # 1. Install necessary system packages (Python, Pip, Venv)
    log_info "Installing dependencies (python3, python3-pip, python3-venv)..."
    if command -v apt-get &>/dev/null; then
        apt-get install -y python3 python3-pip python3-venv # Ensure venv is installed
    elif command -v dnf &>/dev/null; then
        dnf install -y python3 python3-pip python3-virtualenv # Package name might differ slightly
    elif command -v yum &>/dev/null; then
        yum install -y python3 python3-pip python3-virtualenv # Package name might differ slightly
    else
        log_error "Could not determine package manager (apt, dnf, yum). Please install Python 3, Pip, and Venv/Virtualenv manually."
        exit 1
    fi

    # 2. Create application directory and copy files
    log_info "Creating Web UI directory ${WEBUI_APP_DIR}"
    mkdir -p "$WEBUI_APP_DIR"
    log_info "Copying Web UI files to ${WEBUI_APP_DIR}"
    # Use cp -T to copy contents into the target directory if source is directory
    cp -R "$WEBUI_SOURCE_DIR"/app.py "$WEBUI_SOURCE_DIR"/templates "$WEBUI_APP_DIR/"
    if [ -d "$WEBUI_SOURCE_DIR/static" ]; then
        cp -R "$WEBUI_SOURCE_DIR/static" "$WEBUI_APP_DIR/"
    fi

    # 3. Create the virtual environment
    log_info "Creating Python virtual environment in ${WEBUI_VENV_PATH}..."
    # Check if python3 command exists before using it
    if ! command -v python3 &>/dev/null; then
        log_error "python3 command not found. Cannot create virtual environment."
        exit 1
    fi
    python3 -m venv "$WEBUI_VENV_PATH"
    if [ $? -ne 0 ]; then
        log_error "Failed to create virtual environment."
        exit 1
    fi

    # 4. Install Flask into the virtual environment
    log_info "Installing Flask into the virtual environment..."
    # Use the pip from the virtual environment
    if "$WEBUI_VENV_PATH/bin/pip" install Flask; then
        log_info "Flask installed successfully into virtual environment."
    else
        log_error "Failed to install Flask using virtual environment pip."
        # Provide more debug info if possible
        log_error "Check permissions for ${WEBUI_VENV_PATH} and network connectivity."
        exit 1
    fi

    # 5. Set ownership and permissions
    # Run service as root for simplicity, but own the files as root
    chown -R root:root "$WEBUI_APP_DIR"
    chmod -R 750 "$WEBUI_APP_DIR"

    # 6. Create systemd service file pointing to the venv python
    log_info "Creating systemd service file ${WEBUI_SERVICE_FILE}"
    # Use the python from the virtual environment in ExecStart
    VENV_PYTHON_BIN="${WEBUI_VENV_PATH}/bin/python"
    tee "$WEBUI_SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=Dynamic Port Guard Web UI (venv)
# Start after networking is up
After=network.target

[Service]
# Running as root to easily manage config/service.
User=root
Group=root
WorkingDirectory=${WEBUI_APP_DIR}
# Execute the python from the virtual environment
ExecStart=${VENV_PYTHON_BIN} ${WEBUI_APP_DIR}/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    # 7. Reload systemd, enable and start service
    log_info "Reloading systemd daemon..."
    systemctl daemon-reload
    log_info "Enabling and starting ${WEBUI_SERVICE_NAME} service..."
    systemctl enable "$WEBUI_SERVICE_NAME"
    if systemctl start "$WEBUI_SERVICE_NAME"; then
        log_info "${WEBUI_SERVICE_NAME} service started."
    else
        log_error "Failed to start ${WEBUI_SERVICE_NAME} service. Check status with 'systemctl status ${WEBUI_SERVICE_NAME}' and logs with 'journalctl -u ${WEBUI_SERVICE_NAME}'."
    fi

    # --- Add Alias ---
    # (Alias logic remains the same)
    INSTALLER_USER_HOME=$(getent passwd "${SUDO_USER:-$(whoami)}" | cut -d: -f6)
    if [ -n "$INSTALLER_USER_HOME" ] && [ -d "$INSTALLER_USER_HOME" ]; then
        BASHRC_PATH="${INSTALLER_USER_HOME}/.bashrc"
        ALIAS_CMD="alias portguard='echo \"[*] Dynamic Port Guard Status:\"; sudo systemctl status ${CORE_SERVICE_NAME} --no-pager; echo; sudo systemctl status ${WEBUI_SERVICE_NAME} --no-pager; echo; echo \"[*] Opening Web UI...\"; xdg-open http://localhost:6060 &>/dev/null &'"
        if [ -f "$BASHRC_PATH" ] && ! grep -q "alias portguard=" "$BASHRC_PATH"; then
            log_info "Adding 'portguard' alias to ${BASHRC_PATH}..."
            echo >>"$BASHRC_PATH" # Add newline for separation
            echo "# Dynamic Port Guard Alias" >>"$BASHRC_PATH"
            echo "$ALIAS_CMD" >>"$BASHRC_PATH"
            INSTALLER_USER=$(getent passwd "${SUDO_USER:-$(whoami)}" | cut -d: -f1)
            if [ -n "$INSTALLER_USER" ]; then
                chown "${INSTALLER_USER}:${INSTALLER_USER}" "$BASHRC_PATH" || log_info "Warning: Could not chown ${BASHRC_PATH}"
            fi
            log_info "Alias added. Please run 'source ~/.bashrc' or open a new terminal."
        elif grep -q "alias portguard=" "$BASHRC_PATH"; then
            log_info "'portguard' alias already exists in ${BASHRC_PATH}."
        else
            log_info "Could not find ${BASHRC_PATH} to add alias."
        fi
    else
        log_info "Could not determine user's home directory to add alias."
    fi
    # --- End Add Alias ---

    IP_ADDR=$(hostname -I | awk '{print $1}')
    log_success "Dynamic Port Guard Web UI installed."
    log_info "Access it at: http://${IP_ADDR:-localhost}:6060"

fi

log_success "Installation finished."
