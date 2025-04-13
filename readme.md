# Dynamic Port Guard: Adaptive Firewall Manager

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Dynamic Port Guard is a lightweight firewall management system designed to enhance security by dynamically adjusting firewall rules based on network services actively listening for connections. It operates on a principle of "allow what's needed, when it's needed," complementing a default-deny firewall policy.

It consists of two main components:
1.  **Core Service (`dynamic-port-guard`):** A background daemon that monitors listening ports and updates firewall rules accordingly.
2.  **Web UI (`dynamic-port-webui`):** An optional web interface for monitoring status, managing configuration, viewing logs, and controlling the core service.

---

## Table of Contents

*   [How it Works](#how-it-works)
*   [Key Features](#key-features)
*   [Prerequisites](#prerequisites)
*   [Installation](#installation)
*   [Post-Installation Verification](#post-installation-verification)
*   [Configuration](#configuration)
*   [Usage](#usage)
    *   [Core Service Control (systemd)](#core-service-control-systemd)
    *   [Web UI](#web-ui)
    *   [`portguard` Alias](#portguard-alias)
*   [Security Considerations](#security-considerations)
*   [Troubleshooting](#troubleshooting)
*   [Uninstallation](#uninstallation)
*   [Contributing](#contributing)
*   [License](#license)

---

## How it Works

### Core Service Logic

1.  **Monitoring:** The core service (`dynamic_port_guard.sh`) periodically (default: 10 seconds) uses the `ss` command to detect all TCP and UDP ports currently in a `LISTEN` state on both IPv4 and IPv6.
2.  **Whitelist:** It combines the list of actively listening ports with a user-defined `WHITELIST` from the configuration file (`/etc/dynamic-port-guard.conf`).
3.  **Firewall Interaction:**
    *   It assumes a dedicated `iptables` chain exists (default: `PORTGUARD_ALLOW`). On startup, it creates this chain if missing and adds a jump rule from the main `INPUT` chain to it (e.g., `iptables -I INPUT 1 -j PORTGUARD_ALLOW`).
    *   During each check cycle, it **flushes** all existing rules within the dedicated `PORTGUARD_ALLOW` chain.
    *   It then iterates through the combined list (listening ports + whitelist) and adds an `ACCEPT` rule to the `PORTGUARD_ALLOW` chain for each unique `protocol:port` combination.
4.  **Default-Deny Assumption:** The system **relies on the main firewall having a default-deny policy** or subsequent rules in the `INPUT` chain (after the jump to `PORTGUARD_ALLOW`) to block any traffic not explicitly allowed by this tool. Dynamic Port Guard *only opens ports*; it doesn't explicitly block traffic itself beyond managing its dedicated allow chain.

### Web UI Role

*   The Web UI runs as a separate Flask application within its own Python **virtual environment** located at `/opt/dynamic-port-webui/venv/` for dependency isolation.
*   It acts as a **management interface**. It does **not** directly modify firewall rules.
*   It provides:
    *   Status display of currently listening ports (`ss` output).
    *   Viewing and editing of the core service's configuration file (`/etc/dynamic-port-guard.conf`).
    *   Viewing of the core service's log file (`/var/log/dynamic_ports.log` by default).
    *   Control buttons (Start/Stop/Restart) for the `dynamic-port-guard` core service via `systemctl`.

## Key Features

*   **Dynamic Port Allowing:** Automatically allows traffic to ports only when services are actively listening.
*   **Whitelist Support:** Ensures critical services (like SSH) or desired public services (like HTTP/S) are always accessible.
*   **Dedicated Firewall Chain:** Integrates cleanly with `iptables` using a separate chain (`PORTGUARD_ALLOW` by default) for easy management and debugging.
*   **IPv4 & IPv6 Support:** Manages rules for both IP protocols.
*   **Configurable:** Settings managed via `/etc/dynamic-port-guard.conf`.
*   **Systemd Integration:** Both core service and Web UI run as persistent background services.
*   **Web UI for Management:** Optional interface for status checks, configuration, log viewing, and service control.
*   **Isolated Web UI Dependencies:** Web UI uses a Python virtual environment (`venv`) to prevent conflicts with system Python packages.
*   **Minimal Resource Usage:** Designed to be lightweight.

## Prerequisites

*   **Operating System:** Linux distribution using `systemd`. Tested primarily on Debian/Ubuntu derivatives.
*   **Firewall:** `iptables` and `ip6tables` command-line tools installed and operational. (UFW/nftables support is not implemented).
*   **Core Tools:** `bash`, `ss` (from `iproute2`), `awk`, `grep`, `sort`.
*   **Python (for Web UI):** Python 3, `python3-pip`, `python3-venv` (or equivalent packages like `python3-virtualenv` on some distributions).
*   **Root Access:** Required for installation and for the services to manage firewall rules and control systemd units.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/1999AZZAR/dynamic_port_guard.git
    cd dynamic-port-guard
    ```

2.  **Ensure Example Config Exists:** Make sure the example configuration file (`dynamic-port-guard.conf.example`) is present in the repository's root directory.

3.  **Run the installation script:** Execute the script with `sudo`. It installs both components by default.
    ```bash
    sudo ./install.sh
    ```

    **Installation Options:**
    *   Install only the core background service:
        ```bash
        sudo ./install.sh --core-only
        ```
    *   Install only the Web UI (requires core service config/logs to exist):
        ```bash
        sudo ./install.sh --webui-only
        ```

4.  **What the script does:**
    *   Copies `dynamic_port_guard.sh` to `/usr/local/bin/`.
    *   Copies `dynamic-port-guard.conf.example` to `/etc/dynamic-port-guard.conf` if it doesn't already exist.
    *   Creates and enables the `dynamic-port-guard.service` systemd unit.
    *   **(If installing Web UI):**
        *   Installs `python3`, `pip`, and `venv` system packages via the detected package manager (apt/dnf/yum).
        *   Copies the `webui` directory contents (`app.py`, `templates/`) to `/opt/dynamic-port-webui/`.
        *   Creates a Python virtual environment at `/opt/dynamic-port-webui/venv/`.
        *   Installs `Flask` into the virtual environment using its `pip`.
        *   Creates and enables the `dynamic-port-webui.service` systemd unit, configured to use the Python interpreter from the virtual environment.
    *   Reloads the systemd daemon.
    *   Starts the installed services.
    *   **(If installing Web UI):** Adds a convenience alias `portguard` to the invoking user's `~/.bashrc`.

## Post-Installation Verification

1.  **Check Service Status:**
    ```bash
    sudo systemctl status dynamic-port-guard.service
    # If Web UI was installed:
    sudo systemctl status dynamic-port-webui.service
    ```
    Both should show `Active: active (running)`.

2.  **Check Firewall Rules:** Inspect the dedicated chain:
    ```bash
    sudo iptables -nvL PORTGUARD_ALLOW
    sudo ip6tables -nvL PORTGUARD_ALLOW
    ```
    You should see `ACCEPT` rules for your whitelisted ports and any other ports currently being listened on by services (like the Web UI on port 6060 if installed).

3.  **Check Core Service Log:**
    ```bash
    tail /var/log/dynamic_ports.log
    ```
    You should see log entries indicating startup and rule applications.

4.  **Access Web UI (if installed):**
    Open your web browser and navigate to `http://<your-server-ip>:6060`. Replace `<your-server-ip>` with the actual IP address of the machine.

5.  **Use the Alias (if installed):**
    *   Open a *new* terminal window or run `source ~/.bashrc` in your current one.
    *   Run the alias: `portguard`. This will display the status of both services and attempt to open the Web UI in your default browser.

## Configuration

All configuration for the **core service** is done via the `/etc/dynamic-port-guard.conf` file. Edit this file using a text editor (e.g., `sudo nano /etc/dynamic-port-guard.conf`).

**Options:**

*   `WHITELIST="tcp:22 tcp:80 tcp:443"`
    *   Space-separated list of ports to *always* allow.
    *   Format: `protocol:port` (e.g., `tcp:22`, `udp:53`).
    *   Ensure ports essential for access (like SSH) are listed here.

*   `CHECK_INTERVAL=10`
    *   How often (in seconds) the core service checks for listening ports and updates the firewall.

*   `FIREWALL_TOOL="iptables"`
    *   Specifies the firewall backend. Currently, only `iptables` is fully supported. `ufw` and `nftables` are placeholders and require implementation work.

*   `LOG_FILE="/var/log/dynamic_ports.log"`
    *   Path where the core service writes its operational logs. Ensure the service has write permissions to this file/directory.

*   `IPTABLES_CHAIN="PORTGUARD_ALLOW"`
    *   The name of the dedicated `iptables`/`ip6tables` chain managed by the script.

**Applying Changes:** After modifying the configuration file, you **must restart the core service** for the changes to take effect:
```bash
sudo systemctl restart dynamic-port-guard.service
```
*(Note: Saving changes via the Web UI automatically triggers this restart).*

## Usage

Interaction with Dynamic Port Guard is primarily through standard system tools and the optional Web UI.

### Core Service Control (systemd)

Use `systemctl` to manage the core service:
*   Check status: `sudo systemctl status dynamic-port-guard.service`
*   Stop service: `sudo systemctl stop dynamic-port-guard.service`
*   Start service: `sudo systemctl start dynamic-port-guard.service`
*   Restart service: `sudo systemctl restart dynamic-port-guard.service`
*   View logs: `sudo journalctl -u dynamic-port-guard.service` or `tail -f /var/log/dynamic_ports.log`

### Web UI

If installed, the Web UI (default: `http://<your-server-ip>:6060`) provides a graphical way to:
*   View currently listening TCP/UDP ports detected by `ss`.
*   View the current configuration from `/etc/dynamic-port-guard.conf`.
*   Edit and save the configuration (automatically restarts the core service on save).
*   View recent entries from the core service log file (`/var/log/dynamic_ports.log`).
*   View the current `systemd` status of the core service.
*   Start/Stop/Restart the core service using buttons.

### `portguard` Alias

If the Web UI was installed, the `portguard` alias (added to the installing user's `~/.bashrc`) provides a quick command-line shortcut to:
1.  Display the `systemd` status of both the core and web UI services.
2.  Attempt to open the Web UI (`http://localhost:6060`) in the default browser using `xdg-open`.
*(Remember to run `source ~/.bashrc` or open a new terminal after installation for the alias to become available).*

## Security Considerations

**!!! IMPORTANT !!!**

1.  **Default Deny Policy Required:** Dynamic Port Guard **only adds `ACCEPT` rules** to its dedicated chain. It *relies* on your main firewall configuration having a **default-deny policy** for the `INPUT` chain, or having rules *after* the `PORTGUARD_ALLOW` jump rule that block unwanted traffic. Without a default-deny policy, this tool *will not* secure your system.
    *   Example: To set a default-deny policy using `iptables` (apply carefully!):
        ```bash
        # Allow established connections (essential!)
        sudo iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        sudo ip6tables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        # Allow loopback traffic
        sudo iptables -A INPUT -i lo -j ACCEPT
        sudo ip6tables -A INPUT -i lo -j ACCEPT
        # (Ensure the PORTGUARD_ALLOW jump rule is in place near the top)
        # Set default policy to DROP (blocks everything not explicitly allowed)
        sudo iptables -P INPUT DROP
        sudo ip6tables -P INPUT DROP
        # Remember to save rules if needed (e.g., using iptables-persistent)
        ```

2.  **Root Privileges:** Both the core service and the Web UI service run as `root`. This is necessary for the core service to modify `iptables` rules and for the Web UI to manage `systemd` services and edit the configuration file in `/etc`. Be aware of the inherent risks of running services as root. For high-security environments, consider modifying the services to run as dedicated users with carefully configured `sudo` rules (this adds complexity).

3.  **Web UI Exposure:** The Web UI listens on port `6060` on `0.0.0.0` (all interfaces) by default. Avoid exposing this port directly to untrusted networks. Use your main firewall (or the Dynamic Port Guard whitelist itself, carefully) to restrict access to port `6060` to trusted IP addresses if necessary.

4.  **Whitelist Carefully:** Only add ports to the `WHITELIST` that are absolutely necessary to be always open (like SSH). Rely on the dynamic detection for application ports where possible.

5.  **No Egress Filtering:** This tool only manages *incoming* traffic rules in the `INPUT` chain. It does not affect outgoing (`OUTPUT`) traffic.

## Troubleshooting

*   **Core service (`dynamic-port-guard`) fails to start:**
    *   Check systemd journal: `sudo journalctl -u dynamic-port-guard.service -n 50 --no-pager`
    *   Check script log: `tail -n 50 /var/log/dynamic_ports.log`
    *   Verify syntax in `/etc/dynamic-port-guard.conf`.
    *   Ensure `iptables`/`ip6tables` commands are executable.

*   **Web UI service (`dynamic-port-webui`) fails to start:**
    *   Check systemd journal: `sudo journalctl -u dynamic-port-webui.service -n 50 --no-pager`. Look for Python errors (tracebacks).
    *   Verify the virtual environment exists and has Flask installed:
        ```bash
        ls -l /opt/dynamic-port-webui/venv/bin/python
        /opt/dynamic-port-webui/venv/bin/pip list | grep Flask
        ```
    *   Check permissions on `/opt/dynamic-port-webui/`.

*   **Cannot access Web UI in browser:**
    *   Verify the `dynamic-port-webui` service is `active (running)` (`sudo systemctl status ...`).
    *   Check if the service is listening on the correct port and IP: `sudo ss -tlpn 'sport == :6060'`. It should show `0.0.0.0:6060` or `:::6060`.
    *   Check firewall rules:
        *   `sudo iptables -nvL INPUT --line-numbers` (Look for blocks before the `PORTGUARD_ALLOW` jump).
        *   `sudo iptables -nvL PORTGUARD_ALLOW | grep 6060` (Ensure an ACCEPT rule exists).
        *   `sudo ufw status verbose` (if UFW is active, ensure port 6060/tcp is allowed).
    *   Try connecting locally from the server: `curl http://localhost:6060`.

## Uninstallation

1.  Navigate to the cloned repository directory.
2.  Run the uninstall script with `sudo`:
    ```bash
    sudo ./uninstall.sh
    ```
    This removes both components by default.

    **Uninstallation Options:**
    *   Remove only the core service: `sudo ./uninstall.sh --core-only`
    *   Remove only the Web UI: `sudo ./uninstall.sh --webui-only`
    *   Force removal of the config file without asking: `sudo ./uninstall.sh --remove-config`

3.  **What the script does:**
    *   Stops and disables the relevant `systemd` service(s).
    *   Removes the script (`/usr/local/bin/dynamic_port_guard.sh`).
    *   Removes the Web UI application directory (`/opt/dynamic-port-webui/`, including the venv).
    *   Removes the `systemd` service file(s).
    *   Asks whether to remove the configuration file (`/etc/dynamic-port-guard.conf`) unless `--remove-config` is used.
    *   Reloads the systemd daemon.
    *   *(Note: The script does NOT attempt to remove installed package dependencies like python3, pip, flask, click etc.)*
    *   *(Note: Firewall rule cleanup relies on the core service's exit trap. Verify your firewall rules manually after uninstallation to ensure the jump rule and chain are removed if desired.)*

## Contributing

Contributions are welcome! Feel free to fork the repository, make improvements, and open pull requests.

Areas for potential contribution:
*   Implementing full support for `ufw` or `nftables` backends.
*   Adding more robust error handling and logging.
*   Improving the Web UI (e.g., pagination for logs, AJAX updates).
*   Adding unit or integration tests.
*   Packaging for distributions (.deb, .rpm).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
