import subprocess
import os
import shlex
import re
from flask import Flask, render_template, redirect, url_for, request, flash
from markupsafe import escape  # Import escape from markupsafe
import qrcode
import io
import base64
import select
import time
import threading

# --- Determine Folders FIRST ---
# Get the directory where this script resides
script_dir = os.path.dirname(os.path.abspath(__file__))
# Define template and static folder paths relative to the script directory
template_folder = os.path.join(script_dir, "templates")
static_folder = os.path.join(script_dir, "static")

# Check if template folder exists (optional but good practice)
if not os.path.isdir(template_folder):
    print(
        f"Warning: Template folder not found at {template_folder}. Using default 'templates'."
    )
    template_folder = "templates"  # Fallback
if not os.path.isdir(static_folder):
    print(
        f"Warning: Static folder not found at {static_folder}. Using default 'static'."
    )
    static_folder = "static"  # Fallback


# --- Initialize Flask App with Folder Paths ---
app = Flask(__name__, template_folder=template_folder, static_folder=static_folder)
app.secret_key = os.urandom(24)  # Needed for flashing messages


# --- Configuration ---
CONFIG_FILE = "/etc/dynamic-port-guard.conf"
# Default log file path if not in config (read_config handles primary source)
DEFAULT_LOG_FILE = "/var/log/dynamic_ports.log"
CORE_SERVICE_NAME = "dynamic-port-guard.service"


# --- Helper Functions ---


def run_command(command):
    """Runs a shell command and returns stdout, stderr, and return code."""
    try:
        # Use shell=False for security unless shell features are truly needed
        # Ensure command is split correctly
        cmd_parts = shlex.split(command)
        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            check=False,  # Don't raise exception on non-zero exit
            timeout=10,
        )
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        # Provide the command that failed
        cmd_name = cmd_parts[0] if cmd_parts else "Unknown command"
        return "", f"Command not found: {cmd_name}", 127
    except subprocess.TimeoutExpired:
        return "", f"Command '{command}' timed out", 1
    except Exception as e:
        return "", f"Error running '{command}': {e}", 1


def get_process_name_from_pid(pid):
    """Gets the process name (command) from a PID."""
    if not pid or not pid.isdigit():
        return "N/A"
    # Use ps to get the command name, handle cases where PID no longer exists
    # comm= gives the executable name, cmd= gives the full command line
    # Using comm= is usually cleaner for display
    stdout, stderr, retcode = run_command(f"ps -o comm= -p {pid}")
    if retcode == 0 and stdout.strip():
        return stdout.strip()
    else:
        # Try cmd just in case comm failed for some reason or process is gone
        stdout_cmd, _, retcode_cmd = run_command(f"ps -o cmd= -p {pid}")
        if retcode_cmd == 0 and stdout_cmd.strip():
            # Limit length for display
            cmd_line = stdout_cmd.strip()
            return cmd_line[:50] + ("..." if len(cmd_line) > 50 else "")
        return "N/A (ended?)"  # Return if process likely ended between ss and ps


def get_listening_ports():
    """Gets currently listening ports using ss, including process info."""
    # Use -p to show process using socket, -n to avoid resolving names (faster)
    stdout, stderr, retcode = run_command("ss -tunlp")
    ports = []
    # Fetch current whitelist once for checking
    current_config = read_config()
    whitelist_str = current_config.get("WHITELIST", "")
    # Create set of 'proto:port' strings for efficient lookup
    whitelist_set = set(
        item for item in whitelist_str.split() if item
    )  # Filter empty items

    if retcode == 0 and stdout:
        lines = stdout.strip().split("\n")
        if len(lines) > 1:
            for line in lines[1:]:  # Skip header
                parts = line.split()
                # Filter for LISTEN state more reliably
                # State can sometimes shift position slightly, check multiple fields
                if len(parts) < 2 or "LISTEN" not in parts[1]:
                    # Double check if state is in first field (less common but possible)
                    if len(parts) < 1 or "LISTEN" not in parts[0]:
                        continue  # Skip if LISTEN state not found

                # Find the local address:port field (usually 5th, index 4)
                local_addr_port = ""
                if len(parts) > 4:
                    local_addr_port = parts[4]
                else:  # Handle lines with fewer columns if needed
                    continue  # Skip malformed lines

                # Regex to find users:(("name",pid=XXX,...)) or similar patterns
                pid_match = re.search(r"pid=(\d+)", line)
                pid = pid_match.group(1) if pid_match else None

                # Extract protocol cleanly
                proto = parts[0].lower()
                if proto.startswith("tcp"):
                    proto = "tcp"
                elif proto.startswith("udp"):
                    proto = "udp"
                else:
                    continue  # Skip others like raw, packet, unix domain sockets shown by ss

                # Extract IP and port robustly
                try:
                    # Handle IPv6 brackets `[::]:80` vs IPv4 `0.0.0.0:22`
                    if (
                        local_addr_port.count(":") > 1 and "[" in local_addr_port
                    ):  # Likely IPv6
                        ip_part, port_part = local_addr_port.rsplit(":", 1)
                        ip = ip_part.strip("[]")  # Remove brackets
                        port = port_part
                    else:  # Likely IPv4 or wildcard
                        ip_part, port_part = local_addr_port.rsplit(":", 1)
                        ip = ip_part
                        port = port_part

                    # Normalize wildcard IPs
                    if ip in ["0.0.0.0", "::", "*"]:
                        ip = "*"

                    # Ensure port is a valid number
                    if not port.isdigit():
                        continue
                except (IndexError, ValueError):
                    print(
                        f"Debug: Failed to parse IP/Port from: {local_addr_port} in line: {line}"
                    )
                    continue  # Skip if parsing fails

                process_name = get_process_name_from_pid(pid)
                port_identifier = f"{proto}:{port}"
                is_whitelisted = port_identifier in whitelist_set

                ports.append(
                    {
                        "proto": proto,
                        "ip": ip,
                        "port": port,
                        "pid": pid or "N/A",
                        "process_name": process_name,
                        "port_identifier": port_identifier,  # Helper for actions ('tcp:80')
                        "is_whitelisted": is_whitelisted,
                    }
                )
    elif stderr:
        # Avoid flashing errors here, maybe log them instead for backend issues
        print(f"Error getting listening ports: {stderr}")
        # Flash only if command failed, not just stderr noise
        if retcode != 0:
            flash(
                f"Error getting listening ports (ss -tunlp): {escape(stderr)}", "danger"
            )
    elif retcode != 0:
        flash(
            f"Failed to run 'ss -tunlp' (code: {retcode}). Is 'iproute2' installed?",
            "danger",
        )

    # Sort ports for consistent display (by port number, then proto)
    ports.sort(key=lambda x: (int(x["port"]), x["proto"]))
    return ports


def read_config():
    """Reads the configuration file."""
    config = {}
    # Define structure and defaults
    defaults = {
        "WHITELIST": "tcp:22",  # Sensible default: SSH
        "CHECK_INTERVAL": "10",
        "FIREWALL_TOOL": "iptables",
        "LOG_FILE": DEFAULT_LOG_FILE,
        "IPTABLES_CHAIN": "PORTGUARD_ALLOW",
    }
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    # Allow comments and blank lines
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip().upper()  # Ensure keys are uppercase
                        # Remove potential quotes and extra whitespace
                        value = value.strip().strip('"').strip("'").strip()
                        if key in defaults:  # Only store known keys
                            config[key] = value

        # Ensure all expected keys exist in the returned dict, using defaults if necessary
        final_config = defaults.copy()  # Start with defaults
        final_config.update(config)  # Overwrite with values read from file

        # Basic type validation/correction (example for interval)
        try:
            int(final_config.get("CHECK_INTERVAL", defaults["CHECK_INTERVAL"]))
        except ValueError:
            print(
                f"Warning: Invalid CHECK_INTERVAL in config, using default {defaults['CHECK_INTERVAL']}"
            )
            final_config["CHECK_INTERVAL"] = defaults["CHECK_INTERVAL"]

    except Exception as e:
        print(f"Error reading config file {CONFIG_FILE}: {e}")
        # Don't flash here, let the caller decide. Return defaults on major error.
        return defaults
    return final_config


def write_config(config_dict):
    """Writes the configuration dictionary back to the file."""
    # Use defaults from read_config() logic for consistency
    defaults = read_config()
    try:
        with open(CONFIG_FILE, "w") as f:
            f.write("# Configuration for Dynamic Port Guard\n")
            f.write("# Managed by Dynamic Port Guard WebUI\n\n")

            f.write(
                "# Whitelist: Space-separated list of 'proto:port' to always allow.\n"
            )
            # Ensure WHITELIST exists and is a string, handle potential list/set input
            whitelist_val = config_dict.get("WHITELIST", defaults["WHITELIST"])
            if isinstance(whitelist_val, (list, set)):
                whitelist_val = " ".join(
                    sorted(list(whitelist_val))
                )  # Convert back to string
            f.write(f'WHITELIST="{whitelist_val}"\n\n')

            f.write(
                "# Check Interval: How often (in seconds) to check for listening ports.\n"
            )
            interval = config_dict.get("CHECK_INTERVAL", defaults["CHECK_INTERVAL"])
            f.write(f"CHECK_INTERVAL={interval}\n\n")

            f.write(
                "# Firewall Tool: Currently only 'iptables' is fully implemented.\n"
            )
            tool = config_dict.get("FIREWALL_TOOL", defaults["FIREWALL_TOOL"])
            f.write(f'FIREWALL_TOOL="{tool}"\n\n')

            f.write("# Log File: Path for operational logs.\n")
            log_path = config_dict.get("LOG_FILE", defaults["LOG_FILE"])
            f.write(f'LOG_FILE="{log_path}"\n\n')

            f.write("# Dedicated Chain Name (iptables/ip6tables)\n")
            chain = config_dict.get("IPTABLES_CHAIN", defaults["IPTABLES_CHAIN"])
            f.write(f'IPTABLES_CHAIN="{chain}"\n')

        # Attempt to set secure permissions (owner rw, group r, other r)
        try:
            os.chmod(CONFIG_FILE, 0o644)
            # Optionally, set ownership if running as root and want to ensure root ownership
            # import pwd, grp
            # os.chown(CONFIG_FILE, pwd.getpwnam('root').pw_uid, grp.getgrnam('root').gr_gid)
        except OSError as e:
            # Non-critical warning if permissions fail
            print(f"Warning: Could not set permissions on {CONFIG_FILE}: {e}")
        return True
    except Exception as e:
        flash(f"Error writing config file {CONFIG_FILE}: {escape(str(e))}", "danger")
        return False


def control_service(action):
    """Controls the core systemd service."""
    if action not in ["start", "stop", "restart", "status"]:
        flash(f"Invalid service action: {escape(action)}", "warning")
        return False, "Invalid action"

    # Assume this web UI runs as root or has passwordless sudo for systemctl
    # If not running as root, you might need: cmd = f"sudo systemctl {action} {CORE_SERVICE_NAME}"
    cmd = f"systemctl {action} {CORE_SERVICE_NAME}"
    stdout, stderr, retcode = run_command(cmd)

    if action == "status":
        # Return combined output, escaped for safety in HTML context
        return True, escape(stdout + stderr)

    if retcode == 0:
        # Flash success message only for actions, not status
        flash(
            f"Service {CORE_SERVICE_NAME} action '{escape(action)}' executed successfully.",
            "success",
        )
        return True, f"Service {action} successful."
    else:
        # Display stderr if available, otherwise a generic message
        error_msg = (
            stderr.strip()
            if stderr.strip()
            else f"Command '{cmd}' failed with code {retcode}"
        )
        flash(
            f"Error executing '{escape(action)}' on {CORE_SERVICE_NAME}: {escape(error_msg)}",
            "danger",
        )
        return False, error_msg


def read_log(lines=50):
    """Reads the last N lines of the log file specified in the config."""
    config = read_config()
    log_path = config.get(
        "LOG_FILE", DEFAULT_LOG_FILE
    )  # Get log path from current config
    if not os.path.exists(log_path):
        return f"Log file not found: {escape(log_path)}"
    try:
        # Use tail for efficiency, ensure log path is handled safely
        safe_log_path = shlex.quote(log_path)  # Quote path for shell command
        stdout, stderr, retcode = run_command(f"tail -n {lines} {safe_log_path}")
        if retcode == 0:
            return escape(stdout)  # Escape log content for HTML safety
        elif retcode == 127:  # Command 'tail' not found
            print(
                "Warning: 'tail' command not found. Reading log manually (may be slow)."
            )
            # Fallback to Python read (less efficient for large files)
            try:
                with open(
                    log_path, "r", errors="ignore"
                ) as f:  # Ignore decoding errors
                    log_lines = f.readlines()
                return escape("".join(log_lines[-lines:]))
            except Exception as py_read_e:
                return f"Error reading log file manually {escape(log_path)}: {escape(str(py_read_e))}"
        else:
            # Tail command failed for other reason
            return f"Error reading log file with tail ({escape(log_path)}): {escape(stderr)}"

    except Exception as e:
        return f"Error reading log file {escape(log_path)}: {escape(str(e))}"


# === SHARE PORT STATE & ACTIONS ===
SHARE_STATE = {}  # maps port to {'proc': Popen, 'url': shared url}

def stop_share(port):
    """Stop SSH reverse tunnel for given port."""
    info = SHARE_STATE.get(port)
    if info:
        proc = info['proc']
        pid = proc.pid
        proc.terminate()
        del SHARE_STATE[port]
        return pid, port, info.get('url')
    return None, None, None

def _monitor_share(port, proc):
    """Background monitor to update URL if it changes."""
    pattern = re.compile(r'https?://[A-Za-z0-9-]+\.lhr\.life')
    while proc.poll() is None:
        line_bytes = proc.stdout.readline()
        if not line_bytes:
            continue
        line = line_bytes.decode('utf-8', errors='ignore')
        clean = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', line).strip()
        print(f"[share-debug] monitor output: {clean}")
        m = pattern.search(clean)
        if m:
            new_url = m.group(0)
            old_url = SHARE_STATE.get(port, {}).get('url')
            if new_url and new_url != old_url:
                print(f"[share-debug] URL changed for port {port}: {old_url} -> {new_url}")
                SHARE_STATE[port]['url'] = new_url

def start_share(port):
    """Start SSH reverse tunnel for given port and capture URL."""
    if port in SHARE_STATE and SHARE_STATE[port]['proc'].poll() is None:
        return SHARE_STATE[port]['url']
    try:
        cmd = [
            'ssh', '-tt',  # force pseudo-tty allocation for interactive shell
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'ExitOnForwardFailure=yes',
            '-o', 'ServerAliveInterval=60',
            '-o', 'ServerAliveCountMax=3',
            '-R', f'80:localhost:{port}',
            'nokey@localhost.run',
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        url = None
        start_time = time.time()
        pattern = re.compile(r'https?://[A-Za-z0-9-]+\.lhr\.life')
        while time.time() - start_time < 15:
            if proc.poll() is not None:
                break
            rlist, _, _ = select.select([proc.stdout], [], [], 1)
            if proc.stdout in rlist:
                line_bytes = proc.stdout.readline()
                if not line_bytes:
                    continue
                line = line_bytes.decode('utf-8', errors='ignore')
                clean = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', line)
                print(f"[share-debug] SSH output: {clean.strip()}")
                m = pattern.search(clean)
                if m:
                    url = m.group(0)
                    print(f"[share-debug] extracted URL: {url}")
                    break
        if url is None:
            print("[share-debug] No URL found in SSH output after timeout")
        SHARE_STATE[port] = {'proc': proc, 'url': url}
        threading.Thread(target=_monitor_share, args=(port, proc), daemon=True).start()
        return url
    except Exception as e:
        print(f"[share-debug] start_share exception: {e}")
        return None


# --- Flask Routes ---


@app.route("/")
def index():
    config = read_config()  # Read config first to get log path etc.
    ports = get_listening_ports()
    # Get status but don't flash messages from here for initial load
    _, status_output = control_service("status")
    logs = read_log(lines=50)
    # Prepare sharing info
    share_data = {}
    for port, info in SHARE_STATE.items():
        url = info.get('url') or ''
        img = qrcode.make(url)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        share_data[port] = {
            'url': url,
            'qr': base64.b64encode(buf.getvalue()).decode()
        }
    return render_template(
        "index.html",
        ports=ports,
        config=config,
        service_status=status_output,
        logs=logs,
        core_service_name=CORE_SERVICE_NAME,
        config_file_path=CONFIG_FILE,
        share_data=share_data,
    )


@app.route("/update_config", methods=["POST"])
def update_config_route():  # Renamed slightly to avoid conflict with function name
    current_config = read_config()
    new_config = current_config.copy()  # Start with current values

    # --- Sanitize and validate inputs ---
    # Whitelist: Basic strip, further validation happens if modified via buttons
    new_config["WHITELIST"] = request.form.get("whitelist", "").strip()

    # Check Interval: Ensure positive integer
    try:
        interval = int(
            request.form.get("check_interval", current_config["CHECK_INTERVAL"])
        )
        new_config["CHECK_INTERVAL"] = str(max(1, interval))  # Min interval of 1 sec
    except ValueError:
        flash("Invalid Check Interval provided, using previous value.", "warning")
        # Keep the old value if new one is invalid
        new_config["CHECK_INTERVAL"] = current_config.get("CHECK_INTERVAL", "10")

    # Firewall Tool: Only allow supported tools
    firewall_tool = request.form.get("firewall_tool", current_config["FIREWALL_TOOL"])
    if firewall_tool not in [
        "iptables"
    ]:  # Expand this list if more tools are supported
        flash(
            f"Firewall tool '{escape(firewall_tool)}' not supported, using iptables.",
            "warning",
        )
        new_config["FIREWALL_TOOL"] = "iptables"
    else:
        new_config["FIREWALL_TOOL"] = firewall_tool

    # Log File Path: Basic security checks
    log_file = request.form.get("log_file", current_config["LOG_FILE"]).strip()
    if not log_file or ".." in log_file or not os.path.isabs(log_file):
        flash(
            "Invalid Log File path (must be absolute, no '..'), using previous value.",
            "warning",
        )
        new_config["LOG_FILE"] = current_config.get("LOG_FILE", DEFAULT_LOG_FILE)
    else:
        # Further check: ensure parent directory exists? Optional.
        new_config["LOG_FILE"] = log_file

    # IPTables Chain Name: Alphanumeric + underscore/hyphen
    ipt_chain = request.form.get(
        "iptables_chain", current_config["IPTABLES_CHAIN"]
    ).strip()
    if not re.match(
        r"^[a-zA-Z0-9_-]{1,28}$", ipt_chain
    ):  # Added length limit typical for iptables
        flash(
            "Invalid IPTables Chain name (use A-Z, a-z, 0-9, _, -), using previous value.",
            "warning",
        )
        new_config["IPTABLES_CHAIN"] = current_config.get(
            "IPTABLES_CHAIN", "PORTGUARD_ALLOW"
        )
    else:
        new_config["IPTABLES_CHAIN"] = ipt_chain

    # --- Write config and restart ---
    if new_config != current_config:  # Only write and restart if changes were made
        if write_config(new_config):
            flash(
                "Configuration updated successfully. Restarting service...", "success"
            )
            control_service("restart")  # Restart to apply changes
        else:
            # write_config already flashed the error
            pass  # Stay on the page, errors shown
    else:
        flash("No changes detected in configuration.", "info")

    return redirect(url_for("index"))


@app.route("/service_action", methods=["POST"])
def service_action():
    action = request.form.get("action")
    control_service(action)  # Flash messages handled inside
    return redirect(url_for("index"))


@app.route("/whitelist/modify", methods=["POST"])
def modify_whitelist():
    action = request.form.get("action")  # 'add' or 'remove'
    port_identifier = request.form.get("port_identifier")  # 'proto:port'

    # Validate input
    if not port_identifier or ":" not in port_identifier:
        flash("Invalid port identifier format provided.", "warning")
        return redirect(url_for("index"))

    try:
        proto, port_str = port_identifier.split(":", 1)
        if (
            proto not in ["tcp", "udp"]
            or not port_str.isdigit()
            or not (0 < int(port_str) < 65536)
        ):
            raise ValueError("Invalid protocol or port number.")
    except ValueError as e:
        flash(
            f"Invalid port identifier: {escape(str(e))} ({escape(port_identifier)})",
            "warning",
        )
        return redirect(url_for("index"))

    # Proceed with modification
    config = read_config()
    current_whitelist_str = config.get("WHITELIST", "")
    # Use a set for easier manipulation and avoiding duplicates/order issues
    whitelist_set = set(
        item for item in current_whitelist_str.split() if item
    )  # Filter empty items

    modified = False
    if action == "add":
        if port_identifier in whitelist_set:
            flash(
                f"Port {escape(port_identifier)} is already in the whitelist.", "info"
            )
        else:
            whitelist_set.add(port_identifier)
            flash(f"Port {escape(port_identifier)} added to whitelist.", "success")
            modified = True

    elif action == "remove":
        if port_identifier not in whitelist_set:
            flash(
                f"Port {escape(port_identifier)} was not found in the whitelist.",
                "warning",
            )
        else:
            whitelist_set.remove(port_identifier)
            flash(f"Port {escape(port_identifier)} removed from whitelist.", "success")
            modified = True
    else:
        flash(f"Invalid whitelist action: {escape(action)}", "warning")

    # If modification happened, write config and restart service
    if modified:
        config["WHITELIST"] = " ".join(
            sorted(list(whitelist_set))
        )  # Sort for consistency
        if write_config(config):
            flash("Configuration saved. Restarting service...", "info")
            control_service("restart")
        else:
            flash(
                f"Failed to save whitelist change for {escape(port_identifier)} to config.",
                "danger",
            )
            # Don't restart if save failed

    return redirect(url_for("index"))


@app.route("/view_log")
def view_log():
    config = read_config()
    log_path = config.get("LOG_FILE", DEFAULT_LOG_FILE)
    # Show more lines on this dedicated page
    logs = read_log(lines=200)
    # Use the dedicated template
    return render_template("log_viewer.html", logs=logs, log_file=log_path)


@app.route("/share/start", methods=["POST"])
def share_start():
    port = request.form.get("port")
    if not port or not port.isdigit():
        flash("Invalid port for sharing.", "warning")
        return redirect(url_for("index"))
    port = int(port)
    url = start_share(port)
    if url:
        flash(f"Port {port} shared at {url}.", "success")
    else:
        flash(f"Failed to share port {port}.", "danger")
    return redirect(url_for("index"))


@app.route("/share/stop", methods=["POST"])
def share_stop():
    port = request.form.get("port")
    if not port or not port.isdigit():
        flash("Invalid port for stopping share.", "warning")
        return redirect(url_for("index"))
    port = int(port)
    pid, _, _ = stop_share(port)
    if pid is not None:
        flash(f"Stopped sharing port {port} (PID: {pid}).", "success")
    else:
        flash("No active port sharing found.", "info")
    return redirect(url_for("index"))


# --- Main Execution ---
if __name__ == "__main__":
    # Ensure Flask runs with permissions to execute systemctl and write to /etc
    # Typically, this means running the development server as root (NOT recommended for production)
    # or setting up proper sudo rules for the user running Flask.
    # For production, use a proper WSGI server (like Gunicorn or uWSGI) run via systemd
    # under a dedicated user with specific sudo privileges ONLY for the required commands.

    # host='0.0.0.0' makes it accessible externally, ensure firewall rules are in place if needed.
    # Use host='127.0.0.1' (default) to only allow access from the local machine for security.
    print(f"Flask App running with:")
    print(f"  - Template Folder: {os.path.abspath(app.template_folder)}")
    print(f"  - Static Folder: {os.path.abspath(app.static_folder)}")
    print(f"  - Config File: {CONFIG_FILE}")
    print(f"-----------------------------------------------------")
    print(f"WARNING: Running Flask development server.")
    print(f"         Use a production WSGI server (Gunicorn/uWSGI) for deployment.")
    print(f"WARNING: Ensure this process has permissions for:")
    print(f"         - Reading/Writing: {CONFIG_FILE}")
    print(
        f"         - Reading Log File (defined in config, default: {DEFAULT_LOG_FILE})"
    )
    print(f"         - Running: systemctl actions on {CORE_SERVICE_NAME}")
    print(f"         - Running: ss, ps, tail commands")
    print(f"-----------------------------------------------------")

    # Default to localhost for safety during development/testing
    app.run(
        host="127.0.0.1", port=6060, debug=False
    )  # Keep debug=False unless actively debugging
