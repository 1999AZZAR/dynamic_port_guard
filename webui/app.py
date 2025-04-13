import subprocess
import os
import shlex
from flask import Flask, render_template, redirect, url_for, request, flash

# --- Determine Folders FIRST ---
# Get the directory where this script resides
script_dir = os.path.dirname(os.path.abspath(__file__))
# Define template and static folder paths relative to the script directory
template_folder = os.path.join(script_dir, "templates")
static_folder = os.path.join(
    script_dir, "static"
)  # Assuming you might have a static folder too

# Check if template folder exists (optional but good practice)
if not os.path.isdir(template_folder):
    print(
        f"Warning: Template folder not found at {template_folder}. Using default 'templates'."
    )
    template_folder = "templates"  # Fallback

# --- Initialize Flask App with Folder Paths ---
app = Flask(__name__, template_folder=template_folder, static_folder=static_folder)
app.secret_key = os.urandom(24)  # Needed for flashing messages


# --- Configuration ---
CONFIG_FILE = "/etc/dynamic-port-guard.conf"
LOG_FILE = "/var/log/dynamic_ports.log"  # Default log file path if not in config
CORE_SERVICE_NAME = "dynamic-port-guard.service"
WEBUI_APP_DIR = "/opt/dynamic-port-webui"  # Ensure this matches install script


# --- Helper Functions ---


def run_command(command):
    """Runs a shell command and returns stdout, stderr, and return code."""
    try:
        # Use shell=False for security unless shell features are truly needed
        result = subprocess.run(
            shlex.split(command),
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        return "", f"Command not found: {shlex.split(command)[0]}", 127
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1


def get_listening_ports():
    """Gets currently listening ports using ss."""
    stdout, stderr, retcode = run_command("ss -tunlp")
    ports = []
    if retcode == 0 and stdout:
        lines = stdout.strip().split("\n")
        if len(lines) > 1:
            for line in lines[1:]:  # Skip header
                parts = line.split()
                if "LISTEN" not in parts:  # Ensure it's a listening socket
                    continue
                proto = parts[0]
                local_addr_port = parts[4]
                pid_info = (
                    parts[6] if len(parts) > 6 else "N/A"
                )  # users:(("name",pid=...))

                # Extract protocol more reliably
                if proto.startswith("tcp"):
                    proto = "tcp"
                elif proto.startswith("udp"):
                    proto = "udp"
                else:
                    continue  # Skip other types like u_str, etc.

                # Extract port robustly
                try:
                    if ":" in local_addr_port:
                        ip_port = local_addr_port.rsplit(":", 1)
                        port = ip_port[1]
                        ip = ip_port[0]
                        # Handle IPv6 brackets
                        if ip.startswith("[") and ip.endswith("]"):
                            ip = ip[1:-1]
                        # Handle wildcard IP
                        if ip == "0.0.0.0" or ip == "::" or ip == "*":
                            ip = "*"  # Represent wildcard consistently
                    else:  # Should not happen for listening TCP/UDP, but handle anyway
                        continue
                except IndexError:
                    continue  # Skip if parsing fails

                # Basic PID extraction
                pid = "N/A"
                if "pid=" in pid_info:
                    try:
                        pid = pid_info.split("pid=")[1].split(",")[0]
                    except IndexError:
                        pass  # Keep N/A if parsing fails

                ports.append({"proto": proto, "ip": ip, "port": port, "pid": pid})
    elif stderr:
        flash(f"Error getting listening ports: {stderr}", "danger")
    elif retcode != 0:
        flash(f"Failed to run 'ss -tunlp' (code: {retcode})", "danger")
    return ports


def read_config():
    """Reads the configuration file."""
    config = {}
    defaults = {  # Provide defaults if file or keys are missing
        "WHITELIST": "tcp:22 tcp:80 tcp:443",
        "CHECK_INTERVAL": "10",
        "FIREWALL_TOOL": "iptables",
        "LOG_FILE": "/var/log/dynamic_ports.log",
        "IPTABLES_CHAIN": "PORTGUARD_ALLOW",
    }
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip()
                        # Remove potential quotes around value
                        value = value.strip().strip('"').strip("'")
                        config[key] = value
        # Ensure all expected keys exist, using defaults if necessary
        for key, default_value in defaults.items():
            if key not in config:
                config[key] = default_value

    except Exception as e:
        flash(f"Error reading config file {CONFIG_FILE}: {e}", "danger")
        return defaults  # Return defaults on error
    return config


def write_config(config_dict):
    """Writes the configuration dictionary back to the file."""
    try:
        with open(CONFIG_FILE, "w") as f:
            f.write("# Configuration for Dynamic Port Guard\n\n")
            f.write("# Whitelist: Space-separated list of ports to always allow.\n")
            f.write(f'WHITELIST="{config_dict.get("WHITELIST", "")}"\n\n')
            f.write(
                "# Check Interval: How often (in seconds) to check for listening ports.\n"
            )
            f.write(f'CHECK_INTERVAL={config_dict.get("CHECK_INTERVAL", "10")}\n\n')
            f.write(
                "# Firewall Tool: Currently only 'iptables' is fully implemented.\n"
            )
            f.write(
                f'FIREWALL_TOOL="{config_dict.get("FIREWALL_TOOL", "iptables")}"\n\n'
            )
            f.write("# Log File: Path for operational logs.\n")
            f.write(
                f'LOG_FILE="{config_dict.get("LOG_FILE", "/var/log/dynamic_ports.log")}"\n\n'
            )
            f.write("# Dedicated Chain Name (iptables/ip6tables)\n")
            f.write(
                f'IPTABLES_CHAIN="{config_dict.get("IPTABLES_CHAIN", "PORTGUARD_ALLOW")}"\n'
            )
        # Set permissions to be readable by others potentially (like log readers) but writable only by root
        os.chmod(CONFIG_FILE, 0o644)
        return True
    except Exception as e:
        flash(f"Error writing config file {CONFIG_FILE}: {e}", "danger")
        return False


def control_service(action):
    """Controls the core systemd service."""
    if action not in ["start", "stop", "restart", "status"]:
        flash(f"Invalid service action: {action}", "warning")
        return False, "Invalid action"

    # Service runs as root, sudo is not needed here
    stdout, stderr, retcode = run_command(f"systemctl {action} {CORE_SERVICE_NAME}")

    if action == "status":
        # Return raw status output, Flask template will handle display
        return True, stdout + stderr

    if retcode == 0:
        flash(
            f"Service {CORE_SERVICE_NAME} action '{action}' executed successfully.",
            "success",
        )
        return True, f"Service {action} successful."
    else:
        flash(f"Error executing '{action}' on {CORE_SERVICE_NAME}: {stderr}", "danger")
        return False, stderr


def read_log(lines=50):
    """Reads the last N lines of the log file."""
    # Ensure log path comes from config, falling back to default
    log_path = read_config().get("LOG_FILE", LOG_FILE)
    if not os.path.exists(log_path):
        return f"Log file not found: {log_path}"
    try:
        # Use tail for efficiency if available
        stdout, stderr, retcode = run_command(f"tail -n {lines} {log_path}")
        if retcode == 0:
            return stdout
        elif retcode == 127:  # Command not found
            flash("Could not find 'tail' command to read logs efficiently.", "warning")
            # Fallback to Python read (less efficient for large files)
            with open(log_path, "r") as f:
                log_lines = f.readlines()
            return "".join(log_lines[-lines:])
        else:
            return f"Error reading log file with tail ({log_path}): {stderr}"

    except Exception as e:
        return f"Error reading log file {log_path}: {e}"


# --- Flask Routes ---


@app.route("/")
def index():
    ports = get_listening_ports()
    config = read_config()
    # Get status but don't flash messages from here
    _, status_output = control_service("status")
    logs = read_log(lines=50)
    return render_template(
        "index.html",
        ports=ports,
        config=config,
        service_status=status_output,
        logs=logs,
        core_service_name=CORE_SERVICE_NAME,
    )


@app.route("/update_config", methods=["POST"])
def update_config():
    current_config = read_config()  # Read current to preserve keys not in form
    new_config = current_config.copy()  # Start with current values

    # Update with form values if they exist
    new_config["WHITELIST"] = request.form.get(
        "whitelist", current_config.get("WHITELIST", "")
    )
    new_config["CHECK_INTERVAL"] = request.form.get(
        "check_interval", current_config.get("CHECK_INTERVAL", "10")
    )
    new_config["FIREWALL_TOOL"] = request.form.get(
        "firewall_tool", current_config.get("FIREWALL_TOOL", "iptables")
    )
    new_config["LOG_FILE"] = request.form.get(
        "log_file", current_config.get("LOG_FILE", "/var/log/dynamic_ports.log")
    )
    new_config["IPTABLES_CHAIN"] = request.form.get(
        "iptables_chain", current_config.get("IPTABLES_CHAIN", "PORTGUARD_ALLOW")
    )

    if write_config(new_config):
        flash("Configuration updated successfully.", "success")
        # Restart the core service to apply changes
        control_service("restart")
    else:
        flash("Failed to write configuration.", "danger")
        # No restart if write failed

    return redirect(url_for("index"))


@app.route("/service_action", methods=["POST"])
def service_action():
    action = request.form.get("action")
    control_service(action)  # Flash messages handled inside
    return redirect(url_for("index"))


@app.route("/view_log")
def view_log():
    # Simple route to view more logs if needed, or implement pagination later
    logs = read_log(lines=200)  # Show more lines on this dedicated page
    return f"<pre>{logs}</pre>"  # Basic preformatted text display


# --- Main Execution ---
if __name__ == "__main__":
    # The template/static folders are now set during app initialization above
    # Just run the app here
    app.run(host="0.0.0.0", port=6060, debug=False)  # Keep debug=False for production
