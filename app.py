from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
import paramiko
import threading
import os
import io
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Required for flashing messages and session

# Database setup
def init_db():
    conn = sqlite3.connect('keys.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS keys
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  key TEXT UNIQUE,
                  proxy_limit INTEGER DEFAULT 0)''')
    conn.commit()
    conn.close()

init_db()

def normalize_ip_list(ip_input):
    """
    Normalize IP list input by replacing all delimiters (commas, spaces, newlines) with a single delimiter.
    """
    # Replace all delimiters with a comma
    normalized = ip_input.replace("\n", ",").replace(" ", ",")
    # Split into list and remove empty strings
    ip_list = [ip.strip() for ip in normalized.split(",") if ip.strip()]
    return ip_list


def load_key(key_file):
    """Load the key based on the file format (RSA or Ed25519)."""
    try:
        if key_file.endswith('.pem'):
            print(f"Using .pem file: {key_file}")
            key = paramiko.RSAKey.from_private_key_file(key_file)
        else:
            print("Unsupported key file format. Please provide a .pem file.")
            return None
    except Exception as e:
        print(f"Error loading key: {e}")
        return None
    return key


def run_command_on_ip(ip, ssh_client, command):
    """Run a command on a specific IP and return logs."""
    try:
        print(f"Running command on {ip}...")
        stdin, stdout, stderr = ssh_client.exec_command(command)
        
        # Capture output and errors
        output = stdout.read().decode()
        error = stderr.read().decode()
        print(f"Output from {ip}:\n{output}")
        print(f"Error from {ip}:\n{error}")

        # Wait for the command to complete
        while not stdout.channel.exit_status_ready():
            pass

        return output, error

    except Exception as e:
        print(f"Error executing command on {ip}: {e}")
        return None, str(e)


def connect_to_ips(ip_list, key_file, user_name, use_password=False, password=None):
    """Connect to a list of IPs and execute commands."""
    ssh_clients = {}  # Dictionary to hold SSH clients for each IP

    for ip in ip_list:
        print(f"Connecting to {ip}...")

        # Connect to the instance using paramiko
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            if use_password:
                # Use password-based authentication
                ssh_client.connect(hostname=ip, username=user_name, password=password)
            else:
                # Use key-based authentication
                key = load_key(key_file)
                if key is None:
                    continue
                ssh_client.connect(hostname=ip, username=user_name, pkey=key)

            print(f"Connected to {ip}")
            ssh_clients[ip] = ssh_client  # Store the SSH client

        except Exception as e:
            print(f"Error connecting to {ip}: {e}")
            flash(f"Error connecting to {ip}: {e}", "error")

    return ssh_clients


def generate_proxy_file(ip_list, port, proxy_username, proxy_password):
    """Generate a file with proxy details."""
    file_content = ""
    for ip in ip_list:
        file_content += f"{ip}:{port}:{proxy_username}:{proxy_password}\n"
    return file_content


@app.route("/", methods=["GET", "POST"])
def index():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    if request.method == "POST":
        # Clear previous logs from session
        session.pop("logs", None)
        session.pop("file_content", None)
        session.pop("file_name", None)

        # Get form data
        ip_input = request.form.get("ip_list").strip()
        username = request.form.get("username")
        custom_username = request.form.get("custom_username")
        auth_method = request.form.get("auth_method")
        key_file = request.files.get("key_file")
        password = request.form.get("password")

        # Use custom username if selected
        if username == "custom" and custom_username:
            username = custom_username
        elif username == "custom":
            flash("Custom username is required.", "error")
            return redirect(url_for("index"))

        # Normalize and clean the IP list
        ip_list = normalize_ip_list(ip_input)
        if not ip_list:
            flash("No valid IPs provided.", "error")
            return redirect(url_for("index"))

        # Handle authentication
        use_password = auth_method == "password"
        if use_password and not password:
            flash("Password is required for password-based authentication.", "error")
            return redirect(url_for("index"))
        elif not use_password and not key_file:
            flash("Key file is required for key-based authentication.", "error")
            return redirect(url_for("index"))

        # Save the key file if provided
        if key_file:
            key_file_path = os.path.join("uploads", key_file.filename)
            key_file.save(key_file_path)
        else:
            key_file_path = None

        # Connect to IPs
        ssh_clients = connect_to_ips(ip_list, key_file_path, username, use_password, password)

        # Perform actions based on user choice
        action = request.form.get("action")
        logs = {}  # Dictionary to store logs for each IP

        if action == "create_proxy":
            proxy_username = request.form.get("proxy_username")
            proxy_password = request.form.get("proxy_password")

            # Check limit
            conn = sqlite3.connect('keys.db')
            c = conn.cursor()
            c.execute("SELECT proxy_limit FROM keys WHERE key = ?", (session.get("key"),))
            proxy_limit = c.fetchone()[0]
            if proxy_limit < len(ip_list):
                flash("Limit exceeded. Not enough available proxies.", "error")
                return redirect(url_for("index"))

            # Decrease limit
            c.execute("UPDATE keys SET proxy_limit = proxy_limit - ? WHERE key = ?", (len(ip_list), session.get("key")))
            conn.commit()
            conn.close()

            commands = [
                "wget https://raw.githubusercontent.com/serverok/squid-proxy-installer/master/squid3-install.sh -O squid3-install.sh",
                "sudo bash squid3-install.sh",
                f"sudo /usr/bin/htpasswd -b -c /etc/squid/passwd {proxy_username} {proxy_password}"
            ]

            for command in commands:
                threads = []
                for ip, ssh_client in ssh_clients.items():
                    thread = threading.Thread(target=lambda: logs.update({ip: run_command_on_ip(ip, ssh_client, command)}))
                    thread.start()
                    threads.append(thread)

                for thread in threads:
                    thread.join()

            # Generate proxy file and download it directly
            file_content = generate_proxy_file(ip_list, 3128, proxy_username, proxy_password)
            file_name = "proxy_details.txt"

            # Store logs in session
            session["logs"] = logs

            # Close SSH connections
            for ip, ssh_client in ssh_clients.items():
                ssh_client.close()
                print(f"Disconnected from {ip}")

            # Send the file for download
            return send_file(
                io.BytesIO(file_content.encode()),
                as_attachment=True,
                download_name=file_name,
                mimetype="text/plain"
            )

        elif action == "port_change":
            new_port = request.form.get("new_port")

            commands = [
                f"sudo sed -i 's/^http_port.*$/http_port {new_port}/g' /etc/squid/squid.conf",
                "sudo systemctl restart squid",
                f"sudo ufw allow {new_port}/tcp"
            ]

            for command in commands:
                threads = []
                for ip, ssh_client in ssh_clients.items():
                    thread = threading.Thread(target=lambda: logs.update({ip: run_command_on_ip(ip, ssh_client, command)}))
                    thread.start()
                    threads.append(thread)

                for thread in threads:
                    thread.join()

            # Store IP list and new port for later use
            session["ip_list"] = ip_list
            session["new_port"] = new_port

            # Store logs in session
            session["logs"] = logs

            # Close SSH connections
            for ip, ssh_client in ssh_clients.items():
                ssh_client.close()
                print(f"Disconnected from {ip}")

            flash(f"Port updated to {new_port} and firewall updated for all IPs.", "success")
            return redirect(url_for("index"))

        elif action == "uninstall":
            command = "sudo squid-uninstall"

            threads = []
            for ip, ssh_client in ssh_clients.items():
                thread = threading.Thread(target=lambda: logs.update({ip: run_command_on_ip(ip, ssh_client, command)}))
                thread.start()
                threads.append(thread)

            for thread in threads:
                thread.join()

            flash("Squid proxy uninstalled successfully!", "success")

        return redirect(url_for("index"))

    # Retrieve logs from session
    logs = session.get("logs", {})
    return render_template("index.html", logs=logs)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        key = request.form.get("key")

        conn = sqlite3.connect('keys.db')
        c = conn.cursor()
        c.execute("SELECT * FROM keys WHERE key = ?", (key,))
        result = c.fetchone()
        conn.close()

        if result:
            session["logged_in"] = True
            session["key"] = key
            # Set is_admin to True if the key belongs to an admin
            session["is_admin"] = True  # You can customize this logic
            return redirect(url_for("index"))
        else:
            flash("Invalid key.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    session.pop("key", None)
    session.pop("is_admin", None)  # Clear admin status
    return redirect(url_for("login"))


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    # Check if the user is an admin (e.g., by checking a session variable)
    if not session.get("is_admin"):
        flash("You do not have permission to access the admin panel.", "error")
        return redirect(url_for("index"))

    if request.method == "POST":
        action = request.form.get("action")

        if action == "add_key":
            key = request.form.get("key")
            proxy_limit = request.form.get("proxy_limit")

            conn = sqlite3.connect('keys.db')
            c = conn.cursor()
            try:
                c.execute("INSERT INTO keys (key, proxy_limit) VALUES (?, ?)", (key, proxy_limit))
                conn.commit()
                flash("Key added successfully.", "success")
            except sqlite3.IntegrityError:
                flash("Key already exists.", "error")
            conn.close()

        elif action == "delete_key":
            key = request.form.get("key")

            conn = sqlite3.connect('keys.db')
            c = conn.cursor()
            c.execute("DELETE FROM keys WHERE key = ?", (key,))
            conn.commit()
            conn.close()
            flash("Key deleted successfully.", "success")

        elif action == "edit_limit":
            key = request.form.get("key")
            proxy_limit = request.form.get("proxy_limit")

            conn = sqlite3.connect('keys.db')
            c = conn.cursor()
            c.execute("UPDATE keys SET proxy_limit = ? WHERE key = ?", (proxy_limit, key))
            conn.commit()
            conn.close()
            flash("Limit updated successfully.", "success")

    # Retrieve all keys
    conn = sqlite3.connect('keys.db')
    c = conn.cursor()
    c.execute("SELECT * FROM keys")
    keys = c.fetchall()
    conn.close()

    return render_template("admin.html", keys=keys)


@app.route("/download_with_credentials", methods=["GET", "POST"])
def download_with_credentials():
    """Download the proxy file after prompting for credentials."""
    if request.method == "POST":
        proxy_username = request.form.get("proxy_username")
        proxy_password = request.form.get("proxy_password")

        if not proxy_username or not proxy_password:
            flash("Proxy Username and Proxy Password are required.", "error")
            return redirect(url_for("index"))

        # Retrieve IP list and new port from session
        ip_list = session.get("ip_list", [])
        new_port = session.get("new_port", 3128)

        # Generate the file content
        file_content = generate_proxy_file(ip_list, new_port, proxy_username, proxy_password)
        file_name = "proxy_details.txt"

        # Send the file for download
        return send_file(
            io.BytesIO(file_content.encode()),
            as_attachment=True,
            download_name=file_name,
            mimetype="text/plain"
        )

    return render_template("download_credentials.html")


if __name__ == "__main__":
    # Create uploads directory if it doesn't exist
    if not os.path.exists("uploads"):
        os.makedirs("uploads")

    app.run(debug=True)