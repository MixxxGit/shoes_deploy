# Shoes Proxy Auto-Deploy Script

This script automates the deployment of the [`shoes`](https://github.com/cfal/shoes) multi-protocol proxy server on Linux (Ubuntu, AlmaLinux, etc.) and macOS. It is designed to be a "zero-touch" solution, handling everything from downloading the correct binary to generating configuration and setting up a system service.

## Features

-   **Fully Automated**: No interactive prompts. The script runs from start to finish without user input.
-   **System Auto-Detection**: Automatically detects the OS, CPU architecture (x86\_64/aarch64), and C library (GNU/musl) to download the correct release binary.
-   **Latest Version**: Fetches the latest version of `shoes` directly from GitHub releases.
-   **Automatic Firewall Configuration**: Detects and configures `ufw` (on Debian/Ubuntu) or `firewalld` (on RHEL/AlmaLinux) to open the necessary ports (80, 443, 8443).
-   **Certificate Discovery**: Automatically finds your domain and Let's Encrypt certificates in `/etc/letsencrypt/live`. If multiple domains are found, it selects the most recently updated one.
-   **Secure Credential Generation**: Generates random UUIDs, passwords, and usernames to ensure your proxy is secure out-of-the-box.
-   **Template-Based Configuration**: Uses pre-defined templates to generate a valid `config.yml` based on your chosen protocol.
-   **Systemd Service**: Installs and enables `shoes` as a `systemd` service on Linux for automatic startup on boot.
-   **Client Configuration Output**: Generates a client import link (e.g., for NekoBox) or connection details and prints them to the console upon completion.

## Requirements

1.  A server running a modern Linux distribution (like Ubuntu or AlmaLinux) or macOS.
2.  **Root** or `sudo` privileges.
3.  A registered domain name pointing to your server's public IP address.
4.  **Let's Encrypt certificates** must be already generated for your domain (e.g., using `certbot`). The script looks for them in `/etc/letsencrypt/live/`.
5.  Common utilities installed: `curl`, `tar`, `gzip`, `awk`, `grep`, `sed`, `openssl`.

## Quick Start

Run the following command as root to deploy `shoes` with the default configuration (VLESS over WebSocket).

```bash
sudo bash <(curl -Ls https://raw.githubusercontent.com/MixxxGit/shoes_deploy/refs/heads/main/deploy_shoes.sh)
```

To deploy with a specific protocol template, pass the template name as an argument. For example, to set up Trojan:

```bash
sudo bash <(curl -Ls https://raw.githubusercontent.com/MixxxGit/shoes_deploy/refs/heads/main/deploy_shoes.sh) trojan_over_tls
```

## Usage

The script accepts an optional template name as an argument. If no template is provided, it defaults to `vless_over_websocket`.

### Syntax

```
deploy_shoes.sh [OPTIONS] [CONFIG_TEMPLATE]
```

### Options

-   `-h`, `--help`: Display the help message with a list of all available templates.

### Available Templates

-   `vless_over_websocket` (Default): VLESS over WebSocket with TLS on port 443.
-   `wss_vmess`: VMess over WebSocket with TLS on port 443.
-   `trojan_over_tls`: Trojan over TLS on port 443.
-   `shadowsocks_over_tls_ws`: Shadowsocks (2022 edition) over WebSocket with TLS on port 443.
-   `https`: A standard HTTPS proxy (HTTP over TLS) on port 443 with authentication.
-   `vless_over_quic`: VLESS over QUIC on port 443.
-   `hysteria2`: Hysteria2 protocol on port 443 (requires QUIC/UDP).
-   `tuic_v5`: TUIC v5 protocol on port 443 (requires QUIC/UDP).
-   `shadow_tls`: ShadowTLS v3 with a SOCKS5 inner protocol on port 443.
-   `snell`: Snell v3 protocol over TCP on port 8443.
-   `vmess`: Standard VMess over TCP on port 8443 (unencrypted transport).
-   `socks5`: Standard SOCKS5 proxy on port 8443 with authentication.
-   `http`: Standard HTTP proxy on port 8443 with authentication.

## What the Script Does

1.  **Checks Prerequisites**: Verifies root access and required system utilities.
2.  **Configures Firewall**: Opens ports 80, 443, and 8443 for TCP and UDP.
3.  **Detects System**: Determines the OS, architecture, and libc to build the correct release asset name.
4.  **Downloads `shoes`**: Fetches the latest release from GitHub, unpacks it, and installs the binary to `/usr/local/bin/shoes`.
5.  **Finds Certificates**: Scans `/etc/letsencrypt/live` and selects the most recently modified domain for configuration.
6.  **Generates Credentials**: Creates random UUIDs and passwords for the chosen protocol.
7.  **Creates Configuration**: Writes a `config.yml` file to `/etc/shoes/` using the selected template and generated values.
8.  **Installs Service (Linux only)**: Creates a `systemd` service file at `/etc/systemd/system/shoes.service`, enables it to start on boot, and starts it immediately.
9.  **Generates Client Config**: Creates a `client_config.txt` file with the import link or connection details and displays its content.

## Post-Installation

After the script completes, your `shoes` proxy server will be running.

-   **Client Configuration**: The import link/details are printed to the console and saved in `client_config.txt` in the directory where you ran the script.
-   **Service Management (Linux)**:
    -   Check the status of the service: `sudo systemctl status shoes`
    -   View live logs: `sudo journalctl -u shoes -f`
    -   Restart the service: `sudo systemctl restart shoes`
-   **Configuration File**: The main configuration is located at `/etc/shoes/config.yml`. If you make manual changes, restart the service to apply them.

## Uninstallation

To remove `shoes` and its related files, run the following commands:

```bash
# Stop and disable the service (on Linux)
sudo systemctl stop shoes
sudo systemctl disable shoes

# Remove files
sudo rm /etc/systemd/system/shoes.service
sudo rm /usr/local/bin/shoes
sudo rm -rf /etc/shoes

# Reload systemd
sudo systemctl daemon-reload
```

**Note**: This will not close the ports in your firewall or remove your Let's Encrypt certificates.

## License

This script is released under the MIT License.
