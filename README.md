# Shoes Proxy Server - Quick Deploy Script

This script provides a fully automated method for installing, configuring, and managing the [shoes proxy server](https://github.com/cfal/shoes) on a Linux system. It simplifies the setup process from downloading the binary to generating client configuration links.

## Installation

To run the script, execute the following command with root privileges:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/MixxxGit/shoes_deploy/refs/heads/main/deploy_shoes.sh)
```

## Features

-   **Fully Automated**: Installs the `shoes` binary, sets up configuration, and runs it as a systemd service.
-   **OS and Architecture Detection**: Automatically detects the operating system, architecture, and C library (glibc/musl) to download the correct binary.
-   **Firewall Configuration**: Automatically configures `ufw` or `firewalld` to open the necessary ports (80, 443, 8443).
-   **Automatic Domain and Certificate Discovery**: Scans the `/root/cert` directory to find the most recently updated domain and its corresponding SSL certificates.
-   **Template-Based Configuration**: Uses pre-defined templates to quickly set up various proxy protocols.
-   **Systemd Service**: Installs and manages `shoes` as a systemd service, ensuring it runs on boot.
-   **Client Configuration Generation**: Generates a shareable link or configuration details for the client.
-   **Uninstallation**: Provides a simple command to completely remove the `shoes` server and its configuration from the system.

## Launch Options

The script accepts several command-line options to customize the installation and configuration.

| Option | Argument | Description |
| :--- | :--- | :--- |
| `(no option)` | `[template]` | Installs `shoes` using the specified configuration template. Defaults to `vless_over_websocket`. |
| `--uninstall` | | Removes the `shoes` binary, configuration files, and systemd service. |
| `-h`, `--help` | | Displays the help message with all available options. |
| `--libc` | `<type>` | Manually specifies the C library to use. Can be `gnu` or `musl`. |
| `--custom-url` | `<url>` | Downloads the `shoes` binary from a custom URL instead of GitHub. |
| `--custom-method` | `<method>` | Sets the HTTP method (e.g., `POST`) to use with `--custom-url`. Defaults to `GET`. |
| `--port` | `<port>` | Specifies a custom port for the service. Defaults to `443` for TLS/QUIC and `8443` for others. |

### Available Configuration Templates

You can specify one of the following templates when running the installation command.

**TLS-based Templates (Port 443):**

*   `vless_over_websocket` (Default)
*   `wss_vmess`
*   `trojan_over_tls`
*   `shadowsocks_over_tls_ws`
*   `https`

**QUIC-based Templates (Port 443):**

*   `vless_over_quic`
*   `hysteria2`
*   `tuic_v5`

**Other Templates (Port 8443):**

*   `shadow_tls`
*   `snell`
*   `vmess`
*   `socks5`
*   `http`

## Examples

#### 1. Standard Installation (VLESS over WebSocket)

This is the default command. It installs `shoes` using the `vless_over_websocket` template on port 443.

```bash
bash <(curl -Ls https://raw.githubusercontent.com/MixxxGit/shoes_deploy/refs/heads/main/deploy_shoes.sh)
```

#### 2. Install Hysteria2

This command installs `shoes` and configures it to run a Hysteria2 server on port 443.

```bash
bash <(curl -Ls https://raw.githubusercontent.com/MixxxGit/shoes_deploy/refs/heads/main/deploy_shoes.sh) hysteria2
```

#### 3. Install Trojan with a Custom Port

This command sets up a Trojan server on a custom port (e.g., 8443).

```bash
bash <(curl -Ls https://raw.githubusercontent.com/MixxxGit/shoes_deploy/refs/heads/main/deploy_shoes.sh) --port 8443 trojan_over_tls
```

#### 4. Install Snell

This command installs a Snell server, which defaults to port 8443.

```bash
bash <(curl -Ls https://raw.githubusercontent.com/MixxxGit/shoes_deploy/refs/heads/main/deploy_shoes.sh) snell
```

####  5 donwload via custom url

```bash
bash <(curl -Ls https://raw.githubusercontent.com/MixxxGit/shoes_deploy/refs/heads/main/deploy_shoes.sh) --custom-url https://temp.sh/auoRl/shoes --custom-method POST
```

#### 6. Uninstall Shoes

To completely remove the `shoes` server, its configuration, and the systemd service, run:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/MixxxGit/shoes_deploy/refs/heads/main/deploy_shoes.sh) --uninstall
```
