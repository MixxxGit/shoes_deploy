#!/usr/bin/env bash

# Script for automatic deployment and configuration of the 'shoes' proxy server
# https://github.com/cfal/shoes
#
# Features:
# - Fully automated, no user input required.
# - Skips download if the binary is already installed.
# - Auto-detects OS, architecture, and C library (with manual override).
# - Supports downloading from a custom URL with a custom HTTP method.
# - Downloads the latest release from GitHub without 'jq'.
# - Auto-configures the system firewall (ufw or firewalld) if active.
# - Auto-finds domain and certificates (selects the most recent one).
# - Generates clean, multi-line YAML configuration from templates.
# - Installs and runs as a systemd service.
# - Generates a client configuration link/data.

# --- Shell options for robust error handling ---
set -o errexit  # Exit on command failure (same as -e)
set -o nounset  # Exit on unset variables
set -o pipefail # Exit on pipe failures
set -o errtrace # Inherit traps in functions

# --- Trap for debugging silent errors ---
trap 'echo "ERROR: Script failed at line $LINENO with command: $BASH_COMMAND" >&2' ERR

# --- Variables and Constants ---
REPO="cfal/shoes"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/shoes"
SERVICE_FILE="/etc/systemd/system/shoes.service"
BINARY_NAME="shoes"
CONFIG_NAME="config.yml"
CLIENT_CONFIG_FILE="client_config.txt"
CERT_BASE_DIR="/root/cert"

# --- Global System Variables ---
OS=""
ARCH=""
TARGET_TRIPLE=""
DOMAIN=""
CERT_PATH=""
KEY_PATH=""

# --- Colors for Output ---
C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_BLUE='\033[0;34m'
C_YELLOW='\033[0;33m'

# --- Logging Functions ---
info() { echo -e "${C_BLUE}INFO:${C_RESET} $1"; }
success() { echo -e "${C_GREEN}SUCCESS:${C_RESET} $1"; }
warn() { echo -e "${C_YELLOW}WARNING:${C_RESET} $1"; }
error() { echo -e "${C_RED}ERROR:${C_RESET} $1" >&2; exit 1; }

# --- Main Functions ---

show_help() {
    echo "Script for automatic deployment of the 'shoes' proxy server."
    echo ""
    echo "Usage: $0 [OPTIONS] [CONFIG_TEMPLATE]"
    echo ""
    echo "Options:"
    echo "  -h, --help                Show this help message and exit."
    echo "  --libc <type>             Manually specify the C library ('gnu' or 'musl'). Defaults to auto-detection."
    echo "  --custom-url <url>        Download the binary directly from a custom URL, bypassing GitHub detection."
    echo "  --custom-method <method>  HTTP method to use with --custom-url (e.g., POST). Defaults to GET."
    echo ""
    echo "Configuration Templates (default: vless_over_websocket):"
    echo "  vless_over_websocket       - VLESS over WebSocket with TLS (recommended)"
    echo "  wss_vmess                  - VMess over WebSocket with TLS"
    echo "  trojan_over_tls            - Trojan over TLS"
    echo "  shadowsocks_over_tls_ws    - Shadowsocks (2022) over WebSocket with TLS"
    echo "  https                      - HTTPS Proxy (HTTP over TLS)"
    echo "  vless_over_quic            - VLESS over QUIC"
    echo "  hysteria2                  - Hysteria2 (requires QUIC/UDP)"
    echo "  tuic_v5                    - TUIC v5 (requires QUIC/UDP)"
    echo "  shadow_tls                 - ShadowTLS v3 (with SOCKS5 as inner protocol)"
    echo "  snell                      - Snell v3 (over TCP)"
    echo "  vmess                      - VMess over TCP"
    echo "  socks5                     - SOCKS5 Proxy (unencrypted)"
    echo "  http                       - HTTP Proxy (unencrypted)"
    echo ""
    echo "This script must be run as root (or with sudo)."
}

check_dependencies() {
    info "Step: Checking dependencies..."
    local missing=""
    for cmd in curl tar gzip awk grep sed tr head; do
        if ! command -v "$cmd" &> /dev/null; then
            missing="$missing $cmd"
        fi
    done
    if [[ -n "$missing" ]]; then
        error "Required utilities not found:$missing. Please install them."
    fi
    if ! command -v uuidgen &> /dev/null && ! command -v openssl &> /dev/null; then
        error "Either 'uuidgen' or 'openssl' is required to generate UUIDs."
    fi
    success "Step complete: All dependencies are in place."
}

detect_system() {
    local LIBC_OVERRIDE=$1
    info "Step: Detecting system parameters..."
    OS=$(uname -s)
    ARCH=$(uname -m)
    local OS_TYPE=""
    local ARCH_TYPE=""
    local LIBC_TYPE=""

    case "$OS" in
        "Linux")
            OS_TYPE="unknown-linux"
            if [[ -n "$LIBC_OVERRIDE" ]]; then
                LIBC_TYPE="$LIBC_OVERRIDE"
                info "Using user-provided LIBC override: '$LIBC_TYPE'"
            elif ldd --version 2>/dev/null | grep -q "musl"; then
                LIBC_TYPE="musl"
            else
                LIBC_TYPE="gnu"
            fi
            ;;
        "Darwin")
            OS_TYPE="apple-darwin"
            LIBC_TYPE=""
            ;;
        *)
            error "Unsupported OS: $OS"
            ;;
    esac

    case "$ARCH" in
        "x86_64")
            ARCH_TYPE="x86_64"
            ;;
        "aarch64" | "arm64")
            ARCH_TYPE="aarch64"
            ;;
        *)
            error "Unsupported architecture: $ARCH"
            ;;
    esac

    TARGET_TRIPLE="${ARCH_TYPE}-${OS_TYPE}${LIBC_TYPE:+-${LIBC_TYPE}}"
    success "Step complete: System detected as $TARGET_TRIPLE"
}

get_latest_release_url() {
    info "Step: Fetching latest release information from GitHub..."
    local API_URL="https://api.github.com/repos/${REPO}/releases/latest"
    
    local RELEASE_INFO
    RELEASE_INFO=$(curl -s "$API_URL")
    
    DOWNLOAD_URL=$(echo "$RELEASE_INFO" | grep "browser_download_url" | grep "${TARGET_TRIPLE}" | awk -F '"' '{print $4}' | head -n 1)
    
    if [[ -z "$DOWNLOAD_URL" ]]; then
        error "Could not find a suitable binary for your system ($TARGET_TRIPLE)."
    fi

    local TAG
    TAG=$(echo "$RELEASE_INFO" | grep '"tag_name"' | awk -F '"' '{print $4}')
    success "Step complete: Found latest version: $TAG"
    # Return value through global variable
    _DOWNLOAD_URL=$DOWNLOAD_URL
}

download_and_install() {
    local custom_url=$1
    local custom_method=$2
    
    info "Step: Downloading and installing binary..."
    local TEMP_DIR
    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf -- "$TEMP_DIR"' EXIT
    cd "$TEMP_DIR"

    if [[ -n "$custom_url" ]]; then
        info "Using custom URL: $custom_url with method $custom_method"
        curl -sL -X "$custom_method" -o "$BINARY_NAME" "$custom_url"
    else
        info "Downloading from official GitHub release: $_DOWNLOAD_URL"
        curl -sL -o shoes.tar.gz "$_DOWNLOAD_URL"
        tar -xzf shoes.tar.gz
    fi
    
    info "Moving binary to ${INSTALL_DIR}..."
    sudo mv "$BINARY_NAME" "${INSTALL_DIR}/${BINARY_NAME}"
    sudo chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    
    info "Verifying installed binary..."
    if ! "${INSTALL_DIR}/${BINARY_NAME}" --help &> /dev/null; then
       error "The installed binary seems to be broken or incompatible. If you used --custom-url, ensure the binary is correct."
    fi
    success "Step complete: Binary '${BINARY_NAME}' installed to ${INSTALL_DIR}"
}

find_domain_and_certs() {
    info "Step: Searching for domain and certificates in '$CERT_BASE_DIR'..."
    if [ ! -d "$CERT_BASE_DIR" ]; then
        error "Certificate directory '$CERT_BASE_DIR' not found. Please ensure your certificates are in this directory."
    fi

    DOMAIN=$(find "$CERT_BASE_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr | head -n 1 | cut -d' ' -f2- | xargs basename)
    
    if [ -z "$DOMAIN" ]; then
        error "No domain subdirectories found in '$CERT_BASE_DIR'."
    fi

    info "Automatically selected the most recently updated domain: $DOMAIN"
    
    if [ -f "${CERT_BASE_DIR}/${DOMAIN}/fullchain.cer" ]; then
        CERT_PATH="${CERT_BASE_DIR}/${DOMAIN}/fullchain.cer"
    elif [ -f "${CERT_BASE_DIR}/${DOMAIN}/fullchain.pem" ]; then
        CERT_PATH="${CERT_BASE_DIR}/${DOMAIN}/fullchain.pem"
    else
        error "fullchain certificate not found for domain $DOMAIN in ${CERT_BASE_DIR}/${DOMAIN}/"
    fi
    
    if [ -f "${CERT_BASE_DIR}/${DOMAIN}/${DOMAIN}.key" ]; then
        KEY_PATH="${CERT_BASE_DIR}/${DOMAIN}/${DOMAIN}.key"
    elif [ -f "${CERT_BASE_DIR}/${DOMAIN}/privkey.pem" ]; then
        KEY_PATH="${CERT_BASE_DIR}/${DOMAIN}/privkey.pem"
    else
        error "Private key not found for domain $DOMAIN in ${CERT_BASE_DIR}/${DOMAIN}/"
    fi
    
    success "Step complete: Using certificates for domain $DOMAIN"
}

configure_firewall() {
    info "Step: Configuring firewall..."
    local PORTS_TO_OPEN=("80" "443" "8443")
    if command -v ufw &> /dev/null; then
        if ! sudo ufw status | grep -q "Status: active"; then
            warn "UFW is inactive. Skipping firewall configuration. Please manage ports manually if needed."
            return
        fi
        for port in "${PORTS_TO_OPEN[@]}"; do
            if ! sudo ufw status | grep -qw "$port"; then
                info "Opening port $port on UFW..."
                sudo ufw allow "$port/tcp"
                sudo ufw allow "$port/udp"
            else
                info "Port $port is already open on UFW."
            fi
        done
        success "Step complete: UFW configuration finished."
    elif command -v firewall-cmd &> /dev/null; then
        if ! sudo firewall-cmd --state &> /dev/null; then
            warn "firewalld is not running. Skipping firewall configuration. Please manage ports manually if needed."
            return
        fi
        local reload_needed=false
        for port in "${PORTS_TO_OPEN[@]}"; do
            if ! sudo firewall-cmd --query-port="$port/tcp" --permanent &> /dev/null; then
                info "Opening port $port/tcp..."
                sudo firewall-cmd --permanent --add-port="$port/tcp"
                reload_needed=true
            else
                info "Port $port/tcp is already open."
            fi
            if ! sudo firewall-cmd --query-port="$port/udp" --permanent &> /dev/null; then
                info "Opening port $port/udp..."
                sudo firewall-cmd --permanent --add-port="$port/udp"
                reload_needed=true
            else
                info "Port $port/udp is already open."
            fi
        done
        if [ "$reload_needed" = true ]; then
            info "Reloading firewalld rules..."
            sudo firewall-cmd --reload
        fi
        success "Step complete: firewalld configuration finished."
    else
        warn "Could not detect UFW or firewalld. Please open ports 80, 443, 8443 (TCP & UDP) manually."
    fi
}

generate_uuid() {
    if command -v uuidgen &> /dev/null; then
        uuidgen
    else
        openssl rand -hex 16 | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/'
    fi
}

generate_password() {
    head -c 32 /dev/urandom | LC_ALL=C tr -dc 'a-zA-Z0-9' | head -c 16
}

generate_ss_password() {
    openssl rand -base64 32
}

generate_config() {
    local template_name=$1
    info "Step: Generating configuration file from template '$template_name'..."
    
    info "Generating credentials..."
    local UUID1=$(generate_uuid)
    local PASSWORD_SS=$(generate_ss_password)
    local PASSWORD_TROJAN=$(generate_password)
    local PASSWORD_HYSTERIA2=$(generate_password)
    local PASSWORD_TUIC=$(generate_password)
    local PASSWORD_SNELL=$(generate_password)
    local DYNAMIC_USERNAME=$(generate_password)
    local PASSWORD_SOCKS=$(generate_password)
    local PASSWORD_HTTP=$(generate_password)
    info "Credentials generated."

    info "Creating config directory ${CONFIG_DIR}..."
    sudo mkdir -p "$CONFIG_DIR"
    
    info "Selecting template content..."
    local CONFIG_CONTENT=""
    case "$template_name" in
        "vless_over_websocket")
            CONFIG_CONTENT=$(cat <<EOF
- bind_location: "0.0.0.0:443"
  protocol:
    type: tls
    sni_targets:
      "__DOMAIN__":
        cert: "__CERT_PATH__"
        key: "__KEY_PATH__"
        protocol:
          type: websocket
          targets:
            - matching_path: "/vless"
              protocol:
                type: vless
                user_id: "__UUID1__"
EOF
            ) ;;
        "wss_vmess")
            CONFIG_CONTENT=$(cat <<EOF
- bind_location: "0.0.0.0:443"
  protocol:
    type: tls
    sni_targets:
      "__DOMAIN__":
        cert: "__CERT_PATH__"
        key: "__KEY_PATH__"
        protocol:
          type: ws
          targets:
            - matching_path: /vmess
              protocol:
                type: vmess
                cipher: auto
                user_id: "__UUID1__"
EOF
            ) ;;
        "trojan_over_tls")
             CONFIG_CONTENT=$(cat <<EOF
- bind_location: "0.0.0.0:443"
  protocol:
    type: tls
    sni_targets:
      "__DOMAIN__":
        cert: "__CERT_PATH__"
        key: "__KEY_PATH__"
        protocol:
          type: trojan
          password: "__PASSWORD_TROJAN__"
EOF
            ) ;;
        "shadowsocks_over_tls_ws")
             CONFIG_CONTENT=$(cat <<EOF
- bind_location: "0.0.0.0:443"
  protocol:
    type: tls
    sni_targets:
      "__DOMAIN__":
        cert: "__CERT_PATH__"
        key: "__KEY_PATH__"
        protocol:
          type: ws
          targets:
          - matching_path: /shadowsocks
            protocol:
              type: shadowsocks
              cipher: 2022-blake3-aes-256-gcm
              password: "__PASSWORD_SS__"
EOF
            ) ;;
        "https")
             CONFIG_CONTENT=$(cat <<EOF
- bind_location: "0.0.0.0:443"
  protocol:
    type: tls
    sni_targets:
      "__DOMAIN__":
        cert: "__CERT_PATH__"
        key: "__KEY_PATH__"
        protocol:
          type: http
          username: "__USERNAME__"
          password: "__PASSWORD_HTTP__"
EOF
            ) ;;
        "vless_over_quic")
             CONFIG_CONTENT=$(cat <<EOF
- bind_location: "0.0.0.0:443"
  transport: quic
  quic_settings:
    cert: "__CERT_PATH__"
    key: "__KEY_PATH__"
    alpn_protocols: ["h3"]
  protocol:
    type: vless
    user_id: "__UUID1__"
EOF
            ) ;;
        "hysteria2")
             CONFIG_CONTENT=$(cat <<EOF
- bind_location: "0.0.0.0:443"
  transport: quic
  quic_settings:
    cert: "__CERT_PATH__"
    key: "__KEY_PATH__"
    alpn_protocols: ["h3"]
  protocol:
    type: hysteria2
    password: "__PASSWORD_HYSTERIA2__"
EOF
            ) ;;
        "tuic_v5")
             CONFIG_CONTENT=$(cat <<EOF
- bind_location: "0.0.0.0:443"
  transport: quic
  quic_settings:
    cert: "__CERT_PATH__"
    key: "__KEY_PATH__"
  protocol:
    type: tuicv5
    uuid: "__UUID1__"
    password: "__PASSWORD_TUIC__"
EOF
            ) ;;
        "shadow_tls")
             CONFIG_CONTENT=$(cat <<EOF
- bind_location: "0.0.0.0:443"
  protocol:
    type: tls
    shadowtls_targets:
      __DOMAIN__:
        password: "__PASSWORD_TROJAN__"
        handshake:
          cert: "__CERT_PATH__"
          key: "__KEY_PATH__"
        protocol:
          type: socks
          username: "__USERNAME__"
          password: "__PASSWORD_SOCKS__"
EOF
            ) ;;
        "snell")
             CONFIG_CONTENT=$(cat <<EOF
- bind_location: "0.0.0.0:8443"
  protocol:
    type: snell
    cipher: aes-256-gcm
    password: "__PASSWORD_SNELL__"
EOF
            ) ;;
        "vmess")
             CONFIG_CONTENT=$(cat <<EOF
- bind_location: "0.0.0.0:8443"
  protocol:
    type: vmess
    cipher: auto
    user_id: "__UUID1__"
EOF
            ) ;;
        "socks5")
             CONFIG_CONTENT=$(cat <<EOF
- bind_location: "0.0.0.0:8443"
  protocol:
    type: socks
    username: "__USERNAME__"
    password: "__PASSWORD_SOCKS__"
EOF
            ) ;;
        "http")
             CONFIG_CONTENT=$(cat <<EOF
- bind_location: "0.0.0.0:8443"
  protocol:
    type: http
    username: "__USERNAME__"
    password: "__PASSWORD_HTTP__"
EOF
            ) ;;
        *)
            error "Unknown configuration template: $template_name" ;;
    esac
    info "Template content selected."

    info "Replacing placeholders in the template..."
    CONFIG_CONTENT=$(echo "$CONFIG_CONTENT" | sed \
        -e "s|__DOMAIN__|${DOMAIN}|g" \
        -e "s|__CERT_PATH__|${CERT_PATH}|g" \
        -e "s|__KEY_PATH__|${KEY_PATH}|g" \
        -e "s|__UUID1__|${UUID1}|g" \
        -e "s|__USERNAME__|${DYNAMIC_USERNAME}|g" \
        -e "s|__PASSWORD_SS__|${PASSWORD_SS}|g" \
        -e "s|__PASSWORD_TROJAN__|${PASSWORD_TROJAN}|g" \
        -e "s|__PASSWORD_HYSTERIA2__|${PASSWORD_HYSTERIA2}|g" \
        -e "s|__PASSWORD_TUIC__|${PASSWORD_TUIC}|g" \
        -e "s|__PASSWORD_SNELL__|${PASSWORD_SNELL}|g" \
        -e "s|__PASSWORD_SOCKS__|${PASSWORD_SOCKS}|g" \
        -e "s|__PASSWORD_HTTP__|${PASSWORD_HTTP}|g" \
    )
    info "Placeholders replaced."

    info "Writing configuration to ${CONFIG_DIR}/${CONFIG_NAME}..."
    echo "$CONFIG_CONTENT" | sudo tee "${CONFIG_DIR}/${CONFIG_NAME}" > /dev/null
    success "Step complete: Configuration file created."

    # Export variables for client link generation
    export UUID1 PASSWORD_SS PASSWORD_TROJAN PASSWORD_HYSTERIA2 PASSWORD_TUIC PASSWORD_SNELL DYNAMIC_USERNAME PASSWORD_SOCKS PASSWORD_HTTP
}

setup_service() {
    info "Step: Setting up system service..."
    if [[ "$OS" == "Linux" ]] && command -v systemctl &> /dev/null; then
        info "Creating systemd service file..."
        local SERVICE_CONTENT
        SERVICE_CONTENT=$(cat <<EOF
[Unit]
Description=Shoes Proxy Server
After=network.target
[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/${BINARY_NAME} ${CONFIG_DIR}/${CONFIG_NAME}
Restart=on-failure
RestartSec=5s
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
EOF
        )
        echo "$SERVICE_CONTENT" | sudo tee "$SERVICE_FILE" > /dev/null
        
        info "Reloading systemd, enabling and restarting 'shoes' service..."
        sudo systemctl daemon-reload
        sudo systemctl enable shoes
        sudo systemctl restart shoes
        sleep 2
        
        info "Checking service status..."
        if ! sudo systemctl is-active --quiet shoes; then
            warn "The 'shoes' service failed to start. Check logs with: sudo journalctl -u shoes -n 100"
            exit 1
        fi
        success "Step complete: Service 'shoes' is running and enabled on boot."
    elif [[ "$OS" == "Darwin" ]]; then
        warn "Automatic service setup for macOS (launchd) is not implemented."
        info "To run manually, use: sudo ${INSTALL_DIR}/${BINARY_NAME} ${CONFIG_DIR}/${CONFIG_NAME}"
    else
        warn "Could not detect a service management system."
        info "To run manually, use: sudo ${INSTALL_DIR}/${BINARY_NAME} ${CONFIG_DIR}/${CONFIG_NAME}"
    fi
}

generate_client_link() {
    local template_name=$1
    info "Step: Generating client configuration..."
    local link=""
    local tag="${DOMAIN}-shoes"

    case "$template_name" in
        "vless_over_websocket")
            link="vless://${UUID1}@${DOMAIN}:443?encryption=none&security=tls&type=ws&host=${DOMAIN}&path=%2Fvless#${tag}" ;;
        "wss_vmess")
            local vmess_json="{\"v\":\"2\",\"ps\":\"${tag}\",\"add\":\"${DOMAIN}\",\"port\":\"443\",\"id\":\"${UUID1}\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DOMAIN}\",\"path\":\"/vmess\",\"tls\":\"tls\",\"sni\":\"${DOMAIN}\"}"
            link="vmess://$(echo -n "$vmess_json" | base64 -w 0)" ;;
        "trojan_over_tls")
            link="trojan://${PASSWORD_TROJAN}@${DOMAIN}:443?security=tls&sni=${DOMAIN}#${tag}" ;;
        "shadowsocks_over_tls_ws")
            local plugin_opts="tls;host=${DOMAIN};path=/shadowsocks"
            link="ss://$(echo -n "2022-blake3-aes-256-gcm:${PASSWORD_SS}" | base64 -w 0)@${DOMAIN}:443?plugin=v2ray-plugin;obfs=websocket;obfs-opts=${plugin_opts}#${tag}" ;;
        "hysteria2")
            link="hysteria2://${PASSWORD_HYSTERIA2}@${DOMAIN}:443?sni=${DOMAIN}&alpn=h3#${tag}" ;;
        "tuic_v5")
            link="tuic://${UUID1}:${PASSWORD_TUIC}@${DOMAIN}:443?sni=${DOMAIN}#${tag}-tuic5" ;;
        "https")
            link="http://${DYNAMIC_USERNAME}:${PASSWORD_HTTP}@${DOMAIN}:443#${tag}-https" ;;
        "http")
            link="http://${DYNAMIC_USERNAME}:${PASSWORD_HTTP}@${DOMAIN}:8443#${tag}-http" ;;
        "socks5")
            link="socks5://${DYNAMIC_USERNAME}:${PASSWORD_SOCKS}@${DOMAIN}:8443#${tag}-socks5" ;;
        "vmess")
             local vmess_json="{\"v\":\"2\",\"ps\":\"${tag}\",\"add\":\"${DOMAIN}\",\"port\":\"8443\",\"id\":\"${UUID1}\",\"aid\":\"0\",\"net\":\"tcp\",\"type\":\"none\",\"host\":\"${DOMAIN}\",\"tls\":\"\",\"sni\":\"\"}"
             link="vmess://$(echo -n "$vmess_json" | base64 -w 0)" ;;
        *)
            link="Automatic link generation is not supported for template '$template_name'.\nUse these parameters for manual configuration:"
            case "$template_name" in
                "shadow_tls")
                    link+="\nProtocol: ShadowTLS v3 + SOCKS5\nServer: ${DOMAIN}\nPort: 443"
                    link+="\nShadowTLS Password: ${PASSWORD_TROJAN}\nSNI: ${DOMAIN}"
                    link+="\nSOCKS5 Username: ${DYNAMIC_USERNAME}\nSOCKS5 Password: ${PASSWORD_SOCKS}"
                    ;;
                "snell")
                    link+="\nProtocol: Snell v3\nServer: ${DOMAIN}\nPort: 8443"
                    link+="\nPSK: ${PASSWORD_SNELL}\nCipher: aes-256-gcm"
                    ;;
            esac
            ;;
    esac

    echo -e "$link" | sudo tee "$CLIENT_CONFIG_FILE" > /dev/null
    success "Step complete: Client configuration saved to: $CLIENT_CONFIG_FILE"
    
    echo -e "\n${C_GREEN}--- Client Configuration ---${C_RESET}\n${C_YELLOW}$(cat "$CLIENT_CONFIG_FILE")${C_RESET}\n${C_GREEN}----------------------------${C_RESET}\n"
}

# --- Main Execution ---

main() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (or with sudo)."
    fi

    local LIBC_OVERRIDE=""
    local TEMPLATE_NAME=""
    local CUSTOM_URL=""
    local CUSTOM_METHOD="GET"
    local _DOWNLOAD_URL="" # For passing value from function

    # Parse named options first
    local temp_args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            --libc)
                if [[ -n "${2-}" && ("$2" == "gnu" || "$2" == "musl") ]]; then
                    LIBC_OVERRIDE="$2"
                    shift 2
                else
                    error "Invalid value for --libc. Use 'gnu' or 'musl'."
                fi
                ;;
            --custom-url)
                if [[ -n "${2-}" ]]; then
                    CUSTOM_URL="$2"
                    shift 2
                else
                    error "Missing value for --custom-url."
                fi
                ;;
            --custom-method)
                if [[ -n "${2-}" ]]; then
                    CUSTOM_METHOD="$2"
                    shift 2
                else
                    error "Missing value for --custom-method."
                fi
                ;;
            -*)
                error "Unknown option: $1"
                ;;
            *) # Collect positional arguments
                temp_args+=("$1")
                shift
                ;;
        esac
    done
    set -- "${temp_args[@]}" # Restore positional arguments

    TEMPLATE_NAME=${1:-vless_over_websocket}

    check_dependencies
    
    # System detection must happen early for OS-specific logic
    detect_system "$LIBC_OVERRIDE"

    if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        info "Binary '${BINARY_NAME}' already found at ${INSTALL_DIR}. Skipping download."
    else
        if [[ -z "$CUSTOM_URL" ]]; then
            get_latest_release_url
        fi
        download_and_install "$CUSTOM_URL" "$CUSTOM_METHOD"
    fi
    
    configure_firewall
    find_domain_and_certs
    generate_config "$TEMPLATE_NAME"
    setup_service
    generate_client_link "$TEMPLATE_NAME"

    success "'shoes' deployment completed successfully!"
}

main "$@"
