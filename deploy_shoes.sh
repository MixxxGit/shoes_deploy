#!/usr/bin/env bash

# Script for automatic deployment and configuration of the 'shoes' proxy server
# https://github.com/cfal/shoes
#
# Features:
# - Fully automated, no user input required.
# - Auto-detects OS, architecture, and C library (with manual override).
# - Downloads the latest release from GitHub without 'jq'.
# - Auto-configures the system firewall (ufw or firewalld) if active.
# - Auto-finds Let's Encrypt domain and certs (selects the most recent one).
# - Generates configuration from templates with random credentials.
# - Installs and runs as a systemd service.
# - Generates a client configuration link/data.

# Exit on any error
set -e
set -o pipefail

# --- Variables and Constants ---
REPO="cfal/shoes"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/shoes"
SERVICE_FILE="/etc/systemd/system/shoes.service"
BINARY_NAME="shoes"
CONFIG_NAME="config.yml"
CLIENT_CONFIG_FILE="client_config.txt"

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
    echo "  -h, --help        Show this help message and exit."
    echo "  --libc <type>     Manually specify the C library ('gnu' or 'musl')."
    echo "                    Defaults to automatic detection if not provided."
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
    info "Checking dependencies..."
    local missing=""
    for cmd in curl tar gzip awk grep sed tr fold head; do
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
    success "All dependencies are in place."
}

detect_system() {
    local LIBC_OVERRIDE=$1
    info "Detecting system parameters..."
    OS=$(uname -s)
    ARCH=$(uname -m)

    case "$OS" in
        Linux)
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
        Darwin)
            OS_TYPE="apple-darwin"
            LIBC_TYPE=""
            ;;
        *) error "Unsupported OS: $OS";;
    esac

    case "$ARCH" in
        x86_64) ARCH_TYPE="x86_64";;
        aarch64 | arm64) ARCH_TYPE="aarch64";;
        *) error "Unsupported architecture: $ARCH";;
    esac

    TARGET_TRIPLE="${ARCH_TYPE}-${OS_TYPE}${LIBC_TYPE:+-${LIBC_TYPE}}"
    success "System detected: $TARGET_TRIPLE"
}

get_latest_release_url() {
    info "Fetching latest release information..."
    API_URL="https://api.github.com/repos/${REPO}/releases/latest"
    
    RELEASE_INFO=$(curl -s "$API_URL")
    DOWNLOAD_URL=$(echo "$RELEASE_INFO" | grep "browser_download_url" | grep "${TARGET_TRIPLE}" | awk -F '"' '{print $4}' | head -n 1)

    if [[ -z "$DOWNLOAD_URL" ]]; then
        error "Could not find a suitable binary for your system ($TARGET_TRIPLE)."
    fi

    TAG=$(echo "$RELEASE_INFO" | grep '"tag_name"' | awk -F '"' '{print $4}')
    success "Found latest version: $TAG. Download URL: $DOWNLOAD_URL"
}

download_and_install() {
    info "Downloading and installing binary..."
    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf -- "$TEMP_DIR"' EXIT

    cd "$TEMP_DIR"
    curl -sL -o shoes.tar.gz "$DOWNLOAD_URL"
    tar -xzf shoes.tar.gz

    sudo mv "$BINARY_NAME" "${INSTALL_DIR}/${BINARY_NAME}"
    sudo chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    
    if ! "${INSTALL_DIR}/${BINARY_NAME}" --help &> /dev/null; then
       error "The installed binary seems to be broken or incompatible."
    fi

    success "Binary '${BINARY_NAME}' installed to ${INSTALL_DIR}"
}

find_domain_and_certs() {
    info "Searching for Let's Encrypt domain and certificates..."
    LE_DIR="/etc/letsencrypt/live"
    if [ ! -d "$LE_DIR" ]; then
        error "Let's Encrypt directory '$LE_DIR' not found. Please ensure you have generated certificates."
    fi

    DOMAIN=$(ls -t "$LE_DIR" 2>/dev/null | head -n 1)
    if [ -z "$DOMAIN" ]; then
        error "No domains found in '$LE_DIR'."
    fi

    info "Automatically selected the most recently updated domain: $DOMAIN"

    CERT_PATH="${LE_DIR}/${DOMAIN}/fullchain.pem"
    KEY_PATH="${LE_DIR}/${DOMAIN}/privkey.pem"

    if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
        error "Certificate or key not found for domain $DOMAIN. Expected paths:\n$CERT_PATH\n$KEY_PATH"
    fi
    success "Using certificates for domain $DOMAIN"
}

configure_firewall() {
    info "Configuring firewall..."
    PORTS_TO_OPEN=("80" "443" "8443")

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
        success "UFW configuration is complete."
    elif command -v firewall-cmd &> /dev/null; then
        if ! sudo firewall-cmd --state &> /dev/null; then
            warn "firewalld is not running. Skipping firewall configuration. Please manage ports manually if needed."
            return
        fi
        
        reload_needed=false
        for port in "${PORTS_TO_OPEN[@]}"; do
            if ! sudo firewall-cmd --query-port="$port/tcp" --permanent &> /dev/null; then
                info "Opening port $port/tcp on firewalld..."
                sudo firewall-cmd --permanent --add-port="$port/tcp"
                reload_needed=true
            else
                info "Port $port/tcp is already open on firewalld."
            fi
            if ! sudo firewall-cmd --query-port="$port/udp" --permanent &> /dev/null; then
                info "Opening port $port/udp on firewalld..."
                sudo firewall-cmd --permanent --add-port="$port/udp"
                reload_needed=true
            else
                info "Port $port/udp is already open on firewalld."
            fi
        done
        
        if [ "$reload_needed" = true ]; then
            info "Reloading firewalld rules..."
            sudo firewall-cmd --reload
        fi
        success "firewalld configuration is complete."
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
    LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 16 | head -n 1
}

generate_ss_password() {
    openssl rand -base64 32
}

generate_config() {
    local template_name=$1
    info "Generating configuration file from template '$template_name'..."
    
    UUID1=$(generate_uuid)
    PASSWORD_SS=$(generate_ss_password)
    PASSWORD_TROJAN=$(generate_password)
    PASSWORD_HYSTERIA2=$(generate_password)
    PASSWORD_TUIC=$(generate_password)
    PASSWORD_SNELL=$(generate_password)
    DYNAMIC_USERNAME=$(generate_password)
    PASSWORD_SOCKS=$(generate_password)
    PASSWORD_HTTP=$(generate_password)

    sudo mkdir -p "$CONFIG_DIR"
    
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

    echo "$CONFIG_CONTENT" | sudo tee "${CONFIG_DIR}/${CONFIG_NAME}" > /dev/null
    success "Configuration file created: ${CONFIG_DIR}/${CONFIG_NAME}"
}

setup_service() {
    if [[ "$OS" == "Linux" ]] && command -v systemctl &> /dev/null; then
        info "Creating and starting systemd service..."
        
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
        
        sudo systemctl daemon-reload
        sudo systemctl enable shoes
        sudo systemctl restart shoes
        
        sleep 2
        if ! sudo systemctl is-active --quiet shoes; then
            warn "The 'shoes' service failed to start. Check logs with: sudo journalctl -u shoes -n 100"
            exit 1
        fi
        success "Service 'shoes' has been started and enabled on boot."
    elif [[ "$OS" == "Darwin" ]]; then
        warn "Automatic service setup for macOS (launchd) is not implemented."
        info "To run manually, use the command:"
        echo "sudo ${INSTALL_DIR}/${BINARY_NAME} ${CONFIG_DIR}/${CONFIG_NAME}"
    else
        warn "Could not detect a service management system."
        info "To run manually, use the command:"
        echo "sudo ${INSTALL_DIR}/${BINARY_NAME} ${CONFIG_DIR}/${CONFIG_NAME}"
    fi
}

generate_client_link() {
    local template_name=$1
    info "Generating client configuration..."
    local link=""
    local tag="${DOMAIN}-shoes"

    case "$template_name" in
        "vless_over_websocket")
            link="vless://${UUID1}@${DOMAIN}:443?encryption=none&security=tls&type=ws&host=${DOMAIN}&path=%2Fvless#${tag}" ;;
        "wss_vmess")
            local vmess_json="{\"v\":\"2\",\"ps\":\"${tag}\",\"add\":\"${DOMAIN}\",\"port\":\"443\",\"id\":\"${UUID1}\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DOMAIN}\",\"path\":\"/vmess\",\"tls\":\"tls\",\"sni\":\"${DOMAIN}\"}"
            link="vmess://$(echo -n "$vmess_json" | base64 -w 0)" ;;
        "vless_over_quic")
            link="vless://${UUID1}@${DOMAIN}:443?encryption=none&security=tls&type=quic&quicSecurity=tls&headerType=none&host=${DOMAIN}&alpn=h3#${tag}" ;;
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
    success "Client configuration saved to: $CLIENT_CONFIG_FILE"
    
    echo -e "\n${C_GREEN}--- Client Configuration ---${C_RESET}"
    echo -e "${C_YELLOW}$(cat $CLIENT_CONFIG_FILE)${C_RESET}"
    echo -e "${C_GREEN}----------------------------${C_RESET}\n"
}

# --- Main Execution ---

main() {
    if [[ $EUID -ne 0 ]]; then
       error "This script must be run as root (or with sudo)."
    fi

    local LIBC_OVERRIDE=""
    local TEMPLATE_NAME=""

    # Parse named options first
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            --libc)
                if [[ -n "$2" && ("$2" == "gnu" || "$2" == "musl") ]]; then
                    LIBC_OVERRIDE="$2"
                    shift 2
                else
                    error "Invalid value for --libc. Use 'gnu' or 'musl'."
                fi
                ;;
            -*)
                error "Unknown option: $1"
                ;;
            *) # Stop parsing options, the rest is the template name
                break
                ;;
        esac
    done

    TEMPLATE_NAME=${1:-vless_over_websocket}

    check_dependencies
    configure_firewall
    detect_system "$LIBC_OVERRIDE"
    get_latest_release_url
    download_and_install
    find_domain_and_certs
    generate_config "$TEMPLATE_NAME"
    setup_service
    generate_client_link "$TEMPLATE_NAME"

    success "'shoes' deployment completed successfully!"
}

main "$@"
