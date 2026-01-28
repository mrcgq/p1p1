#!/usr/bin/env bash
#═══════════════════════════════════════════════════════════════════════════════
#                        Phantom Server v1.1 一键安装脚本
#                     战术级隐匿代理协议 - 快 · 稳 · 隐
#═══════════════════════════════════════════════════════════════════════════════

set -e

# ═══════════════════════════════════════════════════════════════════════════════
# 配置变量
# ═══════════════════════════════════════════════════════════════════════════════



PHANTOM_VERSION="1.1.1"
GITHUB_REPO="mrcgq/p1p1"
INSTALL_DIR="/opt/phantom"
CONFIG_DIR="/etc/phantom"
LOG_DIR="/var/log/phantom"
BINARY_NAME="phantom-server"
SERVICE_NAME="phantom"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# ═══════════════════════════════════════════════════════════════════════════════
# 辅助函数
# ═══════════════════════════════════════════════════════════════════════════════

print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                                                                       ║
    ║     ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗  ║
    ║     ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║  ║
    ║     ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║  ║
    ║     ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║  ║
    ║     ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║  ║
    ║     ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝  ║
    ║                                                                       ║
    ║                     战术级隐匿代理协议 v1.1                           ║
    ║                      快 · 稳 · 隐                                     ║
    ╚═══════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

confirm() {
    local prompt="$1"
    local default="${2:-N}"
    
    if [[ "$default" == "Y" ]]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi
    
    read -rp "$prompt" response
    response=${response:-$default}
    
    [[ "$response" =~ ^[Yy]$ ]]
}

# ═══════════════════════════════════════════════════════════════════════════════
# 系统检测
# ═══════════════════════════════════════════════════════════════════════════════

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要 root 权限运行"
        log_info "请使用: sudo bash $0"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    elif [[ -f /etc/redhat-release ]]; then
        OS="centos"
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
    else
        OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    fi
    
    log_info "检测到操作系统: ${OS} ${OS_VERSION:-}"
}

detect_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l|armv7)
            ARCH="armv7"
            ;;
        *)
            log_error "不支持的架构: $ARCH"
            exit 1
            ;;
    esac
    
    log_info "检测到系统架构: $ARCH"
}

check_dependencies() {
    local deps=("curl" "tar" "openssl")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warn "缺少依赖: ${missing[*]}"
        log_step "正在安装依赖..."
        
        case $OS in
            ubuntu|debian)
                apt-get update -qq
                apt-get install -y -qq "${missing[@]}"
                ;;
            centos|rhel|fedora|rocky|almalinux)
                yum install -y -q "${missing[@]}" || dnf install -y -q "${missing[@]}"
                ;;
            alpine)
                apk add --no-cache "${missing[@]}"
                ;;
            *)
                log_error "无法自动安装依赖，请手动安装: ${missing[*]}"
                exit 1
                ;;
        esac
    fi
    
    log_info "依赖检查完成"
}

get_public_ip() {
    local ip=""
    local services=(
        "https://api.ipify.org"
        "https://ifconfig.me/ip"
        "https://icanhazip.com"
        "https://ipinfo.io/ip"
        "https://api.ip.sb/ip"
    )
    
    for service in "${services[@]}"; do
        ip=$(curl -s --connect-timeout 5 "$service" 2>/dev/null | tr -d '[:space:]')
        if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    
    # 尝试 IPv6
    for service in "${services[@]}"; do
        ip=$(curl -6 -s --connect-timeout 5 "$service" 2>/dev/null | tr -d '[:space:]')
        if [[ -n "$ip" ]]; then
            echo "$ip"
            return 0
        fi
    done
    
    return 1
}

# ═══════════════════════════════════════════════════════════════════════════════
# 下载和安装
# ═══════════════════════════════════════════════════════════════════════════════

download_binary() {

    local download_url="https://github.com/${GITHUB_REPO}/releases/download/v${PHANTOM_VERSION}/${BINARY_NAME}-linux-${ARCH}.tar.gz"
    local temp_file="/tmp/${BINARY_NAME}.tar.gz"
    
    log_step "下载 Phantom Server v${VERSION}..."
    log_info "下载地址: $download_url"
    
    if ! curl -fSL --progress-bar -o "$temp_file" "$download_url"; then
        log_error "下载失败"
        
        # 尝试从 latest 下载
        log_info "尝试下载最新版本..."
        
        download_url="https://github.com/${GITHUB_REPO}/releases/download/v${PHANTOM_VERSION}/phantom-server-linux-${ARCH}"

        if ! curl -fSL --progress-bar -o "$temp_file" "$download_url"; then
            log_error "下载失败，请检查网络连接"
            exit 1
        fi
    fi
    
    log_info "下载完成"
    
    # 解压
    log_step "解压文件..."
    mkdir -p "$INSTALL_DIR"
    tar -xzf "$temp_file" -C "$INSTALL_DIR"
    
    # 查找并移动二进制文件
    if [[ -f "$INSTALL_DIR/${BINARY_NAME}" ]]; then
        chmod +x "$INSTALL_DIR/${BINARY_NAME}"
    elif [[ -f "$INSTALL_DIR/${BINARY_NAME}-linux-${ARCH}" ]]; then
        mv "$INSTALL_DIR/${BINARY_NAME}-linux-${ARCH}" "$INSTALL_DIR/${BINARY_NAME}"
        chmod +x "$INSTALL_DIR/${BINARY_NAME}"
    fi
    
    # 创建软链接
    ln -sf "$INSTALL_DIR/${BINARY_NAME}" "/usr/local/bin/${BINARY_NAME}"
    
    # 清理
    rm -f "$temp_file"
    
    log_info "安装完成: $INSTALL_DIR/${BINARY_NAME}"
}

# ═══════════════════════════════════════════════════════════════════════════════
# 配置生成
# ═══════════════════════════════════════════════════════════════════════════════

generate_psk() {
    openssl rand -base64 32
}

generate_config() {
    local psk="$1"
    local domain="${2:-}"
    local tcp_port="${3:-443}"
    local udp_port="${4:-54321}"
    local cert_file="${5:-}"
    local key_file="${6:-}"
    local tls_enabled="false"
    
    if [[ -n "$cert_file" && -n "$key_file" ]]; then
        tls_enabled="true"
    fi
    
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    
    cat > "$CONFIG_DIR/config.yaml" << EOF
#═══════════════════════════════════════════════════════════════════
# Phantom Server v${PHANTOM_VERSION} 配置文件
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')
#═══════════════════════════════════════════════════════════════════

# 监听配置
listen:
  address: "0.0.0.0"
  tcp_port: ${tcp_port}
  udp_port: ${udp_port}

# 认证配置
auth:
  # 预共享密钥 (Base64 编码, 32 字节)
  psk: "${psk}"
  # TSKD 时间窗口 (秒)
  time_window: 30

# TLS 配置
tls:
  enabled: ${tls_enabled}
  cert_file: "${cert_file}"
  key_file: "${key_file}"
  server_name: "${domain}"

# 前向纠错配置
fec:
  enabled: true
  mode: "adaptive"
  data_shards: 10
  fec_shards: 3
  min_parity: 1
  max_parity: 8
  target_loss: 0.01
  adjust_interval: 5s

# 多路复用配置
mux:
  enabled: true
  max_streams: 256
  stream_buffer: 65536
  keepalive_interval: 30s
  idle_timeout: 5m

# 代理配置
proxy:
  socks5:
    enabled: true
    udp_enabled: true
    udp_timeout: 60
  http:
    enabled: true

# 日志配置
log:
  level: "info"
  file: "${LOG_DIR}/server.log"
EOF

    chmod 600 "$CONFIG_DIR/config.yaml"
    log_info "配置文件已生成: $CONFIG_DIR/config.yaml"
}

# ═══════════════════════════════════════════════════════════════════════════════
# 证书管理
# ═══════════════════════════════════════════════════════════════════════════════

generate_self_signed_cert() {
    local domain="$1"
    local cert_dir="$CONFIG_DIR/ssl"
    
    mkdir -p "$cert_dir"
    
    log_step "生成自签名证书..."
    
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$cert_dir/key.pem" \
        -out "$cert_dir/cert.pem" \
        -subj "/CN=${domain}" \
        2>/dev/null
    
    chmod 600 "$cert_dir/key.pem"
    chmod 644 "$cert_dir/cert.pem"
    
    log_info "自签名证书已生成"
    echo "$cert_dir/cert.pem"
}

obtain_acme_cert() {
    local domain="$1"
    local email="$2"
    local cert_dir="$CONFIG_DIR/ssl"
    
    mkdir -p "$cert_dir"
    
    # 检查是否安装了 acme.sh
    if [[ ! -f ~/.acme.sh/acme.sh ]]; then
        log_step "安装 acme.sh..."
        curl -fsSL https://get.acme.sh | sh -s email="$email"
        source ~/.bashrc 2>/dev/null || true
    fi
    
    log_step "申请 Let's Encrypt 证书..."
    
    # 停止可能占用 80 端口的服务
    systemctl stop nginx 2>/dev/null || true
    systemctl stop apache2 2>/dev/null || true
    systemctl stop httpd 2>/dev/null || true
    
    if ~/.acme.sh/acme.sh --issue --standalone -d "$domain" \
        --fullchain-file "$cert_dir/cert.pem" \
        --key-file "$cert_dir/key.pem" \
        --force; then
        
        chmod 600 "$cert_dir/key.pem"
        chmod 644 "$cert_dir/cert.pem"
        
        log_info "证书申请成功"
        return 0
    else
        log_warn "证书申请失败，将使用自签名证书"
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Systemd 服务
# ═══════════════════════════════════════════════════════════════════════════════

install_systemd_service() {
    log_step "安装 systemd 服务..."
    
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=Phantom Server - 战术级隐匿代理协议
Documentation=https://github.com/${GITHUB_REPO}
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/${BINARY_NAME} run -c ${CONFIG_DIR}/config.yaml
Restart=always
RestartSec=5
LimitNOFILE=1048576
LimitNPROC=512

# 安全加固
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${LOG_DIR} ${CONFIG_DIR}
PrivateTmp=true

# 性能优化
Nice=-10
CPUSchedulingPolicy=rr
CPUSchedulingPriority=50

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}" --now 2>/dev/null || true
    
    log_info "Systemd 服务已安装"
}

# ═══════════════════════════════════════════════════════════════════════════════
# 防火墙配置
# ═══════════════════════════════════════════════════════════════════════════════

configure_firewall() {
    local tcp_port="$1"
    local udp_port="$2"
    
    log_step "配置防火墙..."
    
    # UFW (Ubuntu/Debian)
    if command -v ufw &> /dev/null; then
        ufw allow "$tcp_port/tcp" 2>/dev/null || true
        ufw allow "$udp_port/udp" 2>/dev/null || true
        log_info "UFW 规则已添加"
    fi
    
    # Firewalld (CentOS/RHEL/Fedora)
    if command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port="$tcp_port/tcp" 2>/dev/null || true
        firewall-cmd --permanent --add-port="$udp_port/udp" 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        log_info "Firewalld 规则已添加"
    fi
    
    # iptables
    if command -v iptables &> /dev/null; then
        iptables -I INPUT -p tcp --dport "$tcp_port" -j ACCEPT 2>/dev/null || true
        iptables -I INPUT -p udp --dport "$udp_port" -j ACCEPT 2>/dev/null || true
        
        # 保存规则
        if command -v iptables-save &> /dev/null; then
            iptables-save > /etc/iptables.rules 2>/dev/null || true
        fi
        log_info "iptables 规则已添加"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# 系统优化
# ═══════════════════════════════════════════════════════════════════════════════

optimize_system() {
    log_step "优化系统参数..."
    
    # 创建 sysctl 配置
    cat > /etc/sysctl.d/99-phantom.conf << 'EOF'
# Phantom Server 系统优化

# 网络性能优化
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.netdev_max_backlog = 65535
net.core.somaxconn = 65535

# TCP 优化
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_max_syn_backlog = 65535

# UDP 优化
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# 连接追踪
net.netfilter.nf_conntrack_max = 1048576
net.nf_conntrack_max = 1048576

# 文件描述符
fs.file-max = 2097152
fs.nr_open = 2097152
EOF

    # 应用配置
    sysctl -p /etc/sysctl.d/99-phantom.conf 2>/dev/null || true
    
    # 配置文件描述符限制
    cat > /etc/security/limits.d/99-phantom.conf << 'EOF'
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 65535
* hard nproc 65535
root soft nofile 1048576
root hard nofile 1048576
EOF

    log_info "系统优化完成"
}

# ═══════════════════════════════════════════════════════════════════════════════
# 生成分享链接
# ═══════════════════════════════════════════════════════════════════════════════

generate_share_link() {
    local psk="$1"
    local server="$2"
    local tcp_port="$3"
    local udp_port="$4"
    local tls="${5:-false}"
    
    local config_json=$(cat << EOF
{
  "version": 1,
  "server": "${server}",
  "tcp_port": ${tcp_port},
  "udp_port": ${udp_port},
  "psk": "${psk}",
  "tls": ${tls},
  "fec": "adaptive",
  "mux": true
}
EOF
)
    
    local encoded=$(echo -n "$config_json" | base64 -w 0)
    echo "phantom://${encoded}"
}

# ═══════════════════════════════════════════════════════════════════════════════
# 交互式安装
# ═══════════════════════════════════════════════════════════════════════════════

interactive_install() {
    echo ""
    echo -e "${WHITE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}                      配置向导${NC}"
    echo -e "${WHITE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # 获取服务器 IP
    log_step "获取服务器公网 IP..."
    SERVER_IP=$(get_public_ip)
    if [[ -z "$SERVER_IP" ]]; then
        read -rp "无法自动获取，请手动输入服务器 IP: " SERVER_IP
    else
        log_info "服务器 IP: $SERVER_IP"
    fi
    
    # 域名配置
    echo ""
    read -rp "请输入域名 (直接回车跳过，使用 IP): " DOMAIN
    DOMAIN=${DOMAIN:-$SERVER_IP}
    
    # 端口配置
    echo ""
    read -rp "TCP 端口 [默认: 443]: " TCP_PORT
    TCP_PORT=${TCP_PORT:-443}
    
    read -rp "UDP 端口 [默认: 54321]: " UDP_PORT
    UDP_PORT=${UDP_PORT:-54321}
    
    # TLS 配置
    CERT_FILE=""
    KEY_FILE=""
    TLS_ENABLED="false"
    
    if [[ "$DOMAIN" != "$SERVER_IP" ]]; then
        echo ""
        if confirm "是否申请 TLS 证书?" "Y"; then
            read -rp "请输入邮箱 (用于证书通知): " EMAIL
            EMAIL=${EMAIL:-"admin@${DOMAIN}"}
            
            if obtain_acme_cert "$DOMAIN" "$EMAIL"; then
                CERT_FILE="$CONFIG_DIR/ssl/cert.pem"
                KEY_FILE="$CONFIG_DIR/ssl/key.pem"
                TLS_ENABLED="true"
            else
                if confirm "是否使用自签名证书?" "Y"; then
                    generate_self_signed_cert "$DOMAIN"
                    CERT_FILE="$CONFIG_DIR/ssl/cert.pem"
                    KEY_FILE="$CONFIG_DIR/ssl/key.pem"
                    TLS_ENABLED="true"
                fi
            fi
        fi
    fi
    
    # 生成 PSK
    PSK=$(generate_psk)
    
    # 生成配置
    generate_config "$PSK" "$DOMAIN" "$TCP_PORT" "$UDP_PORT" "$CERT_FILE" "$KEY_FILE"
    
    # 配置防火墙
    if confirm "是否配置防火墙?" "Y"; then
        configure_firewall "$TCP_PORT" "$UDP_PORT"
    fi
    
    # 系统优化
    if confirm "是否优化系统参数?" "Y"; then
        optimize_system
    fi
    
    # 安装服务
    install_systemd_service
    
    # 启动服务
    log_step "启动服务..."
    systemctl restart "${SERVICE_NAME}"
    sleep 2
    
    # 检查服务状态
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        log_info "服务启动成功"
    else
        log_error "服务启动失败，请检查日志: journalctl -u ${SERVICE_NAME} -f"
    fi
    
    # 生成分享链接
    SHARE_LINK=$(generate_share_link "$PSK" "$DOMAIN" "$TCP_PORT" "$UDP_PORT" "$TLS_ENABLED")
    
    # 打印结果
    print_result
}

# ═══════════════════════════════════════════════════════════════════════════════
# 快速安装
# ═══════════════════════════════════════════════════════════════════════════════

quick_install() {
    log_step "快速安装模式..."
    
    # 获取服务器 IP
    SERVER_IP=$(get_public_ip)
    if [[ -z "$SERVER_IP" ]]; then
        log_error "无法获取服务器 IP"
        exit 1
    fi
    
    DOMAIN="$SERVER_IP"
    TCP_PORT="443"
    UDP_PORT="54321"
    CERT_FILE=""
    KEY_FILE=""
    TLS_ENABLED="false"
    
    # 生成 PSK
    PSK=$(generate_psk)
    
    # 生成配置
    generate_config "$PSK" "$DOMAIN" "$TCP_PORT" "$UDP_PORT"
    
    # 配置防火墙
    configure_firewall "$TCP_PORT" "$UDP_PORT"
    
    # 系统优化
    optimize_system
    
    # 安装服务
    install_systemd_service
    
    # 启动服务
    systemctl restart "${SERVICE_NAME}"
    sleep 2
    
    # 生成分享链接
    SHARE_LINK=$(generate_share_link "$PSK" "$DOMAIN" "$TCP_PORT" "$UDP_PORT" "$TLS_ENABLED")
    
    # 打印结果
    print_result
}

# ═══════════════════════════════════════════════════════════════════════════════
# 打印结果
# ═══════════════════════════════════════════════════════════════════════════════

print_result() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              Phantom Server v${PHANTOM_VERSION} 安装完成！              ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${WHITE}┌─────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${WHITE}│  服务器信息                                                            │${NC}"
    echo -e "${WHITE}├─────────────────────────────────────────────────────────────────────────┤${NC}"
    printf "${WHITE}│  %-15s ${CYAN}%-55s${WHITE} │${NC}\n" "服务器地址:" "$DOMAIN"
    printf "${WHITE}│  %-15s ${CYAN}%-55s${WHITE} │${NC}\n" "服务器 IP:" "$SERVER_IP"
    printf "${WHITE}│  %-15s ${CYAN}%-55s${WHITE} │${NC}\n" "TCP 端口:" "$TCP_PORT"
    printf "${WHITE}│  %-15s ${CYAN}%-55s${WHITE} │${NC}\n" "UDP 端口:" "$UDP_PORT"
    printf "${WHITE}│  %-15s ${CYAN}%-55s${WHITE} │${NC}\n" "TLS:" "$TLS_ENABLED"
    echo -e "${WHITE}├─────────────────────────────────────────────────────────────────────────┤${NC}"
    printf "${WHITE}│  %-15s ${YELLOW}%-55s${WHITE} │${NC}\n" "PSK:" "$PSK"
    echo -e "${WHITE}├─────────────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${WHITE}│  功能状态                                                              │${NC}"
    echo -e "${WHITE}│    ${GREEN}✓${NC} TSKD 0-RTT 认证                                               ${WHITE}│${NC}"
    echo -e "${WHITE}│    ${GREEN}✓${NC} Adaptive FEC (动态冗余)                                       ${WHITE}│${NC}"
    echo -e "${WHITE}│    ${GREEN}✓${NC} SOCKS5 代理 (含 UDP ASSOCIATE)                                ${WHITE}│${NC}"
    echo -e "${WHITE}│    ${GREEN}✓${NC} HTTP 代理                                                     ${WHITE}│${NC}"
    echo -e "${WHITE}│    ${GREEN}✓${NC} 多路复用                                                      ${WHITE}│${NC}"
    echo -e "${WHITE}└─────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}客户端分享链接 (复制到客户端导入):${NC}"
    echo ""
    echo -e "${CYAN}$SHARE_LINK${NC}"
    echo ""
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${WHITE}管理命令:${NC}"
    echo -e "  ${GREEN}启动服务:${NC}  systemctl start ${SERVICE_NAME}"
    echo -e "  ${GREEN}停止服务:${NC}  systemctl stop ${SERVICE_NAME}"
    echo -e "  ${GREEN}重启服务:${NC}  systemctl restart ${SERVICE_NAME}"
    echo -e "  ${GREEN}查看状态:${NC}  systemctl status ${SERVICE_NAME}"
    echo -e "  ${GREEN}查看日志:${NC}  journalctl -u ${SERVICE_NAME} -f"
    echo ""
    echo -e "${WHITE}配置文件:${NC} ${CONFIG_DIR}/config.yaml"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# 卸载
# ═══════════════════════════════════════════════════════════════════════════════

uninstall() {
    echo ""
    log_warn "即将卸载 Phantom Server"
    
    if ! confirm "确定要卸载吗?" "N"; then
        log_info "取消卸载"
        exit 0
    fi
    
    log_step "停止服务..."
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    
    log_step "删除文件..."
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    rm -rf "$INSTALL_DIR"
    rm -f "/usr/local/bin/${BINARY_NAME}"
    
    if confirm "是否删除配置文件和日志?" "N"; then
        rm -rf "$CONFIG_DIR"
        rm -rf "$LOG_DIR"
    fi
    
    rm -f /etc/sysctl.d/99-phantom.conf
    rm -f /etc/security/limits.d/99-phantom.conf
    
    systemctl daemon-reload
    
    log_info "卸载完成"
}

# ═══════════════════════════════════════════════════════════════════════════════
# 更新
# ═══════════════════════════════════════════════════════════════════════════════

update() {
    log_step "更新 Phantom Server..."
    
    # 保存当前版本
    local current_version=""
    if [[ -f "$INSTALL_DIR/${BINARY_NAME}" ]]; then
        current_version=$("$INSTALL_DIR/${BINARY_NAME}" version 2>/dev/null | grep -oP 'v\d+\.\d+\.\d+' || echo "unknown")
    fi
    
    log_info "当前版本: $current_version"
    
    # 下载新版本
    download_binary
    
    # 重启服务
    log_step "重启服务..."
    systemctl restart "${SERVICE_NAME}"
    
    # 检查服务状态
    sleep 2
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        local new_version=$("$INSTALL_DIR/${BINARY_NAME}" version 2>/dev/null | grep -oP 'v\d+\.\d+\.\d+' || echo "unknown")
        log_info "更新完成: $current_version -> $new_version"
    else
        log_error "服务启动失败，请检查日志"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# 显示状态
# ═══════════════════════════════════════════════════════════════════════════════

show_status() {
    echo ""
    echo -e "${WHITE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}                   Phantom Server 状态${NC}"
    echo -e "${WHITE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # 版本信息
    if [[ -f "$INSTALL_DIR/${BINARY_NAME}" ]]; then
        echo -e "${WHITE}版本:${NC}"
        "$INSTALL_DIR/${BINARY_NAME}" version 2>/dev/null || echo "  未知"
        echo ""
    fi
    
    # 服务状态
    echo -e "${WHITE}服务状态:${NC}"
    systemctl status "${SERVICE_NAME}" --no-pager 2>/dev/null || echo "  服务未安装"
    echo ""
    
    # 端口监听
    echo -e "${WHITE}端口监听:${NC}"
    if command -v ss &> /dev/null; then
        ss -tlnp | grep -E "phantom|:443|:54321" || echo "  无监听端口"
    elif command -v netstat &> /dev/null; then
        netstat -tlnp | grep -E "phantom|:443|:54321" || echo "  无监听端口"
    fi
    echo ""
    
    # 配置文件
    echo -e "${WHITE}配置文件:${NC}"
    if [[ -f "$CONFIG_DIR/config.yaml" ]]; then
        echo "  $CONFIG_DIR/config.yaml"
    else
        echo "  未找到配置文件"
    fi
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# 主函数
# ═══════════════════════════════════════════════════════════════════════════════

main() {
    print_banner
    
    # 检查权限
    check_root
    
    # 解析参数
    case "${1:-}" in
        install|"")
            detect_os
            detect_arch
            check_dependencies
            download_binary
            interactive_install
            ;;
        quick)
            detect_os
            detect_arch
            check_dependencies
            download_binary
            quick_install
            ;;
        uninstall|remove)
            uninstall
            ;;
        update|upgrade)
            detect_os
            detect_arch
            update
            ;;
        status)
            show_status
            ;;
        help|-h|--help)
            echo ""
            echo "用法: $0 [命令]"
            echo ""
            echo "命令:"
            echo "  install   交互式安装 (默认)"
            echo "  quick     快速安装 (使用默认配置)"
            echo "  update    更新到最新版本"
            echo "  uninstall 卸载 Phantom Server"
            echo "  status    显示运行状态"
            echo "  help      显示帮助信息"
            echo ""
            ;;
        *)
            log_error "未知命令: $1"
            echo "使用 '$0 help' 查看帮助"
            exit 1
            ;;
    esac
}

# 运行主函数
main "$@"
