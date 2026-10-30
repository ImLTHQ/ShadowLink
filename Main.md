# Trojan

## 如何连接服务器
```
ssh 用户名@地址
```

## 脚本
```bash
bash <<'EOF'

set -Eeuo pipefail
umask 077

# ============================================================
# 基础检查
# ============================================================

# 绑定 443 等特权端口、安装程序和创建 systemd 服务均需要 root 权限。
if [[ "${EUID}" -ne 0 ]]; then
    echo "错误：请使用 root 用户运行此脚本。"
    exit 1
fi

echo
echo "========== sing-box 安装配置 =========="
echo

# ============================================================
# 读取用户配置
# ============================================================

# 输入域名：只填写域名，不要包含 https:// 或端口号。
read -r -p "请输入域名: " DOMAIN </dev/tty
DOMAIN="${DOMAIN%.}"
DOMAIN="${DOMAIN,,}"

# 检查域名格式，并拒绝将 IPv4 地址误当成域名。
if [[ ! "$DOMAIN" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] \
    || [[ "$DOMAIN" =~ ^[0-9.]+$ ]]; then
    echo "错误：域名格式不正确，请输入有效的域名。"
    exit 1
fi

# Trojan 密码同时用作 WS 路径，必须采用 URL 安全字符。
# 限制字符可避免 JSON 转义问题以及路径中的特殊字符问题。
read -r -s -p "请输入密码（16～128 位，仅限字母、数字、下划线、连字符）: " PASSWORD </dev/tty
echo

if [[ ! "$PASSWORD" =~ ^[A-Za-z0-9_-]{16,128}$ ]]; then
    echo "错误：密码必须为 16～128 位，只能使用字母、数字、_ 和 -。"
    exit 1
fi

# Cloudflare API Token 可留空。
# 推荐填写具有指定 Zone 的 DNS:Edit 和 Zone:Read 权限的 Token，
# 以便使用 DNS-01 验证，不需要开放 TCP 80 进行证书验证。
read -r -s -p "请输入 Cloudflare API Token（推荐填写，直接回车则使用 HTTP-01）: " CF_API_TOKEN </dev/tty
echo

# 防止 API Token 被意外拼接进 JSON。
# Cloudflare 常规 API Token 为 URL 安全字符串。
if [[ -n "$CF_API_TOKEN" ]] &&
   [[ ! "$CF_API_TOKEN" =~ ^[A-Za-z0-9_-]{20,256}$ ]]; then
    echo "错误：API Token 格式不符合预期，请检查输入。"
    exit 1
fi

# Hysteria2 的 Brutal 拥塞控制依赖合理的带宽配置。
# 请尽量填写服务器真实的上行、下行带宽；直接回车默认 100 Mbps。
read -r -p "服务器实际上行带宽（Mbps，默认 100）: " UP_MBPS </dev/tty
UP_MBPS="${UP_MBPS:-100}"

read -r -p "服务器实际下行带宽（Mbps，默认 100）: " DOWN_MBPS </dev/tty
DOWN_MBPS="${DOWN_MBPS:-100}"

# 带宽必须是 1～100000 之间的整数。
if [[ ! "$UP_MBPS" =~ ^[0-9]+$ ]] ||
   [[ ! "$DOWN_MBPS" =~ ^[0-9]+$ ]] ||
   (( UP_MBPS < 1 || UP_MBPS > 100000 ||
      DOWN_MBPS < 1 || DOWN_MBPS > 100000 )); then
    echo "错误：上下行带宽必须是 1～100000 之间的整数。"
    exit 1
fi

echo
echo "域名、密码及带宽参数检查通过。"

# ============================================================
# 选择 ACME 验证方式
# ============================================================

if [[ -n "$CF_API_TOKEN" ]]; then
    # DNS-01：通过 Cloudflare API 创建 DNS 验证记录。
    # 适合域名启用 Cloudflare 橙色云代理的情况。
    ACME_CHALLENGE_CONFIG="\"dns01_challenge\": {\"provider\": \"cloudflare\", \"api_token\": \"$CF_API_TOKEN\"}"
    ACME_MODE="Cloudflare DNS-01"
else
    # HTTP-01：不依赖单独的证书脚本。
    # 禁用 TLS-ALPN 验证，避免普通 CDN 代理干扰该验证方式。
    # 服务器必须能通过 TCP 80 完成 HTTP 验证。
    ACME_CHALLENGE_CONFIG='"disable_tls_alpn_challenge": true'
    ACME_MODE="HTTP-01"
fi

# ============================================================
# 安装官方 sing-box
# ============================================================

echo
echo "正在安装或更新官方 sing-box..."

curl -fsSL https://sing-box.app/install.sh | sh

# 自动定位 sing-box 可执行文件。
SING_BOX_CMD="$(command -v sing-box || true)"

if [[ -z "$SING_BOX_CMD" ]]; then
    echo "错误：没有找到 sing-box 可执行文件。"
    exit 1
fi

# 新的共享证书提供者配置要求 sing-box 1.14.0 或更高版本。
SB_VERSION="$(
    "$SING_BOX_CMD" version 2>/dev/null |
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+' |
        head -n 1 || true
)"

if [[ -z "$SB_VERSION" ]]; then
    echo "错误：无法读取 sing-box 版本。"
    exit 1
fi

LOWEST_VERSION="$(
    printf '%s\n' "$SB_VERSION" "1.14.0" |
        sort -V |
        head -n 1
)"

if [[ "$LOWEST_VERSION" != "1.14.0" ]]; then
    echo "错误：当前 sing-box 版本为 $SB_VERSION，要求 1.14.0 或更高版本。"
    exit 1
fi

echo "sing-box 版本：$SB_VERSION"

# ============================================================
# 准备 ACME 数据目录
# ============================================================

# 此目录由 sing-box 自己维护 ACME 账户、证书和续期数据。
# 不需要手动下载 acme.sh，也不需要手动复制证书文件。
install -d -m 700 /var/lib/sing-box/acme

# ============================================================
# 生成 sing-box 配置文件
# ============================================================

# 提醒：
# 1. Trojan 和 Hysteria2 共用一张 ACME 证书。
# 2. Trojan 使用 TCP 443，WebSocket 路径为 /密码。
# 3. Hysteria2 使用 UDP 443，两者可以共用相同的端口号。
# 4. 配置文件内包含认证密码；如启用了 DNS-01，也会包含 API Token。
#    后续请勿将配置文件公开。

cat > /root/sing-box_config.json <<JSON
{
    "log": {
        "level": "warn"
    },

    "certificate_providers": [
        {
            "type": "acme",
            "tag": "acme-cert",
            "domain": [
                "$DOMAIN"
            ],
            "data_directory": "/var/lib/sing-box/acme",
            "provider": "letsencrypt",
            $ACME_CHALLENGE_CONFIG,
            "key_type": "p256"
        }
    ],

    "inbounds": [
        {
            "type": "trojan",
            "tag": "trojan-ws-in",
            "listen": "::",
            "listen_port": 443,

            "users": [
                {
                    "password": "$PASSWORD"
                }
            ],

            "tls": {
                "enabled": true,
                "server_name": "$DOMAIN",
                "certificate_provider": "acme-cert"
            },

            "transport": {
                "type": "ws",
                "path": "/$PASSWORD"
            }
        },

        {
            "type": "hysteria2",
            "tag": "hysteria2-in",
            "listen": "::",
            "listen_port": 443,

            "up_mbps": $UP_MBPS,
            "down_mbps": $DOWN_MBPS,

            "users": [
                {
                    "password": "$PASSWORD"
                }
            ],

            "tls": {
                "enabled": true,
                "server_name": "$DOMAIN",
                "certificate_provider": "acme-cert"
            }
        }
    ],

    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        }
    ]
}
JSON

# 限制配置文件访问权限，防止其他普通用户读取密码及 API Token。
chmod 600 /root/sing-box_config.json

# ============================================================
# 检查配置文件
# ============================================================

echo
echo "正在检查 sing-box 配置..."

if ! "$SING_BOX_CMD" check -c /root/sing-box_config.json; then
    echo
    echo "错误：配置检查失败，未继续启动服务。"
    echo "请检查 /root/sing-box_config.json。"
    exit 1
fi

echo "配置检查通过。"

# ============================================================
# 创建 systemd 服务
# ============================================================

# 以 systemd 管理服务，使 sing-box 能在重启后自动启动，
# 并在进程异常退出后自动重启。
cat > /etc/systemd/system/sing-box.service <<SERVICE
[Unit]
Description=sing-box proxy service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$SING_BOX_CMD run -c /root/sing-box_config.json
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SERVICE

# 重载服务定义，启用开机启动并重启 sing-box。
systemctl daemon-reload
systemctl enable sing-box

if ! systemctl restart sing-box; then
    echo
    echo "错误：sing-box 启动失败，以下为最近的服务日志："
    journalctl -u sing-box -n 80 --no-pager || true
    exit 1
fi

# 清除 shell 中不再需要的敏感变量。
# 密码及 ACME 配置仍保存在权限为 600 的配置文件中。
unset PASSWORD CF_API_TOKEN ACME_CHALLENGE_CONFIG

# ============================================================
# 输出安装结果
# ============================================================

echo
echo "========================================"
echo "          sing-box 配置完成"
echo "========================================"
echo
echo "域名：$DOMAIN"
echo
echo "协议一：Trojan + WebSocket + TLS"
echo "传输端口：443/TCP"
echo "WebSocket 路径：输入密码前添加 /"
echo "认证密码：安装时设置，不在输出中回显"
echo "Cloudflare：可通过橙色云代理转发 WebSocket"
echo
echo "协议二：Hysteria2 + TLS"
echo "传输端口：443/UDP"
echo "认证密码：与 Trojan 相同"
echo "TLS SNI：$DOMAIN"
echo "服务器上行带宽：$UP_MBPS Mbps"
echo "服务器下行带宽：$DOWN_MBPS Mbps"
echo "连接地址：服务器真实 IP（详见下方说明）"
echo
echo "ACME 验证方式：$ACME_MODE"
echo "证书数据目录：/var/lib/sing-box/acme"
echo "配置文件：/root/sing-box_config.json"
echo "服务日志：journalctl -u sing-box -f"
echo
echo "请确认防火墙及云服务器安全组已经放行："
echo "  TCP 443：Trojan WebSocket"
echo "  UDP 443：Hysteria2"
if [[ "$ACME_MODE" == "HTTP-01" ]]; then
    echo "  TCP 80：Let's Encrypt HTTP-01 验证"
fi
echo
echo "请留意：服务启动不代表 ACME 证书一定已成功签发。"
echo "首次连接前，请检查服务日志确认没有证书申请错误。"
echo
echo "========================================"
echo

systemctl --no-pager --full status sing-box || true

echo
echo "最近的 sing-box 日志："
journalctl -u sing-box -n 30 --no-pager || true

EOF
```

## 服务器重装系统后SSH需要输入
```bash
ssh-keygen -R <Address>
```

## 查询进程与结束进程
```bash
ps aux | grep sing-box

pkill sing-box
```