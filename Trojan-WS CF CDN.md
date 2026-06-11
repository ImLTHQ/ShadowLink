# Trojan-WS-TLS CF CDN

```bash
bash <(cat <<'EOF'
set -euo pipefail

read -p "请输入域名 (不要开小黄云): " DOMAIN
read -s -p "请输入密码: " PASSWORD
echo

# 安装 sing-box
curl -fsSL https://sing-box.app/install.sh | sh

# 安装 acme
curl -fsSL https://get.acme.sh | sh

~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

# 申请证书 (注意：需要 80 端口可用 + 关闭小黄云)
~/.acme.sh/acme.sh --issue \
-d "$DOMAIN" \
--standalone \
--server letsencrypt

# 放到固定路径 (避免 acme.sh 目录变化)
mkdir -p /root/cert

~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
--key-file /root/cert/private.key \
--fullchain-file /root/cert/fullchain.cer

# 自动检测 sing-box 路径
SINGBOX_BIN=$(command -v sing-box)

# 生成配置
cat >/root/config.json <<JSON
{
  "log": {
    "level": "info"
  },
  "inbounds": [
    {
      "type": "trojan",
      "listen": "::",
      "listen_port": 443,
      "users": [
        {
          "password": "$PASSWORD"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "/root/cert/fullchain.cer",
        "key_path": "/root/cert/private.key"
      },
      "transport": {
        "type": "ws"
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct"
    }
  ]
}
JSON

# systemd
cat >/etc/systemd/system/sing-box.service <<SERVICE
[Unit]
Description=sing-box
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$SINGBOX_BIN run -c /root/config.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable sing-box
systemctl restart sing-box

echo
echo "=============================="
echo "部署完毕 (可开小黄云)"
echo
echo "域名: $DOMAIN"
echo "端口: 443"
echo "密码: $PASSWORD"
echo "WS路径: /"
echo "=============================="
echo

systemctl --no-pager --full status sing-box
EOF
)
```