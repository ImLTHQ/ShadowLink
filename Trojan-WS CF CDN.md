# Trojan-WS-TLS CF CDN

```bash
bash <(cat <<'EOF'
set -e

read -p "请输入域名(不要开小黄云): " DOMAIN
read -s -p "请输入密码: " PASSWORD

curl -fsSL https://sing-box.app/install.sh | sh

curl -fsSL https://get.acme.sh | sh

~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

~/.acme.sh/acme.sh --issue \
-d "$DOMAIN" \
--standalone \
--server letsencrypt

mkdir -p /root

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
        "certificate_path": "/root/.acme.sh/$DOMAIN/fullchain.cer",
        "key_path": "/root/.acme.sh/$DOMAIN/$DOMAIN.key"
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

cat >/etc/systemd/system/sing-box.service <<SERVICE
[Unit]
Description=sing-box
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /root/config.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable sing-box
systemctl restart sing-box

echo
echo "部署完成  请打开小黄云"
echo
echo "Trojan-WS-TLS"
echo "域名: $DOMAIN"
echo "端口: 443"
echo "密码: $PASSWORD"
echo "WS路径: /"
echo

systemctl --no-pager --full status sing-box
EOF
)
```