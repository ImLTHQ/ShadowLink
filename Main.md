# Trojan

## 如何连接服务器
```
ssh 用户名@地址
```

## 脚本
```bash
bash <<'EOF'

set -euo pipefail

echo
read -p "请输入域名: " DOMAIN </dev/tty
read -s -p "请输入密码: " PASSWORD </dev/tty
echo

curl -fsSL https://sing-box.app/install.sh | sh

curl -fsSL https://get.acme.sh | sh

/root/.acme.sh/acme.sh \
--set-default-ca \
--server letsencrypt

/root/.acme.sh/acme.sh \
--issue \
-d "$DOMAIN" \
--standalone \
--server letsencrypt \
--force

mkdir -p /root/cert

/root/.acme.sh/acme.sh \
--install-cert \
-d "$DOMAIN" \
--key-file /root/cert/private.key \
--fullchain-file /root/cert/fullchain.cer

SING_BOX_CMD=$(command -v sing-box)

cat >/root/sing-box_config.json <<JSON
{
    "log": {
        "level": "warn"
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
                "type": "ws",
                "path": "/ws"
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

$SING_BOX_CMD check \
    -c /root/sing-box_config.json

apt update
apt install -y nftables

cat >/etc/nftables.conf <<NFT

flush ruleset

table inet filter {

    chain input {
        type filter hook input priority 0;
        policy drop;
        ct state invalid drop;
        ct state established,related accept;
        iif lo accept;

        tcp dport 22 accept;
        tcp dport 80 accept;
        tcp dport 443 accept;
    }



    chain forward {
        type filter hook forward priority 0;
        policy drop;
    }



    chain output {
        type filter hook output priority 0;
        policy accept;
    }
}

NFT

nft -c -f /etc/nftables.conf
nft -f /etc/nftables.conf

systemctl enable nftables
systemctl restart nftables

cat >/etc/systemd/system/sing-box.service <<SERVICE

[Unit]

Description=sing-box
After=network-online.target
Wants=network-online.target

[Service]

Type=simple

ExecStart=$SING_BOX_CMD run -c /root/sing-box_config.json

Restart=always

RestartSec=3

[Install]

WantedBy=multi-user.target

SERVICE

systemctl daemon-reload

systemctl enable sing-box

systemctl restart sing-box

echo
echo "--------------------"
echo "协议: Trojan"
echo "域名: $DOMAIN"
echo "端口: 443"
echo "密码: $PASSWORD"
echo "传输: WS"
echo "路径: /ws"
echo "TLS: 启用"
echo "--------------------"
echo "[防火墙] 白名单模式"
echo "TCP 22 -> SSH"
echo "TCP 80 -> ACME"
echo "TCP 443 -> Trojan"
echo "--------------------"
echo

systemctl --no-pager --full status sing-box

EOF
```

## 服务器重装系统后SSH需要输入
```bash
ssh-keygen -R DOMAIN
```

## 查询进程与结束进程
```bash
ps aux | grep sing-box

pkill sing-box
```