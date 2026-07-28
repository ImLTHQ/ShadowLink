# Trojan + Hysteria2

## 如何连接服务器
```
ssh 用户名@地址
```

## 脚本
```bash
bash <(cat <<'EOF'
set -euo pipefail

####################################
# 检测已有 sing-box
####################################

if pgrep -x sing-box >/dev/null 2>&1; then

    echo
    echo "检测到 sing-box 正在运行"
    echo
    echo "y = 完全清理旧部署"
    echo "n = 退出"
    echo
    read -p "请选择 (y/n): " CHOICE
    echo

    if [[ "$CHOICE" =~ ^[Yy]$ ]]; then

        echo
        echo "正在清理旧部署..."
        echo

        systemctl stop sing-box 2>/dev/null || true

        systemctl disable sing-box 2>/dev/null || true

        rm -f /etc/systemd/system/sing-box.service

        rm -f /root/config.json

        rm -rf /root/cert

        systemctl daemon-reload

        pkill -x sing-box 2>/dev/null || true

        if command -v sing-box >/dev/null 2>&1; then
            rm -f "$(command -v sing-box)"
        fi

        echo
        echo "清理完成，请重新运行脚本"
        echo

        exit 0

    else

        echo
        echo "退出"
        echo

        exit 0

    fi
fi

####################################
# 输入参数
####################################

echo
read -p "请输入域名: " DOMAIN
echo
read -s -p "请输入密码: " PASSWORD
echo

####################################
# 安装 sing-box
####################################

curl -fsSL https://sing-box.app/install.sh | sh

####################################
# 安装 acme.sh
####################################

if [ ! -f ~/.acme.sh/acme.sh ]; then

    curl -fsSL https://get.acme.sh | sh

fi

~/.acme.sh/acme.sh \
--set-default-ca \
--server letsencrypt

####################################
# 申请证书
####################################

~/.acme.sh/acme.sh \
--issue \
-d "$DOMAIN" \
--standalone \
--server letsencrypt

####################################
# 安装证书
####################################

mkdir -p /root/cert

~/.acme.sh/acme.sh \
--install-cert \
-d "$DOMAIN" \
--key-file /root/cert/private.key \
--fullchain-file /root/cert/fullchain.cer \
--reloadcmd "systemctl restart sing-box"

####################################
# 获取 sing-box 路径
####################################

SINGBOX_BIN=$(command -v sing-box)

####################################
# 生成配置
####################################

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
        "type": "ws",
        "path": "/"
      }
    },
    {
      "type": "hysteria2",
      "listen": "::",
      "listen_port": 8443,
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
      "obfs": {
        "type": "salamander",
        "password": "$PASSWORD"
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

####################################
# 检查配置
####################################

$SINGBOX_BIN check \
-c /root/config.json

####################################
# 防火墙
####################################

apt update

apt install -y nftables

systemctl enable nftables

systemctl start nftables

cat >/etc/nftables.conf <<NFT

flush ruleset

table inet filter {

    chain input {

        type filter hook input priority filter;

        policy drop;


        # 已建立连接

        ct state established,related accept;


        # 回环

        iif lo accept;


        # ICMP

        ip protocol icmp accept;


        # SSH

        tcp dport 22 accept;


        # Trojan

        tcp dport 443 accept;


        # Hysteria2

        udp dport 8443 accept;


        # ACME HTTP验证

        tcp dport 80 accept;

    }


    chain forward {

        type filter hook forward priority filter;

        policy drop;

    }


    chain output {

        type filter hook output priority filter;

        policy accept;

    }

}

NFT



nft -f /etc/nftables.conf



####################################
# systemd
####################################


cat >/etc/systemd/system/sing-box.service <<SERVICE

[Unit]

Description=Trojan WS TLS + Hysteria2

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



####################################
# 启动服务
####################################


systemctl daemon-reload

systemctl enable sing-box

systemctl restart sing-box



####################################
# 输出信息
####################################


echo

echo "=============================="

echo "部署完成"

echo

echo "域名: $DOMAIN"

echo "密码: $PASSWORD"

echo

echo "Trojan:"
echo "TCP 443"

echo "WS Path: /"

echo

echo "Hysteria2:"
echo "UDP 8443"

echo

echo "开放端口:"
echo "22 SSH"
echo "80 ACME"
echo "443 Trojan"
echo "8443 Hysteria2"
echo
echo "=============================="

systemctl --no-pager --full status sing-box

EOF
)
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