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
# 检测已有部署
####################################

if pgrep -x sing-box >/dev/null 2>&1 \
|| [ -f /etc/systemd/system/sing-box.service ] \
|| [ -f /root/config.json ] \
|| [ -d /root/.acme.sh ] \
|| [ -f /etc/nftables.conf ]; then

    echo
    echo "检测到已有部署"
    echo
    echo "y = 完全清理旧部署（代理软件 + 证书 + 防火墙）"
    echo "n = 退出"
    echo

    read -p "请选择 (y/n): " CHOICE


    if [[ "$CHOICE" =~ ^[Yy]$ ]]; then

        echo
        echo "正在清理旧部署..."
        echo


        ####################################
        # 停止 sing-box
        ####################################

        systemctl stop sing-box 2>/dev/null || true

        systemctl disable sing-box 2>/dev/null || true



        ####################################
        # 删除 systemd
        ####################################

        rm -f /etc/systemd/system/sing-box.service



        ####################################
        # 删除代理配置
        ####################################

        rm -f /root/config.json



        ####################################
        # 删除证书和 acme
        ####################################

        rm -rf /root/cert

        rm -rf /root/.acme.sh



        ####################################
        # 删除 sing-box
        ####################################

        if command -v sing-box >/dev/null 2>&1; then

            rm -f "$(command -v sing-box)"

        fi


        pkill -x sing-box 2>/dev/null || true



        ####################################
        # 清理 nftables
        ####################################

        if command -v nft >/dev/null 2>&1; then

            nft flush ruleset || true

        fi


        rm -f /etc/nftables.conf


        systemctl disable nftables 2>/dev/null || true



        ####################################
        # 重载 systemd
        ####################################

        systemctl daemon-reload


        echo
        echo "清理完成"
        echo "请重新运行脚本"
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

read -p "请输入域名: " DOMAIN


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
    --server letsencrypt \
    --force



####################################
# 安装证书
####################################

mkdir -p /root/cert


~/.acme.sh/acme.sh \
    --install-cert \
    -d "$DOMAIN" \
    --key-file /root/cert/private.key \
    --fullchain-file /root/cert/fullchain.cer



####################################
# 获取 sing-box 路径
####################################

SINGBOX_BIN=$(command -v sing-box)



####################################
# 生成 sing-box 配置
####################################

cat >/root/config.json <<JSON
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
# 检查 sing-box 配置
####################################

$SINGBOX_BIN check \
    -c /root/config.json



####################################
# 安装 nftables
####################################

apt update

apt install -y nftables



####################################
# 配置防火墙
####################################

cat >/etc/nftables.conf <<NFT

flush ruleset


table inet filter {


    chain input {

        type filter hook input priority 0;

        policy drop;


        # 已建立连接

        ct state established,related accept;


        # 回环

        iif lo accept;


        # Ping IPv4

        ip protocol icmp accept;


        # Ping IPv6

        icmpv6 type echo-request accept;

        icmpv6 type echo-reply accept;


        # SSH

        tcp dport 22 accept;


        # ACME

        tcp dport 80 accept;


        # Trojan

        tcp dport 443 accept;


        # Hysteria2

        udp dport 8443 accept;

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



####################################
# 检查并应用 nftables
####################################

nft -c -f /etc/nftables.conf

nft -f /etc/nftables.conf


systemctl enable nftables

systemctl restart nftables



####################################
# 创建 systemd 服务
####################################

cat >/etc/systemd/system/sing-box.service <<SERVICE

[Unit]

Description=sing-box proxy trojan + hy2

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

echo

echo "部署完成"

echo

echo "域名: $DOMAIN"

echo

echo "密码: $PASSWORD"

echo

echo "TLS启用"

echo

echo "Trojan: TCP 443"

echo "WS Path: /"

echo

echo "Hysteria2: UDP 8443"

echo

echo "防火墙白名单:"

echo "ICMP"

echo "TCP 22   SSH"

echo "TCP 80   ACME"

echo "TCP 443  Trojan"

echo "UDP 8443 Hysteria2"

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