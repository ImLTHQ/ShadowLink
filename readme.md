# Hy2

```bash
wget -O /root/hy2 https://download.hysteria.network/app/latest/hysteria-linux-amd64-avx && chmod +x /root/hy2 && nano /root/config.yaml && cat >/etc/systemd/system/hy2.service <<'EOF'
[Unit]
Description=Hysteria2
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/root
ExecStart=/root/hy2 server -c /root/config.yaml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now hy2 && systemctl status hy2
```

```bash
acme:
  domains:
    -  # 域名
  email:  # 邮箱

listen: :12345-13337

auth:
  type: password
  password:  # 密码

obfs:
  type: salamander 
  salamander:
    password: # 密码

masquerade:
  type: proxy
  proxy:
    url: # 伪装网页地址
    rewriteHost: true 
  listenHTTP: :80 
  listenHTTPS: :443 
  forceHTTPS: true
```

```bash
ps aux | grep hy2

pkill hy2
```