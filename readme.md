# Hy2 Debian命令

```bash
apt update && apt install -y iptables && wget -O hy2 https://download.hysteria.network/app/latest/hysteria-linux-amd64-avx && chmod +x ./hy2 && nano config.yaml && (nohup ./hy2 server &) && (nohup iptables -t nat -A PREROUTING -i eth0 -p udp --dport 6666:8888 -j REDIRECT --to-ports 443 &)
```

```bash
acme:
  domains:
    - your-domain.com # 域名
  email: your-email@example.com # 邮箱

listen: :443

auth:
  type: password
  password: password # 密码

obfs:
  type: salamander 
  salamander:
    password: password # 混淆密码

speedTest: true
```

```bash
ps aux | grep hy2

kill ID
```