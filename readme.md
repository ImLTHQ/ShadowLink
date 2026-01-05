# Hy2 Debian命令

```bash
wget -O hy2 https://download.hysteria.network/app/latest/hysteria-linux-amd64-avx && chmod +x ./hy2 && nano config.yaml && (nohup ./hy2 server &)
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

masquerade: 
  type: proxy
  proxy:
    url: https://www.x-mol.com # 伪装网站
    rewriteHost: true

speedTest: true
```

```bash
ps aux | grep hy2

kill ID
```