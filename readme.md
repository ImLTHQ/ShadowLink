# Hy2

```bash
wget -O hy2 https://download.hysteria.network/app/latest/hysteria-linux-amd64-avx && nano config.yaml && (nohup sudo ./hy2 server &)
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

speedTest: true

masquerade:
  type: proxy
  proxy:
    url: https://gta5-blackjack-helper.pages.dev
    rewriteHost: true 
  listenHTTP: :80 
  listenHTTPS: :443 
  forceHTTPS: true
```

```bash
ps aux | grep hy2

kill ID
```