# Hy2 Debian命令

```bash
wget -O hy2 https://github.com/apernet/hysteria/releases/download/app%2Fv2.6.5/hysteria-linux-amd64-avx && chmod +x ./hy2 && nano config.yaml && (nohup ./hy2 server &)
```

```bash
acme:
  domains:
    - your-domain.com
  email: your-email@example.com

listen: :443

auth:
  type: password
  password: password 

masquerade: 
  type: proxy
  proxy:
    url: https://www.x-mol.com
    rewriteHost: true

speedTest: true
```

```bash
ps aux | grep hy2

kill ID
```