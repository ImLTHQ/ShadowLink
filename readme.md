# Debian命令

- 需确保端口80和443开放

```bash
DOMAIN="域名" && sudo apt update && sudo apt install python3 python3-pip python3-websockets socat idn -y && curl https://get.acme.sh | sh && ln -s  /root/.acme.sh/acme.sh /usr/local/bin/acme.sh && acme.sh --set-default-ca --server letsencrypt && acme.sh --issue -d $DOMAIN --standalone && acme.sh --installcert -d $DOMAIN --ecc --key-file /root/server.key --fullchain-file /root/server.crt && wget https://raw.githubusercontent.com/ImLTHQ/ShadowLink/main/ss_ws_tls_server.py && python3 ss_ws_tls_server.py &
```

```bash
ps aux | grep ss_ws_tls_server.py

kill ID
```