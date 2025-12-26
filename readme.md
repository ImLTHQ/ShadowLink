# Debian命令

- 需确保端口80和443开放

`代理`
```bash
DOMAIN="域名" && sudo apt update && sudo apt install python3 python3-pip python3-websockets socat idn -y && curl https://get.acme.sh | sh && ln -sf /root/.acme.sh/acme.sh /usr/local/bin/acme.sh && acme.sh --set-default-ca --server letsencrypt && acme.sh --issue -d $DOMAIN --standalone && acme.sh --installcert -d $DOMAIN --ecc --key-file /root/$DOMAIN.key --fullchain-file /root/$DOMAIN.crt && wget https://raw.githubusercontent.com/ImLTHQ/ShadowLink/main/ss_ws_tls_server.py && nano ss_ws_tls_server.py && (nohup python3 ss_ws_tls_server.py &)
```

`中转 (自签证书, 免备案, 客户端需要跳过证书验证)`
```bash
DOMAIN="域名" && sudo apt update && sudo apt install python3 python3-pip python3-websockets socat idn -y && openssl req -x509 -newkey rsa:2048 -keyout $DOMAIN.key -out $DOMAIN.crt -days 3650 -nodes -subj "/CN=$DOMAIN" && wget https://raw.githubusercontent.com/ImLTHQ/ShadowLink/main/ss_ws_tls_relay.py && nano ss_ws_tls_relay.py && (nohup python3 ss_ws_tls_relay.py &)
```

```bash
ps aux | grep ss_ws_tls_server.py

kill ID
```