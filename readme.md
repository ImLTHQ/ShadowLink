# Debian命令

- 需确保端口80和443开放

## nano 基本操作

- `Ctrl + O` - 保存文件
- `Ctrl + X` - 退出编辑器

```bash
sudo apt update && sudo apt install python3 python3-pip python3-websockets socat -y && curl https://get.acme.sh | sh && ln -s  /root/.acme.sh/acme.sh /usr/local/bin/acme.sh && acme.sh --set-default-ca --server letsencrypt && wget https://raw.githubusercontent.com/ImLTHQ/ShadowLink/main/ss_ws_tls_server.py && nano ss_ws_tls_server.py && (nohup python3 ss_ws_tls_server.py > ss_ws_tls_server.log 2>&1 &) && tail -f ss_ws_tls_server.log
```

```bash
ps aux | grep ss_ws_tls_server.py
```

```bash
kill ID
```