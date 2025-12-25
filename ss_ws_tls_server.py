import asyncio
import websockets
import ssl
import re
import socket
import os
import subprocess
import idna
import threading
import time
from typing import Tuple, Optional
from datetime import datetime

# 需要修改的关键配置
shadowsocks_password = "password"   # 密码
server_domain = "localhost" # 服务器域名
listen_port = 443   # 服务器监听端口

# 无需修改的全局变量
original_domain = "localhost"
tls_context = None
shutdown_event = None

# 连接统计
connection_count = 0
total_bytes_transferred = 0
active_connections = set()

# 证书续期相关
cert_renewal_thread = None
renewal_check_interval = 86400  # 24小时检查一次（秒）
renewal_threshold_days = 30  # 证书到期前30天开始续期

def check_certificate_expiry(cert_file: str) -> Tuple[bool, int]:
    """检查证书到期时间，返回(是否即将到期，剩余天数)"""
    try:
        # 使用openssl检查证书到期时间
        result = subprocess.run([
            "openssl", "x509", "-enddate", "-noout", "-in", cert_file
        ], capture_output=True, text=True, check=True)
        
        # 解析到期时间
        expiry_line = result.stdout.strip()
        if "notAfter=" in expiry_line:
            expiry_str = expiry_line.split("=")[1].strip()
            expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            days_remaining = (expiry_date - datetime.now()).days
            is_near_expiry = days_remaining <= renewal_threshold_days
            return is_near_expiry, days_remaining
    except Exception as e:
        print(f"[证书检查] 无法检查证书到期时间: {str(e)}")
    
    return True, 0  # 无法检查时默认需要续期

def renew_certificate(domain: str) -> bool:
    """续期Let's Encrypt证书"""
    try:
        print(f"[证书续期] 开始为 {domain} 续期Let's Encrypt证书")
        
        # 使用certbot续期
        certbot_renew_cmd = [
            "certbot", "renew",
            "--non-interactive",
            "--agree-tos",
            "--cert-name", domain,
            "--post-hook", f"cp /etc/letsencrypt/live/{domain}/fullchain.pem {domain}.crt && cp /etc/letsencrypt/live/{domain}/privkey.pem {domain}.key"
        ]
        
        result = subprocess.run(certbot_renew_cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"[证书续期] {domain} 证书续期成功")
            return True
        else:
            print(f"[证书续期] {domain} 证书续期失败: {result.stderr}")
            
            # 如果续期失败，尝试重新获取
            print(f"[证书续期] 尝试重新获取 {domain} 证书")
            certbot_cmd = [
                "certbot", "certonly",
                "--standalone",
                "--non-interactive",
                "--agree-tos",
                "--register-unsafely-without-email",
                "--domain", domain,
                "--cert-name", domain,
                "--force-renewal"
            ]
            
            result = subprocess.run(certbot_cmd, capture_output=True, text=True)
            if result.returncode == 0:
                letsencrypt_dir = f"/etc/letsencrypt/live/{domain}"
                subprocess.run(["cp", f"{letsencrypt_dir}/fullchain.pem", f"{domain}.crt"], check=True)
                subprocess.run(["cp", f"{letsencrypt_dir}/privkey.pem", f"{domain}.key"], check=True)
                print(f"[证书续期] {domain} 证书重新获取成功")
                return True
            else:
                print(f"[证书续期] {domain} 证书重新获取失败: {result.stderr}")
                return False
                
    except Exception as e:
        print(f"[证书续期] 续期过程中发生异常: {str(e)}")
        return False

def certificate_renewal_monitor(domain: str):
    """证书续期监控线程"""
    print(f"[续期监控] 启动证书续期监控线程，域名: {domain}")
    print(f"[续期配置] 检查间隔: {renewal_check_interval//3600}小时，续期阈值: {renewal_threshold_days}天")
    
    while not shutdown_event.is_set():
        try:
            cert_file = f"{domain}.crt"
            if os.path.exists(cert_file):
                is_near_expiry, days_remaining = check_certificate_expiry(cert_file)
                
                if is_near_expiry:
                    print(f"[续期警告] 证书将在 {days_remaining} 天后到期，开始续期")
                    
                    if renew_certificate(domain):
                        # 重新加载TLS上下文
                        reload_tls_context(domain)
                        print(f"[续期成功] 证书已续期并重新加载TLS上下文")
                    else:
                        print(f"[续期失败] 证书续期失败，将在下次检查时重试")
                else:
                    print(f"[续期检查] 证书正常，剩余 {days_remaining} 天")
            else:
                print(f"[续期检查] 证书文件不存在: {cert_file}")
                
        except Exception as e:
            print(f"[续期监控] 检查过程中发生异常: {str(e)}")
        
        # 等待下次检查，同时监听关闭事件
        for _ in range(renewal_check_interval):
            if shutdown_event.is_set():
                break
            time.sleep(1)

def reload_tls_context(domain: str):
    """重新加载TLS上下文"""
    global tls_context
    
    try:
        cert_file = f"{domain}.crt"
        key_file = f"{domain}.key"
        
        if os.path.exists(cert_file) and os.path.exists(key_file):
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
            tls_context = ssl_context
            print(f"[TLS重载] SSL/TLS上下文重新加载成功")
        else:
            print(f"[TLS重载] 证书文件不存在，无法重新加载")
    except Exception as e:
        print(f"[TLS重载] 重新加载TLS上下文失败: {str(e)}")

def generate_certs(domain="localhost"):
    #   生成证书文件
    cert_file = f"{domain}.crt"
    key_file = f"{domain}.key"
    
    print(f"[证书检查] 检查 {domain} 的证书文件")
    
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print(f"[证书状态] 证书文件已存在: {cert_file}, {key_file}")
        
        # 检查证书到期时间
        is_near_expiry, days_remaining = check_certificate_expiry(cert_file)
        if is_near_expiry and domain != "localhost":
            print(f"[证书警告] 证书将在 {days_remaining} 天后到期，尝试续期")
            if renew_certificate(domain):
                print(f"[证书续期] 证书续期成功")
            else:
                print(f"[证书续期] 证书续期失败，将使用现有证书")
        
        return True, cert_file, key_file
    
    if domain == "localhost":
        print(f"[证书生成] 测试环境 生成自签名证书")
        print(f"[证书配置] 有效期: 365天, 算法: RSA-2048")
        openssl_cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_file, "-out", cert_file,
            "-days", "365", "-nodes",
            "-subj", f"/C=CN/CN={domain}"
        ]
        subprocess.check_call(openssl_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[证书完成] 自签名证书生成成功: {cert_file}")
        return True, cert_file, key_file
    else:
        print(f"[证书生成] 正在使用Certbot为 {domain} 生成Let's Encrypt证书")
        certbot_cmd = [
            "certbot", "certonly",
            "--standalone",
            "--non-interactive",
            "--agree-tos",
            "--register-unsafely-without-email",
            "--domain", domain,
            "--cert-name", domain
        ]
        subprocess.run(certbot_cmd, check=True)
        
        # Let's Encrypt证书存储在/etc/letsencrypt/live/domain/目录下
        letsencrypt_dir = f"/etc/letsencrypt/live/{domain}"
        print(f"[证书复制] 从 {letsencrypt_dir} 复制证书文件")
        subprocess.run(["cp", f"{letsencrypt_dir}/fullchain.pem", cert_file], check=True)
        subprocess.run(["cp", f"{letsencrypt_dir}/privkey.pem", key_file], check=True)
        print(f"[证书完成] Let's Encrypt证书生成成功: {cert_file}")
        return True, cert_file, key_file

#   核心逻辑
def validate_password(password: str) -> bool:
    pattern = r'^[a-zA-Z0-9]+$'
    return bool(re.match(pattern, password))

def parse_shadowsocks_request(data: bytes) -> Tuple[Optional[str], Optional[int]]:
    try:
        if len(data) < 2:
            return None, None
        
        atyp = data[0]
        addr = None
        port = None
        offset = 1
        
        if atyp == 0x01:  # IPv4
            if len(data) < offset + 6:
                return None, None
            addr = socket.inet_ntoa(data[offset:offset+4])
            port = int.from_bytes(data[offset+4:offset+6], byteorder='big')
        elif atyp == 0x03:  # 域名
            if len(data) < offset + 1:
                return None, None
            domain_len = data[offset]
            if len(data) < offset + 1 + domain_len + 2:
                return None, None
            addr = data[offset+1:offset+1+domain_len].decode('utf-8')
            port = int.from_bytes(data[offset+1+domain_len:offset+3+domain_len], byteorder='big')
        elif atyp == 0x04:  # IPv6
            if len(data) < offset + 18:
                return None, None
            addr = socket.inet_ntop(socket.AF_INET6, data[offset:offset+16])
            port = int.from_bytes(data[offset+16:offset+18], byteorder='big')
        else:
            return None, None
        
        return addr, port
    except Exception:
        return None, None

async def handle_client(websocket):
    global connection_count, active_connections
    
    client_ip = websocket.remote_address[0] if websocket.remote_address else "unknown"
    connection_count += 1
    active_connections.add(client_ip)
    
    print(f"[新连接] 客户端IP: {client_ip}")
    print(f"[连接统计] 当前活跃连接数: {len(active_connections)}")
    
    try:
        #   接收Shadowsocks请求数据
        request_data = await websocket.recv()
        if not request_data:
            print(f"[断开连接] {client_ip}: 未收到数据")
            await websocket.close(code=1003)
            return
        
        #   解析目标地址和端口
        target_addr, target_port = parse_shadowsocks_request(request_data)
        if not target_addr:
            print(f"[解析失败] {client_ip}: 无法解析目标地址")
            await websocket.close(code=1003)
            return
        
        #   找到实际数据的起始位置
        data_offset = 0
        atyp = request_data[0]
        if atyp == 0x01:  # IPv4
            data_offset = 7
        elif atyp == 0x03:  # 域名
            domain_len = request_data[1]
            data_offset = 2 + domain_len + 2
        elif atyp == 0x04:  # IPv6
            data_offset = 19
        
        #   获取要传输的初始数据（如果有）
        initial_data = b""
        if len(request_data) > data_offset:
            initial_data = request_data[data_offset:]

        #   双向数据转发
        async def forward_ws_to_socket(ws, sock):
            bytes_transferred = 0
            try:
                while not shutdown_event.is_set():
                    try:
                        data = await asyncio.wait_for(ws.recv(), timeout=1.0)
                        if not data:
                            break
                        sock.sendall(data)
                        bytes_transferred += len(data)
                    except asyncio.TimeoutError:
                        continue
                    except Exception:
                        break
            except Exception as e:
                pass
        
        async def forward_socket_to_ws(sock, ws):
            bytes_transferred = 0
            try:
                loop = asyncio.get_event_loop()
                while not shutdown_event.is_set():
                    try:
                        data = await asyncio.wait_for(loop.sock_recv(sock, 4096), timeout=1.0)
                        if not data:
                            break
                        await ws.send(data)
                        bytes_transferred += len(data)
                    except asyncio.TimeoutError:
                        continue
                    except Exception:
                        break
            except Exception as e:
                pass
        
        #   建立到目标服务器的连接
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.settimeout(10)
        try:
            target_socket.connect((target_addr, target_port))
            target_socket.setblocking(False)
            #   如果有初始数据，立即发送到目标服务器
            if initial_data:
                target_socket.sendall(initial_data)
            
            await asyncio.gather(
                forward_ws_to_socket(websocket, target_socket),
                forward_socket_to_ws(target_socket, websocket),
                return_exceptions=True
            )
            
        except socket.timeout:
            print(f"[连接超时] {client_ip}: 连接 {target_addr}:{target_port} 超时")
        except socket.gaierror as e:
            print(f"[DNS解析错误] {client_ip}: 无法解析 {target_addr} - {str(e)}")
        except ConnectionRefusedError:
            print(f"[连接被拒] {client_ip}: {target_addr}:{target_port} 拒绝连接")
        except Exception as e:
            print(f"[连接错误] {client_ip}: 连接 {target_addr}:{target_port} 失败 - {str(e)}")
        finally:
            try:
                target_socket.close()
            except Exception:
                pass
    
    except websockets.exceptions.ConnectionClosed:
        print(f"[连接关闭] {client_ip}: WebSocket连接正常关闭")
    except ConnectionResetError:
        print(f"[连接重置] {client_ip}: 连接被重置")
    except asyncio.CancelledError:
        print(f"[任务取消] {client_ip}: 任务被取消")
    except Exception as e:
        print(f"[异常] {client_ip}: 未处理异常 - {str(e)}")
    finally:
        try:
            active_connections.discard(client_ip)
            await websocket.close()
            print(f"[清理完成] {client_ip}: WebSocket连接已清理")
            print(f"[连接统计] 当前活跃连接数: {len(active_connections)}")
        except Exception:
            pass

#   服务器初始化
async def main():
    global shadowsocks_password, listen_port, server_domain, tls_context, shutdown_event, cert_renewal_thread
    
    #   使用全局变量配置的域名
    # 转换为Punycode格式用于证书生成（如果有中文字符）
    if any(ord(char) > 127 for char in server_domain):
        punycode_domain = idna.encode(server_domain).decode('ascii')
        print(f"{server_domain} = {punycode_domain}")
        server_domain = punycode_domain
        original_domain = server_domain
    
    #   生成证书
    _, cert_file, key_file = generate_certs(server_domain)
    
    # 使用全局变量配置的Shadowsocks密码
    if not shadowsocks_password:
        print("[错误] 密码不能为空")
        return
    elif not validate_password(shadowsocks_password):
        print("[错误] 密码只支持英文和数字字符")
        return
    else:
        print(f"[密码状态] 密码格式通过")

    #   配置TLS上下文
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        tls_context = ssl_context
    except Exception as e:
        print(f"[TLS错误] TLS配置失败：{str(e)}")
        return

    # 初始化关闭事件
    shutdown_event = asyncio.Event()
    
    # 启动证书续期监控（仅对非localhost域名）
    if server_domain != "localhost":
        cert_renewal_thread = threading.Thread(
            target=certificate_renewal_monitor, 
            args=(server_domain,),
            daemon=True
        )
        cert_renewal_thread.start()
        print(f"[续期监控] 证书自动续期监控已启动")
    
    print("=" * 50)
    print("SS+WS+TLS 代理")
    print("=" * 50)
    print(f"服务器域名: {server_domain}")
    print(f"监听端口: {listen_port}")
    print(f"密码: {shadowsocks_password}")
    print("加密方式: none (通过TLS加密)")
    if server_domain == "localhost":
        print("使用自签名证书，客户端需要跳过证书验证")
    else:
        print(f"证书自动续期: 已启用 (到期前{renewal_threshold_days}天续期)")
    print("=" * 50)

    server = await websockets.serve(
        handle_client,
        "0.0.0.0",
        listen_port,
        ssl=ssl_context,
        ping_interval=10,
        ping_timeout=10,
        extensions=[],
        subprotocols=None
    )
    
    await shutdown_event.wait()

async def run_server():
    """运行服务器的主函数"""
    await main()

if __name__ == "__main__":
    asyncio.run(run_server())