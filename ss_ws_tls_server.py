import asyncio
import websockets
import ssl
import re
import socket
import os
import subprocess
import idna
import datetime
from typing import Tuple, Optional

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

# 定时检查相关
last_check_time = None
check_interval = datetime.timedelta(days=7)  # 每7天检查一次

def check_certificate_expiry(cert_file: str) -> Tuple[bool, bool, datetime.datetime]:
    """检查证书到期时间，返回(是否已过期, 是否需要重新申请, 到期时间)"""
    try:
        # 使用openssl获取证书到期时间
        result = subprocess.run([
            "openssl", "x509", "-in", cert_file, "-noout", "-enddate"
        ], capture_output=True, text=True, check=True)
        
        # 解析输出获取到期时间
        output = result.stdout.strip()
        if "notAfter=" in output:
            date_str = output.split("notAfter=")[1].strip()
            # 格式: "Month Day HH:MM:SS YYYY GMT"
            expiry_date = datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %GMT")
            # 转换为本地时间
            expiry_date = expiry_date.replace(tzinfo=datetime.timezone.utc)
            now = datetime.datetime.now(datetime.timezone.utc)
            
            # 计算距离到期的天数
            days_until_expiry = (expiry_date - now).days
            is_expired = now >= expiry_date
            needs_renewal = days_until_expiry <= 30  # 提前30天重新申请
            
            if is_expired:
                print(f"[证书检查] 证书已过期: 到期时间 {expiry_date}")
            elif needs_renewal:
                print(f"[证书检查] 证书即将到期: 到期时间 {expiry_date} (剩余{days_until_expiry}天)")
            else:
                print(f"[证书检查] 证书有效: 到期时间 {expiry_date} (剩余{days_until_expiry}天)")
            
            return is_expired, needs_renewal, expiry_date
        else:
            print(f"[证书检查] 无法解析证书到期时间: {output}")
            return True, True, datetime.datetime.now(datetime.timezone.utc)  # 假设已过期且需要重新申请
            
    except subprocess.CalledProcessError as e:
        print(f"[证书检查] 无法读取证书文件: {cert_file} - {str(e)}")
        return True, True, datetime.datetime.now(datetime.timezone.utc)  # 假设已过期且需要重新申请
    except Exception as e:
        print(f"[证书检查] 检查证书到期时间失败: {str(e)}")
        return True, True, datetime.datetime.now(datetime.timezone.utc)  # 假设已过期且需要重新申请

def delete_certificate_files(domain: str):
    """删除acme.sh和当前目录下的证书文件"""
    try:
        home_dir = os.path.expanduser("~")
        acme_dir = f"{home_dir}/.acme.sh/{domain}"
        
        cert_file = f"{domain}.crt"
        key_file = f"{domain}.key"
        
        # 删除当前目录的证书文件
        deleted_files = []
        if os.path.exists(cert_file):
            os.remove(cert_file)
            deleted_files.append(cert_file)
        if os.path.exists(key_file):
            os.remove(key_file)
            deleted_files.append(key_file)
        
        # 删除acme.sh目录下的证书
        if os.path.exists(acme_dir):
            subprocess.run(["rm", "-rf", acme_dir], check=True)
            deleted_files.append(f"acme目录: {acme_dir}")
        
        if deleted_files:
            print(f"[证书删除] 已删除证书文件: {', '.join(deleted_files)}")
            return True
        else:
            print(f"[证书删除] 没有找到需要删除的证书文件")
            return True
            
    except subprocess.CalledProcessError as e:
        print(f"[证书删除] 删除命令失败: {str(e)}")
        return False
    except Exception as e:
        print(f"[证书删除] 删除证书文件失败: {str(e)}")
        return False

def copy_certificate_files(domain: str):
    """从acme.sh目录复制证书文件到当前目录"""
    try:
        # acme.sh默认证书路径
        home_dir = os.path.expanduser("~")
        acme_dir = f"{home_dir}/.acme.sh/{domain}"
        
        cert_file = f"{domain}.crt"
        key_file = f"{domain}.key"
        
        # 检查acme.sh证书目录是否存在
        if not os.path.exists(acme_dir):
            print(f"[证书复制] acme.sh证书目录不存在: {acme_dir}")
            return False
        
        # 构建完整的证书文件路径
        cert_path = f"{acme_dir}/fullchain.cer"
        key_path = f"{acme_dir}/{domain}.key"
        
        # 检查证书文件是否存在
        if not os.path.exists(cert_path):
            print(f"[证书复制] 证书文件不存在: {cert_path}")
            return False
        if not os.path.exists(key_path):
            print(f"[证书复制] 私钥文件不存在: {key_path}")
            return False
        
        # 检查证书是否已过期或需要重新申请
        is_expired, needs_renewal, expiry_date = check_certificate_expiry(cert_path)
        if is_expired or needs_renewal:
            if is_expired:
                print(f"[证书检查] 证书已过期，需要重新申请")
            else:
                print(f"[证书检查] 证书即将到期，需要重新申请")
            return False
        else:
            print(f"[证书检查] 证书有效且无需重新申请")
        
        # 复制证书文件
        subprocess.run(["cp", cert_path, cert_file], check=True)
        subprocess.run(["cp", key_path, key_file], check=True)
        print(f"[证书复制] 证书文件复制成功: {cert_file}, {key_file}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"[证书复制] 复制命令失败: {str(e)}")
        return False
    except Exception as e:
        print(f"[证书复制] 复制证书文件失败: {str(e)}")
        return False

def generate_certs(domain="localhost"):
    #   生成证书文件
    cert_file = f"{domain}.crt"
    key_file = f"{domain}.key"
    
    print(f"[证书检查] 检查 {domain} 的证书文件")
    
    # 检查当前目录的证书文件是否存在和是否过期
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print(f"[证书状态] 证书文件已存在: {cert_file}, {key_file}")
        
        # 检查证书是否已过期或需要重新申请
        is_expired, needs_renewal, expiry_date = check_certificate_expiry(cert_file)
        if is_expired or needs_renewal:
            if is_expired:
                print(f"[证书状态] 证书已过期: 到期时间 {expiry_date}")
            else:
                print(f"[证书状态] 证书即将到期: 到期时间 {expiry_date}")
            print(f"[证书操作] 删除证书文件并重新申请")
            if delete_certificate_files(domain):
                print(f"[证书操作] 证书删除完成，重新申请新证书")
            else:
                print(f"[证书错误] 删除证书失败")
                return False, None, None
        else:
            print(f"[证书状态] 证书有效且无需重新申请")
            return True, cert_file, key_file
    
    if domain == "localhost":
        print(f"[证书生成] 生成自签名证书")
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
        # 首先尝试复制已存在的证书
        home_dir = os.path.expanduser("~")
        acme_dir = f"{home_dir}/.acme.sh/{domain}"
        
        if os.path.exists(acme_dir):
            print(f"[证书检查] 发现acme.sh证书目录，检查现有证书状态")
            if copy_certificate_files(domain):
                if os.path.exists(cert_file) and os.path.exists(key_file):
                    print(f"[证书完成] 现有Let's Encrypt证书复制成功: {cert_file}")
                    return True, cert_file, key_file
            else:
                print(f"[证书检查] 现有证书无效或已过期，删除旧证书并重新申请")
                delete_certificate_files(domain)
        
        print(f"[证书生成] 正在使用acme.sh为 {domain} 生成Let's Encrypt证书")
        acme_cmd = [
            "acme.sh", "--issue", "-d", domain, "--standalone"
        ]
        result = subprocess.run(acme_cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            if copy_certificate_files(domain):
                print(f"[证书完成] Let's Encrypt证书生成成功: {cert_file}")
                return True, cert_file, key_file
            else:
                print(f"[证书复制] 证书复制失败")
                return False, None, None
        elif "Domains not changed" in result.stderr or "Skipping. Next renewal time" in result.stderr:
            print(f"[证书状态] 证书已存在且未到期，尝试复制现有证书")
            if copy_certificate_files(domain):
                print(f"[证书完成] 现有Let's Encrypt证书复制成功: {cert_file}")
                return True, cert_file, key_file
            else:
                print(f"[证书复制] 无法复制现有证书，可能证书已过期")
                print(f"[证书操作] 删除现有证书并重新申请")
                delete_certificate_files(domain)
                
                # 重新申请证书
                print(f"[证书生成] 重新申请 {domain} 的Let's Encrypt证书")
                result = subprocess.run(acme_cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    if copy_certificate_files(domain):
                        print(f"[证书完成] 重新申请Let's Encrypt证书成功: {cert_file}")
                        return True, cert_file, key_file
                    else:
                        print(f"[证书复制] 新证书复制失败")
                        return False, None, None
                else:
                    print(f"[证书生成] 重新申请Let's Encrypt证书失败: {result.stderr}")
                    return False, None, None
        else:
            print(f"[证书生成] Let's Encrypt证书生成失败: {result.stderr}")
            return False, None, None

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

async def periodic_cert_check():
    """定时检查证书的任务"""
    global last_check_time, server_domain
    
    while not shutdown_event.is_set():
        try:
            now = datetime.datetime.now()
            
            # 检查是否需要进行定时检查
            if last_check_time is None or (now - last_check_time) >= check_interval:
                print(f"[定时检查] 开始执行证书检查 (上次检查: {last_check_time})")
                
                # 检查证书状态
                cert_file = f"{server_domain}.crt"
                key_file = f"{server_domain}.key"
                
                if os.path.exists(cert_file) and os.path.exists(key_file):
                    is_expired, needs_renewal, expiry_date = check_certificate_expiry(cert_file)
                    
                    if is_expired or needs_renewal:
                        print(f"[定时检查] 证书需要更新，开始重新申请")
                        if delete_certificate_files(server_domain):
                            success, new_cert, new_key = generate_certs(server_domain)
                            if success:
                                print(f"[定时检查] 证书更新成功")
                            else:
                                print(f"[定时检查] 证书更新失败")
                        else:
                            print(f"[定时检查] 删除旧证书失败")
                    else:
                        print(f"[定时检查] 证书状态良好，无需更新")
                else:
                    print(f"[定时检查] 证书文件不存在，重新生成")
                    success, new_cert, new_key = generate_certs(server_domain)
                    if not success:
                        print(f"[定时检查] 证书生成失败")
                
                last_check_time = now
            
            # 每6小时检查一次时间间隔
            await asyncio.sleep(6 * 3600)
            
        except Exception as e:
            print(f"[定时检查] 检查过程出错: {str(e)}")
            await asyncio.sleep(3600)  # 出错时1小时后重试

#   服务器初始化
async def main():
    global shadowsocks_password, listen_port, server_domain, tls_context, shutdown_event, last_check_time
    
    # 转换为Punycode格式用于证书生成（如果有中文字符）
    if any(ord(char) > 127 for char in server_domain):
        punycode_domain = idna.encode(server_domain).decode('ascii')
        print(f"{server_domain} = {punycode_domain}")
        server_domain = punycode_domain
    
    #   生成证书
    success, cert_file, key_file = generate_certs(server_domain)
    
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
    
    print("=" * 50)
    print("SS+WS+TLS 代理")
    print("=" * 50)
    print(f"服务器域名: {server_domain}")
    print(f"监听端口: {listen_port}")
    print(f"密码: {shadowsocks_password}")
    print("加密方式: none (通过TLS加密)")
    if server_domain == "localhost":
        print("使用自签名证书，客户端需要跳过证书验证")
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
    
    # 启动定时检查任务
    last_check_time = datetime.datetime.now()
    asyncio.create_task(periodic_cert_check())
    
    print(f"[服务器] 代理服务器已启动，定时检查已启用 (每{check_interval.days}天检查一次)")
    
    await shutdown_event.wait()

async def run_server():
    """运行服务器的主函数"""
    await main()

if __name__ == "__main__":
    asyncio.run(run_server())