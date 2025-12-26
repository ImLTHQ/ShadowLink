import asyncio
import websockets
import ssl
import socket
import os
import idna
from typing import Tuple, Optional, Dict, Set

# 配置参数
local_listen_port = 443        # 本地监听端口
local_verify_path = "/password"  # 本地WS路径 (代替密码作为验证)

remote_ss_host = "domain.com"    # 代理服务器地址
remote_verify_path = "/password" # 代理的WS路径
remote_ss_port = 443            # 代理服务器端口  

# 全局变量
local_tls_context = None
remote_tls_context = None
shutdown_event = None

# 连接统计
connection_count = 0
active_connections: Set[str] = set()
connection_pairs: Dict[str, Dict] = {}

# 错误路径日志记录
logged_invalid_paths = set()

def log_invalid_path(client_ip: str, path: str, source: str = "local"):
    """记录无效路径到日志文件"""
    log_entry = f"客户端IP: {client_ip}, 路径: {path}"
    
    if log_entry in logged_invalid_paths:
        return
    
    logged_invalid_paths.add(log_entry)
    
    try:
        with open("proxy.log", "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")
    except Exception as e:
        print(f"[错误] 无法写入日志文件: {str(e)}")

def find_certificate_files():
    """从当前目录查找证书文件"""
    import glob
    
    cert_files = glob.glob("*.crt")
    key_files = glob.glob("*.key")

    if len(cert_files) == 0:
        print(f"[证书] 错误: 未找到证书文件 (.crt)")
        return False, None, None
    elif len(cert_files) > 1:
        print(f"[证书] 错误: 找到多个证书文件 {cert_files}，请只保留一个")
        return False, None, None
    
    if len(key_files) == 0:
        print(f"[证书] 错误: 未找到私钥文件 (.key)")
        return False, None, None
    elif len(key_files) > 1:
        print(f"[证书] 错误: 找到多个私钥文件 {key_files}，请只保留一个")
        return False, None, None
    
    cert_file = cert_files[0]
    key_file = key_files[0]
    print(f"[证书] 使用证书: {cert_file} 和私钥: {key_file}")
    return True, cert_file, key_file

async def process_local_request(path, request_headers):
    """处理本地用户请求，验证路径"""
    client_ip = request_headers.get('x-forwarded-for', 'unknown')
    if ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()
    
    if path != local_verify_path:
        print(f"[拒绝访问] 客户端IP: {client_ip}, 路径: {path}")
        log_invalid_path(client_ip, path, "local")
        from websockets.exceptions import AbortHandshake
        raise AbortHandshake(status=403, headers={}, body=b"Forbidden: Invalid path")
    
    return None

def parse_shadowsocks_request(data: bytes) -> Tuple[Optional[str], Optional[int], int]:
    """解析Shadowsocks请求，返回目标地址、端口和数据偏移量"""
    try:
        if len(data) < 2:
            return None, None, 0
        
        atyp = data[0]
        addr = None
        port = None
        offset = 1
        
        if atyp == 0x01:  # IPv4
            if len(data) < offset + 6:
                return None, None, 0
            addr = socket.inet_ntoa(data[offset:offset+4])
            port = int.from_bytes(data[offset+4:offset+6], byteorder='big')
            data_offset = offset + 6
        elif atyp == 0x03:  # 域名
            if len(data) < offset + 1:
                return None, None, 0
            domain_len = data[offset]
            if len(data) < offset + 1 + domain_len + 2:
                return None, None, 0
            addr = data[offset+1:offset+1+domain_len].decode('utf-8')
            port = int.from_bytes(data[offset+1+domain_len:offset+3+domain_len], byteorder='big')
            data_offset = offset + 1 + domain_len + 2
        elif atyp == 0x04:  # IPv6
            if len(data) < offset + 18:
                return None, None, 0
            addr = socket.inet_ntop(socket.AF_INET6, data[offset:offset+16])
            port = int.from_bytes(data[offset+16:offset+18], byteorder='big')
            data_offset = offset + 18
        else:
            return None, None, 0
        
        return addr, port, data_offset
    except Exception:
        return None, None, 0

async def forward_data(src, dst, connection_id: str):
    """双向数据转发（WebSocket到WebSocket）"""
    bytes_transferred = 0
    try:
        while not shutdown_event.is_set():
            try:
                data = await asyncio.wait_for(src.recv(), timeout=1.0)
                if not data:
                    break
                await dst.send(data)
                bytes_transferred += len(data)
            except asyncio.TimeoutError:
                continue
            except Exception:
                break
    except Exception as e:
        pass
    return bytes_transferred

def encode_domain_for_uri(domain: str) -> str:
    """将域名（包括中文域名）编码为适用于URI的格式"""
    try:
        # 如果域名包含非ASCII字符，使用punycode编码
        if any(ord(c) > 127 for c in domain):
            import idna
            return idna.encode(domain).decode('ascii')
        return domain
    except Exception:
        return domain

async def connect_to_remote_proxy():
    """连接到代理"""
    # 编码中文域名为punycode格式
    encoded_host = encode_domain_for_uri(remote_ss_host)
    uri = f"wss://{encoded_host}:{remote_ss_port}{remote_verify_path}"
    
    try:
        # 创建远程SSL上下文（客户端）- 生产环境安全配置
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = True  # 生产环境必须验证主机名
        ssl_context.verify_mode = ssl.CERT_REQUIRED  # 生产环境必须验证证书
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3  # 最低TLS 1.3
        
        # 只有域名被编码时才显示编码信息
        if encoded_host != remote_ss_host:
            print(f"[远程] 正在连接到代理: {remote_ss_host} (编码为: {encoded_host})")
        else:
            print(f"[远程] 正在连接到代理: {remote_ss_host}")
        remote_ws = await websockets.connect(
            uri,
            ssl=ssl_context,
            ping_interval=10,
            ping_timeout=10
        )
        print(f"[远程] 成功连接到代理")
        return remote_ws
    except Exception as e:
        print(f"[错误] {str(e)}")
        return None

async def handle_local_client(local_ws, path):
    """处理本地用户连接"""
    global connection_count, active_connections
    
    client_ip = local_ws.remote_address[0] if local_ws.remote_address else "unknown"
    connection_id = f"{client_ip}_{connection_count}"
    connection_count += 1
    active_connections.add(connection_id)

    print(f"[新连接] 客户端IP: {client_ip}")
    print(f"[统计] 当前活跃连接数: {len(active_connections)}")
    
    remote_ws = None
    try:
        # 接收用户的Shadowsocks请求数据
        request_data = await local_ws.recv()
        if not request_data:
            print(f"[断开连接] {client_ip}: 未收到数据")
            await local_ws.close(code=1003)
            return
        
        # 解析目标地址和端口
        target_addr, target_port, data_offset = parse_shadowsocks_request(request_data)
        if not target_addr:
            print(f"[解析失败] {client_ip}: 无法解析目标地址")
            await local_ws.close(code=1003)
            return
        
        print(f"[目标] {client_ip}: 请求连接 {target_addr}:{target_port}")
        
        # 获取要传输的初始数据
        initial_data = b""
        if len(request_data) > data_offset:
            initial_data = request_data[data_offset:]
        
        # 连接到代理
        remote_ws = await connect_to_remote_proxy()
        if not remote_ws:
            print(f"[失败] {client_ip}: 无法连接到代理")
            await local_ws.close(code=1011)
            return
        
        # 转发完整的Shadowsocks请求到远程代理
        await remote_ws.send(request_data)
        
        # 记录连接对
        connection_pairs[connection_id] = {
            "local": local_ws,
            "remote": remote_ws,
            "client_ip": client_ip,
            "target": f"{target_addr}:{target_port}"
        }
        
        # 双向数据转发（WebSocket到WebSocket）
        await asyncio.gather(
            forward_data(local_ws, remote_ws, connection_id),
            forward_data(remote_ws, local_ws, connection_id),
            return_exceptions=True
        )
        
    except websockets.exceptions.ConnectionClosed:
        print(f"[连接关闭] {client_ip}: WebSocket连接正常关闭")
    except ConnectionResetError:
        print(f"[连接重置] {client_ip}: 连接被重置")
    except asyncio.CancelledError:
        print(f"[任务取消] {client_ip}: 任务被取消")
    except Exception as e:
        print(f"[异常] {client_ip}: 未处理异常 - {str(e)}")
    finally:
        # 清理连接
        try:
            active_connections.discard(connection_id)
            if connection_id in connection_pairs:
                del connection_pairs[connection_id]
            
            if remote_ws:
                await remote_ws.close()
            await local_ws.close()
            print(f"[清理完成] {client_ip}: 连接已清理")
            print(f"[统计] 当前活跃连接数: {len(active_connections)}")
        except Exception:
            pass

async def main():
    global local_tls_context, shutdown_event, remote_ss_host, remote_ss_port, remote_verify_path

    # 查找证书文件
    success, cert_file, key_file = find_certificate_files()
    if not success:
        print("[错误] 在当前目录未找到证书和私钥文件 (*.crt 和 *.key)")
        return

    # 配置本地TLS上下文（服务端）
    local_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        print(f"[TLS] 加载本地服务端证书: {cert_file}, {key_file}")
        if not os.path.exists(cert_file):
            print(f"[错误] 证书文件不存在: {cert_file}")
            return
        if not os.path.exists(key_file):
            print(f"[错误] 私钥文件不存在: {key_file}")
            return
            
        local_ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        local_ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        local_tls_context = local_ssl_context
        print(f"[TLS] 本地服务端配置成功")
    except Exception as e:
        print(f"[错误] 本地TLS配置失败：{str(e)}")
        return

    # 初始化关闭事件
    shutdown_event = asyncio.Event()
    
    print("=" * 50)
    print("SS+WS+TLS 中转")
    print("=" * 50)
    print("密码: 任意值")
    print("加密方式: none")
    print("=" * 50)
    print(f"端口: {local_listen_port}")
    print(f"WS路径: {local_verify_path}")
    print("=" * 50)

    # 启动本地WebSocket服务器
    server = await websockets.serve(
        handle_local_client,
        "0.0.0.0",
        local_listen_port,
        ssl=local_ssl_context,
        ping_interval=10,
        ping_timeout=10,
        extensions=[],
        subprotocols=None,
        process_request=process_local_request
    )
    await shutdown_event.wait()

if __name__ == "__main__":
    asyncio.run(main())