import asyncio
import websockets
import ssl
import socket
import os
from typing import Tuple, Optional

# 需要修改的关键配置
verify_path = "/password"  # WS路径(代替密码作为验证)
listen_port = 443   # 服务器监听端口

# 无需修改的全局变量
tls_context = None
shutdown_event = None

# 连接统计
connection_count = 0
total_bytes_transferred = 0
active_connections = set()

def find_certificate_files():
    """从当前目录查找证书文件"""
    import glob
    
    # 查找所有的.crt和.key文件
    cert_files = glob.glob("*.crt")
    key_files = glob.glob("*.key")

    # 检查证书文件数量
    if len(cert_files) == 0:
        print(f"[证书] 错误: 未找到证书文件 (.crt)")
        return False, None, None
    elif len(cert_files) > 1:
        print(f"[证书] 错误: 找到多个证书文件 {cert_files}，请只保留一个")
        return False, None, None
    
    # 检查私钥文件数量
    if len(key_files) == 0:
        print(f"[证书] 错误: 未找到私钥文件 (.key)")
        return False, None, None
    elif len(key_files) > 1:
        print(f"[证书] 错误: 找到多个私钥文件 {key_files}，请只保留一个")
        return False, None, None
    
    # 只有一个证书和一个私钥，使用它们
    cert_file = cert_files[0]
    key_file = key_files[0]
    print(f"[证书] 使用证书: {cert_file} 和私钥: {key_file}")
    return True, cert_file, key_file

#   核心逻辑

async def process_request(path, request_headers):
    """处理请求，验证路径"""
    # 检查路径
    if path != verify_path:
        return None, None, 403, b"Forbidden: Invalid path"
    
    # 通过验证，允许继续WebSocket握手
    return None, None, None, None

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

async def handle_client(websocket, path):
    global connection_count, active_connections
    
    # 验证路径
    if path != verify_path:
        print(f"[拒绝访问] 客户端IP: {websocket.remote_address[0] if websocket.remote_address else 'unknown'}, 路径: {path}")
        await websocket.close(code=403, reason="Forbidden")
        return

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
    global listen_port, tls_context, shutdown_event
    
    #   查找证书文件
    success, cert_file, key_file = find_certificate_files()
    if not success:
        print("[错误] 在当前目录未找到匹配的证书和私钥文件 (*.crt 和 *.key)")
        return

    #   配置TLS上下文
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        print(f"[TLS] 加载证书文件: {cert_file}, {key_file}")
        if not os.path.exists(cert_file):
            print(f"[错误] 证书文件不存在: {cert_file}")
            return
        if not os.path.exists(key_file):
            print(f"[错误] 私钥文件不存在: {key_file}")
            return
            
        ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        tls_context = ssl_context
        print(f"[TLS] 配置成功")
    except Exception as e:
        print(f"[错误] TLS配置失败：{str(e)}")
        return

    # 初始化关闭事件
    shutdown_event = asyncio.Event()
    
    print("=" * 50)
    print("SS+WS+TLS 代理")
    print("=" * 50)
    print(f"端口: {listen_port}")
    print("密码: 任意值")
    print("加密方式: none")
    print(f"WS路径: {verify_path} (代替密码作为验证)")
    print("=" * 50)

    server = await websockets.serve(
        handle_client,
        "0.0.0.0",
        listen_port,
        ssl=ssl_context,
        ping_interval=10,
        ping_timeout=10,
        extensions=[],
        subprotocols=None,
        process_request=process_request
    )
    await shutdown_event.wait()

async def run_server():
    """运行服务器的主函数"""
    await main()

if __name__ == "__main__":
    asyncio.run(run_server())