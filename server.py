import socket
import sys
import time
from threading import Thread

LOCAL_UDP_PORT = 6666 # 本地监听端口
TARGET_HOST = "" # IP或域名
TARGET_PORT = 443 # 目标端口

def udp_relay(local_port: int, target_host: str, target_port: int):
    SOCKET_TIMEOUT = 5.0
    # 存储客户端地址与转发端口的映射
    client_map = {}

    # 接收客户端数据并转发到服务端
    def forward_to_server():
        try:
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            recv_sock.bind(("", local_port))
            recv_sock.settimeout(SOCKET_TIMEOUT)

            while True:
                try:
                    data, client_addr = recv_sock.recvfrom(65535)
                    if data and client_addr not in client_map:
                        # 为每个客户端创建独立的转发套接字
                        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        send_sock.settimeout(SOCKET_TIMEOUT)
                        client_map[client_addr] = send_sock
                        # 启动线程接收服务端返回数据并回传给客户端
                        Thread(target=forward_to_client, args=(send_sock, client_addr), daemon=True).start()
                    # 转发客户端数据到服务端
                    client_map[client_addr].sendto(data, (target_host, target_port))
                except socket.timeout:
                    continue
                except Exception:
                    if client_addr in client_map:
                        del client_map[client_addr]
                    time.sleep(0.1)
        except Exception:
            sys.exit(1)

    # 接收服务端返回数据并转发给客户端
    def forward_to_client(send_sock, client_addr):
        try:
            while True:
                try:
                    data, _ = send_sock.recvfrom(65535)
                    if data:
                        # 回传数据给原客户端
                        send_sock.sendto(data, client_addr)
                except socket.timeout:
                    continue
                except Exception:
                    if client_addr in client_map:
                        del client_map[client_addr]
                    break
        except Exception:
            pass

    # 启动上行转发线程
    server_thread = Thread(target=forward_to_server, daemon=True)
    server_thread.start()
    # 主线程保持运行
    try:
        while server_thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        # 关闭所有套接字
        for sock in client_map.values():
            sock.close()
        sys.exit(0)

if __name__ == "__main__":
    udp_relay(LOCAL_UDP_PORT, TARGET_HOST, TARGET_PORT)