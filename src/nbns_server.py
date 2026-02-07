import socket
import struct
import logging
import logging.handlers
import time
import multiprocessing
import os
import sys
from src.utils import get_local_ip, get_hostname

def run_nbns_server(log_queue):
    """
    运行简易 NBNS 服务器 (UDP 137)
    用于替代被禁用的 Windows NetBT 服务，提供基本的计算机名解析
    """
    # [v1.52] 直接使用 log_queue.put() 发送启动信息，避免 logger 配置问题
    try:
        log_queue.put(f"[NBNS] 进程启动 (PID: {os.getpid()})")
    except:
        pass
    
    try:
        # 配置 logger
        logger = logging.getLogger('NBNSServer')
        logger.handlers = []  # 清除可能存在的旧 handler
        logger.addHandler(logging.handlers.QueueHandler(log_queue))
        logger.setLevel(logging.INFO)
        logger.propagate = False

        local_ip = get_local_ip()
        hostname = get_hostname().upper()
        log_queue.put(f"[NBNS] 本机名: {hostname}, IP: {local_ip}")
        
        bind_ip = '0.0.0.0'
        bind_port = 137

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind((bind_ip, bind_port))
            log_queue.put(f"[NBNS] ✓ 服务已启动 (UDP 137), 等待查询...")
        except Exception as e:
            log_queue.put(f"[NBNS] ✗ 端口绑定失败 (UDP 137): {e}")
            log_queue.put(f"[NBNS] 提示: 端口可能被 Windows NetBT 服务占用，请检查注册表设置")
            return

        while True:
            try:
                data, addr = sock.recvfrom(1024)
                if not data:
                    continue

                # Parse Header (12 bytes)
                # TID(2), Flags(2), QDCOUNT(2), ANCOUNT(2), NSCOUNT(2), ARCOUNT(2)
                if len(data) < 12:
                    continue

                tid, flags, qdcount, _, _, _ = struct.unpack('!HHHHHH', data[:12])
                
                # Check if it's a query (Flags & 0x8000 == 0) and Opcode == 0
                is_response = (flags & 0x8000)
                if is_response:
                    continue # Ignore responses

                if qdcount == 0:
                    continue

                # Parse Question Section
                offset = 12
                
                try:
                    len_byte = data[offset]
                    if len_byte != 32:
                         continue
                    
                    offset += 1
                    encoded_name = data[offset:offset+32]
                    offset += 32
                    
                    if data[offset] != 0:
                        continue
                    offset += 1
                    
                    q_type, q_class = struct.unpack('!HH', data[offset:offset+4])
                    
                    if q_type != 0x0020:
                        continue
                    if q_class != 0x0001:
                        continue

                    # Decode Name
                    decoded_name = ""
                    try:
                        for i in range(0, 32, 2):
                            char_code = ((encoded_name[i] - 0x41) << 4) | (encoded_name[i+1] - 0x41)
                            decoded_name += chr(char_code)
                    except:
                        continue
                    
                    query_pure_name = decoded_name[:15].strip()
                    suffix = ord(decoded_name[15]) if len(decoded_name) > 15 else 0

                    # [v1.52] 记录所有收到的查询（便于调试）
                    log_queue.put(f"[NBNS] 收到查询: {query_pure_name}<{suffix:02x}> 来自 {addr[0]}")
                    
                    # 忽略大小写比较
                    if query_pure_name.upper() == hostname:
                        log_queue.put(f"[NBNS] ✓ 匹配成功! 响应 IP: {local_ip}")
                        
                        resp_flags = 0x8500 
                        resp_header = struct.pack('!HHHHHH', tid, resp_flags, 1, 1, 0, 0)
                        q_section = data[12:offset+4]
                        
                        ip_parts = [int(x) for x in local_ip.split('.')]
                        ip_bytes = struct.pack('!BBBB', *ip_parts)
                        
                        ans_header = struct.pack('!HHHLH', 0x0020, 0x0001, 300, 6) 
                        ans_data = struct.pack('!H', 0x0000) + ip_bytes 
                        
                        response = resp_header + q_section + struct.pack('!H', 0xC00C) + ans_header + ans_data
                        
                        sock.sendto(response, addr)
                    else:
                        log_queue.put(f"[NBNS] ✗ 不匹配 (查询: {query_pure_name}, 本机: {hostname})")
                
                except Exception as e:
                    pass

            except Exception as e:
                log_queue.put(f"[NBNS] 处理出错: {e}")
    
    except Exception as e:
        # [v1.52] 捕获 NBNS 服务的所有未处理异常
        try:
            log_queue.put(f"[NBNS] 服务崩溃: {e}")
        except:
            pass
