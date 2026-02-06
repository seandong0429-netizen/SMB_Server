import socket
import struct
import logging
import time
import multiprocessing
from src.utils import get_local_ip, get_hostname

def run_nbns_server(log_queue):
    """
    运行简易 NBNS 服务器 (UDP 137)
    用于替代被禁用的 Windows NetBT 服务，提供基本的计算机名解析
    """
    logger = logging.getLogger('NBNSServer')
    logger.addHandler(logging.handlers.QueueHandler(log_queue))
    logger.setLevel(logging.INFO)

    local_ip = get_local_ip()
    hostname = get_hostname().upper()
    # NetBIOS name must be 16 chars, padded with spaces (usually 15 chars + suffix)
    # But for matching, we decdoe the query.
    
    bind_ip = '0.0.0.0'
    bind_port = 137

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.bind((bind_ip, bind_port))
        logger.info(f"NBNS 服务已启动 (UDP 137), 本机名: {hostname}, IP: {local_ip}")
    except Exception as e:
        logger.error(f"NBNS 端口绑定失败 (UDP 137): {e}")
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
            # Name (variable, usually 34 bytes for 16-char encoded name), Type(2), Class(2)
            offset = 12
            
            # Read encoded name (label sequence)
            # Typically [1 byte length][encoded_string][0]
            # NetBIOS names are length 32 (encoded from 16) -> length byte is 0x20 (32)
            
            try:
                # Simple parsing for standard NV name
                len_byte = data[offset]
                if len_byte != 32:
                     # Complex parsing not supported for now, usually it is 32 for NBNS
                     continue
                
                offset += 1
                encoded_name = data[offset:offset+32]
                offset += 32
                
                if data[offset] != 0: # Terminating zero
                    continue
                offset += 1
                
                q_type, q_class = struct.unpack('!HH', data[offset:offset+4])
                
                if q_type != 0x0020: # NB (NetBIOS General Name Service)
                    continue
                if q_class != 0x0001: # IN (Internet)
                    continue

                # Decode Name
                decoded_name = ""
                try:
                    for i in range(0, 32, 2):
                        char_code = ((encoded_name[i] - 0x41) << 4) | (encoded_name[i+1] - 0x41)
                        decoded_name += chr(char_code)
                except:
                    continue
                
                # Trim spaces and check suffix
                # The 16th byte is the suffix (service type).
                query_pure_name = decoded_name[:15].strip()
                suffix = ord(decoded_name[15]) if len(decoded_name) > 15 else 0

                # 调试日志: 记录收到的所有请求
                logger.debug(f"NBNS Query: {query_pure_name}<{suffix:02x}> from {addr[0]}")
                
                # 简单匹配: 忽略后缀，只要名字对就行 (00=Workstation, 20=Server)
                if query_pure_name == hostname:
                    logger.info(f"收到解析请求: {query_pure_name}<{suffix:02x}> 来自 {addr[0]} -> 响应 {local_ip}")
                    
                    # Construct Response
                    # Header
                    # TID: echo
                    # Flags: Response(1) | Opcode(0) | AA(1) | TC(0) | RD(1) | RA(0) | B(0) | RCODE(0)
                    # 0x8500 = 1000 0101 0000 0000
                    
                    # [Fix] 如果请求是广播 (Flags B=1?)
                    # RFC 1002: Header Flags bit 4 is B.
                    # 但在这里我们作为 NBNS Server 响应，通常 Unicast 回应即可。
                    # 有些老设备希望看到我们声称是 "Unique Name" (Flags 0x0000 in Resource Record)
                    
                    resp_flags = 0x8500 
                    
                    # Echo Header
                    # QDCOUNT=1, ANCOUNT=1
                    resp_header = struct.pack('!HHHHHH', tid, resp_flags, 1, 1, 0, 0)
                    
                    # Question Section (Echo)
                    q_section = data[12:offset+4]
                    
                    # Answer Section
                    # Name (Pointer to question name: 0xC000 | offset 12) = 0xC00C
                    # Type (NB=0x20)
                    # Class (IN=1)
                    # TTL (300s)
                    # RDLENGTH (6 bytes: 2 flags + 4 IP)
                    
                    # RDATA Flags: 
                    # 0x0000 = Unique Name, B-node
                    # 0x6000 = Group Name? No. 
                    # 我们声明自己是 Unique Name
                    
                    ip_parts = [int(x) for x in local_ip.split('.')]
                    ip_bytes = struct.pack('!BBBB', *ip_parts)
                    
                    ans_header = struct.pack('!HHHLH', 0x0020, 0x0001, 300, 6) 
                    ans_data = struct.pack('!H', 0x0000) + ip_bytes 
                    
                    # Pointer Name (0xC00C)
                    response = resp_header + q_section + struct.pack('!H', 0xC00C) + ans_header + ans_data
                    
                    sock.sendto(response, addr)
                else:
                    # 如果开启了详细调试，可以记录不匹配的
                    # logger.info(f"忽略请求: {query_pure_name} (本机: {hostname})")
                    pass
            
            except Exception as e:
                # Parsing error
                pass

        except Exception as e:
            logger.error(f"NBNS 处理出错: {e}")
