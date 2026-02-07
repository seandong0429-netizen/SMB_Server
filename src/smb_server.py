
import multiprocessing
import logging
import time
import sys
import os
from src.utils import get_local_ip, get_local_ipv6, get_hostname
from src.logger import QueueHandler
from src.nbns_server import run_nbns_server

# 独立的进程函数，避免 Pickling 问题
def run_smb_server_process(share_name, share_path, username, password, port, log_queue, listen_address='0.0.0.0'):
    """[v1.54] 在独立进程中运行 SMB 服务，支持指定监听地址"""
    
    # 配置子进程日志
    # [v1.39] 全局日志钩子: 强行捕获 Impacket 的所有输出
    q_handler = QueueHandler(log_queue)
    formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%H:%M:%S')
    q_handler.setFormatter(formatter)

    # 1. 根 Logger (捕获所有未捕获的)
    root_logger = logging.getLogger()
    # 必须设为 DEBUG，否则 info 以下的日志会被过滤
    root_logger.setLevel(logging.DEBUG) 
    if not root_logger.handlers:
        root_logger.addHandler(q_handler)
    
    # 2. Impacket 专用 Logger (核心)
    # Impacket 使用 'impacket' 作为 logger name
    impacket_logger = logging.getLogger('impacket')
    impacket_logger.setLevel(logging.DEBUG) # 开启 DEBUG级别以显示更多握手细节
    # 确保他不重复
    impacket_logger.handlers = [] 
    impacket_logger.addHandler(q_handler)
    impacket_logger.propagate = False # 防止重复上报给 root

    # 3. 我们的 SMBServer logger
    logger = logging.getLogger('SMBServer')
    logger.setLevel(logging.INFO)
    logger.handlers = []
    logger.addHandler(q_handler)
    logger.propagate = False
    
    # 4. 重定向 stdout/stderr (捕捉 print 输出)
    class StreamToLogger:
        def __init__(self, logger, level):
            self.logger = logger
            self.level = level
        def write(self, buf):
            for line in buf.rstrip().splitlines():
                self.logger.log(self.level, line.rstrip())
        def flush(self):
            pass

    sys.stdout = StreamToLogger(logger, logging.INFO)
    sys.stderr = StreamToLogger(logger, logging.ERROR)
    
    try:
        logger.info(f"正在初始化 SMB 服务 (PID: {os.getpid()})...")
        
        # [Self-Check] 发送一条测试日志验证 Impacket 钩子是否生效
        test_imp = logging.getLogger('impacket')
        test_imp.info("系统自检: Impacket 日志通道已挂载")

        if sys.stderr:
            sys.stderr.write("系统自检: Impacket 日志通道已挂载\n")

        # 延迟导入 impacket，以便捕获 ImportError
        # 在打包环境中，如果缺少 hidden import，这里会抛出异常，现在可以被 log 捕获了
        log_queue.put("[DIAG] Step 1: 开始导入 impacket...")
        from impacket import smbserver
        from impacket.ntlm import compute_lmhash, compute_nthash
        log_queue.put("[DIAG] Step 2: impacket 导入成功")
        
        import signal
        log_queue.put("[DIAG] Step 3: 各模块导入成功")
        
        # [v1.50] 终极诊断: 直接写文件，绕过所有 Python 日志机制
        import tempfile
        debug_log_path = os.path.join(tempfile.gettempdir(), "smb_debug.log")
        def debug_write(msg):
            try:
                with open(debug_log_path, 'a', encoding='utf-8') as f:
                    import datetime
                    f.write(f"{datetime.datetime.now().strftime('%H:%M:%S')} - {msg}\n")
                    f.flush()
            except:
                pass
        
        debug_write(f"[INIT] 调试日志开始 (PID: {os.getpid()})")
        log_queue.put(f"[DIAG] 调试日志写入: {debug_log_path}")
        
        # [v1.50] Monkey Patch: 使用直接文件写入 + logging 双重记录
        try:
            # Hook 1: verify_request (连接建立前)
            original_verify_request = smbserver.SMBSERVER.verify_request
            def my_verify_request(self, request, client_address):
                debug_write(f"[CONN] 连接请求: {client_address}")
                logging.getLogger().info(f"[CONN] 连接请求: {client_address}")
                return original_verify_request(self, request, client_address)
            smbserver.SMBSERVER.verify_request = my_verify_request
            
            # Hook 2: process_request (处理请求)
            original_process_request = smbserver.SMBSERVER.process_request
            def my_process_request(self, request, client_address):
                debug_write(f"[PROC] 处理请求: {client_address}")
                logging.getLogger().info(f"[PROC] 处理请求: {client_address}")
                return original_process_request(self, request, client_address)
            smbserver.SMBSERVER.process_request = my_process_request

            log_queue.put("[DIAG] Step 4: MONITOR 钩子注入成功")
            debug_write("[INIT] MONITOR 钩子注入成功")
        except Exception as e:
            log_queue.put(f"[ERROR] MONITOR 钩子注入失败: {e}")
            debug_write(f"[ERROR] MONITOR 钩子注入失败: {e}")


        
        # 更好的方法：我们在创建 SimpleSMBServer 之前，Hack socketserver
        import socketserver
        socketserver.TCPServer.allow_reuse_address = True

        # 定义优雅关闭的信号处理
        def signal_handler(signum, frame):
            log_queue.put(f"接收到终止信号 ({signum})，正在关闭 SMB 服务...")
            sys.exit(0)

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        log_queue.put("[DIAG] Step 5: 信号处理器设置完成")

        # [v1.50] 心跳检测: 同时写文件和 logging
        def heartbeat_log():
            import datetime
            while True:
                time.sleep(5)
                try:
                    debug_write(f"[HEARTBEAT] 服务进程存活 (PID: {os.getpid()})")
                    logging.getLogger().info(f"[HEARTBEAT] 服务进程存活 (PID: {os.getpid()})")
                except:
                    break
        import threading
        threading.Thread(target=heartbeat_log, daemon=True).start()
        log_queue.put("[DIAG] Step 6: 心跳线程已启动")
        debug_write("[INIT] 心跳线程已启动")

        # [v1.56] 使用传入的监听地址
        # 如果是 IPv6 地址，强制 TCPServer 使用 AF_INET6
        try:
            if ':' in listen_address:
                import socketserver
                import socket
                socketserver.TCPServer.address_family = socket.AF_INET6
                log_queue.put("[IPv6] 强制启用 AF_INET6 地址族")
            
            server = smbserver.SimpleSMBServer(listenAddress=listen_address, listenPort=port)
            addr_type = "IPv6" if ':' in listen_address else "IPv4"
            logger.info(f"已绑定 {addr_type} 接口 ({listen_address})")
        except Exception as e:
            logger.error(f"绑定 {listen_address} 失败: {e}")
            return
            
        # [v1.44] 实例级 Monkey Patch: 针对内部的真实 TCPServer 对象
        # SimpleSMBServer 只是 facade，真正的 TCP Server 是 _SMBServer__server
        try:
            # 先尝试获取内部的 TCPServer 对象
            # 注意: SimpleSMBServer 在调用 addShare 之前可能还没初始化 __server
            # 所以我们延迟到 start 调用之前再 patch
            pass # 延迟到 start 之前
        except Exception as e:
            print(f"[ERROR] 预检失败: {e}")

        # 添加共享文件夹
        server.addShare(share_name, share_path, shareComment='SMB Share')
        
        # 设置权限
        if username and password:
            lmhash = compute_lmhash(password)
            nthash = compute_nthash(password)
            server.addCredential(username, 0, lmhash, nthash)
            server.setSMB2Support(True)
            # [v1.12] 优化兼容性: 允许计算机名访问时的匿名探测
            server.setSMBChallenge('')
        else:
            server.setSMB2Support(True)
            server.setSMBChallenge('')

        logger.info("SMB 服务准备就绪，开始监听...")
        
        # [v1.57] 在 start 之前对内部 TCPServer 挂载监控钩子
        # SimpleSMBServer 用 name mangling 隐藏了 __server
        # 尝试两种可能的混淆名称
        try:
            internal_server = getattr(server, '_SimpleSMBServer__server', 
                                    getattr(server, '_SMBServer__server', None))
            
            if internal_server is None:
                raise AttributeError("无法访问内部 TCPServer 对象")
                
            print(f"[INIT] 找到内部 TCPServer: {type(internal_server)}")
            
            # 保存原方法
            old_process = internal_server.process_request
            
            # 定义新方法
            def logged_process(request, client_address):
                print(f"[CONN] 新连接: {client_address}")
                return old_process(request, client_address)
            
            # 替换
            internal_server.process_request = logged_process
            print("[INIT] 内部 TCPServer 监控钩子挂载成功")
        except Exception as e:
            print(f"[ERROR] 内部钩子挂载失败: {e}")
        
        # 启动服务
        server.start()
        
    except SystemExit:
        logger.info("SMB 服务子进程正在退出...")
        # 尝试清理资源 (SimpleSMBServer 没有 close 方法 exposed easily, 但 socket 会被系统回收)
        try:
             # 如果能访问到 server._SMBServer__server (ThreadingTCPServer)
             if 'server' in locals():
                 server._SMBServer__server.server_close()
                 logger.info("Socket 资源已主动释放")
        except:
             pass
    except Exception as e:
        logger.error(f"子进程发生严重错误: {str(e)}")
        # 同时打印到 stderr 以便调试
        if sys.stderr:
            try:
                print(f"[SMB Process Error] {str(e)}", file=sys.stderr)
            except Exception:
                pass
        sys.exit(1)

class SMBService:
    def __init__(self, share_name, share_path, username=None, password=None, port=445, log_queue=None):
        self.share_name = share_name
        self.share_path = share_path
        self.username = username
        self.password = password
        self.val_port = port 
        self.log_queue = log_queue
        # [v2.2] 支持多进程 (监听多个端口)
        self.processes = [] 
        self.logger = logging.getLogger('SMBServer')

    def start(self, legacy_mode=False):
        """启动 SMB 服务进程 (支持多端口)"""
        if self.processes:
            self.logger.warning("服务已经在运行中")
            return

        ports_to_listen = [self.val_port]
        if legacy_mode:
            ports_to_listen.append(139)

        local_ip = get_local_ip()
        hostname = get_hostname()
        ipv6 = get_local_ipv6()

        for p in ports_to_listen:
            self.logger.info(f"正在启动服务进程 (端口 {p})...")
            
            # 使用 multiprocessing 启动 IPv4 服务
            proc = multiprocessing.Process(
                target=run_smb_server_process,
                args=(self.share_name, self.share_path, self.username, self.password, p, self.log_queue, '0.0.0.0'),
                daemon=True
            )
            proc.start()
            self.processes.append(proc)
            
            # [v1.54] 如果有 IPv6 地址，启动额外的 IPv6 服务进程
            if ipv6 and p == self.val_port:
                self.logger.info(f"正在启动 IPv6 服务进程 (端口 {p})...")
                ipv6_proc = multiprocessing.Process(
                    target=run_smb_server_process,
                    args=(self.share_name, self.share_path, self.username, self.password, p, self.log_queue, '::'),
                    daemon=True
                )
                ipv6_proc.start()
                self.processes.append(ipv6_proc)
            elif p == self.val_port and not ipv6:
                self.logger.warning(f"未检测到 IPv6 地址，跳过 IPv6 服务")
            
            # [v1.35] 如果启用了兼容模式 (legacy_mode)，我们除了监听端口 139，
            # 还需要启动 NBNS 服务 (UDP 137) 来替代被禁用的 Windows NetBT 服务
            # 这样复印机才能通过 computer name 找到我们
            if legacy_mode and p == 139:
                self.logger.info("正在启动内置 NBNS 名称解析服务 (UDP 137)...")
                nbns_proc = multiprocessing.Process(
                    target=run_nbns_server,
                    args=(self.log_queue,),
                    daemon=True
                )
                nbns_proc.start()
                self.processes.append(nbns_proc)
            
            # 简单检查
            time.sleep(0.5)
            if not proc.is_alive():
                self.logger.error(f"端口 {p} 的服务进程启动失败 (Exit Code: {proc.exitcode})")
                # 不阻断其他端口尝试

        self.logger.info(f"服务启动尝试完成")
        self.logger.info(f"═══════════════════════════════════════")
        self.logger.info(f"📁 共享名称: {self.share_name}")
        self.logger.info(f"📂 共享路径: {self.share_path}")
        self.logger.info(f"🔌 监听端口: {verbs_ports(ports_to_listen)}")
        self.logger.info(f"═══════════════════════════════════════")
        self.logger.info(f"🌐 可用访问方式:")
        self.logger.info(f"   \\\\{local_ip}\\{self.share_name} (IPv4)")
        
        # [v1.56] 显示 IPv6 访问方式（处理 scope ID）
        ipv6 = get_local_ipv6()
        if ipv6:
            # Windows UNC 路径中 IPv6 需要特殊格式
            # 处理带 scope ID 的地址（如 fe80::xxx%4）
            if '%' in ipv6:
                # 提取地址和 scope ID
                addr, scope = ipv6.split('%')
                # 格式：fe80--xxx-s4.ipv6-literal.net (s 后面跟 scope ID)
                ipv6_unc = addr.replace(':', '-') + f"-s{scope}.ipv6-literal.net"
            else:
                ipv6_unc = ipv6.replace(':', '-') + ".ipv6-literal.net"
            self.logger.info(f"   \\\\{ipv6_unc}\\{self.share_name} (IPv6 Link-Local)")
            # 也显示直接地址格式供参考
            self.logger.info(f"   \\\\\\\\[{ipv6}]\\\\{self.share_name} (IPv6 直接格式)")
        
        self.logger.info(f"   \\\\{hostname}\\{self.share_name} (计算机名)")
        self.logger.info(f"═══════════════════════════════════════")

    def stop(self):
        """停止所有服务进程"""
        if not self.processes:
            return

        self.logger.info("正在停止所有服务进程...")
        
        for proc in self.processes:
            try:
                if proc.is_alive():
                    proc.terminate()
                    proc.join(timeout=2) # 增加等待时间
                    if proc.is_alive():
                        self.logger.warning(f"进程 {proc.pid} 未响应，强制 Kill...")
                        proc.kill()
                        proc.join(timeout=1)
            except Exception as e:
                self.logger.error(f"停止进程时出错: {e}")
        
        self.processes = []
        self.logger.info("服务已全部停止")

    def check_port_conflict(self, preferred_port=445, fallback_port=4445):
        """检查端口冲突并返回可用端口"""
        if not is_port_in_use(preferred_port):
            return preferred_port
        
        self.logger.warning(f"端口 {preferred_port} 被占用，尝试切换到 {fallback_port}")
        if not is_port_in_use(fallback_port):
            return fallback_port
        
        self.logger.error(f"端口 {preferred_port} 和 {fallback_port} 均被占用")
        return None

def verbs_ports(ports):
    return ", ".join(str(p) for p in ports)

