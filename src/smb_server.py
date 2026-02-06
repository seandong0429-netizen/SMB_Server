
import multiprocessing
import logging
import time
import sys
import os
from src.utils import get_local_ip, get_hostname
from src.logger import QueueHandler
from src.nbns_server import run_nbns_server

# 独立的进程函数，避免 Pickling 问题
def run_smb_server_process(share_name, share_path, username, password, port, log_queue):
    """在独立进程中运行 SMB 服务"""
    
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

        # 延迟导入 impacket，以便捕获 ImportError
        # 在打包环境中，如果缺少 hidden import，这里会抛出异常，现在可以被 log 捕获了
        from impacket import smbserver
        from impacket.ntlm import compute_lmhash, compute_nthash
        import signal
        from src.license_manager import license_manager

        # [v2.0] Double-check License in child process
        valid, msg, _ = license_manager.verify()
        if not valid:
            logger.error(f"[FATAL] License Validation Failed: {msg}")
            sys.exit(1)


        
        # 更好的方法：我们在创建 SimpleSMBServer 之前，Hack socketserver
        import socketserver
        socketserver.TCPServer.allow_reuse_address = True

        # 定义优雅关闭的信号处理
        def signal_handler(signum, frame):
            logger.info(f"接收到终止信号 ({signum})，正在关闭 SMB 服务...")
            # 由于 server.start() 是阻塞的，我们需要在另一个线程或回调中关闭
            # 但在这里，我们可以抛出异常或者调用 server 停止方法 如果 server 是全局的
            # 这是一个难点。SimpleSMBServer.start() 是死循环。
            # 我们通过 sys.exit() ? 不，这会导致 finally 块执行
            sys.exit(0)

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        logger.info("已开启端口重用 (allow_reuse_address=True)")

        try:
            # [v1.22] 尝试优先绑定 IPv6 (::) 以支持双栈 (如果系统支持)
            # 现代 Windows 的 localhost 经常解析为 ::1，如果只监听 IPv4 会导致 connection refused
            server = smbserver.SimpleSMBServer(listenAddress='::', listenPort=port)
            logger.info("已绑定 IPv6 双栈接口 (::)")
        except Exception as e:
            logger.warning(f"绑定 IPv6 失败 ({e})，回退到 IPv4 (0.0.0.0)")
            server = smbserver.SimpleSMBServer(listenAddress='0.0.0.0', listenPort=port)
            
        # [v1.14] 显式设置服务端名称，防止 NTLM 身份验证时的目标名称不匹配SimpleSMBServer object has no attribute 'setServerName'
        # 我们暂时不仅是用此方法，而是依赖 hosts 文件和注册表
        # real_hostname = get_hostname()
        # if real_hostname:
        #     server.setServerName(real_hostname)
        
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

        for p in ports_to_listen:
            self.logger.info(f"正在启动服务进程 (端口 {p})...")
            
            # 使用 multiprocessing 启动
            proc = multiprocessing.Process(
                target=run_smb_server_process,
                args=(self.share_name, self.share_path, self.username, self.password, p, self.log_queue),
                daemon=True
            )
            proc.start()
            self.processes.append(proc)
            
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
        self.logger.info(f"主机名: {hostname}")
        self.logger.info(f"监听端口: {verbs_ports(ports_to_listen)}")
        self.logger.info(f"共享路径: {self.share_name} -> {self.share_path}")

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

