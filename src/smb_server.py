
import multiprocessing
import logging
import time
import sys
from impacket import smbserver
from impacket.ntlm import compute_lmhash, compute_nthash
from src.utils import get_local_ip, get_hostname, is_port_in_use

# 独立的进程函数，避免 Pickling 问题
def run_smb_server_process(share_name, share_path, username, password, port):
    """在独立进程中运行 SMB 服务"""
    # 在子进程中重新配置日志（可选，或者直接打印到 stdout）
    # 这里简单起见，不配置复杂日志，impacket 默认会打印到 console
    
    try:
        # 初始化 SimpleSMBServer
        server = smbserver.SimpleSMBServer(listenAddress='0.0.0.0', listenPort=port)
        
        # 添加共享文件夹
        server.addShare(share_name, share_path, shareComment='SMB Share')
        
        # 设置权限
        if username and password:
            lmhash = compute_lmhash(password)
            nthash = compute_nthash(password)
            server.addCredential(username, 0, lmhash, nthash)
            server.setSMB2Support(True)
            server.setSMBChallenge('')
        else:
            server.setSMB2Support(True)
            server.setSMBChallenge('')
            server.setSMB2Support(True)

        # 启动服务
        server.start()
        
    except Exception as e:
        # 子进程中的错误最好能通过管道传回，或者打印
        print(f"[SMB Process] Error: {str(e)}")
        sys.exit(1)

class SMBService:
    def __init__(self, share_name, share_path, username=None, password=None, port=445):
        self.share_name = share_name
        self.share_path = share_path
        self.username = username
        self.password = password
        self.val_port = port # Rename to avoid conflict if any
        self.process = None
        self.logger = logging.getLogger('SMBServer')

    def start(self):
        """启动 SMB 服务进程"""
        if self.process and self.process.is_alive():
            self.logger.warning("服务已经在运行中")
            return

        self.logger.info(f"正在启动服务进程 (端口 {self.val_port})...")
        
        # 使用 multiprocessing 启动
        # 注意 args 必须是 picklable 的
        self.process = multiprocessing.Process(
            target=run_smb_server_process,
            args=(self.share_name, self.share_path, self.username, self.password, self.val_port),
            daemon=True
        )
        self.process.start()
        
        local_ip = get_local_ip()
        hostname = get_hostname()
        self.logger.info(f"服务进程已启动 (PID: {self.process.pid})")
        self.logger.info(f"主机名: {hostname}")
        self.logger.info(f"监听地址: {local_ip}:{self.val_port}")
        self.logger.info(f"共享路径: {self.share_name} -> {self.share_path}")

    def stop(self):
        """停止服务"""
        if not self.process:
            return

        self.logger.info("正在停止服务进程...")
        
        if self.process.is_alive():
            # 强制终止进程 - 这是使用 multiprocessing 的主要优势
            # 可以立即释放端口，不需要等待 socket 超时
            self.process.terminate()
            self.process.join(timeout=2) # 等待进程结束
            
            if self.process.is_alive():
                 self.logger.warning("进程未响应，正在强制 Kill...")
                 self.process.kill() # 更加暴力的 Kill
            
            self.logger.info("服务进程已终止")
        else:
            self.logger.info("服务进程此前已结束")
            
        self.process = None

    def check_port_conflict(self, preferred_port=445, fallback_port=4445):
        """检查端口冲突并返回可用端口"""
        if not is_port_in_use(preferred_port):
            return preferred_port
        
        self.logger.warning(f"端口 {preferred_port} 被占用，尝试切换到 {fallback_port}")
        if not is_port_in_use(fallback_port):
            return fallback_port
        
        self.logger.error(f"端口 {preferred_port} 和 {fallback_port} 均被占用")
        return None

