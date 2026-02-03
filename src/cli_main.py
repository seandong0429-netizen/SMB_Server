
import sys
import os
import time
import logging
import signal
import threading

# Ensure src is in path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.utils import get_local_ip, get_hostname, is_port_in_use
# Do NOT import src.main to avoid tkinter

# Check for impacket
try:
    from src.smb_server import SMBService
except ImportError:
    print("错误: 找不到 impacket 模块。")
    print("请先安装依赖: python3 -m pip install impacket")
    sys.exit(1)

def setup_cli_logger():
    logger = logging.getLogger('SMBServer')
    logger.setLevel(logging.INFO)
    
    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%H:%M:%S')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger

def signal_handler(sig, frame):
    print("\n接收到停止信号，正在关闭服务...")
    # This might not be enough for threads but better than nothing
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    logger = setup_cli_logger()

    print("=== 独立 SMB 服务端 (CLI版) ===")
    print(f"主机名: {get_hostname()}")
    print("由于 GUI 在当前环境不可用，启动命令行模式。\n")

    # 1. Path
    default_path = os.getcwd()
    path = input(f"请输入共享文件夹路径 [默认: current dir]: ").strip()
    if not path:
        path = default_path
    
    if not os.path.exists(path):
        print(f"错误: 路径 '{path}' 不存在")
        return

    # 2. Name
    name = input(f"请输入共享名称 [默认: MyShare]: ").strip()
    if not name:
        name = "MyShare"

    # 3. Port
    port_str = input(f"请输入监听端口 [默认: 445]: ").strip()
    if not port_str:
        port = 445
    else:
        try:
            port = int(port_str)
        except ValueError:
            print("端口必须是数字")
            return

    # 4. Auth
    auth = input(f"需要身份验证吗? (y/N) [默认: N]: ").strip().lower()
    username = None
    password = None
    if auth == 'y':
        username = input("请输入用户名: ").strip()
        password = input("请输入密码: ").strip()
        if not username or not password:
            print("用户名和密码不能为空")
            return

    # Check port
    if is_port_in_use(port):
        print(f"警告: 端口 {port} 已被占用")
        choice = input(f"是否尝试使用端口 4445? (Y/n): ").strip().lower()
        if choice != 'n':
            port = 4445
            if is_port_in_use(port):
                print(f"错误: 端口 {port} 也被占用")
                return
        else:
            return

    print("\n正在启动服务...")
    
    server = SMBService(name, path, username, password, port)
    server.start()

    print("\n服务运行中。按 Ctrl+C 停止。")
    
    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n正在停止...")
        server.stop()

if __name__ == "__main__":
    main()
