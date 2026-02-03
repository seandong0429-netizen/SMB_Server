
import socket
import logging
import platform
import sys
import os

def set_windows_startup(name, enable=True):
    """设置 Windows 开机自启 (通过注册表)"""
    if platform.system() != 'Windows':
        return False, "非 Windows 系统"

    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                            r"Software\Microsoft\Windows\CurrentVersion\Run", 
                            0, winreg.KEY_ALL_ACCESS)
        
        if enable:
            # 获取当前运行的 python 解释器和脚本路径
            # 如果是打包后的 exe，sys.executable 就是 exe 路径
            # 如果是脚本运行，则是 python.exe 路径，需加上参数
            if getattr(sys, 'frozen', False):
                cmd = f'"{sys.executable}"'
            else:
                # 假设从 run.py 启动，定位到项目根目录的 run.py
                # 向上找两级: src -> root
                root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                script = os.path.join(root_dir, 'run.py')
                # 使用 pythonw.exe 避免黑框 (如果存在)
                py_exe = sys.executable.replace("python.exe", "pythonw.exe")
                if not os.path.exists(py_exe):
                    py_exe = sys.executable
                cmd = f'"{py_exe}" "{script}"'
            
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, cmd)
            winreg.CloseKey(key)
            return True, "已开启开机自启"
        else:
            try:
                winreg.DeleteValue(key, name)
            except FileNotFoundError:
                pass
            winreg.CloseKey(key)
            return True, "已关闭开机自启"
            
    except Exception as e:
        return False, f"注册表操作失败: {str(e)}"

def check_windows_startup(name):
    """检查是否已开启自启"""
    if platform.system() != 'Windows':
        return False

    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                            r"Software\Microsoft\Windows\CurrentVersion\Run", 
                            0, winreg.KEY_READ)
        winreg.QueryValueEx(key, name)
        winreg.CloseKey(key)
        return True
    except FileNotFoundError:
        return False
    except Exception:
        return False

def get_local_ip():
    """获取本机局域网IP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 这里的 IP 并不需要实际可达，只是用来通过路由表确定本机 IP
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'

def get_hostname():
    """获取本机计算机名"""
    return socket.gethostname()

def is_port_in_use(port):
    """检查端口是否被占用"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def stop_windows_server_service():
    """停止 Windows Server 服务 (释放 445 端口)"""
    if platform.system() != 'Windows':
        return False, "非 Windows 系统"

    import subprocess
    
    try:
        # 1. 停止服务: net stop LanmanServer /y
        stop_cmd = "net stop LanmanServer /y"
        stop_res = subprocess.run(stop_cmd, shell=True, capture_output=True, text=True)
        
        # 2. 设置为手动启动: sc config LanmanServer start= demand
        # 这样重启后它就不会自动抢占端口
        config_cmd = "sc config LanmanServer start= demand"
        config_res = subprocess.run(config_cmd, shell=True, capture_output=True, text=True)
        
        # 检查停止结果
        if stop_res.returncode == 0:
            msg = "成功停止 Server 服务。"
        elif "The service is not started" in stop_res.stderr or "服务没有启动" in stop_res.stderr:
            msg = "服务本来就未启动。"
        else:
            return False, f"停止服务失败: {stop_res.stderr.strip() or stop_res.stdout.strip()}"

        # 检查配置结果
        if config_res.returncode == 0:
            msg += "\n已设置为【手动启动】，重启依然有效。"
        else:
            msg += "\n但设置为手动启动失败，重启后可能失效。"
            
        return True, msg
            
    except Exception as e:
        return False, f"执行命令出错: {str(e)}"
