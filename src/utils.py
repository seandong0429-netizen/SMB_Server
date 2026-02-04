
import socket
import logging
import platform
import sys
import os
import subprocess

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
        config_msg = ""
        if config_res.returncode == 0:
            config_msg = "\n已设置为【手动启动】，重启依然有效。"
        else:
            config_msg = "\n但设置为手动启动失败，重启后可能失效。"
            
        # 3. 验证端口是否真的释放
        # 有时候服务停了，socket 还没释放，需要等一会
        import time
        for i in range(10): # 尝试 10 次，每次 0.5 秒
            if not is_port_in_use(445):
                return True, "成功停止 Server 服务，端口 445 已释放。" + config_msg
            time.sleep(0.5)

        # 如果还没释放，尝试查看是谁占用
        kill_msg = ""
        try:
            # netstat -ano | findstr :445
            netstat = subprocess.run("netstat -ano", shell=True, capture_output=True, text=True)
            for line in netstat.stdout.splitlines():
                if ":445 " in line and "LISTENING" in line:
                    parts = line.strip().split()
                    pid = parts[-1]
                    if pid == "4":
                        kill_msg = "\n\n端口仍被 System (PID 4) 占用，这通常是 Windows 内核驱动 (srv.sys) 未释放。\n可能需要【重启电脑】才能完全生效。"
                    else:
                        kill_msg = f"\n\n端口仍被 PID {pid} 占用，请手动结束该进程。"
                    break
        except Exception:
            pass

        return False, "服务显示已停止，但端口 445 依然被占用。" + config_msg + kill_msg
            
    except Exception as e:
        return False, f"执行命令出错: {str(e)}"

def fix_port_445_environment():
    """
    一键修复环境 (增强版)：
    1. 禁用服务/驱动: srv2, srvnet, server (LanmanServer), SMBDevice
    2. 设置注册表 Start=4 (禁用)
    3. 停止相关服务
    4. 如果没有管理员权限，自动申请提权
    """
    if platform.system() != 'Windows':
        return False, "非 Windows 系统"

    import ctypes
    
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    # 目标服务列表
    services = ['srv2', 'srvnet', 'LanmanServer'] # LanmanServer is 'server'
    # 注册表项列表
    reg_keys = ['SMBDevice', 'srv2', 'srvnet']

    # 如果不是管理员，构造 CMD 命令提权执行
    if not is_admin():
        commands = [
            'echo 正在尝试强力修复 445 端口环境，请勿关闭窗口...',
            'echo 正在禁用系统 SMB 驱动和服务...'
        ]
        
        # 1. SC Config Disabled
        # 注意: sc config <service> start= disabled (注意空格)
        for svc in ['srv2', 'srvnet']:
             commands.append(f'sc config {svc} start= disabled')
        
        # 2. Registry Start=4
        for key in reg_keys:
            commands.append(f'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{key}" /v Start /t REG_DWORD /d 4 /f')
            
        # 3. Net Stop
        # 顺序很重要，先停依赖项
        for svc in ['srv2', 'srvnet', 'server']:
            commands.append(f'net stop {svc} /y')

        commands.append('echo.')
        commands.append('echo ---------------------------------------')
        commands.append('echo 修复命令已发送。')
        commands.append('echo 如果显示成功，请务必手动重启电脑！')
        commands.append('echo ---------------------------------------')
        commands.append('pause')

        cmd_str = ' && '.join(commands)
        
        try:
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", f"/c {cmd_str}", None, 1)
            if ret > 32:
                return True, "已尝试申请管理员权限执行强力修复。\n\n请在弹出的黑色窗口中查看执行结果。\n关键步骤：SC禁用服务、注册表禁用驱动、停止服务。\n\n如果有任何成功提示，请务必【重启电脑】。"
            else:
                return False, "申请管理员权限失败，用户可能取消了操作。"
        except Exception as e:
            return False, f"提权执行失败: {str(e)}"

    # 管理员模式逻辑 (Python 直接执行)
    try:
        import winreg
        import subprocess
        
        # 1. 修改注册表
        for service_name in reg_keys:
            try:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                        f"SYSTEM\\CurrentControlSet\\Services\\{service_name}", 
                                        0, winreg.KEY_SET_VALUE)
                except FileNotFoundError:
                    # 尝试创建
                    key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, f"SYSTEM\\CurrentControlSet\\Services\\{service_name}")
                
                winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 4)
                winreg.CloseKey(key)
            except Exception as e:
                print(f"设置注册表 {service_name} 失败: {e}")

        # 2. SC Config Disabled
        for svc in ['srv2', 'srvnet']:
            subprocess.run(f"sc config {svc} start= disabled", shell=True, capture_output=True)

        # 3. 停止服务
        for svc in ['srv2', 'srvnet', 'server']:
            subprocess.run(f"net stop {svc} /y", shell=True, capture_output=True)

        # 4. 额外增强: 直接使用 SC 禁用服务 (防止注册表修改失败)
        # 针对部分系统找不到注册表项的情况
        try:
            subprocess.run("sc config lanmanserver start= disabled", shell=True, capture_output=True)
            subprocess.run("sc config srv2 start= disabled", shell=True, capture_output=True)
            subprocess.run("sc config srvnet start= disabled", shell=True, capture_output=True)
            # 5. 清理 NetBIOS 缓存 (解决部分占用的玄学问题)
            subprocess.run("nbtstat -R", shell=True, capture_output=True)
            subprocess.run("nbtstat -RR", shell=True, capture_output=True)
            subprocess.run("nbtstat -RR", shell=True, capture_output=True)
            subprocess.run("nbtstat -RR", shell=True, capture_output=True)

            # 6. [NEW] 确保 NetBIOS Helper 和 Computer Browser 服务开启
            # 停止了 Server 服务可能会影响 Browser，尝试强制开启 lmhosts (TCP/IP NetBIOS Helper)
            # 这对计算机名解析至关重要
            subprocess.run("sc config lmhosts start= auto", shell=True, capture_output=True)
            subprocess.run("net start lmhosts /y", shell=True, capture_output=True)

            # [v1.12] 强制开启 FDResPub (Function Discovery Resource Publication)
            # 这让电脑能在"网络"邻居里被发现 (WSD协议)
            subprocess.run("sc config FDResPub start= auto", shell=True, capture_output=True)
            subprocess.run("net start FDResPub /y", shell=True, capture_output=True)
            
            # Browser 服务通常依赖 Server 服务，如果 Server 被我们关了，Browser 也起不来
            # 但我们还是尝试一下，或者至少保证 lmhosts 是活着的

            # 6. [NEW] 注册表优化: 允许别名访问 (DisableStrictNameChecking) 和 回环检查 (DisableLoopbackCheck)
            # 这对于通过计算机名访问非常关键
            try:
                # LanmanServer Parameters
                key_params = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                          r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", 
                                          0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key_params, "DisableStrictNameChecking", 0, winreg.REG_DWORD, 1)
                winreg.CloseKey(key_params)

                # Lsa
                key_lsa = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                       r"SYSTEM\CurrentControlSet\Control\Lsa", 
                                       0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key_lsa, "DisableLoopbackCheck", 0, winreg.REG_DWORD, 1)
                winreg.CloseKey(key_lsa)
            except Exception:
                # 如果打开失败，尝试用命令补充
                subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v DisableStrictNameChecking /t REG_DWORD /d 1 /f', shell=True, capture_output=True)
                subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v DisableLoopbackCheck /t REG_DWORD /d 1 /f', shell=True, capture_output=True)

        except Exception:
            pass
        
        return True, "环境修复完成 (强力模式)。\n\n已执行：\n1. 禁用 srv2, srvnet 服务\n2. 注册表禁用 SMBDevice, srv2, srvnet 驱动\n3. 停止相关服务\n\n请务必【重启电脑】以确保生效。"



    except Exception as e:
        return False, f"执行修复操作失败: {str(e)}"

def manage_firewall_rule(action, port=445):
    """
    管理 Windows 防火墙规则
    action: 'add' or 'delete'
    port: 端口号
    """
    if platform.system() != 'Windows':
        return
        
    rule_name = f"PythonSMBServer_Port{port}"
    
    if action == 'add':
        # 先尝试删除旧规则，避免重复 (包括新的 _TCP/_UDP 和旧的默认规则)
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name}"', shell=True, capture_output=True)
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name}_TCP"', shell=True, capture_output=True)
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name}_UDP"', shell=True, capture_output=True)
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name}_ICMP"', shell=True, capture_output=True)
        # 添加新规则 (TCP 445 + 139) - 139 是 NetBIOS Session，虽然 Impacket 主要用 445，但旧系统可能探测
        # profile=any 确保在公用/专用网络下都生效
        cmd_tcp = f'netsh advfirewall firewall add rule name="{rule_name}_TCP" dir=in action=allow protocol=TCP localport="445,139" profile=any'
        
        # 添加 UDP 覆盖 (UDP 445, 137, 138, 5355) 增强发现
        # 5355 is LLMNR (Link-Local Multicast Name Resolution) - vital for hostname with no DNS
        cmd_udp = f'netsh advfirewall firewall add rule name="{rule_name}_UDP" dir=in action=allow protocol=UDP localport="445,137,138,5355" profile=any'
        
        # [NEW] 允许 ICMP (Ping) - 有助于网络发现
        cmd_icmp = f'netsh advfirewall firewall add rule name="{rule_name}_ICMP" dir=in action=allow protocol=icmpv4:8,any profile=any'

        res_tcp = subprocess.run(cmd_tcp, shell=True, capture_output=True, text=True)
        res_udp = subprocess.run(cmd_udp, shell=True, capture_output=True, text=True)
        res_icmp = subprocess.run(cmd_icmp, shell=True, capture_output=True, text=True)
        
        if res_tcp.returncode != 0:
            logging.error(f"添加防火墙规则(TCP)失败: {res_tcp.stderr}")
        else:
            logging.info(f"已添加防火墙规则: {rule_name}_TCP")
            
        if res_udp.returncode != 0:
            # UDP 失败不影响核心功能，警告即可
            logging.warning(f"添加防火墙规则(UDP)失败: {res_udp.stderr}")
        else:
            logging.info(f"已添加防火墙规则: {rule_name}_UDP")
            
    elif action == 'delete':
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name}_TCP"', shell=True, capture_output=True)
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name}_UDP"', shell=True, capture_output=True)
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name}_ICMP"', shell=True, capture_output=True)
        
        # 兼容旧版本规则名
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name}"', shell=True, capture_output=True)
        logging.info(f"已移除防火墙规则: {rule_name}")

