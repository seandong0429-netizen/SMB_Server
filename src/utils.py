
import socket
import logging
import platform
import sys
import os
import subprocess
import time
import re
import ctypes

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
        for svc in ['srv2', 'srvnet', 'server', 'NetBT']:
            commands.append(f'net stop {svc} /y')

        # 4. [v1.17] 启动关键依赖服务 (WSD, NetBIOS)
        # 必须先启动 SSDPSRV (SSDP Discovery) 才能启动 FDResPub
        for svc in ['SSDPSRV', 'FDResPub', 'lmhosts']:
            commands.append(f'sc config {svc} start= auto')
            commands.append(f'net start {svc} /y')

        # 5. [v1.17] 注册表优化与 Hosts修复 
        # (由于 CMD 写入 Hosts 较复杂，这里主要保证注册表和缓存清理)
        commands.append('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v DisableStrictNameChecking /t REG_DWORD /d 1 /f')
        commands.append('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v DisableLoopbackCheck /t REG_DWORD /d 1 /f')
        commands.append('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" /v AllowInsecureGuestAuth /t REG_DWORD /d 1 /f')
        # [v2.2] 强制 NetBT 广播模式 (NodeType=1)
        commands.append('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netbt\\Parameters" /v NodeType /t REG_DWORD /d 1 /f')
        
        # [v2.2] 强制 NetBIOS 重广播
        commands.append('nbtstat -RR')
        commands.append('ipconfig /flushdns')

        # Hosts 文件修改比较困难仅靠 CMD 一行命令 (涉及换行符)，
        # 我们仍依赖 Python 部分在提权失败时尝试，或者用户手动运行。
        # 但既然已经提权，Python 后续的 try...except 逻辑其实不会执行到(因为 ShellExecuteW 返回后 current process 还是非 admin)
        # 等等，当前的逻辑是: if not is_admin -> ShellExecuteW -> return
        # 所以 Python 的后续逻辑根本不会跑！这是一个巨大的设计漏洞。
        # 我们必须让 Python 逻辑在提权后也能跑，但这不可能 (那是另一个进程)。
        # 所以必须把所有逻辑都塞进 commands，或者让 Python 重新以 admin 启动自己? 
        # 简单方案: 尽可能在 CMD 里做完。
        # Hosts 文件追加一行: echo 127.... >> ... 
        
        # [v1.21] 解锁 Hosts 文件 (去只读/隐藏/系统属性)
        # 很多时候写入失败是因为文件属性被设为了只读
        commands.append(f'attrib -r -s -h "C:\\Windows\\System32\\drivers\\etc\\hosts"')

        # [v1.21] 使用 PowerShell 写入 Hosts (Hybrid Strategy)
        # 1. 再次确保去只读
        # 2. 检测最后一行是否有换行符，没有则补齐
        # 3. 追加记录
        # 4. 强制刷新 DNS
        ps_script = """
        $hosts = 'C:\\Windows\\System32\\drivers\\etc\\hosts';
        if (Test-Path $hosts) {
            Set-ItemProperty -Path $hosts -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue;
            $content = Get-Content $hosts -Raw;
            if ($content -notmatch '\\n$') { Add-Content -Path $hosts -Value \"`r`n\" -NoNewline };
            Add-Content -Path $hosts -Value \"127.0.0.1 $env:COMPUTERNAME\" -Force;
        }
        """
        # 将多行 PS 脚本压缩为一行执行 (由于 cmd limitation，稍微简化一下)
        # 实际上直接用 multiple Add-Content 比较稳
        
        commands.append(f'powershell -Command "Set-ItemProperty -Path \'C:\\Windows\\System32\\drivers\\etc\\hosts\' -Name IsReadOnly -Value $false"')
        # 补换行 (如果需要) - 简单粗暴补一个空行
        commands.append(f'powershell -Command "Add-Content -Path \'C:\\Windows\\System32\\drivers\\etc\\hosts\' -Value \"`r`n\" -Force"')
        # 追加记录
        commands.append(f'powershell -Command "Add-Content -Path \'C:\\Windows\\System32\\drivers\\etc\\hosts\' -Value \"127.0.0.1 $env:COMPUTERNAME\" -Force"')

        # [v2.3 Fix] 强力操作: 禁用网卡上的 "File and Printer Sharing" 绑定 (ms_server)
        # 这必须在提权的 CMD 串中执行，否则普通用户点击无效
        ps_unbind_cmd = 'Get-NetAdapter | Disable-NetAdapterBinding -ComponentID ms_server -PassThru'
        # 注意转义双引号
        commands.append(f'powershell -Command "{ps_unbind_cmd}"')

        # commands.append(f'echo.>>"{hosts_f}"') # 确保新行
        # commands.append(f'echo 127.0.0.1 {hn} # Auto-added>>"{hosts_f}"')

        commands.append('echo.')
        commands.append('echo ---------------------------------------')
        commands.append('echo 修复命令已发送。')
        commands.append('echo 必须重启电脑！')
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
        # [v1.34] 显式停止 NetBT (NetBIOS over TCP/IP) 驱动服务
        # 这是 PID 4 占用 Port 139 的根源
        for svc in ['srv2', 'srvnet', 'server', 'NetBT']:
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

            # [v2.3 Fix] 强力操作: 禁用网卡上的 "File and Printer Sharing" 绑定 (ms_server)
            # 这能彻底释放 Port 139/445 而不需要禁用整个 NetBIOS
            # 需要 PowerShell 并且管理员权限
            try:
                ps_unbind_cmd = 'Get-NetAdapter | Disable-NetAdapterBinding -ComponentID ms_server -PassThru'
                subprocess.run(f'powershell -Command "{ps_unbind_cmd}"', shell=True, capture_output=True)
            except Exception as e:
                print(f"尝试禁用 ms_server 绑定失败: {e}")

            # [v2.3] 强力操作: 禁用网卡上的 "File and Printer Sharing" 绑定 (ms_server)
            # 这能彻底释放 Port 139/445 而不需要禁用整个 NetBIOS
            # 需要 PowerShell 并且管理员权限
            try:
                ps_unbind_cmd = 'Get-NetAdapter | Disable-NetAdapterBinding -ComponentID ms_server -PassThru'
                subprocess.run(f'powershell -Command "{ps_unbind_cmd}"', shell=True, capture_output=True)
            except Exception as e:
                print(f"尝试禁用 ms_server 绑定失败: {e}")

            # 6. [NEW] 确保 NetBIOS Helper 和 Computer Browser 服务开启
            # 停止了 Server 服务可能会影响 Browser，尝试强制开启 lmhosts (TCP/IP NetBIOS Helper)
            # 这对计算机名解析至关重要
            subprocess.run("sc config lmhosts start= auto", shell=True, capture_output=True)
            subprocess.run("net start lmhosts /y", shell=True, capture_output=True)

            # [v1.17] 强制开启依赖服务 SSDPSRV (SSDP Discovery)
            subprocess.run("sc config SSDPSRV start= auto", shell=True, capture_output=True)
            subprocess.run("net start SSDPSRV /y", shell=True, capture_output=True)

            # [v1.12] 强制开启 FDResPub (Function Discovery Resource Publication)
            # 这让电脑能在"网络"邻居里被发现 (WSD协议)
            subprocess.run("sc config FDResPub start= auto", shell=True, capture_output=True)
            subprocess.run("net start FDResPub /y", shell=True, capture_output=True)
            
            # [v2.2] 注册表: 强制 NodeType=1 (Broadcast)
            try:
                key_netbt = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                           r"SYSTEM\CurrentControlSet\Services\Netbt\Parameters", 
                                           0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key_netbt, "NodeType", 0, winreg.REG_DWORD, 1)
                winreg.CloseKey(key_netbt)
            except Exception:
                subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netbt\\Parameters" /v NodeType /t REG_DWORD /d 1 /f', shell=True, capture_output=True)

            # [v2.2] 再次刷新 NetBIOS
            subprocess.run("nbtstat -RR", shell=True, capture_output=True)
            
            # [v2.4] 核弹级修复: 遍历注册表强制禁用所有网卡的 NetBIOS
            # 等同于在 TCP/IP 高级设置中选择 "禁用 NetBIOS over TCP/IP"
            try:
                netbt_interfaces_path = r"SYSTEM\CurrentControlSet\Services\Netbt\Parameters\Interfaces"
                try:
                    key_interfaces = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, netbt_interfaces_path, 0, winreg.KEY_READ)
                    num_subkeys = winreg.QueryInfoKey(key_interfaces)[0]
                    
                    print(f"正在扫描 {num_subkeys} 个网络接口配置...")
                    
                    for i in range(num_subkeys):
                        subkey_name = winreg.EnumKey(key_interfaces, i)
                        full_subkey_path = f"{netbt_interfaces_path}\\{subkey_name}"
                        
                        try:
                            # 打开子键 (Write 权限)
                            key_sub = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, full_subkey_path, 0, winreg.KEY_SET_VALUE)
                            # NetbiosOptions: 0=Default, 1=Enable, 2=Disable
                            winreg.SetValueEx(key_sub, "NetbiosOptions", 0, winreg.REG_DWORD, 2)
                            winreg.CloseKey(key_sub)
                            print(f"  - 接口 {subkey_name}: 已强制禁用 NetBIOS (Option=2)")
                        except Exception as e:
                             print(f"  - 接口 {subkey_name} 设置失败: {e}")
                             
                    winreg.CloseKey(key_interfaces)
                    
                except FileNotFoundError:
                    print("未找到 Netbt 接口注册表路径，跳过。")
            except Exception as e:
                print(f"全局禁用 NetBIOS 失败: {e}")

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

            # 7. [NEW v1.13] 客户端访问策略增强 & Hosts 补丁
            try:
                # 允许启用不安全的来宾登录 (针对本机访问本机常遇到的策略阻止)
                # LanmanWorkstation Parameters
                subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" /v AllowInsecureGuestAuth /t REG_DWORD /d 1 /f', shell=True, capture_output=True)
                
                # [Critical Fix] 修改 Hosts 文件，强制本机计算机名解析为 127.0.0.1 (IPv4)
                # 解决 Windows 默认将 localhost/计算机名解析为 IPv6 (::1)，而我们服务仅监听 IPv4 的问题
                hostname = socket.gethostname()
                hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
                entry = f"\n127.0.0.1       {hostname}    # Auto-added by SMBServer"
                
                try:
                    with open(hosts_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    if f"127.0.0.1       {hostname}" not in content:
                        with open(hosts_path, 'a', encoding='utf-8') as f:
                            f.write(entry)
                except Exception as e:
                    subprocess.run(f'echo {entry} >> "{hosts_path}"', shell=True, capture_output=True)

                # 刷新 DNS 缓存以应用 Hosts 修改
                subprocess.run("ipconfig /flushdns", shell=True, capture_output=True)

            except Exception:
                pass

        except Exception:
            pass
        
        return True, "环境修复完成 (强力模式)。\n\n已执行：\n1.全局注册表强制禁用 NetBIOS (释放端口 139)\n2. 禁用网卡上的【文件和打印机共享】绑定\n3. 禁用 srv2, srvnet 服务\n\n请务必【重启电脑】以确保生效。"



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


def run_system_diagnostics():
    """运行系统环境诊断"""
    if platform.system() != 'Windows':
        return "诊断功能仅支持 Windows 系统。"
    
    report = []
    report.append(f"=== 系统环境诊断报告 ({time.strftime('%Y-%m-%d %H:%M:%S')}) ===")
    
    # 1. 主机名解析
    try:
        hostname = socket.gethostname()
        report.append(f"\n[1. 主机名解析]")
        report.append(f"计算机名: {hostname}")
        
        # Check IPv4
        try:
            ip4 = socket.gethostbyname(hostname)
            suffix = ""
            if ip4.startswith("127."):
                suffix = "(优: 指向本地 - Hosts修改生效)"
            elif ip4 == "127.0.0.1":
                suffix = "(优: 指向本地 - Hosts修改生效)"
            else:
                suffix = "(指向局域网IP - 如连接失败请尝试一键修复)"
            report.append(f"IPv4 解析: {ip4} {suffix}")
        except Exception as e:
            report.append(f"IPv4 解析失败: {e}")

        # Check IPv6 preference
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            ips = [info[4][0] for info in addr_info]
            ip_set = set(ips)
            report.append(f"所有解析结果: {', '.join(ip_set)}")
            if '::1' in ip_set:
                 report.append("⚠️ 警告: 解析结果包含 IPv6 回环地址 (::1)。")
                 report.append("   如果不强制 IPv4 (127.0.0.1)，Windows 可能优先尝试 IPv6 连接导致失败。")
        except:
            pass

        # [v2.2] 检查 NetBT NodeType
        try:
             import winreg
             key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netbt\Parameters", 0, winreg.KEY_READ)
             node_type, _ = winreg.QueryValueEx(key, "NodeType")
             winreg.CloseKey(key)
             
             if node_type == 1:
                 report.append("✅ NetBIOS 节点类型: Broadcast (1) - 已优化")
             else:
                 report.append(f"⚠️ NetBIOS 节点类型: {node_type} (建议: Broadcast=1)")
        except Exception:
             report.append("⚠️ NetBIOS 节点类型: 未设置或无法读取 (默认可能是 Hybrid)")

        # [v2.5] 深度诊断: 扫描所有网卡接口的 NetBIOS 状态
        try:
            netbt_interfaces_path = r"SYSTEM\CurrentControlSet\Services\Netbt\Parameters\Interfaces"
            key_interfaces = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, netbt_interfaces_path, 0, winreg.KEY_READ)
            num_subkeys = winreg.QueryInfoKey(key_interfaces)[0]
            
            report.append(f"\n[NetBIOS 接口检查]")
            found_active_netbt = False
            
            for i in range(num_subkeys):
                subkey_name = winreg.EnumKey(key_interfaces, i)
                full_subkey_path = f"{netbt_interfaces_path}\\{subkey_name}"
                try:
                    key_sub = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, full_subkey_path, 0, winreg.KEY_READ)
                    try:
                         # 0=Default(Enable if Static IP or DHCP), 1=Enable, 2=Disable
                         opt, _ = winreg.QueryValueEx(key_sub, "NetbiosOptions")
                         
                         if opt != 2: # 发现未禁用的
                             found_active_netbt = True
                             report.append(f"⚠️ 发现潜在元凶: 接口 {{{subkey_name}}}")
                             report.append(f"   NetbiosOptions = {opt} (未彻底禁用)")
                             
                    except FileNotFoundError:
                        # 默认值通常意味着启用(如果IP是静态的)或由DHCP决定。通常视为潜在风险。
                        # report.append(f"ℹ️ 接口 {subkey_name} 使用默认 NetBIOS 设置 (可能有风险)")
                        pass
                    winreg.CloseKey(key_sub)
                except Exception:
                    pass
            
            if not found_active_netbt:
                 report.append("✅ 所有注册表接口均已显式禁用 NetBIOS (Option=2)。")
            else:
                 report.append("❌ 发现有一个或多个接口开启了 NetBIOS！这可能是 PID 4 占用的原因。")
                 
        except Exception as e:
            report.append(f"接口扫描失败: {e}")
            
    except Exception as e:
        report.append(f"主机名检查出错: {e}")

    # 2. 端口占用 (445 & 139)
    report.append(f"\n[2. 端口状态]")
    for check_port in [445, 139]:
        try:
            res = subprocess.run(f'netstat -ano | findstr :{check_port}', shell=True, capture_output=True, text=True)
            if not res.stdout.strip():
                 report.append(f"端口 {check_port} 未被监听")
            else:
                lines = res.stdout.strip().splitlines()
                found_listening = False
                for line in lines:
                    if "LISTENING" in line:
                        found_listening = True
                        parts = line.split()
                        pid = parts[-1]
                        report.append(f"[{check_port}] 正在监听: {line.strip()}")
                        if pid == "4":
                            if check_port == 445:
                                report.append(f"❌ 严重错误: 端口 {check_port} 被 System (PID 4) 占用！")
                                report.append("   这意味着某个隐藏网卡仍在运行 NetBIOS。")
                                report.append("   【手动查询命令】请在 CMD 运行: wmic nicconfig get Description,TcpipNetbiosOptions")
                            else:
                                report.append(f"❌ 关键冲突: 端口 {check_port} 被 System (PID 4) 占用。")
                                report.append("   【重要】这会导致复印机无法通过计算机名访问！")
                                report.append("   解决方案: 请运行【一键修复】。\n   或者手动: 打开【网络连接(ncpa.cpl)】-> 右键网卡 -> 属性 -> 取消勾选【Microsoft 网络文件和打印机共享】。")
                        else:
                            report.append(f"✅ 端口 {check_port} 被 PID {pid} 占用 (正常)。")
                if not found_listening:
                     report.append(f"端口 {check_port} 似乎没有处于 LISTENING 状态。")
        except Exception as e:
            report.append(f"端口 {check_port} 检查失败: {e}")

    # 3. 关键服务状态
    report.append(f"\n[3. 关键服务状态]")
    services = {
        'LanmanServer': 'Server (干扰项，应停止)',
        'lmhosts': 'TCP/IP NetBIOS Helper (必需，应运行)',
        'FDResPub': 'Function Discovery (WSD) (必需，应运行)',
        'SSDPSRV': 'SSDP Discovery (WSD依赖) (必需，应运行)'
    }
    
    for svc, desc in services.items():
        try:
            res = subprocess.run(f'sc query {svc}', shell=True, capture_output=True, text=True)
            # sc query output format: STATE : 4 RUNNING
            if "RUNNING" in res.stdout:
                state = "RUNNING"
            elif "STOPPED" in res.stdout:
                state = "STOPPED"
            elif "PAUSED" in res.stdout:
                state = "PAUSED"
            else:
                state = "未知/未安装"

            status_icon = "❓"
            if svc == 'LanmanServer':
                status_icon = "✅" if state != 'RUNNING' else "❌" # Server 最好是 Stopped, 但有时候禁用状态查不到
            else:
                status_icon = "✅" if state == 'RUNNING' else "❌"
                
            report.append(f"{status_icon} {svc} ({desc}): {state}")
        except Exception:
             report.append(f"❓ {svc}: 检查失败")

    # 4. 防火墙规则
    report.append(f"\n[4. 防火墙规则]")
    check_rule = "PythonSMBServer_Port445_TCP"
    res = subprocess.run(f'netsh advfirewall firewall show rule name="{check_rule}"', shell=True, capture_output=True, text=True)
    if not res.stdout.strip() or "没有与指定标准匹配的规则" in res.stdout:
        report.append("❌ 未找到防火墙规则！请重新启动服务或点击修复。")
    else:
        # 简单检查是否有输出即可，详细解析比较繁琐
        report.append("✅ 防火墙规则已存在。")
        if "配置文件" in res.stdout and "任何" in res.stdout: 
             report.append("   (配置: 覆盖所有网络配置文件)")
        elif "Profiles" in res.stdout and "Any" in res.stdout:
             report.append("   (Configuration: Covers all network profiles)")

    # 5. Hosts 文件
    report.append(f"\n[5. Hosts 文件检测]")
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    try:
        content = ""
        # 尝试读取
        try:
            with open(hosts_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            report.append("✅ 成功读取 Hosts 文件。")
        except PermissionError:
             report.append("❌ 权限不足，无法读取 Hosts 文件。")
        except Exception as e:
             report.append(f"读取 Hosts 文件出错: {e}")

        if content:
            # [v1.19] 使用 Regex 严格检查，必须是行首且非注释
            # 兼容域名后可能有注释的情况
            pattern = r"^\s*127\.0\.0\.1\s+" + re.escape(hostname)
            if re.search(pattern, content, re.MULTILINE):
                report.append(f"✅ 已包含本机重定向记录: 127.0.0.1 {hostname}")
            else:
                report.append(f"❌ 未找到有效的本机重定向记录 (预期: 127.0.0.1 {hostname})。")
                if f"127.0.0.1       {hostname}" in content:
                     report.append("   (检测到字符串存在但格式可能错误，例如在注释行中或没有换行)")
                report.append("   解决方案: 点击【一键修复环境】或【手动修改 Hosts】。")
    except Exception as e:
        report.append(f"Hosts 检查逻辑错误: {e}")

    report.append("\n=== 诊断结束 ===")
    return "\n".join(report)

def open_hosts_file():
    """以管理员身份用记事本打开 Hosts 文件"""
    if platform.system() != 'Windows':
        return
        
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    try:
        # 使用 ShellExecuteW 提权运行 notepad
        # operation="runas" 请求管理员权限
        ctypes.windll.shell32.ShellExecuteW(None, "runas", "notepad.exe", hosts_path, None, 1)
        return True, "已尝试打开 Hosts 文件，请在弹出的记事本中手动编辑并保存。"
    except Exception as e:
        return False, f"打开失败: {str(e)}"
