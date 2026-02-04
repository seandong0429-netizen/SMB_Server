

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import queue
import threading
import multiprocessing
import os
import sys

# Ensure src is in path if running from root
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))


from src.utils import get_local_ip, get_hostname, is_port_in_use, set_windows_startup, check_windows_startup, stop_windows_server_service, fix_port_445_environment, manage_firewall_rule, run_system_diagnostics, open_hosts_file

# ... imports ...



from src.logger import setup_logger
from src.smb_server import SMBService
from src.version import VERSION

class MainApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"独立 SMB 服务端 (Windows/Mac) v{VERSION}")
        self.root.geometry("600x750")
        
        # 状态变量
        self.share_path = tk.StringVar()
        self.share_name = tk.StringVar(value="MyShare")
        self.auth_mode = tk.StringVar(value="anonymous")
        self.username = tk.StringVar(value="admin")
        self.password = tk.StringVar()
        self.port_var = tk.IntVar(value=445)
        self.is_running = False
        self.service = None
        
        # 日志队列 - 使用 multiprocessing.Queue 以支持跨进程日志
        self.log_queue = multiprocessing.Queue()
        self.logger = setup_logger(self.log_queue)
        
        self.create_widgets()
        self.check_log_queue()

    def create_widgets(self):
        # 样式设置
        style = ttk.Style()
        style.theme_use('clam')
        
        # 定义颜色和字体
        bg_color = '#ffffff'
        fg_color = '#333333'
        main_font = ('Microsoft YaHei UI', 9)
        header_font = ('Microsoft YaHei UI', 11, 'bold')
        
        style.configure('TFrame', background=bg_color)
        style.configure('TLabel', background=bg_color, foreground=fg_color, font=main_font)
        style.configure('TButton', font=main_font)
        style.configure('Header.TLabel', font=header_font, background=bg_color, foreground=fg_color)
        style.configure('TLabelframe', background=bg_color, foreground=fg_color)
        style.configure('TLabelframe.Label', background=bg_color, foreground=fg_color, font=main_font)
        style.configure('TRadiobutton', background=bg_color, foreground=fg_color, font=main_font)
        style.configure('TCheckbutton', background=bg_color, foreground=fg_color, font=main_font)
        
        self.root.configure(bg=bg_color)
        
        # 主容器
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 1. 文件夹设置
        self.create_section_header(main_frame, "1. 共享目录设置")
        
        folder_frame = ttk.Frame(main_frame)
        folder_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(folder_frame, text="路径:").pack(side=tk.LEFT)
        ttk.Entry(folder_frame, textvariable=self.share_path, width=40).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        ttk.Button(folder_frame, text="选择文件夹", command=self.browse_folder).pack(side=tk.LEFT)
        
        name_frame = ttk.Frame(main_frame)
        name_frame.pack(fill=tk.X, pady=5)
        ttk.Label(name_frame, text="共享名:").pack(side=tk.LEFT)
        ttk.Entry(name_frame, textvariable=self.share_name, width=20).pack(side=tk.LEFT, padx=5)

        # 2. 安全设置
        self.create_section_header(main_frame, "2. 权限与端口")
        
        auth_frame = ttk.Labelframe(main_frame, text="认证模式", padding=10)
        auth_frame.pack(fill=tk.X, pady=5)
        
        # 第一行：匿名访问
        ttk.Radiobutton(auth_frame, text="匿名访问 (无需密码)", variable=self.auth_mode, value="anonymous", command=self.toggle_auth_inputs).pack(anchor=tk.W, pady=2)
        
        # 第二行：安全模式 + 输入框
        secure_frame = ttk.Frame(auth_frame)
        secure_frame.pack(fill=tk.X, pady=2, anchor=tk.W)
        
        ttk.Radiobutton(secure_frame, text="安全模式", variable=self.auth_mode, value="secure", command=self.toggle_auth_inputs).pack(side=tk.LEFT)
        
        self.auth_input_frame = ttk.Frame(secure_frame)
        self.auth_input_frame.pack(side=tk.LEFT, padx=10)
        
        ttk.Label(self.auth_input_frame, text="用户:").pack(side=tk.LEFT)
        ttk.Entry(self.auth_input_frame, textvariable=self.username, width=12).pack(side=tk.LEFT, padx=5)
        ttk.Label(self.auth_input_frame, text="密码:").pack(side=tk.LEFT)
        ttk.Entry(self.auth_input_frame, textvariable=self.password, show="*", width=12).pack(side=tk.LEFT, padx=5)
        
        # 初始状态隐藏输入框
        self.toggle_auth_inputs()

        # 端口设置
        port_frame = ttk.Frame(main_frame)
        port_frame.pack(fill=tk.X, pady=10)
        ttk.Label(port_frame, text="监听端口 (默认445):").pack(side=tk.LEFT)
        ttk.Entry(port_frame, textvariable=self.port_var, width=10).pack(side=tk.LEFT, padx=5)
        ttk.Button(port_frame, text="检测是否占用", command=self.check_port).pack(side=tk.LEFT)
        ttk.Button(port_frame, text="一键修复环境 (推荐)", command=self.fix_environment_445).pack(side=tk.LEFT, padx=10)
        # [v1.16] 诊断按钮
        ttk.Button(port_frame, text="环境诊断", command=self.show_diagnostics).pack(side=tk.LEFT, padx=0)
        # [v1.18] 手动修改 Hosts 按钮
        ttk.Button(port_frame, text="手动修改 Hosts", command=self.manual_edit_hosts).pack(side=tk.LEFT, padx=10)

        # 3. 控制与状态
        self.create_section_header(main_frame, "3. 服务控制")
        
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=10)
        
        # 加大按钮 Padding
        self.start_btn = ttk.Button(control_frame, text="启动服务", command=self.start_server, width=15)
        self.start_btn.pack(side=tk.LEFT, padx=10, ipady=5)
        
        self.stop_btn = ttk.Button(control_frame, text="停止服务", command=self.stop_server, width=15, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=10, ipady=5)
        
        self.status_label = ttk.Label(control_frame, text="状态: 未运行", foreground="#d9534f") # Bootstrap danger red
        self.status_label.pack(side=tk.LEFT, padx=10)

        # 开机自启 (右侧)
        self.startup_var = tk.BooleanVar(value=check_windows_startup("MySMBServer"))
        ttk.Checkbutton(control_frame, text="开机自动启动", variable=self.startup_var, command=self.toggle_startup).pack(side=tk.RIGHT, padx=10)

        # 4. 日志窗口
        self.create_section_header(main_frame, "运行日志")
        self.log_area = scrolledtext.ScrolledText(main_frame, height=15, state='disabled', font=('Consolas', 9))
        self.log_area.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 底部提示
        local_ip = get_local_ip()
        hostname = get_hostname()
        ttk.Label(main_frame, text=f"访问地址: \\\\{hostname}  或  \\\\{local_ip}").pack(side=tk.BOTTOM, pady=5)

    def create_section_header(self, parent, text):
        f = ttk.Frame(parent)
        f.pack(fill=tk.X, pady=(15, 5))
        ttk.Label(f, text=text, style='Header.TLabel').pack(side=tk.LEFT)
        ttk.Separator(f, orient=tk.HORIZONTAL).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)

    def browse_folder(self):
        directory = filedialog.askdirectory()
        if directory:
            self.share_path.set(directory)

    def toggle_auth_inputs(self):
        if self.auth_mode.get() == "secure":
            for child in self.auth_input_frame.winfo_children():
                child.configure(state='normal')
        else:
            for child in self.auth_input_frame.winfo_children():
                child.configure(state='disabled')
        
    def check_port(self):
        port = self.port_var.get()
        if is_port_in_use(port):
             # 检查是否是 PID 4
            is_system = False
            try:
                import subprocess
                res = subprocess.run(f'netstat -ano | findstr :{port}', shell=True, capture_output=True, text=True)
                if " 4" in res.stdout: # PID 4 ends of line usually
                     is_system = True
            except:
                pass
            
            if is_system:
                messagebox.showwarning("端口冲突 (System)", f"端口 {port} 被 System (PID 4) 占用。\n这是 Windows 内核驱动 (srv.sys) 导致的。\n\n请点击【一键修复环境】按钮，然后重启电脑。")
            else:
                messagebox.showwarning("端口冲突", f"端口 {port} 已被占用！")
        else:
            messagebox.showinfo("端口检查", f"端口 {port} 可用。")

    def fix_environment_445(self):
        """一键修复环境"""
        if messagebox.askyesno("环境修复", "此操作将执行以下环境修复：\n\n1. 修改注册表禁用 SMBDevice 驱动 (Start=4)\n2. 强制停止 Windows Server 服务\n\n注意：此操作需要【管理员权限】，会弹出黑色命令窗口。\n执行成功后，即使当前端口未立即释放，【重启电脑】后即可解决问题。\n\n是否继续？"):
            success, msg = fix_port_445_environment()
            if success:
                messagebox.showinfo("操作已提交", msg)
            else:
                messagebox.showerror("操作失败", msg)

    def show_diagnostics(self):
        """显示系统环境诊断报告"""
        report = run_system_diagnostics()
        
        # 创建弹窗显示报告
        diag_win = tk.Toplevel(self.root)
        diag_win.title("系统环境诊断报告")
        diag_win.geometry("600x500")
        
        text_area = scrolledtext.ScrolledText(diag_win, width=80, height=30, font=('Consolas', 9))
        text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text_area.insert(tk.END, report)
        text_area.config(state=tk.DISABLED) # 只读
        
        text_area.config(state=tk.DISABLED) # 只读
        
        ttk.Label(diag_win, text="请截图此报告发给开发者以排查问题", foreground="blue").pack(pady=5)

    def manual_edit_hosts(self):
        """手动打开 Hosts 文件"""
        success, msg = open_hosts_file()
        if not success:
            messagebox.showerror("错误", msg)
        else:
            # 提示用户怎么改
            hostname = get_hostname()
            info = f"即将为您打开 Hosts 文件。\n请在文件末尾手动添加一行：\n\n127.0.0.1       {hostname}\n\n添加后保存并关闭记事本即可。"
            messagebox.showinfo("手动修改指引", info)

    def start_server(self):
        try:
            self.logger.info("正在尝试启动服务...")
            
            path = self.share_path.get()
            name = self.share_name.get()
            port = self.port_var.get()
            
            if not path or not os.path.exists(path):
                messagebox.showerror("错误", "请选择有效的共享目录")
                return
                
            if not name:
                messagebox.showerror("错误", "请设置共享名称")
                return
                
            # 检查端口占用
            if is_port_in_use(port):
                 # 尝试自动切换逻辑或询问用户
                 # 这里简单起见，如果用户手动填了端口还冲突，就报错。如果是默认445冲突，尝试切换。
                 if port == 445:
                     if messagebox.askyesno("端口冲突", "端口 445 被占用，是否尝试使用端口 4445？"):
                         port = 4445
                         self.port_var.set(port)
                         if is_port_in_use(port):
                             messagebox.showerror("错误", f"端口 {port} 也被占用，请手动指定其他端口。")
                             return
                     else:
                         return
                 else:
                     messagebox.showerror("错误", f"端口 {port} 被占用。")
                     return

            user = self.username.get() if self.auth_mode.get() == "secure" else None
            pwd = self.password.get() if self.auth_mode.get() == "secure" else None
            
            # 添加防火墙规则
            manage_firewall_rule('add', port)
            
            # Pass log_queue to service for child process logging
            self.service = SMBService(name, path, user, pwd, port, self.log_queue)
            self.service.start()
            
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.status_label.config(text=f"状态: 运行中 (端口 {port})", foreground="green")
            self.is_running = True
            
        except Exception as e:
            import traceback
            err_msg = f"启动服务时发生严重错误:\n{str(e)}\n\n{traceback.format_exc()}"
            self.logger.error(err_msg)
            messagebox.showerror("启动失败", err_msg)


    def stop_server(self):
        if self.service:
            # 停止前获取端口移除防火墙规则
            # 注意: 这里假设用户在运行期间没有改端口号输入框
            port = self.service.val_port
            self.service.stop()
            self.service = None
            
            # 移除防火墙规则
            manage_firewall_rule('delete', port)
            
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="状态: 已停止", foreground="red")
        self.is_running = False

    def toggle_startup(self):
        enabled = self.startup_var.get()
        success, msg = set_windows_startup("MySMBServer", enabled)
        if success:
            self.logger.info(f"系统设置: {msg}")
        else:
            self.logger.error(f"系统设置失败: {msg}")
            # 回滚状态
            self.startup_var.set(not enabled)

    def check_log_queue(self):
        """定期把队列里的日志取出来显示在界面上"""
        while not self.log_queue.empty():
            try:
                msg = self.log_queue.get_nowait()
                self.log_area.configure(state='normal')
                self.log_area.insert(tk.END, msg + '\n')
                self.log_area.see(tk.END)
                self.log_area.configure(state='disabled')
            except queue.Empty:
                pass
        self.root.after(100, self.check_log_queue)

if __name__ == "__main__":
    root = tk.Tk()
    app = MainApp(root)
    root.mainloop()
