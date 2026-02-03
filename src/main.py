
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import queue
import threading
import os
import sys

# Ensure src is in path if running from root
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.utils import get_local_ip, get_hostname, is_port_in_use, set_windows_startup, check_windows_startup
from src.logger import setup_logger
from src.smb_server import SMBService

class MainApp:
    def __init__(self, root):
        self.root = root
        self.root.title("独立 SMB 服务端 (Windows/Mac)")
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
        
        # 日志队列
        self.log_queue = queue.Queue()
        self.logger = setup_logger(self.log_queue)
        
        self.create_widgets()
        self.check_log_queue()

    def create_widgets(self):
        # 样式设置
        style = ttk.Style()
        style.theme_use('clam')  # 使用 clam 主题获得更现代的外观
        style.configure('TFrame', background='#f0f0f0')
        style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        style.configure('TButton', font=('Arial', 10))
        style.configure('Header.TLabel', font=('Arial', 12, 'bold'))
        
        self.root.configure(bg='#f0f0f0')
        
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
        
        ttk.Radiobutton(auth_frame, text="匿名访问 (无需密码)", variable=self.auth_mode, value="anonymous", command=self.toggle_auth_inputs).pack(anchor=tk.W)
        ttk.Radiobutton(auth_frame, text="安全模式 (用户名/密码)", variable=self.auth_mode, value="secure", command=self.toggle_auth_inputs).pack(anchor=tk.W)
        
        self.auth_input_frame = ttk.Frame(auth_frame)
        self.auth_input_frame.pack(fill=tk.X, pady=5, padx=20)
        
        ttk.Label(self.auth_input_frame, text="用户:").pack(side=tk.LEFT)
        ttk.Entry(self.auth_input_frame, textvariable=self.username, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Label(self.auth_input_frame, text="密码:").pack(side=tk.LEFT)
        ttk.Entry(self.auth_input_frame, textvariable=self.password, show="*", width=15).pack(side=tk.LEFT, padx=5)
        
        # 初始状态隐藏输入框
        self.toggle_auth_inputs()

        # 端口设置
        port_frame = ttk.Frame(main_frame)
        port_frame.pack(fill=tk.X, pady=10)
        ttk.Label(port_frame, text="监听端口 (默认445):").pack(side=tk.LEFT)
        ttk.Entry(port_frame, textvariable=self.port_var, width=10).pack(side=tk.LEFT, padx=5)
        ttk.Button(port_frame, text="检测是否占用", command=self.check_port).pack(side=tk.LEFT)

        # 3. 控制与状态
        self.create_section_header(main_frame, "3. 服务控制")
        
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=10)
        
        self.start_btn = ttk.Button(control_frame, text="启动服务", command=self.start_server, width=20)
        self.start_btn.pack(side=tk.LEFT, padx=10)
        
        self.stop_btn = ttk.Button(control_frame, text="停止服务", command=self.stop_server, width=20, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=10)
        
        self.status_label = ttk.Label(control_frame, text="状态: 未运行", foreground="red")
        self.status_label.pack(side=tk.LEFT, padx=10)

        # 开机自启 (右侧)
        self.startup_var = tk.BooleanVar(value=check_windows_startup("MySMBServer"))
        ttk.Checkbutton(control_frame, text="开机自动启动", variable=self.startup_var, command=self.toggle_startup).pack(side=tk.RIGHT, padx=10)

        # 4. 日志窗口
        self.create_section_header(main_frame, "运行日志")
        self.log_area = scrolledtext.ScrolledText(main_frame, height=15, state='disabled', font=('Courier', 9))
        self.log_area.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 底部提示
        local_ip = get_local_ip()
        hostname = get_hostname()
        ttk.Label(main_frame, text=f"提示: 可通过 \\\\{hostname} 或 \\\\{local_ip} 访问 (共享名: {self.share_name.get()})").pack(side=tk.BOTTOM, pady=5)

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
            messagebox.showwarning("端口冲突", f"端口 {port} 已被占用！\n建议使用 4445 或其他端口。")
        else:
            messagebox.showinfo("端口检查", f"端口 {port} 可用。")

    def start_server(self):
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
        
        self.service = SMBService(name, path, user, pwd, port)
        self.service.start()
        
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_label.config(text=f"状态: 运行中 (端口 {port})", foreground="green")
        self.is_running = True

    def stop_server(self):
        if self.service:
            self.service.stop()
            self.service = None
            
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
