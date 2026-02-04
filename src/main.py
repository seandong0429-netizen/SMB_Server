

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
from src.config import ConfigManager

class MainApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"云铠智能办公 SMB 服务端 v{VERSION}")
        self.root.geometry("750x750")
        
        # 加载配置
        self.config_mgr = ConfigManager()
        cfg = self.config_mgr.get_all()

        # 状态变量 (从配置加载)
        self.share_path = tk.StringVar(value=cfg.get("share_path", ""))
        self.share_name = tk.StringVar(value=cfg.get("share_name", "MyShare"))
        self.auth_mode = tk.StringVar(value=cfg.get("auth_mode", "anonymous"))
        self.username = tk.StringVar(value=cfg.get("username", "admin"))
        self.password = tk.StringVar(value=cfg.get("password", ""))
        self.port_var = tk.IntVar(value=cfg.get("port", 445))
        
        self.is_running = False
        self.service = None
        
        # 日志队列 - 使用 multiprocessing.Queue 以支持跨进程日志
        self.log_queue = multiprocessing.Queue()
        self.logger = setup_logger(self.log_queue)
        
        self.create_widgets()
        self.check_log_queue()

        # [v1.24] 检查是否需要自动启动服务
        # 延时检测，等待UI渲染完毕
        if cfg.get("auto_start_service", False):
            self.root.after(1000, self.auto_start_check)

    def auto_start_check(self):
        """开机自动启动服务的检查逻辑"""
        self.logger.info("检测到自动启动配置，正在尝试启动服务...")
        # 只有当路径有效时才启动
        if self.share_path.get() and os.path.exists(self.share_path.get()):
            self.start_server()
        else:
            self.logger.warning("自动启动失败: 共享路径无效或为空")

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
            
            # [v1.24] 保存配置 & 标记已启动
            self.config_mgr.set("auto_start_service", True)
            self.config_mgr.update_from_ui(path, name, port, self.auth_mode.get(), self.username.get(), self.password.get())
            
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
            port = self.service.val_port
            self.service.stop()
            self.service = None
            
            # 移除防火墙规则
            manage_firewall_rule('delete', port)
            
        # [v1.24] 标记为手动停止，避免下次自动启动
        self.config_mgr.set("auto_start_service", False)
        self.config_mgr.save()
            
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="状态: 已停止", foreground="red")
        self.is_running = False

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
        # [v1.23] 使用自定义 Label 模拟复选框，确保显示绿色对勾 (解决 Win 原生 Checkbox 样式问题)
        self.startup_lbl = ttk.Label(control_frame, text="", cursor="hand2") 
        self.startup_lbl.pack(side=tk.RIGHT, padx=10)
        self.startup_lbl.bind("<Button-1>", lambda e: self.toggle_startup())
        self.update_startup_ui()

        # 4. 日志窗口
        self.create_section_header(main_frame, "运行日志")
        self.log_area = scrolledtext.ScrolledText(main_frame, height=15, state='disabled', font=('Consolas', 9))
        self.log_area.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 底部提示
        local_ip = get_local_ip()
        hostname = get_hostname()
        # [v1.22] 优先推荐 127.0.0.1，因为这是最稳的本机访问方式
        ttk.Label(main_frame, text=f"本机访问推荐: \\\\127.0.0.1  (或 \\\\{hostname})").pack(side=tk.BOTTOM, pady=(0, 5))
        ttk.Label(main_frame, text=f"局域网访问: \\\\{local_ip}").pack(side=tk.BOTTOM, pady=(5, 0))

    def create_section_header(self, parent, text):
        f = ttk.Frame(parent)
        f.pack(fill=tk.X, pady=(15, 5))
        ttk.Label(f, text=text, style='Header.TLabel').pack(side=tk.LEFT)
        ttk.Separator(f, orient=tk.HORIZONTAL).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)

    # ... (omitted methods) ...

    def toggle_startup(self):
        # [v1.23] 更新逻辑以适配自定义 Toggle
        # 当前状态
        current_state = self.startup_var.get()
        target_state = not current_state
        
        success, msg = set_windows_startup("MySMBServer", target_state)
        if success:
            self.startup_var.set(target_state)
            self.update_startup_ui()
            self.logger.info(f"系统设置: {msg}")
        else:
            self.logger.error(f"系统设置失败: {msg}")
            # 如果是权限等原因失败，状态不变
            messagebox.showerror("设置失败", msg)

    def update_startup_ui(self):
        """[v1.23] 更新自定义复选框的 UI 状态"""
        if self.startup_var.get():
            self.startup_lbl.config(text="✅ 开机自动启动", foreground="green")
        else:
            self.startup_lbl.config(text="⬜ 开机自动启动", foreground="#666666")

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
