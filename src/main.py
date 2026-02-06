
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import queue
import threading
import multiprocessing
import os
import sys
from PIL import Image, ImageDraw
import pystray

# Ensure src is in path if running from root
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))


from src.utils import get_local_ip, get_hostname, is_port_in_use, set_windows_startup, check_windows_startup, stop_windows_server_service, fix_port_445_environment, manage_firewall_rule, run_system_diagnostics, open_hosts_file
from src.logger import setup_logger
from src.smb_server import SMBService
from src.version import VERSION
from src.config import ConfigManager


class MainApp:
    def __init__(self, root):
        self.root = root
        

        
        self.root.title(f"云铠智能办公 SMB 服务端 v{VERSION}")
        self.root.geometry("750x750")
        
        # [v1.26] 拦截关闭事件 -> 最小化到托盘
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.tray_icon = None
        self.tray_thread = None
        
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
        self.legacy_mode_var = tk.BooleanVar(value=cfg.get("legacy_mode", False))
        
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

        # [v2.2] 兼容模式 Checkbox (Advanced Settings)
        legacy_frame = ttk.LabelFrame(main_frame, text="高级兼容性设置", padding=10)
        legacy_frame.pack(fill=tk.X, pady=(0, 10))
        
        # [v1.36] 兼容模式 Checkbox (使用 Label 模拟以实现绿色对勾)
        self.legacy_lbl = ttk.Label(legacy_frame, text="", cursor="hand2")
        self.legacy_lbl.pack(side=tk.LEFT, padx=5)
        self.legacy_lbl.bind("<Button-1>", lambda e: self.toggle_legacy())
        self.update_legacy_ui()

        ttk.Label(legacy_frame, text="(适用于复印机/旧版 Windows)", font=('Microsoft YaHei UI', 8), foreground='#666666').pack(side=tk.LEFT, padx=5)

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
        # [v1.23] 使用自定义 Label 模拟复选框，确保显示绿色对勾
        self.startup_lbl = ttk.Label(control_frame, text="", cursor="hand2") 
        self.startup_lbl.pack(side=tk.RIGHT, padx=10)
        self.startup_lbl.bind("<Button-1>", lambda e: self.toggle_startup())
        self.update_startup_ui()

        # 底部提示 (优先 Pack 底部，防止被日志挤出)
        local_ip = get_local_ip()
        hostname = get_hostname()
        
        footer_frame = ttk.Frame(main_frame)
        footer_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=5)
        ttk.Label(footer_frame, text=f"访问地址: \\\\{local_ip}   (或 \\\\{hostname})", 
                 font=('Microsoft YaHei UI', 10, 'bold'), foreground="#0056b3").pack()

        # 4. 日志窗口
        self.create_section_header(main_frame, "运行日志")
        self.log_area = scrolledtext.ScrolledText(main_frame, height=15, state='disabled', font=('Consolas', 9))
        self.log_area.pack(fill=tk.BOTH, expand=True, pady=5)

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

    def start_server(self):
        try:
            self.logger.info("正在尝试启动服务...")
            
            path = self.share_path.get()
            name = self.share_name.get()
            name = self.share_name.get()
            port = self.port_var.get()
            legacy = self.legacy_mode_var.get()
            
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
                     messagebox.showerror("错误", f"端口 {port} 被占用。")
                     return

            # [v2.2] 检查 139 端口占用
            if legacy:
                if is_port_in_use(139):
                     messagebox.showwarning("端口 139 冲突", "端口 139 被占用 (可能是系统 NetBIOS Session)。\n这可能会影响兼容模式，但我们将继续尝试启动。\n建议先点击【一键修复环境】。")

            user = self.username.get() if self.auth_mode.get() == "secure" else None
            pwd = self.password.get() if self.auth_mode.get() == "secure" else None
            
            # [v1.24 Fix] 不要强制标记为自动启动，除非用户有专门的设置项（当前逻辑是用户手动点启动不应导致下次自启）
            # self.config_mgr.set("auto_start_service", True)
            self.config_mgr.update_from_ui(path, name, port, self.auth_mode.get(), self.username.get(), self.password.get(), legacy)
            
            # 添加防火墙规则 (manage_firewall_rule 已在 utils 中配置为开启 139)
            manage_firewall_rule('add', port)
            
            # Pass log_queue to service for child process logging
            self.service = SMBService(name, path, user, pwd, port, self.log_queue)
            self.service.start(legacy_mode=legacy)
            
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.status_label.config(text=f"状态: 运行中 (端口 {port})", foreground="green")
            self.is_running = True
            
        except Exception as e:
            import traceback
            err_msg = f"启动服务时发生严重错误:\n{str(e)}\n\n{traceback.format_exc()}"
            self.logger.error(err_msg)
            messagebox.showerror("启动失败", err_msg)
            # 确保按钮状态正确
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)


    def stop_server(self):
        """停止服务"""
        try:
            # 立即给用户反馈
            self.stop_btn.config(state=tk.DISABLED, text="停止中...")
            self.root.update()

            if self.service:
                # 停止前获取端口移除防火墙规则
                port = self.service.val_port
                self.service.stop()
                self.service = None
                
                # 移除防火墙规则
                manage_firewall_rule('delete', port)
                
            # [v1.24] 标记为手动停止
            self.config_mgr.set("auto_start_service", False)
            self.config_mgr.save()
                
            self.status_label.config(text="状态: 已停止", foreground="red")
            self.is_running = False

        except Exception as e:
            import traceback
            err_msg = f"停止服务时发生错误:\n{str(e)}\n\n{traceback.format_exc()}"
            self.logger.error(err_msg)
            messagebox.showerror("停止失败", err_msg)
        finally:
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED, text="停止服务")


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

    def toggle_legacy(self):
        """[v1.36] 切换兼容模式状态"""
        current = self.legacy_mode_var.get()
        self.legacy_mode_var.set(not current)
        self.update_legacy_ui()

    def update_legacy_ui(self):
        """[v1.36] 更新兼容模式 UI"""
        if self.legacy_mode_var.get():
            self.legacy_lbl.config(text="✅ 开启兼容模式 (Port 139 + NetBIOS)", foreground="green")
        else:
            self.legacy_lbl.config(text="⬜ 开启兼容模式 (Port 139 + NetBIOS)", foreground="#666666")

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

    # [v1.26] 系统托盘逻辑
    def create_tray_image(self):
        # 生成一个简单的绿色图标
        width = 64
        height = 64
        color1 = (0, 128, 0)
        color2 = (255, 255, 255)
        image = Image.new('RGB', (width, height), color1)
        dc = ImageDraw.Draw(image)
        dc.rectangle((width // 4, height // 4, width * 3 // 4, height * 3 // 4), fill=color2)
        return image

    def start_tray_icon(self):
        if self.tray_icon:
            return
        
        image = self.create_tray_image()
        menu = pystray.Menu(
            pystray.MenuItem("显示主界面", self.on_show_window),
            pystray.MenuItem("退出程序", self.on_exit_app)
        )
        self.tray_icon = pystray.Icon("SMBServer", image, f"SMB 服务端 v{VERSION}", menu)
        # Run in separate thread to not block Tkinter
        self.tray_thread = threading.Thread(target=self.tray_icon.run, daemon=True)
        self.tray_thread.start()

    def on_closing(self):
        # 最小化到托盘
        if messagebox.askokcancel("最小化", "程序将缩小到系统托盘继续运行。\n\n如需彻底退出，请右键点击托盘图标选择【退出】。"):
            self.root.withdraw()
            if not self.tray_icon:
                self.start_tray_icon()
            else:
                self.tray_icon.visible = True
                # Notification if possible? 
                pass

    def on_show_window(self, icon, item):
        self.root.after(0, self.root.deiconify)
        # Optional: Hide tray icon when window logic if desired, 
        # but standard behavior keeps it or hides it. Keep it for now.

    def on_exit_app(self, icon, item):
        self.root.after(0, self.real_exit)

    def real_exit(self):
        # 停止服务
        if self.service:
            self.stop_server()
        
        # 停止托盘
        if self.tray_icon:
            self.tray_icon.stop()
            

        
        self.root.quit()
        sys.exit(0)

if __name__ == "__main__":
    multiprocessing.freeze_support() # [v1.7] 必须放在这里
    root = tk.Tk()
    app = MainApp(root)
    root.mainloop()
