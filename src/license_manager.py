
import os
import sys
import json
import base64
import datetime
import platform
import subprocess
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# --- PUBLIC KEY (HARDCODED) ---
PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyTeBdEbklo8AJFjMN/ZO
cPqf0IYDRIbSe3d1P+qHPDPqmONAIF0QLBx2SDNdswO7JYHK9rIg41HM4lJ0IjYr
eEmWWOKrtBhRDOwXHSRAGbh4KzWFUBSre6ElNpo+g8nhuFk4GtaDX63z1jARSJIb
C35p+gOhN4gwcfOhy0ORaSIkOeLg8l5AVDjEkOqSvOnIO4QooC2QzY/VEaNPK/eP
XWu5lmeCKPgsvSfe94NGPq/Uxgs3UnAW98moBzyPRZxYzO0fLuouMqbp4qoJ++PB
Y/Ee3aezFAjoysObR606Q9X7Tr/Ft8kQroWvhaX6UIyYpgwE5UGG34XKUGegM+YV
wQIDAQAB
-----END PUBLIC KEY-----"""
# ------------------------------

class LicenseManager:
    def __init__(self):
        self.license_file = "license.lic"
        # 锚点文件隐藏在用户目录下 / AppData
        self.anchor_file = os.path.join(os.path.expanduser("~"), ".smb_server_sys_conf")
        self.public_key = serialization.load_pem_public_key(PUBLIC_KEY_PEM)

    def verify(self):
        """
        [DEBUG] 强制通过验证，忽略所有检查
        """
        return True, "Debug Mode: License Check Bypassed", {"Status": "Debug"}

    def _load_anchor(self):
        """
        读取锚点文件
        Returns: (is_activated: bool, last_run_timestamp: float)
        """
        if not os.path.exists(self.anchor_file):
            return False, 0.0
            
        try:
            with open(self.anchor_file, "r") as f:
                raw = f.read().strip()
                
            # 尝试解析 JSON (v2.1)
            try:
                data = json.loads(raw)
                return data.get("activated", False), data.get("last_run", 0.0)
            except json.JSONDecodeError:
                # 兼容 v2.0 (纯 float)
                return False, float(raw)
        except:
            return False, 0.0

    def _save_anchor(self, activated=False):
        """保存状态到锚点"""
        # 如果之前已经是 activated，保持 true
        prev_activated, _ = self._load_anchor()
        final_activated = activated or prev_activated
        
        data = {
            "last_run": datetime.datetime.now().timestamp(),
            "activated": final_activated,
            "version": "v2.1"
        }
        
        try:
            # 移除旧属性以便写入
            if platform.system() == "Windows":
                 subprocess.run(['attrib', '-h', self.anchor_file], capture_output=True)

            with open(self.anchor_file, "w") as f:
                json.dump(data, f)
            
            # 恢复隐藏
            if platform.system() == "Windows":
                subprocess.run(['attrib', '+h', self.anchor_file], capture_output=True)
        except:
            pass

    def _check_time_tampering(self):
        """三重时间卫士"""
        now = datetime.datetime.now()
        
        # Guard 1: System Directory
        try:
            sys_dir = "C:\\Windows" if platform.system() == "Windows" else "/etc"
            min_trust_time = datetime.datetime(2025, 1, 1)
            if now < min_trust_time:
                 return True, "系统时间严重滞后"
        except:
            pass
            
        # Guard 2: Anchor File (Last Run)
        _, last_run_ts = self._load_anchor()
        if last_run_ts > 0:
            last_run_time = datetime.datetime.fromtimestamp(last_run_ts)
            # 允许 5 分钟误差
            if now < last_run_time - datetime.timedelta(minutes=5):
                return True, "检测到时间回拨 (早于上次运行)"
                
        return False, ""

    def update_anchor(self):
        """外部调用的更新接口 (仅更新时间)"""
        self._save_anchor(activated=False) # 参数 False 不会覆盖已有的 True，_save_anchor 内部有逻辑保持 True

# 单例
license_manager = LicenseManager()
