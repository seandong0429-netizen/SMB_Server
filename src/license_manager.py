
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
        v2.1 验证逻辑:
        1. 检查是否存在【已激活】标记 (Perpetual Logic)。
        2. 否则，检查 License 是否存在且在【激活期限】内。
        3. 无论哪种情况，都执行【时间卫士】检查防回拨。
        
        Returns: (is_valid, message, metadata)
        """
        # A. 时间卫士检查 (Before anything else)
        # 防止用户把时间调回去来绕过 ActivationDeadline
        tampered, reason = self._check_time_tampering()
        if tampered:
            return False, f"检测到系统时间异常: {reason}。请恢复真实时间。", {}

        # B. 检查是否已永久激活
        is_activated, last_run = self._load_anchor()
        if is_activated:
            # 已经激活过，直接通过
            # 但我们仍然要更新锚点时间，以维持反回拨机制
             if os.path.exists(self.license_file) and not last_run:
                 pass # Edge case
             
             return True, "软件已激活 (永久授权)", {"Status": "Activacted"}

        # C. 未激活，执行激活流程
        if not os.path.exists(self.license_file):
            return False, "未激活：找不到授权文件 (license.lic)。请放置有效的授权文件。", {}

        try:
            with open(self.license_file, "r") as f:
                content = f.read().strip()
            
            if "." not in content:
                return False, "授权文件格式错误。", {}
            
            b64_data, b64_sig = content.split(".", 1)
            
            # Verify Signature
            json_data = base64.b64decode(b64_data)
            signature = base64.b64decode(b64_sig)
            
            self.public_key.verify(
                signature,
                json_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Check Deadline
            data = json.loads(json_data)
            deadline_str = data.get("ActivationDeadline") or data.get("ExpiryDate") # 兼容 v2.0
            
            if not deadline_str:
                return False, "授权文件缺少激活期限字段。", {}
                
            deadline_date = datetime.datetime.strptime(deadline_str, "%Y-%m-%d").date()
            current_date = datetime.datetime.now().date()
            
            if current_date > deadline_date:
                return False, f"授权文件已失效 (激活截止: {deadline_str})。请联系管理员。", data
            
            # 激活成功！
            # 写入激活标记
            self._save_anchor(activated=True)
            
            return True, f"激活成功！(截止日期: {deadline_str})", data
            
        except Exception as e:
            return False, f"授权验证失败: {str(e)}", {}

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
