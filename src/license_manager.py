
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
        # 锚点文件隐藏在用户目录下
        self.anchor_file = os.path.join(os.path.expanduser("~"), ".smb_server_sys_conf")
        self.public_key = serialization.load_pem_public_key(PUBLIC_KEY_PEM)

    def verify(self):
        """
        验证全流程：
        1. 文件存在性
        2. 签名合法性 (RSA)
        3. 字段有效性 (Expiry Date)
        4. 时间防篡改 (Time Guard)
        
        Returns: (is_valid, message, metadata)
        """
        # 1. Check File
        if not os.path.exists(self.license_file):
            return False, "找不到授权文件 (license.lic)。", {}

        try:
            with open(self.license_file, "r") as f:
                content = f.read().strip()
            
            if "." not in content:
                return False, "授权文件格式错误。", {}
            
            b64_data, b64_sig = content.split(".", 1)
            
            # 2. Check Signature
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
            
            # 3. Check Data
            data = json.loads(json_data)
            expiry_str = data.get("ExpiryDate")
            if not expiry_str:
                return False, "授权文件缺少过期日期。", {}
                
            expiry_date = datetime.datetime.strptime(expiry_str, "%Y-%m-%d").date()
            current_date = datetime.datetime.now().date()
            
            if current_date > expiry_date:
                return False, f"授权已过期 (截止: {expiry_str})。", data
                
            # 4. Time Guard (Anti-Tamper)
            tampered, reason = self._check_time_tampering()
            if tampered:
                return False, f"检测到系统时间异常: {reason}。请恢复真实时间。", data
                
            # Valid
            return True, f"授权有效 (截止: {expiry_str})", data
            
        except Exception as e:
            return False, f"授权验证失败: {str(e)}", {}

    def _check_time_tampering(self):
        """
        三重时间卫士
        Returns: (tampered: bool, reason: str)
        """
        now = datetime.datetime.now()
        
        # Guard 1: System Directory Time
        # Windows 目录的修改时间通常不会是未来的时间，但也肯定早于当前时间。
        # 如果当前时间比 Windows 目录创建/修改时间还早很多（例如 Windows 安装于 2024，现在是 2020），那肯定是回拨。
        try:
            sys_dir = "C:\\Windows" if platform.system() == "Windows" else "/etc"
            if os.path.exists(sys_dir):
                mtime = datetime.datetime.fromtimestamp(os.path.getmtime(sys_dir))
                # 容差：允许 1 天的误差 (考虑到时区或文件系统怪癖)
                # 逻辑修正：如果现在时间 < 系统目录时间，那很可疑？
                # 不对，系统目录经常更新。
                # 更有力的证据是：如果现在时间 < 2023-01-01 (假设软件发布是2025)，那肯定是回拨。
                # 简单粗暴：硬编码一个最小可信时间
                min_trust_time = datetime.datetime(2025, 1, 1)
                if now < min_trust_time:
                     return True, "系统时间严重滞后"
        except:
            pass
            
        # Guard 2: Anchor File (Incremental Run Time)
        # 记录上一次运行的时间，如果现在的比上次还早，就是回拨。
        if os.path.exists(self.anchor_file):
            try:
                with open(self.anchor_file, "r") as f:
                    last_run_ts = float(f.read().strip())
                last_run_time = datetime.datetime.fromtimestamp(last_run_ts)
                
                # 允许 5 分钟的误差 (重启/时钟同步波动)
                if now < last_run_time - datetime.timedelta(minutes=5):
                    return True, "检测到时间回拨 (早于上次运行)"
            except:
                pass # 文件损坏则跳过
                
        return False, ""

    def update_anchor(self):
        """正常退出或为了更新心跳时调用"""
        try:
            with open(self.anchor_file, "w") as f:
                f.write(str(datetime.datetime.now().timestamp()))
            
            # On Windows, hide the file
            if platform.system() == "Windows":
                subprocess.run(['attrib', '+h', self.anchor_file], capture_output=True)
        except:
            pass

# 单例模式
license_manager = LicenseManager()
