
import json
import os
import logging
from pathlib import Path

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".smbserver")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

class ConfigManager:
    def __init__(self):
        self._ensure_dir()
        self.config = self._load_default()
        self.load()

    def _ensure_dir(self):
        if not os.path.exists(CONFIG_DIR):
            try:
                os.makedirs(CONFIG_DIR)
            except Exception as e:
                logging.error(f"Failed to create config dir: {e}")

    def _load_default(self):
        return {
            "share_path": "",
            "share_name": "MyShare",
            "port": 445,
            "auth_mode": "anonymous",
            "username": "admin",
            "password": "",
            "auto_start_service": False
        }

    def load(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    saved = json.load(f)
                    # Update default with saved, keeping new keys if any
                    self.config.update(saved)
            except Exception as e:
                logging.error(f"Failed to load config: {e}")

    def save(self):
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logging.error(f"Failed to save config: {e}")

    # Getters and Setters
    def get(self, key, default=None):
        return self.config.get(key, default)

    def set(self, key, value):
        self.config[key] = value

    def get_all(self):
        return self.config

    def update_from_ui(self, share_path, share_name, port, auth_mode, username, password):
        self.config["share_path"] = share_path
        self.config["share_name"] = share_name
        self.config["port"] = port
        self.config["auth_mode"] = auth_mode
        self.config["username"] = username
        self.config["password"] = password
        self.save()
