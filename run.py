
import os
import sys

# 将当前目录添加到 PYTHONPATH
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.main import MainApp
import tkinter as tk

if __name__ == "__main__":
    root = tk.Tk()
    app = MainApp(root)
    root.mainloop()
