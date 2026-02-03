
import os
import sys

# 将当前目录添加到 PYTHONPATH
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.cli_main import main

if __name__ == "__main__":
    main()
