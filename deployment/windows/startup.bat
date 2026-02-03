@echo off
:: windows_startup.bat
:: 将此快捷方式放入 Shell:startup 文件夹即可实现开机自启

:: 切换到项目目录 (请修改为实际路径)
cd /d "C:\Path\To\SMB_Server"

:: 启动服务 (使用 pythonw 可隐藏黑框，或者直接用 python)
:: 如果需要管理员权限监听 445，建议通过 "任务计划程序" 运行此脚本
python run.py

pause
