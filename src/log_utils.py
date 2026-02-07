
import os
import time
import tempfile
import logging

def cleanup_old_logs(retention_days=7):
    """
    [v1.58] 清理超过保留天数的调试日志文件
    
    Args:
        retention_days: 日志保留天数，默认 7 天
        
    Returns:
        tuple: (删除的文件数, 释放的空间(字节))
    """
    try:
        temp_dir = tempfile.gettempdir()
        log_file = os.path.join(temp_dir, "smb_debug.log")
        
        deleted_count = 0
        freed_space = 0
        current_time = time.time()
        cutoff_time = current_time - (retention_days * 24 * 60 * 60)
        
        # 检查主日志文件
        if os.path.exists(log_file):
            file_mtime = os.path.getmtime(log_file)
            file_size = os.path.getsize(log_file)
            
            # 如果文件超过保留期限
            if file_mtime < cutoff_time:
                try:
                    os.remove(log_file)
                    deleted_count += 1
                    freed_space += file_size
                    logging.info(f"已删除旧日志文件: {log_file} ({file_size / 1024:.1f} KB)")
                except Exception as e:
                    logging.error(f"删除日志文件失败: {e}")
            # 如果文件过大（超过 10MB），截断
            elif file_size > 10 * 1024 * 1024:
                try:
                    # 读取最后 5MB 内容
                    with open(log_file, 'rb') as f:
                        f.seek(-5 * 1024 * 1024, 2)  # 从文件末尾向前 5MB
                        recent_content = f.read()
                    
                    # 重写文件
                    with open(log_file, 'wb') as f:
                        f.write(b"=== Log truncated due to size limit ===\n")
                        f.write(recent_content)
                    
                    freed_space += file_size - os.path.getsize(log_file)
                    logging.info(f"已截断过大的日志文件: {log_file}")
                except Exception as e:
                    logging.error(f"截断日志文件失败: {e}")
        
        return deleted_count, freed_space
    
    except Exception as e:
        logging.error(f"清理日志失败: {e}")
        return 0, 0


def get_log_info():
    """
    [v1.58] 获取当前日志文件信息
    
    Returns:
        dict: 日志文件信息 {path, size, modified_time}
    """
    try:
        temp_dir = tempfile.gettempdir()
        log_file = os.path.join(temp_dir, "smb_debug.log")
        
        if os.path.exists(log_file):
            stat_info = os.stat(log_file)
            return {
                "path": log_file,
                "size": stat_info.st_size,
                "size_mb": stat_info.st_size / (1024 * 1024),
                "modified_time": stat_info.st_mtime,
                "exists": True
            }
        else:
            return {
                "path": log_file,
                "exists": False
            }
    except Exception as e:
        logging.error(f"获取日志信息失败: {e}")
        return {"exists": False}
