
import logging
import queue
import logging.handlers

class QueueHandler(logging.Handler):
    """
    Log handler that sends records to a queue.
    Used to safely pass logs from server thread to GUI thread.
    """
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put(self.format(record))

def setup_logger(log_queue):
    """配置日志，将日志输出到队列中"""
    logger = logging.getLogger('SMBServer')
    logger.setLevel(logging.INFO)
    
    # 防止重复添加 handler
    if not logger.handlers:
        handler = QueueHandler(log_queue)
        formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%H:%M:%S')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        # 同时也输出到控制台，方便调试
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    return logger
