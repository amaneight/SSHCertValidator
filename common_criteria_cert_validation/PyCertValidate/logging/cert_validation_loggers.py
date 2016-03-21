import logging 

def get_custom_logger(name, default_level, logfile):
    
    logger = logging.getLogger(name) 
    
    logger.setLevel(default_level)    
    
    filehandler = logging.FileHandler(logfile)
    format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    formatter = logging.Formatter(format)    
    filehandler.setFormatter(formatter)    
    logger.addHandler(filehandler)
    
    return logger


def get_audit_logger():
    
    name = 'audit_logger'
    default_level = logging.DEBUG
    logfile = 'audit.log'
    
    audit_logger = get_custom_logger(name, default_level, logfile)
    
    return audit_logger


def get_debug_logger():
    
    name = 'debug_logger'
    default_level = logging.NOTSET
    logfile = 'debug.log'
    
    debug_logger = get_custom_logger(name, default_level, logfile)
    
    return debug_logger
