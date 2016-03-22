import logging 

def get_custom_logger(name, default_level, logfile):
    
    logger = logging.getLogger(name) 
    
    logger.setLevel(default_level)    
    
    filehandler = logging.FileHandler(logfile)
    format = '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s - %(message)s'
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

def get_audit_logger():
    
    logger = logging.getLogger('audit_logger') 
    
    logger.setLevel(logging.DEBUG)
    
    filehandler = logging.FileHandler('audit.log')
    streamhandler = logging.StreamHandler()
    
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    filehandler.setFormatter(formatter)
    
    logger.addHandler(filehandler)
    logger.addHandler(streamhandler)
    
    return logger


def get_error_logger():
    
    logger = logging.getLogger('error_logger') 
    
    logger.setLevel(logging.WARN)
    
    filehandler = logging.FileHandler('error.log')
    streamhandler = logging.StreamHandler()
    
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    filehandler.setFormatter(formatter)
    
    logger.addHandler(filehandler)
    logger.addHandler(streamhandler)
    
    return logger


def get_debug_logger():
    
    logger = logging.getLogger('debug_logger') 
    
    logger.setLevel(logging.NOTSET)
    logfile = 'E:\DEV_ENV\Source\Git\git_implementation_repo\common_criteria_cert_validation\PyCertValidate\debug.log'
    filehandler = logging.FileHandler(logfile)
    streamhandler = logging.StreamHandler()
    
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    filehandler.setFormatter(formatter)
    
    logger.addHandler(filehandler)
    logger.addHandler(streamhandler)
    
    return logger
