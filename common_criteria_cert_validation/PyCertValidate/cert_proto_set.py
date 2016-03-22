#! /usr/bin/python

import CertValidate_pb2
import sys
from loggers.cert_validation_loggers import *


def PromptForConfigurations(cert): # pragma: no cover
  cert.cert_age = int(raw_input("Enter certificate age : "))
  cert.trust_store_path = raw_input("Enter trust store path : ")

  while True:
    flag = raw_input("Add public key algorithm details (Y/N) ? : ")
    if flag == 'N' or flag == 'n':
      break

    pub_key = cert.PubKey.add()

    pub_key.key_id = int(raw_input("Enter algoirthm id : "))
    pub_key.algo_name = raw_input("Enter algorithm name : ")
    pub_key.bits = int(raw_input("Enter lower limit of acceptable bits : "))
    
  while True:
    flag = raw_input("Add key usage details (Y/N) ? ")
    if flag == 'N' or flag == 'n':
      break

    key_usage = cert.KeyUsage.add()

    key_usage.key_id = int(raw_input("Enter key id : "))
    key_usage.key_name = raw_input("Enter key name : ")
    


  while True:
    flag = raw_input("Add extended key usage details (Y/N) ? ")
    if flag == 'N' or flag == 'n':
      break

    ext_key_usage = cert.ExtKeyUsage.add()

    ext_key_usage.dotted_string = raw_input("Enter dotted string : ")
    ext_key_usage.name = raw_input("Enter extended key usage name : ")
    ext_key_usage.display_name = raw_input("Enter display name : ")

  while True:
    flag = raw_input("Add acceptable signing algorithm (Y/N) ? ")
    if flag == 'N' or flag == 'n':
      break

    sign_algo = cert.SignAlgo.add()

    sign_algo.algo_name = raw_input("Enter algoirthm name : ")

  check_list = ["check_validity", "check_expiry","check_period","check_issuer","check_subject","check_key_usage","check_ext_key_usage","check_keysize","check_crl","check_ocsp"]
  

   
  for check in check_list:
    cert_check = cert.Check.add()
    cert_check.check_name = check
    print "\nCheck name : %s" %(check)
    ctype = int(raw_input("Enter type : (1) MANDATORY | (2) OPTIONAL | (3) NOT_REQUIRED  : "))

    if ctype == 1:
        cert_check.ctype = "MANDATORY"
    elif ctype == 2:
        cert_check.ctype = "OPTIONAL"
    elif ctype == 3:
        cert_check.ctype = "NOT_REQUIRED"

  cert.preferred_mechanism = raw_input("Preferred mechanism for revocation (CRL/OCSP) : ")
  cert.fail_status = bool(raw_input("Allow certificate if revocation check fails (True / False)? : "))
        

logger = get_audit_logger()

def update_config(config, file_name):
    try:
        f = open(file_name, "wb")
        f.write(config.SerializeToString())
        logger.info("Configuration updated in " + file_name)
    except Exception as e:
        logger.error("Error updating configuration. " + e.message)
        return False
    finally:
        f.close()    
    return True

    
def update_default_config():
    
    try:
        config = CertValidate_pb2.Certificate_Cfg()        
        config.cert_age = 3
        config.trust_store_path = "./default_truststore/"
        file_name = "default_proto.obj"
        update_config(config, file_name)
    except Exception as e:
        logger.error("Error updating default configuration. " + e.message)
        return False
    
    return True





