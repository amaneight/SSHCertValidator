#
# Author : Aman Sehgal
# Timestamp : Mar 25, 2016 | 10:41:20 AM 
#
#! /usr/bin/python
#

import CertValidate_pb2
import sys
import ConfigParser
import json
from cert_proto_get import GetCertConfig
import texttable as tt

class Proto(object):

  def __init__(self,path):
    self.path = path
    self.config = ConfigParser.RawConfigParser()    
    self.config.read(self.path)

  def read_cfg(self):
    cfg_sections_list = []
    cfg_list = []
    
    cfg_sections_list = self.config.sections()


    for section in cfg_sections_list:
      for items in self.config.items(section):
        cfg_list.append(items)

    return cfg_list


#--------------------------------CFG INPUT--------------------------------
  def cfg_to_proto(self,cert_config):
    cfg_item = self.config.items
    
    "Cert Age"
    cert_config.cert_age = json.loads(cfg_item("Validity")[0][1])
    
    "Path"
    check_path = cfg_item("Path")
    cert_config.trust_store_path = check_path[0][1].strip('"')

    "Public Key"
    check_algo = cfg_item("PublicKey")

    for index in range(len(json.loads(check_algo[0][1]))):
      pub_key = cert_config.PubKey.add()
      pub_key.key_id = json.loads(check_algo[0][1])[index]
      pub_key.algo_name = json.loads(check_algo[1][1])[index]
      pub_key.bits = json.loads(check_algo[2][1])[index]
      

    "Key Usage"
    check_key_usage = cfg_item("KeyUsage")
    for index in range(len(json.loads(check_key_usage[0][1]))):
      key_usage = cert_config.KeyUsage.add()
      key_usage.key_id = json.loads(check_key_usage[0][1])[index]
      key_usage.key_name = json.loads(check_key_usage[1][1])[index]


    "Extended Key Usage"
    check_ext_key_usage = cfg_item("ExtendedKeyUsage")
    for index in range(len(json.loads(check_ext_key_usage[0][1]))):
      ext_key_usage = cert_config.ExtKeyUsage.add()
      ext_key_usage.dotted_string = json.loads(check_ext_key_usage[0][1])[index]
      ext_key_usage.name = json.loads(check_ext_key_usage[1][1])[index]
      ext_key_usage.display_name = json.loads(check_ext_key_usage[2][1])[index]

    "Signing Algo"
    check_algo = cfg_item("SigningAlgo")
    for algo in json.loads(check_algo[0][1]):
      sign_algo = cert_config.SignAlgo.add()
      sign_algo.algo_name = algo

    "Check"
    check_list = cfg_item("Check")
    for chk in check_list:
      cert_check = cert_config.Check.add()
      cert_check.check_name = chk[0]
      cert_check.ctype = chk[1] 
    
    "Revocation"    
    cert_config.preferred_mechanism = cfg_item("Revocation")[0][1]
    cert_config.fail_status = json.loads(cfg_item("Revocation")[1][1])

    return True

  def set_proto(self):
    cfg_item = self.config.items
    check_path = cfg_item("Path")
    file_name = check_path[1][1].strip('"')

    cert_config = CertValidate_pb2.Certificate_Cfg()
    self.cfg_to_proto(cert_config)

    f = open(file_name, "wb")
    f.write(cert_config.SerializeToString())
    print "\nCertificate validation constraints written into file %s " %(file_name)
    f.close()
    return True

 