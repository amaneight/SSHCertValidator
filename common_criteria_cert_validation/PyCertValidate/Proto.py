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
      for items in config.items(section):
        cfg_list.append(items)

    return cfg_list


#--------------------------------CFG INPUT--------------------------------
  def cfg_to_proto(self,cert):
    cfg_item = self.config.items
    
    "Cert Age"
    cert.cert_age = json.loads(cfg_item("Validity")[0][1])
    
    "Path"
    check_path = cfg_item("Path")
    cert.trust_store_path = check_path[0][1].strip('"')

    "Public Key"
    check_algo = cfg_item("PublicKey")

    for index in range(len(json.loads(check_algo[0][1]))):
      pub_key = cert.PubKey.add()
      pub_key.key_id = json.loads(check_algo[0][1])[index]
      pub_key.algo_name = json.loads(check_algo[1][1])[index]
      pub_key.bits = json.loads(check_algo[2][1])[index]

    "Key Usage"
    check_key_usage = cfg_item("KeyUsage")
    for index in range(len(json.loads(check_key_usage[0][1]))):
      key_usage = cert.KeyUsage.add()
      key_usage.key_id = json.loads(check_key_usage[0][1])[index]
      key_usage.key_name = json.loads(check_key_usage[1][1])[index]


    "Extended Key Usage"
    check_ext_key_usage = cfg_item("ExtendedKeyUsage")
    for index in range(len(json.loads(check_ext_key_usage[0][1]))):
      ext_key_usage = cert.ExtKeyUsage.add()
      ext_key_usage.dotted_string = json.loads(check_ext_key_usage[0][1])[index]
      ext_key_usage.name = json.loads(check_ext_key_usage[1][1])[index]
      ext_key_usage.display_name = json.loads(check_ext_key_usage[2][1])[index]

    "Signing Algo"
    check_algo = cfg_item("SigningAlgo")
    for algo in json.loads(check_algo[0][1]):
      sign_algo = cert.SignAlgo.add()
      sign_algo.algo_name = algo

    "Check"
    check_list = cfg_item("Check")
    for chk in check_list:
      cert_check = cert.Check.add()
      cert_check.check_name = chk[0]
      cert_check.ctype = chk[1] 
    
    "Revocation"    
    cert.preferred_mechanism = cfg_item("Revocation")[0][1]
    cert.fail_status = json.loads(cfg_item("Revocation")[1][1])

  def set_proto(self):
    cfg_item = self.config.items
    check_path = cfg_item("Path")
    file_name = check_path[1][1].strip('"')

    cert = CertValidate_pb2.Certificate_Cfg()
    self.cfg_to_proto(cert)

    f = open(file_name, "wb")
    f.write(cert.SerializeToString())
    print "\nCertificate validation constraints written into file %s " %(file_name)
    f.close()
    
  

  def get_cfg(self):
      
    config_obj = GetCertConfig()
    
    print "CHECKS"
    
    tab = tt.TextTable()
    header = ['Check Name', 'Type']
    tab.header(header)
    tab.set_cols_width([20,20])
    tab.set_cols_align(['l','r','c'])
    tab.set_cols_valign(['t','b','m'])
    tab.set_deco(tab.HEADER | tab.VLINES)
    tab.set_chars(['-','|','+','-'])

    for element in config_obj.cert_check_list:
        tab.add_row([element[0], element[1]])
        print "%r : %r" %(element[0], element[1])
        
        with open("table.txt","wb") as f:
            f.write(tab.draw())
            
    "Key Usage"
    
    for element in config_obj.key_list:
        print "%r %r" %(element[0], element[1])
    
    "Extended Key Usage"
    for element in config_obj.ext_key_list:
        print "%r %r %r" %(element[0], element[1], element[2])
        
    
    "Signing Algo"
    for element in config_obj.pub_key_list:
        print "%r %r %r" %(element[0], element[1], element[2])
    
    "Public Key"
    for element in config_obj.algo_name_list:
        print "%r" %(element[0])
    
    "Validity"
    print config_obj.cert_age
    
    "Trust store path"
    print config_obj.trust_store_path
    
    "Proto object path"
    print "Preferred revocation mechanism : %r" %(config_obj.preferred_mechanism)
    print "Fail status : %r"  %(config_obj.fail_status)
    