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

  def table_config(self,header_list):
    tab = tt.Texttable()
    
    header = []
    for title in header_list:
      header.append(title)
    tab.header(header)

    cols = []
    for index in range(len(header_list)):
      cols.append("20")
    tab.set_cols_width(cols)

    align = ["l"]
    for index in range(len(header_list)-1):
      align.append("r")
    tab.set_cols_align(align)    
    
    valign = ["l"]
    for index in range(len(header_list)-1):
      valign.append("r")
    tab.set_cols_valign(valign)

    tab.set_deco(tab.HEADER | tab.VLINES)
    tab.set_chars(['-','|','+','-'])

    return tab


  def get_proto(self):
      
    config_obj = GetCertConfig()
    table_content = []

    table_content.append("CHECKS\n\n")

    header = ['Check Name', 'Type']
    tab = self.table_config(header)

    for element in config_obj.cert_check_list:
        tab.add_row([element[0], element[1]])
        print "%r : %r" %(element[0], element[1])
        
    table_content.append(tab.draw())
            
    "Key Usage"
    table_content.append("\n\nKEY USAGE\n\n")
    header = ['Key ID', 'Key Name']
    tab = self.table_config(header)

    for element in config_obj.key_list:
        tab.add_row([element[0], element[1]])
        print "%r %r" %(element[0], element[1])

    table_content.append(tab.draw())
    
    "Extended Key Usage"
    table_content.append("\n\nEXT KEY USAGE\n\n")
    header = ['Dotted String', 'Usage Name', 'Display Name']
    tab = self.table_config(header)
    for element in config_obj.ext_key_list:
      tab.add_row([element[0], element[1], element[2]])
      print "%r %r %r" %(element[0], element[1], element[2])

    table_content.append(tab.draw())

    "Public Key"
    table_content.append("\n\nPUBLIC KEY\n\n")
    header = ['Algo Code', 'Algo Name', 'Required bits']
    tab = self.table_config(header)
    
    for element in config_obj.pub_key_list:
      tab.add_row([element[0], element[1], element[2]])
      print "%r %r %r" %(element[0], element[1], element[2])

    table_content.append(tab.draw())
    
    "Signing Algo"
    table_content.append("\n\nSIGNING ALGO\n\n")
    header = ['Algo Name']
    tab = self.table_config(header)
    
    for element in config_obj.algo_name_list:
      tab.add_row([element])
      print "%r" %(element)
    table_content.append(tab.draw())

    "Validity"
    table_content.append("\n\nVALIDITY\n\n")
    header = ['Age']
    tab = self.table_config(header)
    tab.add_row([config_obj.cert_age])
    print config_obj.cert_age
    table_content.append(tab.draw())

    "Trust store path"
    table_content.append("\n\nPATH\n\n")
    header = ['Path']
    tab = self.table_config(header)
    tab.add_row([config_obj.trust_store_path])
    print config_obj.trust_store_path
    table_content.append(tab.draw())

    "Proto object path"
    table_content.append("\n\nREVOCATION\n\n")
    header = ['Mechanism', 'Fail Satatus']
    tab = self.table_config(header)

    tab.add_row([config_obj.preferred_mechanism, config_obj.fail_status])
    print "Preferred revocation mechanism : %r" %(config_obj.preferred_mechanism)
    print "Fail status : %r"  %(config_obj.fail_status)
    table_content.append(tab.draw())
    print ''.join(table_content)


    with open("Table.txt","wb") as f:
      f.write(''.join(table_content))    