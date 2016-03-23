#! /usr/bin/python

import CertValidate_pb2
import sys

class GetCertConfig(object):

  def __init__(self):    

    protopath = "E:\\DEV_ENV\\Source\\Git\\git_implementation_repo\\common_criteria_cert_validation\\PyCertValidate\\a.txt"
    f = open(protopath, "rb")
    config = CertValidate_pb2.Certificate_Cfg()
    config.ParseFromString(f.read())
    f.close()
  
    self.cert_age = config.cert_age
    self.trust_store_path = config.trust_store_path

    self.pub_key_list = []

    for key_algo in config.PubKey:
      pub_key = []
      pub_key.append(key_algo.key_id)
      pub_key.append(key_algo.algo_name)
      pub_key.append(key_algo.bits)
      self.pub_key_list.append(pub_key)

    self.key_list = []

    for key in config.KeyUsage:
      keys = []
      keys.append(key.key_id)
      keys.append(key.key_name)
      self.key_list.append(keys)

    self.ext_key_list = []
    for ext_key in config.ExtKeyUsage:
      ext_keys = []
      ext_keys.append(ext_key.dotted_string)
      ext_keys.append(ext_key.name)
      ext_keys.append(ext_key.display_name)
      self.ext_key_list.append(ext_keys)

    self.algo_name_list = []

    for algo in config.SignAlgo:
      self.algo_name_list.append(algo.algo_name)

    self.cert_check_list=[]

    for check in config.Check:
      cert_check = []
      cert_check.append(check.check_name)
      cert_check.append(check.ctype)
      self.cert_check_list.append(cert_check)

  
    self.preferred_mechanism = config.preferred_mechanism
    self.fail_status = config.fail_status  

# Implementation
# from cert_proto_get import GetCertConfig
# g = GetCertConfig()
# g.cert_age


# def ListConfig(cert):
#   print cert.cert_age
#   print cert.trust_store_path

#   for key_algo in cert.PubKey:
#     print key_algo.key_id
#     print key_algo.algo_name
#     print key_algo.bits

#   for ext_key in cert.ExtKeyUsage:
#     print ext_key.dotted_string
#     print ext_key.name
#     print ext_key.display_name

#   for algo in cert.SignAlgo:
#     print algo.algo_name


#   for check in cert.Check:
#     print check.check_name
#     print check.ctype
  
#   print cert.preferred_mechanism
#   print cert.fail_status  

# cert = CertValidate_pb2.Certificate_Cfg()
# file_name = raw_input("Enter file name : ")

# f = open(file_name, "rb")
# cert.ParseFromString(f.read())
# f.close()
# ListConfig(cert)