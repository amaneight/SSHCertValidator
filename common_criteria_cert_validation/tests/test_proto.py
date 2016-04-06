import unittest

import os
import OpenSSL
this_dir_path = os.path.dirname(os.path.abspath(__file__))
path_to_append = os.path.abspath(os.path.join(this_dir_path, ".."))
import sys
sys.path.append(path_to_append)

import PyCertValidate.CertValidate_pb2
import sys
import ConfigParser
import json
from PyCertValidate.cert_proto_get import GetCertConfig

from PyCertValidate.SetProto import Proto

from PyCertValidate import CertValidate_pb2

class TestProto(unittest.TestCase):
    
    global proto, path, msg,config, cert_config,keyusage_extension, ext_keyusage_extension, required_EKUs, other_EKUs
    
    msg = "#### TEST FAILED !"
    

    path = path_to_append + '/PyCertValidate/example.cfg'
    config = ConfigParser.RawConfigParser()    
    config.read(path)

    cert_config = CertValidate_pb2.Certificate_Cfg()
    
    
    def test_proto_true(self):
        proto = Proto(path)
        self.assertIsInstance(proto.read_cfg(), list, msg)
        self.assertTrue(proto.set_proto(),msg)
        
    def test_update_default_config_true(self):
        self.assertTrue(proto.update_default_config(), msg)
    
    def test_update_config_true(self):
        config = CertValidate_pb2.Certificate_Cfg()        
        config.cert_age = 5
        config.trust_store_path = "test_truststore"
        config.preferred_mechanism = 'CRL'
        config.fail_status = True
        file_name = "test_proto.obj"
        
        self.assertTrue(proto.update_config(config, file_name), msg)

if __name__ == "__main__":
    unittest.main()       