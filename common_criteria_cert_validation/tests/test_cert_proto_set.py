import unittest
import OpenSSL

import os
this_dir_path = os.path.dirname(os.path.abspath(__file__))
path_to_append = os.path.abspath(os.path.join(this_dir_path, ".."))
import sys
sys.path.append(path_to_append)

from PyCertValidate.cert_proto_set import *
from PyCertValidate import CertValidate_pb2

class TestCertProtoSet(unittest.TestCase):
    
    global msg
    
    msg = '#### TEST FAILED !'
    
    def test_update_default_config_true(self):
        self.assertTrue(update_default_config(), msg)
    
    def test_update_config_true(self):
        config = CertValidate_pb2.Certificate_Cfg()        
        config.cert_age = 5
        config.trust_store_path = "test_truststore"
        config.preferred_mechanism = 'CRL'
        config.fail_status = True
        file_name = "test_proto.obj"
        
        self.assertTrue(update_config(config, file_name), msg)
        
if __name__ == "__main__":
    unittest.main()