import unittest

import CertValidate_pb2
import sys
import ConfigParser
import json
from cert_proto_get import GetCertConfig
import texttable as tt
from PyCertValidate.Proto import *


class TestProto(unittest.TestCase):
    
    global path, msg,config, cert_config,keyusage_extension, ext_keyusage_extension, required_EKUs, other_EKUs
    
    msg = "#### TEST FAILED !"
    
    path = 'D:\PyCertValidate\Final Implementation\PyCertValidate\example.cfg'
    config = ConfigParser.RawConfigParser()    
    config.read(path)

    cert_config = CertValidate_pb2.Certificate_Cfg()
    
    
    def test_proto_true(self):
        proto = Proto(path)
        self.assertIsInstance(proto.read_cfg(), list, msg)
        self.assertTrue(proto.set_proto(),msg)

if __name__ == "__main__":
    unittest.main()       