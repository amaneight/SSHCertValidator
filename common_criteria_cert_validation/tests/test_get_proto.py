#
# Author : Aman Sehgal
# Timestamp : Mar 28, 2016 | 12:24:31 PM 
#
#! /usr/bin/python

import unittest
import os


this_dir_path = os.path.dirname(os.path.abspath(__file__))
path_to_append = os.path.abspath(os.path.join(this_dir_path, ".."))
import sys
sys.path.append(path_to_append)

from PyCertValidate.GetProto import GetProto
from PyCertValidate.cert_proto_get import GetCertConfig
import texttable as tt

class TestProto(unittest.TestCase):
    
    global cert_config, gp, msg
    
    msg = "#### TEST FAILED !"
    

    cert_config = GetCertConfig()
    gp = GetProto()
    
    def test_proto_true(self):
        self.assertIsInstance(gp.table_config(['header']) , tt.Texttable, msg)
        self.assertTrue(gp.get_proto())

if __name__ == "__main__":
    unittest.main()       
