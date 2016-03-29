import unittest

import os
this_dir_path = os.path.dirname(os.path.abspath(__file__))
path_to_append = os.path.abspath(os.path.join(this_dir_path, ".."))
import sys
sys.path.append(path_to_append)

from PyCertValidate.rules import *
import OpenSSL

class TestRules(unittest.TestCase):
    
    global cert, other_cert, rules, other_rules, msg
    
    msg = '#### TEST FAILED !'
    
    certpath = path_to_append + '\\certificates\\citi.pem'    
    certfile = open(certpath, 'r').read()
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile)

    other_certpath = path_to_append + '\\certificates\\soundcloud.cer'
    other_certfile = open(other_certpath, 'r').read()
    other_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, other_certfile)


    
    rules = CertRules(cert)
    other_rules = CertRules(other_cert)
    
    
    def test_check_validity_true(self):
        self.assertTrue(rules.check_validity(), msg)
    
    def test_check_period_true(self):
        self.assertTrue(rules.check_period(), msg)

    def test_check_issuer_true(self):
        self.assertTrue(rules.check_issuer(), msg)

    def test_check_issuer_false(self):
        self.assertFalse(other_rules.check_issuer(), msg)

    def test_check_subject_true(self):
        self.assertTrue(rules.check_subject(),msg)

    def test_check_key_usage_true(self):
        self.assertTrue(rules.check_key_usage(),msg)

    def test_check_keysize_true(self):
        self.assertTrue(rules.check_keysize(),msg)

    def test_check_revocation_true(self):
        self.assertTrue(rules.check_revocation(),msg)
        
    def test_check_ocsp_true(self):     
        self.assertTrue(rules.check_ocsp(), msg)
    
    def test_check_ext_key_usage_true(self):
        self.assertTrue(rules.check_ext_key_usage(), msg)
        
    def test_check_crl_true(self):
        self.assertTrue(rules.check_crl(), msg)
        
        
if __name__ == "__main__":
    unittest.main()