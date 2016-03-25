import unittest
import sys


from PyCertValidate.rules import *
import OpenSSL

class TestRules(unittest.TestCase):
    
    global cert, msg
    
    msg = '#### TEST FAILED !'
    
    certpath = 'Citi.pem'    
    certfile = open(certpath, 'r').read()
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile)
    
    def test_check_validity_true(self):
        rules = CertRules(cert)
        self.assertTrue(rules.check_validity(), msg)
        
    def test_check_ocsp_true(self):     
        rules = CertRules(cert)
        self.assertTrue(rules.check_ocsp(), msg)
    
    def test_check_ext_key_usage_true(self):
        rules = CertRules(cert)
        self.assertTrue(rules.check_ext_key_usage(), msg)
        
if __name__ == "__main__":
    unittest.main()