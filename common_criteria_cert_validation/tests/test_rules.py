import unittest
import sys
sys.path.append("E:\\DEV_ENV\\Source\\Git\\git_implementation_repo\\common_criteria_cert_validation")
sys.path.append("E:\\DEV_ENV\\Source\\Git\\git_implementation_repo\\common_criteria_cert_validation\\PyCertValidate")
from PyCertValidate.rules import *
import OpenSSL

class TestRules(unittest.TestCase):
    
    global cert, rules, msg
    
    msg = '#### TEST FAILED !'
    
    certpath = 'E:\\DEV_ENV\\Source\\Git\\git_implementation_repo\\common_criteria_cert_validation/certificates/citi.pem'    
    certfile = open(certpath, 'r').read()
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile)
    
    rules = CertRules(cert)
    
    
    def test_check_validity_true(self):
        self.assertTrue(rules.check_validity(), msg)
        
    def test_check_ocsp_true(self):     
        self.assertTrue(rules.check_ocsp(), msg)
    
    def test_check_ext_key_usage_true(self):
        self.assertTrue(rules.check_ext_key_usage(), msg)
        
    def test_check_crl_true(self):
        self.assertTrue(rules.check_crl(), msg)
        
        
if __name__ == "__main__":
    unittest.main()