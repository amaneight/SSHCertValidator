import unittest
import sys
sys.path.append("E:\\DEV_ENV\\Source\\Git\\git_implementation_repo\\common_criteria_cert_validation")
from PyCertValidate.Revocation import *
import OpenSSL

class TestRevocation(unittest.TestCase):
    
    global cert, cert_revoked, msg
    
    msg = '#### TEST FAILED !'
    
    certpath = 'E:\\DEV_ENV\\Source\\Git\\git_implementation_repo\\common_criteria_cert_validation/certificates/citi.pem'    
    certfile = open(certpath, 'r').read()
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile)
    
    certpath_revoked = 'E:\\DEV_ENV\\Source\\Git\\git_implementation_repo\\common_criteria_cert_validation/certificates/self_signed_1024.pem'    
    certfile_revoked = open(certpath_revoked, 'r').read()
    cert_revoked = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile_revoked)
    
    
    def test_crl_check_true(self):
        revocation = Revocation(cert)
        self.assertTrue(revocation.crl_check(), msg)
        
    def test_crl_check_false(self):
        revocation = Revocation(cert_revoked)
        self.assertFalse(revocation.crl_check(), msg)
        
    def test_get_ocsp_status_true(self):
        revocation = Revocation(cert)
        self.assertTrue(revocation.get_ocsp_status(), msg)
    
    def test_get_ocsp_status_false(self):
        revocation = Revocation(cert_revoked)
        self.assertTrue(revocation.get_ocsp_status(), msg)
    
    def test_get_ocsp_url_true(self):
        revocation = Revocation(cert)
        self.assertIsInstance(revocation.get_ocsp_url(), str, msg)    
    
    def test_get_ocsp_url_false(self):
        revocation = Revocation(cert_revoked)
        self.assertFalse(revocation.get_ocsp_url(), msg)    
        

if __name__ == "__main__":
    unittest.main()        
