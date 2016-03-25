import unittest
import sys
sys.path.append("E:\\DEV_ENV\\Source\\Git\\git_implementation_repo\\common_criteria_cert_validation")
from PyCertValidate.Revocation import *
from PyCertValidate.TrustStore import *
import OpenSSL

class TestRevocation(unittest.TestCase):
    
    global cert, cert_revoked, cert_issuer, cert_revoked_issuer, revocation, msg
    
    msg = '#### TEST FAILED !'
    
    certpath = 'E:\\DEV_ENV\\Source\\Git\\git_implementation_repo\\common_criteria_cert_validation/certificates/citi.pem'    
    certfile = open(certpath, 'r').read()
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile)
    
    certpath_revoked = 'E:\\DEV_ENV\\Source\\Git\\git_implementation_repo\\common_criteria_cert_validation/certificates/self_signed_1024.pem'    
    certfile_revoked = open(certpath_revoked, 'r').read()
    cert_revoked = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile_revoked)
    
    revocation = Revocation()
    
    truststore = TrustStore(cert)
    cert_issuer = truststore.get_issuer(truststore_path)
    
    truststore = TrustStore(cert_revoked)
    cert_revoked_issuer = truststore.get_issuer(truststore_path)
    
    def test_crl_check_true(self):
        self.assertTrue(revocation.crl_check(cert, cert_issuer), msg)
        
    def test_crl_check_false(self):
        self.assertFalse(revocation.crl_check(cert_revoked, cert_revoked_issuer), msg)
        
    def test_get_ocsp_status_true(self):
        self.assertTrue(revocation.get_ocsp_status(), msg)
    
    def test_get_ocsp_status_false(self):
        self.assertTrue(revocation.get_ocsp_status(), msg)
    
    def test_get_ocsp_url_true(self):
        self.assertIsInstance(revocation.get_ocsp_url(cert), str, msg)    
    
    def test_get_ocsp_url_false(self):
        self.assertFalse(revocation.get_ocsp_url(cert_revoked), msg)    
        

if __name__ == "__main__":
    unittest.main()        
