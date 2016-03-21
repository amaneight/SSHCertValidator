import unittest
import sys
sys.path.append("E:\\DEV_ENV\\Source\\Git\\git_implementation_repo\\common_criteria_cert_validation")
from PyCertValidate.TrustStore import *
import OpenSSL

class TestTrustStore(unittest.TestCase):
    
    global truststore_path, cert_trusted, cert_untrusted, msg
    
    msg = '#### TEST FAILED !'
    
    truststore_path = "E:\\DEV_ENV\\Source\\Git\\git_implementation_repo\\common_criteria_cert_validation\\PyCertValidate\\truststore\\*.cer"
     
    certpath_trusted = 'E:\\DEV_ENV\\Source\\Git\\git_implementation_repo\\common_criteria_cert_validation/certificates/citi.pem'
    certfile_trusted = open(certpath_trusted, 'r').read()
    cert_trusted = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile_trusted)
    
    certpath_untrusted = 'E:\\DEV_ENV\\Source\\Git\\git_implementation_repo\\common_criteria_cert_validation/certificates/self_signed_1024.pem'
    certfile_untrusted = open(certpath_untrusted, 'r').read()
    cert_untrusted = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile_untrusted)
    
    
    def test_get_issuer_true(self):
        truststore = TrustStore(cert_trusted)
        self.assertIsNotNone(truststore.get_issuer(truststore_path), msg)
    
    def test_get_issuer_false(self):
        truststore = TrustStore(cert_untrusted)
        self.assertFalse(truststore.get_issuer(truststore_path), msg)
        
if __name__ == "__main__":
    unittest.main()