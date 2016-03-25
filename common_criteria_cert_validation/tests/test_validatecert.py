import unittest
import sys


from PyCertValidate.ValidateCertificate import *
import OpenSSL
from cryptography.x509.oid import ExtensionOID

class TestValidateCert(unittest.TestCase):
    
    global cert, msg
    
    msg = '#### TEST FAILED !'
    
    certpath = 'Citi.pem'    
    certfile = open(certpath, 'r').read()
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile)
    
    def test_classify_rules_true(self):
        validateCert = ValidateCert()
        self.assertTrue(validateCert.classify_rules(), msg)
        
if __name__ == "__main__":
    unittest.main()