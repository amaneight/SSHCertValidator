import unittest

import os
this_dir_path = os.path.dirname(os.path.abspath(__file__))
path_to_append = os.path.abspath(os.path.join(this_dir_path, ".."))
import sys
sys.path.append(path_to_append)

from PyCertValidate.ValidateCertificate import *
import OpenSSL
from cryptography.x509.oid import ExtensionOID

class TestValidateCert(unittest.TestCase):
    
    global cert, msg
    
    msg = '#### TEST FAILED !'
    
    certpath = path_to_append + '/certificates/citi.pem'    
    certfile = open(certpath, 'r').read()
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile)
    
    def test_classify_rules_true(self):
        validateCert = ValidateCert()
        self.assertTrue(validateCert.classify_rules(), msg)
        
if __name__ == "__main__":
    unittest.main()