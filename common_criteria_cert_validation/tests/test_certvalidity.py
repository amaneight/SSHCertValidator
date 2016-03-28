import unittest

import os
this_dir_path = os.path.dirname(os.path.abspath(__file__))
path_to_append = os.path.abspath(os.path.join(this_dir_path, ".."))
import sys
sys.path.append(path_to_append)

from PyCertValidate.CertValidity import *
import OpenSSL

class TestCertValidity(unittest.TestCase):
    
    global cert, cert_longduration, cert_expired, msg
    
    msg = '#### TEST FAILED !'
    
    certpath = path_to_append + '/certificates/citi.pem'    
    certfile = open(certpath, 'r').read()
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile)
    
    certpath = path_to_append + '/certificates/longduration_cert.pem'
    certfile_longduration = open(certpath, 'r').read()
    cert_longduration = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile_longduration)
    
    certpath = path_to_append + '/certificates/expired_cert.pem'
    certfile_expired = open(certpath, 'r').read()
    cert_expired = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile_expired)
    
    
    def test_check_validity_true(self):
        certvalidity = CertValidity(cert)
        self.assertTrue(certvalidity.check_validity(), msg)
        
    def test_check_validity_false(self):
        certvalidity = CertValidity(cert_expired)
        self.assertFalse(certvalidity.check_validity(), msg)    
    
    def test_check_period_true(self):
        certvalidity = CertValidity(cert)
        self.assertTrue(certvalidity.check_period(3), msg)
            
    def test_check_period_false(self):
        certvalidity = CertValidity(cert_longduration)
        self.assertFalse(certvalidity.check_period(3), msg)


if __name__ == "__main__":
    unittest.main()