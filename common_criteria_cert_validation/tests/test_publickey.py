import unittest

import os
this_dir_path = os.path.dirname(os.path.abspath(__file__))
path_to_append = os.path.abspath(os.path.join(this_dir_path, ".."))
import sys
sys.path.append(path_to_append)

from PyCertValidate.PublicKey import *
import OpenSSL

class TestPublicKey(unittest.TestCase):
    
    global cert, cert_1024, keysizes_with_1024, keysizes, msg
    msg = '#### TEST FAILED !'
    certpath = path_to_append + '/certificates/citi.pem'
    certpath_1024 = path_to_append + '/certificates/self_signed_1024.pem'
    
    certfile = open(certpath, 'r').read()
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile)
    
    certfile_1024 = open(certpath_1024, 'r').read()
    cert_1024 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile_1024)
    
    keysize_1024 = [6, 'RSA', 1024]
    keysize_2048 = [6, 'RSA', 2048]
    keysize_4096 = [6, 'RSA', 4096]
    keysizes = [keysize_2048, keysize_4096]
    keysizes_with_1024 = [keysize_1024]
    keysizes_with_1024.append(keysizes)
    
    def test_check_keysize_true(self):
        pubkey = PublicKey(cert)
        self.assertTrue(pubkey.check_keysize(keysizes), msg)
    
    def test_check_keysize_false(self):
        pubkey = PublicKey(cert_1024)
        self.assertFalse(pubkey.check_keysize(keysizes), msg)
    
    def test_check_keysize_1024_true(self):
        pubkey = PublicKey(cert_1024)
        self.assertTrue(pubkey.check_keysize(keysizes_with_1024), msg)
        
if __name__ == "__main__":
    unittest.main()