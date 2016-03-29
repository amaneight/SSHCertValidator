import unittest
import OpenSSL

import os
this_dir_path = os.path.dirname(os.path.abspath(__file__))
path_to_append = os.path.abspath(os.path.join(this_dir_path, ".."))
import sys
sys.path.append(path_to_append)

from PyCertValidate.TrustStore import *


class TestTrustStore(unittest.TestCase):
    
    global truststore_path, cert_trusted, cert_untrusted, msg
    
    def setUp(self):
        import os
        this_dir_path = os.path.dirname(os.path.abspath(__file__))
        print "THIS : " + this_dir_path
        path_to_append = os.path.abspath(os.path.join(this_dir_path, ".."))
        print "APPEND : " + path_to_append
        import sys
        #sys.path.append("E:\\DEV_ENV\\Source\\Git\\git_implementation_repo\\common_criteria_cert_validation")
        sys.path.append(path_to_append)
        #print sys.path
        from PyCertValidate.TrustStore import *
        
        self.msg = '#### TEST FAILED !'
    
        self.truststore_path = truststore_path = path_to_append + '\\PyCertValidate\\truststore\\*.*'
        path_to_append + '/certificates/citi.pem' 
        certpath_trusted = path_to_append + '\\certificates\\citi.pem' 
        certfile_trusted = open(certpath_trusted, 'r').read()
        self.cert_trusted = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile_trusted)
        
        certpath_untrusted = path_to_append + '\\certificates\\self_signed_1024.pem'
        certfile_untrusted = open(certpath_untrusted, 'r').read()
        self.cert_untrusted = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile_untrusted)
    
    
    def test_get_issuer_true(self):
        truststore = TrustStore(self.cert_trusted)
        self.assertIsNotNone(truststore.get_issuer(self.truststore_path), self.msg)
    
    def test_get_issuer_false(self):
        truststore = TrustStore(self.cert_untrusted)
        self.assertFalse(truststore.get_issuer(self.truststore_path), self.msg)
        
if __name__ == "__main__":
    unittest.main()