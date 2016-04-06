import unittest

import os
this_dir_path = os.path.dirname(os.path.abspath(__file__))
path_to_append = os.path.abspath(os.path.join(this_dir_path, ".."))
import sys
sys.path.append(path_to_append)

from PyCertValidate.Revocation import *
from PyCertValidate.TrustStore import *
import OpenSSL

class TestRevocation(unittest.TestCase):
    
    global cert, cert_revoked, cert_issuer, cert_revoked_issuer, revocation, msg, cert_url, cert_issuer_url,cert_revoked , cert_revoked_url, cert_revoked_issuer_url
    
    msg = '#### TEST FAILED !'
    revocation = Revocation()
    
    truststore_path = path_to_append + '\\PyCertValidate\\truststore\\*.*'
    
    certpath = path_to_append + '/certificates/citi.pem'    
    certfile = open(certpath, 'r').read()
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile)
    
    certpath_revoked = path_to_append + '/certificates/self_signed_1024.pem'    
    certfile_revoked = open(certpath_revoked, 'r').read()
    cert_revoked = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile_revoked)
    
<<<<<<< Upstream, based on origin/cc_implementation_asterix
    
=======
    truststore_path = path_to_append + '/PyCertValidate/truststore/*.cer'
    
    revocation = Revocation()
>>>>>>> 2870ef5 More corrections to test cases.
    
    truststore = TrustStore(cert)
    cert_issuer = truststore.get_issuer(truststore_path)

   
    truststore = TrustStore(cert_revoked)
    cert_revoked_issuer = truststore.get_issuer(truststore_path)

    cert_url = revocation.get_ocsp_url(cert)
    cert_issuer_url = revocation.get_ocsp_url(cert_issuer)
    cert_revoked_url = revocation.get_ocsp_url(cert_revoked)
    #cert_revoked_issuer_url = revocation.get_ocsp_url(cert_revoked_issuer)
    
    def test_crl_check_true(self):
        self.assertTrue(revocation.crl_check(cert, cert_issuer), msg)
        
    def test_crl_check_false(self):
        self.assertFalse(revocation.crl_check(cert_revoked, cert_revoked_issuer), msg)
        
    def test_get_ocsp_status_true(self):
<<<<<<< Upstream, based on origin/cc_implementation_asterix
        
        self.assertTrue(revocation.get_ocsp_status(cert,cert_issuer,cert_url,cert_issuer_url), msg)
=======
        cert_ocsp_url = revocation.get_ocsp_url(cert)
        cert_issuer_ocsp_url = revocation.get_ocsp_url(cert_issuer)
        self.assertTrue(revocation.get_ocsp_status(cert, cert_issuer, 
                                                   cert_ocsp_url, cert_issuer_ocsp_url), msg)
>>>>>>> 2870ef5 More corrections to test cases.
    
    def test_get_ocsp_status_false(self):
<<<<<<< Upstream, based on origin/cc_implementation_asterix
        self.assertTrue(revocation.get_ocsp_status(cert,cert_issuer,cert_url,cert_issuer_url), msg)
        #self.assertTrue(revocation.get_ocsp_status(cert_revoked,cert_revoked,cert_revoked_url,cert_revoked_url), msg)
=======
        cert_revoked_ocsp_url = revocation.get_ocsp_url(cert_revoked)
        cert_revoked_issuer_ocsp_url = revocation.get_ocsp_url(cert_revoked_issuer)
        self.assertTrue(revocation.get_ocsp_status(cert_revoked, cert_revoked_issuer, 
                                                   cert_revoked_ocsp_url, cert_revoked_issuer_ocsp_url), msg)
>>>>>>> 2870ef5 More corrections to test cases.
    
    def test_get_ocsp_url_true(self):
        self.assertIsInstance(revocation.get_ocsp_url(cert), str, msg)    
    
    def test_get_ocsp_url_false(self):
        self.assertFalse(revocation.get_ocsp_url(cert_revoked), msg)    
        

if __name__ == "__main__":
    unittest.main()        
