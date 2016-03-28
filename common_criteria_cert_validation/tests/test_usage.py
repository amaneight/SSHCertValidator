import unittest
import sys
sys.path.append("E:\\DEV_ENV\\Source\\Git\\git_implementation_repo\\common_criteria_cert_validation")
from PyCertValidate.Usage import *
import OpenSSL
from cryptography.x509.oid import ExtensionOID
#import cryptography.x509.oid.ExtensionOID

class TestUsage(unittest.TestCase):
    
    global cert, msg, keyusage_extension, ext_keyusage_extension, required_EKUs, other_EKUs, required_KUs, other_KUs
    
    msg = '#### TEST FAILED !'
    
    certpath = 'E:\\DEV_ENV\\Source\\Git\\git_implementation_repo\\common_criteria_cert_validation/certificates/citi.pem'    
    certfile = open(certpath, 'r').read()
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile)
    
    required_EKUs = ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"]
    other_EKUs = ["1.3.6.1.5.5.7.3.3", "1.3.6.1.5.5.7.3.4"]

    required_KUs = [0,1,2]
    other_KUs = [4,5]
    #all_EKUs.append(required_EKUs)
    
    def test_key_usage_chk_true(self):

        
        extension_dict = {}
    
        for index in range(cert.get_extension_count()): 
            extension = cert.get_extension(index)
            ext_name = extension.get_short_name()
            extension_dict[ext_name] = extension
            
        usage = Usage()

        self.assertTrue(usage.key_usage_chk(cert,extension_dict['keyUsage'],required_KUs),msg)  

    def test_key_usage_chk_false(self):

        
        extension_dict = {}
    
        for index in range(cert.get_extension_count()): 
            extension = cert.get_extension(index)
            ext_name = extension.get_short_name()
            extension_dict[ext_name] = extension
            
        usage = Usage()

        self.assertTrue(usage.key_usage_chk(cert,extension_dict['keyUsage'],other_KUs),msg)    

      
    
    def test_extkey_usage_chk_true(self):
        
        for index in range(cert.get_extension_count()):            
            extension = cert.get_extension(index)
            extension_name = extension.get_short_name()           
            if ExtensionOID.EXTENDED_KEY_USAGE._name == extension_name:
                ext_keyusage_extension = extension
        
        usage = Usage()
        self.assertTrue(usage.extkey_usage_chk(cert, ext_keyusage_extension, required_EKUs), msg)
    
    def test_extkey_usage_chk_false(self):
        
        for index in range(cert.get_extension_count()):            
            extension = cert.get_extension(index)
            extension_name = extension.get_short_name()           
            if ExtensionOID.EXTENDED_KEY_USAGE._name == extension_name:
                ext_keyusage_extension = extension
        
        usage = Usage()
        self.assertFalse(usage.extkey_usage_chk(cert, ext_keyusage_extension, other_EKUs), msg)
 
     
if __name__ == "__main__":
    unittest.main()       