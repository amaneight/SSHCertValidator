import unittest
import sys


from PyCertValidate import util
import OpenSSL 

class TestUtil(unittest.TestCase):
    
    global msg, main_list, certpath, cert
    main_list = [1, 2, 3, 4, 5]
    msg = '#### TEST FAILED !'
    certpath = 'Citi.pem'
    certfile = open(certpath, 'r').read()
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile)
    
    def setUp(self):
        unittest.TestCase.setUp(self)
        main_list = [1, 2, 3, 4, 5]
        certfile = open(certpath, 'r').read()
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certfile)
    
    def test_less_than_true(self):    
        self.assertTrue(util.less_than(2, 3), msg)    
    
    def test_less_than_false(self):
        self.assertFalse(util.less_than(3, 2), msg)    
    
    def test_greater_than_true(self):
        self.assertTrue(util.greater_than(3, 2), msg)    
    
    def test_greater_than_false(self):
        self.assertFalse(util.greater_than(2, 3), msg)        
    
    def test_less_than_eq_true(self):
        self.assertTrue(util.less_than_eq(2,3), msg)
        self.assertTrue(util.less_than_eq(2,2), msg)
    
    def test_less_than_eq_false(self):
        self.assertFalse(util.less_than_eq(3,2), msg)
    
    def test_greater_than_eq_true(self):
        self.assertTrue(util.greater_than_eq(3,2), msg)
        self.assertTrue(util.greater_than_eq(2,2), msg)
    
    def test_greater_than_eq_false(self):
        self.assertFalse(util.greater_than_eq(2,3), msg)
    
    def test_equal_to_true(self):
        self.assertTrue(util.equal_to(2, 2), msg)

    def test_equal_to_false(self):
        self.assertFalse(util.equal_to(2, 3), msg)
        
    def test_present_in_true(self):
        self.assertTrue(util.present_in(2, main_list), msg)
    
    def test_present_in_false(self):
        self.assertFalse(util.present_in(7, main_list), msg)
        
    def test_get_extension(self):
        self.assertIsNotNone(util.get_extension(cert), msg)
            
if __name__ == "__main__":
    unittest.main()
        
    


