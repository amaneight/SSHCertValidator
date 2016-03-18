import unittest
import sys
sys.path.append("E:\\DEV_ENV\\Source\\Git\\git_implementation_repo\\common_criteria_cert_validation")

from PyCertValidate import util
import OpenSSL 

class TestUtil(unittest.TestCase):
    
    global msg
    global main_list
    main_list = [1, 2, 3, 4, 5]
    msg = '#### TEST FAILED !'
    
    def setUp(self):
        unittest.TestCase.setUp(self)
        main_list = [1, 2, 3, 4, 5]
    
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
            
if __name__ == "__main__":
    unittest.main()
        
    


