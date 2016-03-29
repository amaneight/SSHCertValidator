from cert_proto_get import GetCertConfig
from rules import CertRules

import re
import sys
import glob
import logging
import OpenSSL
import requests
#import certmessage_pb2

from datetime import date
from dateutil.relativedelta import relativedelta

from enum import Enum
from OpenSSL import crypto

from pyasn1.type import univ
from pyasn1.codec.ber import encoder, decoder

class ValidateCert(object):

	def __init__(self):
		self.config_obj = GetCertConfig()

	def classify_rules(self):
		chk_dict = {}
		chk_dict['MANDATORY'] = []
		chk_dict['OPTIONAL'] = []
		chk_dict['NOT_REQUIRED'] = []
		
		chk_list = self.config_obj.cert_check_list

		for index in chk_list:		
			check_name = index[0]
			ctype = index[1]
			chk_dict[ctype].append(check_name)
			
		return chk_dict
			


if __name__ == '__main__': # pragma: no cover
#logging.basicConfig(filename="D:\Nutanix\example.log", level=logging.DEBUG)

	c = OpenSSL.crypto


	st_cert = open("Citi.cer", 'rt').read()  # Read certificate
	cert = c.load_certificate(c.FILETYPE_PEM, st_cert)

	cert_obj = ValidateCert()	
	rule_obj = CertRules(cert)
	

	rules_dict = cert_obj.classify_rules()	

	print "--- Executing mandatory checks ---"
	fail_count = 0
	
	for rule in rules_dict['MANDATORY']:
		methodName = getattr(rule_obj, rule)
		
		status = methodName()
		
		if status == False:
			fail_count += 1
		
		print "-------------------------------------------"
		print " MethodName %s > Result %s" %(rule,status)
		print "-------------------------------------------"
		
	if fail_count == 0:

		print "Mandatory checks passed"
		print "--- Executing optional checks ---"
		for rule in rules_dict['OPTIONAL']:
			methodName = getattr(rule_obj, rule)
			
			status = methodName()
			
			print "-------------------------------------------"
			print " MethodName %s > Result %s" %(rule,status)
			print "-------------------------------------------"
	else:
		print "Mandatory checks failed"