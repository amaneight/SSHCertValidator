from cert_proto_get import GetCertConfig
from rules import CertRules

import re
import sys
import glob
import logging
import OpenSSL
import requests
#import certmessage_pb2


#from Crypto import *
#from Crypto.Util import asn1

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


	st_cert = open("fb.cer", 'rt').read()  # Read certificate
	cert = c.load_certificate(c.FILETYPE_PEM, st_cert)

	cert_obj = ValidateCert()	
	rule_obj = CertRules(cert)
	

	rules_dict = cert_obj.classify_rules()	

	print "--- Executing mandatory checks ---"

	for rule in rules_dict['MANDATORY']:
		methodName = getattr(rule_obj, rule)
		status = methodName()
		print "-------------------------------------------"
		print " MethodName %s > Result %s" %(rule,status)
		print "-------------------------------------------"
		#print status

	# for rule in rules_dict['MANDATORY']:

	# 	func_name = "rule_obj."+rule +"()"
	# 	res = eval(func_name) 
	# 	if res == True:
	# 		print 'Success'
	# 	else:
	# 		print 'Failure'


    #exec("print '%s' has  characters % (abc(2,3))", {"__builtins__" : None}, safe_dict)
	#cert_store = certmessage_pb2.CertStore()

	#f = open("a.txt",'rb')
	#cert_store.ParseFromString(f.read())
	#f.close()

	#st_cert = ListCert(cert_store)

	#print type(st_cert)

	  # Load certificate                                  
	# print cert.get_subject()
	# print "--------------------------------------------------------------------"
	# print "Validity status >> %s" % (Validity(cert))
	# print "--------------------------------------------------------------------"
	# print "Is Key size greater than 2048 bits >> %r" % (KeySize(cert))
	# print "--------------------------------------------------------------------"
	# # print "Revocation Status >> %s" %(RevocationStatus(cert))
	# print "--------------------------------------------------------------------"
	# print "Signing algorithm >> %s" % (SigningAlgo(cert))
	# print "--------------------------------------------------------------------"
	# print "Issuer >> %s" % (Issuer(cert, 'TrustStore/*.cer'))
	# print "--------------------------------------------------------------------"
	# print "Subject >> %s" % (Subject(cert))
	# print "--------------------------------------------------------------------"
	# print "Key Usage >> %s" % (Usage(cert))
	# print "--------------------------------------------------------------------"
	# print "Extended Key Usage >> %s" % (ExtendedKeyUsage(cert))
	# print "--------------------------------------------------------------------"

#Get attr
#Multiple cert in a cert file