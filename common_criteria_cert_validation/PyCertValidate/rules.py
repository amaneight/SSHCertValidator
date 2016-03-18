from util import *
from CertValidity import *
from Usage import *
from Revocation import *
from TrustStore import *
from cert_proto_get import GetCertConfig
from Crypto import *
from Crypto.Util import asn1
from PublicKey import *
import OpenSSL

class CertRules(object):

	def __init__(self,cert):
		# c = OpenSSL.crypto
		# st_cert = open("Citi.cer", 'rt').read() 
		# cert = c.load_certificate(c.FILETYPE_PEM, st_cert)

		self.cert = cert
		self.config_obj = GetCertConfig()
		self.valid_obj = CertValidity(cert)
		self.revocation_obj = Revocation(cert)
		self.trust_store_obj = TrustStore(cert)

		self.usage_obj = Usage()
		self.pubkey_obj = PublicKey(cert)
		self.ext_dict = get_extension(cert)
		

	def check_validity(self):
		return self.valid_obj.check_validity()

	def check_expiry(self):
		return self.valid_obj.check_expiry()

	def check_period(self):
		return self.valid_obj.check_period(self.config_obj.cert_age)

	def check_issuer(self):
		res = self.trust_store_obj.get_issuer("TrustStore/*.cer")#self.config_obj.trust_store_path)
		if res == False:
			return False
		return True
		#return True
		#return check_issuer(self.cert,self.config_obj.trust_store_path)

	def check_subject(self):
		return True

	def check_keysize(self):
		return self.pubkey_obj.check_keysize(self.config_obj.pub_key_list)

	def check_key_usage(self):
		return True
		# req_usage_list = []
		# key_list = self.config_obj.key_list
		# for index in len(key_list):
		# 	req_usage_list.append(key_list[index][0])

		# return self.usage_obj.key_usage_check(self.cert,self.ext_dict['keyUsage'],req_usage_list)

	def check_ext_key_usage(self):
		req_extusage_list = []
		extusage_list = self.config_obj.ext_key_list
		#print extusage_list
		
		for element in extusage_list:
			#print element[0]
			req_extusage_list.append(element[0])

		return self.usage_obj.extkey_usage_chk(self.cert,self.ext_dict['extendedKeyUsage'],req_extusage_list)

	def check_crl(self):
		return self.revocation_obj.crl_check()

	def check_ocsp(self):
	
		cert_url = self.revocation_obj.get_ocsp_url()
		
		#is_cert_name, 
		is_cert_obj = self.trust_store_obj.get_issuer("TrustStore/*.cer")#self.config_obj.trust_store_path
		
		if is_cert_obj == False:
			return False
		else:
			revocation_obj = Revocation(is_cert_obj)
			is_cert_url = revocation_obj.get_ocsp_url()

			if is_cert_url == False:
				return False
			else:
				res = self.revocation_obj.get_ocsp_status(is_cert_obj,cert_url,is_cert_url)
				if res == True:
					return True
				else:
					return False
		#res = self.trust_store_obj.get_issuer("TrustStore/*.cer")
		