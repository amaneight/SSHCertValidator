from util import *
from CertValidity import *
from Usage import *
from Revocation import *
from TrustStore import *
from cert_proto_get import GetCertConfig
#from Crypto import *
#from Crypto.Util import asn1
from PublicKey import *
import OpenSSL
from cryptography.x509.oid import ExtensionOID
from loggers.cert_validation_loggers import *

class CertRules(object):

	def __init__(self,cert):
		# c = OpenSSL.crypto
		# st_cert = open("Citi.cer", 'rt').read() 
		# cert = c.load_certificate(c.FILETYPE_PEM, st_cert)
		
		self.logger = get_audit_logger()

		self.cert = cert
		self.config_obj = GetCertConfig()
		self.valid_obj = CertValidity(cert)
		self.revocation_obj = Revocation()
		self.trust_store_obj = TrustStore(cert)

		self.usage_obj = Usage()
		self.pubkey_obj = PublicKey(cert)
		self.ext_dict = get_extension(cert)
		#self.config_obj.trust_store_path = "E:\\DEV_ENV\\Source\\Git\\git_implementation_repo\\common_criteria_cert_validation\\PyCertValidate\\truststore\\*.cer"
		

	def check_validity(self):
		return self.valid_obj.check_validity()

	def check_period(self):
		return self.valid_obj.check_period(self.config_obj.cert_age)

	def check_issuer(self):
		print self.config_obj.trust_store_path
		res = self.trust_store_obj.get_issuer(self.config_obj.trust_store_path+"\*.*")#self.config_obj.trust_store_path)
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
		req_usage_list = []
		key_list = self.config_obj.key_list
		for index in key_list:
			req_usage_list.append(index[0])

		return self.usage_obj.key_usage_chk(self.cert,self.ext_dict['keyUsage'],req_usage_list)

	def check_ext_key_usage(self):
		req_extusage_list = []
		extusage_list = self.config_obj.ext_key_list
		#print extusage_list
		
		for element in extusage_list:
			#print element[0]
			req_extusage_list.append(element[0])

		return self.usage_obj.extkey_usage_chk(self.cert,self.ext_dict[ExtensionOID.EXTENDED_KEY_USAGE._name],req_extusage_list)
	
	def check_revocation(self):
		mech = self.config_obj.preferred_mechanism
		
		if mech == "CRL":
			return self.check_crl()
		elif mech == "OCSP":
			return self.check_ocsp()

	def check_crl(self):
		print "CRL"
		t0 = time.clock()
		cert = self.cert
		res = True

		while res == True:
			
			trust_store_obj = TrustStore(cert)
			is_cert = trust_store_obj.get_issuer(self.config_obj.trust_store_path+"\*.*")

			if str(is_cert.get_issuer()) == str(is_cert.get_subject()): 
				break
			else:
				res =  self.revocation_obj.crl_check(cert,is_cert)
				
				if res == False:
					return False
				else:
					cert = is_cert

		print "Total CRL check time"
		print time.clock() - t0
		return True



	def check_ocsp(self):
		print "OCSP"
		cert = self.cert
		res = True

		while res == True:
			trust_store_obj = TrustStore(cert)
			is_cert = trust_store_obj.get_issuer(self.config_obj.trust_store_path+"\*.*")#self.config_obj.trust_store_path

			if str(is_cert.get_issuer()) == str(is_cert.get_subject()): 
				break
			else:
				cert_url = self.revocation_obj.get_ocsp_url(cert)		
			
				if is_cert == False:
					return False
				else:				
					is_cert_url = self.revocation_obj.get_ocsp_url(is_cert)

					if is_cert_url == False:
						return False
					else:
						res = self.revocation_obj.get_ocsp_status(cert,is_cert,cert_url,is_cert_url)
						if res == True:
							cert = is_cert
						else:
							return False

			return True
		