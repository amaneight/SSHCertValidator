
from logging.cert_validation_loggers import *

class PublicKey(object):

	def __init__(self,cert):
		self.cert = cert
		self.logger = get_debug_logger()
		self.logger.setLevel(logging.DEBUG)

	def check_keysize(self, supported_keys):
		cert_pubkey = self.cert.get_pubkey()
		cert_pubkey_type = cert_pubkey.type()
		cert_pubkey_size = cert_pubkey.bits()
		
		#self.logger.info("------------ START --------------")
		
		self.logger.info("Checking key with type : " + str(cert_pubkey_type) + 
						" & size : " + str(cert_pubkey_size))

		for supported_key in supported_keys:			
			# supported_key[0] = (Integer) Code for the key algorithm (6:RSA, 116:DSA, 408:EC)
			# supported_key[1] = (String)  Display name for the key algorithm
			# supported_key[2] = (Integer) Key Size in bits 
			if cert_pubkey_type == supported_key[0]:
				self.logger.info("Certificate key belongs to a supported key type : " 
								+ supported_key[1])
				if cert_pubkey_size == supported_key[2]:
					self.logger.info("Certificate key belongs to a supported key size : " 
									+ str(supported_key[2]))
					return True
				
		self.logger.error("Certificate key does not belong to a supported key type or size.")
		return False