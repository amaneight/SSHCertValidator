import glob
import OpenSSL
class TrustStore(object):

	def __init__(self,cert):
		self.cert = cert

	def get_issuer(self, trust_store_path):
		c = OpenSSL.crypto
		ts_certs = glob.glob(trust_store_path)  # Returns list with names of all the files present in a directory
		#print trust_store_path
		#print ts_certs
		#print str(self.cert.get_subject())
		#print str(self.cert.get_issuer())
		for cert in ts_certs:

			with open(cert, 'rt') as f:
				cert_data = f.read()			

			certificate = OpenSSL.crypto.load_certificate(c.FILETYPE_PEM, cert_data)  # Loads the certificate in PEM format
			#print "\n"
			#print certificate.get_issuer()
			#print "\n"
			if str(self.cert.get_issuer()) == str(certificate.get_subject()):  # Compare subject of Certificate and issuer of cert
				#logging.info("Issuer found in TrustStore")
				return certificate

		#logging.info("Issuer not found in TrustStore")
		return False 