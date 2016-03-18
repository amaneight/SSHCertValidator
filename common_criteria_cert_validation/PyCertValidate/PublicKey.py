#! /usr/bin/python

class PublicKey(object):

	def __init__(self,cert):
		self.cert = cert

	def check_keysize(self,algo):
		pubkey = self.cert.get_pubkey()
		pubkey_type = pubkey.type()
		pubkey_bits = pubkey.bits()

		for element in algo:
			if element[0] == pubkey_type:
				if element[2] >= pubkey_bits:
					return True
		return False