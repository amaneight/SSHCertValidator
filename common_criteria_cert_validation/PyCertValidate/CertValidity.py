#! /usr/bin/python
from datetime import date
from dateutil.relativedelta import relativedelta
import logging

class CertValidity(object):

	def __init__(self,cert):
		self.cert = cert

	def check_validity(self):
		
		''' 
		Check if certificate is currently valid 
		'''
		
		StDate = self.cert.get_notBefore()[:8]
		StartDate = date(int(StDate[:4]), int(StDate[4:6]), int(StDate[6:8]))

		EnDate = self.cert.get_notAfter()[:8]
		EndDate = date(int(EnDate[:4]), int(EnDate[4:6]), int(EnDate[6:8]))

		CurrDate = date.today()

		if CurrDate > StartDate and CurrDate < EndDate:
			logging.info("Certificate is valid")
			return True
		else:
			logging.info("Certificate is invalid")
			return False


	def check_expiry(self):

		'''
		Check if certificate has expired
		'''

		if self.cert.has_expired() is True:
			logging.critical("Certificate has expired")  
			return False
		else:
			logging.info("Certificate has not expired")  
			return True


	def check_period(self,duration):

		'''
		Check if certificate life is not more than 3 years
		'''

		StDate = self.cert.get_notBefore()[:8]
		StartDate = date(int(StDate[:4]), int(StDate[4:6]), int(StDate[6:8]))
		
		EnDate = self.cert.get_notAfter()[:8]
		EndDate = date(int(EnDate[:4]), int(EnDate[4:6]), int(EnDate[6:8]))

		CurrDate = date.today()

		if CurrDate > StartDate and (EndDate.year - StartDate.year) <= duration:
			logging.info("Validity period doesnt exceed 3 years")
			return True
		else:
			logging.error("Validity period exceeds 3 years")
			return False
