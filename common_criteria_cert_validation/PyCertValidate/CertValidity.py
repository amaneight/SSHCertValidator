#! /usr/bin/python
from datetime import date
from dateutil.relativedelta import relativedelta
from logging.cert_validation_loggers import *

class CertValidity(object):

	def __init__(self,cert):
		self.cert = cert
		self.logger = get_audit_logger()

	def check_validity(self):
		
		''' 
		Check if certificate is currently valid 
		'''
		
		StDate = self.cert.get_notBefore()[:8]
		StartDate = date(int(StDate[:4]), int(StDate[4:6]), int(StDate[6:8]))		
		self.logger.info("Certificate start date : " + str(StartDate))

		EnDate = self.cert.get_notAfter()[:8]
		EndDate = date(int(EnDate[:4]), int(EnDate[4:6]), int(EnDate[6:8]))
		self.logger.info("Certificate end date : " + str(EndDate))
		
		CurrDate = date.today()

		if CurrDate >= StartDate and CurrDate <= EndDate:
			self.logger.info("Certificate is valid")
			return True
		else:
			self.logger.info("Certificate is invalid")
			return False



	def check_period(self, acceptable_duration_in_years):

		'''
		Check if certificate life is not more than n years. Where, n = duration.
		'''

		StDate = self.cert.get_notBefore()[:8]
		StartDate = date(int(StDate[:4]), int(StDate[4:6]), int(StDate[6:8]))
		self.logger.info("Certificate start date : " + str(StartDate))
		
		EnDate = self.cert.get_notAfter()[:8]
		EndDate = date(int(EnDate[:4]), int(EnDate[4:6]), int(EnDate[6:8]))
		self.logger.info("Certificate end date : " + str(EndDate))

		CurrDate = date.today()
		
		cert_validity_in_days = (EndDate - StartDate).days
		acceptable_duration_in_days = acceptable_duration_in_years*365
		
		if CurrDate > StartDate and cert_validity_in_days <= acceptable_duration_in_days:
			self.logger.info("Validity period does not exceed 3 years")
			return True
		else:
			self.logger.error("Validity period exceeds 3 years")
			return False
