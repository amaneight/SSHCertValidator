import OpenSSL
from pyasn1.codec.der import decoder as der_decoder
from pyasn1_modules.rfc2459 import CRLDistPointsSyntax , AuthorityInfoAccessSyntax, AccessDescription, SubjectAltName
import urllib
from oscrypto import asymmetric
from ocspbuilder import OCSPRequestBuilder
from pyasn1_modules.rfc2560 import OCSPResponse, BasicOCSPResponse
import requests
from pyasn1.codec.der import decoder as der_decoder
import pyasn1_modules.rfc2560
import time
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID

class Revocation(object):



    def get_ocsp_url(self,cert):
        
        crl_dist_points = CRLDistPointsSyntax()
        
        if not isinstance(cert, OpenSSL.crypto.X509):
            return False

        for index in range(cert.get_extension_count()):
            
            ext = cert.get_extension(index)
            ext_name = ext.get_short_name()
            #print ext_name

            authInfoAccessSyntax = AuthorityInfoAccessSyntax()
            if ext_name == ExtensionOID.AUTHORITY_INFORMATION_ACCESS._name:

                ext_dat = ext.get_data()
                decoded_dat = der_decoder.decode(ext_dat, 
                                                 asn1Spec=authInfoAccessSyntax)
                
                for authInfoAccess in decoded_dat:
                    
                    if isinstance(authInfoAccess, AuthorityInfoAccessSyntax):
                        for entry in range(len(authInfoAccess)):
                            accessDescription = authInfoAccess.getComponentByPosition(entry)
                            accessMethod = str(accessDescription.getComponentByName('accessMethod'))
                            ocsp_oid = AuthorityInformationAccessOID.OCSP.dotted_string
                            if  ocsp_oid == accessMethod:
                                ocsp_url_generalname = accessDescription.getComponentByName('accessLocation')
                                ocsp_url = ocsp_url_generalname.getComponentByName('uniformResourceIdentifier')
                                #print '\t ocsp_url: ' + str(ocsp_url)
                                return str(ocsp_url)
        return False                        

    def get_ocsp_status(self,cert,is_cert,cert_url,is_cert_url):
        t0 = time.clock()
        #print "Issuer Certificate is >> %s" %(is_cert_name)
        c = OpenSSL.crypto
        
        if not isinstance(cert, c.X509) or not isinstance(is_cert, c.X509):
            return False
        
        id_cert_buf = c.dump_certificate(c.FILETYPE_PEM, cert)
        issuer_cert_buf = c.dump_certificate(c.FILETYPE_PEM, is_cert)
        # with open(cert_name,"rb") as f:
        #     id_cert_buf = f.read()
        # with open(is_cert_name,"rb") as f:
        #     issuer_cert_buf = f.read()

        id_cert = asymmetric.load_certificate(id_cert_buf)
        issuer_cert = asymmetric.load_certificate(issuer_cert_buf)

        builder = OCSPRequestBuilder(id_cert, issuer_cert)
        ocsp_request = builder.build()

        ocsp_req_dump = ocsp_request.dump()

        cert_ocsp_url = cert_url 
        is_ocsp_url = is_cert_url 
        
        resp = requests.post(cert_ocsp_url, ocsp_req_dump)

        ocsp_response = resp.content

        ocspResponse = OCSPResponse()
        basicOcspResponse = BasicOCSPResponse()

        decoded_resp = der_decoder.decode(ocsp_response, asn1Spec=ocspResponse)
        
        for resp in decoded_resp:
        
            if isinstance(resp, OCSPResponse):
                ocsp_response_status = resp.getComponentByName('responseStatus')
                
                ocsp_resp_bytes = resp.getComponentByName('responseBytes')
                ocsp_resp = ocsp_resp_bytes.getComponentByName('response') 
                basic_ocsp_response, _ = der_decoder.decode(ocsp_resp, asn1Spec=basicOcspResponse)
                tbs_response_data = basic_ocsp_response.getComponentByName('tbsResponseData')
                responses = tbs_response_data.getComponentByName('responses')
                for response in responses:
                    
                    serial_no = response.getComponentByName('certID').getComponentByName('serialNumber')                
                    #print str(serial_no)
                    #print response.getComponentByName('certStatus').getName()
                    print time.clock() - t0
                    if response.getComponentByName('certStatus').getName() == "good":
                        return True
                    else:
                        return False

    def crl_check(self,cert,is_cert):

        t0 = time.clock()

        crl_dist_points = CRLDistPointsSyntax()

        for i in range(cert.get_extension_count()):
        
            ext = cert.get_extension(i)
            ext_name = ext.get_short_name()
            #print ext_name
            
            # There is a difference in the string name defined for CRL Distribution Points 
            # in PyOpenSSL & cryptography packages (crlDistributionPoints vs cRLDistributionPoints). 
            # Hence, converting name to lowercase to prevent any error.
            # Such difference is not present for other extensions.
            if ext_name.lower() == (ExtensionOID.CRL_DISTRIBUTION_POINTS._name).lower():
                # PyOpenSSL returns extension data in ASN.1 encoded form
                ext_dat = ext.get_data()
                decoded_dat = der_decoder.decode(ext_dat, 
                                                 asn1Spec=crl_dist_points)
                
                for name in decoded_dat:                    
                    if isinstance(name, CRLDistPointsSyntax):
                        for entry in range(len(name)):

                            component = name.getComponentByPosition(entry)
                            distpoint = component.getComponentByName('distributionPoint')
                            distpointvalue = distpoint.getComponentByName('fullName')

                            for gen_name in distpointvalue:
                                url_name = gen_name.getComponentByName('uniformResourceIdentifier')

                                url_name_str = str(url_name)                             
                                
                                crl_data = urllib.urlopen(url_name_str).read()
                                
                                c = OpenSSL.crypto
                                
                                crl_tuples = c.load_crl(c.FILETYPE_ASN1,crl_data)
                                
                                revoked_data = crl_tuples.get_revoked()

                                curr_serial = format(cert.get_serial_number(),'x').upper()
                                print "No. of entries %r" %(len(revoked_data))
                                for element in revoked_data:
                                    if curr_serial == element.get_serial():
                                            print "Certificate is revoked"
                                            print time.clock() - t0
                                            return False
                                    
                print "Certificate is not revoked"
                print time.clock() - t0
                return True
