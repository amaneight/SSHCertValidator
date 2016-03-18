import urllib
from cryptography.x509.oid import ExtendedKeyUsageOID, ObjectIdentifier
import OpenSSL
from pyasn1.codec.der import decoder as der_decoder
from pyasn1_modules.rfc2459 import ExtKeyUsageSyntax, KeyUsage, Validity, namedtype

ext_key_usage = ExtKeyUsageSyntax()
key_usage = KeyUsage()

class Usage(object):

    def key_usage_chk(self,cert,extension):

        # for index in range(cert.get_extension_count()):

        #     extension = cert.get_extension(index)
        #     ext_name = extension.get_short_name()
           
        #     if ext_name == 'keyUsage':
        ext_data = extension.get_data()
        decoder_data = der_decoder.decode(ext_data, asn1Spec = key_usage)
        key_usage_list = []
        #print [name.namedValues[index][0] for name in decoder_data for index in range(len(name)) if name[index]==1]
        for name in decoder_data:
            for index in range(len(name)):
                if name[index] == 1:
                    key_usage_list.append(name.namedValues[index][0])
                    
        return key_usage_list


    def extkey_usage_chk(self,cert,extension,req_extension):

        #id = cryptography.x509.oid

        eku_values = ExtendedKeyUsageOID.__dict__.values()
        

        ext_dat = extension.get_data()
        decoder_dat = der_decoder.decode(ext_dat, asn1Spec = ext_key_usage)
        extkey_usage_list = []
        for name in decoder_dat:
            if isinstance(name,ExtKeyUsageSyntax):

                for entry in range(len(name)):
                    component = name.getComponentByPosition(entry)                  
                    
                    for index in range(len(eku_values)):
            
                        if isinstance(eku_values[index], ObjectIdentifier):
                            
                            if eku_values[index].dotted_string == str(component):
                                ek_dstr = eku_values[index].dotted_string
                                extkey_usage_list.append(eku_values[index].dotted_string)

                                #print eku_values[index]._name

        if len(set(extkey_usage_list) & set(req_extension)) > 0:
            return True
        else:
            return False
                

# certfile = open('fb.cer', 'r').read()
# c = OpenSSL.crypto
# cert = OpenSSL.crypto.load_certificate(c.FILETYPE_PEM, certfile) 
# u = Usage()
# #u.key_usage_chk(cert)

# validity = Validity()
# print validity.getComponentType()

# for index in range(cert.get_extension_count()):

#     extension = cert.get_extension(index)
#     ext_name = extension.get_short_name()
#     print ext_name

#     #print der_decoder.decode(extension.get_data())

#     if ext_name == 'ct_precert_scts':
#         ext_dat = extension.get_data()
#         print type(ext_dat)

#         #decoder_dat = der_decoder.decode(ext_dat, asn1Spec = )
#         #print decoder_dat
#         #u.extkey_usage_chk(cert,extension)