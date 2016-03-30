#
# Author : Aman Sehgal
# Timestamp : Mar 28, 2016 | 11:20:21 AM 
#
#! /usr/bin/python

from cert_proto_get import GetCertConfig


class GetProto(object):
    
    def lformat(self, element):
        return "{:20}".format(element)
    
    def rformat(self, element):
        return "{:>20}".format(element)
    
    def cformat(self, element):
        return "{:^20}".format(element)
    
    def draw(self, char, spaces):
        l = ["{:"]
        l.append(char)
        l.append("<")
        l.append(str(spaces))
        l.append("}")

        return "".join(l).format("")


    def get_proto(self):
        config_obj = GetCertConfig()
        table_content = []

        "Check"
        table_content.append( "\n Check \n")
        
        table_content.append(self.draw('-',40))
        table_content.append( "%s|%s" %(self.cformat("Check Name"),self.cformat("Type")))
        table_content.append( self.draw('-',40))
        

        for element in config_obj.cert_check_list:
            table_content.append( "%s|%s" %(self.lformat(element[0]),self.rformat(element[1])))
                
        "Key Usage"
        table_content.append( "\n Key Usage \n")
        table_content.append( self.draw('-',40))
        table_content.append( "%s|%s" %(self.cformat("Key ID"),self.cformat("Key Name")))
        table_content.append( self.draw('-',40))

        for element in config_obj.key_list:
            table_content.append( "%s|%s" %(self.cformat(element[0]),self.rformat(element[1])))
            

        "Extended Key Usage"
        table_content.append( "\n Extended Key Usage \n")
        
        table_content.append( self.draw('-',60))
        table_content.append( "%s|%s|%s" %(self.cformat("Dotted String"),self.cformat("Usage Name"),self.cformat("Display Name")))
        table_content.append( self.draw('-',60))
        for element in config_obj.ext_key_list:
            table_content.append( "%s|%s|%s" %(self.cformat(element[0]),self.lformat(element[1]),self.rformat(element[2])))

        "Public Key"
        table_content.append( "\n Public Key \n")
        table_content.append( self.draw('-',60))
        table_content.append( "%s|%s|%s" %(self.cformat("Algo Code"),self.cformat("Algo Name"),self.cformat("Required bits")))
        table_content.append( self.draw('-',60))
        for element in config_obj.pub_key_list:
            table_content.append( "%s|%s|%s" %(self.cformat(element[0]),self.lformat(element[1]),self.rformat(element[2])))
            
        "Signing Algo"
        table_content.append( "\n Signing Algo \n")
        table_content.append( self.draw('-',20))
        table_content.append( "%s" %(self.cformat("Algo Name")))
        table_content.append( self.draw('-',20))
        for element in config_obj.algo_name_list:
            table_content.append( "%s" %(self.cformat(element)))
            
        "Validity"
        table_content.append( "\n Validity \n")
        table_content.append( self.draw('-',20))
        table_content.append( "%s" %(self.cformat("Certificate Age")))
        table_content.append( self.draw('-',20))
        table_content.append( "%s" %(self.cformat(config_obj.cert_age)))
        
        "Trust Store Path"
        table_content.append( "\n Trust Store Path \n")
        table_content.append( self.draw('-',20))
        table_content.append( "%s" %(self.cformat("Path")))
        table_content.append( self.draw('-',20))
        table_content.append( "%s" %(self.cformat(config_obj.trust_store_path)))

        "Revocation"
        table_content.append( "\n Revocation Mechanism \n")
        table_content.append( self.draw('-',40))
        table_content.append( "%s|%s" %(self.cformat("Preferred Mechanism"),self.cformat("Fail Status")))
        table_content.append( self.draw('-',40))
        table_content.append( "%s|%s" %(self.cformat(config_obj.preferred_mechanism),self.cformat(config_obj.fail_status)))

        with open("Tablenew.txt","wb") as f:
            f.write("\n".join(table_content))
            
        return True