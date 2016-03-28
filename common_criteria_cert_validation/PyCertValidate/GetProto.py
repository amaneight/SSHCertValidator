#
# Author : Aman Sehgal
# Timestamp : Mar 28, 2016 | 11:20:21 AM 
#
#! /usr/bin/python

from cert_proto_get import GetCertConfig
import texttable as tt

class GetProto(object):
    
      def table_config(self,header_list):
            tab = tt.Texttable()
            
            header = []
            for title in header_list:
              header.append(title)
            tab.header(header)

            cols = []
            for index in range(len(header_list)):
              cols.append("20")
            tab.set_cols_width(cols)

            align = ["l"]
            for index in range(len(header_list)-1):
              align.append("r")
            tab.set_cols_align(align)    
            
            valign = ["l"]
            for index in range(len(header_list)-1):
              valign.append("r")
            tab.set_cols_valign(valign)

            tab.set_deco(tab.HEADER | tab.VLINES)
            tab.set_chars(['-','|','+','-'])

            return tab


      def get_proto(self):
              
            config_obj = GetCertConfig()
            table_content = []

            table_content.append("CHECKS\n\n")

            header = ['Check Name', 'Type']
            tab = self.table_config(header)

            for element in config_obj.cert_check_list:
                tab.add_row([element[0], element[1]])                
                
            table_content.append(tab.draw())
                    
            "Key Usage"
            table_content.append("\n\nKEY USAGE\n\n")
            header = ['Key ID', 'Key Name']
            tab = self.table_config(header)

            for element in config_obj.key_list:
                tab.add_row([element[0], element[1]])
                
            table_content.append(tab.draw())
            
            "Extended Key Usage"
            table_content.append("\n\nEXT KEY USAGE\n\n")
            header = ['Dotted String', 'Usage Name', 'Display Name']
            tab = self.table_config(header)
            for element in config_obj.ext_key_list:
              tab.add_row([element[0], element[1], element[2]])

            table_content.append(tab.draw())

            "Public Key"
            table_content.append("\n\nPUBLIC KEY\n\n")
            header = ['Algo Code', 'Algo Name', 'Required bits']
            tab = self.table_config(header)
            
            for element in config_obj.pub_key_list:
              tab.add_row([element[0], element[1], element[2]])
              
            table_content.append(tab.draw())
            
            "Signing Algo"
            table_content.append("\n\nSIGNING ALGO\n\n")
            header = ['Algo Name']
            tab = self.table_config(header)
            
            for element in config_obj.algo_name_list:
              tab.add_row([element])
            table_content.append(tab.draw())

            "Validity"
            table_content.append("\n\nVALIDITY\n\n")
            header = ['Age']
            tab = self.table_config(header)
            tab.add_row([config_obj.cert_age])
            table_content.append(tab.draw())

            "Trust store path"
            table_content.append("\n\nPATH\n\n")
            header = ['Path']
            tab = self.table_config(header)
            tab.add_row([config_obj.trust_store_path])
            table_content.append(tab.draw())

            "Proto object path"
            table_content.append("\n\nREVOCATION\n\n")
            header = ['Mechanism', 'Fail Satatus']
            tab = self.table_config(header)

            tab.add_row([config_obj.preferred_mechanism, config_obj.fail_status])
            table_content.append(tab.draw())
            print ''.join(table_content)


            with open("Table.txt","wb") as f:
              f.write(''.join(table_content))

            return True   