"""
Assumes you have a text file contaning salted passwords
Conducts a dictionary attack by salting teh passwords and comparing them
The file for common passwords has to be supploed by the user
"""
import crypt

def testPassword(cryptPass):
    salt= cryptPass[0:2]
    #First two characters of the salted password are the keys/ salts used to hash it
    dictFile = open('dictionary.txt','r')
    for word in dictFile.readlines():
        word = word.strip('\n')
        cryptWord = crypt.crypt(word,salt)
        #Hashes the password from ductionay file with the first two characters read from password file as the hash
        if (cryptWord == cryptPass):
            print("[+] Found Password: ",word,"\n")
            return
        print( "[-] Password Not Found.\n")
    return


passFile = open('passwords.txt')
for line in passFile.readlines():
    if ":" in line:
        user = line.split(':')[0]
        #Password stores as: user-name:salted-password
        cryptPass = line.split(':')[1].strip(' ')
    testPassword(cryptPass) 

