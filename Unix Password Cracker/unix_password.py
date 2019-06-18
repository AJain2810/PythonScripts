"""
Assumes you have a text file contaning salted passwords
Conducts a dictionary attack by salting teh passwords and comparing them
The file for common passwords has to be supplied by the user

    passwords.txt: A file containing password extracted from a server/ any other source
    dictionary.txt: A file containig list of common UNIX passwords

    
"""
import crypt
from termcolor import colored

def testPassword(cryptPass):
    salt= cryptPass[0:2]
    #First two characters of the salted password are the keys/ salts used to hash it
    dictFile = open('../pass_dict.txt','r')
    for word in dictFile.readlines():
        word = word.strip('\n')
        cryptWord = crypt.crypt(word,salt)
        #Hashes the password from ductionay file with the first two characters read from password file as the hash
        if (cryptWord == cryptPass):
            print(colored("Found Password: ",word,"\n"),'green')
            return
    print(colored("Password Not Found."),'red')
    return


passFile = open('passwords.txt')
for line in passFile.readlines():
    if ":" in line:
        user = line.split(':')[0]
        #Password stores as: user-name:salted-password
        cryptPass = line.split(':')[1].strip(' ')
    testPassword(cryptPass) 

