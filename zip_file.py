import zipfile
from termcolor import colored

def try_extract_file(zip_file, test_password):
    try:
        zip_file.extractall(pwd=test_password)
        #If the password is incorrect, exception would be raised
        return True
        #Since, this statement would be reached only on the non- occcurence of an exception, its returning True as the password id corrct
    except:
        #excption raised, password is incorrect, time to return False
        return False

def driver_code(zip_file, dict_file):
    password_file = dict_file
    for line in password_file.readlines():
        test_pass = line.strip('\n')
        check_guess = try_extract_file(zip_file, test_pass)

        if check_guess == True:
            print colored("Passord found...\n It is"+ test_pass, green)
            exit(0)
    print colored(" Could not find the password!!!",red)

parser = argparse.ArgumentParser()
parser.add_argument('-z','--zip-file', help='The file to be extracted')
parser.add_argument('-p','--pass-file', default = 'dict.txt',help="The dictionary file for passwords")

args = vars(parser.parse_args())
print(args)
zip_file = open(args["zip_file"],'r')
pass_file = open(args["pass_file"],'a+')

driver_code(zip_file, pass_file)