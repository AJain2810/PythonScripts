#Working
#
#
#   python3 -i <input- urls> -o <desired active output URLs file> 
#   OR:
#   python -i <input-urls> -o <output-file-desired-name>
#   // if the defauly python version on your OS is Python3.
#   in- active URLs in dump.txt
#
#
  
import requests
import argparse
import urllib
import os
import re
from termcolor import colored

def valid_url_check(url_input): 
    # with valid conditions for urls in string 
    url = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\), ]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', url_input)
    return len(url)>0
    # True if it is a valid URL

 
def url_scan(url_input):
    try:
        res = requests.head(url_input)
        stats = res.status_code
        return stats==200 or stats==302 or stats==202 or stats==301
    except:
        return False
    #google.com

def https_add(url_input):
    url = 'https://'+url_input
    return url

def http_add(url_input):
    url = 'http://'+url_input
    return url

  
  
print('File containing invalid arguments would be named: invalid_domains.txt')
parser = argparse.ArgumentParser()
parser.add_argument('-i','--input-file', help='The file containing the sublist3d domains')
parser.add_argument('-o','--output-file', help="Desired name of output file containing valid URLs")
  
#CMD Arg parsing done
  
  
  
args = vars(parser.parse_args())
print(args)
input_file = open(args["input_file"],'r')
output_file = open(args["output_file"],'a+')
dump_file = open('invalid_domains.txt','a+')
  
  
#Start scanning for each URL
for line in input_file.readlines():
    #check fr each domain
    line = line[:-1]
    url_valid=url_scan(line)
    
    stats=bool()
    if(url_valid):
        stats = url_scan(line)

    else:
        url_1 = http_add(line)
        url_2 = https_add(line)

        stats = url_scan(url_1)
        stats2 = url_scan(url_2)

        stats = stats or stats2
        print(stats)
    
    if stats:
        output_file.write(line)
        output_file.write('\n')
        print(colored(line, 'yellow'))
  
    else:
        dump_file.write(line)
        dump_file.write('\n')
        print(colored(line,'red'))