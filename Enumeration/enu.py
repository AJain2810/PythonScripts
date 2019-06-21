#TODO: Scan the subdomains
#   List out the active subdomians
#   Get the host I.P. address
#   Get the nmap scan results
#   List out the open ports
#   Check for vulnerabilities on them
#   Usage:
#   python3 -d <domain_name>
#
#   Deliverables:
#   domian_name_sub_domains : list of all sub domians
#   <domain_name>_active_domains: list of active sub domains
#   NMap: open ports, services runniing on them and their name
#   NOTE: NMAP output only displayed and not saved to any file
 
import requests
import os
import re
import nmap
import argparse
from termcolor import colored
import socket
import time
import urllib

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







def subdomainScan(target_domain):
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    API_KEY=''
    if len(API_KEY==0):
        print('Virus Total API KEY missing')
        exit(0)
    params = {'apikey':API_KEY,'domain': target_domain}
    response = requests.get(url, params=params)
    resp = response.json()
    sub_domains = resp['subdomains'] 
    print(sub_domains)
    print(len(sub_domains))
    return sub_domains

#Sub domian scan complete
 
#TODO: Scan for subdomains, live domain scan, 


def write_to_file(file_name, content):
    input_file = open(file_name,'a+')
    for i in content:
        input_file.write(i)
        input_file.write('\n')
     
    input_file.close()
 
 
def read_from_file(file_name):
    to_read_file = open(file_name, 'r')
    res=list()
    for line in to_read_file.readlines():
        res.append(line)
    to_read_file.close()
    return res

def eval_res(res_list):
    lgn = len(res_list)
    active_domains=list()
    res1,res2=0,0
    for i in range(0,lgn,2):
        res1=res_list[i]
        res2=res_list[i+1]
        stats = res1 or res2
        if stats:
            active_domains.append(i)
    return active_domains

def active_domain_check(sub_domains):
    pool = ThreadPool(13)
    res = pool.map(url_scan,sub_domains)
    pool.close()
    pool.join()
    active_domains = eval_res(res)
    write_to_file(sub_domains[0]+'_subdom.txt', active_domains)
    return active_domains
# Check for active domians

# furthermore save the two lists in a file
 
#   Done: active domain scan sub domain scans, reading and saving to file
#   Outcomes: active domians ( in a file, list also ), list of subdomains ( in a file also )
#   TODO: Scan the ports for active services, find their exploits and list them out...   


def renderNmapResult(nmap_scan_res):
    print('\n\n')
    port_list=list()
    port_service_list=list()
    stri=''
    for i in range(40):
        stri = stri+'-'
    print(colored(stri,'red'))
    print(colored('Port Number:\tService_Name\tProduct_Name\tProduct_Version', 'yellow'))
    for key, value in nmap_scan_res.items():
        port_list.append(key)
        port_service_list.append(value['product'])
        print(key,'\t', value['name'],'\t',value['product'],'\t',value['version'])
    return port_list, port_service_list

    #Prints the open port
    #product: name
    #version: version info


def runNmapScan(host_address):
    scanner = nmap.PortScanner()
    scanner.scan(host_address)
    res = scanner[host_address]['tcp']

    rendered_res = renderNmapResult(res)
    return rendered_res


def driver_code(url_input):
    sub_domians=subdomainScan(url_input)
    write_to_file(url_input+'_sub_domains.txt', sub_domians)
    active_domains = active_domain_check(sub_domians)
    ip = socket.gethostbyname(url_input)
    sscan = runNmapScan(ip)

initi=time.time()

welcome_message="""
             | | ___| | | ___   \\ \\      / / _ \\ _ __| | __| |\n| |_| |/ _ \\ | |/ _ \\   \\ \\ /\\ / / | | | '__| |/ _` |\n|  _  |  __/ | | (_) |   \\ V  V /| |_| | |  | | (_| |\n|_| |_|\\___|_|_|\\___/     \\_/\\_/  \\___/|_|  |_|\\__,_
"""
print(welcome_message)

parser = argparse.ArgumentParser()
parser.add_argument('-d','--domain', help='The domain to be checked')

args = vars(parser.parse_args())
print(args)

dom = args["domain"]
if valid_url_check(dom)==True:
    print(colored("Enter URL without any http or https or any protocol mention", red))
    exit(0)
driver_code(dom)
  
fina = time.time()
print(colored('Time taken: '+str(fina-initi),'cyan'))