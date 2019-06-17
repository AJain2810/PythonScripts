#Run Nmap scan on a website and store the result in a file named 'nmap_res.txt'

import nmap
import argparse
import socket
from termcolor import colored

def write_to_file(file_name, content):
    input_file = open(file_name,'a+')
    for i in content:
        input_file.write(str(i))
        input_file.write('\n')
     
    input_file.close()

def scanAPort(target_host):
    nmap_scanner = nmap.PortScanner()
    nmap_scanner.scan(target_host)
    target_host = socket.gethostbyname(target_host)
    res = nmap_scanner[target_host]['tcp']
    write_to_file('nmap_res.txt',res)
    #res is a dictionary containint:
    #port number as the key
    #items: port status, name of servei runing
    #name of server/ application running on that port
    #version number of that port
    #135 {'state': 'open', 'reason': 'syn-ack', 'name': 'msrpc', 'product': 'Microsoft Windows RPC', 'version': '', 'extrainfo': '', 'conf': '10', 'cpe': 'cpe:/o:microsoft:windows'}

    

def driver_code():
    print(colored('Running NMap scan to determine active ports and services running on them', 'green'))
    scanAPort('boomi.com')

driver_code()
    