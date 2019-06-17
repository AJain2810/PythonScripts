import argparse
from socket import *
from threading import *
from termcolor import colored

console_print_lock = Semaphore(value=1)
#Semaphore so that multiple threads dont print to the screen at the same time, intermixing the rsults

def scan_port(target_host, target_port):
    try:
        socket = socket(AF_INET, SOCK_STREAM)
        #IPv4 based TCP socket
        socket.connect((target_host, target_port))
        #Attempt a connection to the specified host and the port
        console_print_lock.acquire()
        
        print(colored(target_port+': open...', 'green'))

        #Attempt to send osmthing to the port to get the information returnes as the header
        socket.send('Hello World!')
        res = socket.recv(2000)
        if res is not None:
            print('Result is: '+ res)
    except:
        print(colored(target_port+' is closed...','red'))
    finally:
        console_print_lock.release()
        socket.close()


def driver_code(host_address):
    #get corresponding IP adress
    try:
        target_ip_name = gethostbyname(host_address)
    except:
        print(colored('Error in host name resolution...',red))
        print(colored('Unknown Host','maroon'))
    
    print(colored('Scan results for: ' + target_ip_name,'cyan'))
    port_scan_list = list(range(1024))
    port_scan_list.append(8080)
    port_scan_list.append(8000)
    for port in port_scan_list:
        t = Thread()
        t = Thread(target=scan_port, args=(host_address, int(port)))
        t.start()