#!/usr/bin/env python

import os
import time
import socket
import subprocess
import multiprocessing
from multiprocessing import Process,Queue

from src.core import *

def detailed_nmap(ipaddr, scandir, nmap_options, quiet):
    print("{0}[*][*]{1} IMPORT SUCCESSFUL!!!".format(bcolors.GREEN, bcolors.ENDC))
    service_dict = {}
    
    port = ''
    scripts = ''
    service = ''
    NMAP_SCAN = 'nmap -Pn -n --open -T4 -p {} --script={} -oN {}/detailed_{}.nmap {}'.format(port, 
        scripts, scandir, service, ipaddr)
    
    # Generate basic mapping of ports to services
    with open('{0}/basic_nmap.nmap'.format(scandir), 'r') as f:
        basic_results = [line for line in f.readlines() if 'open' in line]
    for result in basic_results:
        ports = []
        if ('tcp' in result) and ('open' in result) and not ('Discovered' in result):
            service = result.split()[2]
            port = result.split()[0]
            
            if service in service_dict:
                ports = service_dict[service]
                
            ports.append(port)
            service_dict[service] = ports
            
    for service in service_dict:
        if ('ssh' in service):
            scripts = SSH_SCRIPTS
            print(scripts)
            print(service)
            for port in service_dict[service]:
                port = port.split('/')[0]
                NMAP_SCAN = 'nmap -Pn -n --open -T4 -p {} --script={} -oN {}/detailed_{}.nmap {}'.format(port,
                    scripts, scandir, service, ipaddr)
                print(port)
                print(NMAP_SCAN)
                if quiet is True:
                    with open(os.devnull, 'w') as FNULL:
                        nmap_results = subprocess.check_call(NMAP_SCAN, stdout=FNULL, 
                            stderr=subprocess.STDOUT, shell=True)
                else:
                    print("{0}[+]{1} {2}".format(bcolors.GREEN, bcolors.ENDC, NMAP_SCAN))
                    #nmap_results = subprocess.check_call(NMAP_SCAN, shell=True)