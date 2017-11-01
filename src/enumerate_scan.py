#!/usr/bin/env python

import os
import socket
import subprocess
import multiprocessing
from multiprocessing import Process,Queue

from src.core import *

# Verify which enumerate tools are installed
installed_tools = []
for tool in enum_software:
    print tool
    try:
        subprocess.check_output("which {0}".format(tool), shell=True).strip()
        installed_tools.append(tool)
        pass
    except Exception:
        print("{0}[!]{1} Unable to find {2}. Skipping those checks"
            .format(bcolors.RED, bcolors.ENDC, tool))
        pass
        



def id_services(scandir):
    print("{0}[+]{1} Checking for Enumeration Scans".format(bcolors.GREEN, bcolors.ENDC))
    # Variables
    global service_dict
    global script_dict
    service_dict = {}
    
    # Generate basic mapping of ports to services
    with open('{0}/basic_nmap.nmap'.format(scandir), 'r') as f:
        basic_results = [line for line in f.readlines() if 'open' in line]
    for result in basic_results:
        ports = []
        if ('tcp' in result) or ('udp' in result) and not ('Discovered' in result):
            service = result.split()[2]
            if service == 'ssl/http':
                service = 'https'
            else: pass
            port = result.split()[0]
            
            if service in service_dict:
                ports = service_dict[service]
                
            ports.append(port)
            service_dict[service] = ports
            
    if len(service_dict) > 0:
        print("{0}[+]{1} Running Detailed Nmap Scans on {2} Services".format(bcolors.GREEN, bcolors.ENDC, str(len(service_dict))))
