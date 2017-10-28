#!/usr/bin/env python

import os
import time
import socket
import subprocess
import multiprocessing
from multiprocessing import Process,Queue

from src.core import *
from src.file_helper import check_dirs

def masscan(ipaddr, scandir, interface, speed, ports, protocol, quiet):
    # Configure Ports Based on Protocol and Port Selection [D/A]
    if protocol == 'tcp':
        if ports == 'D':
            ports = tcp_ports_100
        elif ports == 'A':
            ports = tcp_ports_1000
    elif protocol == 'udp':
        if ports == 'D':
            ports = udp_ports_100
        elif ports == 'A':
            ports = udp_ports_1000
    elif protocol == 'all':
        if ports == 'D':
            ports = tcp_ports_100 + "," + udp_ports_100
        elif ports == 'A':
            ports = tcp_ports_1000 + "," + udp_ports_1000

    MASSCAN = "masscan -p {0} --max-rate {1} -e {2} --wait 5 --interactive -oL {3}/masscan-{5}.txt {4}".format(
        ports, speed, interface, scandir, ipaddr, protocol)
    print("{0}[+]{1} Starting Masscan for {2}".format(bcolors.GREEN, bcolors.ENDC, ipaddr))
    if quiet is True:
        with open(os.devnull, 'w') as FNULL:
            mass_results = subprocess.check_call(MASSCAN, stdout=FNULL, stderr=subprocess.STDOUT, shell=True)
    else:
        print("{0}[+]{1} masscan -p {2}_ports --max-rate {3} -e {4} --wait 5 --interactive {5} -oL {6}/masscan-{2}.txt"
            .format(bcolors.GREEN, bcolors.ENDC, protocol, speed, interface, 
            ipaddr, scandir))
        mass_results = subprocess.check_call(MASSCAN, shell=True)
        
        
def basic_nmap(ipaddr, scandir, nmap_options, protocol, quiet):
    with open('{0}/masscan-{1}.txt'.format(scandir, protocol), 'r') as f:
        results = f.readlines()[1:-1]
        ports = ','.join(i.split()[2] for i in results)
    
    NMAPSCAN = "nmap {0} -p{1} -oA {2}/basic_nmap {3}".format(nmap_options, ports, scandir, ipaddr)
    print("{0}[+]{1} Starting Nmap Scan for {2}".format(bcolors.GREEN, bcolors.ENDC, ipaddr))
    if quiet is True:
        with open(os.devnull, 'w') as FNULL:
            nmap_results = subprocess.check_call(NMAPSCAN, stdout=FNULL, stderr=subprocess.STDOUT, shell=True)
    else:
        print("{0}[+]{1} nmap {2} -p {3} -oA {4}/basic_nmap {5}"
            .format(bcolors.GREEN, bcolors.ENDC, nmap_options, ports, scandir, ipaddr))
        nmap_results = subprocess.check_call(NMAPSCAN, shell=True)
    

def scanner(ipaddr, 
            output_dir, 
            protocol, 
            interface, 
            speed, 
            nmap_options, 
            enumerate,
            ports, 
            quick,
            quiet):
    
    # Variables
    ipaddr = ipaddr.strip()
    hostdir = output_dir + "/" + ipaddr
    scandir = hostdir + "/scans"
    
    try:
        check_dirs(output_dir, hostdir, scandir, quiet)
        masscan(ipaddr, scandir, interface, speed, ports, protocol, quiet)
        basic_nmap(ipaddr, scandir, nmap_options, protocol, quiet)
    except KeyboardInterrupt:
        print("\n\n{0}[!]{1} Scan Cancelled!".format(bcolors.RED, bcolors.ENDC))