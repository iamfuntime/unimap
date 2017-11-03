#!/usr/bin/env python

import os
import re
import sys
import time
import socket
import subprocess
import multiprocessing
from multiprocessing import Process,Queue

from src.core import *

def unicornscan(ipaddr, scandir, interface, speed, ports, protocol, quiet):
    if (ports == 'd'):
        ports = 'p'
    else: pass

    print("{0}[+]{1} Starting Unicornscan for {2}".format(bcolors.GREEN, bcolors.ENDC, ipaddr))
    with open(os.devnull, 'w') as FNULL:
        if (protocol == 'tcp'):
            proto = 'T'
            if quiet is not True:
                print("{0}[+]{1} unicornscan -i {2} -m{3} -r {4} -l {5}/unicornscan.txt {7}:{6}_ports"
                    .format(bcolors.GREEN, bcolors.ENDC, interface, proto, speed, scandir, protocol, ipaddr))
            else: pass
            UNICORNSCAN = "unicornscan -i {0} -m{1} -r {2} -l {3}/unicornscan.txt {4}:{5}".format( 
                interface, proto, speed, scandir, ipaddr, ports)
            subprocess.call(UNICORNSCAN, stdout=FNULL, shell=True)
        elif (protocol == 'udp'):
            proto = 'U'
            if quiet is not True:
                print("{0}[+]{1} unicornscan -i {2} -m{3} -r {4} -l {5}/unicornscan.txt {7}:{6}_ports"
                    .format(bcolors.GREEN, bcolors.ENDC, interface, proto, speed, scandir, protocol, ipaddr))
            else: pass
            UNICORNSCAN = "unicornscan -i {0} -m{1} -r {2} -l {3}/unicornscan.txt {4}:{5}".format( 
                interface, proto, speed, scandir, ipaddr, ports)
            subprocess.call(UNICORNSCAN, stdout=FNULL, shell=True)
        elif (protocol == 'all'):
            proto = 'T'
            if quiet is not True:
                print("{0}[+]{1} unicornscan -i {2} -m{3} -r {4} -l {5}/unicornscan.txt {7}:{6}_ports"
                    .format(bcolors.GREEN, bcolors.ENDC, interface, proto, speed, scandir, protocol, ipaddr))
            else: pass
            UNICORNSCAN = "unicornscan -i {0} -m{1} -r {2} -l {3}/unicornscan.txt {4}:{5}".format( 
                interface, proto, speed, scandir, ipaddr, ports)
            subprocess.call(UNICORNSCAN, stdout=FNULL, shell=True)
            
            proto = 'U'
            if quiet is not True:
                print("{0}[+]{1} unicornscan -i {2} -m{3} -r {4} -l {5}/unicornscan.txt {7}:{6}_ports"
                    .format(bcolors.GREEN, bcolors.ENDC, interface, proto, speed, scandir, protocol, ipaddr))
            else: pass
            UNICORNSCAN = "unicornscan -i {0} -m{1} -r {2} -l {3}/unicornscan.txt {4}:{5}".format( 
                interface, proto, speed, scandir, ipaddr, ports)
            subprocess.call(UNICORNSCAN, stdout=FNULL, shell=True)
    
        
        
def basic_nmap(ipaddr, scandir, nmap_options, protocol, quiet):
    with open('{0}/unicornscan.txt'.format(scandir), 'r') as f:
        results = f.readlines()
        if (protocol == 'tcp'):
            ports = ','.join(i.split('[')[1].split(']')[0].replace(' ', '') for i in results)
        elif (protocol == 'udp'):
            ports = 'U:' + ',U:'.join(i.split('[')[1].split(']')[0].replace(' ', '') for i in results)
        elif (protocol == 'all'):
            tcp_ports = ','.join(i.split('[')[1].split(']')[0].replace(' ', '') for i in results if i.startswith('TCP'))
            udp_ports = re.sub('^', 'U:', ','.join(i.split('[')[1].split(']')[0].replace(' ', '') for i in results 
                if i.startswith('UDP')))
            udp_ports = re.sub(',', ',U:', udp_ports)
            ports = tcp_ports + ',' + udp_ports
        else: pass
    
    BASIC_NMAP = "nmap {0} -p{1} -oA {2}/basic_nmap {3}".format(nmap_options, ports, scandir, ipaddr)
    print("{0}[+]{1} Starting Basic Nmap Scan for {2}".format(bcolors.GREEN, bcolors.ENDC, ipaddr))
    if quiet is not True:
        print("{0}[+]{1} nmap {2} -p {3} -oA {4}/basic_nmap {5}"
            .format(bcolors.GREEN, bcolors.ENDC, nmap_options, ports, scandir, ipaddr))
    else: pass
    with open(os.devnull, 'w') as FNULL:
        subprocess.call(BASIC_NMAP, stdout=FNULL, shell=True)
        
        
def quick_scan(ipaddr, scandir, protocol, interface, speed, nmap_options, ports, quiet):
    ipaddr = ipaddr.strip()
    
    try:
        unicornscan(ipaddr, scandir, interface, speed, ports, protocol, quiet)
        basic_nmap(ipaddr, scandir, nmap_options, protocol, quiet)
    except Exception, e:
        print("{0}[!]{1} Unknown Error: {2}".format(bcolors.RED, bcolors.ENDC, e))
        sys.exit(0)
