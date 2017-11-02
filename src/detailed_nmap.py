#!/usr/bin/env python

import os
import socket
import subprocess
import multiprocessing
from multiprocessing import Process,Queue
from multiprocessing import Pool
from multiprocessing.dummy import Pool as ThreadPool

from src.core import *

def scan_func(port, service, scripts, scandir, ipaddr):
    global NMAP_SCAN
    NMAP_SCAN = 'nmap -Pn -n --open -T4 -p {} --script="{}" -oN {}/nmap_{}.nmap {}'.format(port, 
        scripts, scandir, service, ipaddr)
    return NMAP_SCAN


def id_services(scandir):
    print("{0}[+]{1} Checking for Detailed Nmap Scan Services".format(bcolors.GREEN, bcolors.ENDC))
    # Variables
    global service_dict
    global script_dict
    service_dict = {}
    script_dict = {
        'ssh': SSH_SCRIPTS, 
        'ftp': FTP_SCRIPTS, 
        'domain': DNS_SCRIPTS, 
        'http': HTTP_SCRIPTS,
        'microsoft-ds': WIN_SCRIPTS,
        'rpcbind': RPC_SCRIPTS,
        'ms-wbt-server': RDP_SCRIPTS,
        'snmp': SNMP_SCRIPTS,
        'ms-sql': MSSQL_SCRIPTS,
        'oracle': ORACLE_SCRIPTS,
        'mysql': MYSQL_SCRIPTS,
        'mongod': MONGODB_SCRIPTS,
        }
    
    # Generate basic mapping of ports to services
    with open('{0}/basic_nmap.nmap'.format(scandir), 'r') as f:
        basic_results = [line for line in f.readlines() if 'open' in line]
    for result in basic_results:
        ports = []
        if ('tcp' in result) and ('open' in result) and not ('Discovered' in result):
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
        print("{0}[+]{1} Running Detailed Nmap Scans on {2} Services\n".format(bcolors.GREEN, bcolors.ENDC, str(len(service_dict))))


def nmap_scan((port, scripts, scandir, service, ipaddr, quiet)):
    NMAP_SCAN = 'nmap -Pn -n --open -T4 -p {} --script="{}" -oN {}/nmap_{}.nmap {}'.format(port,
            scripts, scandir, service, ipaddr)
    if quiet is not True:
        print("{0}[+]{1} {2}\n".format(bcolors.GREEN, bcolors.ENDC, NMAP_SCAN))
    else: pass
    with open(os.devnull, 'w') as FNULL:
        try:
            subprocess.call(NMAP_SCAN, stdout=FNULL, shell=True)
            print("{0}[+]{1} Finished Scanning for {2}".format(bcolors.GREEN, bcolors.ENDC, service))
        except subprocess.CalledProcessError as e:
            raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))


def detailed_nmap(ipaddr, scandir, quiet):
    id_services(scandir)
    jobs = []
    for service in service_dict:
        for script in script_dict:
            if script in service:
                scripts = script_dict[script]
                for port in service_dict[service]:
                    port = port.split('/')[0]
                    jobs.append((port, scripts, scandir, service, ipaddr, quiet))

    # Establish multithreading
    #jobs = []
    #p = multiprocessing.Process(target=nmap_scan, args=(ipaddr, scandir, service_dict, quiet))
    #jobs.append(p)
    #p.start()
    pool = ThreadPool(4)
    pool.map(nmap_scan, jobs)
