#!/usr/bin/env python

import os
import socket
import subprocess
import multiprocessing
from multiprocessing import Process,Queue
from multiprocessing import Pool
from multiprocessing.dummy import Pool as ThreadPool

from src.core import *

# Verify which enumeration tools are installed
installed_tools = []
for tool in enum_software:
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
            port = result.split()[0]
            
            if service in service_dict:
                ports = service_dict[service]
                
            ports.append(port)
            service_dict[service] = ports
            
    if len(service_dict) > 0:
        print("{0}[+]{1} Running Detailed Nmap Scans on {2} Services".format(bcolors.GREEN, bcolors.ENDC, str(len(service_dict))))
        
        
def tool_scans(ipaddr, scandir, service, port, quiet):
    if ('http' == service) or ('ssl/http' == service) or ('http' in service) or ('https' in service):
        if ('nikto' in installed_tools):
            NIKTO_SCAN = 'nikto -h {0} -p {1} | tee {2}/nikto_{1}.txt'.format(ipaddr, port, scandir, port)
            if quiet is not True:
                print("{0}[+]{1} Running Nikto Scan on {2}:{3}".format(bcolors.GREEN, bcolors.ENDC, ipaddr, port))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess.call(NIKTO_SCAN, stdout=FNULL, shell=True)
                except subprocess.CalledProcessError as e:
                    raise RuntimeError("command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output))
                except KeyboardInterrupt:
                    print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
        else: pass

        if ('dirb' in installed_tools):
            DIRB_SCAN = 'dirb http://{0}:{1}/ -o {2}/dirb_{1}.txt'.format(ipaddr, port, scandir)
            if quiet is not True:
                print("{0}[+]{1} Running Dirb Scan on {2}:{3}".format(bcolors.GREEN, bcolors.ENDC, ipaddr, port))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess.call(DIRB_SCAN, stdout=FNULL, shell=True)
                except subprocess.CalledProcessError as e:
                    raise RuntimeError("command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output))
                except KeyboardInterrupt:
                    print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
        else: pass
        
        if ('curl' in installed_tools):
            CURL_SCAN = 'curl -i {0}'.format(ipaddr)
            if quiet is not True:
                print("{0}[+]{1} Grabbing Web Headers on {2}:{3}".format(bcolors.GREEN, bcolors.ENDC, ipaddr, port))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess.call(CURL_SCAN, stdout=FNULL, shell=True)
                except subprocess.CalledProcessError as e:
                    raise RuntimeError("command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output))
                except KeyboardInterrupt:
                    print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
        else: pass
        
    elif ('microsoft-ds' == service) or ('microsoft-ds' in service):
        if ('enum4linux' in installed_tools):
            ENUM_SCAN = 'enum4linux {0} | tee {1}/enum4linux.txt'.format(ipaddr, scandir)
            if quiet is not True:
                print("{0}[+]{1} Running Enum4Linux on {0}".format(bcolors.GREEN, bcolors.ENDC, ipaddr))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess,call(ENUM_SCAN, stdout=FNULL, shell=True)
                except subprocess.CalledProcessError as e:
                    raise RuntimeError("command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output))
                except KeyboardInterrupt:
                    print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
        else: pass
                    
    elif ('telnet' == service) or ('telnet' in service):
        if ('nc' in installed_tools):
            BANNER_GRAB = 'nc -nv {0} {1} | tee {2}/telnet_banner.txt'.format(ipaddr, port, scandir)
            if quiet is not True:
                print("{0}[+]{1} Grabbing Telnet Banner".format(bcolors.GREEN, bcolors.ENDC))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess.call(BANNER_GRAB, stdout=FNULL, shell=True)
                except subprocess.CalledProcessError as e:
                    raise RuntimeError("command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output))
                except KeyboardInterrupt:
                    print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
        else: pass
                    
    elif ('smtp' == service) or ('smtp' in service):
        if ('smtp-user-enum' in installed_tools):
            SMTP_SCAN = 'smtp-user-enum -M VRFY -U usernames/top_shortlist.txt -t {0} -p {1}'.format(ipaddr, port)
            if quiet is not True:
                print("{0}[+]{1} Enumerating SMTP Users".format(bcolors.GREEN, bcolors.ENDC))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess.call(SMTP_SCAN, stdout=FNULL, shell=True)
                except subprocess.CalledProcessError as e:
                    raise RuntimeError("command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output))
                except KeyboardInterrupt:
                    print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
        else: pass
                        
    elif ('snmp' == service) or ('snmp' in service):
        if ('onesixtyone' in installed_tools):
            SNMP_SCAN = 'onesixtyone {0}'.format(ipaddr)
            if quiet is not True:
                print("{0}[+]{1} Enumerating SNMP with OneSixtyOne".format(bcolors.GREEN, bcolors.ENDC))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess.call(SNMP_SCAN, stdout=FNULL, shell=True)
                except subprocess.CalledProcessError as e:
                    raise RuntimeError("command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output))
                except KeyboardInterrupt:
                    print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
        else: pass
                    
        if ('snmpwalk' in installed_tools):
            SNMP_SCAN = 'snmpwalk -c public -v1 {0} | tee {1}/snmpwalk.txt'.format(ipaddr, scandir)
            if quiet is not True:
                print("{0}[+]{1} Enumerating SNMP with SNMPWalk".format(bcolors.GREEN, bcolors.ENDC))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess.call(SNMP_SCAN, stdout=FNULL, shell=True)
                except subprocess.CalledProcessError as e:
                    raise RuntimeError("command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output))
                except KeyboardInterrupt:
                    print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
        else: pass
    elif ('ssh' == service) or ('ssh' in service):
        if ('hydra' in installed_tools):
            SSH_SCAN = 'hydra -f -V -t 1 -l root -P /usr/share/wordlists/rockyou.txt -s {0} {1} ssh'.format(
                port, ipaddr)
            if quiet is not True:
                print("{0}[+]{1} Running Hydra Against SSH".format(bcolors.GREEN, bcolors.ENDC))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess.call(SSH_SCAN, stdout=FNULL, shell=True)
                except subprocess.CalledProcessError as e:
                    raise RuntimeError("command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output))
                except KeyboardInterrupt:
                    print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
        else: pass
        
        if ('medusa' in installed_tools):
            SSH_SCAN = 'medus -u root -p /usr/share/wordlists/rockyou.txt -e ns -h {0} - {1} -M ssh'.format(
                ipaddr, port)
            if quiet is not True:
                print("{0}[+]{1} Running Medusa Against SSH".format(bcolors.GREEN, bcolors.ENDC))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess.call(SSH_SCAN, stdout=FNULL, shell=True)
                except subprocess.CalledProcessError as e:
                    raise RuntimeError("command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output))
                except KeyboardInterrupt:
                    print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
        else: pass
            
            
def enumerate_scan(ipaddr, scandir, quiet):
    id_services(scandir)
    jobs = []
    for service in service_dict:
        for ports in service_dict[service]:
            port = port.split('/')[0]
            jobs.append((ipaddr, scandir, service, port, quiet))
            
    pool = ThreadPool(4)
    pool.map(tool_scans, jobs)
        