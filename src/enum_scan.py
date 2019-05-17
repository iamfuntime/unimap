#!/usr/bin/env python

import os
import socket
import subprocess
import multiprocessing
from multiprocessing import Process,Queue
from multiprocessing import Pool
from multiprocessing.dummy import Pool as ThreadPool

from src.core import *

        
def id_services(scandir):
    print("\n{0}[>]{1} Checking for Enumeration Scans\n".format(bcolors.BLUE, bcolors.ENDC))

    # Variables
    global service_dict
    global installed_tools
    service_dict = {}
    
    # Verify which enumeration tools are installed
    installed_tools = []
    for tool in enum_software:
        try:
            subprocess.check_output("which {0}".format(tool), shell=True).strip()
            installed_tools.append(tool)
            pass
        except Exception:
            print("{0}[!]{1} Unable to find {2}. Skipping..."
                .format(bcolors.RED, bcolors.ENDC, tool))
            pass

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
        print("\n{0}[+]{1} Running Detailed Enumeration Scans on {2} Services\n".format(bcolors.GREEN, bcolors.ENDC, str(len(service_dict))))
        
        
def tool_scans((ipaddr, scandir, service, port, quiet)):
    if ('http' == service) or ('ssl/http' == service) or ('http' in service) or ('https' in service):
        if ('nikto' in installed_tools):
            NIKTO_SCAN = 'nikto -h {0} -p {1} | tee {2}/nikto_{1}.txt'.format(ipaddr, port, scandir, port)
            if quiet is not True:
                print("{0}[*]{1} Running Nikto Scan on {2}:{3}".format(bcolors.YELLOW, bcolors.ENDC, ipaddr, port))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess.call(NIKTO_SCAN, stdout=FNULL, shell=True)
                    print("{0}[+]{1} Finished running Nikto Scan".format(bcolors.GREEN, bcolors.ENDC))
                except subprocess.CalledProcessError as e:
                    raise RuntimeError("command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output))
                except KeyboardInterrupt:
                    print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
        else: pass

        if ('dirb' in installed_tools):
            DIRB_SCAN = 'dirb http://{0}:{1}/ -o {2}/dirb_{1}.txt'.format(ipaddr, port, scandir)
            if quiet is not True:
                print("{0}[*]{1} Running Dirb Scan on {2}:{3}".format(bcolors.YELLOW, bcolors.ENDC, ipaddr, port))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess.call(DIRB_SCAN, stdout=FNULL, shell=True)
                    print("{0}[+]{1} Finished running Dirb Scan".format(bcolors.GREEN, bcolors.ENDC))
                except subprocess.CalledProcessError as e:
                    raise RuntimeError("command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output))
                except KeyboardInterrupt:
                    print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
        else: pass
        
        if ('curl' in installed_tools):
            CURL_SCAN = 'curl -i {0} | tee {1}/webheaders.txt'.format(ipaddr, scandir)
            HTML2TEXT = 'curl -i {0} | html2text | tee {1}/html2text.txt'.format(ipaddr, scandir)
            if quiet is not True:
                print("{0}[*]{1} Grabbing Web Headers on {2}:{3}".format(bcolors.YELLOW, bcolors.ENDC, ipaddr, port))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess.call(CURL_SCAN, stdout=FNULL, shell=True)
                    subprocess.call(HTML2TEXT, stdout=FNULL, shell=True)
                    print("{0}[+]{1} Finished running curl".format(bcolors.GREEN, bcolors.ENDC))
                except subprocess.CalledProcessError as e:
                    raise RuntimeError("command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output))
                except KeyboardInterrupt:
                    print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
        else: pass

        if ('gobuster' in installed_tools):
            wordlist = '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
            cgi_wordlist = '/usr/share/wordlists/dirb/vulns/cgis.txt'
            try:
                os.stat(wordlist)
                os.stat(cgi_wordlist)
                GOBUSTER_COMMON = "gobuster -w {0} -u http://{1}:{2} -s '200,204,301,302,307,403,500' -e > {3}/gobuster_common.txt -t 50".format(wordlist, ipaddr, port, scandir)
                GOBUSTER_CGIS = "gobuster -w {0} -u http://{1}:{2} -s '200,204,301,302,307,403,500' -e > {3}/gobuster_cgis.txt -t 50".format(cgi_wordlist, ipaddr, port, scandir)
                if quiet is not True:
                    print("{0}[*]{1} Running GoBuster on {1}".format(bcolors.YELLOW, bcolors.ENDC, ipaddr))
                else: pass
                with open(os.devnull, 'w') as FNULL:
                    try:
                        subprocess.call(GOBUSTER_COMMON, stdout=FNULL, shell=True)
                        subprocess.call(GOBUSTER_CGIS, stdout=FNULL, shell=True)
                        print("{0}[+]{1} Finished running GoBuster".format(bcolors.GREEN, bcolors.ENDC))
                    except subprocess.CalledProcessError as e:
                        raise RuntimeError("command '{}' return with error (code {}): {}".format(
                            e.cmd, e.returncode, e.output))
                    except KeyboardInterrupt:
                        print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
            except: pass
        else: pass
        
    elif ('microsoft-ds' == service) or ('microsoft-ds' in service) or ('netbios' in service):
        if ('enum4linux' in installed_tools):
            ENUM_SCAN = 'enum4linux {0} | tee {1}/enum4linux.txt'.format(ipaddr, scandir)
            if quiet is not True:
                print("{0}[*]{1} Running Enum4Linux on {0}".format(bcolors.YELLOW, bcolors.ENDC, ipaddr))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess,call(ENUM_SCAN, stdout=FNULL, shell=True)
                    print("{0}[+]{1} Finished running Enum4Linux Scan".format(bcolors.GREEN, bcolors.ENDC))
                except subprocess.CalledProcessError as e:
                    raise RuntimeError("command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output))
                except KeyboardInterrupt:
                    print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
        else: pass
        
        if ('nbtscan' in installed_tools):
            ENUM_SCAN = 'nbtscan {0} | tee {1}/nbtscan.txt'.format(ipaddr, scandir)
            if quiet is not True:
                print("{0}[*]{1} Running NBTScan on {0}".format(bcolors.YELLOW, bcolors.ENDC, ipaddr))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess,call(ENUM_SCAN, stdout=FNULL, shell=True)
                    print("{0}[+]{1} Finished running NBTScan Scan".format(bcolors.GREEN, bcolors.ENDC))
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
                print("{0}[*]{1} Grabbing Telnet Banner".format(bcolors.YELLOW, bcolors.ENDC))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess.call(BANNER_GRAB, stdout=FNULL, shell=True)
                    print("{0}[+]{1} Finished running banner grab".format(bcolors.GREEN, bcolors.ENDC))
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
                print("{0}[*]{1} Enumerating SMTP Users".format(bcolors.YELLOW, bcolors.ENDC))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess.call(SMTP_SCAN, stdout=FNULL, shell=True)
                    print("{0}[+]{1} Finished enumerating SMTP Users".format(bcolors.GREEN, bcolors.ENDC))
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
                print("{0}[*]{1} Enumerating SNMP with OneSixtyOne".format(bcolors.YELLOW, bcolors.ENDC))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess.call(SNMP_SCAN, stdout=FNULL, shell=True)
                    print("{0}[+]{1} Finished Running SNMP with OneSixtyOne".format(bcolors.GREEN, bcolors.ENDC))
                except subprocess.CalledProcessError as e:
                    raise RuntimeError("command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output))
                except KeyboardInterrupt:
                    print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
        else: pass
                    
        if ('snmpwalk' in installed_tools):
            SNMP_SCAN = 'snmpwalk -c public -v1 {0} | tee {1}/snmpwalk.txt'.format(ipaddr, scandir)
            if quiet is not True:
                print("{0}[*]{1} Enumerating SNMP with SNMPWalk".format(bcolors.YELLOW, bcolors.ENDC))
            else: pass
            with open(os.devnull, 'w') as FNULL:
                try:
                    subprocess.call(SNMP_SCAN, stdout=FNULL, shell=True)
                    print("{0}[+]{1} Finished Running SNMP with SNMPWalk".format(bcolors.GREEN, bcolors.ENDC))
                except subprocess.CalledProcessError as e:
                    raise RuntimeError("command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output))
                except KeyboardInterrupt:
                    print("{0}[!]{1} Scan Cancelled! Moving On!".format(bcolors.RED, bcolors.ENDC))
        else: pass
            
            
def enum_scan(ipaddr, scandir, quiet):
    id_services(scandir)

    jobs = []
    for service in service_dict:
        for port in service_dict[service]:
            port = port.split('/')[0]
            jobs.append((ipaddr, scandir, service, port, quiet))
            
    pool = ThreadPool(4)
    pool.map(tool_scans, jobs)
        
