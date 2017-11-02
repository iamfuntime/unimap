#!/usr/bin/env python

import os
import sys
import subprocess
import socket
from argparse import ArgumentParser

import src
from src.core import *
from src.quick_scan import quick_scan
from src.file_helper import check_dirs
from src.detailed_nmap import detailed_nmap
from src.enumerate_scan import enumerate_scan
from src.crack_scan import brute_force

# Running as root?
if os.geteuid() != 0:
    print("{0}[!]{1} This program needs to be run as root!".format(bcolors.RED, bcolors.ENDC))
    sys.exit(0)
    
# Dependencies
for tool in standard_software:
    try:
        subprocess.check_output("which {0}".format(tool), shell=True).strip()
        pass
    except Exception:
        print("{0}[!]{1} Unable to find {2}. Install it and ensure it is in your PATH"
            .format(bcolors.RED, bcolors.ENDC, tool))
        sys.exit(0)
        

def main():
    parser = ArgumentParser()
    parser.add_argument("-t",
                        dest="target", 
                        required=True, 
                        type=str, 
                        help="Set a target IP address. Ex. 10.10.10.10" )
    parser.add_argument("-o",   
                        dest="output_dir", 
                        default='/tmp/unimap',
                        required=False, 
                        type=str, 
                        help="Set the output directory. Defaults to /tmp/unimap")
    parser.add_argument("-p",   
                        dest="protocol", 
                        default='tcp',
                        choices=['tcp', 'udp', 'all'],
                        required=False, 
                        type=str, 
                        help="Select the protocol to use. Ex. tcp/udp/all")
    parser.add_argument("-i",   
                        dest="interface", 
                        default='eth0',
                        required=False, 
                        type=str, 
                        help="Select the interface. Ex. eth0")
    parser.add_argument("-s",   
                        dest="speed", 
                        default='1000',
                        required=False, 
                        type=str, 
                        help="Set the Packets Per Second for Unicornscan. Ex. 1000")
    parser.add_argument("-n",   
                        dest="nmap_options", 
                        default='-PN -A -T4 -sS -sC',
                        required=False, 
                        type=str, 
                        help="Set NMAP options. Include in double quotes")
    parser.add_argument("-e",
                        dest="enumerate",
                        default=False,
                        required=False,
                        action="store_true",
                        help="Run additional enumeration programs? e.g. wpscan, nikto, dirb, etc")
    parser.add_argument("-c",
                        dest="crack",
                        default=False,
                        required=False,
                        action="store_true",
                        help="Run Brute Force password cracking against known services")
    parser.add_argument("--ports",
                        dest="ports",
                        default="d",
                        choices=['d', 'a'],
                        required=False,
                        type=str,
                        help="Default or All  ports.")
    parser.add_argument("--quick",
                        dest="quick",
                        default=False,
                        action="store_true",
                        required=False,
                        help="Run Unicornscan and basic Nmap scan")
    parser.add_argument("--quiet",
                        dest="quiet",
                        default=False,
                        action="store_true",
                        required=False,
                        help="Suppress banner and headers to limit results")
    arguments = parser.parse_args()

    if arguments.quick is True and arguments.enumerate is True:
        print("{0}[!]{1} Error! Unable to do a quick scan, and a deep enumeration scan"
            .format(bcolors.RED, bcolors.ENDC))
        sys.exit(0)
        
    # Verify Target IP Address
    try:
        socket.inet_aton(arguments.target)
    except socket.error:
        print((bcolors.RED) + ("[!]") + (bcolors.ENDC) + (" Invalid IP Address"))
        sys.exit(0)

    # Cleanup CLI Options
    if arguments.target.endswith('/' or '\\'):
        arguments.target = arguments.target[:-1]
    if arguments.output_dir.endswith('/' or '\\'):
        arguments.output_dir = arguments.output_dir[:-1]
    
    # Print Configuration    
    if arguments.quiet is not True:
        print (banner)
        print("{0}[>] {1}Target: " + arguments.target).format(bcolors.BLUE, bcolors.ENDC)
        print("{0}[>] {1}Output Directory: " + arguments.output_dir).format(bcolors.BLUE, bcolors.ENDC)
        print("{0}[>] {1}Protocol: " + arguments.protocol).format(bcolors.BLUE, bcolors.ENDC)
        print("{0}[>] {1}Interface: " + arguments.interface).format(bcolors.BLUE, bcolors.ENDC)
        print("{0}[>] {1}Unicornscan Speed: " + arguments.speed).format(bcolors.BLUE, bcolors.ENDC)
        print("{0}[>] {1}NMAP Options: " + str(arguments.nmap_options)).format(bcolors.BLUE, bcolors.ENDC)
        print("{0}[>] {1}Enumerate: " + str(arguments.enumerate)).format(bcolors.BLUE, bcolors.ENDC)
        print("{0}[>] {1}Quick Scan?: " + str(arguments.quick)).format(bcolors.BLUE, bcolors.ENDC)
        if arguments.ports == 'D':
            print("{0}[>] {1}Port Selection: Default\n").format(bcolors.BLUE, bcolors.ENDC)
        elif arguments.ports == 'A':
            print("{0}[>] {1}Port Selection: All\n").format(bcolors.BLUE, bcolors.ENDC)
      
    # Rename Variables
    hostdir = arguments.output_dir + "/" + arguments.target
    scandir = hostdir + "/scans"
    ipaddr = arguments.target
    protocol = arguments.protocol
    interface = arguments.interface
    speed = arguments.speed
    nmap_options = arguments.nmap_options
    enumerate = arguments.enumerate
    crack = arguments.crack
    ports = arguments.ports
    quick = arguments.quick
    quiet = arguments.quiet
    
    # Run Functions
    try:
        check_dirs(arguments.output_dir, hostdir, scandir, arguments.quiet)
        quick_scan(ipaddr, scandir, protocol, interface, speed, nmap_options, ports, quiet)

        if quick is not True:
            detailed_nmap(ipaddr, scandir, quiet)
        else: pass
        
        if enumerate is True:
            enumerate_scan(ipaddr, scandir, quiet)
        else: pass
        
        if crack is True:
            brute_force(ipaddr, scandir, quiet)
        else: pass
        
        print("\n{0}[>]{1} Scans Complete! Results are located in {2}".format(bcolors.BLUE, bcolors.ENDC, scandir))
        sys.exit(0)

    except KeyboardInterrupt:
        print("{0}[!]{1} Scan Cancelled!".format(bcolors.RED, bcolors.ENDC))
        sys.exit(0)
    except Exception, e:
        print("{0}[!]{1} Unknown Error: {2}".format(bcolors.RED, bcolors.ENDC, e))
        sys.exit(0)

if __name__ == '__main__':
    main()
