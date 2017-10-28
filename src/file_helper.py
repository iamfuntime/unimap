#!/usr/bin/env python

import os
from src.core import *


def check_dirs(output_dir, hostdir, scandir, quiet):
    try:
        os.stat(output_dir)
    except:
        os.mkdir(output_dir)
        if quiet is not True:
            print("{}[>]{} Creating {}".format(bcolors.BLUE, bcolors.ENDC, output_dir))
        else: pass
        
    # Host Directory
    try:
        os.stat(hostdir)
    except:
        os.mkdir(hostdir)
        if quiet is not True:
            print("{}\t[>]{} Creating {}".format(bcolors.BLUE, bcolors.ENDC, hostdir))
        else: pass
        
    # Scan Results Directory
    try:
        os.stat(scandir)
    except:
        os.mkdir(scandir)
        if quiet is not True:
            print("{}\t[>]{} Creating {}".format(bcolors.BLUE, bcolors.ENDC, scandir))
        else: pass
    # Exploit Directory
    exploitdir = hostdir + "/exploit"
    try:
        os.stat(exploitdir)
    except:
        os.mkdir(exploitdir)
        if quiet is not True:
            print("{}\t[>]{} Creating {}".format(bcolors.BLUE, bcolors.ENDC, exploitdir))
        else: pass

    # Store yo loot here!
    lootdir = hostdir + "/loot"
    try:
        os.stat(lootdir)
    except:
        os.mkdir(lootdir)
        if quiet is not True:
            print("{}\t[>]{} Creating {}".format(bcolors.BLUE, bcolors.ENDC, lootdir))
        else: pass
