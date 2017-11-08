#!/usr/bin/env python

import os
import shutil
from src.core import *


def check_dirs(output_dir, hostdir, scandir, quiet):
    if quiet is not True:
        print("{}[>]{} Checking Directory Structure".format(bcolors.BLUE, bcolors.ENDC, output_dir))
    else: pass
    try:
        os.stat(output_dir)
        if quiet is not True:
            print("\t{0}[>]{1} {2}: Directory exists.".format(bcolors.BLUE, bcolors.ENDC, output_dir))
        else: pass
    except:
        os.mkdir(output_dir)
        if quiet is not True:
            print("{}[>]{} Creating {}".format(bcolors.BLUE, bcolors.ENDC, output_dir))
        else: pass
        
    # Host Directory
    try:
        os.stat(hostdir)
        if quiet is not True:
            print("\t{0}[>]{1} {2}: Directory exists.".format(bcolors.BLUE, bcolors.ENDC, hostdir))
        else: pass
    except:
        os.mkdir(hostdir)
        if quiet is not True:
            print("{}\t[>]{} Creating {}".format(bcolors.BLUE, bcolors.ENDC, hostdir))
        else: pass
        
    # Scan Results Directory
    try:
        os.stat(scandir)
        shutil.rmtree(scandir)
        os.mkdir(scandir)
        if quiet is not True:
            print("\t{0}[>]{1} {2}: Directory exists.".format(bcolors.BLUE, bcolors.ENDC, scandir))
        else: pass
    except:
        os.mkdir(scandir)
        if quiet is not True:
            print("{}\t[>]{} Creating {}".format(bcolors.BLUE, bcolors.ENDC, scandir))
        else: pass
    # Exploit Directory
    exploitdir = hostdir + "/exploit"
    try:
        os.stat(exploitdir)
        if quiet is not True:
            print("\t{0}[>]{1} {2}: Directory exists.".format(bcolors.BLUE, bcolors.ENDC, exploitdir))
        else: pass
    except:
        os.mkdir(exploitdir)
        if quiet is not True:
            print("{}\t[>]{} Creating {}".format(bcolors.BLUE, bcolors.ENDC, exploitdir))
        else: pass

    # Store yo loot here!
    lootdir = hostdir + "/loot"
    try:
        os.stat(lootdir)
        if quiet is not True:
            print("\t{0}[>]{1} {2}: Directory exists.\n".format(bcolors.BLUE, bcolors.ENDC, lootdir))
        else: pass
    except:
        os.mkdir(lootdir)
        if quiet is not True:
            print("{}\t[>]{} Creating {}\n".format(bcolors.BLUE, bcolors.ENDC, lootdir))
        else: pass
