#!/usr/bin/env python

import os
import time
import socket
import subprocess
import multiprocessing
from multiprocessing import Process,Queue

from src.core import *

def detailed_nmap(ipaddr, scandir, nmap_options, quiet):
    print("{0}[*][*]{1} IMPORT SUCCESSFUL!!!".format(bcolors.GREEN, bcolors.ENDC))