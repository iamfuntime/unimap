# UniMap

# Credit

This tool was heavily inspired by a few different tools that I came across while studying for my OSCP. After heavily using [Reconnoitre](https://github.com/codingo/Reconnoitre) written by [Codingo](https://www.twitter.com/codingo_), it would make some recommendations on further tools to run. But because I'm lazy, I wanted to have the option to run these automatically. But full Nmap scans can take an extremely long time, so I needed to find something else. In walks [onetwopunch](https://github.com/superkojiman/onetwopunch) which uses unicornscan to scan for open ports and then pushes that to Nmap. I utilized both these ideas. Much of the layout ideas were influenced by [Dave Kennedy](https://www.twitter.com/HackingDave). 

# Usage

| Argument        | Description |
| ------------- |:-------------|
| -h, --help | Display help message and exit |
| -t TARGET | Set a target IP Address |
| -o OUTPUT_DIR | Directory where results will be written |
| -p {tcp, udp, all } | Which protocol to scan for. Default is tcp |
| -i INTERFACE | Which interface to use. Defaults to eth0 |
| -s SPEED | Speed of Unicornscan by packets per second. Default is 1000 |
| -n NMAP_OPTIONS | Set specific Nmap Options |
| -e ENUM | Run additional enumeration programs |
| -c CRACK | Run brute force password cracking utilities |
| --ports {d, a} | Default Unicornscan ports, or all 1-65535 ports |
| --quick | Run Unicornscan and basic Nmap scan |
| --quiet | Suppress banner and headers to limit results |

## Usage Examples

```
root@kali:~/tools/unimap# python unimap.py -h
usage: unimap.py [-h] -t TARGET [-o OUTPUT_DIR] [-p {tcp,udp,all}]
                 [-i INTERFACE] [-s SPEED] [-n NMAP_OPTIONS] [-e] [-c]
                 [--ports {d,a}] [--quick] [--quiet]

optional arguments:
  -h, --help        show this help message and exit
  -t TARGET         Set a target IP address. Ex. 10.10.10.10
  -o OUTPUT_DIR     Set the output directory. Defaults to /tmp/unimap
  -p {tcp,udp,all}  Select the protocol to use. Ex. tcp/udp/all
  -i INTERFACE      Select the interface. Ex. eth0
  -s SPEED          Set the Packets Per Second for Unicornscan. Ex. 1000
  -n NMAP_OPTIONS   Set NMAP options. Include in double quotes
  -e                Run additional enumeration programs? e.g. wpscan, nikto,
                    dirb, etc
  -c                Run Brute Force password cracking against known services
  --ports {d,a}     Default or All ports.
  --quick           Run Unicornscan and basic Nmap scan
  --quiet           Suppress banner and headers to limit results
```

```
root@kali:~/tools/unimap# python unimap.py -t 192.168.1.1 -s 1000 --quick

             .__                       
 __ __  ____ |__| _____ _____  ______  
|  |  \/    \|  |/     \\__  \ \____ \ 
|  |  /   |  \  |  Y Y  \/ __ \|  |_> >
|____/|___|  /__|__|_|  (____  /   __/ 
           \/         \/     \/|__|    
                             by funtime

[>] Target: 192.168.1.1
[>] Output Directory: /tmp/unimap
[>] Protocol: tcp
[>] Interface: eth0
[>] Unicornscan Speed: 1000
[>] NMAP Options: -PN -A -T4 -sS -sC
[>] Enumerate: False
[>] Quick Scan?: True
[>] Checking Directory Structure
[>] Creating /tmp/unimap
	[>] Creating /tmp/unimap/192.168.1.1
	[>] Creating /tmp/unimap/192.168.1.1/scans
	[>] Creating /tmp/unimap/192.168.1.1/exploit
	[>] Creating /tmp/unimap/192.168.1.1/loot

[*] Starting Unicornscan for 192.168.1.1
[+] unicornscan -i eth0 -mT -r 1000 -l /tmp/unimap/192.168.1.1/scans/unicornscan.txt 192.168.1.1:tcp_ports
[*] Starting Basic Nmap Scan for 192.168.1.1
[+] nmap -PN -A -T4 -sS -sC -p 22,53,80,443 -oA /tmp/unimap/192.168.1.1/scans/basic_nmap 192.168.1.1
[*] Starting Amap Scan for 192.168.1.1
[+] amap -bqv 192.168.1.1 22 53 80 443 -o /tmp/unimap/192.168.1.1/scans/amapscan.txt

[>] Scans Complete! Results are located in /tmp/unimap/192.168.1.1/scans
```

# Requirements

This tool requires at the bare minimum *unicornscan* and *nmap*. Any additional tools are not required but will make for more inclusive results.
