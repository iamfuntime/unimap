#!/usr/bin/env python

# Color Schemes <- Thanks @HackingDave
class bcolors:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERL = '\033[4m'
    ENDC = '\033[0m'
    backBlack = '\033[40m'
    backRed = '\033[41m'
    backGreen = '\033[42m'
    backYellow = '\033[43m'
    backBlue = '\033[44m'
    backMagenta = '\033[45m'
    backCyan = '\033[46m'
    backWhite = '\033[47m'
    
# Software Dependencies
standard_software = ['nmap', 'unicornscan']
enum_software = ['nikto', 'wpscan', 'dirb', 'onesixtyone', 'snmpwalk', 'nc', 
                 'medusa', 'hydra', 'ncrack', 'enum4linux', 'smtp-user-enum',]
    
# UNIMAP Banner    
banner = '''
             .__                       
 __ __  ____ |__| _____ _____  ______  
|  |  \\/    \\|  |/     \\\\__  \\ \\____ \\ 
|  |  /   |  \\  |  Y Y  \\/ __ \\|  |_> >
|____/|___|  /__|__|_|  (____  /   __/ 
           \\/         \\/     \\/|__|    
                                by funtime
'''


# NMAP Scripts
WIN_SCRIPTS = 'msrpc-enum,stuxnet-detect,smb* and not smb-brute and not smb-flood'
FTP_SCRIPTS = 'ftp* and not ftp-brute'
RPC_SCRIPTS = 'nfs-*,rpcinfo'
SSH_SCRIPTS = 'ssh* and not ssh-brute and not ssh-run'
HTTP_SCRIPTS = 'http-adobe-coldfusion-apsa1301.nse,http-apache-server-status.nse,http-aspnet-debug.nse,http-auth.nse,http-coldfusion-subzero.nse,http-date.nse,http-drupal-enum.nse,http-enum.nse,http-errors.nse,http-exif-spider.nse,http-headers.nse,http-iis-webdav-vuln.nse,http-ls.nse,http-methods.nse,http-php-version.nse,http-phpmyadmin-dir-traversal.nse,http-phpself-xss.nse,http-put.nse,http-robots.txt.nse,http-security-headers.nse,http-server-header.nse,http-shellshock.nse,http-title.nse,http-vuln-cve2006-3392.nse,http-vuln-cve2009-3960.nse,http-vuln-cve2010-0738.nse,http-vuln-cve2010-2861.nse,http-vuln-cve2011-3192.nse,http-vuln-cve2011-3368.nse,http-vuln-cve2012-1823.nse,http-vuln-cve2013-0156.nse,http-vuln-cve2013-6786.nse,http-vuln-cve2013-7091.nse,http-vuln-cve2014-2126.nse,http-vuln-cve2014-2127.nse,http-vuln-cve2014-2128.nse,http-vuln-cve2014-2129.nse,http-vuln-cve2014-3704.nse,http-vuln-cve2014-8877.nse,http-vuln-cve2015-1427.nse,http-vuln-cve2015-1635.nse,http-vuln-cve2017-1001000.nse,http-vuln-cve2017-5638.nse,http-vuln-cve2017-5689.nse,http-vuln-cve2017-8917.nse,http-vuln-misfortune-cookie.nse,http-vuln-wnr1000-creds.nse,http-wordpress-enum.nse,http-xssed.nse'
DNS_SCRIPTS = 'dns-* and not dns-brute'
RDP_SCRIPTS = 'rdp-*'
SNMP_SCRIPTS = 'snmp-netstat,snmp-processes'
MSSQL_SCRIPTS = 'ms-sql-* and not ms-sql-brute'
ORACLE_SCRIPTS = 'oracle-sid-brute --script oracle-enum-users --script-args oracle-enum-users.sid=ORCL,userdb=orausers.txt'
MYSQL_SCRIPTS = 'mysql-* and not mysql-brute'
MONGODB_SCRIPTS = 'mongodb-* and not mongodb-brute'