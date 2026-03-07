---
date: 2026-03-05T16:15:21-06:00
# description: ""
image: "/images/HTB-Expressway/Expressway.png"
lastmod: 2026-03-05
showTableOfContents: true
tags: ["Hackthebox", "VPN", "ISAKMP/IKE", "PSK-Cracking", "CVE-2025-32463", "hashcat", "UDP-scan", "Sudo-PrivEsc"]
categories: ["Writeups"]
title: "HTB: Expressway"
type: "post"
---

* Platform: HackTheBox
* Link: [Expressway](https://app.hackthebox.com/machines/Expressway)
* Level: Easy
* OS: Linux
---

Expressway begins with the discovery of a very limited attack surface through a TCP scan. A subsequent UDP scan reveals that the target is running an IPsec VPN service. By enumerating the IKE service, we obtain the IKE identity and an Aggressive Mode authentication hash, which enables an offline attack against the VPN’s pre-shared key.

After successfully recovering the key, we authenticate to the system via SSH and obtain an initial foothold. Further local enumeration reveals that the installed version of sudo is vulnerable to `CVE-2025-32463`, allowing us to escalate privileges and obtain a root shell.

Overall, the compromise involves exploiting a weak VPN configuration to recover credentials and leveraging a vulnerable sudo version to achieve full system compromise.

# Scanning

```
nmap -sC -sV -Pn -oA nmap/Expressway {TARGET_IP}
```

**Results**
```shell
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-06 06:15 EST
Nmap scan report for 10.129.1.32 (10.129.1.32)
Host is up (0.11s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.82 seconds
```

Our TCP scan only shows one open port (22) running SSH with the `OpenSSH 10.0p2` version.

We run a UDP scan to find more services since SSH is a relatively small attack surface.

```
sudo nmap -sU --top-ports 100 -sC -sV {TARGET_IP}
```

**Results**
```shell
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-06 06:26 EST
Nmap scan report for 10.129.1.32 (10.129.1.32)
Host is up (0.13s latency).
Not shown: 96 closed udp ports (port-unreach)
PORT     STATE         SERVICE   VERSION
68/udp   open|filtered dhcpc
69/udp   open          tftp      Netkit tftpd or atftpd
500/udp  open          isakmp?
| fingerprint-strings: 
|   IKE_MAIN_MODE: 
|_    "3DUfwO
| ike-version: 
|   attributes: 
|     XAUTH
|_    Dead Peer Detection v1.0
4500/udp open|filtered nat-t-ike
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port500-UDP:V=7.95%I=7%D=3/6%Time=69AABA8F%P=x86_64-pc-linux-gnu%r(IKE_
SF:MAIN_MODE,70,"\0\x11\"3DUfwO\xd8\x19\x12~\xa2\x9f\x08\x01\x10\x02\0\0\0
SF:\0\0\0\0\0p\r\0\x004\0\0\0\x01\0\0\0\x01\0\0\0\(\x01\x01\0\x01\0\0\0\x2
SF:0\x01\x01\0\0\x80\x01\0\x05\x80\x02\0\x02\x80\x04\0\x02\x80\x03\0\x01\x
SF:80\x0b\0\x01\x80\x0c\0\x01\r\0\0\x0c\t\0&\x89\xdf\xd6\xb7\x12\0\0\0\x14
SF:\xaf\xca\xd7\x13h\xa1\xf1\xc9k\x86\x96\xfcwW\x01\0");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 303.83 seconds
```
The UDP scan discovers a few ports:
* `68` - DHCP
* `69` - TFTP
* `500` - isakmp
* `4500` - NAT Traversal for IPsec

The UDP ports discovered are a strong indication of an IPsec VPN running on the target. Ports `500` and `4500` are often appear together when a system supports IPsec with NAT Traversal.

## UDP 500 - ISAKMP / IKE

ISAKMP (Internet Security Association and Key Management Protocol) is used during the initial negotiation of an IPsec VPN tunnel. The modern implementations use IKE (Internet Key Exchange) on this port.

Functions:
* Negotiates security parameters
* Authenticates VPN peers
* Establish Security Associate (SAs)
* Exchange cryptographic keys

## UDP 4500 - NAT Traversal (NAT-T)

NAT-Traversal allows IPsec to work through NAT devices (home routers, firewalls). Normally IPsec uses ESP (protocol 50) however it does not work well with NAT.

The typical workflow is as such:
1. IKE negotiation begins on **UDP 500**
2. NAT is detected
3. Tunnel switches to **UDP 4500**
4. Encrypted ESP traffic is encapsulated inside UDP packets

This allows VPN clients behind NAT to connect successfully. Our discovery points to the target being a VPN gateway.

# Enumeration

We run a IKE scan to get more information.

```
ike-scan -M -A {TARGET_IP}
```

> * `-M` - Use Main Mode probe
> * `-A` - Also test Aggressive Mode

**Results**
```shell
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.1.32     Aggressive Mode Handshake returned
        HDR=(CKY-R=0dc7411b28450ec4)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.123 seconds (8.11 hosts/sec).  1 returned handshake; 0 returned notify
```

From the ike-scan output we can derive several key observations:
* Aggressive Mode is enabled, which exposes the IKE identity (`ike@expressway.htb`) as well as an authentication hash `Hash(20 bytes)`. Because the VPN uses Pre-Shared Key (PSK) authentication, this hash can potentially be used for offline PSK cracking attacks.
* The cryptographic parameters used during Phase 1 negotiation are weak and outdated:
    - Encryption: 3DES
    - Integrity: SHA1
    - Diffie-Hellman: Group 2 (modp1024)
These algorithms are considered deprecated. In particular, 3DES is vulnerable to Sweet32 attacks, SHA-1 has known collision weaknesses, and DH Group 2 (1024-bit) no longer provides adequate security.
* The authentication method is PSK (Pre-Shared Key) rather than certificate-based authentication, which further increases the risk when combined with Aggressive Mode, since it allows attackers to attempt offline brute-force attacks against the shared key.

Overall, the configuration indicates an outdated and weakly secured IKEv1 VPN setup.

We extract the hash for offline cracking:

```
ike-scan -A -M expressway.htb --pskcrack=hash.txt
```

![Hash extraction](/images/HTB-Expressway/expressway_pscrack.png)

Using Hashcat we perform an offline brute-force attack against the captured IKE authentication hash and successfully recover the VPN pre-shared key.

```
hashcat -m 5400 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

```
freakingrockstarontheroad
```

![Hash cracking](/images/HTB-Expressway/ike_ssh_pwd.png)

# Initial Foothold

Using the password we login via SSH as `ike`:

```
ssh ike@expressway.thb
```

![ike SSH login](/images/HTB-Expressway/ike_SSH_login.png)

# Privilege Escalation

We run `sudo -l` to check the sudo privileges of the user. We are met with a sudo lecture, a security warning displayed the first time a user runs sudo on a Linux system, reminding them to use elevated privileges responsibly.

![sudo privileges](/images/HTB-Expressway/expressway_sudo_privs.png)

The SSH password is not valid here.

With linPEAS we discover the running version of sudo (`1.9.17`).

![Hash cracking](/images/HTB-Expressway/expressway_sudo_version.png)

Researching vulnerabilities for this version we find [CVE-2025-32463](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2025-096/) with a PoC available [here](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot/blob/main/sudo-chwoot.sh).

> CVE-2025-32463 is a critical local privilege escalation vulnerability in sudo where the `--chroot` option allows an attacker to load user-controlled NSS configuration files and execute arbitrary libraries as root.

We upload the exploit script to the target and execute it to gain root privileges.

![Roor flag](/images/HTB-Expressway/expressway_root_flag.png)

## Exploit Explanation

The exploit gains root privileges by abusing how vulnerable versions of `sudo` handle the `--chroot` (`-R`) option.

The script first creates a fake chroot environment (`woot/`) containing a malicious `nsswitch.conf` file that instructs the system to load a custom NSS module. It then compiles a malicious shared library (`libnss_/woot1337.so.2`) whose constructor executes a command with UID and GID set to `0` (root).

When the script runs `sudo -R woot woot`, the vulnerable `sudo` processes the attacker-controlled `nsswitch.conf` inside the chroot and loads the malicious NSS library as part of its user lookup process. Because this happens during `sudo`’s privileged execution, the library is loaded with root privileges.

The library’s constructor immediately executes and spawns a root shell (or runs the provided command), resulting in privilege escalation to root.

