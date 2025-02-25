---
date: 2024-08-29T21:44:51-05:00
# description: ""
image: "/images/THM-Summit/Summit.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: Summit"
type: "post"
---

This is a blue team challenge where we need to create defensive countermeasures for various malware samples. This will be achieved by using file hashes, IP addresses, firewall rules, DNS and sigma rules.

* Platform: TryHackMe
* Link: [Summit](https://tryhackme.com/r/room/summit)
* Level: Easy

## What is the first flag you receive after successfully detecting sample1.exe?

After navigating to the link provided, go to `Malware Snadbox`, the file `sample1.exe` is already loaded and click on `Submit for Analysis`.

![Malware Sandbox](/images/THM-Summit/malware_sandbox.png)

![Submit for analysis button](/images/THM-Summit/submit_for_analysis.png)

After the analysis is completed, we get three hash values.

![Sample1 analysis results](/images/THM-Summit/general_info.png)

Back to the drop down menu, there is a `Manage Hashes` section, copy one of the hashes, check the correct `Hash Algorithm` box and submit it.

![Detect Hashes](/images/THM-Summit/detect_hashes.png)

You will get some results and an email (check the `Mail` section in the drop down menu) with the first flag.

![Hash Blocklist](/images/THM-Summit/hash_blocklist.png)

![First flag](/images/THM-Summit/first_flag.png)

## What is the second flag you receive after successfully detecting sample2.exe?

Using the same process we analyze `sample2.exe`. The report tells us that this file tries to send an HTTP request to IP address `154.35.10.113:4444`.

> If we try to get the flag via hash submission we are told that it requires another method.

![Sample2 analysis results](/images/THM-Summit/sample2_network_activity.png)

Let's create a rule in the `Firewall Rule Manager` section.

![Firewall rule manager](/images/THM-Summit/firewall_rule_manager.png)

After saving that rule we get flag 2 in our mail.

![Second flag](/images/THM-Summit/flag_2.png)

## What is the third flag you receive after successfully detecting sample3.exe?

After analyzing `sample3.exe`, we notice some HTTP requests to IP `62.123.140.9` and DNS requests to `emudyn.bresonicz.info` with the same IP address.

![Sample3 analysis results](/images/THM-Summit/sample3_network_activity.png)

We head to the `DNS Filter` section and create a DNS rule for that domain which gets us the third flag.

![DNS Rule Manager](/images/THM-Summit/DNS_malicious_domain.png)

![Third flag](/images/THM-Summit/flag_3.png)

## What is the fourth flag you receive after successfully detecting sample4.exe?

From the previous email, we know that blocking hashes, IPs, or domain will not solve our problem. We need to look deeper.

The analysis report of `sample4.exe` shows some registry activity.

![sample4 analysis results](/images/THM-Summit/sample4_registry_activity.png)

We will use the `Sigma Rule Builder` for this case. For Step 1 we choose `Sysmon Event Logs` and for Step 2 we pick `Registry Modifications`. In Step 3 we enter the values from the report.

> If you google `att&ck DisableRealtimeMonitoring ID` you will see that its ID is `T1562.002` which falls under [Defense Evasion](https://attack.mitre.org/tactics/TA0005/) with ID `TA0005`.

| Registry Key  | HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection |
| ------------- | --------------------------------------------------------------------------- |
| Registry Name | DisableRealtimeMonitoring                                                   |
| Value         | 1                                                                           |
| ATT&CK ID     | Defense Evasion (TA0005)                                                    |

![Sigma rule for sample4](/images/THM-Summit/Sigma_rule.png)

After validating the rule we get flag 4 in our inbox.

![Fourth flag](/images/THM-Summit/flag_4.png)

## What is the fifth flag you receive after successfully detecting sample5.exe?

This time we have to focus on the logs to determine our countermeasure. 

![Log file for sample5](/images/THM-Summit/log_file.png)

After paying close attention we notice some recurring traffic on the same port at regular intervals. Every 30 minutes there is some outgoing traffic of 97 bytes to IP `51.102.10.19`. In the `Sigma Rule Builder` go to `Sysmon Event Logs`  -> `Network connections`.

Because the threat actor can now change the artifacts we cannot rely of IP addresses, protocols, or port numbers. Also given the fact that the traffic occurs every 30 minutes we can assume that it uses an automated process probably via a C2 framework.

Using the values in the picture below we get the fifth flag.

![Sigma rule C2 server](/images/THM-Summit/Sigma_rule_C2.png)

![Fifth flag](/images/THM-Summit/flag_5.png)

## What is the final flag you receive from Sphinx?

We now need to make use of a commands log file.

![commands log file](/images/THM-Summit/commands_log.png)

First we need to understand what those commands are doing. The commands suggest that the malware is performing reconnaissance and collecting information about the system, network, and user accounts. The output is stored in a log file (`exfiltr8.log`) in the temporary directory (`%temp%`), likely with the intention of exfiltrating this data to an external attacker.

The log file shows us that the temporary directory `%temp%` is always used in conjunction with a file named `exfiltr8.log`. So we should focus on that with our countermeasure.

Go to `Sigma Rule Builder` -> `Sysmon Event Logs` -> `FIle Creation and Modification` and use the options depicted below. 

![Sigma rule data exfiltration malware](/images/THM-Summit/sigma_rule_exfiltration.png)

We then get the final flag.

![Final flag](/images/THM-Summit/final_flag.png)
