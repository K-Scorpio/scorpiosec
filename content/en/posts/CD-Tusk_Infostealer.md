---
date: 2026-05-03T17:12:36-05:00
# description: ""
# image: ""
showTableOfContents: true
tags: ["CyberDefenders", "Blue-Team-Lab", "Threat-Intel", "Tusk", "Infostealer", "Phishing", "Brand-Impersonation"]
categories: ["Blue Teaming"]
title: "CyberDefenders: Tusk Infostealer Lab"
type: "post"
---

* Platform: CyberDefenders
* Link: [Tusk Infostealer Lab](https://cyberdefenders.org/blueteam-ctf-challenges/tusk-infostealer/) 
* Level: Easy
* Category: Threat Intel
---

# Scenario

A blockchain development company detected unusual activity when an employee was redirected to an unfamiliar website while accessing a DAO management platform. Soon after, multiple cryptocurrency wallets linked to the organization were drained. Investigators suspect a malicious tool was used to steal credentials and exfiltrate funds.

Your task is to analyze the provided intelligence to uncover the attack methods, identify indicators of compromise, and track the threat actor’s infrastructure.

---

Extraction of the provided archive yields a MD5 hash.

![file_hash](/images/CD-Tusk_InfoStealer/Tusk_hash.png)


```
E5B8B2CF5B244500B22B665C87C11767
```

---

# Q1 - In KB, what is the size of the malicious file?

## Methodology

The investigation began with the provided MD5 hash, which was used as an indicator of compromise (IOC) to query a threat intelligence platform.

The hash was searched on VirusTotal to retrieve metadata and analysis results associated with the file.

## Findings

The lookup returned a malicious file identified as:

- File Name: `madHcNet.dll`
- Detection Ratio: 45/72 vendors flagged as malicious

From the file metadata, the file size is reported as: `921.36 KB`.

![VirusTotal look up](/images/CD-Tusk_InfoStealer/VT_LOOKUP.png)

## Conclusion

The size of the malicious file is:

```
921.36 KB
```

# Q2 - What word do the threat actors use in log messages to describe their victims, based on the name of an ancient hunted creature?


## Methodology

To better understand the threat actor’s terminology and behavior, open-source intelligence (OSINT) was used. Based on the context of the attack (cryptocurrency theft and suspected infostealer usage), research was conducted on campaigns related to Tusk Infostealer.

Relevant threat intelligence reports were identified through targeted searches, leading to an analysis published by [Kaspersky](https://www.kaspersky.com/about/press-releases/kaspersky-discovers-tusk-active-information-and-crypto-stealing-campaign).

## Findings

The report revealed that the threat actors use a specific term in their logs and communications: `“Mammoth” (from Russian: _Мамонт_)`

Key insight:

- The term is slang used by Russian-speaking threat actors
- It refers to a victim
- The naming draws an analogy to ancient mammoths being hunted for valuable resources

This term appeared in:

- Malware communications
- Data exfiltration logs

![Tusk report Kaspersky](/images/CD-Tusk_InfoStealer/Tusk_report.png)

## Conclusion

The word used by the threat actors to describe their victims is:

```
Mammoth
```

# Q3 - The threat actor set up a malicious website to mimic a platform designed for creating and managing decentralized autonomous organizations (DAOs) on the MultiversX blockchain (peerme.io). What is the name of the malicious website the attacker created to simulate this platform?

## Methodology

To identify the phishing infrastructure used in the campaign, open-source intelligence (OSINT) was leveraged. Based on previous findings linking the activity to the Tusk Infostealer campaign, external threat intelligence reports were reviewed.

A targeted search led to an analysis published on [Securelist](https://securelist.com/tusk-infostealers-campaign/113367/), which provides detailed insights into the campaign’s infrastructure.

## Findings

The report revealed that the threat actors created a fraudulent website designed to impersonate the legitimate DAO management platform `peerme.io`.

The malicious domain identified in the campaign is: `tidyme.io`.

This domain is part of the TidyMe sub-campaign, which targets cryptocurrency users by mimicking legitimate blockchain services to harvest credentials and deploy malware.

![TidyMe sub campaign](/images/CD-Tusk_InfoStealer/tidyme.png)

## Conclusion

The malicious website used by the attacker is:

```
tidyme.io
```

# Q4 - Which cloud storage service did the campaign operators use to host malware samples for both macOS and Windows OS versions?

## Methodology

To determine where the malware samples were hosted, open-source intelligence (OSINT) was used. Based on prior findings linking the activity to the Tusk Infostealer campaign, external threat intelligence reports were reviewed.

Relevant information was gathered from:

- Securelist
- Kaspersky press release

## Findings

Both sources confirm that the threat actors leveraged a cloud storage service to distribute malicious payloads.

Key observations:

- Malware loader files were hosted on a cloud platform
- Victims were redirected to download these files
- The loaders then deployed additional malware (infostealers, clippers)

The service identified in both reports is: `Dropbox`.

![Dropbox for malware sample hosting](/images/CD-Tusk_InfoStealer/dropbox.png)

![Dropbox for malware sample hosting 2](/images/CD-Tusk_InfoStealer/dropbox2.png)

## Analysis

Using a legitimate cloud storage provider such as Dropbox allows attackers to:

- Blend malicious traffic with legitimate usage
- Bypass basic security filtering
- Increase trust from victims

This is a common technique in modern phishing and malware distribution campaigns.

## Conclusion

The cloud storage service used by the attackers to host malware samples is:

```
Dropbox
```

# Q5 - The malicious executable contains a configuration file that includes base64-encoded URLs and a password used for archived data decompression, enabling the download of second-stage payloads. What is the password for decompression found in this configuration file?

## Methodology

To identify the password used by the malware for decompressing archived payloads, open-source intelligence (OSINT) was leveraged. Based on previous findings linking the activity to the Tusk Infostealer campaign, detailed technical analysis was reviewed on Securelist.

The report includes a breakdown of the malware’s internal configuration file (`config.json`), which contains encoded data used during execution.

## Findings

The analysis revealed that the malicious executable (`tidyme.exe`) includes a configuration file containing:

- Base64-encoded URLs (used to download second-stage payloads)
- A password used to decompress archived data

The relevant excerpt from the configuration shows:

```JSON
{
  "password": "newfile2024"
}
```

![Archive decompression password](/images/CD-Tusk_InfoStealer/tusk_pwd.png)

## Analysis

This password is used by the malware to extract additional payloads after download, enabling the continuation of the infection chain (e.g., infostealers and other malicious components).

Embedding such credentials in configuration files is a common technique used by attackers to automate multi-stage payload delivery.

## Conclusion

The password used for archive decompression is:

```
newfile2024
```

# Q6 - What is the name of the function responsible for retrieving the field archive from the configuration file?

## Methodology

To identify the function responsible for retrieving the archive field from the configuration file, open-source intelligence (OSINT) was leveraged. Based on previous findings related to the Tusk Infostealer campaign, detailed technical analysis was reviewed on Securelist.

The report provides insight into the internal structure and behavior of the malware, including its downloader logic and function implementations.

## Findings

The analysis describes the downloader routine implemented within the malware, specifically highlighting two key functions:

- `downloadAndExtractArchive`
- `loadFile`

The report explicitly states that the function responsible for retrieving the `archive` field from the configuration file is: `downloadAndExtractArchive`.

This function:

- Extracts the `archive` value from the configuration file
- Decodes the embedded (base64-encoded) Dropbox URL
- Downloads the archive to the victim system
- Uses the embedded password to extract its contents


![Tusk download functions](/images/CD-Tusk_InfoStealer/tusk_function.png)

## Analysis

The `downloadAndExtractArchive` function plays a central role in the malware’s multi-stage execution chain by automating:

- Retrieval of second-stage payloads
- Decryption/decompression of archived content
- Execution of additional malicious binaries

This reflects a modular design commonly used in modern infostealer campaigns.

## Conclusion

The function responsible for retrieving the archive field is:

```
downloadAndExtractArchive
```

# Q7 - In the third sub-campaign carried out by the operators, the attacker mimicked an AI translator project. What is the name of the legitimate translator, and what is the name of the malicious translator created by the attackers?

## Methodology

To identify the platforms used in the third sub-campaign, open-source intelligence (OSINT) was leveraged. Based on prior findings related to the Tusk Infostealer campaign, detailed analysis was reviewed on Securelist.

The report describes multiple sub-campaigns where threat actors impersonate legitimate services to lure victims.

## Findings

In the third sub-campaign, the attackers simulated an AI-based translator service.

The report identifies:
- Legitimate platform: `yous.ai`
- Malicious impersonation: `voico.io`

The malicious site closely mimics the legitimate one in appearance and functionality to deceive users into interacting with it.

![Tusk third sub-campaign](/images/CD-Tusk_InfoStealer/3rd_sub_campaign.png)

## Analysis

This technique is a classic example of:

- Brand impersonation
- Social engineering via fake services

By replicating a legitimate AI translator platform, the attackers increase trust and likelihood of user interaction, enabling:

- Malware delivery
- Credential harvesting

## Conclusion

The legitimate and malicious translator platforms are:

```
Yous.ai, voico.io
```


# Q8 - The downloader is tasked with delivering additional malware samples to the victim’s machine, primarily infostealers like StealC and Danabot. What are the IP addresses of the StealC C2 servers used in the campaign?

## Methodology

To identify the command-and-control (C2) infrastructure used in the campaign, open-source intelligence (OSINT) was leveraged. Based on prior findings related to the Tusk Infostealer campaign, detailed analysis was reviewed on Securelist.

The `Network IOCs` section of the report was examined to extract infrastructure associated with the malware.

## Findings

The report lists multiple network indicators, including IP addresses linked to different components of the campaign.

The IP addresses specifically identified as StealC C2 servers are:

> 46.8.238.240  
> 23.94.225.177

![C2 IP addresses](/images/CD-Tusk_InfoStealer/C2_IPs.png)

## Analysis

These IP addresses serve as command-and-control (C2) servers for the StealC infostealer, enabling attackers to:

- Receive stolen data from infected systems
- Issue commands to compromised hosts
- Maintain persistence and control over infected machines

The presence of multiple C2 servers indicates redundancy in the attacker’s infrastructure.

## Conclusion

The StealC C2 server IP addresses used in the campaign are:

```
46.8.238.240, 23.94.225.177
```

# Q9 - What is the address of the Ethereum cryptocurrency wallet used in this campaign?

## Methodology

To identify the cryptocurrency infrastructure used by the threat actors, open-source intelligence (OSINT) was leveraged. Based on prior findings related to the Tusk Infostealer campaign, detailed analysis was reviewed on Securelist.

The `Cryptocurrency wallet addresses` section of the report was examined to extract wallet identifiers associated with the campaign.

## Findings

The report lists multiple cryptocurrency wallet addresses linked to the attackers, including Bitcoin and Ethereum wallets.

The Ethereum wallet address identified in the campaign is:

> 0xaf0362e215Ff4e004F30e785e822F7E20b99723A

![Etherum address](/images/CD-Tusk_InfoStealer/ETH_address.png)

## Analysis

This wallet is used by the attackers to:

- Receive stolen cryptocurrency funds
- Aggregate assets from compromised victims
- Facilitate financial gain from the campaign

Tracking such wallet addresses is critical for:

- Blockchain analysis
- Attribution efforts
- Monitoring illicit transactions


## Conclusion

The Ethereum wallet address used in the campaign is:

```
0xaf0362e215Ff4e004F30e785e822F7E20b99723A
```

