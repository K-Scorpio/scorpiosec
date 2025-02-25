---
date: 2024-09-19T21:09:28-05:00
# description: ""
image: "/images/THM-Friday_Overtime/Friday_Overtime.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: Friday Overtime"
type: "post"
---

* Platform: TryHackMe
* Link: [Friday Overtime](https://tryhackme.com/r/room/fridayovertime)
* Level: Medium
---

For this blue team challenge we need to conduct an investigation and provide answers to some questions.

After launching the provided VM we login with the credentials `ericatracy:Intel321!`.

## Who shared the malware samples?

Right after logging in we find a document titled `Urgent: Malicious Malware Artefacts Detected`.

![latest document](/images/THM-Friday_Overtime/urgent_doc.png)

The author of the document is `Oliver Bennett`.

![document author](/images/THM-Friday_Overtime/author.png)

Answer: `Oliver Bennett`


## What is the SHA1 hash of the file "pRsm.dll" inside samples.zip?

Click on `Documents` then on `View All`.

![View all documents](/images/THM-Friday_Overtime/view_all_docs.png)

After selecting `Urgent: Malicious Malware Artefacts Detected` document, scroll down and you will find `samples.zip` on the right side.

![malware file](/images/THM-Friday_Overtime/samples_zip.png)

We extract it, the password is `Panda321!`.

![malware file extraction](/images/THM-Friday_Overtime/unzip_samples_zip.png)

We then compute the hash of `pRsm.dll`.

```
sha1sum pRsm.dll
```

![sha1 hash](/images/THM-Friday_Overtime/sha1_hash.png)

Answer: `9d1ecbbe8637fed0d89fca1af35ea821277ad2e8`


## Which malware framework utilizes these DLLs as add-on modules?

We compute the sha256 hash for the `pRsm.dll` file and search for it on VirusTotal.

```
2c0cfe2f4f1e7539b4700e1205411ec084cbc574f9e4710ecd4733fbf0f8a7dc
```

![sha256 hash](/images/THM-Friday_Overtime/sha256_dll.png)

We discover the family labels attached to this file.

![VirusTotal family label](/images/THM-Friday_Overtime/family_labels_VT.png)

Answer: `MgBot`


## Which MITRE ATT&CK Technique is linked to using pRsm.dll in this malware framework?

We research `MITRE ATT&CK Technique pRsm.dll` and find [this article](https://www.welivesecurity.com/2023/04/26/evasive-panda-apt-group-malware-updates-popular-chinese-software/).

![pRsm.dll MITRE ATT&CK Technique](/images/THM-Friday_Overtime/pRsm_search.png)

Searching for `pRsm.dll` on the page we find the technique ID to be [T1123](https://attack.mitre.org/versions/v12/techniques/T1123).

![Technique ID](/images/THM-Friday_Overtime/technique_ID.png)

Answer: `T1123`


## What is the CyberChef defanged URL of the malicious download location first seen on 2020-11-02?

On the same page we find an url `http://update.browser.qq[.]com/qmbs/QQ/QQUrlMgr_QQ88_4296.exe`.

![url provided](/images/THM-Friday_Overtime/defanged_url.png)

On [cyberchef.org](https://cyberchef.org/) we use the `defang URL` recipe to get the correct URL.

![defanged url](/images/THM-Friday_Overtime/defanged_url2.png)

Answer: `hxxp[://]update[.]browser[.]qq[.]com/qmbs/QQ/QQUrlMgr_QQ88_4296[.]exe`


## What is the CyberChef defanged IP address of the C&C server first detected on 2020-09-14 using these modules?

Using the same article, under the `Network` section we find an IP address for the specified date.

![IP address](/images/THM-Friday_Overtime/IP_address.png)

![Defanged IP address](/images/THM-Friday_Overtime/defanged_IP.png)


With cyberchef we get the defanged IP address with the `Defang IP addresses` recipe.

Answer: `122[.]10[.]90[.]12`


## What is the SHA1 hash of the spyagent family spyware hosted on the same IP targeting Android devices on November 16, 2022?

On VirusTotal we search for `122.10.90.12` and go to the `Relations` section.

![Communicated files](/images/THM-Friday_Overtime/android_spyware.png)

We then search for `951F41930489A8BFE963FCED5D8DFD79` and under `Details` we find the SHA1 hash.

![sha1 android file hash](/images/THM-Friday_Overtime/sha1_android.png)

Answer: `1c1fe906e822012f6235fcc53f601d006d15d7be`
