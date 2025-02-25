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

* Platforme: TryHackMe
* Lien: [Friday Overtime](https://tryhackme.com/r/room/fridayovertime)
* Niveau: Moyen
---

Après avoir lancé la VM fournie, nous nous connectons avec les identifiants `ericatracy:Intel321!`.

## Who shared the malware samples?

Immédiatement après notre identification, nous trouvons un document intitulé `Urgent: Malicious Malware Artefacts Detected`.

![latest document](/images/THM-Friday_Overtime/urgent_doc.png)

L'auteur du document est `Oliver Bennett`.

![document author](/images/THM-Friday_Overtime/author.png)

**Réponse** : Oliver Bennett


## What is the SHA1 hash of the file "pRsm.dll" inside samples.zip?

Cliquez sur `Documents` puis sur `View All`.

![View all documents](/images/THM-Friday_Overtime/view_all_docs.png)

Après avoir sélectionné le document `Urgent : Artefacts malveillants détectés`, vous trouverez le fichier `samples.zip` sur le côté droit.

![malware file](/images/THM-Friday_Overtime/samples_zip.png)

Téléchargez le fichier et extrayez-le, le mot de passe est `Panda321!`.

![malware file extraction](/images/THM-Friday_Overtime/unzip_samples_zip.png)

Nous calculons ensuite le hash de `pRsm.dll`.

```
sha1sum pRsm.dll
```

![sha1 hash](/images/THM-Friday_Overtime/sha1_hash.png)

Réponse : `9d1ecbbe8637fed0d89fca1af35ea821277ad2e8`


## Which malware framework utilizes these DLLs as add-on modules?

Avec le hash sha256 du fichier `pRsm.dll`, nous effectuons une recherche sur VirusTotal.

```
2c0cfe2f4f1e7539b4700e1205411ec084cbc574f9e4710ecd4733fbf0f8a7dc
```

![sha256 hash](/images/THM-Friday_Overtime/sha256_dll.png)

Nous découvrons que le fichier est utilisé par des malwares de la famille MgBot.

![VirusTotal family label](/images/THM-Friday_Overtime/family_labels_VT.png)

Réponse: `MgBot`


## Which MITRE ATT&CK Technique is linked to using pRsm.dll in this malware framework?

Une recherche google avec `MITRE ATT&CK Technique pRsm.dll` nous amène à cet [article](https://www.welivesecurity.com/2023/04/26/evasive-panda-apt-group-malware-updates-popular-chinese-software/).

![pRsm.dll MITRE ATT&CK Technique](/images/THM-Friday_Overtime/pRsm_search.png)

En recherchant `pRsm.dll` sur la page, nous trouvons que l'ID de la technique est [T1123](https://attack.mitre.org/versions/v12/techniques/T1123).

![Technique ID](/images/THM-Friday_Overtime/technique_ID.png)

Réponse: `T1123`


## What is the CyberChef defanged URL of the malicious download location first seen on 2020-11-02?

Sur la même page, nous trouvons un lien `http://update.browser.qq[.]com/qmbs/QQ/QQUrlMgr_QQ88_4296.exe`.

![url provided](/images/THM-Friday_Overtime/defanged_url.png)

Sur [cyberchef.org](https://cyberchef.org/), nous utilisons la recette `defang URL` pour obtenir l'URL valide.

![defanged url](/images/THM-Friday_Overtime/defanged_url2.png)

Réponse: `hxxp[://]update[.]browser[.]qq[.]com/qmbs/QQ/QQUrlMgr_QQ88_4296[.]exe`


## What is the CyberChef defanged IP address of the C&C server first detected on 2020-09-14 using these modules?

Dans la section `Réseau`, nous trouvons une adresse IP pour la date spécifiée.

![IP address](/images/THM-Friday_Overtime/IP_address.png)

![Defanged IP address](/images/THM-Friday_Overtime/defanged_IP.png)


Avec cyberchef, nous obtenons l'adresse IP modifiée avec la recette `Defang IP addresses`.

Réponse: `122[.]10[.]90[.]12`


## What is the SHA1 hash of the spyagent family spyware hosted on the same IP targeting Android devices on November 16, 2022?

Sur VirusTotal, nous recherchons `122.10.90.12` et consultons la section `Relations`.

![Communicated files](/images/THM-Friday_Overtime/android_spyware.png)

Nous recherchons ensuite `951F41930489A8BFE963FCED5D8DFD79` et sous `Details` nous trouvons le hash SHA1.

![sha1 android file hash](/images/THM-Friday_Overtime/sha1_android.png)

Réponse: `1c1fe906e822012f6235fcc53f601d006d15d7be`
