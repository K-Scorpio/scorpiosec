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

Ce challenge nécessite de créer des contre-mesures défensives pour différents échantillons de malware. Nous utiliserons des hachages de fichiers, des adresses IP, des règles de pare-feu, des règles DNS et des règles sigma.

* Platforme: TryHackMe
* Lien: [Summit](https://tryhackme.com/r/room/summit)
* Niveau: Facile

## What is the first flag you receive after successfully detecting sample1.exe?

Après avoir cliqué sur le lien fourni, sélectionnez `Malware Snadbox`, le fichier `sample1.exe` est déjà présent et cliquez sur `Submit for Analysis`.

![Malware Sandbox](/images/THM-Summit/malware_sandbox.png)

![Submit for analysis button](/images/THM-Summit/submit_for_analysis.png)

Une fois l'analyse terminée, nous obtenons trois valeurs de hachage.

![Sample1 analysis results](/images/THM-Summit/general_info.png)

Dans le menu déroulant, il y a une section `Manage Hashes`, copiez l'un des hashs, cochez la case correcte pour `Hash Algorithm` et soumettez-le.

![Detect Hashes](/images/THM-Summit/detect_hashes.png)

Nous obtenons quelques résultats et un e-mail (la section `Mail` dans le menu déroulant) avec le premier drapeau.

![Hash Blocklist](/images/THM-Summit/hash_blocklist.png)

![First flag](/images/THM-Summit/first_flag.png)

## What is the second flag you receive after successfully detecting sample2.exe?

En utilisant le même processus, nous analysons `sample2.exe`. Le rapport indique que ce fichier tente d'envoyer une requête HTTP à l'adresse IP `154.35.10.113:4444`.

![Sample2 analysis results](/images/THM-Summit/sample2_network_activity.png)

Créons une règle dans la section `Firewall Rule Manager`.

![Firewall rule manager](/images/THM-Summit/firewall_rule_manager.png)

Après la sauvegarde de cette règle, nous recevons le deuxième drapeau.

![Second flag](/images/THM-Summit/flag_2.png)

## What is the third flag you receive after successfully detecting sample3.exe?

Après l'analyse de `sample3.exe`, nous remarquons des requêtes HTTP vers l'IP `62.123.140.9` et des requêtes DNS vers `emudyn.bresonicz.info` avec la même adresse IP.

![Sample3 analysis results](/images/THM-Summit/sample3_network_activity.png)

Nous nous dirigeons vers la section `DNS Filter` et créons une règle DNS pour ce domaine, ce qui nous permet d'obtenir le troisième drapeau.

![DNS Rule Manager](/images/THM-Summit/DNS_malicious_domain.png)

![Third flag](/images/THM-Summit/flag_3.png)

## What is the fourth flag you receive after successfully detecting sample4.exe?

Grâce à l'e-mail précédent, nous savons que le blocage des hashs, des IP ou des domaines ne résoudra pas ce problème. Nous devons aller plus loin.

Le rapport d'analyse de `sample4.exe` montre quelques modifications du registre.

![sample4 analysis results](/images/THM-Summit/sample4_registry_activity.png)

Nous utilisons le `Sigma Rule Builder` pour ce cas. Pour l'étape 1, nous choisissons `Sysmon Event Logs` et pour l'étape 2 `Registry Modifications`. A l'étape 3, nous entrons les valeurs observées dans le rapport.

> Si vous cherchez sur Google `att&ck DisableRealtimeMonitoring ID` vous verrez que son ID est `T1562.002` qui appartient à [Defense Evasion](https://attack.mitre.org/tactics/TA0005/) avec l'ID `TA0005`.

| Registry Key  | HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection |
| ------------- | --------------------------------------------------------------------------- |
| Registry Name | DisableRealtimeMonitoring                                                   |
| Value         | 1                                                                           |
| ATT&CK ID     | Defense Evasion (TA0005)                                                    |

![Sigma rule for sample4](/images/THM-Summit/Sigma_rule.png)

Après avoir validé la règle, nous recevons le drapeau 4.

![Fourth flag](/images/THM-Summit/flag_4.png)

## What is the fifth flag you receive after successfully detecting sample5.exe?

Cette fois-ci, nous devons utiliser les logs pour déterminer notre solution.

![Log file for sample5](/images/THM-Summit/log_file.png)

Nous remarquons une tendance dans les logs. Toutes les 30 minutes, il y a un trafic sortant de 97 octets vers l'IP `51.102.10.19`. Dans le `Sigma Rule Builder`, allez dans `Sysmon Event Logs` -> `Network connections`.

Puisque l'attaquant peut maintenant modifier les artefacts, nous ne pouvons pas nous fier aux adresses IP, aux protocoles ou aux numéros de port. De plus, étant donné que le trafic se produit toutes les 30 minutes, nous pouvons supposer qu'il utilise un processus automatisé, probablement via un framework C2.

En utilisant les valeurs de l'image ci-dessous, nous obtenons le cinquième drapeau.

![Sigma rule C2 server](/images/THM-Summit/Sigma_rule_C2.png)

![Fifth flag](/images/THM-Summit/flag_5.png)

## What is the final flag you receive from Sphinx?

Nous devons maintenant utiliser un journaul de commandes.

![commands log file](/images/THM-Summit/commands_log.png)

Tout d'abord, nous devons comprendre ce que font ces commandes. Elles suggèrent que le logiciel malveillant effectue une reconnaissance et collecte des informations sur le système, le réseau et les comptes d'utilisateurs. Les résultats sont stockés dans un fichier journal (`exfiltr8.log`) dans le répertoire temporaire (`%temp%`), probablement dans le but d'exfiltrer ces données.

Le fichier journal nous montre que le répertoire temporaire `%temp%` est toujours utilisé en combinaison avec un fichier nommé `exfiltr8.log`. Nous nous concentrerons donc sur ces éléments pour créer notre contre-mesure.

Allez dans `Sigma Rule Builder` -> `Sysmon Event Logs` -> `FIle Creation and Modification` et utilisez les options ci-dessous. 

![Sigma rule data exfiltration malware](/images/THM-Summit/sigma_rule_exfiltration.png)

Nous obtenons le drapeau final.

![Final flag](/images/THM-Summit/final_flag.png)
