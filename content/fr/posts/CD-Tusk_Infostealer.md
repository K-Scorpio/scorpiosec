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

* Platforme: CyberDefenders
* Lien: [Tusk Infostealer Lab](https://cyberdefenders.org/blueteam-ctf-challenges/tusk-infostealer/) 
* Niveau: Facile
* Categorie: Threat Intel
---

# Scénario

Une entreprise de développement blockchain a détecté une activité inhabituelle lorsqu’un employé a été redirigé vers un site web inconnu alors qu’il accédait à une plateforme de gestion de DAO. Peu de temps après, plusieurs portefeuilles de cryptomonnaies liés à l’organisation ont été vidés. Les enquêteurs soupçonnent l’utilisation d’un outil malveillant pour voler des identifiants et exfiltrer des fonds.

Votre mission consiste à analyser les renseignements fournis afin de comprendre les méthodes d’attaque, identifier les indicateurs de compromission et retracer l’infrastructure de l’acteur malveillant.

---

L'extraction de l'archive fournie produit un hachage MD5.

![file_hash](/images/CD-Tusk_InfoStealer/Tusk_hash.png)


```
E5B8B2CF5B244500B22B665C87C11767
```

---

# Q1 - En Ko, quelle est la taille du fichier malveillant?

## Méthodologie

L’enquête a débuté à partir du hachage MD5 fourni, utilisé comme indicateur de compromission (IOC) pour interroger une plateforme de renseignement sur les menaces.

Ce hachage a été recherché sur VirusTotal afin de récupérer les métadonnées et les résultats d’analyse associés au fichier.

## Observations

La recherche a permis d’identifier un fichier malveillant:

Nom du fichier: `madHcNet.dll`
Taux de détection: 45/72 éditeurs l’ont signalé comme malveillant

D’après les métadonnées du fichier, sa taille est de: `921,36 KB`.

![VirusTotal look up](/images/CD-Tusk_InfoStealer/VT_LOOKUP.png)

## Conclusion

La taille du fichier malveillant est de:

```
921.36 KB
```

# Q2 - Quel mot les acteurs malveillants utilisent-ils dans les logs pour désigner leurs victimes, en se basant sur le nom d’une ancienne créature chassée?


## Méthodologie

Pour mieux comprendre la terminologie et le comportement de l’acteur malveillant, des techniques de renseignement open-source (OSINT) ont été utilisées. En se basant sur le contexte de l’attaque (vol de cryptomonnaies et utilisation suspectée d’un infostealer), des recherches ont été menées sur des campagnes liées à Tusk Infostealer.

Des rapports de renseignement sur les menaces ont été identifiés grâce à des recherches ciblées, menant à une analyse publiée par [Kaspersky](https://www.kaspersky.com/about/press-releases/kaspersky-discovers-tusk-active-information-and-crypto-stealing-campaign).

## Observations

Le rapport a révélé que les auteurs de ces menaces utilisent un terme spécifique dans leurs journaux et leurs communications: «Mammoth» (du russe: _Мамонт_)

Point clés:

- Ce terme est un argot utilisé par des cybercriminels russophones
- Il désigne une victime
- Ce nom fait référence aux mammouths de l'Antiquité, chassés pour leurs ressources précieuses

Ce terme apparaît dans:

- les communications des logiciels malveillants
- les logs d'exfiltration de données

![Tusk report Kaspersky](/images/CD-Tusk_InfoStealer/Tusk_report.png)

## Conclusion

Le terme utilisé par les auteurs de la menace pour désigner leurs victimes est:

```
Mammoth
```

# Q3 - L'auteur de la menace a mis en place un site web malveillant imitant une plateforme destinée à la création et à la gestion d'organisations autonomes décentralisées (DAO) sur la blockchain MultiversX (peerme.io). Quel est le nom du site web malveillant créé par l'attaquant pour imiter cette plateforme ?

## Méthodologie

Afin d'identifier l'infrastructure de phishing utilisée dans le cadre de cette campagne, Des techniques d'OSINT ont été utilisé. Sur la base de conclusions antérieures établissant un lien entre cette activité et la campagne Tusk Infostealer, des rapports externes sur les menaces ont été examinés.

Une recherche ciblée sur Tusk a mené à un rapport publié sur [Securelist](https://securelist.com/tusk-infostealers-campaign/113367/), lequel fournit des informations détaillées sur l'infrastructure de la campagne.

## Observations

Le rapport a révélé que les cybercriminels ont créé un site web frauduleux destiné à se faire passer pour la plateforme légitime de gestion DAO `peerme.io`.

Le domaine malveillant identifié dans le cadre de cette campagne est: `tidyme.io`.

Ce domaine fait partie de la sous-campagne TidyMe, qui cible les utilisateurs de cryptomonnaies en imitant des services blockchain légitimes afin de récupérer des identifiants et de déployer des logiciels malveillants.

![TidyMe sub campaign](/images/CD-Tusk_InfoStealer/tidyme.png)

## Conclusion

Le site web malveillant utilisé par l'attaquant est:

```
tidyme.io
```

# Q4 - Quel service de stockage cloud les auteurs de la campagne ont-ils utilisé pour héberger les échantillons de logiciels malveillants destinés aux versions macOS et Windows ?

## Méthodologie

Pour déterminer où étaient hébergés les échantillons de logiciels malveillants, des sources d'informations OSINT ont été utilisé. Sur la base de conclusions antérieures établissant un lien entre cette activité et la campagne Tusk Infostealer, des rapports externes sur les menaces ont été examinés.

Les informations pertinentes ont été recueillies auprès de:

- Securelist
- Communiqué de presse de Kaspersky

## Observations

Les deux sources confirment que les auteurs de la menace ont utilisé un service de stockage en ligne pour diffuser des payload malveillants.

Principales observations:

- Les fichiers de chargement des malware étaient hébergés sur une plateforme cloud
- Les victimes ont été redirigées vers un lien leur permettant de télécharger ces fichiers
- Les chargeurs ont ensuite déployé d'autres logiciels malveillants (infostealers, clippers)

Le service identifié dans les deux rapports est: `Dropbox`.

![Dropbox for malware sample hosting](/images/CD-Tusk_InfoStealer/dropbox.png)

![Dropbox for malware sample hosting 2](/images/CD-Tusk_InfoStealer/dropbox2.png)

## Analyse

Le recours à un fournisseur de stockage en ligne légitime tel que Dropbox permet aux pirates de:

- Camoufler le trafic malveillant parmi les activités légitimes
- Contourner les filtres de sécurité de base
- Renforcer la confiance des victimes

Il s'agit d'une technique couramment utilisée dans les campagnes modernes de phishing et de diffusion de logiciels malveillants.

## Conclusion

Le service de stockage en ligne utilisé par les pirates pour héberger des échantillons de logiciels malveillants est:

```
Dropbox
```

# Q5 - Le fichier exécutable malveillant contient un fichier de configuration qui comprend des URL encodées en base64 ainsi qu'un mot de passe utilisé pour décompresser les données archivées, ce qui permet le téléchargement de payloads de deuxième phase. Quel est le mot de passe de décompression figurant dans ce fichier de configuration?

## Méthodologie

Afin d'identifier le mot de passe utilisé par le logiciel malveillant pour décompresser les payloads archivées, des sources d'informations OSINT ont été utilisé. Sur la base de conclusions antérieures établissant un lien entre cette activité et la campagne Tusk Infostealer, une analyse technique détaillée a été publiée sur Securelist.

Le rapport comprend une analyse détaillée du fichier de configuration interne du logiciel malveillant (`config.json`), qui contient les données codées utilisées lors de son exécution.

## Observations

L'analyse a révélé que le fichier exécutable malveillant (tidyme.exe) contient un fichier de configuration comprenant:

- des URL encodées en Base64 (utilisées pour télécharger des payloads de deuxième phase)
- un mot de passe servant à décompresser les données archivées

L'extrait pertinent de la configuration indique:

```JSON
{
  "password": "newfile2024"
}
```

![Archive decompression password](/images/CD-Tusk_InfoStealer/tusk_pwd.png)

## Analyse

Ce mot de passe est utilisé par le logiciel malveillant pour extraire des payloads supplémentaires après le téléchargement, ce qui permet de poursuivre la chaîne d'infection (par exemple, des infostealers et d'autres composants malveillants).

L'intégration de ces identifiants dans des fichiers de configuration est une technique couramment utilisée par les acteurs malicieux pour automatiser la diffusion de payload en plusieurs étapes.

## Conclusion

Le mot de passe utilisé pour décompresser l'archive est:

```
newfile2024
```

# Q6 - Quel est le nom de la fonction responsable du téléchargement de l'archive de données à partir du fichier de configuration?

## Méthodologie

Pour identifier la fonction chargée de récupérer le champ « archive » dans le fichier de configuration, des sources d'informations OSINT ont été utilisé. Sur la base des conclusions antérieures relatives à la campagne Tusk Infostealer, une analyse technique détaillée a été examinée sur Securelist.

Le rapport fournit des informations sur la structure interne et le comportement du logiciel malveillant, y compris la logique de son téléchargeur et la mise en œuvre de ses fonctions.

## Observations

L'analyse décrit la routine de téléchargement intégrée au logiciel malveillant, en mettant particulièrement en avant deux fonctions clés :

- `downloadAndExtractArchive`
- `loadFile`

Le rapport indique clairement que la fonction chargée de récupérer le champ `archive` dans le fichier de configuration est: `downloadAndExtractArchive`.

Cette fonction:

- Extrait la valeur `archive` du fichier de configuration
- Décode l'URL Dropbox intégrée (encodée en base64)
- Télécharge l'archive sur le système de la victime
- Utilise le mot de passe intégré pour en extraire le contenu


![Tusk download functions](/images/CD-Tusk_InfoStealer/tusk_function.png)

## Analyse

La fonction `downloadAndExtractArchive` joue un rôle central dans la chaîne d'exécution en plusieurs étapes du logiciel malveillant en automatisant:

- la récupération des payloads de deuxième étape
- le déchiffrement/la décompression du contenu archivé
- l'exécution de binaires malveillants supplémentaires

Cela reflète une conception modulaire couramment utilisée dans les campagnes modernes de vol d'informations.

## Conclusion

La fonction chargée de récupérer le champ `archive` est la suivante:

```
downloadAndExtractArchive
```

# Q7 - Dans la troisième sous-campagne menée par les opérateurs, l'attaquant s'est fait passer pour un projet de traducteur basé sur l'IA. Quel est le nom du traducteur légitime, et quel est celui du traducteur malveillant créé par les attaquants?

## Méthodologie

Pour identifier les plateformes utilisées dans la troisième sous-campagne, des sources d'informations OSINT ont été utilisé. Sur la base des conclusions antérieures relatives à la campagne Tusk Infostealer, une analyse détaillée a été examinée sur Securelist.

Le rapport décrit plusieurs sous-campagnes dans lesquelles les auteurs de menaces se font passer pour des services légitimes afin d'appâter leurs victimes.

## Observations

Dans le cadre de la troisième sous-campagne, les acteurs malveillants ont simulé un service de traduction basé sur l'IA.

Le rapport identifie:
- la plateforme légitime: `yous.ai`
- l'usurpation malveillante : `voico.io`

Le site malveillant imite fidèlement le projet légitime, tant au niveau de l'apparence que des fonctionnalités, afin d'inciter les utilisateurs à interagir avec lui.

![Tusk third sub-campaign](/images/CD-Tusk_InfoStealer/3rd_sub_campaign.png)

## Analyse

Cette technique est un exemple classique de:

- l'usurpation d'identité d'une marque
- l'ingénierie sociale via de faux services

En reproduisant une plateforme de traduction par IA légitime, les pirates renforcent la confiance des utilisateurs et augmentent les chances qu'ils interagissent avec le site, ce qui leur permet:

- de diffuser des logiciels malveillants
- de collecter des identifiants

## Conclusion

Les plateformes de traduction légitimes et malveillantes sont les suivantes:

```
Yous.ai, voico.io
```

# Q8 - Le programme de téléchargement a pour mission d'introduire d'autres logiciels malveillants sur la machine de la victime, principalement des programmes de vol d'informations tels que StealC et Danabot. Quelles sont les adresses IP des serveurs C2 de StealC utilisés dans le cadre de cette campagne?

## Méthodologie

Pour identifier l'infrastructure de commande et de contrôle (C2) utilisée dans le cadre de cette campagne, des sources d'informations OSINT ont été utilisé. Sur la base des conclusions antérieures relatives à la campagne Tusk Infostealer, une analyse détaillée a été examinée sur Securelist.

La section `Network IOCs` du rapport a été utilisé afin d'extraire les éléments d'infrastructure associés au logiciel malveillant.

## Observations

Le rapport répertorie plusieurs indicateurs réseau, notamment des adresses IP associées à différents éléments de la campagne.

Les adresses IP spécifiquement identifiées comme des serveurs C2 de StealC sont les suivantes:

> 46.8.238.240  
> 23.94.225.177

![C2 IP addresses](/images/CD-Tusk_InfoStealer/C2_IPs.png)

## Analyse

Ces adresses IP servent de serveurs de commande et de contrôle (C2) pour le logiciel de vol d'informations StealC, permettant ainsi aux acteurs malveillants de:

- Recevoir les données volées provenant des systèmes infectés
- Envoyer des commandes aux hôtes compromis
- Assurer la persistance et le contrôle des machines infectées


## Conclusion

Les adresses IP des serveurs C2 StealC utilisées dans le cadre de cette campagne sont les suivantes:

```
46.8.238.240, 23.94.225.177
```

# Q9 - Quelle est l'adresse du portefeuille de cryptomonnaie Ethereum utilisé dans cette campagne ?

## Méthodologie

Afin d'identifier l'infrastructure de cryptomonnaie utilisée par les auteurs de la menace, des sources d'informations OSINT ont été utilisé. Sur la base des conclusions antérieures relatives à la campagne Tusk Infostealer, une analyse détaillée a été examinée sur Securelist.

La section `Cryptocurrency wallet addresses` du rapport a été utilisé afin d'extraire les identifiants de portefeuilles associés à la campagne.

## Observations

Le rapport répertorie plusieurs adresses de portefeuilles de cryptomonnaies liées aux pirates, notamment des portefeuilles Bitcoin et Ethereum.

L'adresse du portefeuille Ethereum identifiée dans le cadre de cette campagne est la suivante:

> 0xaf0362e215Ff4e004F30e785e822F7E20b99723A

![Etherum address](/images/CD-Tusk_InfoStealer/ETH_address.png)

## Analyse

Ce portefeuille est utilisé par les attaquants pour:

- Recevoir des fonds en cryptomonnaie volés
- Regrouper les actifs provenant des victimes compromises
- Faciliter la réalisation de gains financiers issus de la campagne

Le suivi de ces adresses de portefeuille est essentiel pour:

- L'analyse de la blockchain
- Les efforts d'attribution
- La surveillance des transactions illicites


## Conclusion

L'adresse du portefeuille Ethereum utilisée dans le cadre de cette campagne est la suivante:

```
0xaf0362e215Ff4e004F30e785e822F7E20b99723A
```

