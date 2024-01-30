+++
title = "Comparaison des Modèles Réseau: OSI vs. TCP/IP"
date = 2024-01-28T14:23:09-06:00
draft = false
toc = true
tags = ['Networking']
+++

## Introduction 

Comprendre les réseaux informatiques est une compétence indispensable pour la plupart des professionnels évoluant dans le domaine des technologies de l’information. Deux modèles majeurs sont au cœur de cette compréhension : le modèle d’interconnexion des systèmes ouverts (OSI) et le modèle de protocole de contrôle de transmission/protocole Internet (TCP/IP). Ces modèles OSI et TCP/IP servent de références pour la conception, la mise en œuvre et la maintenance des réseaux informatiques. Ils représentent des plans directeurs qui facilitent la communication entre les différents composants d'un réseau. Dans cet article, nous allons examiner ces deux modèles, explorer les différentes couches qui les composent, et comprendre leurs fonctionnalités respectives.

## OSI Model

![OSI Model](/images/OSI-7-layers.jpg)

Le modèle d'interconnexion des systèmes ouverts (OSI) constitue un schéma de base pour la compréhension et la conceptualisation de la communication en réseau. Introduit par l'Organisation internationale de normalisation (ISO), le modèle OSI est structuré en sept couches distinctes, chacune ayant une fonction spécifique dans la transmission des données.

1. **Couche Physique** 

La base du modèle OSI est la couche physique, où les éléments tangibles de la communication réseau entrent en jeu. Les câbles, les connecteurs et les composants matériels sont les éléments centraux de cette couche, qui déterminent la manière dont les [bits](https://www.ionos.fr/digitalguide/sites-internet/developpement-web/quest-ce-quun-bit/) sont transmis sur les différents supports.

2. **Couche de Liaison de Données**

La couche liaison de données offre un mécanisme de détection et de correction des erreurs au sein de la couche physique. Cette couche est chargée d'organiser les bits en trames et supervise les échanges d'informations entre deux machines reliées directement l'une à l'autre ou connectées à un dispositif simulant une connexion directe, tel qu'un commutateur. Vous y trouverez des protocoles et des technologies tels qu'Ethernet, MAC/LLC, VLAN, etc.

3. **Couche Réseau**

La couche réseau établit le concept d'adressage logique, comme les adresses IP. Elle assure la gestion du routage des paquets de données entre les appareils situés sur différents réseaux, ce qui permet la communication entre divers systèmes. Les équipements de cette couche font usage du protocole Internet (IP), IPsec, et autres. 

4. **Couche Transport** 

La couche transport garantit la fiabilité des communications de bout en bout en segmentant et réassemblant les données en portions gérables. Elle s'occupe de divers aspects tels que le contrôle du flux, la récupération des erreurs et l'accusé de réception des données reçues. Les protocoles de cette couche sont chargés de transporter les données entre les appareils, avec les protocoles les plus courants étant TCP et UDP.

5. **Couche Session** 

Pour établir une communication entre deux appareils, une application doit initier une session, une entité unique liée à l'utilisateur et l'identifiant sur le serveur distant.

La durée de la session doit être suffisamment longue pour permettre le transfert des données, mais elle doit être clôturée une fois le transfert terminé. Lorsque des volumes importants de données sont en cours de transfert, la session a pour responsabilité de garantir que le fichier est transféré intégralement, et de rétablir la transmission en cas d'incomplétude des données.

Par exemple, si 10 Mo de données sont en cours de transfert et que seulement 5 Mo sont complets, la couche session garantit que seuls les 5 Mo complets sont retransmis en cas d'incomplétude des données. Cette approche du transfert optimise l'efficacité de la communication sur le réseau en évitant le gaspillage de ressources et en limitant la retransmission à la partie nécessaire du fichier. 

6. **Couche Présentation** 

La couche présentation prépare les données pour l'affichage. Deux applications différentes utilisent souvent des codages différents.

Par exemple, lors d'une communication avec un serveur web via HTTPS, les informations sont chiffrées. La couche présentation est responsable de l'encodage et du décodage des informations afin qu'elles puissent être lues. En plus de cela, elle gère la compression et la décompression des données lorsqu'elles sont transférées d'un appareil à l'autre.

7. **Couche Application** 

Au sommet du modèle OSI se trouve la couche application, l'interface entre le réseau et l'utilisateur. Cette couche facilite la communication entre les applications logicielles, permettant aux utilisateurs d'interagir avec les services du réseau. La plupart des utilisateurs sont familiers avec certaines technologies de cette couche, telles que le protocole de transfert hypertexte (HTTP), le protocole de transfert de courrier simple (SMTP) et le système de noms de domaine (DNS). C'est cette couche qui permet d'interagir avec les sites internets et les applications.

> L'une des caractéristiques du modèle OSI est sa nature hiérarchique. Chaque couche s'appuie sur les fonctionnalités des couches inférieures, créant un système structuré et modulaire pour la conception des réseaux. Cette organisation permet une flexibilité et une évolutivité qui en font une excellente référence pour les architectes et les administrateurs de réseaux. Le modèle OSI fournit une structure universelle pour comprendre et construire des systèmes de communication en réseau, indépendamment des protocoles ou des technologies spécifiques.

## TCP/IP Model

![TCP/IP Model Model](/images/The-TCP-IP-five-layer-model.png)

Le modèle TCP/IP (Transmission Control Protocol/Internet Protocol) s'est imposé comme le standard pour la conception et la mise en œuvre de réseaux Internet. Issu du développement de l'ARPANET, le modèle TCP/IP est réputé pour sa simplicité et son efficacité. Contrairement aux sept couches du modèle OSI, le modèle TCP/IP condense le processus de communication réseau en cinq couches, offrant ainsi une approche simplifiée et pratique.

1. **Couche Physique**

Dans le modèle TCP/IP, la couche physique englobe les mêmes fonctions que la couche correspondante dans le modèle OSI. Elle traite de la connexion physique entre les appareils, en spécifiant des détails tels que les types de câbles, les connecteurs et les interfaces matérielles.

2. **Couche de Liaison de Données**

La couche de liaison de données TCP/IP assure une communication sans erreur entre les appareils d'un même réseau local, à l'aide de protocoles tels que Ethernet, MAC et LLC. Elle joue un rôle crucial dans le traitement des données, la détection des erreurs et la gestion de l'adressage des appareils pour une communication efficace sur le réseau local.

3. **Couche Réseau**

Tout comme le modèle OSI, la couche réseau du modèle TCP/IP gère l'adressage logique et le routage. C'est là qu'entre en jeu le protocole Internet (IP), qui gère la livraison des paquets de données sur différents réseaux.

4. **Couche Transport**

La couche transport du modèle TCP/IP ressemble beaucoup à son homologue du modèle OSI. Elle est responsable de la communication de bout en bout et assure la livraison fiable et ordonnée des données entre les appareils. Le protocole de contrôle de transmission (TCP) et le protocole de datagramme de l'utilisateur (UDP) fonctionnent à cette couche.

5. **Couche Application**

En tête du modèle TCP/IP se trouve la couche application, qui englobe les fonctionnalités des trois couches supérieures du modèle OSI (Session, Présentation et Application). Cette couche sert d'interface entre les services du réseau et les applications de l'utilisateur, en gérant la communication entre le logiciel et les couches inférieures.

> L'un des principaux atouts du modèle TCP/IP réside dans sa simplicité. En consolidant les sept couches du modèle OSI en cinq, le modèle TCP/IP optimise l'architecture du réseau, ce qui le rend plus intuitif pour une mise en œuvre dans le monde réel. Cette adaptabilité a contribué à l'adoption généralisée du modèle TCP/IP comme fondement de l'internet moderne.

## OSI vs. TCP/IP

![OSI vs TCP/IP Model](/images/Network-Models.png)

### OSI 

* Le modèle OSI, avec ses couches détaillées, s'avère inestimable dans les premières étapes de la conception d'un réseau. Les architectes peuvent utiliser ce modèle comme un plan pour organiser et structurer les différents composants d'un réseau. De plus, le modèle OSI est conçu pour être indépendant des protocoles, ce qui signifie qu'il peut être appliqué à n'importe quelle technologie de réseau.

* Le modèle OSI est largement utilisé dans l'éducation pour enseigner les fondamentaux des réseaux. Ses sept couches fournissent un cadre complet permettant aux étudiants de saisir les subtilités de la communication en réseau. Cependant, sa nature théorique peut être perçue comme complexe dans les applications du monde réel.

* L'un des principaux atouts du modèle OSI réside dans sa capacité à compartimenter les fonctionnalités du réseau en couches distinctes. Lors du dépannage d'un réseau, cette stratification est un atout. En isolant les problèmes dans des couches spécifiques, les professionnels de l'informatique peuvent localiser plus efficacement la source des problèmes. Par exemple, les problèmes de la couche de liaison de données peuvent concerner le matériel ou le câblage, tandis que les problèmes de la couche de transport peuvent être liés à des erreurs de protocole ou de configuration.

### TCP/IP 

* Le modèle TCP/IP est le pilier de l'internet. Sa structure simplifiée, composée de cinq couches, s'aligne parfaitement sur les protocoles qui régissent la communication sur l'internet.

* Connu pour sa simplicité, le modèle TCP/IP est privilégié pour la mise en œuvre dans le monde réel. Il offre une approche pratique et directe de la mise en réseau, ce qui le rend adapté à un large éventail d'applications. Sa capacité d'adaptation lui a valu d'être largement adopté dans divers environnements de mise en réseau.

* Le modèle TCP/IP est basé sur des protocoles spécifiques tels que TCP et IP, qui sont dominants dans l'internet. Cependant, comme le modèle combine de nombreuses fonctions dans la couche application, le dépannage à ce niveau peut s'avérer difficile. Si quelqu'un pense qu'il y a un problème à ce niveau, il faudra peut-être creuser un peu plus, car il encapsule de nombreux protocoles et fonctionnalités différents.

## Conclusion 

Les modèles OSI et TCP/IP ont tous deux des applications dans la conception de réseaux, le dépannage et la mise en œuvre dans le monde réel. La stratification du modèle OSI s'avère avantageuse dans les contextes éducatifs, tandis que la simplicité du modèle TCP/IP brille dans les environnements pratiques et réels. Chaque modèle apporte son lot de points forts, et les professionnels doivent considérer le contexte, les exigences et les objectifs de leurs projets de mise en réseau. 

Nous n'avons fait que survoler chaque modèle et leurs différentes couches, je vous encourage à continuer à explorer le domaine passionnant des réseaux, en particulier si vous aspirez à exercer dans ce domaine. Si vous souhaitez rafraîchir et approfondir vos compétences en la matière, je vous recommande ces deux livres [The TCP/IP Guide: A Comprehensive, Illustrated Internet Protocols Reference](https://www.amazon.com/TCP-Guide-Comprehensive-Illustrated-Protocols/dp/159327047X#customerReviews) et [Attacking Network Protocols: A Hacker's Guide to Capture, Analysis, and Exploitation](https://www.amazon.com/Attacking-Network-Protocols-Analysis-Exploitation/dp/1593277504).

Merci d'avoir pris le temps de lire cet article. Si vous avez d'autres questions ou si vous souhaitez que j'aborde des sujets spécifiques à l'avenir, n'hésitez pas à me contacter. D'ici là, continuez à apprendre!
