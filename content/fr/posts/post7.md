+++
title = "PXE: Un Outil pour Gérer les Environnements Informatiques de Grande Envergure"
date = 2024-02-04T15:42:38-06:00
draft = false
toc = true
tags = []
+++

## Introduction 

Vous êtes-vous déjà demandé comment les installations de systèmes d'exploitation ou la maintenance des systèmes sont gérées dans une vaste infrastructure informatique? Imaginez la situation suivante: vous travaillez dans le service informatique et vous êtes chargé de préparer les ordinateurs des nouveaux employés. Ces personnes travailleront dans différents services, chacun nécessitant un système d'exploitation spécifique. Comment aborderiez-vous cette tâche? Interviendriez-vous physiquement sur chaque ordinateur portable pour mener à bien le processus? Imaginez maintenant qu'il ne s'agisse pas seulement de 10, 20 ou 30 ordinateurs, mais aussi de serveurs, de commutateurs, de routeurs, de machines virtuelles, etc. La difficulté devient évidente.

PXE est une des solutions pour simplifier cette situation. Le processus de démarrage PXE (Pre-boot eXecution Environment) permet le démarrage d'une ordinateur à partir du réseau, le client récupère une image du système d'exploitation située sur un serveur. Cette image peut consister en un système d'exploitation de base ou être personnalisée avec divers éléments logiciels tels qu'une suite bureautique, des utilitaires, des packs de sécurité, des scripts, etc.

Couramment utilisé dans les environnements informatiques à grande échelle, PXE facilite les tâches telles que le déploiement de systèmes d'exploitation, la restauration de systèmes et les installations en réseau. En permettant à un ordinateur d'obtenir sa configuration réseau et les fichiers nécessaires, PXE lance le processus de démarrage sans dépendre des périphériques de stockage locaux. 

![PXE server diagram](/images/PXE-server-topology.png)
*Crédits pour l'image CC(ChenChih) sur medium.com*

## Configuration du serveur PXE  

PXE simpifie les configurations d'ordinateurs en grand nombre, en éliminant le besoin de CD ou de clés USB et en permettant l'installation d'une seule image de système d'exploitation sur plusieurs machines simultanément, ce qui vous permet de gagner du temps. Il utilise un serveur DHCP, un serveur TFTP et un serveur web. Le serveur DHCP attribue une adresse IP à l'ordinateur et fournit des informations sur le serveur PXE, notamment l'emplacement du serveur TFTP (Trivial File Transfer Protocol) pour le transfert des fichiers d'amorçage PXE aux clients pendant le processus d'amorçage.

Bien qu'un serveur web ne soit pas strictement nécessaire pour la fonctionnalité PXE de base, il devient essentiel lorsqu'il s'agit de configurations PXE plus avancées et du déploiement de systèmes d'exploitation qui s'appuient sur la récupération de fichiers via HTTP au cours du processus d'installation. Le serveur web est principalement utilisé pour stocker les fichiers d'installation, ce qui améliore considérablement les capacités de votre serveur PXE.

Pour de nombreux systèmes d'exploitation, en particulier les versions modernes de Windows et diverses distributions Linux, les fichiers d'installation sont trop volumineux pour être transférés uniquement par TFTP. Un serveur web est utilisé pour stocker ces fichiers et les rendre accessibles aux clients PXE pendant le processus d'installation. Passons maintenant aux aspects pratiques de la mise en place d'un serveur PXE.

### Préalables

Tout d'abord, assurez-vous que les conditions suivantes sont réunies:

1. Infrastructure du serveur :
* Un serveur dédié ou une machine virtuelle qui servira de serveur PXE.

2. Système d'exploitation :
* Choisir une distribution Linux pour le serveur PXE. Les choix les plus courants sont Ubuntu Server, CentOS ou Debian.

3. Configuration du réseau :
* Établir un réseau stable avec DHCP configuré pour allouer des adresses IP aux clients PXE.
* Établir un segment de réseau isolé ou un VLAN dédié au trafic lié au PXE afin d'améliorer la sécurité.

### Étapes de configuration d'un serveur PXE

1. Serveur DHCP: Installer et configurer un serveur DHCP pour fournir des adresses IP aux clients PXE. Assurez-vous que les options DHCP sont définies pour indiquer l'emplacement du serveur PXE et des fichiers de démarrage.
```
sudo apt-get install isc-dhcp-server
```

2. Serveur TFTP: Installer un serveur TFTP pour transférer les fichiers de démarrage PXE aux clients pendant le processus de démarrage.
```
sudo apt-get install tftpd-hpa
```

3. Serveur web: Configurer un serveur web pour héberger les fichiers d'installation de divers systèmes d'exploitation.
```
sudo apt-get install apache2
```

4. Configurer le serveur DHCP : Modifier le fichier de configuration du serveur DHCP pour y inclure les paramètres spécifiques à PXE. Par exemple, dans le fichier /etc/dhcp/dhcpd.conf:
```
option domain-name "example.com";
option domain-name-servers ns1.example.com, ns2.example.com;

subnet 192.168.1.0 netmask 255.255.255.0 {
  range 192.168.1.100 192.168.1.200;
  option routers 192.168.1.1;
  option broadcast-address 192.168.1.255;
  option subnet-mask 255.255.255.0;
  filename "pxelinux.0";
  next-server 192.168.1.10; # PXE Server IP
}
```

5. Configurer le serveur TFTP : Modifiez le fichier de configuration du serveur TFTP (généralement situé dans /etc/default/tftpd-hpa) pour définir le répertoire racine du TFTP:
```
TFTP_USERNAME="tftp"
TFTP_DIRECTORY="/var/lib/tftpboot"
TFTP_ADDRESS="0.0.0.0:69"
TFTP_OPTIONS="--secure"
```

6. Préparer les fichiers d'amorçage PXE: Téléchargez les fichiers d'amorçage PXE, tels que PXELinux, à partir du site web officiel ou des dépôts de paquets. Placez ces fichiers dans le répertoire racine TFTP (/var/lib/tftpboot).
```
sudo mkdir /var/lib/tftpboot
sudo wget https://www.syslinux.org/wiki/uploads/attachments/syslinux-6.04-pre1.tar.xz
sudo tar -xvf syslinux-6.04-pre1.tar.xz
sudo cp syslinux-6.04-pre1/bios/core/pxelinux.0 /var/lib/tftpboot
sudo cp syslinux-6.04-pre1/bios/com32/elflink/ldlinux/ldlinux.c32 /var/lib/tftpboot
sudo cp syslinux-6.04-pre1/bios/com32/lib/libcom32.c32 /var/lib/tftpboot
sudo cp syslinux-6.04-pre1/bios/com32/libutil/libutil.c32 /var/lib/tftpboot
```

7. Configurer le serveur web: Copiez les fichiers d'installation pour les systèmes d'exploitation souhaités (Windows, distributions Linux) dans le répertoire racine du serveur web (par exemple, /var/www/html pour Apache).

8. Tester le démarrage PXE: 
* Démarrer les services DHCP et TFTP:
```
sudo systemctl restart isc-dhcp-server
sudo systemctl restart tftpd-hpa
```
* S'assurer que le serveur web fonctionne:
```
sudo systemctl restart apache2
```
* Démarrer un client compatible PXE et vérifiez qu'il lance avec succès le processus de démarrage PXE.

Après ces étapes, vous disposez maintenant d'un serveur PXE prêt à l'emploi. 

## Considérations en matière de sécurité

### Vulnérabilités

Bien que PXE soit une technologie pratique et efficace, elle comporte des vulnérabilités potentielles. En voici quelques unes et les contre-mesures correspondantes:

* Accès non autorisé: Des acteurs malveillants pourraient tenter d'obtenir un accès non autorisé au serveur PXE, en injectant ou en modifiant les fichiers de démarrage afin de compromettre l'intégrité des installations du système d'exploitation.

* Attaques de l'homme du milieu (HDM) ou man-in-the-middle attack (MITM): Les attaquants peuvent intercepter les communications entre le serveur PXE et les machines clientes, ce qui leur permet de manipuler ou de surveiller le processus d'installation.

* Usurpation du protocole DHCP (DHCP Spoofing): Si un attaquant réussit à usurper les réponses DHCP, il peut rediriger les clients PXE vers un autre serveur PXE sous son contrôle, ce qui conduit à des installations non autorisées du système d'exploitation ou à une exploitation potentielle.

> Si vous voulez lire sur une vulnérabilité PXE, consultez [CVE-2020-3284](https://nvd.nist.gov/vuln/detail/CVE-2020-3284)

### Contre-mesures

* Sécuriser le serveur PXE: Mettre en place des contrôles d'authentification et d'accès robustes pour le serveur PXE. Mettez régulièrement à jour et corrigez le système d'exploitation et les logiciels du serveur afin de remédier aux vulnérabilités connues.

* Cryptage: Utiliser des protocoles de chiffrement (tels que HTTPS) pour sécuriser les communications entre le serveur PXE et les clients. Cela permet de se prémunir contre les attaques de type "man-in-the-middle" et de garantir l'intégrité des fichiers de démarrage.

* Segmentation du réseau: Utiliser la segmentation du réseau pour isoler le serveur PXE des réseaux non fiables. Cette stratégie limite la surface d'attaque potentielle et réduit le risque d'accès non autorisé.

* Signatures numériques: Signer les fichiers de démarrage avec des signatures numériques pour vérifier leur authenticité. N'autoriser l'installation que d'images de systèmes d'exploitation signées et vérifiées, ce qui réduit le risque d'injection ou d'altération de fichiers.

* Sécurité DHCP: Mettre en œuvre le snooping DHCP et l'inspection ARP dynamique (DAI) pour prévenir les attaques par usurpation d'identité DHCP. Cette mesure garantit que les clients PXE reçoivent des réponses DHCP valides de la part de serveurs légitimes.

* Surveillance et journalisation: Surveiller et journaliser régulièrement les activités du serveur PXE afin de détecter tout comportement inhabituel ou suspect, et de fournir des indicateurs précoces d'incidents de sécurité potentiels.

* Mots de passe Firmware/BIOS: Définissez des mots de passe complexes pour les paramètres du micrologiciel/BIOS afin d'empêcher toute modification non autorisée. Cette étape permet de se protéger contre la falsification des paramètres de démarrage PXE sur des machines individuelles.

En mettant en œuvre ces contre-mesures, vous pouvez renforcer la sécurité de votre déploiement PXE et réduire le risque d'exploitation par des acteurs malveillants. Si vous souhaitez obtenir plus de détails sur les mesures de sécurité, Microsoft propose un ensemble de méthodes disponibles [ici](https://learn.microsoft.com/en-us/mem/configmgr/osd/plan-design/security-and-privacy-for-operating-system-deployment).

## Automatisation

Un serveur web vous permet d'héberger des scripts personnalisés, des fichiers de démarrage, des fichiers preseed ou d'autres fichiers de configuration qui automatisent le processus d'installation. Cette capacité est particulièrement précieuse pour les installations sans surveillance et la personnalisation.

Les fichiers de réponse pour Windows et les fichiers preseed pour Ubuntu sont des fichiers de configuration utilisés dans les installations sans surveillance. Ces fichiers contiennent des réglages et des paramètres qui automatisent le processus d'installation, éliminant ainsi le besoin d'interaction de l'utilisateur pendant l'installation du système d'exploitation.

### Fichiers de réponse (Answer files) pour Windows

1. Unattend.xml (Windows Vista et versions ultérieures):
* Pour Windows Vista et les versions ultérieures, y compris les éditions Windows Server, l'installation sans surveillance est généralement contrôlée par un fichier XML appelé Unattend.xml.
* Ce fichier contient des paramètres tels que la clé de produit, le fuseau horaire, les comptes d'utilisateurs, etc.

2. Sysprep:
Avant de créer une image pour le déploiement, on utilise souvent l'outil de préparation du système (Sysprep) pour généraliser l'installation de Windows. Pendant Sysprep, vous pouvez spécifier un fichier de réponse qui sera utilisé lors du prochain démarrage pour configurer le système.

3. Kit de déploiement et d'évaluation Windows:
* Utilisez l'invite de commande des outils de déploiement (qui fait partie du kit d'évaluation et de déploiement Windows - ADK) pour générer et modifier les fichiers de réponse.
* Windows SIM (System Image Manager) est couramment utilisé pour la création et la modification des fichiers de réponse.

### Fichiers Preseed pour Ubuntu

1. Fichier de configuration Preseed:
* Pour les systèmes Ubuntu et Debian, le fichier preseed est utilisé pour automatiser le processus d'installation.
* Le fichier est généralement nommé preseed.cfg ou un nom similaire et contient des instructions sur le partitionnement, la sélection des paquets, la création d'utilisateurs et d'autres options d'installation.

2. Emplacement du fichier Preseed:
* Au cours du processus de démarrage PXE, le programme d'installation recherche le fichier preseed à un emplacement spécifique. Par exemple, il peut se trouver à l'adresse http://example.com/preseed.cfg sur un serveur web.

3. Configuration DHCP:
* La configuration DHCP de votre serveur PXE doit inclure une option permettant de spécifier l'emplacement du fichier preseed. Par exemple, dans la configuration DHCP, vous pouvez définir:
```
option preseed-url "http://example.com/preseed.cfg";
```

### Utilisation des fichiers Answer et Preseed avec PXE

1. Créer des fichiers de réponse/Preseed: Utiliser des outils tels que Windows SIM pour Windows ou créer manuellement un fichier preseed pour Ubuntu. Ces fichiers définissent les options de configuration pour l'installation sans surveillance.

2. Placez les fichiers sur le serveur Web: Héberger le fichier de réponse (par exemple, Unattend.xml pour Windows ou preseed.cfg pour Ubuntu) sur un serveur web accessible aux clients PXE.

3. Configurer le serveur PXE : Modifier la configuration du serveur PXE pour inclure l'URL ou le chemin d'accès au fichier de réponse ou au fichier preseed. Cette opération s'effectue généralement dans le fichier de configuration du serveur PXE ou dans les options DHCP. Par exemple, dans un fichier de configuration PXE, vous pouvez spécifier l'emplacement du fichier de réponse Windows comme suit:
```
APPEND  ... inst.ks=http://example.com/Unattend.xml
```

* Dans la configuration DHCP, vous pouvez spécifier l'emplacement du fichier Ubuntu preseed:
```
option preseed-url "http://example.com/preseed.cfg";
```

4. Tester l'installation :
* Démarrer une machine cliente via PXE et observez le processus d'installation automatisé. Le programme d'installation récupère le fichier de réponse ou le fichier preseed à l'emplacement spécifié et l'utilise pour configurer les paramètres d'installation.

L'utilisation de fichiers de réponse ou de fichiers preseed avec PXE permet un déploiement efficace et automatisé des systèmes d'exploitation.

## Conclusion

En conclusion, PXE est une excellente technologie capable de gérer des environnements informatiques divers et vastes. Elle permet de simplifier le déploiement et la maintenance des systèmes d'exploitation. PXE est utilisé à diverses fins, notamment pour le déploiement de systèmes d'exploitation, la récupération de systèmes, la maintenance, les déploiements automatisés et la création d'images. J'espère vous avoir donné un aperçu détaillé de cette technologie. J'ai l'intention de réaliser un projet autour d'elle. Après avoir créé un réseau avec un serveur PXE et déployé plusieurs systèmes d'exploitation sur des machines virtuelles, j'essaierai de démontrer les vulnérabilités du réseau et d'appliquer des contre-mesures pour améliorer la sécurité du serveur. Restez à l'écoute et à la prochaine!
