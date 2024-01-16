+++
title = "Comprendre la Structure des Répertoires Linux"
date = 2024-01-14T20:05:43-06:00
draft = false
toc = true
categories = ['Operating Systems']
tags = ['Linux', 'Filesystem']
+++

## Hiérarchie des fichiers sous Linux

La connaissance de Linux est indispensable pour les professionnels de la cybersécurité. Vous remarquerez que Linux est différent de Windows dans la façon dont les fichiers sont organisés. La norme de hiérarchie du système de fichiers (FHS) entretenue par la Fondation Linux établit un modèle pour la structure des répertoires. Bien qu'il puisse y avoir quelques variations entre les distributions Linux, elles adhèrent généralement à cette norme. Pour améliorer vos compétences Linux, une compréhension du système de fichiers est essentielle. Dans cet article, nous allons explorer le système de fichiers Linux.

> Il ne s'agit pas d'une liste exhaustive, nous examinerons les répertoires les plus communs.

![Linux Filesystem Overview](/images/Linux-File-Hierarchy-Structure.png)
*Linux Filesystem Overview*

## / (Root)

Au cœur de la hiérarchie du système de fichiers Linux se trouve le répertoire root, représenté par le symbole "/". Ce répertoire est le point de départ de tout le système de fichiers. 
* Tous les fichiers et répertoires ont pour point de départ le répertoire root.
* Seul l'utilisateur root dispose des permissions nécessaires pour modifier les fichiers de ce répertoire.
* Le répertoire personnel de l'utilisateur root est /root.
* L'exécution de `ls -l /` affiche le contenu du répertoire root.

## /bin & /sbin

Ces répertoires contiennent des fichiers binaires essentiels et des commandes système. Bien que les deux répertoires contiennent des fichiers binaires, ils diffèrent principalement par le type de binaires qu'ils contiennent.

Le répertoire /bin, dérivé de "binary", est réservé au stockage des fichiers binaires essentiels aux fonctions basiques du système d'exploitation. Ces binaires sont nécessaires pour les interactions avec l'utilisateur et sont souvent utilisés en mode mono-utilisateur. Les commandes courantes telles que ls (liste des fichiers), cp (copie) et mv (déplacement) se trouvent dans ce répertoire.

À l'inverse, le répertoire /sbin, qui représente "system binary", contient des binaires conçus exclusivement pour les tâches d'administration et de maintenance du système. Contrairement aux binaires du répertoire /bin, ceux du répertoire /sbin sont généralement destinés à l'administrateur du système plutôt qu'aux utilisateurs ordinaires. Les binaires système essentiels pour des tâches telles que la récupération, la réparation et le diagnostic du système sont hébergés dans ce répertoire.

| **/bin** | **/sbin** |
| -------- | --------- |
| Contient des commandes linux courantes utilisées en mode mono-utilisateur telles que ps, ls, ping, grep, cp, etc. | Contient des commandes typiquement utilisées par les administrateurs système telles que iptables, reboot, fdisk, ifconfig, swapon, etc. |

## /boot

Le répertoire /boot contient des fichiers indispensables au processus de démarrage du système d'exploitation. Les fichiers du chargeur de démarrage et le noyau Linux sont stockés dans ce répertoire. Le chargeur d'amorçage (bootloader) est chargé de lancer le système d'exploitation au cours du processus de démarrage. La corruption ou la suppression de certains fichiers dans ce répertoire peut empêcher le démarrage correct de votre système.

## /dev

Le répertoire /dev sert de passerelle vers les fichiers périphériques qui représentent les périphériques matériels connectés au système. Contrairement aux fichiers ordinaires, ces fichiers périphériques agissent comme des interfaces, permettant la communication entre le système d'exploitation et les composants matériels.

Le nom "/dev" est l'abréviation de "device", et ce répertoire agit comme un système de fichiers virtuel contenant des entrées pour chaque périphérique ou pseudo-périphérique connecté au système. Ces entrées sont représentées sous forme de fichiers spéciaux, ce qui permet aux processus d'interagir avec le périphérique par le biais d'opérations d'entrée et de sortie standardisées.

Dans le répertoire /dev, vous trouverez différents fichiers périphériques. Quelques-uns d'entre eux sont décrits ci-dessous :
* */dev/fd* - Périphériques de disquette
* */dev/tty* - Périphériques de terminal représentant les ports de console et de série  
* */dev/sda* (1,2,3, etc.) - Périphériques de disque représentant les disques durs
* */dev/usb* (1,2,3, etc.) - entrées de périphériques USB

## /etc

Le répertoire /etc sert de centre pour les fichiers de configuration qui dictent le comportement du système d'exploitation, des services système et des applications installées. Ces fichiers de configuration sont souvent des fichiers texte et permettent de personnaliser les paramètres des différents composants.

Linux adhère au principe de séparation des fichiers de configuration et des fichiers exécutables en centralisant les fichiers de configuration dans le répertoire /etc. Cette séparation facilite l'administration du système, puisque les modifications et les mises à jour des paramètres peuvent être effectuées sans altérer la fonctionnalité de base des programmes associés. Dans ce répertoire, vous trouverez:
* */etc/passwd* - Contient les informations relatives aux comptes d'utilisateurs, y compris les noms d'utilisateurs, les identifiants et les répertoires personnels (vos mots de passe ne se trouvent pas dans ce répertoire)
* */etc/hosts* - Correspondance entre les adresses IP et les noms d'hôtes, facilitant la résolution des noms d'hôtes locaux
* */etc/shadow* - Stocke les mots de passe des utilisateurs dans un format crypté
* */etc/network/* - Fichiers de configuration pour les paramètres réseau, y compris les interfaces et le routage

## /home

Le répertoire /home fonctionne comme un espace privé pour chaque utilisateur, englobant les répertoires personnels de chaque utilisateur tels que Documents, Téléchargements, Bureau, Images, etc. Son objectif premier est de fournir un espace dédié au stockage des fichiers, documents et paramètres personnels de chaque utilisateur. Lorsqu'un nouveau compte utilisateur est créé, un répertoire correspondant est établi dans /home, constituant l'environnement unique de l'utilisateur.

## /lib 

Le répertoire /lib contient des bibliothèques partagées et des modules du noyau. Abréviation de "library" (bibliothèque), ce répertoire assure la disponibilité de ressources essentielles au fonctionnement de divers programmes et applications sur un système Linux, tels que les binaires contenus dans /bin et /sbin.

Les bibliothèques partagées, également connues sous le nom de bibliothèques de liens dynamiques, sont des modules de code compilé que plusieurs programmes peuvent utiliser simultanément. Le fait de placer ces bibliothèques partagées dans /lib garantit qu'elles sont facilement accessibles aux applications qui en dépendent, ce qui favorise l'efficacité et l'optimisation des ressources.

Les modules de noyau, qui augmentent la fonctionnalité du noyau Linux, sont également stockés dans /lib. Ces modules peuvent être chargés ou déchargés dynamiquement selon les besoins, ce qui améliore l'adaptabilité et la polyvalence du système d'exploitation.

## /media

Le répertoire /media est un point de montage pour les périphériques amovibles tels que les clés USB, les disques durs externes et les disques optiques. Il agit comme une zone de stockage temporaire pour ces périphériques, /media permet aux utilisateurs d'accéder à leur contenu et de le gérer facilement.

Il joue un rôle crucial en fournissant un emplacement standardisé pour le montage des périphériques de stockage externes et amovibles. Lorsqu'un utilisateur connecte une clé USB ou insère un disque optique, le système d'exploitation monte le périphérique dans un sous-répertoire de /media, créant ainsi un point d'accès permettant aux utilisateurs de contrôler le contenu.

## /mnt 

Le répertoire /mnt sert de point de montage générique pour les systèmes de fichiers temporaires et les systèmes de fichiers décentralisés. Contrairement au répertoire /media, qui est spécifiquement conçu pour les supports amovibles, /mnt est un emplacement flexible et géré manuellement qui permet aux utilisateurs et aux administrateurs de monter différents systèmes de fichiers en fonction des besoins.

Le répertoire /mnt sert de zone de transit pour le montage temporaire de systèmes de fichiers supplémentaires, qu'ils soient locaux ou décentralisés. Cette flexibilité fait de /mnt un emplacement polyvalent permettant d'accéder à des données provenant de différentes sources, telles que des partages réseau, des lecteurs externes ou des systèmes de fichiers destinés à une utilisation temporaire.

Le répertoire /media est dédié au montage automatique des périphériques amovibles, tandis que le répertoire /mnt offre une approche plus manuelle et personnalisable, permettant aux utilisateurs de monter et d'accéder à divers systèmes de fichiers en fonction de leurs besoins spécifiques.

## /opt

Le répertoire /opt est destiné à l'installation de logiciels optionnels ou complémentaires. Abrégé de "optional", /opt fournit un emplacement uniformisé pour les applications tierces qui ne font pas partie du système principal, mais qui sont ajoutées pour améliorer les fonctionnalités du système d'exploitation.

Le répertoire /opt est un espace dédié aux vendeurs et développeurs de logiciels qui leur permet d'installer leurs applications sans interférer avec les fichiers et répertoires standard du système. Cette séparation permet de s'assurer que les logiciels optionnels ne perturbent pas les composants centraux du système et qu'ils respectent une structure d'installation cohérente.

Les applications installées dans /opt ont généralement leurs propres sous-répertoires, qui contiennent les binaires, les bibliothèques, la documentation et les autres ressources nécessaires. Cette organisation simplifie la gestion et la suppression des logiciels optionnels et favorise une approche propre et modulaire de l'extension des capacités du système Linux.

## /tmp

Le répertoire /tmp est un emplacement de stockage temporaire pour les fichiers nécessaires au fonctionnement du système. Abréviation de "temporary", /tmp est destiné au stockage de données transitoires dont les applications, les processus ou les utilisateurs peuvent avoir besoin et qui sont automatiquement effacées au redémarrage du système.

Il s'agit d'un espace partagé pour le stockage des fichiers temporaires, qui facilite la communication entre les différents processus et permet aux applications de créer et de manipuler des données temporaires selon leurs besoins. Les principales caractéristiques de /tmp sont sa nature éphémère et l'absence de stockage persistant, ce qui en fait un emplacement idéal pour les besoins de stockage à court terme.

## /usr

Le répertoire /usr est un composant fondamental du système de fichiers Linux, abritant les ressources liées à l'utilisateur, les programmes secondaires de l'utilisateur et les données. Abréviation de "Unix System Resources", /usr englobe un large éventail de répertoires, chacun contribuant à la fonctionnalité et à l'organisation globales du système d'exploitation Linux.

Le répertoire /usr est conçu pour contenir les ressources liées à l'utilisateur et les programmes secondaires de l'utilisateur qui ne sont pas essentiels au démarrage et à la réparation du système. Il joue un rôle crucial en séparant les binaires du système central dans /bin et /sbin des programmes et ressources supplémentaires qui améliorent l'expérience de l'utilisateur.

## Conclusion 

Cette vue d'ensemble n'est que la partie émergée de l'iceberg. Vous pouvez explorer plus en profondeur chaque répertoire pour approfondir votre compréhension de la hiérarchie du système de fichiers Linux. Si vous cherchez des livres, je vous suggère [How Linux Works, What Every Superuser Should Know, 3rd Edition](https://www.amazon.com/How-Linux-Works-Brian-Ward/dp/1718500408) et [The Linux Command Line, 2nd Edition : A Complete Introduction](https://linuxcommand.org/tlcl.php) (le second livre est gratuit).

J'espère que cet article de blog vous a été utile. N'arrêtez pas d'apprendre!
