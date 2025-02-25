---
date: 2025-01-13T21:00:11-06:00
# description: ""
image: "/images/THM-SilverPlatter/SilverPlatter.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: Silver Platter"
type: "post"
---

* Platforme: TryHackMe
* Lien: [Silver Platter](https://tryhackme.com/r/room/silverplatter)
* Niveau: Facile
* OS: Linux
---

Silver Platter est une machine toute simple qui commence par des services `http` fonctionnant sur deux ports différents, dont l'un révèle un nom d'utilisateur potentiel. Grâce à l'énumération, nous découvrons une page de connexion pour Silverpeas. Nous utilisons une liste de mots de passe personnalisée pour identifier les identifiants valides, ce qui nous permet d'accéder au tableau de bord. En poursuivant nos recherches, nous trouvons le `CVE-2023-47323`, que nous utilisons pour obtenir des identifiants supplémentaires et un accès initial. L'utilisateur, qui fait partie du groupe `adm`, a accès aux fichiers journaux du système où un autre mot de passe est trouvé. Ceci nous permet de changer d'utilisateur. Avec les privilèges `sudo` sans restriction sur le nouveau compte, il est facile d'obtenir l'accès à l'utilisateur root.

## Balayage

```
nmap -sC -sV -oA nmap/SilverPlatter [IP_ADDRESS]
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-13 23:13 CST
Nmap scan report for 10.10.49.248
Host is up (0.26s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 1b:1c:87:8a:fe:34:16:c9:f7:82:37:2b:10:8f:8b:f1 (ECDSA)
|_  256 26:6d:17:ed:83:9e:4f:2d:f6:cd:53:17:c8:80:3d:09 (ED25519)

80/tcp   open  http       nginx 1.18.0 (Ubuntu)
|_http-title: Hack Smarter Security
|_http-server-header: nginx/1.18.0 (Ubuntu)

8080/tcp open  http-proxy
|_http-title: Error
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Connection: close
|     Content-Length: 74
|     Content-Type: text/html
|     Date: Tue, 14 Jan 2025 05:14:16 GMT
|     <html><head><title>Error</title></head><body>404 - Not Found</body></html>
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SMBProgNeg, SSLSessionReq, Socks5, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Length: 0
|     Connection: close
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 404 Not Found
|     Connection: close
|     Content-Length: 74
|     Content-Type: text/html
|     Date: Tue, 14 Jan 2025 05:14:14 GMT
|_    <html><head><title>Error</title></head><body>404 - Not Found</body></html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=1/13%Time=6785F2A7%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,C9,"HTTP/1\.1\x20404\x20Not\x20Found\r\nConnection:\x20clos
SF:e\r\nContent-Length:\x2074\r\nContent-Type:\x20text/html\r\nDate:\x20Tu
SF:e,\x2014\x20Jan\x202025\x2005:14:14\x20GMT\r\n\r\n<html><head><title>Er
SF:ror</title></head><body>404\x20-\x20Not\x20Found</body></html>")%r(HTTP
SF:Options,C9,"HTTP/1\.1\x20404\x20Not\x20Found\r\nConnection:\x20close\r\
SF:nContent-Length:\x2074\r\nContent-Type:\x20text/html\r\nDate:\x20Tue,\x
SF:2014\x20Jan\x202025\x2005:14:14\x20GMT\r\n\r\n<html><head><title>Error<
SF:/title></head><body>404\x20-\x20Not\x20Found</body></html>")%r(RTSPRequ
SF:est,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nC
SF:onnection:\x20close\r\n\r\n")%r(FourOhFourRequest,C9,"HTTP/1\.1\x20404\
SF:x20Not\x20Found\r\nConnection:\x20close\r\nContent-Length:\x2074\r\nCon
SF:tent-Type:\x20text/html\r\nDate:\x20Tue,\x2014\x20Jan\x202025\x2005:14:
SF:16\x20GMT\r\n\r\n<html><head><title>Error</title></head><body>404\x20-\
SF:x20Not\x20Found</body></html>")%r(Socks5,42,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(Ge
SF:nericLines,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x2
SF:00\r\nConnection:\x20close\r\n\r\n")%r(Help,42,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r
SF:(SSLSessionReq,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length
SF::\x200\r\nConnection:\x20close\r\n\r\n")%r(TerminalServerCookie,42,"HTT
SF:P/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConnection:\
SF:x20close\r\n\r\n")%r(TLSSessionReq,42,"HTTP/1\.1\x20400\x20Bad\x20Reque
SF:st\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(Kerberos
SF:,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConn
SF:ection:\x20close\r\n\r\n")%r(SMBProgNeg,42,"HTTP/1\.1\x20400\x20Bad\x20
SF:Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(LPD
SF:String,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r
SF:\nConnection:\x20close\r\n\r\n")%r(LDAPSearchReq,42,"HTTP/1\.1\x20400\x
SF:20Bad\x20Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\
SF:n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 138.59 seconds
```

Nous avons trois ports ouverts:
* 22 - SSH
* 80 - HTTP
* 8080 - HTTP

## Enumération

À `http://silverplatter.thm/`, nous trouvons le site web d'une entreprise offrant des services de cybersécurité.

![Silver Platter website](/images/THM-SilverPlatter/silverplatter_website.png)

La page de contact à `http://silverplatter.thm/#contact` nous donne un potentiel nom d'utilisateur, `scr1ptkiddy`. Nous apprenons également qu'ils utilisent Silverpeas.

![Contact page](/images/THM-SilverPlatter/contact_page.png)

L'énumération des répertoires et des sous-domaines est infructueuse sur le port 80.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://silverplatter.thm/
```

![Gobuster on port 80](/images/THM-SilverPlatter/gobuster_80.png)

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://axlle.htb -H "Host: FUZZ.silverplatter.thm" -ic
```

![Ffuf on port 80](/images/THM-SilverPlatter/ffuf_80.png)

`http://silverplatter.thm:8080/` leads to a `404` error page.

![404 error page](/images/THM-SilverPlatter/404_error.png)

L'énumération pour le port 8080 révèle `http://silverplatter.thm:8080/website/`, mais nous ne pouvons pas y accéder.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://silverplatter.thm:8080/
```

![gobuster on port 8080](/images/THM-SilverPlatter/gobuster_8080.png)

![forbidden page](/images/THM-SilverPlatter/forbidden.png)

De même, `http://silverplatter.thm:8080/console` est également inaccessible.

![console page](/images/THM-SilverPlatter/8080_console.png)

Silverpeas fonctionne généralement sur le port 8080.

![silverpeas port](/images/THM-SilverPlatter/silverpeas_port.png)

Nous pouvons y accéder à l'adresse `http://silverplatter.thm:8080/silverpeas` où nous trouvons une page de connexion.

![silverpeas login page](/images/THM-SilverPlatter/silverpeas_login.png)

## Accès initial

Nous ne pouvons pas utiliser la liste `rockyou.txt`, la description du challenge nous indique que ces mots de passe sont exclus. Nous allons donc essayer de créer une liste de mots de passe avec `cewl`.

```
cewl http://silverplatter.thm > passwords.txt
```

![password list](/images/THM-SilverPlatter/pwds_list.png)

Avec hydra, nous effectuons une attaque par force brute. Nous obtenons le nom du formulaire après avoir capturé une demande de connexion avec Burp.

![login request](/images/THM-SilverPlatter/login_request.png)

```
hydra -l scr1ptkiddy -P pwds.txt silverplatter.thm -s 8080 http-post-form "/silverpeas/AuthenticationServlet:Login=^USER^&Password=^PASS^&DomainId=0:F=Login or password incorrect"
```

![brute force attack with Hydra](/images/THM-SilverPlatter/hydra_creds.png)

En utilisant ces identifiants, nous arrivons à nous connecter.

![silverpeas dashboard](/images/THM-SilverPlatter/silverpeas_dashboard.png)

Cliquez sur `1 unread notification` pour lire le message. 

![inbox message](/images/THM-SilverPlatter/message_url.png)

[Cet article](https://rhinosecuritylabs.com/research/silverpeas-file-read-cves/) de Rhino Security Labs détaille les vulnérabilités de Silverpeas.

Après avoir lu attentivement les CVE, nous constatons que le [CVE-2023-47323](https://github.com/RhinoSecurityLabs/CVEs/tree/master/CVE-2023-47323) peut être exploité pour lire tous les messages en changeant simplement la valeur `ID`.

![Read messages vulnerability](/images/THM-SilverPlatter/read_message_cve.png)

En changeant la valeur en `6`, nous récupérons les informations d'identification de l'utilisateur `tim`.

![tim credentials](/images/THM-SilverPlatter/tim_creds.png)

```
Username: tim

Password: cm0nt!md0ntf0rg3tth!spa$$w0rdagainlol
```

Nous nous connectons via SSH et récupérons le drapeau de utilisateur.

![user flag](/images/THM-SilverPlatter/user_flag.png)

### Shell en tant que Tyler

Il existe un autre compte `tyler` sur le système.

![user list](/images/THM-SilverPlatter/user_list.png)

Avec linpeas, nous apprenons que l'utilisateur actuel fait partie du groupe `adm`. Les membres de ce groupe peuvent lire les logs du système.

![adm group](/images/THM-SilverPlatter/adm_group.png)

Cherchons des mots de passe dans les fichiers journaux.

```
grep -Ri "password" 2>/dev/null
```

![find password in logs](/images/THM-SilverPlatter/pwd_find.png)

Vers la fin du résultat, nous trouvons un mot de passe de base de données : `_Zd_zx7N823/`.

![database password](/images/THM-SilverPlatter/db_pwd.png)

En l'utilisant, nous pouvons passer à `tyler`.

![tyler account](/images/THM-SilverPlatter/switch_to_tyler.png)

## Elévation de Privilèges

Avec `sudo -l` nous découvrons que `tyler` a un accès `sudo` non restreint sur le système. 

![sudo privileges command](/images/THM-SilverPlatter/sudo-l_cmd.png)

Une simple commande `sudo su` nous permet de devenir root et de lire le drapeau root.

![root flag](/images/THM-SilverPlatter/root_flag.png)

