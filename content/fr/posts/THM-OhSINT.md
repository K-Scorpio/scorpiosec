---
date: 2024-02-13T14:31:59-06:00
# description: ""
image: "/images/THM-OhSINT/OhSINT.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: OhSINT"
type: "post"
---

* Platforme: TryHackMe
* Lien: [OhSINT](https://tryhackme.com/room/ohsint)
* Niveau: Easy
* Type: OSINT
---

Il s'agit d'un défi OSINT, c'est-à-dire Open-Source Intelligence. L'OSINT est essentiellement de la collecte et de l'analyse d'informations accessibles au public afin d'obtenir des renseignements. C'est un peu comme reconstituer un puzzle en utilisant les pièces que vous trouvez sur Internet, dans les bibliothèques ou dans tout autre endroit où l'information est librement accessible.

Après avoir téléchargé les fichiers de tâches à l'aide du bouton `Download Task Files`, vous obtenez une seule image nommée `WindowsXP.jpg`. Comme vous pouvez le constater, vous ne pouvez rien tirer de cette image à première vue. 

![WindowsXP backgroung image](/images/THM-OhSINT/WindowsXP.jpg)

## 1. What is this user's avatar of?

>Imaginez que vous ayez une collection de photos de vos dernières vacances. Les photos elles-mêmes immortalisent les souvenirs, mais vous aimeriez en savoir plus sur elles : quand ont-elles été prises, où, par qui ? Ces informations "supplémentaires" qui décrivent les photos elles-mêmes sont appelées métadonnées (metadata). Pour résumer, les métadonnées sont des données qui fournissent des informations sur d'autres données.

Sous Linux, nous pouvons utiliser `exiftool` pour lire les métadonnées de l'image. Exécutez la commande `exiftool WindowsXP.jpg` et vous obtiendrez des informations sur l'image.

![Output of exiftool command](/images/THM-OhSINT/exiftool-cmd-result.png)

Nous obtenons quelques informations utiles et un pseudo pour le droit d'auteur, `OWoodflint`. Cet challenge étant un cas OSINT, nous recherchons des informations publiquement disponibles.

En cherchant sur Google `OWoodflint`, nous obtenons de nombreux liens, mais commençons par le compte X (anciennement Twitter).

![Search results of googling OWoodflint](/images/THM-OhSINT/OWoodflint-search-results.png)

Nous voyons un chat comme photo de profil, essayons `cat` comme réponse à la première question et c'est la bonne!

## 2. What city is this person in?

L'indice nous indique d'utiliser le BSSID trouvé sur X sur un site appelé `Wigle.net`.

![BSSID found on X account](/images/THM-OhSINT/OWoodflint-BSSID.png)

Dans son deuxième poste, l'utilisateur nous donne un BSSID de `B4:5D:50:AA:86:41`. Nous allons maintenant sur [wigle.net](https://www.wigle.net/) pour l'utiliser.

> Un identifiant BSSID (**Basic Service Set Identifier**) est un identifiant unique attribué à chaque point d'accès (AP) ou routeur d'un réseau Wi-Fi. Il permet de distinguer un réseau sans fil d'un autre dans une zone de couverture donnée. Le BSSID sert essentiellement d'adresse MAC (Media Access Control) à l'appareil sans fil.

Saisissez le BSSID et cliquez sur le bouton `Filter` plus bas.

![BSSID search on wigle.net](/images/THM-OhSINT/Wigle-BSSID-search.png)

Vous aurez à faire un zoom arrière et à chercher un cercle violet sur la carte. La correspondance indique `London`. Il s'agit de la bonne réponse à la deuxième question.

![BSSID search result](/images/THM-OhSINT/BSSID-location-match.png)

## 3. What is the SSID of the WAP he connected to?

>Un SSID (**Service Set Identifier**) est essentiellement le nom d'un réseau Wi-Fi. Il s'agit de l'identifiant public qu'un routeur Wi-Fi communique pour annoncer sa présence et permettre aux appareils voisins de se connecter.

Continuez à zoomer sur l'emplacement indiqué sur la carte et vous verrez le mot "UnileverWiFi" au-dessus du BSSID que vous avez saisi plus tôt, ce qui est la bonne réponse à cette question.

![WAP SSID](/images/THM-OhSINT/OhSINT-WAP-SSID.png)

## 4. What is his personal email address?

Le deuxième résultat de la recherche est un compte Github, examinons-le. Nous trouvons une adresse email `OWoodflint@gmail.com`.

![Email address found on Github](/images/THM-OhSINT/OhSINT-email.png)

## 5. What site did you find his email address on?

Nous avons trouvé l'adresse email sur `Github`.

## 6. Where has he gone on holiday?

Nous trouvons un site web WordPress sur le compte Github.

![WordPress site url](/images/THM-OhSINT/OhSINT-WordPress-site.png)

Sur le site WordPress, l'utilisateur révèle sa localisation en disant qu'il se trouve à `New York`, ce qui est la bonne réponse.

![Target holiday location](/images/THM-OhSINT/OhSINT-holiday-location-1.png)

## 7. What is the person's password?

J'ai récemment appris ce qu'est l'exposition aux données sensibles et comment on peut parfois trouver des données sensibles dans le code source des pages web. En examinant le code source, nous trouvons un texte écrit en blanc (`#ffffff` est le code hexadécimal de la couleur blanche). L'auteur de cette page web a tenté de cacher ce texte en l'écrivant en blanc sur un fond blanc, ce qui le rend invisible. Nous essayons `pennYDr0pper.!` comme mot de passe et nous obtenons un résultat correct.

![user password in source code](/images/THM-OhSINT/OhSINT-password.png)

> Je pense que lorsqu'il s'agit de défis OSINT, il faut être très attentif et ne rien négliger. Le mot de passe était juste devant moi, mais je ne l'ai pas remarqué tout de suite. J'ai accidentellement appuyé sur `Ctrl+a` et le message `pennYDr0pper.!` est devenu visible, mais je n'ai pas remarqué qu'il ne l'était pas auparavant. 

![Target holiday location](/images/THM-OhSINT/WP-password-trick.png)

C'est tout pour ce premier hacking challenge. J'essaierai de résoudre différents types de défis qui requièrent des compétences variées. A la prochaine!
