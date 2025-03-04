---
date: 2025-03-01T21:11:49-06:00
# description: ""
# image: ""
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups", "Challenge"]
title: "HTB: ApacheBlaze"
type: "post"
---

* Platforme: Hack The Box
* Lien: [ApacheBlaze](https://app.hackthebox.com/challenges/ApacheBlaze)
* Niveau: Facile
* Catégorie : Web
---

# DESCRIPTION DU DÉFI

Step into the ApacheBlaze universe, a world of arcade clicky games. Rumor has it that by playing certain games, you have the chance to win a grand prize. However, before you can dive into the fun, you'll need to crack a puzzle.

> MOT DE PASSE ZIP: `hackthebox`

## Énumération du site web

À l'adresse IP cible, nous trouvons un site web proposant quatre jeux différents.

![ApacheBlaze website](/images/HTB-ApacheBlaze/apacheblaze_website.png)

Les jeux 1, 2 et 3 sont tous indisponibles. Lorsque nous cliquons sur `PLAY` pour le jeu 4, nous obtenons le message suivant: `This game is currently available only from dev.apacheblaze.local.`.

![Game 4 message](/images/HTB-ApacheBlaze/game4.png)

Le code source de la page et la recherche de répertoires cachés ne révèlent rien d'utile.

Le bouton play pour `Game 4` envoie une requête GET à `/api/games/click_topia`. Cette requête nous donne le même message que celui que nous avons vu sur l'application.

![game 4 access message in Burp](/images/HTB-ApacheBlaze/req_game_access.png)

## Revue du code source

Portons notre attention sur le code source. 

Dans `app.py`, nous voyons que l'application accepte un paramètre `game`. Si la valeur de `game` est `click_topia` (`game == click_topia`) et que la valeur de `X-Forwarded-Host` est `dev.apacheblaze.local`, le drapeau est révélé. 

![Flag obtention method](/images/HTB-ApacheBlaze/get_flag_method.png)

Nous ajoutons le paramètre `X-Forwarded-Host` à la requête mais celle-ci ne renvoie pas le drapeau.

```
X-Forwarded-Host: dev.apacheblaze.local
```

![Modified request with X-Forwarded-Host](/images/HTB-ApacheBlaze/modified_request.png)

Dans `http.conf` nous apprenons que l'application utilise un proxy et un load balancer.

Apache agit comme un reverse-proxy (`mod_proxy_http`) pour transmettre les requêtes à un équilibreur de charge (load balancer), en utilisant un hôte virtuel sur le port `1337`.

> L'utilisation du drapeau `[P]` avec Apache lui indique d'agir en tant que proxy pour la requête.

La règle mod_rewrite réécrit la requête et la transmet à l'équilibreur de charge sur le port 8080.
Par exemple, une requête telle que `GET /api/games/click_topia` est réécrite et transmise à `GET http://127.0.0.1:8080/?game=click_topia`.

![Apache Reverse proxy](/images/HTB-ApacheBlaze/rev_proxy.png)

L'hôte virtuel sur le port 8080 met en place un équilibreur de charge en utilisant `mod_proxy_balancer`. Les requêtes sont envoyées à un cluster interne de backend composé de deux serveurs à : `http://127.0.0.1:8081` et `http://127.0.0.1:8082`.

![load balancer setup](/images/HTB-ApacheBlaze/proxy_info.png)

L'utilisation d'un proxy et d'un équilibreur de charge peut potentiellement introduire des problèmes de désynchronisation, ce qui signifie que si Apache traite les requêtes HTTP différemment du backend, nous pourrions manipuler les en-têtes en utilisant la contrebande de requêtes HTTP.

Nous changeons l'hôte en `localhost:1337` (le proxy) mais toujours pas de drapeau.

![Request with modified Host parameter](/images/HTB-ApacheBlaze/modified_req2.png)

### Contrebande de Requête HTTP

Dans le fichier Docker, nous voyons que `httpd version 2.4.55` est utilisé. La recherche de vulnérabilités pour cette version conduit à la découverte du [CVE-2023-25690](https://httpd.apache.org/security/vulnerabilities_24.html) avec une preuve de concept [ici](https://github.com/dhmosfunk/CVE-2023-25690-POC). La vulnérabilité est une contrebande de requêtes HTTP par injection d'en-tête.

![httpd version](/images/HTB-ApacheBlaze/httpd_version.png)

Elle est causée par une mauvaise vérification des en-têtes entrants lorsque `mod_proxy` est activé. Les attaquants sont capables d'injecter des en-têtes additionnels en utilisant `CRLF` (`\r\n`) pour rompre les limites de la requête entre Apache et le backend.

> CRLF (Carriage Return Line Feed) est une séquence de deux caractères indiquant un saut de ligne.

Notre objectif est donc d'ajouter une seconde requête à la première. En suivant l'exemple du PoC, nous modifions la requête et obtenons le drapeau.

![Working request and flag value](/images/HTB-ApacheBlaze/flag_value.png)

**DRAPEAU**
```
HTB{1t5_4ll_4b0ut_Th3_Cl1ck5}
```

Nous avons modifié deux paramètres pour que la requête fonctionne correctement:

> Voici la requête sans modification: `GET /api/games/click_topia HTTP/1.1\r\nHost: dev.apacheblaze.local\r\n\r\nGET /HTTP/1.1`.

```
GET /api/games/click_topia%20HTTP/1.1%0d%0aHost:%20dev.apacheblaze.local%0d%0a%0d%0aGET%20/ HTTP/1.1


Host: localhost:1337
```

## Explication

1. La requête initiale est envoyée au proxy Apache (port 1337).

Nous envoyons deux requêtes HTTP en une.

Nous envoyons deux requêtes HTTP en une. Apache ne traite que le contenu jusqu'à la première limite `\r\n\r\n`, ce qui signifie qu'il ne traite que la première partie de la requête (`GET /api/games/click_topia%20HTTP/1.1`). Le `Host: dev.apacheblaze.local` introduit en contrebande est traité par Apache comme faisant partie du corps de la requête. La seconde requête GET (`GET / HTTP/1.1`) est transmise à Flask sans modification.

2. La requête est transmise à l'équilibreur de charge sur le port 8080.

L'équilibreur de charge envoie la requête à l'un des serveurs backend (sur le port 8081 ou 8082), mais la seconde requête, passée en contrebande, est effectivement injectée dans le flux de requêtes parce qu'Apache n'a pas réussi à la traiter correctement.

3. L'application Flask traite la requête.

L'application vérifie la condition `if request.headers.get('X-Forwarded-Host') == 'dev.apacheblaze.local'`. Cependant, nous n'avons pas explicitement envoyé `X-Forwarded-Host : dev.apacheblaze.local`. Apache a ajouté automatiquement `X-Forwarded-Host : dev.apacheblaze.local` lors du traitement de la première requête avant de la transmettre au backend. 

Ensuite, à cause de la contrebande de requêtes HTTP, le backend (Flask) interprète la seconde requête (`GET / HTTP/1.1`) comme faisant partie de la même connexion. Puisque Flask traite plusieurs requêtes sur la même connexion sans réinitialiser les en-têtes, la seconde requête hérite des en-têtes de la première requête, y compris : `X-Forwarded-Host: dev.apacheblaze.local`.

4. Nous obtenons le drapeau

Flask répond avec le drapeau parce que l'en-tête `X-Forwarded-Host` correspond à la valeur attendue (`dev.apacheblaze.local`).

> **NOTE:** Lorsque Apache agit comme un proxy inverse (reverse proxy), il ajoute automatiquement plusieurs en-têtes à des fins de transfert, y compris `X-Forwarded-Host`, qui reflète l'en-tête Host d'origine de la requête du client. Apache l'insère pendant le processus de proxy inverse. Cela permet à l'application Flask de voir l'en-tête de contrebande et d'effectuer le contrôle de sécurité par rapport à lui. _Pour en savoir plus, cliquez [ici](https://httpd.apache.org/docs/2.4/mod/mod_proxy.html#page-header)._





