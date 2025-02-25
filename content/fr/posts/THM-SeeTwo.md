---
date: 2024-11-04T12:11:25-06:00
# description: ""
image: "/images/THM-SeeTwo/SeeTwo.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: SeeTwo"
type: "post"
---

* Platforme: TryHackMe
* Lien: [SeeTwo](https://tryhackme.com/r/room/seetworoom)
* Niveau: Moyen
---

Pour ce défi, nous devons examiner un fichier pcap. Initialement, nous trouvons ce qui semble être du trafic banal, mais en creusant un peu, nous découvrons un binaire ELF contenant des fichiers `.pyc`. La décompilation d'un de ces fichiers nous permet de comprendre les tactiques utilisées par l'attaquant, et avec un script python nous trouvons toutes les informations dont nous avons besoin.

## Investigation

Juste après avoir chargé le fichier pcap, nous obtenons une vision d'ensemble du trafic. Utilisons la fonction `Conversations` de Wireshark (Statistics --> Conversations).

Sous `IPv4` nous trouvons deux communications:
- `10.0.2.64` a envoyé 2152 paquets à `10.0.2.71`. Nous remarquons également que 16 MB de données ont été transférés, ce qui vaut la peine d'être examiné.
- `10.0.2.71` a envoyé 2 paquets à `10.0.2.3`.

![SeeTwo - Wireshark IPv4 conversations](/images/THM-SeeTwo/IPv4_conv.png)

Sous la section `TCP`, nous trouvons plus d'informations, nous constatons qu'il y a du trafic sur les ports: `22` probablement SSH, `1337` et `80` probablement HTTP. Les 16 MB de données ont été envoyés via le port 80.

![SeeTwo - Wireshark TCP conversations](/images/THM-SeeTwo/TCP_conv.png)

Wireshark confirme que le trafic sur le port 22 est bien SSH, nous pouvons l'ignorer puisque nous n'avons pas de clé de décryptage.

![Wireshark SSH traffic](/images/THM-SeeTwo/SSH_traffic.png)

Nous ne pouvons pas dire avec certitude quel protocole fonctionne sur le port `1337`, examinons ce trafic. Nous commençons par la conversation avec `60kB` de données.

Après le three-way handshake, nous constatons que des données sont transférées avec la trame `1810`.

![Wireshark 1337 traffic](/images/THM-SeeTwo/frame_1810.png)

Nous copions les données et nous nous rendons sur [CyberChef](https://gchq.github.io/CyberChef/), il s'agit d'une image.

![Pokeball image](/images/THM-SeeTwo/pokeball_pic.png)

Après avoir décodé d'autres données issues de cette même conversation, nous obtenons une autre image.

![Milk image](/images/THM-SeeTwo/frame_1856.png)

Le trafic sur le port `1337` semble être une impasse, jusqu'à présent nous ne trouvons que des images. Intéressons-nous maintenant à la conversation HTTP, mais voyons d'abord si nous pouvons exporter des fichiers liés au protocole ( File --> Export Objects --> HTTP).

Nous obtenons un fichier appelé `base64_client`.

![base64_client file](/images/THM-SeeTwo/base64_client.png)

![base64_client file type](/images/THM-SeeTwo/base64_client_filetype.png)

Après son décodage, nous obtenons un binaire Linux.

![Linux ELF](/images/THM-SeeTwo/Linux_ELF.png)

En utilisant `strings` sur le fichier, nous pouvons lire `pydata` à la fin.

```
strings decoded_base64 | tail
```

![pydata](/images/THM-SeeTwo/pydata.png)

En supposant qu'il s'agit d'une référence à python, nous pouvons essayer de trouver toutes les mentions de `python` dans le résultat de la commande.

```
strings decoded_base64 | grep "python"
```

![grep on python](/images/THM-SeeTwo/strings_python.png)

Il y a beaucoup de mentions de `CPython` et de python `version 3.8`. Nous pouvons utiliser un outil tel que [PyInstaller Extractor](https://github.com/extremecoders-re/pyinstxtractor) pour extraire le contenu du binaire ELF.

```
git clone https://github.com/extremecoders-re/pyinstxtractor
cd pyinstxtractor
python pyinstxtractor.py ELF_binary_location
```

![pyinstextractor command](/images/THM-SeeTwo/pyinstxtractor.png)

Nous obtenons des fichiers `.pyc` qui sont des fichiers Python compilés. Nous devons utiliser un décompilateur pour Python version `3.8`.

![pyc files](/images/THM-SeeTwo/pyc_files.png)

Avec [decompyle3](https://github.com/rocky/python-decompile3) nous décompilons `client.pyc`. Après l'avoir installé, nous exécutons la commande ci-dessous.

```
decompyle3 client.pyc_location > client.py
```

![decompyle3 command](/images/THM-SeeTwo/decompyle3_clientpyc.png)

Nous pouvons maintenant lire le contenu de `client.py`.

![client.py code](/images/THM-SeeTwo/client_py.png)

Maintenant nous comprenons clairement la situation, ce code est une communication de commande et de contrôle (C2) avec l'adresse IP `10.0.2.64` et il utilise le port `1337`. Il exploite également un cryptage `XOR`, nous avons la clé, nous pouvons décrypter les données.

La commande envoyée par l'attaquant et la réponse qu'il reçoit sont toujours divisées en deux parties : `encoded_image` et `encoded_command`. Ces deux parties sont séparées par `AAAAAAAA`.

De retour sur Wireshark, nous utilisons le filtre `tcp.port == 1337` et suivons le flux TCP (click droit --> Follow --> TCP Stream).

![separator in Wireshark](/images/THM-SeeTwo/separator.png)

> Les données de la requête sont en bleu et celles de la réponse en rouge.

Lorsque nous décryptons l'ensemble des données d'une requête ou d'une réponse, nous obtenons une image et nous sommes amenés à croire qu'il s'agit d'une communication inoffensive. La commande est en fait ce qui vient après le séparateur. 

Utilisons `JB0=` qui est la première commande envoyée par l'attaquant. Nous utilisons la clé ci-dessous pour le décryptage XOR.

```
MySup3rXoRKeYForCommandandControl
```

![decoded command in CyberChef](/images/THM-SeeTwo/cmd_decoded.png)

![decoded response in CyberChef](/images/THM-SeeTwo/C2_response_decoded.png)

La commande est `id` et la réponse est `uid=1000(bella) gid=1000(bella) groups=1000(bella),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)`.

Nous pouvons prendre chaque commande, les décrypter et nous découvrirons tout ce qui a été fait par l'attaquant sur le serveur, mais ce processus manuel est lent, nous allons donc utiliser un script.

```python
from scapy.all import rdpcap, TCP
import base64

PCAP_FILE = "capture.pcap"
TARGET_PORT = 1337
SEPARATOR = "AAAAAAAAAA"
XOR_KEY = "MySup3rXoRKeYForCommandandControl".encode("utf-8")

def xor_crypt(data, key):
    key_length = len(key)
    return bytes([byte ^ key[i % key_length] for i, byte in enumerate(data)])

def decode_and_decrypt(payload):
    try:
        parts = payload.split(SEPARATOR)
        if len(parts) < 2:
            return None  

        encoded_part = parts[1]
        decoded_part = base64.b64decode(encoded_part.encode("utf-8"))

        decrypted_data = xor_crypt(decoded_part, XOR_KEY)

        return decrypted_data.decode("utf-8")
    except Exception as e:
        print(f"Error decoding payload: {e}")
        return None

packets = rdpcap(PCAP_FILE)
for packet in packets:
    if packet.haslayer(TCP):
        if packet[TCP].sport == TARGET_PORT:
            payload = bytes(packet[TCP].payload).decode("utf-8", errors="ignore")
            decoded_command = decode_and_decrypt(payload)
            if decoded_command:
                print("Decoded C2 Command:", decoded_command)
        elif packet[TCP].dport == TARGET_PORT:
        
            payload = bytes(packet[TCP].payload).decode("utf-8", errors="ignore")
            decoded_response = decode_and_decrypt(payload)
            if decoded_response:
                print("Decoded C2 Response:", decoded_response)
```

Le résultat du script fournit toutes les réponses.

### What is the first file that is read? Enter the full path of the file.

Exécutez le script et trouvez la commande `cat`.

### What is the output of the file from question 1?

La réponse est le résultat de la commande `cat`.

### What is the user that the attacker created as a backdoor? Enter the entire line that indicates the user.

La première commande `echo` vous donne la réponse.

### What is the name of the backdoor executable?

Trouvez la commande qui ajoute le bit `SUID` au binaire.

### What is the md5 hash value of the executable from question 4?

L'attaquant a calculé le hash md5 avec la commande `md5sum`, nous avons juste besoin de la trouver et de lire son résultat.

### What was the first cronjob that was placed by the attacker?

Trouvez la deuxième commande `echo` et vous obtiendrez la réponse.

### What is the flag?

Avec la troisième commande `echo`, l'attaquant a encodé une chaîne de caractères, décodez-la et vous obtiendrez le drapeau.
