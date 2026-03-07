---
date: 2026-03-05T16:15:21-06:00
# description: ""
image: "/images/HTB-Expressway/Expressway.png"
lastmod: 2026-03-05
showTableOfContents: true
tags: ["Hackthebox", "VPN", "ISAKMP/IKE", "PSK-Cracking", "CVE-2025-32463", "hashcat", "UDP-scan", "Sudo-PrivEsc"]
categories: ["Writeups"]
title: "HTB: Expressway"
type: "post"
---

* Platforme: HackTheBox
* Lien: [Expressway](https://app.hackthebox.com/machines/Expressway)
* Niveau: Facile
* OS: Linux
---

Expressway débute par la découverte d'une surface d'attaque restreinte grâce à un scan TCP. Un scan UDP ultérieur révèle que la cible exécute un service VPN IPsec. En énumérant le service IKE, nous obtenons l'identité IKE et un hachage d'authentification en mode agressif, ce qui permet une attaque hors ligne contre la clé pré-partagée du VPN.

Après avoir récupéré la clé, nous nous authentifions sur le système via SSH et obtenons un point d'ancrage. Une énumération locale supplémentaire révèle que la version installée de sudo est vulnérable au `CVE-2025-32463`, qui nous permet d'élever nos privilèges et d'obtenir un shell root.

Dans l'ensemble, la compromission consiste à exploiter une configuration VPN faible pour récupérer les identifiants et à tirer parti d'une version sudo vulnérable pour compromettre entièrement le système.

# Balayage

```
nmap -sC -sV -Pn -oA nmap/Expressway {TARGET_IP}
```

**Résultats**
```shell
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-06 06:15 EST
Nmap scan report for 10.129.1.32 (10.129.1.32)
Host is up (0.11s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.82 seconds
```

Notre scan TCP ne détecte qu'un seul port ouvert (22) exécutant SSH avec la version `OpenSSH 10.0p2`.

Nous effectuons un scan UDP pour trouver d'autres services, étant donné que SSH représente une surface d'attaque relativement réduite.

```
sudo nmap -sU --top-ports 100 -sC -sV {TARGET_IP}
```

**Résultats**
```shell
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-06 06:26 EST
Nmap scan report for 10.129.1.32 (10.129.1.32)
Host is up (0.13s latency).
Not shown: 96 closed udp ports (port-unreach)
PORT     STATE         SERVICE   VERSION
68/udp   open|filtered dhcpc
69/udp   open          tftp      Netkit tftpd or atftpd
500/udp  open          isakmp?
| fingerprint-strings: 
|   IKE_MAIN_MODE: 
|_    "3DUfwO
| ike-version: 
|   attributes: 
|     XAUTH
|_    Dead Peer Detection v1.0
4500/udp open|filtered nat-t-ike
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port500-UDP:V=7.95%I=7%D=3/6%Time=69AABA8F%P=x86_64-pc-linux-gnu%r(IKE_
SF:MAIN_MODE,70,"\0\x11\"3DUfwO\xd8\x19\x12~\xa2\x9f\x08\x01\x10\x02\0\0\0
SF:\0\0\0\0\0p\r\0\x004\0\0\0\x01\0\0\0\x01\0\0\0\(\x01\x01\0\x01\0\0\0\x2
SF:0\x01\x01\0\0\x80\x01\0\x05\x80\x02\0\x02\x80\x04\0\x02\x80\x03\0\x01\x
SF:80\x0b\0\x01\x80\x0c\0\x01\r\0\0\x0c\t\0&\x89\xdf\xd6\xb7\x12\0\0\0\x14
SF:\xaf\xca\xd7\x13h\xa1\xf1\xc9k\x86\x96\xfcwW\x01\0");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 303.83 seconds
```
Le scan UDP détecte quelques ports :
* `68` - DHCP
* `69` - TFTP
* `500` - isakmp
* `4500` - NAT Traversal pour IPsec

Les ports UDP détectés indiquent clairement qu'un VPN IPsec est en cours d'exécution sur la cible. Les ports `500` et `4500` apparaissent souvent ensemble lorsqu'un système prend en charge IPsec avec NAT Traversal.

## UDP 500 - ISAKMP / IKE

Le protocole ISAKMP (Internet Security Association and Key Management Protocol) est utilisé lors de la négociation initiale d'un tunnel VPN IPsec. Les implémentations modernes utilisent le protocole IKE (Internet Key Exchange) sur ce port.

Fonctions :
* Négociation des paramètres de sécurité
* Authentification des pairs VPN
* Établissement d'associations de sécurité (SA)
* Échange de clés cryptographiques

## UDP 4500 - NAT Traversal (NAT-T)

Le NAT-Traversal permet à IPsec de fonctionner à travers des dispositifs NAT (routeurs domestiques, pare-feu). Normalement, IPsec utilise ESP (protocole 50), mais il ne fonctionne pas aussi bien avec NAT.

Le flux de travail type est le suivant :
1. La négociation IKE commence sur **UDP 500**.
2. Le NAT est détecté.
3. Le tunnel passe à **UDP 4500**.
4. Le trafic ESP crypté est encapsulé dans des paquets UDP.

Cela permet aux clients VPN derrière le NAT de se connecter avec succès. Notre découverte indique que la cible est une passerelle VPN.

# Énumération

Nous effectuons un scan IKE pour obtenir plus d'informations.

```
ike-scan -M -A {TARGET_IP}
```

> * `-M` - Utiliser le test en mode principal
> * `-A` - Tester également le mode agressif

**Results**
```shell
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.1.32     Aggressive Mode Handshake returned
        HDR=(CKY-R=0dc7411b28450ec4)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.123 seconds (8.11 hosts/sec).  1 returned handshake; 0 returned notify
```

À partir des résultats de l'analyse ike-scan, nous pouvons tirer plusieurs conclusions importantes :
* Le mode agressif est activé, ce qui expose l'identité IKE (ike@expressway.htb) ainsi qu'un hachage d'authentification Hash(20 octets). Étant donné que le VPN utilise l'authentification par clé pré-partagée (PSK), ce hachage peut potentiellement être utilisé pour des attaques de craquage PSK hors ligne.
* Les paramètres cryptographiques utilisés pendant la négociation de phase 1 sont faibles et obsolètes :
- Cryptage : 3DES
- Intégrité : SHA1
- Diffie-Hellman : Groupe 2 (modp1024)
Ces algorithmes sont considérés comme obsolètes. En particulier, 3DES est vulnérable aux attaques Sweet32, SHA-1 présente des faiblesses connues en matière de collision et le groupe DH 2 (1024 bits) n'offre plus une sécurité adéquate.
* La méthode d'authentification est PSK (clé pré-partagée) plutôt qu'une authentification basée sur un certificat, ce qui augmente encore le risque lorsqu'elle est combinée avec le mode agressif, car elle permet aux attaquants de tenter des attaques par force brute hors ligne contre la clé partagée.

Dans l'ensemble, la configuration indique une configuration VPN IKEv1 obsolète et faiblement sécurisée.

Nous extrayons le hachage pour le craquage hors ligne :

```
ike-scan -A -M expressway.htb --pskcrack=hash.txt
```

![Hash extraction](/images/HTB-Expressway/expressway_pscrack.png)

À l'aide de Hashcat, nous effectuons une attaque par force brute hors ligne contre le hachage d'authentification IKE capturé et récupérons avec succès la clé pré-partagée VPN.

```
hashcat -m 5400 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

```
freakingrockstarontheroad
```

![Hash cracking](/images/HTB-Expressway/ike_ssh_pwd.png)

# Accès initial

À l'aide du mot de passe, nous nous connectons via SSH en tant que `ike`:

```
ssh ike@expressway.thb
```

![ike SSH login](/images/HTB-Expressway/ike_SSH_login.png)

# Élévation des privilèges

Nous exécutons `sudo -l` pour vérifier les privilèges sudo de l'utilisateur. Nous obtenons un message d'avertissement sudo, un avertissement de sécurité qui s'affiche la première fois qu'un utilisateur exécute sudo sur un système Linux, lui rappelant d'utiliser ses privilèges élevés de manière responsable.

![sudo privileges](/images/HTB-Expressway/expressway_sudo_privs.png)

Le mot de passe SSH n'est pas valide.

Avec linPEAS, nous découvrons la version en cours d'exécution de sudo (`1.9.17`).

![Hash cracking](/images/HTB-Expressway/expressway_sudo_version.png)

En recherchant les vulnérabilités de cette version, nous trouvons le [CVE-2025-32463](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2025-096/) avec un PoC disponible [ici](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot/blob/main/sudo-chwoot.sh).

> CVE-2025-32463 is a critical local privilege escalation vulnerability in sudo where the `--chroot` option allows an attacker to load user-controlled NSS configuration files and execute arbitrary libraries as root.

Nous transférons le script d'exploitation sur la cible et l'exécutons pour obtenir les privilèges root.

![Roor flag](/images/HTB-Expressway/expressway_root_flag.png)

## Explication de l'exploitation

L'exploit obtient les privilèges root en exploitant la manière dont les versions vulnérables de `sudo` gèrent l'option `--chroot` (`-R`).

Le script crée d'abord un faux environnement chroot (`woot/`) contenant un fichier `nsswitch.conf` malveillant qui ordonne au système de charger un module NSS personnalisé. Il compile ensuite une bibliothèque partagée malveillante (`libnss_/woot1337.so.2`) dont le constructeur exécute une commande avec les UID et GID définis sur `0` (root).

Lorsque le script exécute `sudo -R woot woot`, le `sudo` vulnérable traite le fichier `nsswitch.conf` contrôlé par l'attaquant à l'intérieur du chroot et charge la bibliothèque NSS malveillante dans le cadre de son processus de recherche d'utilisateur. Comme cela se produit pendant l'exécution privilégiée de `sudo`, la bibliothèque est chargée avec les privilèges root.

Le constructeur de la bibliothèque s'exécute immédiatement et génère un shell root (ou exécute la commande fournie), ce qui entraîne une élévation des privilèges vers root.
