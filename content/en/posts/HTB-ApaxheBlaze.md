---
date: 2025-03-01T21:11:49-06:00
# description: ""
# image: ""
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups", "Challenge"]
title: "HTB Challenge: ApacheBlaze"
type: "post"
---

* Platform: Hack The Box
* Link: [ApacheBlaze](https://app.hackthebox.com/challenges/ApacheBlaze)
* Level: Easy
* Category: Web
---

# CHALLENGE DESCRIPTION

Step into the ApacheBlaze universe, a world of arcade clicky games. Rumor has it that by playing certain games, you have the chance to win a grand prize. However, before you can dive into the fun, you'll need to crack a puzzle.

> ZIP PASSWORD: `hackthebox`

## Website Enumeration

At the target IP address we find a website with four different games to play.

![ApacheBlaze website](/images/HTB-ApacheBlaze/apacheblaze_website.png)

Games 1, 2 and 3 are all unavailable. When we click on `PLAY` for Game 4 we get the message: `This game is currently available only from dev.apacheblaze.local.`.

![Game 4 message](/images/HTB-ApacheBlaze/game4.png)

The page's source code and directory brute forcing do not reveal anything useful.

The play button for `Game 4` sends a GET request to `/api/games/click_topia`. Sending the request gives us the same message we saw on the application.

![game 4 access message in Burp](/images/HTB-ApacheBlaze/req_game_access.png)

## Source Code Review

Let's turn our attention to the source code. 

In `app.py`, we see that the application accepts a `game` parameter. If the value of `game` is `click_topia` (`game == click_topia`) and the value of `X-Forwarded-Host` is `dev.apacheblaze.local`, the flag is revealed. 

![Flag obtention method](/images/HTB-ApacheBlaze/get_flag_method.png)

We add the `X-Forwarded-Host` parameter to the request however sending it does not return the flag.

```
X-Forwarded-Host: dev.apacheblaze.local
```

![Modified request with X-Forwarded-Host](/images/HTB-ApacheBlaze/modified_request.png)

In `http.conf` we learn that the application uses a proxy and a load balancer.

Apache is acting as a reverse-proxy (`mod_proxy_http`) to forward requests to a load balancer, this is done using a virtual host on port `1337`.

> Using the `[P]` flag in Apache instructs it to act as a proxy for the request.

The mod_rewrite rule rewrites the request and forwards it to the load balancer on port 8080.
For example a request such as `GET /api/games/click_topia` is rewritten and forwarded to `GET http://127.0.0.1:8080/?game=click_topia`.

![Apache Reverse proxy](/images/HTB-ApacheBlaze/rev_proxy.png)

The virtual host on port 8080 sets up a load balancer using `mod_proxy_balancer`. The requests are sent to an internal backend cluster consisting of two servers at: `http://127.0.0.1:8081` and `http://127.0.0.1:8082`.

![load balancer setup](/images/HTB-ApacheBlaze/proxy_info.png)

Using a proxy and a load balancer can potentially introduce desynchronization issues meaning if Apache processes HTTP requests differently than the backend we could manipulate the headers using HTTP Request Smuggling.

We try to change the host to `localhost:1337` (the proxy) but still no flag.

![Request with modified Host parameter](/images/HTB-ApacheBlaze/modified_req2.png)

### HTTP Request Smuglling Vulnerability

In the Docker file we see that `httpd version 2.4.55` is used. Searching for vulnerabilities for this version leads to the discovery of [CVE-2023-25690](https://httpd.apache.org/security/vulnerabilities_24.html)  with a PoC [here](https://github.com/dhmosfunk/CVE-2023-25690-POC). The vulnerability is an HTTP Request Smuggling via header injection. 

![httpd version](/images/HTB-ApacheBlaze/httpd_version.png)

It is caused by an improper sanitization of incoming headers when `mod_proxy` is enabled. Attackers are able to inject additional headers using `CRLF` (`\r\n`) to break the request boundaries between Apache and the backend.

> CRLF (Carriage Return Line Feed) is a sequence of two characters indicating a line break.

So our goal is to append a second request to the first one. Following the PoC example we modify the request and obtain the flag.

![Working request and flag value](/images/HTB-ApacheBlaze/flag_value.png)

**FLAG VALUE**
```
HTB{1t5_4ll_4b0ut_Th3_Cl1ck5}
```

We modified two parameters for the request to work properly:

> Here is the non encoded request: `GET /api/games/click_topia HTTP/1.1\r\nHost: dev.apacheblaze.local\r\n\r\nGET /HTTP/1.1`.

```
GET /api/games/click_topia%20HTTP/1.1%0d%0aHost:%20dev.apacheblaze.local%0d%0a%0d%0aGET%20/ HTTP/1.1


Host: localhost:1337
```

## Explanation

1. The initial request is sent to the Apache Proxy (port 1337).

We are sending two HTTP requests in one. Apache only processes up to the first `\r\n\r\n` boundary, meaning it only processes the first part of the request (`GET /api/games/click_topia%20HTTP/1.1`). The smuggled `Host: dev.apacheblaze.local` is treated as part of the request body by Apache. The second GET request (`GET / HTTP/1.1`) is forwarded to Flask without modification.

2. The request is forwarded to the load balancer on port 8080.

The load balancer sends the request to one of the backend servers (either port 8081 or 8082), but the second, smuggled request is effectively injected into the request flow because Apache failed to process it properly.

3. The Flask application processes the request.

The application checks the condition `if request.headers.get('X-Forwarded-Host') == 'dev.apacheblaze.local'`. However, we did not explicitly send `X-Forwarded-Host: dev.apacheblaze.local`. Instead, Apache automatically added `X-Forwarded-Host: dev.apacheblaze.local` when processing the first request before forwarding it to the backend. 

Now, because of HTTP request smuggling, the backend (Flask) interprets the second smuggled request (`GET / HTTP/1.1`) as part of the same connection. Since Flask processes multiple requests over the same connection without resetting headers, the second request inherits the headers from the first request, including: `X-Forwarded-Host: dev.apacheblaze.local`. 

4. The flag is returned.

Flask responds with the flag because the `X-Forwarded-Host` header matches the expected value (`dev.apacheblaze.local`).

> **NOTE:** When Apache is acting as a reverse proxy, it automatically adds several headers for forwarding purposes, including `X-Forwarded-Host`, which mirrors the original Host header from the client request. Apache inserts it during the reverse proxy process. This allows the backend Flask application to see the smuggled header and perform the security check against it. _Read more about it [here](https://httpd.apache.org/docs/2.4/mod/mod_proxy.html#page-header)._



