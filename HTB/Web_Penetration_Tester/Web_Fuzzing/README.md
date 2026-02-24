# HTB: Web Pentest: Module 3: Web Fuzzing 

[Web_Fuzzing_Module_Cheat_Sheet.pdf](https://www.scribd.com/document/772780446/Web-Fuzzing-Module-Cheat-Sheet)

```bash
 ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -ic -u http://94.237.123.185:40357/recursive_fuzz/level1/FUZZ -e .txt,.bak,.js,.html -recursion -mc 200 

```

```bash
 wenum -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -u http://94.237.52.235:41618/get.php?x=FUZZ --hc 404 

Code    Lines     Words        Size  Method   URL 
───────────────────────────── Response number 293: ─────────────────────────────
 200       1 L       1 W        25 B  GET      http://94.237.52.235:41618/get.p 
                                               hp?x=OA_HTML                     

```

## Vhosts and Subdomains

https://wudiaries.com/2024/08/09/A-Comprehensive-Comparison-Between-Virtual-Hosts-and-Subdomains/

```bash
echo "94.237.52.208 inlanefreight.htb" | sudo tee -a /etc/hosts
```

```bash
gobuster vhost -u http://inlanefreight.htb:48851 -w /usr/share/seclists/Discovery/Web-Content/common.txt --append-domain -o result.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://inlanefreight.htb:48851
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/seclists/Discovery/Web-Content/common.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: ADMIN.inlanefreight.htb:48851 Status: 200 [Size: 100]
Found: Admin.inlanefreight.htb:48851 Status: 200 [Size: 100]
Found: admin.inlanefreight.htb:48851 Status: 200 [Size: 100]
Found: awmdata.inlanefreight.htb:48851 Status: 200 [Size: 104]
Found: ipdata.inlanefreight.htb:48851 Status: 200 [Size: 102]
Found: web-beans.inlanefreight.htb:48851 Status: 200 [Size: 108]
Progress: 4723 / 4724 (99.98%)
===============================================================
Finished

```

Fuzzing subdomains that belong to the main domain (inlanefreight.com → 94.237.52.208 )

```bash
$ gobuster dns -d inlanefreight.com  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     inlanefreight.com
[+] Threads:    10
[+] Timeout:    1s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: www.inlanefreight.com

Found: ns1.inlanefreight.com

Found: blog.inlanefreight.com

Found: ns2.inlanefreight.com

Found: ns3.inlanefreight.com

Found: support.inlanefreight.com

Found: my.inlanefreight.com

Found: customer.inlanefreight.com

Progress: 4989 / 4990 (99.98%)
===============================================================
Finished
======================
```

## Filtering Fuzzing out

```bash
# Find directories with status code 200, based on the amount of words, and a response size greater than 500 bytes
aishaxx@htb[/htb]$ ffuf -u http://example.com/FUZZ -w wordlist.txt -mc 200 -fw 427 -ms >500

# Filter out responses with status codes 404, 401, and 302
aishaxx@htb[/htb]$ ffuf -u http://example.com/FUZZ -w wordlist.txt -fc 404,401,302

# Find backup files with the .bak extension and size between 10KB and 100KB
aishaxx@htb[/htb]$ ffuf -u http://example.com/FUZZ.bak -w wordlist.txt -fs 0-10239 -ms 10240-102400

# Discover endpoints that take longer than 500ms to respond
aishaxx@htb[/htb]$ ffuf -u http://example.com/FUZZ -w wordlist.txt -mt >500
```

## Validating Findings

**+ 1**  Fuzz the target system using directory-list-2.3-medium.txt, looking for a hidden directory. Once you have found the hidden directory, responsibly determine the validity of the vulnerability by analyzing the tar.gz file in the directory. Answer using the full Content-Length header, eg "Content-Length: 1337"

```bash
$ ffuf -ic -u http://94.237.120.112:34366/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -mc 200 -e .tar.gz,.txt,.html -recursion -s

index.html
Adding a new job to the queue: http://94.237.120.112:34366/backup/FUZZ
Adding a new job to the queue: http://94.237.120.112:34366/ur-hiddenmember/FUZZStarting queued job on target: http://94.237.120.112:34366/backup/FUZZ
password.txt

Starting queued job on target: http://94.237.120.112:34366/ur-hiddenmember/FUZZ
backup.tar.gz
secret.txt

note2.txt
note1.txt

$ curl http://94.237.120.112:34366/ur-hiddenmember/backup.tar.gz -I
HTTP/1.1 200 OK
Content-Type: application/x-gtar-compressed
ETag: "3478014647"
Last-Modified: Thu, 01 Aug 2024 13:38:21 GMT
Content-Length: 210
Accept-Ranges: bytes
Date: Wed, 17 Dec 2025 09:13:10 GMT
Server: lighttpd/1.4.76

```

## Web APIs

**Web APIs** allow different software applications to communicate over the web using defined rules and data formats. They act as a bridge between a **client** (browser, mobile app, another service) and a **server** that provides data or functionality, independent of programming language or platform.

---

### Types of Web APIs

**REST (Representational State Transfer)**

- Resource-based architecture using **multiple endpoints**
- Uses standard HTTP methods: GET, POST, PUT, DELETE
- Stateless communication
- Common data formats: JSON, XML
- Widely used due to simplicity and flexibility

**Example:**

```
GET /users/123
```

---

**SOAP (Simple Object Access Protocol)**

- Formal, standardized protocol
- Uses **XML** messages wrapped in SOAP envelopes
- Often includes built-in security, reliability, and transaction support
- Common in enterprise environments

**Example:**

```xml
<soapenv:Envelopexmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"xmlns:tem="http://tempuri.org/">
<soapenv:Header/>
<soapenv:Body>
<tem:GetStockPrice>
<tem:StockName>AAPL</tem:StockName>
</tem:GetStockPrice>
</soapenv:Body>
</soapenv:Envelope>
```

---

**GraphQL**

- Single endpoint (e.g., `/graphql`)
- Clients request **exactly** the data they need
- Avoids over-fetching and under-fetching
- Strongly typed with schema introspection
- Popular for modern web and mobile apps

**Example:**

```graphql
query{
  user(id:123){
    name
    email
}
}
```

---

**Advantages of Web APIs**

- Enable standardized data access and integration
- Promote code reuse and modular application design
- Simplify integration with third-party services (authentication, payments, maps)
- Foundation of **microservices architectures**, improving scalability and resilience

---

## APIs vs Web Servers

| Feature | Web Server | API |
| --- | --- | --- |
| Purpose | Serve web pages and assets | Enable application-to-application communication |
| Communication | HTTP with browsers | HTTP, HTTPS, SOAP, and others |
| Data Format | HTML, CSS, JavaScript | JSON, XML, etc. |
| User Interaction | Direct (via browser) | Indirect (used by applications) |
| Access | Usually public | Public, private, or partner-only |

**Examples:**

- Visiting a website loads HTML/CSS/JS from a web server
- A weather app calls an API to fetch weather data, then displays it to the user

---

### Key Takeaway for Fuzzing

Unlike traditional web servers where fuzzing focuses on directories and files, **API fuzzing** targets:

- API endpoints
- Parameters
- Request/response data formats (JSON, XML, GraphQL)

Understanding how APIs differ from web servers is essential for effective API security testing

## **Identifying Endpoints**

**Goal:** Before fuzzing or testing an API, you must first identify the endpoints it exposes and understand how parameters are used.

### REST APIs

- **Endpoints:** URL-based resources arranged hierarchically
    - Examples: `/users`, `/users/123`, `/products/456`
- **Parameter types:**
    - **Query:** `?limit=10&sort=name`
    - **Path:** `/products/{id}`
    - **Body:** JSON data in POST/PUT/PATCH
- **Discovery methods:**
    - Official API documentation (OpenAPI/Swagger, RAML)
    - Network traffic analysis (browser dev tools, Burp)
    - Parameter fuzzing (ffuf, wfuzz) to find hidden parameters

---

### SOAP APIs

- **Structure:** Typically a single endpoint; operations defined in XML
- **Parameters:** Inside the SOAP XML body
- **Key artifact:** WSDL file (defines operations, parameters, data types, endpoint URL)
- **Discovery methods:**
    - Analyze the Web Services Description Language( WSDL)
    - Capture and inspect SOAP traffic
    - Fuzz XML elements and values for undocumented behavior

---

### GraphQL APIs

- **Endpoint:** Usually a single `/graphql` endpoint
- **Operations:**
    - **Queries:** Read data (fields, nested objects, arguments)
    - **Mutations:** Create, update, or delete data
- **Discovery methods:**
    - **Introspection:** Retrieve the full schema (types, fields, arguments)
    - GraphQL documentation and IDEs (GraphiQL, Playground)
    - Network traffic analysis to observe real queries/mutations

example:

1. Code: graphql

```graphql
query {
  user(id: 123) {
    name
    email
    posts(limit: 5) {
      title
      body
    }
  }
}
```

In this example:

- We query for information about a `user` with the ID 123.
- We request their `name` and `email`.
- We also fetch their first 5 `posts`, including the `title` and `body` of each post.

2. Code: graphql

```graphql
mutation {
  createPost(title: "New Post", body: "This is the content of the new post") {
    id
    title
  }
}
```

This mutation creates a new post with the specified title and body, returning the `id` and `title` of the newly created post in the response.

---

### Key Takeaway

- **REST:** Find multiple resource-based URLs and parameters
- **SOAP:** Study the WSDL and XML message structure
- **GraphQL:** Focus on schema discovery via introspection and observed queries

## API Fuzzing

**API fuzzing** is a targeted form of fuzzing focused on web APIs. It sends automated, malformed, or unexpected requests to API endpoints to uncover vulnerabilities such as input validation flaws, injection issues, authentication/authorization bypasses, and logic errors.

---

### What API Fuzzing Does

Each fuzzing test slightly alters an API request by:

- Changing parameter values
- Modifying headers
- Reordering parameters
- Injecting unexpected data types or formats

**Goal:** Trigger errors, crashes, or abnormal behavior that reveal security weaknesses.

---

### Types of API Fuzzing

**1) Parameter Fuzzing**

Tests query parameters, headers, and request bodies with invalid or malicious values.

Helps uncover:

- Injection attacks (SQLi, command injection)
- XSS
- Parameter tampering

**2) Data Format Fuzzing**

Targets structured formats like JSON or XML by altering structure, encoding, or content.

Reveals:

- Parsing errors
- Buffer overflows
- Improper handling of special characters

**3) Sequence Fuzzing**

Tests request order, timing, and interdependencies across endpoints.

Finds:

- Race conditions
- IDOR
- Authorization bypasses
- Logic/state management flaws

---

### Beyond Endpoint Discovery

Fuzzing parameters can also expose:

- **Broken Object-Level Authorization**
- **Broken Function-Level Authorization**
- **Server-Side Request Forgery (SSRF)**

---

**Challenge:** 

```bash
$ ffuf -u http://94.237.52.235:57964/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -s
czcmdcvt
docs
items
┌─[eu-academy-6]─[10.10.15.105]─[htb-ac-1742988@htb-abum030dik]─[~]
└──╼ [★]$ curl http://94.237.52.235:57964/czcmdcvt
{"flag":"h1dd3n_r357"}
```

## Skill Assessment

```bash
 ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt  -ic -u http://94.237.59.242:54760/admin/FUZZ -s -e .txt,.js,.php,.html,.bak --recursion-depth 3
.hta
.hta.txt
.hta.js
.hta.php
.hta.html
.hta.bak
.htaccess
.htaccess.txt
.htaccess.js
.htpasswd
.htaccess.bak
.htaccess.php
.htaccess.html
.htpasswd.txt
.htpasswd.js
.htpasswd.php
.htpasswd.html
.htpasswd.bak
index.php
index.php
panel.php
```

page panel.php requires the accessID parameter with the correct value, so I fuzz it

```bash
$ ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt  -u "http://94.237.59.242:54760/admin/panel.php?accessID=FUZZ" -fw 8 -s
getaccess
                                                                                              
┌──(kali㉿kali)-[~]
└─$ curl http://94.237.59.242:54760/admin/panel.php?accessID=getaccess
Head on over to the fuzzing_fun.htb vhost for some more fuzzing fun!                                                                                              
 
```

Updated my /etc/hosts file with the domain `fuzzing_fun.htb` to map it to the target ip so I can fuzz its vhosts

```bash
 gobuster vhost -u http://fuzzing_fun.htb:54760 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt --append-domain  -q --no-error -o vhosts.txt

```

result:

```bash
$ grep "Status: 200" vhosts.txt 
Found: hidden.fuzzing_fun.htb:54760 Status: 200 [Size: 45]
```

again, we need to dig deeper in the website

```bash
└─$ curl "http://hidden.fuzzing_fun.htb:54760"
Wrong path, remember to be looking in /godeep 
$ curl "http://hidden.fuzzing_fun.htb:54760/godeep/"
Keep going...  
```

```bash
$ ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -ic -u "http://hidden.fuzzing_fun.htb:54760/godeep/stoneedge/FUZZ" -s --recursion        
.htaccess
.hta
.htpasswd
bbclone
Adding a new job to the queue: http://hidden.fuzzing_fun.htb:54760/godeep/stoneedge/bbclone/FUZZindex.php
Starting queued job on target: http://hidden.fuzzing_fun.htb:54760/godeep/stoneedge/bbclone/FUZZ.htaccess
.htpasswd
.hta
index.php
typo3
Adding a new job to the queue: http://hidden.fuzzing_fun.htb:54760/godeep/stoneedge/bbclone/typo3/FUZZStarting queued job on target: http://hidden.fuzzing_fun.htb:54760/godeep/stoneedge/bbclone/typo3/FUZZ.hta
.htaccess
.htpasswd
index.php

```

final page:

```bash
$ curl http://hidden.fuzzing_fun.htb:54760/godeep/stoneedge/bbclone/typo3/        
HTB{w3b_fuzz1ng_sk1lls}
```