# LetsDefend: Detecting Web Attacks 2 Summary

Table of contents: 

- Detecting Open Redirection Attacks
- Detecting Directory Traversal Attacks
- Detecting Brute Force Attacks
- Detecting XML External Entity Attacks

# Detecting Open Redirection Attacks

## **What is Open Redirection?**

Open Redirection is a web vulnerability that occurs when an application redirects users to a URL taken from user input **without proper validation**. Attackers exploit this by crafting URLs on a trusted site that redirect victims to malicious websites (e.g., phishing or malware sites).

## **Common Open Redirection Vectors**

1. **URL-based** – Application redirects using a user-controlled parameter like `?next=` or `?url=`.
2. **JavaScript-based** – Redirect happens in client-side JavaScript using untrusted input.
3. **Meta Refresh Redirects** – HTML meta tags perform redirection using user-supplied values.
4. **Header-based** – Server uses `Location:` header with unvalidated input.
5. **Parameter-based** – Form or URL parameters are inserted into redirect logic without checks.

## How Open Redirection Works?

Here's an example of a vulnerable code in a web application that demonstrates an open redirection vulnerability using PHP:

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/open+redirection/carbon+(1).png)

In this example, the web application takes a target URL as a query parameter (`url`) from the user and uses it in a redirect without validating or sanitizing the input. This can lead to an open redirection vulnerability, as an attacker can craft a malicious URL and pass it as the `url` parameter, leading to unintended redirection to a malicious website.

For example, an attacker could create a URL like this:

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/open+redirection/Bash+URL.png)

When a user clicks on this URL, the vulnerable application will automatically redirect the user to `http://malicious.com`, which could be a phishing website or a site hosting malware.

## **Impact**

- **Phishing:** Users are tricked into entering credentials on fake pages.
- **Malware delivery:** Redirects to malicious downloads.
- **Social engineering:** Users manipulated into unintended actions.
- **Reputation damage:** Vulnerable site appears unsafe.
- **Legal/Risk exposure:** If user data is compromised, the company may face regulatory penalties.

## **Prevention**

- **Validate & sanitize** all redirect inputs.
- Use **whitelists** of allowed domains/paths.
- **Avoid** using user-controlled input directly in redirect logic.
- Ensure proper **authentication & authorization** for sensitive redirection flows.
- Follow **secure coding standards** and **regular security testing**.

Here's an example of a vulnerable code in PHP that demonstrates an open redirection vulnerability, along with a fixed version:

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/open+redirection/Example+Vulnerable.png)

**Fixed Code:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/open+redirection/Example+Fixed.png)

In the fixed version, the `filter_var` function with `FILTER_VALIDATE_URL` filter is used to validate the user-supplied `url` parameter. This filter checks if the value is a valid URL according to the PHP filter extension, and if it returns `true`, the redirect is performed to the validated URL. If the `url` parameter does not pass the validation, a default URL or an error message can be shown, and no redirection is performed. This helps to prevent malicious URLs or invalid values from being used in the redirection process, mitigating the open redirection vulnerability.

## **Detecting Open Redirect Attacks**

Look for:

- Requests with parameters like `?next=` or `?url=` containing external domains.
- Bypass patterns such as:
    - `localhost`, `127.0.0.1`, IPv6 variations (`http://[::]`)
    - Encoded redirects (`%2f` → `/`)
    - Decimal/Hex encoding of IP addresses (`2130706433` = `127.0.0.1`)

**Useful Regex for Log Detection:**

```
/^.*"GET.*\?.*=(https%3a%2f%2f[a-z0-9-]+%2e[a-z]{2,}).+?.*HTTP\/.*".*$/gm
```

This helps identify requests attempting to redirect to external domains.

### Detection Example

Example nginx access log file;

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/open+redirection/Access+Log.png)

As you can see it on the above screenshot, open redirection attacks were made to the `http://victim.com` website on `18/Apr/2023:20:05:05`. We have mentioned that attention should be to encoded characters. Here is where the importance of this issue is seen.

**Encoded:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/open+redirection/encoded-open.png)

**Decoded:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/open+redirection/decoded-open.png)

When we decode the request, we see that the attacker wants to redirect to `google.com` with the `?pro` parameter. When we realize that all requests occur within seconds, we understand that this is done with the help of a tool. At the same time, the source IPs are all the same.

## Q&A

Log location: `/root/Desktop/QuestionFiles/Open-Redirection/access.log`

**Q1. What date did the exploitation phase of Open Redirection start? Format: dd/MMM/yyyy HH:mm:ss**

```bash
grep -Pi '^.*"(GET|POST) [^"]*\?.*=(https%3a%2f%2f[a-z0-9-]+%2e[a-z]{2,}).*HTTP\/.*".*$' access.log
```

<img width="1301" height="802" alt="image" src="https://github.com/user-attachments/assets/802e2c8c-e9bb-4a7b-ad2c-26106067e416" />

We can see in the result that there are multiple URL injections on `postId`parameter from the same ip address. Viewing the file to see where it’s first started

<img width="1285" height="815" alt="image" src="https://github.com/user-attachments/assets/84188c29-3d64-4b8f-be29-4c755cd3a1d8" />

And it was first started on `27/Apr/2023:15:45:22`

```bash
86.236.188.85 - - [27/Apr/2023:15:45:22  0000] "GET /post?postId=//	/example.com HTTP/1.1" 400 42 "http://victim.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36"

```

**Q2. What is the IP address of the attacker who performed the Open Redirect attack?**

*Ans: 86.236.188.85*

**Q3. What was the parameter that attacked?**

*Ans: postId*

# **Detecting Directory Traversal Attacks**

## **What is Directory Traversal?**

Directory Traversal (also known as *dot-dot-slash* attack) occurs when an attacker manipulates file path input (e.g., using `../`) to access files **outside the web server’s intended directory**.

Example vulnerability:

```
http://example.com/profiles/picture.php?name=../../etc/passwd
```

This may allow unauthorized access to sensitive system files.

**Difference from Local File Inclusion (LFI):**

- **Directory Traversal**: Accesses files directly from the file system.
- **LFI**: Includes files into the application's execution, potentially allowing code execution.

## **Attack Vectors**

Directory traversal can occur through:

- **User Input** (URL parameters, form fields): Attackers supply manipulated path values in query strings or form fields that the server uses to open files.
- **Cookies**: App trusts file-path-like values stored in cookies and uses them server-side (e.g., `lastFile=../../secret.txt`).
- **HTTP Headers**: Some apps use headers (Referer, X-File-Name, User-Agent) as input. Attackers tamper with headers to inject traversal sequences.
- **File Uploads:** Uploads that include path instructions (e.g., zip files with `../` entries), or upload handlers that accept a client-specified filename with directories.
- **Direct URL Manipulation** (adding `/../`): Attacker directly alters the URL path (not a parameter) to traverse directories if server routing maps URL paths to filesystem paths. For example: `GET /static/../../WEB-INF/web.xml HTTP/1.1`
- **Malicious Links**: Attackers craft links that, when clicked by a user (or scanned by a bot), cause the vulnerable app to access/return sensitive files—often used in phishing or to trigger SSRF-like behaviors. `https://victim.com/view?file=../../../../etc/passwd` in an email or forum post.

## How Directory Traversal Works?

Here's an example of vulnerable code that is susceptible to directory traversal attacks in a PHP script:

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/directory+traversal/img1.png)

In this example, the script takes a file name as a parameter from the user input using the $_GET method. The script then concatenates the user input with the document root directory to form a full path to the file.

However, this code is vulnerable to directory traversal attacks since an attacker can manipulate the file parameter to include ../ characters, which will allow them to access files outside of the intended directory. For example, an attacker could use the following URL to access the /etc/passwd file on the server:

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/directory+traversal/img2.png)

## **Impact**

Successful directory traversal can result in:

- **Sensitive Data Exposure** (e.g., config files, credentials)
- **Arbitrary Code Execution** (upload or abuse scripts)
- **Denial of Service** (deleting or corrupting files)
- **Full System Compromise** (privilege escalation, backdoors)

## **Prevention**

To prevent directory traversal attacks:

1. **Validate & sanitize input**, especially file paths.
2. **Restrict file system permissions** to limit accessible directories.
3. **Use relative paths** and avoid user input in direct file paths.
4. **Whitelist allowed filenames** or directories.
5. **Follow secure coding practices** (avoid unsafe functions).

**Here's an example of vulnerable PHP code that is susceptible to directory traversal attacks:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/directory+traversal/img3.png)

In this code, the `$file` variable is set to the value of the file parameter from the user's input. The script then concatenates this value with the document root directory to form a full file path in the `$full_path` variable. This code is vulnerable to directory traversal attacks because an attacker can include directory traversal sequences like `../` in the file parameter to access files outside of the intended directory.

**Here's an updated version of the code that uses input validation and sanitization to prevent directory traversal attacks:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/directory+traversal/img4.png)

In this updated version of the code, we first validate the input using a regular expression to ensure that the file name only contains alphanumeric characters, underscores, and hyphens. We then use the `realpath()` function to get the absolute path of the file and check that the resulting path is within the document root directory. This prevents the use of directory traversal sequences like `../` to access files outside of the intended directory. If the file exists, we read and output its contents; otherwise, we output an error message.

## Detecting Directory Traversal Attacks

In Part 1, we have overviewed what the directory traversal attack is and how to prevent this attack type. In this part, we’ll have a look at detection techniques and some tips to make it easier. Before the moving on, let’s have a quick look for example payloads for the directory traversal vulnerability;

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/directory+traversal/img5.png)

These are really basic payloads for directory traversal attacks. So, we should keep in mind `../` (dot dot slash), encoded and double encoded `../` is the key values for this attack type. Here is the basic example for detecting these payloads on nginx `access.log` file;

```
**/^.*"GET.*\?.*=(%2e%2e%2f).+?.*HTTP\/.*".*$/gm**
```

As a bypass technique, attackers may also use unicode encode characters to bypass WAF or any other product.

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/directory+traversal/img7.png)

In that case, Nginx access log will be like;

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/directory+traversal/img8.png)

These are detection payloads for the Directory Traversal attack. For a successful exploit, attacker needs to access some files. **most popular ones are;**

**Linux** 

- **`/etc/issue`**
- **`/etc/passwd`**
- **`/etc/shadow`**
- **`/etc/group`**
- **`/etc/hosts`**

**Windows**

- `c:/boot.ini` **→** Contains: boot entries, default OS, timeout and partition/loader paths
- `c:/inetpub/logs/logfiles` **→** Contains**:** Per-site log files (W3C/ IIS formats) with timestamps, client IPs, request URLs, response codes, user agents, bytes transferred, and sometimes query strings.
- `c:/inetpub/wwwroot/global.asa` **→ C**ontains: `Application_OnStart`, `Session_OnStart` handlers, global variables, and sometimes configuration values or initialization logic.
- `c:/inetpub/wwwroot/index.asp` → Contains: Application HTML/ASP code that may include includes, logic, or links to other resources.
- `c:/inetpub/wwwroot/web.config` → Contains:  XML configuration sections such as `<connectionStrings>`, `<appSettings>`, `<authentication>`, custom error pages, handler/module settings, and security settings.
- `c:/sysprep.inf` → Contains: Setup and regional options, product key, user account info, and sometimes unattended admin credentials or scripts to run on first boot.

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/directory+traversal/directory-log.png)

Basic regex that we have shared above will work with these logs but to prevent False Positive alarms it can be updated more strictly like;

```
/^.*"GET.*\?.*=(.+?(?=%2e%2e%2fetc%2f)).+?.*HTTP\/.*".*$/gm
```

## Q&A

Log location: `/root/Desktop/QuestionFiles/Directory-Traversal/access.log`

**Q1. What date did the exploitation phase of Directory Traversal start? Format: dd/MMM/yyyy HH:mm:ss**

```bash
grep -Pi '"(GET|POST|HEAD) [^"]*\?(?:(?!").)*(?:\.\./|%2e%2e%2f|%2e%2e\\)' access.log
```

<img width="1907" height="188" alt="image" src="https://github.com/user-attachments/assets/59f91ffb-2d2d-4e2b-8440-a38413f095fc" />

*Ans: 23/Apr/2023 00:16:57*

**Q2. What is the IP address of the attacker who performed the Directory Traversal attack?**

*Ans: 123.114.236.235*

**Q3. What was the parameter that attacked?**

*Ans: uid*

# **Detecting Brute Force Attacks**

## **What is Brute Forcing?**

Brute forcing is an attack where an attacker repeatedly tries different usernames, passwords, or tokens until the correct one is found. Automated tools are commonly used to send thousands or millions of login attempts rapidly. Weak passwords make brute forcing easier and faster.

## **Brute Force Vectors**

Brute force attacks in web environments usually target:

1. **Login pages** – guessing usernames and passwords.
2. **Directory / File Enumeration** – guessing hidden directories or files (e.g., `/admin`, `/backup.zip`).

### How Brute Forcing Works?

Here's an example of vulnerable code that is susceptible to Brute Forcing attacks in a PHP script:

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/brute+force/img1.png)

This form is vulnerable to brute force attacks because it allows unlimited login attempts and does not implement any security measures to prevent automated login attempts.

Here's an example of how you can use Python requests library to send multiple login requests with a list of usernames and passwords:

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/brute+force/img2.png)

## **Impact of Brute Forcing**

- **Denial of Service** – large numbers of requests can slow or crash systems.
- **Data Leakage & Account Takeover** – once credentials are found, attackers can access sensitive data.
- **Password Reuse Exploitation** – one successful credential can compromise multiple platforms.
- **Legal & Reputational Risks** – can lead to breaches, lawsuits, and loss of user trust.

## **Prevention Methods**

- **Account Lockout Policies** (lock account after several failed attempts)
- **Rate limiting** (limit login attempts per minute or IP)
- **CAPTCHA / Bot Detection**
- **Multi-Factor Authentication (MFA)**
- **Strong Password Policies**
- **Monitoring login attempts** for unusual patterns
- **Web Application Firewall (WAF)**
    - IP blocking
    - User behavior analysis

## **Detection Techniques**

To detect brute force attempts:

- Analyze authentication logs for:
    - Many failed login attempts from the same **IP** or **username**
    - Sudden spikes in login requests
- Use tools such as **ELK Stack** (Elasticsearch + Logstash + Kibana) or similar SIEM solutions.
- Apply **Regular Expressions** to detect repeated failed login patterns.
- Use **IDS/IPS** to detect abnormal login traffic.

### **Response After Detection**

- Use **Fail2ban** to automatically block malicious IP addresses.
- Manually block abusive IPs in server configuration (e.g., NGINX ban rules).
- Temporarily lock targeted user accounts or require password reset.

**Example Nginx log file that contains Brute Force attack;**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/brute+force/img3.png)

The log file provided shows the unsuccessful login attempts only. In order to detect the successful login attempts, you would need to analyze the logs further or modify your logging configuration to include the successful login attempts as well.

Successful login attempts would typically result in a response code of `200` or a redirect to a different page, which can be identified in the log file. However, keep in mind that some attackers may attempt to obfuscate their successful login attempts by logging in with valid credentials or using a compromised account, so it is important to perform further analysis to determine if any suspicious activity is occurring.

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/brute+force/img4.png)

In this example, the log entry shows a `POST` request to the `/login.php` page with a response code of `302`, which indicates a successful login attempt. The Cookie header also includes a `PHPSESSID` value and a login value, which may be used to track the user session and authentication status. Note that the exact format and contents of the log files can vary depending on the web server and its configuration.

**For example, you can use the deny rule to block traffic from specific IP addresses:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/brute+force/img5.png)

It's important to note that detecting brute force attacks is not always a straightforward process and may require additional analysis and investigation to identify the suspicious activity accurately.

Here's an example of a regular expression that can be used to detect repeated failed login attempts from the same IP address in an nginx log file:

```
**/^(\S+) \S+ \S+ \[.*?\] "(POST|GET) \/login\.php.*?" (401|403) \d+ ".*?" ".*?"/gm**
```

This regular expression will match any log file entry that includes a failed login attempt (401 or 403 status code) to the /login.php page. It will capture the IP address of the client making the request in the first capture group ((\S+)). You can then use a log analysis tool or script to count the number of times each IP address appears in the log file and flag any IP addresses that have a high number of failed login attempts as potential brute force attackers. Also, you can update the regex’s IP address as suspicious IP source.

## Q&A

Log Location: `/root/Desktop/QuestionFiles/Brute-Forcing/access.log`

**Q1. What is the attacker's user agent?**

I tried first to get the failure response with this filter 

```bash
grep -iE '"(POST|GET).*(/login|wp-login.php|/xmlrpc.php|/admin|/user/login)' access.log 
```

But it didn't show much of information, so i included the successful status code in the filter

```bash
grep -E "(401|403|429|200)" access.log 
```

<img width="1322" height="764" alt="image" src="https://github.com/user-attachments/assets/d668794f-76bf-400b-8a74-b9334669abf2" />

Here you can see there are multiple requests to the login page in a short time frame with the status code 200, note that a `200` doesn’t always mean “successful login. This can be one of these reasons:

- **Failed logins that re-render the login page.** Many apps return `200` and show “invalid credentials” HTML rather than `401`. So every failed attempt still looks like a `200`.
- **Client retries / automation.** A bot or script may rapidly retry the same request on failure (or without checking response), creating rapid identical `200` responses.
- **AJAX / heartbeat behavior.** Client-side code might `POST` and then repeatedly poll, or retry on network hiccups.
- **Session or redirect behavior.** A successful login may return `200` for the login handler while client-side JS then navigates (no `302`), or a proxy/load-balancer could transform responses.
- **Load testing / health checks.** Less likely for `/login`, but synthetic tests or crawlers could hit it.
- **Log aggregation differences.** Some frontends/proxies log the backend response size even for failed flows — identical size (947) strongly suggests the same HTML (likely login page) is returned each time.

```bash
GET /post?postId=6 HTTP/1.1" 200 2632 "http://victim.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36
```

*Ans: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36*

**Q2. What is the IP address of the attacker who performed the Brute Forcing attack?**

*Ans: 146.241.73.240*

**Q3. What date did the Brute Forcing successfully complete to login form? Format: dd/MMM/yyyy HH:mm:ss**

The last POST request to the login page was at `26/Apr/2023 21:44:03` as seen in the image below

<img width="1919" height="288" alt="image" src="https://github.com/user-attachments/assets/63160e3d-712f-43cf-a9b3-27bfa49c1555" />

*Ans: 26/Apr/2023 21:44:03*

# Detecting XML External Entity Attacks

## **What is XML?**

XML (Extensible Markup Language) is used to structure and exchange data. It is flexible and readable but has largely been replaced by JSON due to simplicity and modern compatibility.

**What is an XML External Entity (XXE)?**

An XXE vulnerability occurs when an application parses XML input that allows **external entities** to be included. If the XML parser is not securely configured, an attacker can inject malicious entities that cause the server to:

- Read system files
- Make internal network requests
- Consume system resources
- Potentially execute arbitrary code

### **How XXE Works:**

Attackers submit XML containing external entity references.

If the server's XML parser **allows external entities**, the server may fetch and process attacker-controlled content, leading to data leakage or internal network access.

### **Common Input Vectors:**

- Web forms that accept XML input
- File uploads containing XML
- SOAP/REST APIs using XML payloads
- Config or integration systems using XML

Attackers test these entry points with crafted XML that references files or network resources to check if the parser processes external entities.

### **Impact of XXE**

| Impact | Description |
| --- | --- |
| **Information Disclosure** | Attackers can read sensitive server files (e.g., credentials, system configs). |
| **SSRF (Server-Side Request Forgery)** | Server can be forced to make internal network requests (scan/internal service access). |
| **Denial of Service (DoS)** | Large or recursive XML entities can overload memory/CPU. |
| **Remote Code Execution (in rare cases)** | If combined with other vulnerabilities, full server compromise is possible. |

## **Prevention**

To prevent XXE vulnerabilities:

1. **Disable External Entities**
    
    Turn off external entity processing in the XML parser. (Most languages/frameworks allow disabling DTD processing.)
    
2. **Validate and Sanitize XML Input**
    
    Never trust user-provided XML — strip or block DTDs/entities where not needed.
    
3. **Use Secure XML Parsers**
    
    Use modern, hardened parsers that disable XXE by default.
    
4. **Whitelist Allowed Input**
    
    Only allow known-safe entities or schemas.
    
5. **Apply Access Controls**
    
    Limit what the server is allowed to access even if parsing is compromised.
    
6. **Secure Coding Practices**
    
    Follow standard input validation and error handling best practices.
    

**Here's an example of vulnerable PHP code that is susceptible to XML External Entity attacks:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img5.png)

The code above loads an XML input from the `php://input` stream and passes it directly to the `loadXML()` method of the `DOMDocument` class without any validation or sanitization. This makes it vulnerable to XXE attacks.

To fix this vulnerability, we need to validate and sanitize the XML input and disable external entities. Here is an example of a fixed version of the code:

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img6.png)

In the code above, we have disabled external entities using the function `libxml_disable_entity_loader()`, which prevents XXE attacks. We have then validated and sanitized the XML input using a regular expression that only allows alphanumeric and underscore characters. If the input passes validation, we load it into the `DOMDocument`object and output the sanitized XML. If the input fails validation, we output an error message.

This fixed code ensures that the XML input is properly validated, sanitized, and processed securely, and is much less vulnerable to XXE attacks.

## Detecting XML External Entity Attacks

In Part 1, we have overviewed what the XML External Entity is and how to prevent this vulnerability. In this part, we’ll have a look at the detection techniques and some tips to make it easier. Before moving on let’s take a quick look for example payloads for the XML External Entity vulnerability;

**Basic XXE Payload**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img7.png)

**Blind XXE Payload**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img8.png)

**XXE Payload with PHP Filter**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img9.png)

Here's an example of what an Nginx log might look like when an XXE attack occurs via a vulnerable parameter on a `GET` request (This methodology is the same as analyzing `POST` requests):

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img10.png)

In this log, the IP address of the client making the request is `123.45.67.89`. The request was a GET request to the `processXML` endpoint, with an `xml` parameter that contains an `XXE` payload. The `XXE`payload attempts to read the contents of the `/etc/passwd` file. The response code is `200`, indicating that the request was successful, and the response size is `143`bytes. The user agent string indicates that the request was made from a `Chrome` browser on a `Windows 10` machine.

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img11.png)

The most important things to detect XXE attacks on the logs, you should check specific keyword like;

**DOCTYPEELEMENTENTITY**

- DOCTYPE
- ELEMENT
- ENTITY

**So for the detecting !DOCTYPE keyword in nginx logs, we can use regex like;**

```
**^(\S+) - (\S+) \[(.*?)\] "(\S+) (.*?)\?(?=.*?\b21DOCTYPE\b).*? HTTP\/\d\.\d" (\d+) (\d+) "(.*?)" "(.*?)"**
```

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img12.png)

`21` is for the encoded version of the`!` character. Because `!DOCTYPE` is equal to `%21DOCTYPE`. This regex will match the following line on the example that we have shared above;

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img13.png)

And decoded versions are;

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img14.png)

So, it can be clearly seen that the user sends to `XXE` payload from source IP `123.45.67.89` on dates `30/Apr/2023:12:34:57` and `30/Apr/2023:12:34:59.`

## Q&A

Log location: `/root/Desktop/QuestionFiles/XML-External-Entitiy/access.log`

**Q1. What parameter affected XXE?**

I used this filter:

```bash
grep -iE '(<\!DOCTYPE|<\!ENTITY|%3c%21doctype|%3c%21entity|file://|file%3A%2F%2F|gopher://|%3C!DOCTYPE|%3C!ENTITY)' access.log
```

<img width="1919" height="388" alt="image" src="https://github.com/user-attachments/assets/464b4fbd-55f8-4b13-a663-befbd87dc800" />

```
%3C!DOCTYPE%20root%20%5B%20%3C!ENTITY%20xxe%20SYSTEM%20%22file%3A%2F%2F%2Fetc%2Fshadow%22%3E%20%5D%3E%20%3Croot%3E%20%26xxe%3B%20%3C%2Froot%3E 
```

Decoded

```
<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/shadow"> ]> <root> &xxe; </root> 
```

As seen in the output, the parameter that is used to inject the malicious XML code is the data parameter

```bash
GET /process?data=<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/shadow">]<test>&xxe;</test> HTTP/1.1" 200 123 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36"

```

*Ans: data*

**Q2. What file did that attacker try to read using XXE?**

*Ans: /etc/shadow*

**Q3. What was the attacker's IP address?**

*Ans: 94.23.33.25*
