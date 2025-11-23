# LetsDefend: Detecting Advanced Web Attacks Module Summary

Table of Contents: 

- [Introduction to Detecting Advanced Web Attacks](#introduction-to-detecting-advanced-web-attacks)
- [Detecting SSTI Attacks](#detecting-ssti-attacks)
- [Detecting ELI Attacks](#detecting-eli-attacks)
- [Detecting HTTP Header Injection Attacks](#detecting-http-header-injection-attacks)
- [Detecting Server-Side Request Forgery Attacks](#detecting-server-side-request-forgery-attacks)
- [Detecting NoSQL Injection Attacks](#detecting-nosql-injection-attacks)

# **Introduction to Detecting Advanced Web Attacks**

Welcome to the training session on web application security for SOC analysts. In today's digital age, web applications have become an integral part of our lives. We use them for everything from online banking to social networking to online shopping. However, with the increasing use of web applications, the risk of cyber-attacks and data breaches has also increased.

As a SOC analyst, it is essential to understand the security risks associated with web applications and the measures that can be taken to protect against them. In this training session, we will explore the various security vulnerabilities that exist in web applications, such as Server-side Request Forgery (SSRF), NoSQL Injection, and Server-side Template Injection (SSTI), and discuss best practices for securing web applications against these threats.

# **Detecting SSTI Attacks**

SSTI (Server-side Template Injection)is a server-side vulnerability that occurs when untrusted input is passed into a template engine and interpreted as template code. An attacker can inject payloads that the template engine executes on the server, potentially causing data disclosure, remote code execution, or full server compromise.

**Here's an example of how Jinja, a popular Python-based template engine, can be used to generate dynamic HTML pages:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/2-ssti/img1.png)

In this example, we have a basic HTML template that includes variables and control structures defined using Jinja syntax. Here's what each section of the template does:

- `{{ page_title }}`: This is a variable that will be replaced with the title of the page.
- `{{ user_name }}`: This is a variable that will be replaced with the name of the user viewing the page.
- `{% for post in recent_posts %}` and `{% endfor %`}: This is a control structure that will loop through a list of recent blog posts and generate an HTML list with links to each post.
- `{{ post.url }}` and `{{ post.title }}`: These are variables that will be replaced with the URL and title of each recent blog post.
- `{{ current_date.strftime('%B %d, %Y') }}`: This is a variable that will be replaced with today's date in a specific format.

To use this template in a Python web application, we would pass in values for the variables and control structures using a context object:

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/2-ssti/img2.png)

In this example, we create a Template object from the HTML file containing our Jinja template. We then create a context dictionary with values for each of the variables and control structures in the template. Finally, we render the template with the context using the render method and get back the fully-formed HTML page as a string.

### **How Server-Side Template Injection Works?**

- The app inserts user-supplied data into a server-side template without proper sanitization or escaping.
- The template engine evaluates the injected expression as code (not plain text).
- The attacker’s expression runs on the server and can read files, run commands, or access application context.

**Here is an example of code that contains an SSTI vulnerability:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/2-ssti/img3.png)

In this code, the Flask web application takes a user-supplied parameter '`name`' from the URL query string, and passes it directly to the `render_template_string` function without proper sanitization or validation. This means that an attacker could potentially inject malicious code into the '`name`' parameter and execute it on the server-side. For example, an attacker could inject the following payload into the '`name`' parameter:

```python
{{ 7*'7' }}
```

If the web application is vulnerable to SSTI, this payload would be interpreted as valid code by the `render_template_string` function, and the resulting HTML page would contain the string '`7777777`'.

An attacker could also inject more malicious code, such as executing system commands, reading sensitive files, or accessing database information. This could allow the attacker to take control of the server or gain access to sensitive information.

## **Common vectors:**

- User inputs (forms, comments)
- Query string parameters / URLs
- Cookies or headers
- Data from APIs or databases that aren’t validated before templating

## **Potential impact:**

- Sensitive data leakage (configs, DB, credentials)
- Remote code execution / server takeover
- Malware injection or pivoting to other systems
- Denial of service and reputational damage

## **Prevention (best practices):**

- Use safe template engines and only trusted features.
- Never evaluate user input as template code. Prefer strict variable substitution over evaluation.
- Validate and whitelist user input; sanitize where appropriate.
- Use context-specific escaping for output.
- Apply least privilege on server processes and keep software patched.
- Implement a Content Security Policy (CSP) to reduce client-side attack surface.

**Here is a fixed version of the vulnerable code provided earlier, with added input validation to prevent SSTI attacks:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/2-ssti/img4.png)

In this fixed version of the code, we have added input validation to the '`name`' parameter before passing it to the `render_template_string` function. The regular expression allows only alphanumeric characters and underscores in the '`name`' parameter. If the '`name`' parameter contains any other characters, the function returns an error message instead of rendering the template.

By validating user input in this way, we can prevent SSTI attacks by ensuring that the '`name`' parameter does not contain any malicious code or special characters that could be interpreted as code by the template engine.

## **Detection (testing & signs):**

- Inject non-harmful template expressions (e.g. `{{2*2}}`, `${6*6}`, `<%=3*3%>`) to see if they evaluate.
- Try payloads that access application objects (e.g. `{{dump(app)}}`, `{{app.request.server.all|join(',')}}`) in safe testing environments only.
- Monitor logs for unusual template evaluation errors or suspicious inputs.
- Use automated scanners and manual review focused on places input flows into templating.

**ere is an example of an Nginx log entry that may indicate an SSTI attack:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/2-ssti/img5.png)

In this example, an HTTP GET request was made to the `'/greet`' endpoint, with a query string parameter '`name`' that contains an SSTI payload: `{{%20config.items()%20}}`

The `%20` characters are URL-encoded spaces, which are used to separate the different parts of the payload. The `config.items()` method is a Python function that retrieves a dictionary of all the configuration variables in the application.

If the application is vulnerable to SSTI, this payload could cause the template engine to execute the `config.items()` function and return a dictionary of configuration variables to the attacker.

This log entry can help to detect SSTI attacks by indicating that an SSTI payload was sent to the application and potentially executed by the template engine. By monitoring the web server logs and looking for unusual or suspicious payloads, security analysts can identify potential SSTI attacks and take action to mitigate them.

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/2-ssti/img6.png)

In this example, an `HTTP GET` request was made to the `'/greet`' endpoint, with a query string parameter '`name`' that contains an SSTI payload: `{{7*7}}`.

This payload contains a simple mathematical expression, which in this case would evaluate to `49`. If the application is vulnerable to SSTI, this payload could cause the template engine to execute the mathematical expression and return the result to the attacker.

This log entry can help to detect SSTI attacks by indicating that an SSTI payload was sent to the application and potentially executed by the template engine. By monitoring the web server logs and looking for unusual or suspicious payloads, security analysts can identify potential SSTI attacks and take action to mitigate them. here's a regular expression that can be used to detect potential SSTI attacks in Nginx logs:

```
\{\{.*?\}\}
```

This regular expression matches any string that contains a pair of double curly braces with any character in between them (including newlines), which is the syntax used by many template engines to indicate variable substitution or expressions to be evaluated.

To use this regular expression in practice, you can search the Nginx access log for any log entries that match this pattern, and investigate them further to determine if they represent a genuine SSTI attack. Note that some legitimate web applications may also use this syntax for their own purposes, so it's important to carefully review any matched log entries before assuming they represent an SSTI attack.

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/2-ssti/img7.png)

- In the first log entry, an `HTTP GET` request was made to the '`/greet`' endpoint with a payload of `{{7*7}}`, which represents an SSTI payload that will be evaluated by the server-side template engine. The response code was `200`, indicating a successful request.
- In the second log entry, an `HTTP POST` request was made to the '`/search`' endpoint with no payload, but this does not necessarily mean that the request was not vulnerable to SSTI. It's possible that the payload was sent in a request parameter or in the request body, which may not be visible in the Nginx access log.
- In the third log entry, an `HTTP GET` request was made to the '`/admin`' endpoint with a payload of '`{{1+2}}`', which is another SSTI payload that the template engine will evaluate. However, in this case, the server returned a response code of **500**, indicating that an error occurred during template evaluation. **This could be a sign that the server has some protection mechanisms in place to detect and prevent SSTI attacks.**

So it can clearly be seen user sends to SSTI payload from source IP `203.0.113.3` on dates `15/Apr/2023:15:10:05` and `15/Apr/2023:15:12:35`.

In conclusion, Server-Side Template Injection is a dangerous vulnerability that can have serious consequences if left unchecked. It can be used by attackers to gain unauthorized access to sensitive data, execute arbitrary code, and take control of the server. However, by understanding the techniques used by attackers, detecting and preventing SSTI attacks can be easier.

## Q&A

**Log file:** `/root/Desktop/QuestionFiles/SSTI.log`

**Q1. What parameter affected SSTI?**

```bash
grep -P --color=always -n $'(?i)(%7B%7B|%7B%25|%25257B%25257B|%25257B%2525|%24%7B|%23%7B)' SSTI.log 

```

<img width="1250" height="728" alt="image" src="https://github.com/user-attachments/assets/0c5f2df7-07de-480b-bc50-897deb8343ce" />

*Ans: message*

**Q2. What file did that attacker try to read using SSTI?**

payload-1:

```bash
GET /product?message=%7b%7b2%2a2%7d%7d[[3%2a3]] HTTP/1.1" 
```

Decoded:

```bash
GET /product?message={{2*2}}[[3*3]] HTTP/1.1" 
```

Payload-2: 

```bash
GET /product?message=%7b%7bdump(app)%7d%7d 
```

Decoded:

```bash
GET /product?message={{dump(app)}} 
```

payload-3:

```bash
GET /product?message=%7b%7bapp%2erequest%2eserver%2eall%7cjoin(',')%7d%7d HTTP/1.1"
```

Decoded:

```bash
GET /product?message={{app.request.server.all|join(',')}} HTTP/1.1"
```

Payload-4:

```bash
GET /product?message=%7b%7bconfig%2eitems()%7d%7d HTTP/1.1"
```

Decoded:

```bash
GET /product?message={{config.items()}} HTTP/1.1"
```

Payload-5:

```bash
GET /product?message=%7b%%20for%20key,%20value%20in%20config%2eiteritems()%20%%7d%3cdt%3e%7b%7b%20key%7ce%20%7d%7d%3c%2fdt%3e%3cdd%3e%7b%7b%20value%7ce%20%7d%7d%3c%2fdd%3e%7b%%20endfor%20%%7d HTTP/1.1
```

Decoded:

```bash
GET /product?message={% for key, value in config.iteritems() %}<dt>{{ key|e }}</dt><dd>{{ value|e }}</dd>{% endfor %} HTTP/1.1
```

Payload-6:

```bash
GET /product?message=%7b%7b'a'%2etoUpperCase()%7d%7d%20 HTTP/1.
```

```bash
GET /product?message={{'a'.toUpperCase()}}  HTTP/1.
```

Pyload-7:

```bash
GET /product?message=%7b%7bapp%2erequest%2equery%2efilter(0,0,1024,%7b'options'%3a'system'%7d)%7d%7d 
```

Decoded:

```bash
GET /product?message={{app.request.query.filter(0,0,1024,{'options':'system'})}} 
```

Payload-8:

```bash
ET /product?message=%7b%7b%20''%2e__class__%2e__mro__[2]%2e__subclasses__()[40]('%2fetc%2fpasswd')%2eread()%20%7d%7d HTTP/1.1
```

Decoded:

```bash
ET /product?message={{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }} HTTP/1.1
```

*Ans: /etc/passwd*

**Q3. What was the attacker's IP address?**

*Ans:144.87.91.181*

# Detecting ELI Attacks

An **Expression Language (EL)** is a small language embedded in templates, JSP/JSF pages, configuration files, or frameworks (e.g., JSP EL, Unified EL, Spring EL). It lets developers evaluate expressions at runtime to pull values, call methods, access scopes (request/session/application), and manipulate data.

## What is Expression Language Injection (ELI)

**ELI** occurs when attacker-controlled input is inserted into an EL expression that the server evaluates. If user input reaches an EL evaluator unchecked, an attacker can inject expressions that the server evaluates — ranging from simple arithmetic to object access, data exfiltration, or full remote code execution (RCE) in vulnerable environments.

## Typical attack vectors

- Form fields and query parameters (URL)
- Hidden fields and cookies
- HTTP headers (User-Agent, Referer, etc.)
- Any server-side data sources (APIs, DB values) that are later used inside EL expressions

## How ELI works (mechanics + example)

1. App constructs or renders an EL expression that includes user input (for example in a view/template or when building an expression string).
2. The EL interpreter evaluates the expression on the server.
3. If input contains EL syntax and is not sanitized/whitelisted, it will be executed.

**Simple benign example:**

`${1+1}` → evaluator returns `2` (shows that EL is being evaluated).

**Malicious Java/Spring example (RCE attempt):**

```jsx
${T(java.lang.Runtime).getRuntime().exec('ls')}
```

If evaluated in a vulnerable Spring EL context this can spawn OS commands (or be adapted to read files, call Java APIs, etc.).

**Here's an example of vulnerable code that is susceptible to Expression Language Injection (ELI):**

This example uses the Spring Framework to generate a dynamic web page that displays a list of users and their account balances

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/3-ELI/img1.png)

In this code, the `listUsers`method retrieves a list of all users from a database using the `userService`, adds the list to the Model object, and returns the name of the view `userList`. The view `userList`uses an expression language statement to iterate over the list and display the name and account balance of each user:

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/3-ELI/img2.png)

However, this code is vulnerable to ELI because it uses user input (`userId`) to retrieve a user from the database in the `userDetails` method. An attacker can modify the value of the `userId`parameter to inject a malicious expression into the `userDetails`view.

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/3-ELI/img3.png)

In this example, an attacker can modify the `userId`parameter to inject a malicious expression, such as `${1+1}` or `${user.password}`, which will be evaluated by the expression language interpreter and displayed on the page. The `userDetails`view does not properly validate or sanitize user input, which makes it vulnerable to ELI attacks.

## Common ELI payload patterns

- `${1+1}`, `${3*3}` — test evaluation
- `${request.getSession().getAttribute('x')}` — access session data
- `${sessionScope.attr}`, `${pageContext.request.contextPath}` — read app/request context
- `${T(java.lang.Runtime).getRuntime().exec('command')}` — attempt RCE via Runtime
- Longer reflection-based variants:
    
    `${T(java.lang.Class).forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('command')}`
    

## Impacts

- **Data theft:** read config files, DB content, secrets.
- **Account/session compromise:** read or manipulate session attributes.
- **Remote Code Execution (RCE):** spawn processes, run arbitrary commands.
- **Application disruption:** crashes, errors, DoS.
- **Pivoting & escalation:** use server access to attack internal systems.
- **Combined attacks:** used with SQLi, XSS, etc. to broaden impact.

## Prevention (practical measures)

- **Avoid evaluating user-controlled data.** Don’t build EL expressions with raw user input.
- **Whitelist inputs.** Restrict user-supplied values to known-good tokens or enumerations.
- **Use safe APIs.** Prefer frameworks/features that only perform variable substitution rather than evaluation.
- **Disable or restrict EL where possible.** Turn off/limit EL evaluation in user-editable contexts.
- **Context-specific escaping.** Escape data properly before output; don’t rely on EL escaping.
- **Least privilege.** Run app with minimal OS/process permissions so even if exploited damage is limited.
- **Keep libs patched.** Update frameworks and template engines to pick up fixes.
- **Static/dynamic code review & tests.** Review code paths that evaluate expressions; add security tests.

## Detection — what to look for & testing

**Active testing (safe):**

- Inject benign test payloads into inputs and observe responses: `${2*2}`, `${T('a')}`, etc.
- Try payloads that reference common EL objects (request, session, application) in testing environments.

**Log analysis / signatures:**

- Search access/error logs for EL syntax (`${`, `%{`, other engine-specific delimiters).
- Look for keywords commonly used in attacks: `Runtime`, `ProcessBuilder`, `System`, `forName`, `getRuntime`, `pageContext`, `sessionScope`, `request`, `setAttribute`, `getAttribute`.

**Example regexes for logs (tunable):**

- Detect encoded GET requests containing `${...}`:

```
GET.*\$\%7b.*\%7d.*HTTP\/.*
```

- Generic detection for EL tokens in logs:

```
\$\{.*\}|\#\{.*\}    # matches ${...} or #{...}
```

- Specific suspicious classes:

```
(Runtime|ProcessBuilder|System|java\.lang\.Runtime|forName)\b
```

**Nginx/log examples to watch for:**

- Requests with `%24%7B` or `${` in the query string or headers.
- 200 responses where request echoed back suspicious EL output.
- Unexpected errors/exceptions referencing EL evaluation in application logs.

**Automated scanning:** Use scanners that check for EL evaluation by injecting probe payloads and examining responses. Combine static analysis to find code paths that call EL evaluators with user input.

Example of how an ELI payload could potentially be logged in an Nginx access log.

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/3-ELI/img4.png)

In this example, the user has made a `GET`request to the vulnerable endpoint of the web application, passing the ELI payload `${T(java.lang.Runtime).getRuntime().exec('ls')}` as a parameter named `param`. The server has responded with a `200` status code and a response size of `496` bytes. The user agent string indicates that the request was made using the `Chrome` browser on a `Windows 10` system.

- Note that the exact format and content of Nginx access logs can vary depending on the server configuration and logging settings.

## Detection workflow / checklist

1. Inventory where EL is used and which inputs feed into it.
2. Add targeted tests (benign expressions) to those inputs in staging and observe behavior.
3. Search logs for EL tokens and suspicious class/method names.
4. Deploy WAF/IDS rules to flag requests containing EL delimiters or high-risk keywords.
5. Remediate any code that builds EL from user input — refactor to safe alternatives or add strict validation.
6. Re-test after fixes and monitor logs for recurrence.

## Q&A

**Log file:** `/root/Desktop/QuestionFiles/ELI.log`

**Q1. What is the attacker's IP address?**

<img width="1919" height="767" alt="image" src="https://github.com/user-attachments/assets/295dab80-acb5-487b-a471-b26aae516679" />

Payload-1

```bash
GET /hello.php?name=(T(org%2espringframework%2eutil%2eStreamUtils)%2ecopy(T(java%2elang%2eRuntime)%2egetRuntime()%2eexec(%22cmd%20%22%2bT(java%2elang%2eString)%2evalueOf(T(java%2elang%2eCharacter)%2etoChars(0x2F))%2b%22c%20%22%2bT(java%2elang%2eString)%2evalueOf(new%20char[]%7bT(java%2elang%2eCharacter)%2etoChars(100)[0],T(java%2elang%2eCharacter)%2etoChars(105)[0],T(java%2elang%2eCharacter)%2etoChars(114)[0]%7d))%2egetInputStream(),T(org%2espringframework%2eweb%2econtext%2erequest%2eRequestContextHolder)%2ecurrentRequestAttributes()%2egetResponse()%2egetOutputStream())) HTTP/1.1" 200 2984 "http://victim/process.php?file=Generics/about.nsp
```

Decoded:

```bash
GET /hello.php?name=(T(org.springframework.util.StreamUtils).copy(T(java.lang.Runtime).getRuntime().exec("cmd "+T(java.lang.String).valueOf(T(java.lang.Character).toChars(0x2F))+"c "+T(java.lang.String).valueOf(new char[]{T(java.lang.Character).toChars(100)[0],T(java.lang.Character).toChars(105)[0],T(java.lang.Character).toChars(114)[0]})).getInputStream(),T(org.springframework.web.context.request.RequestContextHolder).currentRequestAttributes().getResponse().getOutputStream())) HTTP/1.1" 200 2984 "http://victim/process.php?file=Generics/about.nsp
```

Payload-2:

```bash
GET /hello.php?name=$%7b%22%22%2egetClass()%2eforName(%22java%2elang%2eRuntime%22)%2egetMethods()[6]%2einvoke(%22%22%2egetClass()%2eforName(%22java%2elang%2eRuntime%22))%2eexec(%22calc%2eexe%22)%7d HTTP/1.1" 
```

decoded:

```bash
GET /hello.php?name=${"".getClass().forName("java.lang.Runtime").getMethods()[6].invoke("".getClass().forName("java.lang.Runtime")).exec("calc.exe")} HTTP/1.1" 
```

Payload-3:

```bash
GET /hello.php?name=$%7brequest%2egetAttribute(%22a%22)%7d HTTP/1.1"
```

Decoded:

```bash
GET /hello.php?name=${request.getAttribute("a")} HTTP/1.1"
```

Payload-4:

```bash
GET /hello.php?name=$%7brequest%2esetAttribute(%22a%22,%22%22%2egetClass()%2eforName(%22java%2elang%2eProcessBuilder%22)%2egetDeclaredConstructors()[0]%2enewInstance(request%2egetAttribute(%22c%22))%2estart())%7d HTTP/1.1"
```

Decdoed:

```bash
GET /hello.php?name=${request.setAttribute("a","".getClass().forName("java.lang.ProcessBuilder").getDeclaredConstructors()[0].newInstance(request.getAttribute("c")).start())} HTTP/1.1"
```

Payload-5:

```bash
GET /hello.php?name=$%7brequest%2esetAttribute(%22c%22,%22%22%2egetClass()%2eforName(%22java%2eutil%2eArrayList%22)%2enewInstance())%7d HTTP/1.1"
```

Decdoed:

```bash
GET /hello.php?name=${request.setAttribute("c","".getClass().forName("java.util.ArrayList").newInstance())} HTTP/1.1"
```

**Q2. What was the command that the attacker tried to run in the bash context?**

<img width="1913" height="68" alt="image" src="https://github.com/user-attachments/assets/845fe705-477d-47f3-8946-b539be4f994f" />

**Q3. How many payloads did the attacker try to the vulnerable parameter?**

<img width="1880" height="804" alt="image" src="https://github.com/user-attachments/assets/c7d736bf-3aff-4611-822e-ddb3a0cd6eb8" />

*Ans: 17*

# **Detecting HTTP Header Injection Attacks**

### **What is HTTP Header Injection?**

HTTP Header Injection is a vulnerability where attackers manipulate data that gets inserted into HTTP request or response headers. When user input is not properly validated, attackers can inject malicious content (such as additional headers or line breaks) into headers.

### **How HTTP Works**

HTTP communication includes:

- **Requests**: Sent by clients to servers.
- **Responses**: Sent by servers back to clients.

Both contain **headers**, which are key-value metadata fields that influence how content is interpreted (e.g., `User-Agent`, `Content-Type`, `Cookie`, etc.).

### **How Header Injection Happens**

The vulnerability occurs when user-supplied input is inserted into HTTP headers **without proper sanitization**.

Attackers often inject:

```
\r\n   (Carriage Return + Line Feed)
```

This breaks the header structure and allows:

- Adding new headers
- Modifying existing ones
- Splitting responses (HTTP Response Splitting)

### **Common Attack Effects**

| Attack Technique | Result |
| --- | --- |
| **CRLF Injection** | Insert rogue headers / break structure |
| **HTTP Response Splitting** | Multiple forged responses |
| **Cache Poisoning** | Poison shared caches with malicious responses |
| **XSS via Header Manipulation** | Run malicious scripts in browser |
| **Session Hijacking** | Modify authentication cookies |

### **Example of Vulnerable Code**

**Here's an example of vulnerable code that demonstrates an HTTP header injection vulnerability in a Java servlet:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/4-HTTP+Header/img1.png)

**I**n this example, the code retrieves user input from the request parameter "`name`" and directly includes it in the value of the "`X-User`" HTTP response header. However, this code does not perform any validation or sanitization on the user input before incorporating it into the header value.

An attacker can exploit this vulnerability by submitting a manipulated value for the "`name`" parameter that includes line breaks (`%0D%0A` or `\r\n`). For instance, consider the following malicious input:

```
John Doe%0D%0AInjected-Header: Malicious-Value
```

When this input is passed to the vulnerable code, the resulting HTTP response will contain two headers instead of one:

```
X-User: Welcome, John Doe
Injected-Header: Malicious-Value
```

### **Example Payload Types**

| Goal | Example Payload |
| --- | --- |
| Add a header | `\r\nInjected-Header: Malicious` |
| Inject JS | `<script>alert('XSS')</script>` |
| Manipulate Cookies | `sessionID=123%0D%0ASet-Cookie: attacker=true` |

## **Impact**

- **XSS:**  Attackers can inject JavaScript into a response header so the victim’s browser runs it.
- **Session Hijacking:** Sessions are often stored in cookies. If an attacker can inject: `Set-Cookie: sessionID=attacker123` then the victim’s browser will **replace their real session ID** with the attacker’s one.
- **Cache Poisoning:** CDNs and reverse proxies store responses for performance. If attackers poison these responses, **everyone** who accesses the site receives the malicious content. The attacker injects headers that make the browser store a **fake login page** in cache. Now all users get the attacker’s fake page → **credential theft**
- **Security Bypass:** Security systems rely on headers for rules (e.g., CORS, authentication checks, cache rules). If attackers modify these headers, they can bypass restrictions.
- **Information Disclosure:** Attackers can cause the application to reveal **internal information**. For example: Injecting debugging headers could reveal: Internal IPs, Server technology, and  file paths

## **Prevention**

1. **Validate and Sanitize Input** (remove `\r`, `\n`, etc.)
2. **Whitelist expected character formats**
3. **Encode output** before inserting into headers
4. **Do not place raw user input in HTTP headers**
5. **Use security-aware frameworks or libraries**
6. **Keep server and app components updated**

**Here's an updated version of the vulnerable code example, incorporating input validation and proper encoding to prevent HTTP header injection:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/4-HTTP+Header/img2.png)

**In the updated code:**

- The user input is passed through a ``sanitizeInput()`` function, which performs input validation and sanitization to remove or encode any special characters that could be used for injection.
- The sanitized input is then used to construct the header value, ensuring that it does not contain any potentially malicious content.
- By separating user input from the header value construction and applying input validation, we mitigate the risk of HTTP header injection.

The ``sanitizeInput()`` function should implement appropriate validation and encoding techniques based on your specific requirements and input context. It may include steps such as removing line breaks, encoding special characters, or implementing a whitelist-based validation approach.

Remember to adapt the validation and sanitization process to your application's needs and consider any additional security measures necessary based on the specific use case.

## Detection Methods (SOC / Monitoring)

- **Network Traffic Monitoring**
- **Web server log analysis (Nginx/Apache logs)**
- **SIEM correlation rules**
- **Regex-based detection**
- **Signature-based rules**

### **Suspicious Indicators**

- `%0D%0A`
- Encoded characters like `%3C` (`<`) or `%3E` (`>`)
- Unexpected new headers appearing in logs

### **Example Suspicious Nginx Log Entry**

```
GET /page HTTP/1.1" 200 "Referer: test%0d%0aX-Payload: malicious"
```

### **Detection Regex Example**

```
/(?i)\b(GET|POST|HEAD)\b.*HTTP\/\d\.\d".*((?:%[0-9a-fA-F]{2}){2,}|[\x00-\x1F\x7F<>])/gm
```

This looks for:

- **Control characters** (`\x00-\x1F`)
- **Encoded characters likely used for injection** (`%xx` patterns)

**Here’s an example of an Nginx access log file entry that includes a potential HTTP header injection attack:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/4-HTTP+Header/img3.png)

In this example, the log entry shows a GET request to ``/example-page`` with a suspicious payload in the ``User-Agent`` header. The payload ``<?php system('ls -la'); ?>`` indicates a potential attempt to execute arbitrary code on the server using the ``system`` function.

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/4-HTTP+Header/img4.png)

In this example, the log entry shows a GET request to `/example-page` with a suspicious payload in the `Referer` header. The payload includes a line break (`%0d%0a`) and a custom header `X-Payload` containing the value `malicious-script`. This combination suggests a potential HTTP header injection attempt, where the attacker tries to manipulate the `Referer` header and introduce their own custom header.

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/4-HTTP+Header/img5.png)

In these examples:

1. The first log entry demonstrates a potential header injection attack by manipulating the ``Referer`` header and introducing a custom header ``X-Payload`` containing an `XSS` payload.

2. The second log entry shows a potential injection attempt by modifying the ``User-Agent`` header with a line break (``%0d%0a``) and an additional header ``X-Inject`` containing an HTML script tag.

3. The third log entry showcases a potential injection attack in a POST request, where the ``User-Agent`` header is manipulated with a line break (``%0d%0a``). The ``Content-Type`` header is also tampered with, followed by an additional header ``X-Payload`` containing JSON data with an XSS payload.

## Q&A

**Log file:** `/root/Desktop/QuestionFiles/HTTP.log`

**Q1. What is the attacker's IP address?**

```bash
grep -P --color=always -n '(?i)(%0d%0a|%0D%0A|%250D%250A|\\r\\n)' HTTP.log 
```

<img width="1017" height="598" alt="image" src="https://github.com/user-attachments/assets/11491a2e-ee33-4382-8a78-748bb16af952" />

*Ans: 154.16.72.210*

**Q2. What was the date of the attack start?**

*Ans: 28/Oct/2015:12:08:59*

**Q3. Which vulnerability is triggered if the attacker's last attempted payload is successful?**

Based on the inserted header and the value inserted to it: 

```bash
Referer: https://example.com%0d%0aX-Payload: <script>alert('Injection')</script>"
```

The header Referer was used to inject another header that will execute XSS payload

*Ans: XSS*

# Detecting Server-Side Request Forgery Attacks

## Understanding SSRF

Server-Side Request Forgery (SSRF) is a web security vulnerability that allows an attacker to manipulate server-side requests initiated by a web application. It occurs when an attacker can control the URL or parameters of a request made by the server to other internal or external systems. Typically, web applications need to make requests to various resources such as databases, APIs, or other web services. SSRF occurs when an attacker is able to manipulate these requests to access unauthorized resources or gain sensitive information.

## Example: SSRF Exploitation Scenario

Consider a web application that allows users to provide a URL to fetch the content of a web page and display it on the site. The application retrieves the content by making a server-side request to the specified URL. Here's how an attacker could exploit SSRF in this scenario:

1. The attacker discovers the URL input field in the web application and realizes that it is susceptible to SSRF.
2. The attacker submits a malicious URL, such as "`http://internal-server/api/get-sensitive-data`," pointing to an internal API that is not intended to be publicly accessible.
3. the web application blindly makes a server-side request to the provided URL without proper validation or restrictions.
4. The server initiates the request, targeting the attacker's supplied URL and attempting to fetch the content.
5. Since the attacker controlled the URL, the server unwittingly sends the request to the internal API, breaching the intended security boundaries.
6. The internal API responds to the request and sends back the sensitive data, thinking it is a legitimate request from within the trusted network.
7. The server-side application receives the response from the internal API and may process or display the sensitive data within the web application.

As a result of this SSRF exploit, the attacker successfully accessed the internal API and retrieved sensitive data that was not meant to be exposed publicly. The attacker could further exploit this data or use it for malicious purposes.

This example demonstrates how an attacker can leverage SSRF to bypass security measures and gain unauthorized access to internal resources. It highlights the importance of proper input validation, secure coding practices, and defense mechanisms to mitigate the risk of SSRF vulnerabilities in web applications.

- It's important to note that this example is just one scenario, and SSRF can be exploited in various ways depending on the specific vulnerabilities and configurations of the targeted application and infrastructure.

**Here's an example of code that showcases a vulnerable implementation susceptible to SSRF:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/5-ssrf/img1.png)

In this example, we have a simple Flask application that exposes an endpoint `/fetch` to retrieve the contents of a webpage specified by the `url`query parameter. However, this implementation is vulnerable to SSRF due to inadequate input validation.

An attacker can exploit this vulnerability by providing a malicious URL that points to an internal or sensitive resource. For instance, the attacker can craft a request like `http://internal-server/api/get-sensitive-data`, where internal-server is an internal network resource.

When the vulnerable server receives this request, it will blindly make a server-side request to the supplied URL using the `requests.get()` function, without properly validating or restricting the input.

As a result, the server-side application will initiate a request to the attacker's specified URL, potentially accessing internal resources or sensitive data. The response obtained from the malicious request can then be further processed or displayed within the application, exposing confidential information.

## Exploitation Techniques

Common exploitation techniques used in SSRF attacks:

1. **URL Manipulation:**
    1. Attackers manipulate the target URL provided to the vulnerable application.
    2. They may modify the scheme, domain, path, or query parameters of the URL to redirect the request to a different resource.
    3. For example, an attacker can change ``https://example.com`` to ``https://attacker.com`` to make the server-side request to their controlled domain.
2. **IP Address Abuse:**
    1. Attackers can use IP addresses instead of domain names in the URL to bypass DNS resolution.
    2. By providing the IP address of an internal server, the attacker can attempt to access internal resources that are not meant to be exposed publicly.
        
        ![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/5-ssrf/img3.png)
        
3. **Protocol Abuse:**
    1. SSRF is not limited to HTTP requests. Attackers can exploit other protocols such as FTP, SMB, SMTP, or `file://` to interact with different services or systems.
    2. For example, an attacker can use ``ftp://attacker.com/malicious-file`` to retrieve a file from their FTP server.
        
        ![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/5-ssrf/img4.png)
        
4. **Port Scanning and Service Enumeration:**
    1. Attackers can abuse SSRF to scan ports and enumerate services running on internal networks.
    2. By making requests to various ports on internal IP addresses, attackers can determine which ports are open and potentially discover vulnerable services.
        
        ![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/5-ssrf/img5.png)
        
5. **SSRF to SSRF:**
    1. In some cases, attackers can chain multiple SSRF vulnerabilities together to escalate their attack.
    2. They can exploit SSRF vulnerabilities in one system to target another system within the same infrastructure, thus bypassing network boundaries.
        
        ![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/5-ssrf/img6.png)
        
6. **Request Smuggling:**
    1. Attackers can utilize SSRF in combination with request smuggling techniques to manipulate and control the flow of requests.
    2. By injecting specific headers or modifying the request structure, attackers can bypass security mechanisms and gain unauthorized access to internal systems.
        
        ![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/5-ssrf/img7.png)
        

These examples illustrate different exploitation techniques that attackers can employ to manipulate server-side requests and leverage SSRF vulnerabilities. It's important to understand these techniques to effectively identify and prevent SSRF vulnerabilities in web applications.

- **For the example payloads please check →  [Server Side Request Forgery Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md).**

## **Impacts of SSRF (Server-Side Request Forgery)**

### **1. Information Disclosure**

- SSRF can expose **sensitive internal information** that should not be publicly accessible.
- Attackers may target internal services, metadata endpoints, or private APIs.
- This can result in leakage of:
    - User data
    - Internal configurations
    - Credentials (e.g., AWS metadata: `http://169.254.169.254/latest/meta-data/`)

### **2. Access to Internal Systems**

- SSRF allows attackers to **bypass firewall restrictions** and access internal networks.
- Internal services such as databases, admin dashboards, or microservices may be exposed.
- This can lead to:
    - Unauthorized data access
    - Changes to internal system state
    - Compromise of internal network components

### **3. Remote Code Execution (RCE)**

- In some cases, SSRF can be escalated to **execute code** on the server.
- Attackers may send crafted requests to trigger:
    - Command execution endpoints
    - Deserialization vulnerabilities
    - File upload or injection points
- This can result in **full server compromise**.

### **4. Server-Side Request Smuggling (SSRS)**

- SSRF can be used with **request smuggling techniques** to manipulate how servers handle requests.
- Attackers may inject or alter HTTP headers.
- Potential consequences:
    - Authentication bypass
    - Privilege escalation
    - Hidden request execution
    - Data leakage between internal systems

### **5. Escalation of Other Vulnerabilities**

- SSRF often acts as a **pivot point** to exploit additional weaknesses within the network.
- Once inside, attackers may launch:
    - SQL Injection (SQLi)
    - XML External Entity attacks (XXE)
    - Server-Side Template Injection (SSTI)
    - Local File Inclusion (LFI)
- This enables deeper compromise and **lateral movement** inside the environment.

## **Best Practices for Prevention**

**1. Input Validation and Whitelisting**

- Implement strict validation on all user-supplied URLs and parameters.
- Sanitize inputs to ensure they match expected formats.
- Use **whitelisting** to allow only approved and trusted domains or URLs.

**2. Secure Configuration**

- Configure firewalls, routers, and server environments to restrict unnecessary outbound requests.
- Disable unused protocols or services that could be exploited.
- Block access to internal IP ranges and sensitive network segments from external requests.

**3. User Access Controls**

- Ensure users only have access to the resources they specifically need (Principle of Least Privilege).
- Implement strong authentication and authorization for sensitive APIs and services.

**4. URL Whitelisting / Blacklisting**

- Maintain a list of **trusted domains** that the application is allowed to connect to.
- Use **whitelisting** to explicitly allow only safe URLs.
- Optionally use **blacklisting** to block known malicious URLs (but do not rely on this alone).

**5. Network-Level Protection**

- Use a Web Application Firewall (WAF) to detect and block SSRF-related traffic.
- Monitor network logs regularly for suspicious or unexpected outbound requests.

**6. Regular Updates and Patches**

- Keep server software, libraries, and application dependencies updated.
- Track security advisories and apply patches quickly to prevent exploitation of known vulnerabilities.

**Here's an updated version of the code that includes fixes to address the SSRF vulnerability:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/5-ssrf/img8.png)

In this updated version, the following fixes have been applied:

- Whitelisting:
    - A whitelist of trusted domains (``allowed_domains`) has been defined.
    - The ``urlparse`` function is used to extract the domain from the provided URL.
    - The extracted domain is checked against the whitelist to ensure it's an allowed domain.
    - If the domain is not in the whitelist, the request is rejected with a `403` Forbidden response.

By implementing this whitelist-based approach, only URLs from trusted domains will be allowed, mitigating the risk of SSRF attacks. It's important to maintain and update the ``allowed_domains`` list with the domains that your application needs to access.

- Note that this code snippet focuses on the SSRF vulnerability fix, and it assumes that other security practices (e.g., input validation, secure coding practices) are already in place. Additionally, it's crucial to consider other security measures, such as rate limiting, network-level protections, and secure configuration, to further enhance the security of your application.

## Cloud SSRF

Cloud Server-Side Request Forgery (Cloud SSRF) targets cloud resources and services (VMs, containers, cloud metadata APIs, managed services). Cloud environments add unique risks because metadata services and internal APIs often expose sensitive information (temporary credentials, instance config) that attackers can access through SSRF.

### Why cloud SSRF is especially dangerous

- Cloud providers expose **instance metadata endpoints** (e.g., AWS IMDS at `169.254.169.254`) that contain instance info, user-data, and **temporary IAM credentials**.
- SSRF that reaches these endpoints lets attackers **steal credentials** and then access other cloud services.
- Dynamic/cloud networking (auto-scaling, ephemeral VMs, overlays) can make detection and containment harder.

### Common cloud SSRF techniques & examples

1. EC2 Metadata access

- Metadata endpoint (AWS): `http://169.254.169.254/latest/meta-data/`
- Attackers probe or request metadata paths to enumerate services or find credentials:
    - Detect IMDS version / endpoints:
        
        ```
        GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
        ```
        
    - Retrieve role credentials:
        
        ```
        GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>/
        ```
        

2. Accessing user-data

- User data may contain scripts, secrets, or configuration injected at instance launch:
    
    ```
    GET http://169.254.169.254/latest/user-data/
    ```
    

3. Metadata path traversal

- Malformed requests or poor parsing can allow traversal beyond intended endpoints:
    
    ```
    http://169.254.169.254/latest/meta-data/iam/security-credentials/../
    ```
    

4. Temporary credential theft

- If an IAM role is attached to the instance, the metadata service returns temporary credentials (access key, secret, token). Stolen creds enable API calls to cloud services.

5. Metadata endpoint overrides / misconfigurations

- Some cloud features let admins override endpoints. An attacker who can control that configuration or exploit SSRF may redirect metadata requests to attacker-controlled servers.

## Detection methods for SOC analysts

### Log analysis

- Review web server, application, and proxy logs for suspicious outgoing requests or parameters containing:
    - Internal IPs (e.g., `169.254.169.254`, `10.*`, `172.16.*`, `192.168.*`)
    - URLs with `http://169.254.169.254` or other metadata paths
    - Unusual ports or protocols

### Network traffic monitoring

- IDS/IPS or network monitoring tools should flag:
    - Unexpected connections from application servers to internal IP ranges
    - High volume of outbound requests to internal addresses
    - Requests to link-local addresses (169.254.x.x)

### Endpoint protection

- Detect processes or app components making unexpected outbound requests (e.g., web app worker contacting metadata endpoints).
- Monitor for tools or scripts that parse or exfiltrate metadata content.

### SIEM / correlation rules

- Create correlation rules that combine:
    - App log entries containing internal IPs or metadata paths
    - Unusual network flows from the app server
    - New privileged API calls (e.g., IAM or EC2 APIs) originating from app × time window

### WAF & web logs

- Inspect WAF logs for requests with parameters containing URLs or protocols (e.g., `http://`, `file://`, `ftp://`) or link-local IPs.
- Tune WAF rules to block or alert on requests that try to reference metadata endpoints.

### Behavioral analytics/anomaly detection

- Establish baseline for normal outbound requests from application servers and alert on deviations (spikes, new destinations, new ports).

## Regex & log patterns to identify SSRF indicators

Use these as starting points; tune to your log format and false-positive tolerance.

- Match `169.254.169.254` (AWS metadata):

```
169\.254\.169\.254
```

- Detect any link-local / private IPs inside parameters:

```
\b(?:169\.254(?:\.\d{1,3}){2}|10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2})\b
```

- Match URLs (protocol + host) in parameters:

```
\b(?:https?|ftp|file):\/\/\S+\b
```

- Match IP addresses inside URLs:

```
\b(?:https?|ftp):\/\/(?:(?:\d{1,3}\.){3}\d{1,3})\b
```

- Detect encoded metadata requests (percent-encoded):

```
(?:169%2E254%2E169%2E254|169%254%169%254|%31%36%39%2E%32%35%34%2E%31%36%39%2E%32%35%34)
```

*(Note: encoded forms vary; tune to logs.)*

**Here's an example of an Nginx access log entry that contains a potential SSRF attack:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/5-ssrf/img9.png)

Let's break down the components of this log entry:

- ``192.168.1.100`` - The IP address of the client making the request.
- `- -` The hyphen placeholder for the remote user and authenticated user (not available in this example).
- `[25/May/2023:10:30:15 +0000]` - The timestamp of the request.
- `"GET /vulnerable?target=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1"`- The HTTP request line, indicating a GET request to the `/vulnerable`endpoint with a query parameter `target` pointing to an AWS metadata URL.
- `200`- The HTTP status code of the response (in this case, a successful response).
- `532` - The size of the response in bytes.
- `"-"` The referrer field (not available in this example).
- `"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`" - The user agent string indicating the client's browser.

In this example, the log entry shows a GET request made to the ``/vulnerable`` endpoint with a query parameter ``target`` pointing to an AWS metadata URL (``http://169.254.169.254/latest/meta-data/iam/security-credentials/``). This is a potential indicator of an SSRF attack, as the client is attempting to access the AWS metadata service endpoint.

The following regular expression (regex) pattern can be used for detecting AWS metadata URLs:

```
\b(https?:\/\/169\.254\.169\.254\/.+)\b
```

This regex pattern matches URLs starting with `http://` or `https://` followed by the AWS metadata IP address `169.254.169.254` and any path or query parameters after it.

Please note that this is a simplified example, and in real-world scenarios, SSRF attacks can take various forms and may be more complex. Analyzing the complete context, additional log entries, and patterns across multiple log entries can provide a more comprehensive understanding of potential SSRF attacks in Nginx access logs.

**Another example:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/5-ssrf/img10.png)

In this example, each log entry represents a different request made to the Nginx server. The lines contain various HTTP methods (GET, POST), query parameters, and URLs that potentially indicate SSRF activity.

Detecting all possible SSRF payloads in Nginx access logs with a single regex pattern can be challenging due to the wide range of potential payloads. However, you can use a combination of regex patterns and filtering techniques to identify common SSRF indicators. Here's an example of an approach to detect SSRF payloads in Nginx access logs:

```
^(?=.*?(GET|POST))(?=.*?(http:\/\/|https:\/\/))(?=.*?(169\.254\.169\.254|127\.0\.0\.1|attacker-site\.com|example\.com|admin-site\.com)).*$
```

By using this regex pattern and applying it to your Nginx access logs, you can identify log entries that contain potential SSRF indicators. However, please note that this regex pattern is not an exhaustive solution and may require customization based on your specific use case and known SSRF indicators.

## Q&A

**Log file:** `/root/Desktop/QuestionFiles/SSRF.log`

**Q1. What was the attacker's IP address?**

I got one result: 

```bash
root@ip-172-31-45-90:~/Desktop/QuestionFiles# grep -P --color=always -n '(?:169\.254\.169\.254|169%2E254%2E169%2E254|169%252E254%252E169%252E254)' SSRF.log 
968:94.23.33.25 - - [29/Oct/2015:23:38:45 +0100] "GET /api?target=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-default-ssm/ HTTP/1.1" 200 532 "http://victim.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

```

*Ans: 94.23.33.25*

**Q2. What was the payload that the attacker tried to access AWS metadata?**

*Ans: http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-default-ssm/*

**Q3. When attack is started?**

*Ans: 29/Oct/2015:23:38:45*

# Detecting NoSQL Injection Attacks

## **What is NoSQL?**

NoSQL (“Not Only SQL”) databases are designed to store large volumes of diverse data types (structured, semi-structured, and unstructured) without requiring a fixed schema. They are commonly used in large-scale, high-availability applications.

### **Key Characteristics**

| Characteristic | Description |
| --- | --- |
| **Schema-less** | Data does not need to conform to a predefined structure. |
| **Scalable** | Supports horizontal scaling across distributed systems. |
| **High Availability** | Designed to remain accessible despite node failures. |
| **Model Diversity** | Supports multiple data models (key-value, document, graph, column-family). |

### **Types of NoSQL Databases**

| Type | Description | Examples |
| --- | --- | --- |
| Key-Value Store | Key → Value lookup | Redis, Riak |
| Document Store | JSON-like document model | MongoDB, CouchDB |
| Column-Family Store | Data stored in columns/column families | Cassandra, HBase |
| Graph Database | Represents relationships | Neo4j, Amazon Neptune |

## **NoSQL Injection vs SQL Injection**

| Aspect | SQL Injection | NoSQL Injection |
| --- | --- | --- |
| Target | SQL databases | NoSQL databases (e.g., MongoDB, CouchDB) |
| Data Model | Fixed schema | Flexible schema |
| Query Language | SQL statements | Database-specific query language or APIs |
| Exploitation | Injects SQL syntax | Injects JSON/NoSQL operators (like `$gt`, `$ne`, `$regex`) |
| Impact | Data theft, modification, admin execution | Data access bypass, privilege escalation, system compromise |

## **Examples of Injection Payloads**

### **SQL Injection (Login Bypass)**

```sql
Input Username: admin' OR '1'='1
```

Resulting Query:

```sql
SELECT * FROM users WHERE username='admin' OR '1'='1';
```

### **NoSQL Injection (MongoDB Example)**

```jsx
db.users.find({ username: req.body.username, password: req.body.password })
```

**Malicious Payload:**

```json
{"$gt": ""}
```

Resulting Query:

```jsx
db.users.find({ username: {"$gt": ""}, password: {"$ne": null} })
```

This bypasses authentication.

## **Common NoSQL Injection Vectors**

### 1. **Query Parameters**

Example vulnerable code:

```jsx
db.users.find({ username: req.query.username })
```

Injection Payload:

```
username[$gt]=admin&password[$ne]=null
```

### 2. **URL Path Parameters**

Vulnerable:

```jsx
db.users.find({ _id: req.params.userId })
```

Payload:

```
/user?userId[$ne]=null
```

### 3. **Form Inputs**

Payload:

```
searchTerm[$regex]=.*)&password[$ne]=null
```

Result: retrieves all records.

### 4. **HTTP Headers / Cookies**

Vulnerable:

```jsx
db.sessions.find({ sessionId: req.cookies.sessionId })
```

Payload:

```
sessionId[$ne]=null
```

## How does NoSQL Injection Work?

Let's walk through an example of how NoSQL injection works using a code snippet. Assume we have a Node.js application using MongoDB as the NoSQL database.

**Here's a vulnerable code snippet that demonstrates a simple login functionality:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/6-nosql/17.png)

In this example, the code retrieves the ``username`` and ``password`` values from the request body and performs a ``findOne`` query to check if there's a matching user in the ``users`` collection.

Now, let's consider a scenario where an attacker tries to exploit a NoSQL injection vulnerability to bypass the authentication check.

- Normal Authentication Request:

If a legitimate user submits the following login request:

- username: `alice`
- password: `123456`

The code will execute the query as follows:

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/6-nosql/18.png)

If a matching user with the provided username and password is found, the user will be authenticated.

- NoSQL Injection Payload:

**However, an attacker can attempt a NoSQL injection by manipulating the input values. Let's say the attacker submits the following login request:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/6-nosql/19.png)

**In this case, the code will execute the query as follows:**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Advanced-Web-Attacks/6-nosql/20.png)

Here, the attacker has injected NoSQL query operators (``$ne: null``) as the values for both the ``username`` and ``password`` fields. This payload instructs the database to find a user where the ``username`` and ``password`` are not null.

As a result, the query will match any user record in the database that has a non-null ``username`` and ``password`` field, bypassing the authentication check and potentially granting unauthorized access.

## **Impact of NoSQL Injection**

| Impact | Description |
| --- | --- |
| **Unauthorized Data Access** | Attacker retrieves private records. |
| **Data Manipulation / Corruption** | Attacker modifies or deletes stored data. |
| **Denial of Service (DoS)** | Overloading DB with expensive queries. |
| **Privacy Breach** | Leakage of PII / credentials. |
| **System Compromise** | Attackers escalate privileges and pivot. |
| **Financial Loss** | Fraud or data tampering affecting business. |

## **Prevention Methods**

### Input Validation & Sanitization

- Reject unexpected input patterns (e.g., objects where strings expected).

### Parameterized Queries

Example safe query:

```jsx
db.users.find({ username: String(req.body.username) })
```

### Least Privilege Access

- Do not give application service accounts admin-level permissions.

### Role-Based Access Control (RBAC)

- Assign permissions based on user roles and required access.

### Server & Client-Side Validation

- Validate input before it reaches the backend.

---

## **Detecting NoSQL Injection in Logs**

Look for:

- Suspicious operators: `$gt`, `$ne`, `$regex`, `$in`, `$where`
- Unexpected JSON-like structures in URL parameters
- Repeated failed authentication attempts
- Unusually long parameter values
- Error messages indicating malformed query syntax

### **Example Suspicious Log Entry**

```
GET /products?category=electronics&sort[$ne]=null
```

---

## **Regex Pattern for Detecting NoSQL Injection in Logs**

```
(?:\b|["'`])(?i)(?:[^\s]*?(?:\$where|\$regex|\$eq|\$gt|\$gte|\$lt|\$lte|\$ne|\$in|\$nin)[^\s]*?\s*(?:[=:])|(?:(?:\s+or|\|\||&&)\s*\{.*\}\s*))+.*
```

### **What This Detects**

- `$where`, `$regex`, `$in`, `$ne`, etc.
- Operators common in malicious NoSQL injection attempts.

---

## **Summary**

- NoSQL injection occurs when attackers manipulate flexible query structures in document-based databases.
- Monitoring logs, input validation, query parameterization, and least privilege significantly reduce risk.
- Detecting NoSQL injection requires analyzing logs for suspicious operator patterns and query anomalies.

## Q&A

**Log file:** `/root/Desktop/QuestionFiles/NoSQL.log`

**Q1. What was the attacker's IP address?**

Using this Filter: 

```bash
grep -P --color=always -n $'(?:%24(?:where|regex|eq|gt|gte|lt|lte|ne|in|nin)|(?:\\$where|\\$regex|\\$gt|\\$ne))' NoSQL.log

```

<img width="1916" height="441" alt="image" src="https://github.com/user-attachments/assets/a8a7102b-f54c-48a9-96ac-5890881768fd" />

URL Decoded

```bash
/process.php?file=,%20$where%3a%20'1%20%3d%3d%201' -> /process.php?file=, $where: '1 == 1'

GET /process.php?file=%7b%20$ne%3a%201%20%7d -> GET /process.php?file={ $ne: 1 }

"GET /process.php?file=%7b$gt%3a%20''%7d -> "GET /process.php?file={$gt: ''}

GET /process.php?file=[$ne]%3d1 -> GET /process.php?file=[$ne]=1
```

*Ans: 45.57.167.114*

Q2. When did the attack begin?

The first log result showed in the first question

*Ans: 30/Oct/2015:03:37:40*

Q3. How many payloads that attacker tried to the vulnerable parameter?

Following the timestamp of the attack and counting the number of times the attacker tried to inject payloads into the file parameter

<img width="1296" height="753" alt="image" src="https://github.com/user-attachments/assets/73090740-9cce-49bd-bf39-e4ce4e09b03a" />

*Ans: 24*

# Detecting using grep command:

## Detecting SSTI

### 1) High-confidence delimiter detector (raw templates)

Find common template delimiters in request lines, params, headers:

```bash
grep -P --color=always -n $'\\{\\{[^}]{1,300}\\}\\}|\\{\\%[^%]{1,300}\\%\\}|<%=?[^%]{1,300}%>|\\$\\{[^}]{1,300}\\}|#\\{[^}]{1,300}\\}' /var/log/nginx/access.log*

```

- Matches `{{...}}`, `{%...%}`, `<%...%>` or `<%=...%>`, `${...}`, `#{...}` up to 300 chars.

---

### 2) Encoded delimiter detector (percent-encoded start of template)

Detect percent-encoded `{{`/`{%` and double-encoded forms:

```bash
grep -P --color=always -n $'(?i)(%7B%7B|%7B%25|%25257B%25257B|%25257B%2525|%24%7B|%23%7B)' /var/log/nginx/access.log*

```

- `%7B%7B` → `{{` ; `%7B%25` → `{%` ; `%24%7B` → `${` ; `%23%7B` → `#{`.

---

### 3) Dangerous object/method keywords (high-risk)

Search for known high-risk method/class names often present in exploit payloads:

```bash
grep -P --color=always -n '(?i)(__class__|__mro__|__subclasses__|__globals__|subprocess|os\\.popen|os\\.system|getattr\\(|globals\\(|import\\(|eval\\(|exec\\(|ProcessBuilder|Runtime|getRuntime|popen|request\\.|config\\.|cycler|join\\()' /var/log/nginx/access.log*

```

- Case-insensitive; tune the word list to your environment.

---

### 4) Compact SSTI probe detector — delimiters + risky verbs

This looks for template delimiters near risky keywords (high confidence):

```bash
grep -P --color=always -n $'(?i)(\\{\\{[^}]{0,150}(__class__|__subclasses__|__globals__|os\\.popen|subprocess|getattr|exec|eval)\\s*[^}]{0,150}\\}\\}|<%=?[^%]{0,150}(exec|system|popen|Runtime|getRuntime)[^%]{0,150}%>)' /var/log/nginx/access.log*

```

---

### 5) Match only the fragment (short output for triage)

Print only matched fragments — useful for quick review:

```bash
grep -P -o --color=always $'\\{\\{[^}]{1,300}\\}\\}|\\{\\%[^%]{1,300}\\%\\}|<%=?[^%]{1,300}%>|%7B%7B|%7B%25|%24%7B|%23%7B' /var/log/nginx/access.log*

```

---

### 6) Detect double-encoded / obfuscated attempts

Catch `%25`-double-encoded forms (e.g., `%257B%257B`):

```bash
grep -P --color=always -n '(?i)(%25257B%25257B|%25257B%2525|%2524%257B|%2523%257B|%25%7B%25%7B)' /var/log/nginx/access.log*

```

---

### 7) Common SSTI payload examples (search explicitly)

Search for literal exploit examples often used by scanners / attackers:

```bash
grep -F --color=always -n -e '{{7*7}}' -e '{{7*\'7\'}}' -e '{{7*\"7\"}}' -e '${T(java.lang.Runtime).getRuntime().exec('ls')}' -e '{{config.items()}}' /var/log/nginx/access.log*

```

(Adjust literal strings to match logs you expect; use `-F` for fixed-string matching.)

---

### 8) Contextual extraction (client IP | timestamp | request | matched fragment)

Assumes Nginx combined log (adjust `awk` fields to match your format). This prints a compact line per match for triage:

```bash
grep -P --color=never -n $'\\{\\{[^}]{1,300}\\}\\}|\\{\\%[^%]{1,300}\\%\\}|<%=?[^%]{1,300}%>|%7B%7B|%7B%25|%24%7B' /var/log/nginx/access.log* \
| while IFS=: read -r file lineno rest; do
    line=$(sed -n "${lineno}p" "$file")
    ip=$(echo "$line" | awk '{print $1}')
    time=$(echo "$line" | awk '{print $4" "$5}')
    req=$(echo "$line" | awk '{print $7}')
    match=$(echo "$line" | grep -oP '\\{\\{[^}]{1,300}\\}\\}|\\{\\%[^%]{1,300}\\%\\}|<%=?[^%]{1,300}%>|%7B%7B|%7B%25|%24%7B' | tr '\n' ' ')
    printf "%s %s %s %s %s\n" "$file:$lineno" "$ip" "$time" "$req" "$match"
  done

```

---

### 9) Compressed logs

Scan gzipped rotated logs:

```bash
zcat /var/log/nginx/access.log*.gz | grep -P --color=always -n $'\\{\\{[^}]{1,300}\\}\\}|%7B%7B|%7B%25|%24%7B'

```

---

### 10) Narrow, high-confidence daily check

Start daily with only the highest-confidence patterns (delimiters + risky functions):

```bash
grep -P --color=always -n $'(?i)(\\{\\{[^}]{0,200}(__class__|__subclasses__|os\\.popen|subprocess|getattr|exec|eval)\\s*[^}]{0,200}\\}\\}|%7B%7B%5B^%5D{0,200}(__class__|subprocess)%5D%7D)' /var/log/nginx/access.log*

```

(That second half detects some encoded forms — tune as needed.)

---

### 11) SIEM / WAF rule ideas

- **Alert** on any request containing `{{` or `{%` or `<%=` or `${` (and their percent-encoded forms) in query params, headers, or cookies.
- **Block** requests that include both template delimiters **and** risky keywords (`__class__`, `__mro__`, `subprocess`, `os.popen`, `getRuntime`, `ProcessBuilder`, `exec`).
- **Normalize** (URL-decode once or twice) before matching to catch double-encoded attempts.
- Correlate SSTI hits with template engine errors / stack traces in application logs — escalate high-confidence hits.
- Rate-limit or block repeat offenders; combine with Geo/IP reputation.

---

## Detecting ELI

### Quick summary — what to look for

ELI attacks inject expression-language syntax so the server evaluates attacker-supplied expressions. Typical indicators in requests (params, headers, cookies, bodies) include:

- EL delimiters: `${...}`, `#{...}`
- JSP/Servlet scriptlet/expression markers: `<%=` ... `%>` (and `<%` sometimes)
- Spring / Java reflection payloads: `T(java.lang.Runtime).getRuntime().exec(...)`, `Class.forName(...)`
- Common EL-access patterns: `request.`, `session.`, `application.`, `pageContext`, `param.`, `headers.`, `cookie`
- Dangerous method/class names: `Runtime`, `ProcessBuilder`, `getRuntime`, `exec`, `forName`, `invoke`
- Encoded forms: `%24%7B` (for `${`), `%23%7B` (for `#{`), double-encoded `%2524%257B` etc.

> These use PCRE (-P) and safe quoting ($'...') so you can paste into bash.
> 

### 1) Detect raw EL delimiters `${...}` or `#{...}`

```bash
grep -P --color=always -n $'\\$\\{.+?\\}|#\\{.+?\\}' /var/log/nginx/access.log*
```

### 2) Detect common EL / Java reflection method names (high-risk)

```bash
grep -P --color=always -n $'(?i)(?:T\\(|Runtime|getRuntime|ProcessBuilder|Class\\.forName|invoke\\(|exec\\(|pageContext|request\\.|session\\.|application\\.|param\\.)' /var/log/nginx/access.log*
```

### 3) Detect JSP expression/scriptlet patterns (`<%=` / `<%`)

```bash
grep -P --color=always -n $'<%=?\\s*.+?%>' /var/log/nginx/access.log*
```

### 4) Detect encoded EL openings (`%24%7B`, `%23%7B`) and double-encoded forms

```bash
grep -P --color=always -n $'(?i)(?:%24%7B|%23%7B|%2524%257B|%2523%257B|%24\\{|%23\\{)' /var/log/nginx/access.log*
```

### 5) Compact operator + object detector — looks for `$`style or `T(` plus `exec`/`getRuntime`

```bash
grep -P --color=always -n $'(?i)(?:\\$\\{[^}]{1,200}\\}|T\\([^)]{1,200}\\).*?(?:exec|getRuntime|forName|invoke|ProcessBuilder))' /var/log/nginx/access.log*
```

---

## Short output (matched fragments only) — useful for triage

```bash
grep -P -o --color=always $'\\$\\{[^}]{1,200}\\}|#\\{[^}]{1,200}\\}|<%=?[^%]{1,200}%>|%24%7B|%23%7B|T\\([^)]{1,200}\\)' /var/log/nginx/access.log*
```

---

## Encoded / obfuscated detection

Attackers often percent-encode characters or double-encode. Use these to catch such evasions.

### 6) Percent-encoded `${` or `#{`

```bash
grep -P --color=always -n $'(?i)(%24%7B|%23%7B|%2524%257B|%2523%257B)' /var/log/nginx/access.log*
```

### 7) Detect percent-encoded keywords (e.g., `Runtime`, `forName`) in various encodings (hex or double-encoded)

```bash
grep -P --color=always -n $'(?i)(?:R(?:u|%75)ntime|Class(?:\\.forName|%2EforName)|getRuntime|exec|ProcessBuilder|%72%75%6E%74%69%6D%65)' /var/log/nginx/access.log*
```

*(Tune which encoded words to match the patterns seen in your logs.)*

---

### Contextual extraction (client IP + time + request + matched fragment)

Assumes nginx combined log (adjust awk fields if needed). Outputs a concise row per hit.

```bash
grep -P --color=never -n $'\\$\\{[^}]{1,200}\\}|#\\{[^}]{1,200}\\}|<%=?[^%]{1,200}%>|%24%7B|%23%7B|T\\([^)]{1,200}\\)' /var/log/nginx/access.log* \
| while IFS=: read -r file lineno rest; do
    line=$(sed -n "${lineno}p" "$file")
    ip=$(echo "$line" | awk '{print $1}')
    time=$(echo "$line" | awk '{print $4" "$5}')
    req=$(echo "$line" | awk '{print $7}')
    match=$(echo "$line" | grep -oP '\\$\\{[^}]{1,200}\\}|#\\{[^}]{1,200}\\}|<%=?[^%]{1,200}%>|%24%7B|%23%7B|T\\([^)]{1,200}\\)' | tr '\n' ' ')
    printf "%s %s %s %s %s\n" "$file:$lineno" "$ip" "$time" "$req" "$match"
  done
```

---

### Example suspicious payloads to search explicitly

- `${T(java.lang.Runtime).getRuntime().exec('ls')}`
- `${request.getSession().setAttribute('x', 'y')}`
- `#{3*3}` or `#{request.contextPath}`
- `<%= 3 * 3 %>` (JSP expression)
- Percent-encoded forms: `%24%7BT(java.lang.Runtime)%7D`

You can search for these exact substrings with `grep -F` or include them in the above regexes.

---

### Compressed rotated logs

```bash
zcat /var/log/nginx/access.log*.gz | grep -P --color=always -n $'\\$\\{[^}]{1,200}\\}|%24%7B|T\\('
```

---

### SIEM / WAF rule ideas

- **Alert** on any request containing `${` or `#{` (or their percent-encoded forms) in query params, headers or body.
- **Block** high-risk patterns: `${T(` , `Class.forName(`, `getRuntime().exec(`, `ProcessBuilder`.
- **Normalize** input (decode URL encoding once or twice) before matching to detect double-encoded payloads.
- Correlate EL hits with: unusual user-agent, rapid repeated requests, or paths that render templates or reflect input (higher risk).

## Detecting HTTP Header Injection Attack

### Key things to look for

- CRLF sequences (`\r\n`) expressed raw or percent-encoded (`%0D%0A`, `%0d%0a`) or double-encoded (`%250D%250A`).
- Encoded/new header delimiters inside parameters or header values (e.g., `%0d%0aInjected-Header:`).
- Unusually long header values or header-like payloads in `User-Agent`, `Referer`, `Cookie`, or query params.
- Script tags or HTML inside headers (`<script>`) or cookie manipulation (`Set-Cookie:` occurrences echoed).
- Requests that include `\r`, `\n`, or null/control characters (`\x00-\x1F`).
- Percent-encoded characters generally (`%[0-9A-Fa-f]{2}`) — often used for obfuscation.

---

### 1) High-confidence: detect percent-encoded CRLF (`%0D%0A`) or variants

```bash
grep -P --color=always -n '(?i)(%0d%0a|%0D%0A|%250D%250A|\\r\\n)' /var/log/nginx/access.log*
```

### Short output (only matched fragment)

```bash
grep -P -o --color=always '(?i)(%0d%0a|%0D%0A|%250D%250A|\\r\\n)' /var/log/nginx/access.log*
```

---

### 2) Detect raw CR & LF characters (control-chars) in logs

(Some systems log them verbatim — this finds control bytes)

```bash
# show lines with any control character (ASCII 0-31, 127)
grep -P --color=always -n '[\x00-\x1F\x7F]' /var/log/nginx/access.log*
```

> May produce many hits — combine with other indicators to reduce noise.
> 

---

### 3) Detect attempts that include header-name-like injection (`Header-Name:`) after encoded CRLF

```bash
grep -P --color=always -n '(?i)(%0d%0a|%0D%0A|\\r\\n).{0,100}:[A-Za-z-]+:' /var/log/nginx/access.log*
```

This looks for percent-encoded CRLF followed shortly by something that looks like `Header-Name:`.

---

### 4) Look for suspicious `User-Agent`, `Referer`, `Cookie` containing scripts, `Set-Cookie`, or header delimiters

```bash
grep -P --color=always -n '(?i)(User-Agent|Referer|Cookie).*?(<script|set-cookie|%0d%0a|%0D%0A|\r\n)' /var/log/nginx/access.log*

```

---

### 5) Find percent-encoded `Set-Cookie:` or attempts to inject cookies via headers/params

```bash
grep -P --color=always -n '(?i)(%53%65%74%2D%43%6F%6F%6B%69%65|Set-Cookie:|%53%65%74-?Cookie)' /var/log/nginx/access.log*
```

(Detects `Set-Cookie` in encoded forms too.)

---

### 6) Generic percent-encoding detector (show any percent-encoded octet)

```bash
grep -P --color=always -n '%[0-9A-Fa-f]{2}' /var/log/nginx/access.log*
```

Use this to catch obfuscation attempts; pair with specific header names to prioritize.

---

### 7) Detect double-encoding evasions (`%25` is `%` encoded)

```bash
grep -P --color=always -n '(?:%25(?:0D|0d)%25(?:0A|0a)|%250D%250A)' /var/log/nginx/access.log*
```

---

### 8) Detect attempts that include `\r\n` followed by an HTTP status-line (response splitting)

Attackers sometimes craft payloads that inject a fake response head like `HTTP/1.1 200 OK`.

```bash
grep -P --color=always -n '(?i)(%0d%0a|%0D%0A|\\r\\n).{0,200}HTTP\/[0-9]\.[0-9]\s+\d{3}' /var/log/nginx/access.log*
```

---

### 9) Detect `\r\n` plus HTML/script tags (XSS via header injection)

```bash
grep -P --color=always -n '(?i)(%0d%0a|%0D%0A|\\r\\n).{0,200}<script\b' /var/log/nginx/access.log*
```

---

### 10) Extract context: client IP + timestamp + request + matched fragment

This pipeline returns useful context for triage (assumes nginx combined log — adjust awk fields if different):

```bash
grep -P --color=never -n '(?i)(%0d%0a|%0D%0A|\\r\\n|%25?0[Dd]%25?0[Aa])' /var/log/nginx/access.log* \
  | while IFS=: read -r file lineno rest; do
      line=$(sed -n "${lineno}p" "$file")
      ip=$(echo "$line" | awk '{print $1}')
      time=$(echo "$line" | awk '{print $4" "$5}')
      req=$(echo "$line" | awk '{print $7}')
      match=$(echo "$line" | grep -oP '(?i)(%0d%0a|%0D%0A|\\r\\n|%25?0[Dd]%25?0[Aa]|Set-Cookie:|%53%65%74%2D%43%6F%6F%6B%69%65|<script\b)' | tr '\n' ' ')
      printf "%s %s %s %s %s\n" "$file:$lineno" "$ip" "$time" "$req" "$match"
    done
```

---

### 11) Compressed rotated logs

```bash
zcat /var/log/nginx/access.log*.gz | grep -P --color=always -n '(?i)(%0d%0a|%0D%0A|%25?0[Dd]%25?0[Aa]|Set-Cookie:|<script\b)'
```

---

### 12) Narrow, high-confidence rule (start here for daily checks)

```bash
grep -P --color=always -n '(?i)(%0d%0a|%0D%0A|%250D%250A|\\r\\n).{0,100}:[A-Za-z-]{3,20}\s*:' /var/log/nginx/access.log*
```

This looks specifically for CRLF + a likely header name — lower noise, higher confidence.

---

### 13) SIEM / WAF rule ideas (translate these into your product)

- Alert on any incoming request containing `%0D%0A` or raw control chars in query string, headers, or cookies.
- Block requests where header values contain `<script>` or `Set-Cookie:` sequences.
- Rate-limit / block IPs that produce repeated CRLF injection attempts.
- Normalize encoded content before matching so double-encoded attempts are detected.

---

## Detecting Server-Side Request Forgery

### 1) Detect direct calls to AWS metadata service (raw & encoded)

```bash
# raw and typical percent-encoded forms
grep -P --color=always -n '(?:169\.254\.169\.254|169%2E254%2E169%2E254|169%252E254%252E169%252E254)' /var/log/nginx/access.log*
```

---

### 2) Detect common metadata paths (IMDS, user-data)

```bash
grep -P --color=always -n '(?:/latest/meta-data/|/latest/user-data/|/meta-data/|/user-data/|%2Flatest%2Fmeta-data%2F|%2Flatest%2Fuser-data%2F)' /var/log/nginx/access.log*
```

---

### 3) Detect requests referencing **private / link-local IP ranges** (incl. encoded)

```bash
grep -P --color=always -n $'\b(?:10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2}|169\.254(?:\.\d{1,3}){2})\b' /var/log/nginx/access.log*
```

Encoded variants (percent-encoded dotted form like `10%2E0%2E0%2E1`):

```bash
grep -P --color=always -n '(?:10%2E|172%2E|192%2E|169%2E)' /var/log/nginx/access.log*
```

---

### 4) Detect URLs / schemes in parameters (http/https/file/gopher/data)

```bash
grep -P --color=always -n '(?i)(?:\b(?:https?|file|gopher|ftp|data):\/\/|%3A%2F%2F|%3A%2F)' /var/log/nginx/access.log*
```

- `gopher://` is frequently abused for port/protocol probing and SSRF -> remote exploitation attempts.
- `file://` and `data:` may reveal attempts to fetch local files or inject data URIs.

---

### 5) Catch percent-encoded URL components (general)

This surfaces many encoded SSRF attempts:

```bash
grep -P --color=always -n '%[0-9A-Fa-f]{2}' /var/log/nginx/access.log*
```

---

### 6) Focused: detect attempts to access IMDSv1 / credential endpoints

```bash
grep -P --color=always -n '(?i)(?:/latest/meta-data/iam/security-credentials/|/meta-data/iam/security-credentials/|security-credentials)' /var/log/nginx/access.log*
```

---

### 7) Detect suspicious ports in URLs (common internal services)

Search for URLs with ports often used internally (e.g., `:22`, `:2375` Docker API, `:9200` Elasticsearch):

```bash
grep -P --color=always -n 'https?:\/\/(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}' /var/log/nginx/access.log* \
  | grep -E --color=always ':(?:22|2375|9200|5984|8000|8080|5000)\b'
```

---

### 8) Detect double-encoded attempts (e.g., `%252F` or encoded `169.254`)

```bash
grep -P --color=always -n '%25(?:2F|2E|2C|3A)|%252E|%25169' /var/log/nginx/access.log*
```

(Adjust for patterns you observe in your logs.)

---

### 9) Show only the matched fragment (short triage)

```bash
grep -P -o --color=always '(?i)(?:169\.254\.169\.254|/latest/meta-data/|file:\/\/|gopher:\/\/|https?:\/\/(?:\d{1,3}\.){3}\d{1,3}|%[0-9A-Fa-f]{2})' /var/log/nginx/access.log*
```

---

### 10) Contextual output: client IP + timestamp + request + matched fragment

This extracts contextual fields from hits. It assumes a common nginx combined log format (IP is field 1, timestamp field 4, request path field 7). If your format differs, adjust the `awk` fields.

```bash
# Grep lines then print useful fields
grep -P --color=never -n '(?i)(169\.254\.169\.254|/latest/meta-data/|file:\/\/|gopher:\/\/|https?:\/\/(?:\d{1,3}\.){3}\d{1,3}|%[0-9A-Fa-f]{2})' /var/log/nginx/access.log* \
  | while IFS=: read -r file lineno rest; do
      line=$(sed -n "${lineno}p" "$file")
      ip=$(echo "$line" | awk '{print $1}')
      time=$(echo "$line" | awk '{print $4" "$5}')
      req=$(echo "$line" | awk '{print $7}')
      match=$(echo "$line" | grep -oP '(?i)(169\.254\.169\.254|/latest/meta-data/|file:\/\/|gopher:\/\/|https?:\/\/(?:\d{1,3}\.){3}\d{1,3}|%[0-9A-Fa-f]{2})' | tr '\n' ' ')
      printf "%s %s %s %s %s\n" "$file:$lineno" "$ip" "$time" "$req" "$match"
    done
```

---

### 11) Scanning compressed rotated logs

```bash
zcat /var/log/nginx/access.log*.gz | grep -P --color=always -n '(169\.254\.169\.254|/latest/meta-data/|%[0-9A-Fa-f]{2})'
```

---

### 12) Reduce false positives — high-confidence short list

Start with only the best indicators (metadata IPs and metadata paths):

```bash
grep -P --color=always -n '(169\.254\.169\.254|/latest/meta-data/|/latest/user-data/)' /var/log/nginx/access.log*
```

---

### Quick detection & triage workflow (recommended)

1. Run the **high-confidence** filter (step 12) daily/near-real-time.
2. For hits, use pipeline (step 10) to gather source IP, timestamp, request, matched fragment.
3. Correlate with outbound network flows from the app server — did the app actually connect to internal IPs?
4. If IMDS credentials are suspected stolen, check cloud audit logs for API calls using unexpected credentials.
5. Tune rules to exclude known, benign internal tooling or monitoring probes.

---

### SIEM / WAF rule ideas

- Alert on any request containing `169.254.169.254` or `/latest/meta-data/`.
- Alert on requests that include both a URL scheme (`http://` / `file://` / `gopher://`) and a private IP range.
- Create an anomaly rule: app endpoint that normally never fetches external URLs suddenly has many requests with `http://` in parameters.
- Block high-risk schemes with WAF (e.g., `file://`, `gopher://`) at the edge if not needed.

---

## Detecting No-SQL Attacks

### 1) Full/strict NoSQL operator detector (grep -P)

Searches for common NoSQL operators (`$where`, `$regex`, `$gt`, `$ne`, `$in`, `$nin`, etc.), JSON-like objects, and logical operator patterns.

```bash
grep -P --color=always -n $'(?:\\b|["\'`])(?i)(?:[^\\s]*?(?:\\$where|\\$regex|\\$eq|\\$gt|\\$gte|\\$lt|\\$lte|\\$ne|\\$in|\\$nin)[^\\s]*?\\s*(?:[=:])|(?:(?:\\s+or|\\|\\||&&)\\s*\\{.*\\}\\s*))+.*' /var/log/nginx/access.log*
```

- `P` = PCRE; `n` = line numbers; `-color=always` highlights matches.
- Good starting point for catching explicit operator use and JSON payloads.

---

### 2) Extract only the matched fragment (grep -oP)

Print just the matching portion (useful for quick triage):

```bash
grep -P -o --color=always $'(?:\\b|["\'`])(?i)(?:[^\\s]*?(?:\\$where|\\$regex|\\$eq|\\$gt|\\$gte|\\$lt|\\$lte|\\$ne|\\$in|\\$nin)[^\\s]*?\\s*(?:[=:])|(?:(?:\\s+or|\\|\\||&&)\\s*\\{.*?\\}\\s*))+.*' /var/log/nginx/access.log*
```

---

### 3) Faster / nicer: ripgrep (rg) PCRE2 version

If you have `rg` (ripgrep) installed — faster and easier quoting:

```bash
rg --pcre2 -n --color=always '(?:\b|["'`])(?i)(?:[^\s]*?(?:\$where|\$regex|\$eq|\$gt|\$gte|\$lt|\$lte|\$ne|\$in|\$nin)[^\s]*?\s*(?:[=:])|(?:(?:\s+or|\|\||&&)\s*\{.*\}\s*))+.*' /var/log/nginx/access.log*
```

(If shell quoting is problematic, wrap the pattern in `$'…'` similarly to the `grep` examples.)

---

### 4) Catch encoded payloads (percent-encoded `$` / operators)

Detect common percent-encoded operator attempts like `%24ne` (encoded `$ne`):

```bash
grep -P --color=always -n $'(?:%24(?:where|regex|eq|gt|gte|lt|lte|ne|in|nin)|(?:\\$where|\\$regex|\\$gt|\\$ne))' /var/log/nginx/access.log*
```

---

### 5) Find `[$name]=` parameter patterns (common in querystring exploits)

Looks for query parameters using `param[$op]=...` style:

```bash
grep -P --color=always -n $'\[\$(?:where|regex|eq|gt|gte|lt|lte|ne|in|nin)\]=' /var/log/nginx/access.log*
```

---

### 6) Search compressed rotated logs

If logs are gzipped (e.g., `access.log.1.gz`), use `zcat`/`zgrep` with care:

```bash
zcat /var/log/nginx/access.log*.gz | grep -P --color=always -n $'(?:\\$where|\\$regex|\\$gt|\\$ne|\\$in|\\$nin)'
```

(Use `zgrep` only for simple patterns; it may not support `-P` on some distros.)

---

### 7) Combine with `awk` to show client IP + request line for context

Helpful to see source IP and exact request:

```bash
grep -P --color=never -n $'(?:\\$where|\\$regex|\\$gt|\\$ne|\\$in|\\$nin)' /var/log/nginx/access.log* \
  | cut -d: -f1 \
  | xargs -I{} sed -n '{}p' /var/log/nginx/access.log* \
  | awk '{print $1 " " $7 " " $0}'
```

(Adjust `awk` fields depending on your log format — common nginx combined format has client IP as `$1` and request path as `$7`.)

---

### 8) Perl one-liner (if `grep -P` not available)

Use Perl to scan with PCRE reliably:

```bash
perl -ne 'print "$.: $_" if /(?:\b|["'\''`])(?i)(?:[^\s]*?(?:\$where|\$regex|\$eq|\$gt|\$gte|\$lt|\$lte|\$ne|\$in|\$nin)[^\s]*?\s*(?:[=:])|(?:(?:\s+or|\|\||&&)\s*\{.*\}\s*))+.*/' /var/log/nginx/access.log*
```

(note the embedded quoting; paste as-is or adapt for your shell)

---

### 9) Reduce false positives — narrower pattern for `$regex` and `$where` only

If your initial scans are noisy, start with only the highest-risk operators:

```bash
grep -P --color=always -n $'(?:\\$where|\\$regex)' /var/log/nginx/access.log*
```

Below are three ready-to-run `grep` filters you can paste into a shell. Each is safe-quoted and tuned for log files (`/var/log/nginx/access.log*`) — change the path if your logs live elsewhere.

- **Detect percent-encoded NoSQL operators (`%24...`, double-encoded `%2524...`, or bracketed `%5B%24...`)**
    
    This looks for encoded forms of `$where`, `$regex`, `$gt`, `$ne`, etc. (case-insensitive). Prints line numbers and highlights matches.
    

```bash
grep -P --color=always -n $'(?i)(?:%24|%2524|%5B%24)(?:where|regex|eq|gt|gte|lt|lte|ne|in|nin)' /var/log/nginx/access.log*
```

If you want **only** the matching fragment (short output for triage):

```bash
grep -P -o --color=always $'(?i)(?:%24|%2524|%5B%24)(?:where|regex|eq|gt|gte|lt|lte|ne|in|nin)' /var/log/nginx/access.log*
```

---

- **General grep to find any percent sign (`%`) in logs**
    
    Quick and dirty: shows any line that contains a `%` character (useful to surface many percent-encoded payloads):
    

```bash
grep --color=always -n '%' /var/log/nginx/access.log*
```

---

- **More precise: detect percent-encoded octets (`%xx` where xx are hex digits)**
    
    This catches typical URL-encoding like `%3C`, `%24`, `%2E` and is better for filtering actual encoded payloads rather than incidental `%` characters:
    

```bash
grep -P --color=always -n '%[0-9A-Fa-f]{2}' /var/log/nginx/access.log*
```
