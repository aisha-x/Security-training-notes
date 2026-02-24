# HTB: Using Web Proxies   

# **Web Proxy**

## **Intercepting Responses**

In Burp, we can enable response interception by going to (`Proxy>Proxy settings`) and enabling `Intercept Response` under `Response interception rules`:

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/1.png)

After that, we can enable request interception once more and refresh the page with [`CTRL+SHIFT+R`] in our browser (to force a full refresh). When we go back to Burp, we should see the intercepted request, and we can click on `forward`. Once we forward the request, we'll see our intercepted response:

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/2.png)

Once we intercepted the html page, change the type from `number`to `text`and the maxlength from `3`to `100`to enable text data type. Now try to input text in the ip field 

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/3.png)

## **Automatic Modification**

### **Burp Match and Replace (request)**

We can go to (`Proxy>Proxy settings>HTTP match and replace rules`) and click on `Add` in Burp. As the screenshot below shows, we will set the following options. Modifying User-Agent

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/4.png)

| `Type`: `Request header` | Since the change we want to make will be in the request header and not in its body. |
| --- | --- |
| `Match`: `^User-Agent.*$` | The regex pattern that matches the entire line with `User-Agent` in it. |
| `Replace`: `User-Agent: HackTheBox Agent 1.0` | This is the value that will replace the line we matched above. |
| `Regex match`: True | We don't know the exact User-Agent string we want to replace, so we'll use regex to match any value that matches the pattern we specified above. |

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/5.png)

### **Automatic Response Modification**

This time we will use the type of `Response body` since the change we want to make exists in the response's body and not in its headers. In this case, we do not have to use regex as we know the exact string we want to replace, though it is possible to use regex to do the same thing if we prefer.

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/6.png)

same thing for maxlength

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/7.png)

Now, once we intercepted the response, it changed automatically to:

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/8.png)

## **Proxying Tools**

If we want to intercept the connection from our command-line or an application to an endpoint, use a proxy between them and run Burp to examine the request set.

### **Proxychains**

One very useful tool in Linux is [proxychains](https://github.com/haad/proxychains), which routes all traffic coming from any command-line tool to any proxy we specify. `Proxychains` adds a proxy to any command-line tool and is hence the simplest and easiest method to route web traffic of command-line tools through our web proxies.

To use `proxychains`, we first have to edit `/etc/proxychains.conf`, comment out the final line and add the following line at the end of it:

```bash
#socks4         127.0.0.1 9050
http 127.0.0.1 8080
```

We should also make use of the `-q` option, which makes `proxychains` operate in "quiet" mode.For example, try using `cURL` 

```bash
$ proxychains -q curl http://94.237.63.174:53045
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Ping IP</title>
    <link rel="stylesheet" href="./style.css">
</head>

<body>
    <form name='ping' class='form' method='post' id='form1' action='/ping'>
        <center>
            <h1>
                <label for="ip">Ping Your IP:</label>
                <center>127.0.0.
                    <input type="text" id="ip" name="ip" min="1" max="255" maxlength="100"
                        oninput="javascript: if (this.value.length > this.maxLength) this.value = this.value.slice(0, this.maxLength);"
                        required>
            </h1>
        </center>
        <br>
        <button class='btn block-cube block-cube-hover' id='submit' type='submit'>
            <div class='bg-top'>
                <div class='bg-inner'></div>
            </div>
            <div class='bg-right'>
                <div class='bg-inner'></div>
            </div>
            <div class='bg'>
                <div class='bg-inner'></div>
            </div>
            <div class='text'>
                Ping
            </div>
        </button>
    </form>
</body>

</html>
```

If we go back to our web proxy (Burp in this case), we will see that the request has indeed gone through it:

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/9.png)

### **Metasploit**

There are options in the modules that allow us to set a proxy. For example, let's try to proxy web traffic made by Metasploit modules to burp suit. We should begin by starting Metasploit with `msfconsole`. Then, to set a proxy for any exploit within Metasploit, we can use the `set PROXIES` flag

```bash
use auxiliary/scanner/http/robots_txt
set PROXIES HTTP:127.0.0.1:8080
set RHOST SERVER_IP
set RPORT PORT

```

`show options` to view the option we set

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/10.png)

Once we type run, we will see that the burp intercepts the request

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/11.png)

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/12.png)

**Challenge**: Try running.'`auxiliary/scanner/http/http_put`' in Metasploit on any website, while routing the traffic through Burp. Once you view the requests sent, what is the last line in the request?

First, use the module, then set the required options

```bash
use auxiliary/scanner/http/http_put
set PROXIES HTTP:127.0.0.1:8080
set RHOSTS 94.237.63.174
set RPORT 53045
```

Once you type run, Burp will intercept it, forward the request, and examine it from http history tab

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/13.png)

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/14.png)

We can similarly use our web proxies with other tools and applications, including scripts and thick clients. All we have to do is set the proxy of each tool to use our web proxy. This allows us to examine exactly what these tools are sending and receiving, and potentially repeat and modify their requests while performing web application penetration testing.

## Skill Assessment

### Q1

**The /lucky.php page has a button that appears to be disabled. Try to enable the button, and then click it to get the flag.** 

in the response, the button is set to disabled

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/s1.png)

In the proxy settings, allow for response interception and on `HTTP match and replace rules`
add a new rule that removes the `disabled` option from the response body

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/s2.png)

Now, every request we intercept, it will change the response body to match the rule

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/s3.png)

click ctrl + shift + R for full refresh

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/s4.png)

### Q2

**The /admin.php page uses a cookie that has been encoded multiple times. Try to decode the cookie until you get a value with 31-characters. Submit the value as the answer.** 

ASCII HEX → BASE64 

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/s5.png)

### Q3.

**Once you decode the cookie, you will notice that it is only 31 characters long, which appears to be an md5 hash missing its last character. So, try to fuzz the last character of the decoded md5 cookie with all alpha-numeric characters, while encoding each request with the encoding methods you identified above. (You may use the "alphanum-case.txt" wordlist from Seclist for the payload)** 

Send the request to the intruder, then: 

1. Highlight the cookie section
2. in the Payload Configuration: load **`alphanum-case.txt` wordlist from Seclist**  
3. In the Payload Processer, add these rules:
    1. Prefix: 3dac93b8cd250aa8c1a36fffc79a17a 
    2. Base64-Encode
    3. Encode as ASCII HEX

As we identified from question 2 that the cookie used multiple encoding for the MD5 hash, and for that, we added the Payload Processer rule to first add the md5 hash + FUZZ on last character, then encode it before sending the payload. 

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/s6.png)

result: 

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/s7.png)

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/s8.png)

### Q4

**You are using the 'auxiliary/scanner/http/coldfusion_locale_traversal' tool within Metasploit, but it is not working properly for you. You decide to capture the request sent by Metasploit so you can manually verify it and repeat it. Once you capture the request, what is the 'XXXXX' directory being called in '/XXXXX/administrator/..'?**

start the metasploit with `msfconsole` then use the module and set the required options

```sql
set Proxies http:127.0.0.1:8080
set RHOSTS 94.237.122.95 
set RPORT 30268

msf6 auxiliary(scanner/http/coldfusion_locale_traversal) > show options

Module options (auxiliary/scanner/http/coldfusion_locale_traversal):

   Name         Current Setting      Required  Description
   ----         ---------------      --------  -----------
   FILE                              no        File to retrieve
   FINGERPRINT  false                yes       Only fingerprint endpoints
   Proxies      http:127.0.0.1:8080  no        A proxy chain of format type:host:port[,type:host:port][...]. Supp
                                               orted proxies: sapni, socks4, socks5, socks5h, http
   RHOSTS       94.237.122.95        yes       The target host(s), see https://docs.metasploit.com/docs/using-met
                                               asploit/basics/using-metasploit.html
   RPORT        30268                yes       The target port (TCP)
   SSL          false                no        Negotiate SSL/TLS for outgoing connections
   THREADS      1                    yes       The number of concurrent threads (max one per host)
   VHOST                             no        HTTP server virtual host

View the full module info with the info, or info -d command.

```

Make sure that the burp is set to intercept, then run the module. 

result: 

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/s9.png)

The burp intercepted the request made by the module 

![Alt](/HTB/Web_Penetration_Tester/Web_Proxies/Images/s10.png)

Ans: CFIDE