# HTB: Information Gathering - Web Edition


## Introduction

### **Web Reconnaissance**

**Web reconnaissance** is the foundational phase of a security assessment and a key part of the **Information Gathering** stage in penetration testing. Its purpose is to systematically collect information about a target web application or website before deeper analysis or exploitation begins.

![image.png](attachment:f4db8770-079f-4417-b614-a12d98cc20f6:image.png)

### **Main Objectives of Web Reconnaissance**

- **Identify Assets:** Discover public-facing components such as domains, subdomains, IPs, pages, and technologies.
- **Discover Hidden Information:** Find exposed files like backups, configs, or documentation that may reveal weaknesses.
- **Analyze the Attack Surface:** Understand technologies, configurations, and possible entry points.
- **Gather Intelligence:** Collect data useful for exploitation or social engineering (e.g., emails, employees, patterns).

This information helps **attackers** customize attacks and **defenders** proactively detect and fix weaknesses.

### **Types of Web Reconnaissance**

### **1. Active Reconnaissance**

- Involves **direct interaction** with the target.
- Examples include:
    - Port scanning
    - Vulnerability scanning
    - Network mapping
    - Banner grabbing
    - OS fingerprinting
    - Service enumeration
    - Web crawling/spidering
- **Advantages:** More detailed and accurate results.
- **Disadvantages:** Higher risk of detection due to logs, IDS, or firewalls.

### **2. Passive Reconnaissance**

- Gathers information **without directly interacting** with the target.
- Relies on publicly available data such as:
    - Search engines
    - WHOIS records
    - DNS data
    - Web archives
    - Social media
    - Public code repositories
- **Advantages:** Very low risk of detection.
- **Disadvantages:** Limited to already exposed information.

## Whois

WHOIS is a widely used query and response protocol designed to access databases that store information about registered internet resources. 

```sql
whois tryhackme.com
   Domain Name: TRYHACKME.COM
   Registry Domain ID: 2282723194_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.namecheap.com
   Registrar URL: http://www.namecheap.com
   Updated Date: 2025-05-11T14:06:02Z
   Creation Date: 2018-07-05T19:46:15Z
   Registry Expiry Date: 2034-07-05T19:46:15Z
   Registrar: NameCheap, Inc.
   Registrar IANA ID: 1068
   Registrar Abuse Contact Email: abuse@namecheap.com
   Registrar Abuse Contact Phone: +1.6613102107
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Name Server: KIP.NS.CLOUDFLARE.COM
   Name Server: UMA.NS.CLOUDFLARE.COM
   DNSSEC: unsigned
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2026-01-08T10:31:43Z <<<
```

Each WHOIS record typically contains the following information:

- `Domain Name`: The domain name itself (e.g., example.com)
- `Registrar`: The company where the domain was registered (e.g., GoDaddy, Namecheap)
- `Registrant Contact`: The person or organization that registered the domain.
- `Administrative Contact`: The person responsible for managing the domain.
- `Technical Contact`: The person handling technical issues related to the domain.
- `Creation and Expiration Dates`: When the domain was registered and when it's set to expire.
- `Name Servers`: Servers that translate the domain name into an IP address.

## Using WHOIS

WHOIS data is a **valuable intelligence source** during investigations because it reveals **ownership, registration, and infrastructure details** about domains. The three scenarios highlight how WHOIS supports different security use cases:

### **Scenario 1: Phishing Investigation**

- **Key WHOIS clues:**
    - Recently registered domain
    - Hidden registrant (privacy service)
    - Suspicious / bulletproof hosting name servers
- **Conclusion:** Strong indicators of a phishing campaign.
- **Outcome:** Domain blocked, employees warned, infrastructure further investigated.

### **Scenario 2: Malware Analysis**

- **Key WHOIS clues:**
    - Anonymous registrant using free email
    - High-risk geographic location
    - Registrar known for weak abuse enforcement
- **Conclusion:** Likely malicious C2 infrastructure.
- **Outcome:** Hosting provider notified, infrastructure mapped.

### **Scenario 3: Threat Intelligence Reporting**

- **Key WHOIS patterns discovered:**
    - Domains registered in batches before attacks
    - Reused name servers
    - Fake or rotating identities
    - Frequent post-attack takedowns
- **Conclusion:** Enables profiling of threat actor **TTPs**.
- **Outcome:** Creation of **IOCs** and proactive detection rules.

**Overall takeaway:** WHOIS helps detect **malicious intent, infrastructure reuse, and operational patterns**, making it essential for phishing detection, malware analysis, and threat intelligence.

### Example:

```bash
$ whois tesla.com 

Domain Name: tesla.com
Registry Domain ID: 187902_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.markmonitor.com
Registrar URL: http://www.markmonitor.com
Updated Date: 2024-10-02T10:15:20+0000
Creation Date: 1992-11-04T05:00:00+0000
Registrar Registration Expiration Date: 2026-11-03T00:00:00+0000
Registrar: MarkMonitor, Inc.
Registrar IANA ID: 292
Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
Registrar Abuse Contact Phone: +1.2086851750
Domain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)
Domain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)
Domain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)
Domain Status: serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)
Domain Status: serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)
Domain Status: serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)
Registrant Name: Domain Administrator
Registrant Organization: DNStination Inc.
Registrant Street: 3450 Sacramento Street, Suite 405
Registrant City: San Francisco
Registrant State/Province: CA
Registrant Postal Code: 94118
Registrant Country: US
Registrant Phone: +1.4155319335
Registrant Phone Ext: 
Registrant Fax: +1.4155319336
Registrant Fax Ext: 
Registrant Email: admin@dnstinations.com
Tech Name: Domain Administrator
Tech Phone: +1.4155319335
Tech Email: admin@dnstinations.com
Name Server: a7-66.akam.net
Name Server: a28-65.akam.net
Name Server: edns69.ultradns.net
Name Server: edns69.ultradns.com
Name Server: a9-67.akam.net
Name Server: edns69.ultradns.org
Name Server: edns69.ultradns.biz
Name Server: a10-67.akam.net
Name Server: a1-12.akam.net
Name Server: a12-64.akam.net
DNSSEC: unsigned
```

- **Domain Name:** The domain that was queried using the `whois` command.
- **Registry Domain ID:** A unique identifier assigned by the domain registry (e.g., `.com`) to track the domain.
- **Registrar:** The company responsible for registering and managing the domain on behalf of the owner.
- **Registrar WHOIS Server:** The WHOIS server operated by the registrar where detailed domain information is stored.
- **Registrar IANA ID:** A unique identifier assigned by IANA to identify the registrar.
- **Updated Date:** The last time the domain’s registration details were modified.
- **Creation Date:** The date when the domain was first registered.
- **Registry Expiry Date:** The date when the domain registration will expire if not renewed.
- **Registrar Registration Expiration Date:** The expiration date as recorded by the registrar.
- **Registrar Abuse Contact Email:** The email address used to report abuse such as phishing or malware.
- **Registrar Abuse Contact Phone:** The phone number used to report domain-related abuse.
- **Domain Status:** Security flags that control whether the domain can be deleted, transferred, or updated.
- **Name Server:** DNS servers responsible for translating the domain name into IP addresses.
- **DNSSEC:** Indicates whether DNS responses are cryptographically signed for integrity protection.
- **Registrant Name:** The individual or role listed as the owner of the domain.
- **Registrant Organization:** The company or entity that owns the domain.
- **Registrant Street / City / State / Country:** The registered physical address of the domain owner.
- **Registrant Phone:** The contact phone number of the domain owner.
- **Registrant Email:** The email address associated with the domain registration.
- **Technical Contact (Tech Name):** The person or role responsible for technical management of the domain.
- **Tech Phone:** Contact number for technical issues related to the domain.
- **Tech Email:** Email address for technical domain-related communication.
- **Last Update of WHOIS Database:** The most recent time the WHOIS database was refreshed.
- **WHOIS Notices / Terms of Use:** Legal conditions describing how WHOIS data may be accessed and used.

# DNS & Subdomains

## Subdomains

### Challenge:

Using the known subdomains for inlanefreight.com (www, ns1, ns2, ns3, blog, support, customer), find any missing subdomains by brute-forcing possible domain names. Provide your answer with the complete subdomain, e.g., www.inlanefreight.com.  

```bash
$ fierce --domain inlanefreight.com --subdomain-file /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
NS: ns1.inlanefreight.com. ns2.inlanefreight.com.
SOA: ns-161.awsdns-20.com. (205.251.192.161)
Zone: failure
Wildcard: failure
Found: www.inlanefreight.com. (134.209.24.248)
Nearby:
{'134.209.24.245': '1266637.cloudwaysapps.com.',
 '134.209.24.248': 'inlanefreight.com.',
 '134.209.24.252': '1322472.cloudwaysapps.com.'}
Found: ns1.inlanefreight.com. (178.128.39.165)
Nearby:
{'178.128.39.168': 'fdcb359d-fe9f-47d8-ae22-95ee8b233a63.fs.lucidlink.com.'}
Found: ns2.inlanefreight.com. (206.189.119.186)
Nearby:
{'206.189.119.185': '344738.cloudwaysapps.com.'}
Found: blog.inlanefreight.com. (134.209.24.248)
Found: ns3.inlanefreight.com. (134.209.24.248)
Found: support.inlanefreight.com. (134.209.24.248)
Found: my.inlanefreight.com. (134.209.24.248)
```

Ans: `my.inlanefreight.com`

## DNS Zone Transfers

Q1. After performing a zone transfer for the domain inlanefreight.htb on the target system, how many DNS records are retrieved from the target system's name server? Provide your answer as an integer, e.g, 123. 

```bash
$ dig axfr @10.129.107.26  inlanefreight.htb 

; <<>> DiG 9.18.12-1-Debian <<>> axfr @10.129.107.26 inlanefreight.htb
; (1 server found)
;; global options: +cmd
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.
admin.inlanefreight.htb. 604800 IN      A       10.10.34.2
ftp.admin.inlanefreight.htb. 604800 IN  A       10.10.34.2
careers.inlanefreight.htb. 604800 IN    A       10.10.34.50
dc1.inlanefreight.htb.  604800  IN      A       10.10.34.16
dc2.inlanefreight.htb.  604800  IN      A       10.10.34.11
internal.inlanefreight.htb. 604800 IN   A       127.0.0.1
admin.internal.inlanefreight.htb. 604800 IN A   10.10.1.11
wsus.internal.inlanefreight.htb. 604800 IN A    10.10.1.240
ir.inlanefreight.htb.   604800  IN      A       10.10.45.5
dev.ir.inlanefreight.htb. 604800 IN     A       10.10.45.6
ns.inlanefreight.htb.   604800  IN      A       127.0.0.1
resources.inlanefreight.htb. 604800 IN  A       10.10.34.100
securemessaging.inlanefreight.htb. 604800 IN A  10.10.34.52
test1.inlanefreight.htb. 604800 IN      A       10.10.34.101
us.inlanefreight.htb.   604800  IN      A       10.10.200.5
cluster14.us.inlanefreight.htb. 604800 IN A     10.10.200.14
messagecenter.us.inlanefreight.htb. 604800 IN A 10.10.200.10
ww02.inlanefreight.htb. 604800  IN      A       10.10.34.112
www1.inlanefreight.htb. 604800  IN      A       10.10.34.111
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
;; Query time: 308 msec
;; SERVER: 10.129.107.26#53(10.129.107.26) (TCP)
;; WHEN: Thu Jan 08 16:11:41 +03 2026
;; XFR size: 22 records (messages 1, bytes 594)

                                                     
```

Ans:`22`

Q2. Within the zone record transferred above, find the ip address for ftp.admin.inlanefreight.htb. Respond only with the IP address, eg 127.0.0.1 

Ans: `10.10.34.2`

Q3. Within the same zone record, identify the largest IP address allocated within the 10.10.200 IP range. Respond with the full IP address, eg 10.10.200.1 

Ans: `10.10.200.14`

## Virtual Hosts

```bash
gobuster vhost -u http://inlanefreight.htb:46520 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```

## Certificate Transparency Logs

```bash
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[] | select(.name_value | contains("dev"))| .name_value' | sort -u
*.dev.facebook.com
dev.facebook.com
devvm1958.ftw3.facebook.com
facebook-amex-dev.facebook.com
facebook-amex-sign-enc-dev.facebook.com
*.newdev.facebook.com
newdev.facebook.com
*.secure.dev.facebook.com
secure.dev.facebook.com
```

# Fingerprinting

### Challenge

```bash
 curl -I app.inlanefreight.local  
HTTP/1.1 200 OK
Date: Fri, 09 Jan 2026 09:31:45 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: 72af8f2b24261272e581a49f5c56de40=0hpc42o8kn1b4gptu9i0c5jac4; path=/; HttpOnly
Permissions-Policy: interest-cohort=()
Expires: Wed, 17 Aug 2005 00:00:00 GMT
Last-Modified: Fri, 09 Jan 2026 09:31:56 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Content-Type: text/html; charset=utf-8
```

```bash
$ wafw00f http://app.inlanefreight.local 

                   ______
                  /      \                                                                            
                 (  Woof! )                                                                           
                  \  ____/                      )                                                     
                  ,,                           ) (_                                                   
             .-. -    _______                 ( |__|                                                  
            ()``; |==|_______)                .)|__|                                                  
            / ('        /|\                  (  |__|                                                  
        (  /  )        / | \                  . |__|                                                  
         \(_)_))      /  |  \                   |__|                                                  

                    ~ WAFW00F : v2.3.1 ~
    The Web Application Firewall Fingerprinting Toolkit                                               
                                                                                                      
[*] Checking http://app.inlanefreight.local
[+] Generic Detection results:
[-] No WAF detected by the generic detection
[~] Number of requests: 7       
```

```bash
nikto -h http://app.inlanefreight.local -Tuning b
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.129.103.191
+ Target Hostname:    app.inlanefreight.local
+ Target Port:        80
+ Start Time:         2026-01-09 12:33:56 (GMT3)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /robots.txt: Entry '/libraries/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/components/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/administrator/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/cli/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/includes/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/bin/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/modules/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/cache/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/tmp/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/layouts/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/language/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/plugins/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: contains 14 entries which should be manually viewed. See: https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt
+ Apache/2.4.41 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /LICENSE.txt: License file found may identify site software.
+ 1414 requests: 0 error(s) and 18 item(s) reported on remote host
+ End Time:           2026-01-09 12:39:15 (GMT3) (319 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

```bash
curl  app.inlanefreight.local/robots.txt  
# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# https://www.robotstxt.org/orig.html

User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

# **Crawling**

![Alt](/HTB/Web_Penetration_Tester/Information_Gathering/Images/1.png)

![Alt](/HTB/Web_Penetration_Tester/Information_Gathering/Images/2.png)

# **Skills Assessment**

```bash
$ curl -I http://94.237.56.175:52576                            
HTTP/1.1 200 OK
Server: nginx/1.26.1
Date: Fri, 09 Jan 2026 13:51:57 GMT
Content-Type: text/html
Content-Length: 120
Last-Modified: Thu, 01 Aug 2024 09:35:23 GMT
Connection: keep-alive
ETag: "66ab56db-78"
Accept-Ranges: bytes
```

```bash
obuster vhost -u http://inlanefreight.htb:52576 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```

Found: web1337 subdomain

```bash
─$ ./finalrecon.py --headers --url http://web1337.inlanefreight.htb:52576/ --crawl 

 ______  __   __   __   ______   __                                                                              
/\  ___\/\ \ /\ "-.\ \ /\  __ \ /\ \                                                                             
\ \  __\\ \ \\ \ \-.  \\ \  __ \\ \ \____                                                                        
 \ \_\   \ \_\\ \_\\"\_\\ \_\ \_\\ \_____\                                                                       
  \/_/    \/_/ \/_/ \/_/ \/_/\/_/ \/_____/                                                                       
 ______   ______   ______   ______   __   __                                                                     
/\  == \ /\  ___\ /\  ___\ /\  __ \ /\ "-.\ \                                                                    
\ \  __< \ \  __\ \ \ \____\ \ \/\ \\ \ \-.  \                                                                   
 \ \_\ \_\\ \_____\\ \_____\\ \_____\\ \_\\"\_\                                                                  
  \/_/ /_/ \/_____/ \/_____/ \/_____/ \/_/ \/_/                                                                  

[>] Created By   : thewhiteh4t
 |---> Twitter   : https://twitter.com/thewhiteh4t
 |---> Community : https://twc1rcle.com/
[>] Version      : 1.1.7

[+] Target : http://web1337.inlanefreight.htb:52576

[+] IP Address : 94.237.56.175

[!] Headers :

Server : nginx/1.26.1
Date : Fri, 09 Jan 2026 14:39:11 GMT
Content-Type : text/html
Content-Length : 104
Last-Modified : Thu, 01 Aug 2024 09:35:23 GMT
Connection : keep-alive
ETag : "66ab56db-68"
Accept-Ranges : bytes

[!] Starting Crawler...

[+] Looking for robots.txt........[ Found ]
[+] Extracting robots Links.......[ 4 ]
[+] Looking for sitemap.xml.......[ Not Found ]                                                                  
[+] Extracting CSS Links..........[ 0 ]
[+] Extracting Javascript Links...[ 0 ]
[+] Extracting Internal Links.....[ 0 ]
[+] Extracting External Links.....[ 0 ]
[+] Extracting Images.............[ 0 ]
[+] Crawling Sitemaps.............[ 0 ]
[+] Crawling Javascripts..........[ 0 ]

[+] Total Unique Links Extracted : 4

[+] Completed in 0:00:01.273705

[+] Exported : /home/kali/.local/share/finalrecon/dumps/fr_web1337.inlanefreight.htb_09-01-2026_17:39:10
                                                     
```

```bash
$ cat /home/kali/.local/share/finalrecon/dumps/fr_web1337.inlanefreight.htb_09-01-2026_17:39:10/robots.txt 
http://web1337.inlanefreight.htb:52576/index.html
http://web1337.inlanefreight.htb:52576/index-3.html
http://web1337.inlanefreight.htb:52576/admin_h1dd3n
http://web1337.inlanefreight.htb:52576/index-2.html
```

```bash
$ curl http://web1337.inlanefreight.htb:52576/robots.txt
User-agent: *
Allow: /index.html
Allow: /index-2.html
Allow: /index-3.html
Disallow: /admin_h1dd3n

$ curl http://web1337.inlanefreight.htb:52576/admin_h1dd3n/  
<!DOCTYPE html><html><head><title>web1337 admin</title></head><body><h1>Welcome to web1337 admin site</h1><h2>The admin panel is currently under maintenance, but the API is still accessible with the key e963d863ee0e82ba7080fbf558ca0d3f</h2></body></html>
                                                    
```

```bash
 gobuster vhost -u http://web1337.inlanefreight.htb:52576 -w /usr/share/wordlists/dirb/common.txt --append-domain
 
 Found: dev.web1337.inlanefreight.htb:52576 Status: 200 [Size: 123]

```

```bash
$ python3 ReconSpider.py http://dev.web1337.inlanefreight.htb:52576/

$ cat results.json 
{
    "emails": [
        "1337testing@inlanefreight.htb"
    ],
    "links": [
        "http://dev.web1337.inlanefreight.htb:52576/index-385.html",
        "http://dev.web1337.inlanefreight.htb:52576/index-660.html",
        "http...
        
 ],
    "external_files": [],
    "js_files": [],
    "form_fields": [],
    "images": [],
    "videos": [],
    "audio": [],
    "comments": [
        "<!-- Remember to change the API key to ba988b835be4aa97d068941dc852ff33 -->"
    ]
}      
```