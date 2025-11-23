# LetsDefend: Detecting Insecure Deserialization Vulnerabilities Module Summary

**Table of Contents:**

- [Introduction to Insecure Deserialization](#introduction-to-insecure-deserialization)
- [What is Deserialization?](#what-is-deserialization)
- [How Insecure Deserialization Works?](#how-insecure-deserialization-works)
- [Understanding Common Insecure Deserialization Attacks](#understanding-common-insecure-deserialization-attacks)
- [Hands-on Lab](#hands-on-lab)


Optional: free lab training from THM → https://tryhackme.com/room/insecuredeserialisation

# **Introduction to Insecure Deserialization**

In today’s digital landscape, web applications power almost every aspect of online life — from shopping and social media to financial systems. With such widespread reliance, securing these applications is essential. One lesser-known yet serious vulnerability that threatens web applications is **insecure deserialization**.

Unlike well-known attacks like SQL injection or phishing, insecure deserialization operates quietly — often going unnoticed until it causes significant damage. This section introduces the concept, explains how serialization and deserialization work, and highlights why insecure deserialization deserves immediate attention. By understanding it, Security Operations Center (SOC) teams can better detect, prevent, and respond to such threats.

# **What is Deserialization?**

**Serialization** and **deserialization** are key processes for converting data structures or objects so they can be easily stored or transmitted.

### **Serialization**

Serialization transforms an object in memory into a format (often bytes, JSON, or XML) suitable for:

- **Data Persistence:** Saving an object’s state for later use.
- **Data Transmission:** Sending data between systems or over a network.
- **Cross-Language Communication:** Enabling interaction between applications written in different programming languages.

Example (Python):

```python
import json
data = {'name': 'John','age':30,'city':'New York'}
serilized_Data = json.dumps(data)
print('serilized data: ', serilized_Data)
```

Here, the dictionary is converted into a JSON string that can be stored or transmitted.

### **Deserialization**

Deserialization reverses the process — it reconstructs the original object from serialized data so it can be used again:

```python

deserilized = json.loads(serilized_Data)
print("deserilized data: ", deserilized)
```

Now, `deserialized_data` is a Python dictionary ready for programmatic use.

Deserialization is essential for **data retrieval**, **processing incoming data**, and **cross-system communication**.

Example of the output: 

```json
serilized data:  {"name": "John", "age": 30, "city": "New York"}
deserilized data:  {'name': 'John', 'age': 30, 'city': 'New York'}
```

- `json.dump`function: Serialize obj to JSON formatted string
- `json.loads` function: Deserialize s (a str, bytes or bytearray instance containing a JSON document) to a Python object.

---

### **Example: Serialization in a Python Web Application**

Below is a simplified example of a **Flask** web application managing user sessions with **pickle**, a Python serialization library:

```python
from flask import Flask, request, jsonify
import pickle

app = Flask(__name__)
user_sessions = {}

@app.route('/login', methods=['POST'])
def login():
    user_id = request.form.get('user_id')
    username = request.form.get('username')

    user_session = {'user_id': user_id, 'username': username}
    serialized_session = pickle.dumps(user_session)
    user_sessions[user_id] = serialized_session
    return jsonify({'message': 'Login successful'})

@app.route('/user_details/<user_id>', methods=['GET'])
def user_details(user_id):
    if user_id not in user_sessions:
        return jsonify({'error': 'Authentication failed'}), 401

    serialized_session = user_sessions[user_id]
    user_session = pickle.loads(serialized_session)
    return jsonify({'user_id': user_session['user_id'], 'username': user_session['username']})

if __name__ == '__main__':
    app.run(debug=True)
```

This example shows how serialization and deserialization work to manage user sessions. However, using **pickle** in production can be dangerous — if attackers control the serialized data, they can execute malicious code during deserialization, leading to **insecure deserialization vulnerabilities**.

Another simple example to show you how the output looks: 

```python
import pickle

# Example Python object
data = {"name": "Alice", "age": 30, "city": "New York"}

# Serialize the object to a byte string
pickled_data = pickle.dumps(data)
print("serilized data: ", pickled_data)

# Deserilize the byte string back to python objects
des = pickle.loads(pickled_data)
print("deserilized data:", des)
```

output:

```bash
serilized data:  b'\x80\x04\x95.\x00\x00\x00\x00\x00\x00\x00}\x94(\x8c\x04name\x94\x8c\x05Alice\x94\x8c\x03age\x94K\x1e\x8c\x04city\x94\x8c\x08New York\x94u.'
deserilized data: {'name': 'Alice', 'age': 30, 'city': 'New York'}
```

- `pickle.dump` converts a Python object hierarchy into a byte stream. This byte stream can then be stored in memory, transmitted over a network, or saved to a file
- `pickle.loads` The resulting byte string can later be "unpickled" back into its original Python object.

---

### **Key Takeaway**

Serialization and deserialization are powerful tools that enable efficient data exchange and storage across systems. However, if not implemented securely, they can become a serious attack vector. Understanding and addressing **insecure deserialization** is crucial for protecting modern web applications and maintaining the integrity of authentication, data processing, and communication systems.

# **How Insecure Deserialization Works?**

**Insecure deserialization** is a serious security vulnerability that occurs when an application **blindly trusts serialized data from untrusted sources** and processes it without proper validation or sanitization. This flaw can lead to **remote code execution (RCE)**, **data tampering**, **privilege escalation**, or **denial of service (DoS)** attacks.

To understand this vulnerability, let’s break down how insecure deserialization can be exploited.

---

### **Example 1: Malicious Deserialization in Python**

Consider a Python application that uses the `pickle` module for object serialization. The `pickle` library allows you to serialize Python objects into binary data and later deserialize them back into objects. However, if the serialized data comes from an untrusted source, attackers can exploit it.

```python
import pickle

class Malicious:

    def __reduce__(self):
        import os
        return (os.system, ("whoami", ))

Malicious_object = Malicious()

# serialize python object to binary data
serialize_data = pickle.dumps(Malicious_object)
print("Serialized data: ", serialize_data)

# deserialize binary data back to python object
deserialize_data = pickle.loads(serialize_data)
print("Deserialized data: ", deserialize_data)
```

Output:

```bash
$ python3 Serialization.py 
Serialized data:  b'\x80\x04\x95!\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x06whoami\x94\x85\x94R\x94.'
aisha
Deserialized data:  0
```

### **Explanation**

1. `__reduce__()` → defines **how to break down an object for pickling** (serialization) and **how to rebuild it** during unpickling (deserialization). It’s commonly used in:
    - Custom class serialization
    - Bypassing default pickling behavior
    - Security research (e.g., studying deserialization vulnerabilities)
2. Here, it’s weaponized to execute `os.system()` — effectively running arbitrary commands on the system.
3. When `pickle.loads()` deserializes the payload, it executes the malicious code automatically.

This demonstrates how insecure deserialization can lead directly to **arbitrary code execution**.

If `__reduce__()` method define **how to convert an object into a form that can be saved (serialized)** and later **reconstructed (deserialized)**. What about if it wasn't defined? 

**Ans:** `pickle` will try other built-in mechanisms to serialize the object. For most normal user-defined classes it will succeed by using a *default protocol* (recreate the object with the class and reconstruct its `__dict__`, or use `__getstate__/__setstate__` if defined). If none of those apply, pickling will fail for objects that are inherently non-picklable (e.g., open file handles, sockets, lambdas, many C extension objects).

Example-1: serialize a string

```python
import pickle

string = "Hello World"

serialize_data = pickle.dumps(string)
print("Serialized data: ", serialize_data)
deserialize_data = pickle.loads(serialize_data)
print("Deserialized data: ", deserialize_data)
```

result:

```bash
Serialized data:  b'\x80\x04\x95\x0f\x00\x00\x00\x00\x00\x00\x00\x8c\x0bHello World\x94.'
Deserialized data:  Hello World
```

Now, how about the objects that are inherently non-pickable? like the function `lambda` ?

```python
import pickle

test = lambda x: x+1

serialize_data = pickle.dumps(test)
print("Serialized data: ", serialize_data)

deserialize_data = pickle.loads(serialize_data)
print("Deserialized data: ", deserialize_data)
```

Result:

```bash
Traceback (most recent call last):
  File "Serialization.py", line 6, in <module>
    serialize_data = pickle.dumps(test)
                     ^^^^^^^^^^^^^^^^^^
_pickle.PicklingError: Can't pickle <function <lambda> at 0x7f9b3c4ac4a0>: attribute lookup <lambda> on __main__ failed
```

Explanation:

- `pickle` can’t find a global reference to the lambda.
- It doesn’t know how to recreate it when deserializing.
- So the serialization fails.

Example-2: with `__reduce__` method

```bash
import pickle

# Define a global function (importable and safe to reference)
def add_one(x):
    return x + 1

class Pickable:
    def __init__(self):
        self.func = add_one   # store the global function reference

    def __reduce__(self):
        # Tell pickle how to rebuild this object:
        #  - what callable to call (Pickable)
        #  - what arguments to give it (none here)
        # Then restore attributes manually.
        return (self.__class__, (), {'func': add_one})

# Create object and serialize it
obj = Pickable()
data = pickle.dumps(obj)
print("Serialized: ", data)

# Deserialize
restored = pickle.loads(data)
print("Deserialize:", restored.func(5))

```

result: 

```bash
Serialized:  b'\x80\x04\x955\x00\x00\x00\x00\x00\x00\x00\x8c\x08__main__\x94\x8c\x08Pickable\x94\x93\x94)R\x94}\x94\x8c\x04func\x94h\x00\x8c\x07add_one\x94\x93\x94sb.'
Deserialize: 6
```

Explanation:

- `__reduce__()` returns instructions:
    1. `(callable, args, state)`
    2. So `pickle` calls `Pickable()`
    3. Then restores its `func` attribute to `add_one`
- Because `add_one` is a *global function*, it can be referenced by name.

### **Example 2: Insecure Deserialization in a Flask Web Application**

Here’s a more realistic example using a Flask web app:

```python
from flask import Flask, request
import pickle

app = Flask(__name__)

class UserData:
    def __reduce__(self):
        import os
        return (os.system, ("echo Insecure Deserialization Exploited!",))

@app.route('/load_data', methods=['POST'])
def load_data():
    serialized_data = request.form['data']
    try:
        data = pickle.loads(serialized_data.encode('latin1'))
    except Exception as e:
        return f"Error: {str(e)}"
    return f"Deserialized data: {data}"

if __name__ == '__main__':
    app.run()
```

### **Attack Scenario**

An attacker can send a **malicious serialized payload** to the `/load_data` endpoint via a POST request. Upon deserialization, the application executes arbitrary system commands defined in the payload.

```bash
curl -X POST http://localhost:5000/load_data -d "data=<malicious_payload>"
```

---

## **How to Prevent Insecure Deserialization**

To protect your application, follow these **security best practices**:

### **1. Avoid Deserializing Untrusted Data**

Never deserialize data directly from untrusted sources such as user input or external APIs.

Instead, use safer formats like **JSON** or **XML** for data exchange.

### **2. Validate and Sanitize Inputs**

Thoroughly validate data before deserializing. Ensure it matches expected schemas and reject any malformed or unexpected input.

### **3. Use Safe Serialization Formats**

Prefer text-based, language-independent formats like **JSON**, **YAML (safe mode)**, or **XML** over binary serialization mechanisms such as `pickle` (Python) or `Serializable` (Java).

### **4. Implement Whitelisting**

Restrict deserialization to a predefined set of safe object types or classes.

### **5. Use Secure Libraries**

Adopt modern libraries that provide built-in security mechanisms against unsafe deserialization.

### **6. Enforce Access Controls**

Limit who or what can perform serialization and deserialization operations within your application.

### **7. Keep Dependencies Updated**

Regularly update serialization libraries and frameworks to patch known vulnerabilities.

### **8. Enable Logging and Monitoring**

Implement robust logging to monitor deserialization events. Look for unusual input patterns or unexpected deserialization failures.

### **9. Use Web Application Firewalls (WAFs)**

A properly configured WAF can detect and block suspicious serialized payloads before they reach your application.

---

## **Am I Vulnerable?**

Your application may be vulnerable if it **deserializes data received from untrusted or user-controllable sources.**

Two main attack categories include:

1. **Object and data structure manipulation:** Attackers modify objects to alter program logic or achieve RCE.
2. **Data tampering:** Attackers alter serialized data to bypass authentication or modify user privileges.

Example (PHP):

```php
# Regular User Cookie
a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}
# Modified Admin Cookie
a:4:{i:0;i:1;i:1;s:5:"Alice";i:2;s:5:"admin";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}
```

If the app deserializes this object, the attacker gains **admin privileges**, bypassing access controls.

---

## **Identifying Insecure Deserialization in Common Languages**

| Language | Risky Functions / Classes | Notes |
| --- | --- | --- |
| **PHP** | `unserialize()` | Inspect user-controlled input |
| **Python** | `pickle.load`, `pickle.loads`, `yaml.load` | Avoid unsafe loaders |
| **Java** | `ObjectInputStream.readObject`, `XMLDecoder`, `XStream.fromXML()` | Check versions ≤ 1.46 |
| **.NET** | `TypeNameHandling`, `JavaScriptTypeResolver` | Watch for user-defined types |

Indicators of serialized data include patterns like `rO0` (Base64 Java objects) or binary headers such as `AC ED 00 05`.

---

## **What Should a SOC Engineer Do?**

SOC teams play a critical role in **detecting and mitigating insecure deserialization** attacks.

### **1. Log Monitoring**

Monitor logs for exceptions or abnormal behavior during deserialization.

### **2. SIEM Integration**

Use **SIEM tools** (e.g., Splunk, QRadar, ELK) to detect patterns of suspicious serialized payloads or repeated deserialization errors.

### **3. Anomaly Detection**

Watch for anomalies like unusually large serialized objects or strange request patterns.

### **4. Custom SIEM Rules Example**

Scenario: Detect malicious Java serialized payloads.

- **Pattern:** Serialized objects containing `"evilData"` or unusually large payloads.
- **Rule Example:**
    - Trigger alert if request body includes `"evilData"`.
    - Alert if payload exceeds normal serialized object size threshold.

### **5. Exception Handling**

Use exception monitoring to detect possible attack attempts:

- **`ClassNotFoundException`**
- **`InvalidClassException`**
- **`ClassCastException`**
- **Custom `readObject()` exceptions**

Example (Java):

```java
try {
    ObjectInputStream in = new ObjectInputStream(inputStream);
    Object obj = in.readObject();
} catch (ClassNotFoundException | InvalidClassException | ClassCastException e) {
    logger.error("Potential Insecure Deserialization detected:", e);
}
```

### **6. Centralized Monitoring**

Forward logs to ELK or SIEM systems for real-time correlation and alerting.

### **7. Alert Thresholds**

Set thresholds to trigger alerts only after multiple suspicious events, minimizing false positives.

### **8. Correlate Events**

Correlate deserialization-related errors with abnormal HTTP requests or privilege escalation attempts.

---

## **Conclusion**

**Insecure deserialization** occurs when applications deserialize untrusted data without validation, allowing attackers to execute arbitrary code or manipulate system logic.

To mitigate this threat:

- Avoid unsafe deserialization.
- Validate inputs.
- Use safe serialization mechanisms.
- Monitor and log suspicious activity.

By combining **secure development**, **active SOC monitoring**, and **continuous security testing**, organizations can effectively protect against insecure deserialization attacks and maintain application integrity.

# **Understanding Common Insecure Deserialization Attacks**

Insecure deserialization attacks vary depending on the programming language and the serialization mechanisms used. While the underlying principle remains the same — **trusting unvalidated serialized data** — the exploitation methods differ.

This section explores **five common types** of insecure deserialization attacks, including detailed explanations, examples, and defense strategies for each.

---

## **1. PHP Object Injection**

**PHP Object Injection** is a form of insecure deserialization attack specific to PHP-based web applications. It occurs when an application unserializes user-supplied data without proper validation.

Attackers can inject **malicious PHP objects** that execute unintended behavior or arbitrary code during deserialization.

### **Example Scenario**

A vulnerable application unserializes user input directly:

```php
<?php
$user_data = $_POST['data'];
unserialize($user_data);
?>
```

- The `unserialize()` function returns the original PHP value (e.g., an array, object, string, integer, etc.) that was serialized.

An attacker submits a crafted serialized payload such as:

```php
O:4:"User":2:{s:8:"username";s:4:"evil";s:8:"isAdmin";b:1;}
```

When deserialized, this payload creates a `User` object with administrator privileges — allowing the attacker to bypass authentication and gain unauthorized access.

### **Recommendations for Securing PHP Applications**

- Validate and filter all user input before deserialization.
- Use a **whitelist approach** to limit which classes can be deserialized.
- Define custom deserialization logic using PHP’s `unserialize_callback_func`.
- Keep PHP and third-party libraries up to date to mitigate known vulnerabilities.
- Replace `unserialize()` with safer alternatives like **JSON decoding** for untrusted data.

---

## **2. Java Deserialization Attacks**

Java applications using native serialization are vulnerable when deserializing objects from untrusted sources.

An attacker can send a **crafted serialized Java object** that executes arbitrary code when deserialized by the server.

### **How Java Deserialization Attacks Work**

1. The attacker crafts a malicious serialized Java object.
2. The vulnerable application deserializes it using `ObjectInputStream.readObject()`.
3. The malicious object triggers code execution through its class methods.

### **Real-world Example**

The **Apache Struts2 vulnerability (CVE-2017-5638)** allowed attackers to execute remote commands through manipulated serialized data, resulting in full system compromise.

### **Example Payload**

```
rO0ABXNyACVqYXZhLnV0aWwuRGF0YUx1Y2Vub2dyYXBLAQATeXt4cHNyADZqYXZhLnV0aWwuSGFtc3Q7cHJpY2Vzc2Vzc2lvbi5iYXNlV2l0aE1lbnV9FhJqYXZhLmxhbmcuSW50ZWdlchLioKT3gAgYKwCAAB4cAAAAABdAAJmYWlsZWRMAAZpZGVudGlmaWVyAANvdXQABmFkbWluAANvcmcARWJzamM=
```

base64 decoding

```bash
¼Ý�sr�%java.util.DataLucenograpK�y{xpsr�6java.util.Hamst;pricessession.baseWithMenu}java.lang.IntegerÔáñ¸Ç+�Ç�����@�ÖÿZ[Y�ÜY[ØYÜY\Ç�█¦]�ÿYZ[Ç�█▄Ö└X£┌ÿ
```

### **Best Practices for Securing Java Applications**

- Avoid deserializing untrusted data.
- Replace Java’s native serialization with **JSON**, **XML**, or **Protocol Buffers**.
- Use a **serialization whitelist** to restrict allowed classes.
- Regularly update the JVM and libraries to fix deserialization flaws.
- Implement security frameworks like **Apache Commons-IO** or **Kryo** with safety checks.

---

## **3. Python Pickle Deserialization Attacks**

Python’s `pickle` module allows complex object serialization but is inherently insecure when handling untrusted data.

Attackers can embed malicious payloads inside pickled data, leading to **remote code execution (RCE)** when deserialized.

### **How Pickle Attacks Work**

1. A malicious payload defines a `__reduce__()` method to execute system commands.
2. When the application calls `pickle.loads()`, the embedded command executes automatically.

### **Example Payload**

```python
ccollections\nOrderedDict\n(p0\n((lp1\n(S'evil_key'\np2\nS'evil_value'\np3\ntp4\n(dp5\nS'__reduce__'\np6\n(cpickle\nload\n(S'cos\nsystem\np7\n(S'echo Malicious Code'\np8\ntp9\nRp10\n.'
```

When deserialized, this payload executes:

```bash
os.system("echo Malicious Code")
```

### **Strategies for Securing Python Applications**

- **Never use `pickle`** with untrusted input.
- Use safe serialization formats like **JSON** or **MessagePack**.
- Implement strict input validation before deserialization.
- Regularly update Python and libraries to mitigate vulnerabilities.
- Use sandboxing or isolated environments when untrusted data must be processed.

---

## **4. .NET BinaryFormatter Deserialization Attacks**

In .NET applications, the **BinaryFormatter** and similar serializers (`NetDataContractSerializer`, `LosFormatter`) can introduce deserialization vulnerabilities.

When an attacker sends a crafted binary object, it can result in **RCE** or **privilege escalation**.

### **Example Payload**

```
AQEAAAD/////AQAAAAAAAAAMAgAAAHN0YXJ0AQcAAAAVc2NoZW1lLkVSRgAAAAMCAAAABgMAAAAZAgAAAAMDAAD/////AAAAAAAAAAD/////AAAAAAAAAAMCAAAACQMAAAAmAwAAAAMIAAAAGAwAAAAsCAAAAEwMAAAAEAgAAAEYDAAAAHwMAAA==
```

This payload can trigger malicious execution when deserialized in an unprotected .NET environment.

### **Real-world Example**

The **MS15-004** vulnerability in Microsoft .NET Framework exploited insecure deserialization to allow remote code execution.

### **Guidance for Securing .NET Applications**

- Avoid `BinaryFormatter`, `LosFormatter`, and `ObjectStateFormatter`.
- Use safer serializers like **DataContractJsonSerializer** or **System.Text.Json**.
- Validate and sanitize all deserialized data.
- Apply regular updates and security patches.
- Consider using custom serialization mechanisms with strict input checks.

---

## **5. Ruby YAML Deserialization Attacks**

Ruby applications using **YAML (YAML Ain’t Markup Language)** for data storage or configuration can be vulnerable to insecure deserialization.

Attackers can insert malicious Ruby objects into YAML data, leading to **code execution** when parsed.

### **How Ruby YAML Attacks Work**

1. The attacker modifies a YAML file or payload to include malicious Ruby objects.
2. The application calls `YAML.load()` to deserialize the data.
3. The malicious object executes arbitrary Ruby code.

### **Example Payload**

```yaml
--- !ruby/object:OpenStruct
table:
  :instance_variable => !ruby/object:ERB {}
  :context => !ruby/object:OpenStruct
    :ivar: malicious_code_here
```

### **Example Scenario**

An attacker modifies a configuration YAML file to execute arbitrary code during deserialization, gaining unauthorized access or manipulating system behavior.

### **Strategies for Securing Ruby Applications**

1. **Input Validation:** Sanitize and validate all external YAML data.
2. **Safe Parsing:** Use `YAML.safe_load()` instead of `YAML.load()`.
3. **Alternative Formats:** Prefer JSON or other safe data formats for external input.
4. **Access Controls:** Limit permissions of processes handling deserialization.
5. **Dependency Hygiene:** Keep Ruby, gems, and YAML parsers updated.
6. **Use Security Gems:** Tools like `safe_yaml` add protective checks against unsafe YAML loading.

---

## **Conclusion**

Insecure deserialization is a **silent but severe** threat across programming languages. It can lead to **remote code execution, privilege escalation, and full system compromise** when left unmitigated.

Across all platforms — PHP, Java, Python, .NET, and Ruby — the key takeaway remains consistent:

> Never trust serialized data from untrusted sources.
> 

**Preventive actions include:**

- Using **safe serialization formats** (like JSON or XML).
- Applying **input validation and sanitization**.
- Restricting deserialization to **trusted, whitelisted classes**.
- Ensuring **timely updates** and **SOC monitoring** for unusual deserialization behavior.

By integrating these security measures and maintaining continuous vigilance, organizations can effectively protect their applications from one of the most deceptive and damaging classes of vulnerabilities.

# Hands-on Lab

## Quick rules-of-thumb to search for

- PHP serialization: `a:...:{`, `O:...:"Class":...{...}`, `s:...:"...";`
- Java serialized objects (base64): strings beginning with `rO0` or MIME `application/x-java-serialized-object`
- Java binary header: bytes `AC ED 00 05` (may appear as hex or base64)
- Python pickle: protocol header `\x80\x04` (can appear encoded), occurrences of `__reduce__`, `pickle.loads`, `cos\nsystem` payload fragments
- .NET BinaryFormatter: base64 prefixes like `AQEAAAD` or references to `BinaryFormatter`
- Ruby YAML: `!ruby/object`, `-- !ruby/object`
- XML Entity / XXE: `<!ENTITY %` inside posted XML
- Generic: `unserialize`, `deserialize`, `pickle`, `ObjectInputStream`, `evilData`, suspicious long POST bodies

## Specific `grep` commands (examples)

Run with `-n` to show line numbers, `-i` for case-insensitive, `-P` for PCRE (if available), and `--color=auto` to highlight.

### 1) PHP serialized payload (plain)

```bash
grep -Pni --color "a:\d+:\{" /var/log/nginx/access.log
```

### 2) PHP serialized payload (URL-encoded)

URL-encoded `a:` becomes `a%3A` — search for both:

```bash
grep -Pni --color "(a:\d+:\{)|(a%3A\d+%3A%7B)" /var/log/nginx/access.log
```

### 3) PHP `O:` object creation pattern (plain & urlencoded)

```bash
grep -Pni --color "O:\d+:\"[A-Za-z0-9_\\\\$]+\"" /var/log/nginx/access.log
grep -Pni --color "O%3A\d+%3A%22" /var/log/nginx/access.log
```

### 4) Java serialized objects (Base64 `rO0`)

```bash
grep -Pni --color "rO0AB" /var/log/nginx/access.log
# catch any 'rO0' base64 start
grep -Pni --color "rO0[A-Za-z0-9+/=]{10,}" /var/log/nginx/access.log
```

Also search for the MIME type:

```bash
grep -Pni --color "application/x-java-serialized-object" /var/log/nginx/access.log
```

### 5) Java binary header (hex / visible)

If your logs contain hex or dump:

```bash
grep -Pni --color "AC ED 00 05|ac ed 00 05" /var/log/nginx/access.log
```

### 6) Python `pickle` / `__reduce__` indicators

```bash
grep -Pni --color "__reduce__|pickle\.loads|pickle\.loads\(|c[pP]ickle" /var/log/nginx/access.log
# detect binary pickle protocol in base64-looking strings (gives many hits but useful)
grep -Pni --color "(gAS|gAN|gAX)[A-Za-z0-9+/=]{10,}" /var/log/nginx/access.log
```

### 7) Ruby YAML signs

```bash
grep -Pni --color "!ruby/object:|--- !ruby/object|!ruby/" /var/log/nginx/access.log
```

### 8) .NET BinaryFormatter base64 prefix

```bash
grep -Pni --color "AQEAAAD" /var/log/nginx/access.log
grep -Pni --color "BinaryFormatter|ObjectStateFormatter|LosFormatter" /var/log/nginx/access.log
```

### 9) XML entity / XXE detection

```bash
grep -Pni --color "<!ENTITY\s+%[^>]+>" /var/log/nginx/access.log
# or URL encoded
grep -Pni --color "%3C!ENTITY%20%25" /var/log/nginx/access.log
```

### 10) Generic suspicious deserialization keywords

```bash
grep -Pni --color "unserialize|deserialize|deserialize\(|unpickle|pickle\.loads|ObjectInputStream|ClassNotFoundException|InvalidClassException|ClassCastException|evilData|evil_payload" /var/log/nginx/access.log
```

---

## Combined single command (catch-all)

A combined PCRE that covers many of the above (can be noisy — tune to your environment):

```bash
grep -Pni --color "(a:\d+:\{)|(O:\d+:\"[A-Za-z0-9_\\\\$]+\")|(rO0AB)|(AQEAAAD)|(__reduce__|pickle\.loads|unserialize|deserialize|!ruby/object|<!ENTITY\s+%[^>]+>)" /var/log/nginx/access.log
```

---

## If request bodies are URL-encoded (POST bodies)

Often POST bodies are logged URL-encoded inside the request field. To extract and urldecode the request body for deeper inspection:

1. Extract request field (Apache combined format — adjust `awk` field index if different):

```bash
# print only the request (method/path/protocol) and the request body if logged; otherwise find POST lines and cut the query
awk -F\" '{print $2 " | " $6}' /var/log/apache2/access.log | grep POST
```

1. If the body is the 7th field or last quoted field, use `sed`/`awk` to extract then `python -c "import sys,urllib.parse;print(urllib.parse.unquote(sys.stdin.read()))"` to decode:

```bash
# example pipeline - adapt positions for your log format
awk -F\" '/POST/ {print $2 " " $6}' access.log | while IFS= read -r line; do echo "$line" | awk '{print $2}' | python3 -c "import sys,urllib.parse;print(urllib.parse.unquote(sys.stdin.read()))"; done
```

(adjust indexing—log formats differ widely)

---

## Reducing false positives

- Filter by **HTTP method POST** and content-type headers (`Content-Type: application/x-www-form-urlencoded`, `application/octet-stream`, `application/x-java-serialized-object`, `application/x-python-serialize`, `application/x-yaml`) if available in logs.
- Correlate matches with **requesting IP**, **user agent**, **time window**, and **unusual spike** in requests to specific endpoints.
- Use `head`/`tail` to view neighboring lines for context:

```bash
grep -n "rO0AB" access.log | cut -d: -f1 | xargs -I{} sed -n '{}-3,{}+3p' access.log
```

---

## Example workflow (investigation)

1. Run targeted greps above and capture hits to a file:

```bash
grep -Pni "rO0AB|a:\d+:\{|__reduce__|!ruby/object|<!ENTITY\s+%[^>]+>" access.log > /tmp/deser_hits.txt
```

1. Inspect top offending IPs:

```bash
awk '{print $1}' /tmp/deser_hits.txt | sort | uniq -c | sort -rn | head
```

1. Pull full requests for a suspicious IP and timeframe for manual review.

---

## Longer-term detection: SIEM/WAF rules

- Convert these `grep` patterns into **SIEM rules**, WAF signatures, or IDS signatures (Suricata/Snort).
- Add thresholds (e.g., alert when `a:\d+:\{` appears >3 times from an IP in 5 minutes) to reduce noise.
- Correlate matches with authentication failures, privilege escalations, or unusual server-side exceptions (`ClassNotFoundException`, `InvalidClassException`, pickle errors).

## Q&A

**Q1. What is the IP address of the attacker who attempted an insecure deserialization attack in the access.log entries?**

In Bash, the `!` character is used for **history expansion,** so you have to escape the `!` charachter with `\` 

```bash
root@ip-172-31-32-160:~/Desktop# grep -Pni --color "\!ruby/object:|--- \!ruby/object|\!ruby" access.log
4626:195.13.156.218 - - [18/Dec/2021:16:13:48  +0100] "GET /serialize?data=--- !ruby/object:OpenStruct\n\ttable:\n\t  :instance_variable => !ruby/object:ERB {}\n\t  :context => !ruby/object:OpenStruct\n\t    :ivar  => malicious_code_here\n" HTTP/1.1" 500 5432 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36"
```

The `data` parameter contains this YAML serialized object (when `\n` and `\t` are interpreted as newlines/tabs):

```yaml
--- !ruby/object:OpenStruct
	table:
	  :instance_variable => !ruby/object:ERB {}
	  :context => !ruby/object:OpenStruct
	    :ivar  => malicious_code_here
```

- `!ruby/object:OpenStruct` and `!ruby/object:ERB` are **Ruby YAML tags** that instruct the YAML loader to reconstruct Ruby objects (OpenStruct, ERB).
- `ERB` objects when instantiated and evaluated can execute Ruby code — attackers commonly use `!ruby/object:ERB` to get code execution during `YAML.load` if the application unsafely loads YAML (e.g., using `YAML.load` instead of `YAML.safe_load`).
- The presence of `malicious_code_here` indicates the payload was intended to supply code or malicious data to be executed when deserialized.

Other logs: 

<img width="1907" height="494" alt="image" src="https://github.com/user-attachments/assets/9edbcb72-1475-4240-a3e5-953663a46c4c" />

Log-1: 

```bash
GET /serialize?data=O:4:%22User%22:2:%7Bs:8:%22username%22%3Bs:4:%22evil%22%3Bs:8:%22isAdmin%22%3Bb:1%3B%7D HTTP/1.1"
```

URL decoding:

```bash
GET /serialize?data=O:4:"User":2:{s:8:"username";s:4:"evil";s:8:"isAdmin";b:1;} HTTP/1.1"
```

Log-2:

```bash
GET /serialize?data=aced0005737200186a6176612e7574696c2e486173685365740c70c9f3ecdd572b80200044c000161737400124c6a6176612f6c616e672f537472696e673b4c000b73656375726974794d616e6167657200115b4c6a6176612e6c616e672e537472696e673b5b000a656c656d656e74747970657374003f4c6a6176612e6c616e672e537472696e673b5b000a656c656d656e74747970657374003f4c6a6176612e6c616e672e537472696e673b5b000a656c656d656e74747970657374003f4c6a6176612e6c616e672e537472696e673b5b000a656c656d656e74747970657374003f4c6a6176612e6c616e672e537472696e673b5b000a656c656d656e74747970657374003f4c6a6176612e6c616e672e537472696e673b5b000a656c656d656e74747970657374003f00014c00087061796c6f616446726f6d74003f4000000000000101007870000000000a020000007872002c6a6176612e6c616e672e496e74656765723b787074000a636f6e6669672e63726f616b65642e6e616d696e672e496e74656765727820000000000000000c770800000000000078787878787870740003636b747400144c6a6176612f6c616e672f537472696e673b7878787878" HTTP/1.1" 500 5432
```

Hex decoding

```bash
ísrjava.util.HashSet ....
```

Log-3: 

```bash
GET /serialize?data=ccopy_reg\n_reconstructor\np0\n(cbuiltins\ngetattr\np1\n(cos\nsystem\np2\ntR\n(tV\nrmalicious_command_hereU\npp3\ntp4\nRp5\n." HTTP/1.1" 500 5432 "-" "Mozilla/5.0 (Windows NT
```

Log-4:

```bash
GET /serialize?data=AAEAAAD/////AQAAAAAAAAAEAQAAAIJTeXN0ZW0uRGVjb2RlAERlY29kZXIAAAABAwAAAENvbW1vbmx5IFBhZ2VDb3VudAIAAAADAgAAAENvbW1vbmx5IFBhZ2VDb3VudFVzZXIAAAADAgAAAENvbW1vbmx5IFBhZ2VDb3VudE51bWJlckNvbnRyb2wAAAAIY29tcGxleCBkZXNpZ25lclBvbGljeQAAAANHZW5lcmFsIENvbW1vbmx5IFN5c3RlbS5EYXRhA2RkYXRhA2JkYXRhA2NhcGFibGUABGJlYXV0eQAEZGVzYw5kZXBzYwRzdHJpbmcGBnRpbGVzdHJlYW0TJl5OYXNkQ2xhc3NBc3NlcnRpb25Gb3JtYXRMb2dzD15TZXR0aW5ncy5BdXRvbWF0aWMuQ29tcGxleE1ldGFEZWNvZGluZw== HTTP/1.1" 500 543
```

```bash
GET /serialize?data=--- !ruby/object:OpenStruct\n\ttable:\n\t  :instance_variable => !ruby/object:ERB {}\n\t  :context => !ruby/object:OpenStruct\n\t    :ivar  => malicious_code_here\n" HTT
```

Note that all these logs retuned an 500 server response which means  the payload reached the application layer (not immediately blocked by WAF) but raised an exception. 

*Ans: 195.13.156.218*

---

**Q2. In the access.log entries, what is the common HTTP response code associated with the insecure deserialization attacks?**

*Ans: 500*

---

**Q3. Which access.log entry contains a payload that attempts to execute a system command?**

- Format: 11/Aug/2022:13:22:15

looking back into the access.log we can note the “`cos\nsystem\np2`”(you can find it )

<img width="1877" height="83" alt="image" src="https://github.com/user-attachments/assets/1ac2bc6f-35c5-4a81-bd61-ab4f15109bbe" />

```python
os.system("malicious_command_here")
```

The payload is a **malicious Python pickle** that, when deserialized by `pickle.loads()` (or `pickle.load()`), will effectively **retrieve `os.system` and invoke it** with the argument `"malicious_command_here"`

*Ans: 18/Dec/2021:16:13:45*

---

Q4. Identify the access.log entry where the attacker used a Ruby object to attempt insecure deserialization. Provide the date and time of this entry

- Format: 11/Aug/2022:13:22:15

