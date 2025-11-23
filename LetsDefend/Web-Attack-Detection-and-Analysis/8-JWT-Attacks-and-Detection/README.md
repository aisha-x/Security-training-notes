# LetsDefend: JWT Attacks and Detection Module Summary
Table of Contents:

- [What is Authentication?](#what-is-authentication)
- [JSON Web Tokens](#json-web-tokens)
- [What is kid?](#what-is-kid)
- [Kid Injection](#kid-injection)
- [Kid SQL Injection](#kid-sql-injection)
- [Kid RCE & Kid Directory Traversal](#kid-rce--kid-directory-traversal)
- [SOC Member Approach](#soc-member-approach)


# What is Authentication?

**Authentication** is the process of verifying an entity’s identity (like a user or system) to ensure they are who they claim to be. It typically involves:

1. **Presentation:** The user provides credentials (e.g., password, biometric, certificate).
2. **Verification:** The system checks these credentials against stored records.
3. **Authorization (after authentication):** Access is granted based on verified identity.

Common methods include passwords, digital certificates, cryptographic keys, and multi-factor authentication (MFA). Authentication ensures data protection, accountability, compliance, and prevention of unauthorized access.

**Authorization** occurs **after authentication** and determines **what an authenticated user can do**—what resources or actions they’re allowed to access based on roles, permissions, or policies.

**Key Difference:**

- **Authentication** = Verifies *who* the user is.
- **Authorization** = Defines *what* the user can access or do.

Together, they form the foundation of secure access control in systems and networks.

# JSON Web Tokens

**Definition:**

JWT (JSON Web Token) is an open standard (RFC 7519) for securely transmitting information between parties as a compact, self-contained JSON object. It’s commonly used for **authentication** and **authorization** in web apps and APIs.

**Structure:**

A JWT has **three Base64URL-encoded parts**, separated by dots (`.`):

1. **Header** – Specifies the token type (JWT) and the signing algorithm (e.g., HS256, RSA).
2. **Payload** – Contains user data or *claims* (e.g., user ID, name, issued time).
3. **Signature** – Ensures the token’s integrity and authenticity, generated using the header, payload, and a secret key  ****(or public/private key pair) using the specified cryptographic algorithm from the header.

**Example format:**

`header.payload.signature`

**Advantages over Traditional Methods:**

- **Stateless & Scalable:** No need for server-side session storage.
- **Decentralized:** Easily shared across multiple services (ideal for microservices).
- **Cross-Platform:** Works with any language or platform using JSON and HTTP.
- **Reduced Database Lookups:** Token holds all necessary information.
- **Granular Authorization:** Supports custom claims for fine-grained access control.
- **Secure & Verifiable:** Tokens are digitally signed to prevent tampering.

**Use Cases:**

JWTs are widely used for **Single Sign-On (SSO)**, **API authentication**, and **session management**.

**Example:** 

```
**eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c**
```

**Header:** Base64URL encoded header: 

```
**eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9**
```

**Decoded header:**

```json
  {
     "alg": "HS256",
     "typ": "JWT"
  }                
```

The header contains information about the cryptographic algorithm used for the signature (in this case, HS256, which is HMAC-SHA256) and the type of the token (JWT).

**Payload:** Base64URL encoded payload:

```
**eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ**
```

 **Decoded payload:**

```json
  {
     "sub": "1234567890",
     "name": "John Doe",
     "iat": 1516239022
  }                   
```

The payload contains the claims or information associated with the token. In this example, the payload includes the subject (`sub`) representing the **user ID**, the **name of the user** (`name`), and the issued at **timestamp** (`iat`).

**Important Note:**

JWTs require careful handling—secure key management, token expiration, and revocation are essential to prevent misuse.

# What is Kid?

In **JSON Web Tokens (JWTs)**, the **`kid`** (Key ID) is an **optional header parameter** used to specify **which key** was used to **sign the token**. It helps the recipient identify and select the correct cryptographic key for **signature verification**, especially when multiple keys exist or when keys are rotated.

### **Purpose and Function:**

- The `kid` allows **dynamic key management**, enabling systems to **rotate or update keys** without interrupting authentication.
- When a JWT is received, the server reads the `kid` value and uses it to **look up the corresponding key** from a key store or database to **verify the token’s signature**.
- It ensures **integrity**, **authenticity**, and **scalability** in large systems with multiple signing keys.

### **Example – Header with `kid`:**

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "my_key_id"
}
```

Here, `"kid": "my_key_id"` indicates the specific key used to sign the JWT. The recipient uses this value to find the right verification key.

### **Example – Token with `kid` in Payload:**

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwia2lkIjoiMTIzNDU2Nzg5MCJ9.1LKTITDqS5FvdShvJzgOAWpH4b5R6wBqqhi_xE9zizg
```

**Decoded Payload:**

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "kid": "1234567890"
}
```

This example shows a `kid` field representing a unique identifier for the signing key.

### **Key Points:**

- The `kid` value can be a **unique ID**, a **thumbprint**, or another **identifier** tied to a key.
- It’s vital for **secure key selection and rotation**, ensuring smooth verification even as keys change.
- Misuse or poor validation of `kid` can lead to vulnerabilities like **JWT “Kid Injection”**, where attackers exploit the `kid` field to manipulate how keys are retrieved (e.g., through SQL injection).

In short, the `kid` parameter enhances JWT security and flexibility by allowing systems to manage and verify tokens using multiple cryptographic keys efficiently and safely.

# Kid Injection

**JWT KID Injection** (Key ID Injection) is a vulnerability that occurs when an attacker manipulates the **`kid`** (Key ID) field in a **JWT header** to trick the server into using an unintended or malicious key for signature verification. This can allow attackers to **bypass authentication**, **forge tokens**, or **gain unauthorized access**.

---

### **How It Works**

- In JWTs, the `kid` parameter indicates which key was used to sign the token.
- Some servers use the `kid` value to **look up the key** (e.g., in a database or file path) without proper validation.
- If the application **trusts user-supplied `kid` values**, attackers can inject malicious inputs—such as SQL commands or file paths—to manipulate how the key is retrieved.

**Example:**

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "' OR 1=1 --"
}
```

If this value is directly used in a SQL query or file lookup, it may result in **SQL injection** or **path traversal**, giving attackers control over key selection or access to sensitive data.

---

### **Common JWT Vulnerabilities**

1. **Insecure Key Management** – Exposed or poorly protected signing keys allow attackers to create forged tokens.
2. **Weak Signature Algorithms** – Using outdated or insecure algorithms (e.g., SHA-1) makes tokens easier to forge.
3. **KID SQL Injection** – Unsanitized `kid` input used in SQL queries can lead to unauthorized database access or data tampering.
4. **Path Traversal via KID** – If `kid` is used in file lookups without sanitization, attackers could access sensitive system files (e.g., `../../../etc/passwd`).

---

### **Impact**

- Forged JWTs allowing **unauthorized login** or **privilege escalation**.
- **Data breaches** through database or file system compromise.
- **Complete authentication bypass**, depending on the application’s trust in JWT validation.

---

### **Mitigation Measures**

- **Validate and sanitize** all JWT inputs, especially the `kid` field.
- **Avoid dynamic key lookups** using untrusted input; use predefined key mappings instead.
- **Implement strong key management** (rotate keys, store securely, never hard-code secrets).
- **Use strong cryptographic algorithms** and avoid weak or deprecated ones.
- **Keep JWT libraries updated** and rely on well-maintained, security-reviewed frameworks.
- **Conduct regular security testing** (code reviews, penetration tests) to detect and fix vulnerabilities early.

### Q&A

**Q1. What is the name of the security vulnerability that occurs when improper input validation and sanitization of the "kid" (key identifier) parameter in JSON Web Tokens (JWTs) leads to potential SQL injection attacks?**

Example payload:

```json
 {
  *"sub"*: "1234567890",
  *"name"*: "John Doe",
  *"kid"*: "' OR 1=1 --"
}
```

*Ans: kid SQL Injection*

---

**Q2. What is the name of the security vulnerability that occurs when inadequate validation of input parameters in JSON Web Tokens (JWTs) allows attackers to perform unauthorized file system traversal?**

Example payload:

```json
 {
  *"sub"*: "1234567890",
  *"name"*: "John Doe",
  *"filename"*: "../../../etc/passwd"
}
```

*Ans: path traversal*

**In summary:**

JWT KID Injection exploits weak handling of the `kid` parameter to manipulate key verification logic. Secure coding, strict input validation, and strong key management are essential to protect JWT-based authentication systems from such attacks.

# Kid SQL Injection

KID SQL Injection happens when an application uses the JWT header `kid` value directly in a database lookup (or other dynamic lookup) without proper validation or parameterization. An attacker injects SQL into `kid` so the database returns a key the attacker controls — enabling them to sign forged JWTs.

---

## Vulnerable flow (example)

Vulnerable query (constructed unsafely):

```
SELECT key FROM keys WHERE key='[kid]'
```

Attacker-controlled header:

```json
{ "alg":"HS256", "typ":"JWT", "kid":"ABC' UNION SELECT 'XYZ" }
```

Resulting query:

```
SELECT key FROM keys WHERE key='ABC' UNION SELECT 'XYZ'
```

If that succeeds, the DB returns `'XYZ'` as the key — the attacker can now sign tokens using `XYZ` and bypass verification.

---

## Why it’s dangerous

- Lets attacker **control which key** the server uses to verify/sign tokens.
- Enables **forged tokens, privilege escalation, impersonation**, or full auth bypass.
- Can combine with other injection payloads to reveal data or perform further DB compromise.

---

## Common causes

- Directly interpolating `kid` into SQL or file paths.
- No input validation/sanitization on JWT headers.
- Trusting client-supplied header values for key selection.
- Missing use of parameterized queries / prepared statements.

---

## Practical mitigations (actionable)

1. **Never use untrusted `kid` directly in SQL or file lookups.**
2. **Use parameterized queries / prepared statements** (bind variables) for DB access.
3. **Whitelist or canonical mapping:** map known `kid` values to keys server-side (e.g., dictionary or trusted keystore) instead of searching the DB with the raw `kid`.
4. **Validate `kid` format:** enforce strict length and character rules (e.g., alphanumerics, fixed length, regex). Reject unexpected characters like quotes or SQL keywords.
5. **Use least-privilege DB accounts** for key lookups to limit impact of injection.
6. **Store keys in a secure keystore or KMS**, not in files/DB rows reachable by arbitrary lookups. Prefer an indexed lookup by a validated identifier.
7. **Log and alert** on malformed or unexpected `kid` values and failed verification attempts.
8. **Rotate keys regularly** and implement token expiration and revocation strategies.
9. **Use vetted JWT libraries** for parsing/validation and keep them updated.
10. **Pen-test and code-review**: include tests for `kid` injection vectors.

---

## Quick safe pattern (pseudo)

Bad:

```sql
-- unsafe
query = "SELECT key FROM keys WHERE key='" + kid + "'"
```

Good:

```sql
-- safe (pseudocode)
query = "SELECT key FROM keys WHERE key = ?"
db.execute(query, [kid])
```

Better: avoid DB lookup using raw kid — instead use server-side mapping:

```python
key = key_map.get(kid)  # key_map is trusted, pre-loaded mapping
```

---

**Bottom line:** treat `kid` as untrusted user input. Validate, whitelist, or map it on the server side and always use parameterized DB access (or a secure keystore) to prevent attackers from manipulating key selection and forging JWTs.

# Kid RCE & Kid Directory Traversal

When an application uses the JWT header `kid` to locate a verification key (in a DB, filesystem, or by executing commands), an attacker who can control `kid` may escalate that into severe exploits: **Remote Code Execution (RCE)**, **Local File Inclusion / Directory Traversal (LFI)**, or **SQL injection** — all of which can allow forged tokens, privilege escalation, data theft, or full server compromise.

---

## Attack types & examples

### 1) **KID → Remote Code Execution (command injection)**

If `kid` is passed into a shell command or program call, an attacker can inject command syntax to run arbitrary commands.

Example header:

```json
{ "alg":"HS256", "typ":"JWT", "kid":"key1|/usr/bin/uname" }
```

If code does something like `exec("get-key " + kid)`, the attacker may run `/usr/bin/uname` or other commands with the app’s privileges — leading to RCE.

**Impact:** arbitrary command execution, token forging (if attacker controls the retrieved key), data exfiltration, pivoting.

---

### 2) **KID → Directory Traversal / LFI**

If `kid` is used to build a file path, attackers can traverse directories to pick files as keys (or read sensitive files).

Example header:

```json
{ "alg":"HS256", "typ":"JWT", "kid":"../../../../../../dev/null" }
```

If the server reads that path as the key, `/dev/null` yields an empty key (allowing attacker to sign tokens with an empty string). Or `../../etc/passwd` could let attackers read sensitive files and craft attacks.

**Impact:** signature bypass (using known/static files), disclosure of sensitive files (e.g., `/etc/passwd`), token forgery, further exploitation.

---

## Why this works (root causes)

- Treating `kid` as trusted user input.
- Direct interpolation of `kid` into SQL, shell commands, or filesystem paths.
- Using weak key lookup patterns (e.g., searching files by unvalidated `kid` string).
- Lack of whitelist/mapping for allowed key identifiers.
- Excessive privileges for components that retrieve keys.

---

## Practical mitigations (actionable & prioritized)

1. **Treat `kid` as untrusted input.** Never trust header values without validation.
2. **Use a server-side whitelist / canonical mapping.** Map accepted `kid` values to keys from a trusted store (in-memory map, KMS, or securely indexed DB).
    
    ```python
    # safe pattern (pseudocode)
    if kid in allowed_kids:
        key = key_map[kid]
    else:
        reject_token()
    ```
    
3. **Avoid dynamic shell/exec usage.** Never build shell commands with `kid`. If external utilities are needed, use safe APIs (no shell interpolation) and strong input validation.
4. **Sanitize & validate format.** Enforce strict regex, length, and charset for `kid` (e.g., `^[A-Za-z0-9_\-]{1,64}$`). Reject suspicious characters (quotes, `|`, `;`, `../`, null bytes).
5. **No direct filesystem lookups from raw `kid`.** If you must fetch from filesystem, use a validated mapping or resolve to a safe directory (use canonicalization and then check the resulting path remains inside an allowed directory).
6. **Use parameterized DB queries** for any DB-based key lookup to prevent SQLi.
    
    ```sql
    SELECT key FROM keys WHERE kid = ?  -- bind parameter
    ```
    
7. **Store keys in a secure keystore/KMS**, not as freely accessible files or rows that can be selected by arbitrary input. Use the KMS API to fetch by validated id.
8. **Least privilege & sandboxing.** Run key-retrieval code with minimal privileges; isolate processes that handle JWT parsing.
9. **Reject unknown/blank keys.** If lookup returns empty or unexpected key material, fail verification—don’t fall back to a default or empty key.
10. **Logging, alerts & rate limiting.** Log malformed `kid` values and alert on repeated suspicious attempts.
11. **Rotate keys & short token lifetimes.** Limit window of misuse and support revocation.
12. **Test/CI:** add unit/integration tests and fuzzing that include `kid` attack patterns (SQLi, path traversal, command injection).
13. **Use vetted JWT libraries** for parsing and signature checks; keep them updated.

---

**Bottom line:** `kid` is convenient for key selection but must be treated as untrusted input. The safest approach is: validate + whitelist or map `kid` → trusted key (from KMS), avoid executing or directly using `kid` in commands/paths/queries, and enforce least privilege. Doing so prevents RCE, LFI, SQLi, and token-forging attacks that stem from `kid` manipulation.

# **SOC Member Approach**

As a **Security Operations Center (SOC)** analyst, adopting a structured and intelligence-driven workflow is essential for identifying, responding to, and mitigating attacks that exploit the `kid` (Key ID) parameter in JSON Web Tokens (JWTs).

This approach ensures continuous visibility, effective detection, and swift containment of potential security incidents involving JWT manipulation.

## **1. Threat Intelligence Monitoring**

**Objective:** Stay ahead of emerging threats targeting JWTs and authentication systems.

- Continuously monitor **threat intelligence feeds**, **security advisories**, and **vendor bulletins** for new attack methods or exploits related to JWT handling and `kid` parameter abuse.
- Track **Indicators of Compromise (IOCs)** related to JWT injection, such as malicious payload structures, uncommon key identifiers, or specific attacker toolkits.
- Incorporate relevant findings into your detection rules and awareness campaigns within the SOC.

## **2. Log Monitoring and Analysis**

**Objective:** Identify early signs of JWT manipulation through systematic log review.

- Aggregate logs from **web servers, authentication services, API gateways, and application servers** handling JWTs.
- Analyze for anomalies such as:
    - Unusual or malformed JWT headers.
    - Unexpected `kid` values (e.g., containing SQL, command-line symbols, or directory traversal patterns like `../`).
    - Repeated login or token verification failures associated with suspicious tokens.
- Correlate JWT logs with other data sources (e.g., firewall, WAF, and system logs) to identify multi-step attacks.

## **3. Security Event Detection**

**Objective:** Automate detection of potential JWT `kid` injection attempts.

- Use a **SIEM (Security Information and Event Management)** or **log analytics platform** to build detection rules and alerts.
- Define **use cases** to flag:
    - JWTs containing characters like `'`, `|`, `;`, or `../` in the `kid` field.
    - Abnormal frequency of unique `kid` values per source IP.
    - Unrecognized or missing `kid` claims during token validation.
- Establish behavioral **baselines** for normal JWT operations to help detect deviations indicative of attack attempts.

---

## **4. Real-Time Monitoring**

**Objective:** Proactively detect and block malicious requests targeting JWT mechanisms.

- Deploy **Web Application Firewalls (WAFs)** or **Intrusion Detection/Prevention Systems (IDS/IPS)** capable of inspecting JWT traffic and detecting injection attempts.
- Integrate **behavioral analytics** to identify irregular token patterns or automated probing activity.
- Enable **real-time alerting** for anomalies tied to authentication requests, especially those including suspicious JWT header structures.

## **5. Incident Response and Mitigation**

**Objective:** Quickly contain, investigate, and resolve confirmed JWT `kid` injection incidents.

- Maintain a **documented Incident Response (IR) plan** for JWT-related attacks.
- Follow defined **escalation procedures**, specifying actions for SOC analysts, developers, and system administrators.
- Key response actions:
    - Isolate affected services or endpoints.
    - Revoke compromised JWT keys and regenerate secure ones.
    - Patch or harden code responsible for `kid` handling.
    - Block attacker IPs and domains associated with malicious activity.
- Communicate findings and coordinate with application and security teams for root cause remediation.

---

## **6. Post-Incident Analysis and Continuous Improvement**

**Objective:** Learn from incidents and strengthen defenses over time.

- Conduct a **root cause analysis (RCA)** to determine how the `kid` injection was exploited.
- Evaluate the **effectiveness of detection and response** measures taken.
- Update SIEM rules, IDS/WAF signatures, and detection logic based on new IOCs or observed attack behaviors.
- Document the incident and **share lessons learned** with the SOC team and relevant stakeholders.
- Continuously improve controls by applying patches, implementing stronger input validation, and refining authentication workflows.

## **7. Detection and Prevention Best Practices**

- **Validate the `kid` claim:**
    
    Compare against a **whitelist of trusted key identifiers**. Any token with an unrecognized or missing `kid` should be treated as suspicious and rejected.
    
- **Log and analyze JWT usage:**
    
    Track every token verification request, especially those with unusual or dynamic `kid` values. Correlate anomalies with IP addresses or user agents.
    
- **Rate limiting and throttling:**
    
    Apply **rate limits** to restrict the number of requests using different or invalid `kid` values within a set timeframe — mitigating brute-force or probing attacks.
    
- **IP-based restrictions:**
    
    Monitor requests by source IP. Repeated invalid or variant `kid` attempts from a single IP may indicate reconnaissance or exploitation efforts.
    
- **Continuous validation:**
    
    Integrate static code analysis, security testing, and fuzzing into the CI/CD pipeline to identify JWT-related vulnerabilities early in development.
    

---

## **Summary Table**

| **Phase** | **Goal** | **Example Actions** |
| --- | --- | --- |
| Threat Intel | Awareness | Track JWT vulnerabilities and IOCs |
| Log Monitoring | Visibility | Detect anomalies in JWT headers and `kid` fields |
| Event Detection | Automation | SIEM correlation rules and alerts |
| Real-Time Monitoring | Prevention | WAF/IDS inspection for malicious JWTs |
| Incident Response | Containment | Revoke keys, patch code, block IPs |
| Post-Incident | Improvement | RCA, detection tuning, lessons learned |

---

**Key Takeaway:**

As a SOC member, your goal is to **detect early**, **respond quickly**, and **continuously harden defenses**.

The `kid` parameter should always be treated as **untrusted input** — monitor its use rigorously, enforce validation, and coordinate with developers to prevent future JWT injection attacks.
