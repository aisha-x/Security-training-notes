# TryHackMe: HTTP Request Smuggling

Room URL: https://tryhackme.com/room/httprequestsmuggling

## Introduction

HTTP Request Smuggling is a vulnerability caused by inconsistencies in how different web infrastructure components (proxies, load balancers, servers) interpret HTTP request boundaries. It mainly occurs when **Content-Length** and **Transfer-Encoding** headers are parsed differently, allowing attackers to “smuggle” hidden requests. 

The attack relies on **keep-alive connections** and **HTTP pipelining**, which allow multiple requests over the same TCP connection. Incorrect handling of `\r\n` characters or automatic header modification (like tools changing Content-Length) can impact testing results.

Because smuggled requests can desync server pipelines, testing this vulnerability must be done carefully to avoid breaking websites.

### **Key Objectives**

- Understand HTTP Request Smuggling and its dangers.
- Identify and exploit it safely in controlled environments.
- Learn how to mitigate and prevent it.

### **Prerequisites**

- Basic knowledge of HTTP/1.1 headers.
- Familiarity with load balancers, proxies, and web servers.
- Ability to use proxy tools like Burp Suite.

### **Why It Matters**

- Smuggled requests can bypass security controls (like WAFs).
- Attackers can poison caches or cause data leakage.
- Desync attacks can break backend systems or lead to further exploitation.
- Because it’s subtle and complex, it often goes undetected.

## Components of Modern Web Applications

Modern web applications are built from multiple interconnected components rather than single monolithic systems.

### **Core Components**

- **Front-end server (Reverse Proxy/Load Balancer):** Receives client requests and forwards them to the appropriate backend server.
- **Back-end server:** Processes requests, handles business logic, and interacts with databases. Built using languages and frameworks like PHP, Python, JavaScript, Laravel, Django, or Node.js.
- **Databases:** Store and manage application data (e.g., MySQL, PostgreSQL, NoSQL systems).
- **APIs:** Enable communication between front-end, back-end, and third-party services.
- **Microservices:** Small, independent services that communicate over networks (HTTP/REST, gRPC), replacing traditional monolithic architectures in many modern systems.

### **Load Balancers & Reverse Proxies**

- **Load Balancers:** Distribute incoming traffic across multiple backend servers, ensuring availability, performance, and reliability. Examples: HAProxy, AWS ELB, F5 BIG-IP.
- **Reverse Proxies:** Sit in front of backend servers, forwarding requests, managing access, and optionally providing load balancing. Examples: NGINX, Apache mod_proxy, Varnish.

### **Caching Mechanisms**

Caching improves speed and reduces server load by reusing previously retrieved or computed data.

Types of caching:

- **Content Caching:** Store static assets (images, CSS, JS) for faster delivery.
- **Database Query Caching:** Cache results of frequent queries to reduce computation.
- **Full-page Caching:** Cache entire pages for high-performance delivery.
- **Edge Caching/CDNs:** Store content closer to users geographically to reduce latency.
- **API Caching:** Cache API responses to reduce backend processing for repeated requests.

Proper cache management is essential to avoid serving outdated or incorrect content.

## Behind the scenes

An HTTP request has **two main parts**:

1. **Headers** – metadata describing the request.
2. **Body** – the actual content being sent (often empty in GET requests, present in POST/PUT requests).

<img width="1222" height="370" alt="image" src="https://github.com/user-attachments/assets/785ba4a2-8739-4887-ae86-5caf217bf47c" />

### **Key Components of an HTTP Request**

### **1. Request Line**

Contains:

- **Method** (e.g., POST) – what action the server should perform.
- **Path** (e.g., /admin/login) – the requested resource.
- **HTTP Version** – specifies the protocol format (HTTP/1.1 vs. HTTP/2).

### **2. Request Headers**

Provide information such as:

- Content type
- Authentication details
- Encoding
- How the body should be interpreted

Think of headers like an envelope that describes the contents of a message.

### **3. Message Body**

Contains actual data:

- Form fields
- JSON
- Files
    
    Only used in certain request types (e.g., POST, PUT).
    

### **Content-Length Header**

Indicates the **exact size (in bytes)** of the message body.

Example: `Content-Length: 14` means the server expects 14 bytes of data.

The server uses this value to decide **where the request ends**.

### **Transfer-Encoding Header**

Defines how the body is delivered.

Most commonly: **chunked encoding**, where data is split into chunks, each labeled with its hexadecimal size.

Example chunked request:

```
b
q=smuggledData
0
```

- `b` = 11 bytes (hex to decimal)
- `0` ends the body

### **Why These Headers Matter**

Servers rely on **Content-Length** and **Transfer-Encoding** to parse requests.

If these headers contradict each other or are handled inconsistently:

- The front-end might believe the request ends at one point
- The back-end might think it continues further

This disagreement opens the door to **HTTP Request Smuggling**.

### **Origin of HTTP Request Smuggling**

This vulnerability happens due to **misaligned interpretations** of request boundaries across components:

- Some servers honor **Content-Length** first
- Others give priority to **Transfer-Encoding**
- When both headers are present, inconsistencies can occur

An attacker can exploit this by crafting a request that ends differently for the front-end vs. back-end server, allowing a hidden request to slip through — effectively “smuggling”

## **Request Smuggling Techniques**

HTTP request smuggling arises when front-end and back-end servers interpret request boundaries differently, especially when handling **Content-Length** (CL) and **Transfer-Encoding** (TE) headers. Attackers exploit these inconsistencies to sneak a hidden request to the back-end.

Below is a simplified summary of the three major techniques.

## **1. CL.TE (Content-Length → Transfer-Encoding)**

### **How It Happens**

- **Front-end** server uses **Content-Length** to determine where the request ends.
- **Back-end** server uses **Transfer-Encoding: chunked** instead.

### **Result**

The front-end thinks the request ends earlier based on Content-Length, while the back-end continues parsing based on chunked encoding—allowing a hidden request to slip through.

### **Key Idea**

Front-end stops early → Back-end reads more → smuggled request is executed.

## **2. TE.CL (Transfer-Encoding → Content-Length)**

### **How It Happens**

- **Front-end** server uses **Transfer-Encoding** (chunked).
- **Back-end** server uses **Content-Length** instead.

### **Result**

The front-end reads the request as chunked and consumes more data, while the back-end only reads the exact number of bytes specified in Content-Length, leaving the remaining bytes to be interpreted as a new, smuggled request.

### **Key Idea**

Front-end reads too much → Back-end reads too little → leftover data becomes a second request.

## **3. TE.TE (Transfer-Encoding → Transfer-Encoding mismatch)**

### **How It Happens**

Both servers use **Transfer-Encoding**, but they handle malformed or duplicated TE headers **differently**.

Example trick:

```
Transfer-Encoding: chunked
Transfer-Encoding: chunked1   (malformed)
```

### **Result**

- Front-end may ignore the malformed TE header and process normally.
- Back-end may interpret it differently (or fall back to Content-Length).
    
    This inconsistency lets the attacker force either a CL.TE or TE.CL scenario.
    

### **Key Idea**

Servers disagree on how to parse malformed TE headers → request gets desynced → smuggled request is processed.

## **Quick Comparison Table**

| Technique | Front-End Uses | Back-End Uses | Main Cause |
| --- | --- | --- | --- |
| **CL.TE** | Content-Length | Transfer-Encoding | FE stops early, BE continues |
| **TE.CL** | Transfer-Encoding | Content-Length | FE consumes more, BE reads less |
| **TE.TE** | Transfer-Encoding | Transfer-Encoding (but differently) | Malformed/duplicate TE header causes different interpretations |

### **In Simple Terms**

- **CL.TE** → *Front-end ends early, back-end continues → hidden request enters.*
- **TE.CL** → *Front-end absorbs more, back-end stops early → leftover becomes a new request.*
- **TE.TE** → *Both use TE, but interpret malformed TE differently → smuggled request appears.*

## Challenge

**CL.TE request smuggling** using a real vulnerable setup:

- **Front-end:** ATS (Apache Traffic Server)
- **Back-end:** Nginx
- **App:** PHP storing contact form submissions in `/submissions/`

The trick is to **smuggle a second, malicious request inside a normal user request** by abusing header interpretation differences.

- For demonstration, the submitted queries are saved to the `/submissions` directory.

### **Exploiting the Application**

Using Burp Suite Proxy, intercept a request sent to the website's index. Send the request to Intruder and copy-paste the below payload to the Payload positions box.

Payload

```bash
POST / HTTP/1.1
Host: httprequestsmuggling.thm
Content-Type: application/x-www-form-urlencoded
Content-Length: 160
Transfer-Encoding: chunked

0

POST /contact.php HTTP/1.1
Host: httprequestsmuggling.thm
Content-Type: application/x-www-form-urlencoded
Content-Length: 500

username=test&query=§
```

<img width="1582" height="803" alt="image" src="https://github.com/user-attachments/assets/bfc7c275-0c2b-4749-9430-9b0b667724c0" />

In CL.TE:

- **Front-end (ATS)** trusts **Content-Length**
- **Back-end (Nginx)** trusts **Transfer-Encoding: chunked**

This mismatch lets you hide a second request behind a fake first one.

So:

- The back-end believes the first request ends at `0`
- Everything after `0` is interpreted as a **new request**
- The attacker’s second request is injected (“smuggled”) into the pipeline

This causes the attacker’s request to be “stuck” in the shared connection, waiting to be delivered to the next victim’s back-end interaction.

Why the 1000 null payload? Because request smuggling is **timing-dependent** and **race-condition based**. So we need to keep inserting smuggled requests → at some point one of them is delivered right before a victim makes a legitimate request to `/contact.php`. 

Victim sends:

```
POST /contact.php
query=someFeedback&password=victimSecret
```

Because the attacker’s smuggled request runs *right before* it, the **victim’s request body gets appended** to the attacker’s `query=` parameter. **Why does it get appended?**

Because the desync causes the back-end to **merge**:

- your fake request body
- plus
- the victim’s request body

**into one combined request**, which PHP saves as a `.txt` file in `/submissions/`.

Start the attack and wait for a while, then check the submissions page 

<img width="1717" height="866" alt="image" src="https://github.com/user-attachments/assets/533f2f5f-8d7d-4274-b246-4d97d51562d5" />

If you checked the page before it captured the admin credentials, your request will also be captured. 

<img width="1018" height="259" alt="image" src="https://github.com/user-attachments/assets/11f5b6b4-93ab-43ae-96ac-34460482b480" />

And here is one of our smuggled requests being appended to a legmite user right before they send their request. 

<img width="1202" height="272" alt="image" src="https://github.com/user-attachments/assets/ff26e988-cdd5-4658-b162-6eaee87401a0" />

Use his credentials `C4Ny0UsMu66L3` to login to his account

<img width="1482" height="503" alt="image" src="https://github.com/user-attachments/assets/5cb4055b-a14a-476a-b05a-9f98be553d1c" />

## Reference

- [Detecting and Preventing HTTP Request Smuggling Attacks](https://onlinelibrary.wiley.com/doi/10.1155/2022/3121177#:~:text=2.2.%20HTTP%20Request%20Smuggling)
- HTTP Request Smuggling Lab Training → https://github.com/ZeddYu/HTTP-Smuggling-Lab
