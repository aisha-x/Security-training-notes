# HTB: Web Pentest Module summary

Module Link: https://academy.hackthebox.com/app/module/35


## **cURL**

| **Command** | **Description** |
| --- | --- |
| `curl -h` | cURL help menu |
| `curl inlanefreight.com` | Basic GET request |
| `curl -s -O inlanefreight.com/index.html` | Download file |
| `curl -k https://inlanefreight.com` | Skip HTTPS (SSL) certificate validation |
| `curl inlanefreight.com -v` | Print full HTTP request/response details |
| `curl -I https://www.inlanefreight.com` | Send HEAD request (only prints response headers) |
| `curl -i https://www.inlanefreight.com` | Print response headers and response body |
| `curl https://www.inlanefreight.com -A 'Mozilla/5.0'` | Set User-Agent header |
| `curl -u admin:admin http://<SERVER_IP>:<PORT>/` | Set HTTP basic authorization credentials |
| `curl http://admin:admin@<SERVER_IP>:<PORT>/` | Pass HTTP basic authorization credentials in the URL |
| `curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://<SERVER_IP>:<PORT>/` | Set request header |
| `curl 'http://<SERVER_IP>:<PORT>/search.php?search=le'` | Pass GET parameters |
| `curl -X POST -d 'username=admin&password=admin' http://<SERVER_IP>:<PORT>/` | Send POST request with POST data |
| `curl -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/` | Set request cookies |
| `curl -X POST -d '{"search":"london"}' -H 'Content-Type: application/json' http://<SERVER_IP>:<PORT>/search.php` | Send POST request with JSON data |

## **APIs**

| **Command** | **Description** |
| --- | --- |
| `curl http://<SERVER_IP>:<PORT>/api.php/city/london` | Read entry |
| `curl -s http://<SERVER_IP>:<PORT>/api.php/city/ | jq` | Read all entries |
| `curl -X POST http://<SERVER_IP>:<PORT>/api.php/city/ -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'` | Create (add) entry |
| `curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'` | Update (modify) entry |
| `curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City` | Delete entry |

## **Browser DevTools**

| **Shortcut** | **Description** |
| --- | --- |
| [`CTRL+SHIFT+I`] or [`F12`] | Show devtools |
| [`CTRL+SHIFT+E`] | Show Network tab |
| [`CTRL+SHIFT+K`] | Show Console tab |

# HTTP Headers

## **. General Headers**

Used in both requests and responses. They describe the **message**, not the content.

- **Date:** Timestamp of when the message was generated.
- **Connection:** Controls whether the connection stays open (`keep-alive`) or closes (`close`).

---

## **2. Entity Headers**

Describe the **content (entity body)** being transferred. Seen in responses, POST, and PUT requests.

- **Content-Type:** Type of data (e.g., text/html, application/json).
- **Media-Type:** Similar to Content-Type; indicates the format of the data.
- **Boundary:** Separates sections in multipart forms.
- **Content-Length:** Size of the message body.
- **Content-Encoding:** How the content is transformed (e.g., gzip compression).

---

## **3. Request Headers**

Sent by the **client**. Describe the client, requested resource, or authentication.

- **Host:** Specifies the domain or IP being requested.
- **User-Agent:** Identifies the browser or client.
- **Referer:** Page where the request originated.
- **Accept:** What content types the client can handle.
- **Cookie:** Key-value data for session tracking.
- **Authorization:** Credentials/token for authentication.

---

## **4. Response Headers**

Sent by the **server**. Provide extra info about the server or how to interpret the response.

- **Server:** Web server name/version.
- **Set-Cookie:** Sends cookies to the client for future requests.
- **WWW-Authenticate:** Specifies authentication method required.

---

## **5. Security Headers**

Protect browsers and users from common attacks.

- **Content-Security-Policy (CSP):** Controls allowed script sources, helps prevent XSS.
- **Strict-Transport-Security (HSTS):** Forces HTTPS to prevent sniffing and downgrade attacks.
- **Referrer-Policy:** Controls how much referrer information is sent during navigation.

## Complete list

- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers
    
    

---

# **Request Methods and Codes**

## **Request Methods**

The following are some of the commonly used methods:

| **Method** | **Description** |
| --- | --- |
| `GET` | Requests a specific resource. Additional data can be passed to the server via query strings in the URL (e.g. `?param=value`). |
| `POST` | Sends data to the server. It can handle multiple types of input, such as text, PDFs, and other forms of binary data. This data is appended in the request body present after the headers. The POST method is commonly used when sending information (e.g. forms/logins) or uploading data to a website, such as images or documents. |
| `HEAD` | Requests the headers that would be returned if a GET request was made to the server. It doesn't return the request body and is usually made to check the response length before downloading resources. |
| `PUT` | Creates new resources on the server. Allowing this method without proper controls can lead to uploading malicious resources. |
| `DELETE` | Deletes an existing resource on the webserver. If not properly secured, can lead to Denial of Service (DoS) by deleting critical files on the web server. |
| `OPTIONS` | Returns information about the server, such as the methods accepted by it. |
| `PATCH` | Applies partial modifications to the resource at the specified location. |

The list only highlights a few of the most commonly used HTTP methods. The availability of a particular method depends on the server as well as the application configuration. For a full list of HTTP methods, you can visit this [link](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods).

**Note:** Most modern web applications mainly rely on the `GET` and `POST` methods. However, any web application that utilizes REST APIs also rely on `PUT` and `DELETE`, which are used to update and delete data on the API endpoint, respectively. Refer to the [Introduction to Web Applications](https://academy.hackthebox.com/module/details/75) module for more details.

---

## **Status Codes**

HTTP status codes are used to tell the client the status of their request. An HTTP server can return five classes of status codes:

| **Class** | **Description** |
| --- | --- |
| `1xx` | Provides information and does not affect the processing of the request. |
| `2xx` | Returned when a request succeeds. |
| `3xx` | Returned when the server redirects the client. |
| `4xx` | Signifies improper requests `from the client`. For example, requesting a resource that doesn't exist or requesting a bad format. |
| `5xx` | Returned when there is some problem `with the HTTP server` itself. |

The following are some of the commonly seen examples from each of the above HTTP status code classes:

| **Code** | **Description** |
| --- | --- |
| `200 OK` | Returned on a successful request, and the response body usually contains the requested resource. |
| `302 Found` | Redirects the client to another URL. For example, redirecting the user to their dashboard after a successful login. |
| `400 Bad Request` | Returned on encountering malformed requests such as requests with missing line terminators. |
| `403 Forbidden` | Signifies that the client doesn't have appropriate access to the resource. It can also be returned when the server detects malicious input from the user. |
| `404 Not Found` | Returned when the client requests a resource that doesn't exist on the server. |
| `500 Internal Server Error` | Returned when the server cannot process the request. |
- For a full list of standard HTTP status codes, you can visit this [link](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status). Apart from the standard HTTP codes, various servers and providers such as [Cloudflare](https://support.cloudflare.com/hc/en-us/articles/115003014432-HTTP-Status-Codes) or [AWS](https://docs.aws.amazon.com/AmazonSimpleDB/latest/DeveloperGuide/APIError.html) implement their own codes.

# GET

## **HTTP Basic Auth**

 ![ALT](/HTB/Web_Penetration_Tester/Web_Requests/Images/1.png)


View the response header with cURL

```bash
C:\Users\aisha>curl -i "http://94.237.49.209:58276/"
HTTP/1.1 401 Authorization Required
Date: Tue, 02 Dec 2025 15:07:36 GMT
Server: Apache/2.4.41 (Ubuntu)
Cache-Control: no-cache, must-revalidate, max-age=0
WWW-Authenticate: Basic realm="Access denied"
Content-Length: 13
Content-Type: text/html; charset=UTF-8

Access denied
```

To provide the credentials through cURL, we can use the `-u` flag, as follows:

```bash
C:\Users\aisha>curl -u admin:admin -i "http://94.237.49.209:58276/" -v
*   Trying 94.237.49.209:58276...
* Connected to 94.237.49.209 (94.237.49.209) port 58276
* using HTTP/1.x
* Server auth using Basic with user 'admin'
> GET / HTTP/1.1
> Host: 94.237.49.209:58276
> Authorization: Basic YWRtaW46YWRtaW4=
> User-Agent: curl/8.14.1
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 200 OK
HTTP/1.1 200 OK
< Date: Tue, 02 Dec 2025 15:13:01 GMT
Date: Tue, 02 Dec 2025 15:13:01 GMT
< Server: Apache/2.4.41 (Ubuntu)
Server: Apache/2.4.41 (Ubuntu)
< Cache-Control: no-cache, must-revalidate, max-age=0
Cache-Control: no-cache, must-revalidate, max-age=0
< Vary: Accept-Encoding
Vary: Accept-Encoding
< Content-Length: 1156
Content-Length: 1156
< Content-Type: text/html; charset=UTF-8
Content-Type: text/html; charset=UTF-8
<

```

Another method to perform basic HTTP auth credentials

```bash
C:\Users\aisha>curl http://admin:admin@94.237.49.209:58276/ -i
HTTP/1.1 200 OK
Date: Tue, 02 Dec 2025 15:24:56 GMT
Server: Apache/2.4.41 (Ubuntu)
Cache-Control: no-cache, must-revalidate, max-age=0
Vary: Accept-Encoding
Content-Length: 1156
Content-Type: text/html; charset=UTF-8
```

Login with the Authorization header 

```bash
C:\Users\aisha>curl -H "Authorization: Basic YWRtaW46YWRtaW4=" http://94.237.49.209:58276/  -i
HTTP/1.1 200 OK
Date: Tue, 02 Dec 2025 15:29:54 GMT
Server: Apache/2.4.41 (Ubuntu)
Cache-Control: no-cache, must-revalidate, max-age=0
Vary: Accept-Encoding
Content-Length: 1156
Content-Type: text/html; charset=UTF-8
```

### **GET Parameters**

Access to the search function view the DevTools, search for a city and observe the results in the network tab

 ![ALT](/HTB/Web_Penetration_Tester/Web_Requests/Images/2.png)

To send a GET request with cURL, we can use the exact same URL seen in the above screenshots since GET requests place their parameters in the URL. However, browser devtools provide a more convenient method of obtaining the cURL command. We can right-click on the request and select `Copy>Copy as cURL`. Then, we can paste the copied command in our terminal and execute it, and we should get the exact same response:

```bash
C:\Users\aisha>curl -H "Authorization: Basic YWRtaW46YWRtaW4=" http://94.237.49.209:58276/search.php?search=flag
flag: HTB{curl_g3773r}

```

We can also repeat the exact request right within the browser devtools, by selecting `Copy>Copy as Fetch`. This will copy the same HTTP request using the JavaScript Fetch library. Then, we can go to the JavaScript console tab by clicking [`CTRL+SHIFT+K`], paste our Fetch command and hit enter to send the request:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Requests/Images/3.png)

# post

## **Login Forms**

post request to <target> and pass the login credentials

 ![ALT](/HTB/Web_Penetration_Tester/Web_Requests/Images/4.png)

Copy the request as cURL (cmd)

```bash
curl ^"http://94.237.122.36:31608/^" ^
  -H ^"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7^" ^
  -H ^"Accept-Language: en,ar;q=0.9^" ^
  -H ^"Cache-Control: max-age=0^" ^
  -H ^"Connection: keep-alive^" ^
  -H ^"Content-Type: application/x-www-form-urlencoded^" ^
  -b ^"PHPSESSID=kdl1imudiuccoaj0pnk41os8ue^" ^
  -H ^"Origin: http://94.237.122.36:31608^" ^
  -H ^"Referer: http://94.237.122.36:31608/^" ^
  -H ^"Upgrade-Insecure-Requests: 1^" ^
  -H ^"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36^" ^
  --data-raw ^"username=admin^&password=admin^" ^
  --insecure
```

Copy as bash:

```bash
curl 'http://94.237.122.36:31608/' \
  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' \
  -H 'Accept-Language: en,ar;q=0.9' \
  -H 'Cache-Control: max-age=0' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -b 'PHPSESSID=kdl1imudiuccoaj0pnk41os8ue' \
  -H 'Origin: http://94.237.122.36:31608' \
  -H 'Referer: http://94.237.122.36:31608/' \
  -H 'Upgrade-Insecure-Requests: 1' \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36' \
  --data-raw 'username=admin&password=admin' \
  --insecure
```

Send POST request using cURL (cmd)

```bash
C:\Users\aisha>curl -X POST -d "username=admin&password=admin" "http://94.237.122.36:31608/"  -i
HTTP/1.1 200 OK
Date: Tue, 02 Dec 2025 15:49:28 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: PHPSESSID=7v740k02i2jr2c53po9alsnkff; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 1554
Content-Type: text/html; charset=UTF-8

```

using cookies to authenticate

```bash
curl -X POST -b "PHPSESSID=7v740k02i2jr2c53po9alsnkff" "http://94.237.122.36:31608/"  -i
```

Using Cookies header

```bash
curl -X POST -H "Cookie: PHPSESSID=7v740k02i2jr2c53po9alsnkff" "http://94.237.122.36:31608/"   -v
```

Using the storage DevTools and passing the cookie to login

 ![ALT](/HTB/Web_Penetration_Tester/Web_Requests/Images/5.png)

then refresh

 ![ALT](/HTB/Web_Penetration_Tester/Web_Requests/Images/6.png)

## **JSON Data**

In the search box, make any search query to see what requests get sent:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Requests/Images/7.png)

As we can see, the search form sends a POST request to `search.php`, with the following data:

```json
{"search":"london"}
```

The request header specifying the content-type to be JSON data

 ![ALT](/HTB/Web_Penetration_Tester/Web_Requests/Images/8.png)

Send the same request with cURL(CMD) to search for flag. We need to specify the content-type and the cookie

```json
C:\Users\aisha>curl -X POST -H "Content-Type: application/json" -H "Cookie: PHPSESSID=7v740k02i2jr2c53po9alsnkff" -d "{\"search\":\"flag\"}" "http://94.237.122.36:31608/search.php"
["flag: HTB{p0$t_r3p34t3r}"] 
```

Finally, let's try to repeat the same above request by using `Fetch`, as we did in the previous section. We can right-click on the request and select `Copy>Copy as Fetch`, and then go to the `Console`

tab and execute our code there:

 ![ALT](/HTB/Web_Penetration_Tester/Web_Requests/Images/9.jpeg)

# CURD API

## **CRUD API**

We saw examples of a `City Search` web application that uses PHP parameters to search for a city name in the previous sections. This section will look at how such a web application may utilize APIs to perform the same thing, and we will directly interact with the API endpoint.

---

## **APIs**

There are several types of APIs. Many APIs are used to interact with a database, such that we would be able to specify the requested table and the requested row within our API query, and then use an HTTP method to perform the operation needed. For example, for the `api.php` endpoint in our example, if we wanted to update the `city` table in the database, and the row we will be updating has a city name of `london`, then the URL would look something like this:

Code: bash

```bash
curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london ...SNIP...

```

## **CRUD**

As we can see, we can easily specify the table and the row we want to perform an operation on through such APIs. Then we may utilize different HTTP methods to perform different operations on that row. In general, APIs perform 4 main operations on the requested database entity:

| **Operation** | **HTTP Method** | **Description** |
| --- | --- | --- |
| `Create` | `POST` | Adds the specified data to the database table |
| `Read` | `GET` | Reads the specified entity from the database table |
| `Update` | `PUT` | Updates the data of the specified database table |
| `Delete` | `DELETE` | Removes the specified row from the database table |

These four operations are mainly linked to the commonly known CRUD APIs, but the same principle is also used in REST APIs and several other types of APIs. Of course, not all APIs work in the same way, and the user access control will limit what actions we can perform and what results we can see. The [Introduction to Web Applications](https://academy.hackthebox.com/module/details/75) module further explains these concepts, so you may refer to it for more details about APIs and their usage.

### **Read**

Specify the table name after the API (e.g. `/city`) and then specify our search term (e.g. `/london`), as follows:

```bash
C:\Users\aisha>curl http://94.237.55.124:37291/api.php/city/london -i
HTTP/1.1 200 OK
Date: Tue, 02 Dec 2025 16:29:45 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 46
Content-Type: text/html; charset=UTF-8

[{"city_name":"London","country_name":"(UK)"}]
C:\Users\aisha>
```

To print JSON in a pretty format, pipe it to jq. If you don't have jq, use as follows: 

```bash
C:\Users\aisha>curl http://94.237.55.124:37291/api.php/city/london -s | python -m json.tool
[
    {
        "city_name": "London",
        "country_name": "(UK)"
    }
]

```

Another example:

```bash
C:\Users\aisha>curl http://94.237.55.124:37291/api.php/city/le -s | python -m json.tool
[
    {
        "city_name": "Leeds",
        "country_name": "(UK)"
    },
    {
        "city_name": "Dudley",
        "country_name": "(UK)"
    },
    {
        "city_name": "Leicester",
        "country_name": "(UK)"
    },
    {
        "city_name": "Newcastle",
        "country_name": "(UK)"
    },
    {
        "city_name": "Los Angeles",
        "country_name": "(US)"
    },
    {
        "city_name": "Jacksonville",
        "country_name": "(US)"
    },
    {
        "city_name": "Seattle",
        "country_name": "(US)"
    },
    {
        "city_name": "Nashville-Davidson",
        "country_name": "(US)"
    }
]
```

To retrieve all the rows, pass an empty query after the database table name

```bash
C:\Users\aisha>curl http://94.237.55.124:37291/api.php/city/ -s | python -m json.tool

    {
        "city_name": "London",
        "country_name": "(UK)"
    },
    {
        "city_name": "Birmingham",
        "country_name": "(UK)"
    },
    {
        "city_name": "Leeds",
        "country_name": "(UK)"
    },
    {
        "city_name": "Glasgow",
        "country_name": "(UK)"
    },
    ..... 
```

 ![ALT](/HTB/Web_Penetration_Tester/Web_Requests/Images/10.jpeg)

### Create

Add a new row to the city table using the json format, then query for the new value

```bash
C:\Users\aisha>curl -X POST -d "{\"city_name\":\"Riyadh\",\"country_name\":\"Saudi Arabia\"}" http://94.237.55.124:37291/api.php/city/

C:\Users\aisha>curl http://94.237.55.124:37291/api.php/city/Riyadh -s | python -m json.tool
[
    {
        "city_name": "Riyadh",
        "country_name": "Saudi Arabia"
    }
]

```

### Update

- **Note:** The HTTP `PATCH` method may also be used to update API entries instead of `PUT`. To be precise, `PATCH` is used to partially update an entry (only modify some of its data "e.g. only city_name"), while `PUT` is used to update the entire entry. We may also use the HTTP `OPTIONS` method to see which of the two is accepted by the server, and then use the appropriate method accordingly. In this section, we will be focusing on the `PUT` method, though their usage is quite similar.

To update an entry we have to specify the name of the entity we want to edit in the URL `api.php/city/Riyadh` otherwise the API will not know which entity to edit.

```bash
C:\Users\aisha>curl -X PUT -d "{\"city_name\":\"Abha\",\"country_name\":\"Saudi Arabia\"}" http://94.237.55.124:37291/api.php/city/Riyadh

C:\Users\aisha>curl http://94.237.55.124:37291/api.php/city/Abha -s | python -m json.tool
[
    {
        "city_name": "Abha",
        "country_name": "Saudi Arabia"
    }
]

C:\Users\aisha>curl http://94.237.55.124:37291/api.php/city/Riyadh -s | python -m json.tool
[]

```

**Note:** In some APIs, the `Update` operation may be used to create new entries as well. Basically, we would send our data, and if it does not exist, it would create it. For example, in the above example, even if an entry with a `Riyadh` city did not exist, it would create a new entry with the details we passed. In our example, however, this is not the case. Try to update a non-existing city and see what you would get.

```bash
C:\Users\aisha>curl -X PUT -d "{\"city_name\":\"Jeddah\",\"country_name\":\"Saudi Arabia\"}" http://94.237.55.124:37291/api.php/city/Riyadh

C:\Users\aisha>curl http://94.237.55.124:37291/api.php/city/Riyadh -s | python -m json.tool
[]

C:\Users\aisha>curl http://94.237.55.124:37291/api.php/city/Jeddah -s | python -m json.tool
[]

```

Since we already updated Riyadh city with Abha, it no longer exists, so it didn't update a non-existing city with a new one. 

### DELETE

Specify the city name for the API and use the HTTP `DELETE` method, and it would delete the entry, as follows:

```bash
C:\Users\aisha>curl -X DELETE http://94.237.55.124:37291/api.php/city/Abha

C:\Users\aisha>curl http://94.237.55.124:37291/api.php/city/Abha -s | python -m json.tool
[]

C:\Users\aisha>
```

### **Conclusion**

With this, we are able to perform all 4 `CRUD` operations through cURL. In a real web application, such actions may not be allowed for all users, or it would be considered a vulnerability if anyone can modify or delete any entry. Each user would have certain privileges on what they can `read` or `write`, where `write` refers to adding, modifying, or deleting data. To authenticate our user to use the API, we would need to pass a cookie or an authorization header (e.g. JWT), as we did in an earlier section. Other than that, the operations are similar to what we practiced in this section.

### Question

Q1. First, try to update any city's name to be 'flag'. Then, delete any city. Once done, search for a city named 'flag' to get the flag.

```bash
C:\Users\aisha>curl -X PUT -d "{\"city_name\":\"flag\",\"country_name\":\"US\"}" http://94.237.55.124:37291/api.php/city/Seattle

C:\Users\aisha>curl -X DELETE http://94.237.55.124:37291/api.php/city/Newcastle

C:\Users\aisha>curl http://94.237.55.124:37291/api.php/city/flag -s | python -m json.tool
[
    {
        "city_name": "flag",
        "country_name": "HTB{crud_4p!_m4n!pul4t0r}"
    }
]
```