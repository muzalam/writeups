---
title: "IDOR Hunting: A Systematic Approach"
date: 2022-08-14T13:00:00-05:00
draft: false
tags: ["idor", "bug-bounty", "api-security", "methodology"]
difficulty: ""
---

IDOR (Insecure Direct Object Reference) is the most common vulnerability I find in bug bounty programs. The concept is simple: the application uses a user-controlled identifier to access resources without checking if the user is authorized to access that resource. The hard part isn't exploiting it. It's finding the right endpoints and parameters.

<!--more-->

## What Makes a Good IDOR Target

Not every parameter that contains an ID is vulnerable. The ones worth testing are parameters where:

- The ID references a resource that belongs to a specific user (orders, messages, documents, profile data)
- The endpoint performs a sensitive action (delete, modify, read private data)
- The application uses sequential or predictable identifiers

APIs are the best hunting ground. Modern SPAs make dozens of API calls, and developers tend to be less careful about authorization on API endpoints than on rendered pages.

## Step 1: Map the Application

Use the app as a normal user and capture everything in Burp. Create two accounts (Account A and Account B). Perform every action available: create resources, update settings, upload files, send messages, make purchases, use every feature.

In Burp's sitemap and HTTP history, you'll see every API endpoint the app uses. Look for patterns:

```
GET /api/v1/users/12345/profile
GET /api/v1/orders/67890
PUT /api/v1/documents/abcdef
DELETE /api/v1/messages/11111
GET /api/v1/invoices/2023-001
```

Every endpoint that contains an identifier is a candidate.

## Step 2: Identify the ID Format

Understanding the ID format tells you how to test it:

**Sequential integers** (1, 2, 3, ...): the easiest case. Just increment or decrement the number. If your order is 1050, try 1049 and 1051.

**UUIDs** (550e8400-e29b-41d4-a716-446655440000): these look random, but they're not always unguessable. UUIDv1 is time-based and includes the MAC address. You can predict them if you know roughly when the resource was created. UUIDv4 is random and effectively unguessable without leaking them somewhere.

**Encoded IDs**: base64-encoded integers are common. If the ID looks like `MTIzNDU=`, decode it. It's `12345`. Now you can enumerate.

**Hashed IDs**: MD5 or SHA1 of sequential integers. If you suspect this, hash a few integers and see if they match the ID format.

**Composite IDs**: `user_12345_order_67890`. Parse the structure. Which part can you change?

## Step 3: Test Horizontally

Horizontal IDOR: accessing another user's resources at the same privilege level.

Take a request from Account A that includes Account A's resource ID. Replace it with Account B's resource ID. If you get Account B's data, that's an IDOR.

```
# Account A's request
GET /api/v1/users/100/settings
Authorization: Bearer TOKEN_A

# Replace with Account B's ID
GET /api/v1/users/101/settings
Authorization: Bearer TOKEN_A
```

Do this systematically for every endpoint you found. Burp's Autorize extension automates this: it replays every request with a different session and flags cases where the response is the same (meaning authorization isn't checked).

## Step 4: Test Vertically

Vertical IDOR: accessing resources or performing actions that require higher privileges.

If you have a regular user account, try accessing admin endpoints:

```
GET /api/v1/admin/users
GET /api/v1/admin/settings
PUT /api/v1/users/100/role  {"role": "admin"}
```

Also test whether lower-privileged users can access resources they shouldn't within the same organization. In multi-tenant apps, try accessing resources from a different tenant entirely.

## Step 5: Test State-Changing Operations

Read-based IDORs are valid findings, but IDORs on write operations are higher severity. Test:

```
PUT /api/v1/users/101/email  {"email": "attacker@evil.com"}
DELETE /api/v1/users/101/account
POST /api/v1/users/101/password-reset
PUT /api/v1/orders/67890/status  {"status": "cancelled"}
```

Account deletion, email change, and password reset IDORs are almost always Critical severity.

## Where Developers Mess Up

**Authorization on GET but not PUT/DELETE**: the developer checks permissions on the read endpoint but forgets to check on the update or delete endpoint for the same resource.

**Authorization on the web route but not the API**: the web page checks permissions and only shows your data. But the underlying API endpoint that the page calls doesn't check. Hit the API directly.

**GraphQL**: GraphQL mutations and queries often take IDs as arguments, and the resolver might not check ownership:

```graphql
query {
  user(id: "101") {
    email
    phone
    ssn
  }
}

mutation {
  deleteDocument(id: "other-users-doc-id") {
    success
  }
}
```

**Batch/bulk endpoints**: the app checks authorization when you fetch one resource, but the batch endpoint that fetches multiple resources at once skips the check:

```
GET /api/v1/documents/123          # checks auth
GET /api/v1/documents?ids=123,456  # doesn't check auth on each ID
```

**Webhook and export features**: "Export my data" might take a user ID parameter. "Send webhook to..." might let you specify a different user's events.

**File access**: uploaded files stored with predictable names:

```
/uploads/user_100/profile.jpg
/uploads/user_101/profile.jpg   # just change the number
```

## Bypassing Protections

If the app seems to check authorization, try:

**Different HTTP methods**: `GET /api/users/101` is blocked but `POST /api/users/101` isn't.

**Parameter pollution**: `GET /api/users/100?id=101` where the route uses 100 for auth but the query parameter overrides the actual lookup.

**Wrapping the ID in an array**: some frameworks handle `{"user_id": 101}` differently from `{"user_id": [101]}`.

**Adding .json or changing Accept header**: `GET /api/users/101.json` might hit a different code path.

**Using old API versions**: `GET /api/v1/users/101` is protected, `GET /api/v0/users/101` isn't.

**Case sensitivity**: `/api/Users/101` vs `/api/users/101`.

## Reporting Tips

When you find an IDOR:

- Show the request from Account A accessing Account B's resource. Include both the request and response.
- Demonstrate with two accounts you control. Never access real user data.
- Emphasize the impact. "I can read any user's email and phone number" is more compelling than "IDOR on user endpoint."
- If it's a write IDOR, demonstrate by modifying your own Account B's data using Account A's session.
- Mention the scope. "This affects all X million users" if you can estimate it.