---
title: "CDN Authorization Delegation: When Signed Cookies Grant More Than They Should"
date: 2026-04-20T10:00:00-05:00
draft: false
tags: ["auth-bypass", "access-control", "cloudfront", "cdn", "signed-cookies", "aws", "web-security"]
difficulty: ""
---

Modern web applications routinely delegate content authorization to a CDN. The application layer verifies the user's SSO session, checks their role against the requested resource, and on success issues a short-lived signed cookie or signed URL that the browser presents to the CDN for subsequent content requests. It's an efficient pattern. Once the delegation happens, the CDN serves content at the edge without any further round trip to the origin.

The problem is that the signed cookie or URL is an authorization artifact, and like any authorization artifact its *scope* has to match the decision that minted it. A lot of real-world implementations get this wrong. The authentication is correct, the authorization check is correct, the signature is valid, and the user ends up with access to resources they were never cleared to see.

This post covers the class of flaw, the specific shape it takes on AWS CloudFront, how to spot it during review, and how to fix it.

<!--more-->

## The Delegation Pattern

The canonical flow:

```
Browser (SSO session)
   │
   │  1. GET /resource/abc/video  (SSO cookie)
   ▼
App server
   │  2. Validates SSO session → user = alice
   │  3. Authorization check: can alice view resource/abc/video? → yes
   │  4. Issues a signed cookie/URL authorizing CDN access
   ▼
Set-Cookie: CloudFront-Signature=...; CloudFront-Policy=...; CloudFront-Key-Pair-Id=...
   │
   ▼
Browser
   │  5. GET https://cdn.example.com/resource/abc/video  (signed cookie)
   ▼
CloudFront
   │  6. Verifies signature valid and unexpired
   │  7. Serves from origin/cache
```

The idea is that once the app has verified Alice is allowed to see `resource/abc/video`, it hands her a token that lets her fetch that video directly from the CDN. The CDN doesn't need to re-run the authorization logic. It just needs to confirm the token is valid.

## The Scope Gap

Here's where the class of flaw lives.

The app server's authorization decision was specific: *Alice can see resource/abc/video*. The token the app hands to the browser is often less specific. Frequently, the signed cookie authorizes access to *the distribution*, not *the resource*. The signature covers `d123.cloudfront.net/*` with a 10-minute expiry, but doesn't bind to the particular video path Alice was cleared for.

The result: Alice holds a token that says "this browser can fetch *anything* from `d123.cloudfront.net` for the next 10 minutes." If she types a different URL into her address bar — `https://d123.cloudfront.net/resource/xyz/other-video` — the CDN verifies the signed cookie, and serves the content.

The authorization service did its job. The authentication was genuine. The signature is valid. The control that was supposed to enforce resource-level scope silently dropped scope at the delegation boundary.

## Why This Pattern Creeps In

Engineers write it this way because distribution-scoped cookies are the easy path in most CDN documentation, and because the authorization check that comes before minting the cookie *looks* like the enforcement point. The cookie is conceptualized as "Alice is allowed to watch videos from this service" rather than "Alice is allowed to watch this specific video." The rest of the system tests clean. The logs show successful SSO, successful authorization check, successful content delivery. Nothing raises a flag.

I have seen this pattern in multiple independent codebases. Any review of a service that uses CloudFront signed cookies or signed URLs should start with one question: *what specifically does the signed token authorize?*

## CloudFront Mechanics

On CloudFront specifically, signed cookies come in two flavors: **canned policy** and **custom policy**.

- **Canned policy** supports one URL at a time and binds the signature to that URL (with wildcard support for a path prefix). A canned-policy signed cookie for `https://d123.cloudfront.net/resource/abc/video/*` has a signature only valid for that path prefix.
- **Custom policy** supports multiple statements and richer conditions (IP restrictions, time ranges, multiple resources). Custom policies are more flexible, which means they're also where scope mistakes are easiest to introduce.

A concrete pair, both valid CloudFront cookies:

```json
// Canned policy, per-resource
{
  "Statement": [{
    "Resource": "https://d123.cloudfront.net/resource/abc/video/*",
    "Condition": {
      "DateLessThan": { "AWS:EpochTime": 1761336000 }
    }
  }]
}
```

```json
// Custom policy, distribution-wide
{
  "Statement": [{
    "Resource": "https://d123.cloudfront.net/*",
    "Condition": {
      "DateLessThan": { "AWS:EpochTime": 1761336000 }
    }
  }]
}
```

Both produce a signed cookie with matching signature. Both pass CloudFront verification. Only the first actually enforces per-resource scope.

## Finding the Bug

During a review of any service that uses a CDN for authenticated content, don't ask "is the authorization service verifying permissions?" That's almost always fine. Ask:

> *Does the signed cookie or signed URL encode the specific resource the user requested, or does it assert that this user, in general, has access to the distribution?*

To answer:

1. Grab a valid signed cookie from a real session (or a URL if you're using `CloudFront-Signed-URL`).
2. Decode the `CloudFront-Policy` value (URL-safe-base64 of JSON).
3. Look at the `Resource` field.
4. Does the resource pattern match the specific asset the user was authorized for, or does it use a wildcard broader than the authorization decision?

If the resource is `https://d123.cloudfront.net/*` (or any path prefix broader than the specific resource), you have the bug.

A quick decode:

```bash
echo "$COOKIE_POLICY" | tr '_-' '/+' | base64 -d | jq .
```

Then try to fetch a resource the user shouldn't have access to, using the same cookies:

```bash
curl -H "Cookie: CloudFront-Policy=...; CloudFront-Signature=...; CloudFront-Key-Pair-Id=..." \
     https://d123.cloudfront.net/resource/xyz/other-video
```

If CloudFront serves it, the scope gap is real.

## The Fix

Scope the signed token per resource. Whenever the app server authorizes a specific resource and needs to hand a CDN token to the browser:

1. Mint a canned-policy signed cookie (or signed URL) whose resource pattern matches the specific path the user was authorized for, not the distribution.
2. Keep expiry short. The token represents a specific authorization decision that should not be reusable indefinitely.
3. If you have to use a custom policy (for example, multiple resources per session), enumerate each authorized resource explicitly. Don't wildcard beyond what the authorization check confirmed.

On AWS, the canned-policy path:

```python
from botocore.signers import CloudFrontSigner
from datetime import datetime, timedelta

signer = CloudFrontSigner(key_id, rsa_signer)

# GOOD: bound to the specific resource
signed_url = signer.generate_presigned_url(
    f"https://d123.cloudfront.net/resource/{resource_id}/video.mp4",
    date_less_than=datetime.utcnow() + timedelta(minutes=10),
)

# BAD: bound to the distribution
signed_url = signer.generate_presigned_url(
    "https://d123.cloudfront.net/*",
    date_less_than=datetime.utcnow() + timedelta(minutes=10),
)
```

The delta in code is small. The delta in the security property is large.

## Related Patterns

The same class of flaw shows up in every CDN that supports signed cookie / URL authorization:

- **Akamai Edge Authorization**: token includes a list of ACLs. A missing or wildcarded `acl` field authorizes the entire hostname.
- **Fastly Signed URLs**: similar canned-vs-custom distinction. The signed URL can be bound to a path or to the service.
- **nginx signed URLs** via `secure_link`: the signature is over the URL and a secret, but the scope of what the signature binds is up to the developer.
- **Custom internal CDNs**: same pattern. Look for any auth flow where the application layer issues a token to a downstream service for content delivery.

## When Your Review Process Doesn't Catch It

This class of flaw isn't technically sophisticated. What makes it dangerous is that a conventional security review reliably catches the things it's trained to catch — missing authentication, missing authorization, unsigned content, expired keys — and this bug doesn't fail any of those checks. Every control is present. Every control is working. The flaw lives in what the successful authorization is actually a token for.

The specific question you have to ask is the one I opened with: *what specifically does the signed token authorize?* If you don't ask that, you don't find it.
