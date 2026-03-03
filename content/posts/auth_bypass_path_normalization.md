---
title: "Authentication Bypass Through Path Normalization"
date: 2024-08-15T10:00:00-05:00
draft: false
tags: ["auth-bypass", "path-traversal", "web-security", "nginx", "tomcat", "spring"]
difficulty: ""
---

One of the most underreported classes of authentication bypass comes from how different components in a web stack parse URL paths differently. A reverse proxy checks the path against its access control rules, decides it's fine, and forwards the request. The backend server normalizes the path differently, resolves it to a protected resource, and serves it. No credentials needed. Much of the foundational research here comes from Orange Tsai's "Breaking Parser Logic" presentation at Black Hat USA 2018, which blew this class of vulnerability wide open. This post covers every variant I know.

<!--more-->

## Why This Happens

Modern web applications almost never consist of a single server. The request passes through multiple layers: a CDN, a reverse proxy or load balancer (nginx, HAProxy, Apache, AWS ALB), maybe a WAF, then hits the backend (Tomcat, Express, Django, Spring Boot, IIS, etc.).

Each layer has its own URL parser. Each parser has its own opinion about what a URL means. The path `/admin/dashboard` is straightforward. But what about these?

```
/admin/dashboard
/Admin/Dashboard
/admin./dashboard
/admin;/dashboard
/admin%2fdashboard
/./admin/dashboard
//admin//dashboard
/admin/..;/admin/dashboard
/admin%00/dashboard
\admin\dashboard
```

Some of these resolve to `/admin/dashboard` on certain servers. Some don't. The vulnerability exists when the proxy and backend disagree. Orange Tsai coined the term "parser differential" for this exact concept, and it's a useful way to think about the entire class.

## Semicolon Path Parameters (Tomcat, Jetty)

This is the classic one, and it's the attack that put parser differentials on the map. The Servlet specification defines semicolons in URL paths as path parameter delimiters. Tomcat and Jetty follow the spec and strip everything between the semicolon and the next slash before resolving the path.

```
/admin;anything/dashboard  ->  Tomcat resolves to /admin/dashboard
/admin;foo=bar/dashboard   ->  Tomcat resolves to /admin/dashboard
/admin/..;/secret/page     ->  Tomcat resolves to /secret/page
```

Nginx does not understand path parameters. It sees `/admin;anything/dashboard` as a literal path. If nginx has a rule like:

```nginx
location /secret/ {
    deny all;
}
```

The request to `/secret;/../secret/page` doesn't match the `/secret/` location block because nginx sees the literal string `/secret;/../secret/page`. It forwards the request to Tomcat. Tomcat strips the path parameter, normalizes `/../`, and serves `/secret/page`.

Orange Tsai demonstrated this exact chain in his Black Hat talk, targeting real-world deployments where nginx sat in front of Tomcat. It was the centerpiece example of how two well-implemented parsers, each following their own spec, create a security gap when combined.

Testing payloads:

```
/admin/..;/target
/admin/..;anything/target
/;/admin/dashboard
/admin;/
/admin;param=value/dashboard
/..;/..;/admin/dashboard
```

The `..;/` trick is especially powerful. Nginx sees `..;` as a directory name (not a parent directory reference) because the semicolon breaks the `..` pattern. Tomcat strips the `;`, reconstructs `../`, and traverses up.

## Double URL Encoding

The proxy decodes the URL once for its routing rules. If the backend decodes it again, you can double-encode characters to sneak past the proxy.

```
/  = %2f  = %252f (double encoded)
.  = %2e  = %252e
```

Nginx rule:

```nginx
location /admin {
    auth_basic "Restricted";
    # ... auth config
}
```

Request:

```
GET /adm%69n/dashboard HTTP/1.1
```

Nginx sees `/adm%69n/dashboard`, doesn't decode `%69` to `i` before matching (depends on configuration), so it doesn't match the `/admin` location block. The backend receives the request, decodes `%69` to `i`, and serves `/admin/dashboard`.

Another variant with path traversal:

```
GET /public/%2e%2e/admin/dashboard HTTP/1.1
```

Nginx sees `/public/%2e%2e/admin/dashboard`. It doesn't decode `%2e%2e` to `..` for path matching purposes. The backend decodes it, resolves `../`, and serves `/admin/dashboard`.

Double encoding:

```
GET /public/%252e%252e/admin/dashboard HTTP/1.1
```

The proxy decodes once: `/public/%2e%2e/admin/dashboard`. Doesn't match the admin rule. Forwards it. The backend decodes again: `/public/../../admin/dashboard`. Normalizes to `/admin/dashboard`.

## Trailing Dot and Slash Variations

Some servers normalize trailing dots and extra slashes. Others don't.

```
/admin.     -> IIS might serve /admin
/admin/     -> might match differently than /admin
/admin//    -> some servers normalize to /admin/
```

IIS is particularly interesting with dots. A request to `/admin.anything` might resolve to `/admin` if there's no matching extension handler. This is because IIS file extension handling kicks in:

```
/admin.json     -> might serve /admin with JSON content type
/admin.html     -> might serve /admin with HTML content type
/admin.xxx      -> might serve /admin (unknown extension, falls through)
```

If the proxy only blocks exact `/admin`, then `/admin.` or `/admin.anything` bypasses it.

## Backslash vs Forward Slash

Windows-based backends (IIS) treat backslashes as path separators. Linux-based proxies don't.

```
GET /admin\..\secret\dashboard HTTP/1.1
```

Nginx sees this as a single path component (backslashes aren't special in URL paths on Linux). IIS interprets the backslash as a separator and resolves the path traversal.

Even on Linux, some application frameworks normalize backslashes. Spring Boot, for example:

```
GET /admin\dashboard HTTP/1.1
```

Spring's path matching might normalize this to `/admin/dashboard` depending on the configuration.

## Case Sensitivity Mismatches

Nginx location matching is case-sensitive by default. Many backends are not.

```nginx
location /admin {
    deny all;
}
```

```
GET /Admin/dashboard HTTP/1.1
GET /ADMIN/dashboard HTTP/1.1
GET /aDmIn/dashboard HTTP/1.1
```

None of these match the nginx location block. If the backend is case-insensitive (IIS always is, some application routers are), it serves the admin page.

For regex-based location blocks in nginx:

```nginx
location ~* /admin {   # ~* = case-insensitive regex
    deny all;
}
```

This catches case variations. But if the admin used `~` (case-sensitive regex) instead of `~*`, the bypass works.

## Spring Security Specifics

Spring Security has had a rough history with path normalization. Multiple CVEs over the years trace back to the same fundamental issue: the security filter and the dispatcher servlet resolve paths differently.

**Trailing slash**:

Spring Security might protect `/admin` but not `/admin/`. Or vice versa. This depends on the version and configuration:

```java
http.authorizeRequests()
    .antMatchers("/admin").authenticated()
```

A request to `/admin/` might not match this rule in older Spring versions, bypassing auth entirely.

**Encoded slashes**:

Spring Security's default configuration rejects requests with encoded slashes (`%2f`). But if you configure `allowUrlEncodedSlash` or use certain embedded servers, the behavior changes:

```
GET /api/public/..%2fadmin/dashboard HTTP/1.1
```

If encoded slashes are allowed, this might normalize to `/api/admin/dashboard` after the security filter has already approved `/api/public/..%2fadmin/dashboard`.

**UseSuffixPatternMatch**:

Older Spring MVC configurations with suffix pattern matching enabled treat `/admin.anything` the same as `/admin`:

```
GET /admin.json HTTP/1.1
GET /admin.html HTTP/1.1
GET /admin.css HTTP/1.1
```

All of these might hit the admin controller. If the security rule only protects `/admin`, the suffixed versions bypass it. Spring disabled this by default starting in Spring 5.3, but plenty of older applications still have it on.

**Path traversal in static resources (CVE-2024-38819)**:

This one dropped in late 2024. Spring's handling of static resource requests didn't properly neutralize path traversal sequences in certain configurations. A request with crafted `..` sequences could escape the static resource directory and hit protected endpoints. This was part of a series of related CVEs (CVE-2024-38816 and CVE-2024-38820 landed around the same time) that all dealt with path traversal in Spring's resource handling. If you're testing a Spring app, check which version it's running. Anything before the patches for these CVEs is worth testing.

**Spring4Shell (CVE-2022-22965)**:

While Spring4Shell was primarily a class manipulation RCE, the initial exploit chain relied on path handling quirks to reach the vulnerable ClassLoader property. The exploit used nested property access through Spring's parameter binding, but the path through which the request reached the vulnerable code was part of the puzzle.

## Nginx Configuration Pitfalls

The Detectify research team has published extensively on nginx misconfigurations that lead to path normalization issues. A couple of the most common:

**Missing trailing slash in proxy_pass**:

```nginx
# VULNERABLE
location /app {
    proxy_pass http://backend;
}

# An attacker requests: /app/../admin
# Nginx normalizes to /admin and forwards to backend
# But the location only matched because of /app prefix
```

vs

```nginx
# Different behavior
location /app/ {
    proxy_pass http://backend/;
}
```

The interaction between the location directive and the proxy_pass URI determines how the path is rewritten before forwarding. Getting this wrong leads to path traversal to unintended backend routes. Detectify's "Common Nginx Misconfigurations" blog series covers this in detail and is worth reading if you test applications behind nginx.

**merge_slashes**:

By default nginx has `merge_slashes on`, which collapses `//` to `/`. If you turn this off for some reason, or if the proxy in front of nginx doesn't merge slashes:

```
GET //admin/dashboard HTTP/1.1
```

Nginx location blocks matching `/admin` don't match `//admin`. But the backend might normalize the double slash and serve the admin page.

## Unicode and Overlong UTF-8

Old but still relevant in some environments. Overlong UTF-8 encodings represent a character using more bytes than necessary:

```
/ = 0x2F
/ = 0xC0 0xAF (overlong 2-byte encoding)
/ = 0xE0 0x80 0xAF (overlong 3-byte encoding)
```

The proxy might not decode overlong UTF-8, so it doesn't see a slash. The backend decodes it and processes the path traversal. The original IIS Unicode vulnerability from 2000 (CVE-2000-0884) was exactly this issue, and it was one of the first major path normalization bugs to get widespread attention. Modern variants still pop up. Some applications use C-based libraries for path handling that don't properly reject overlong encodings.

Other Unicode characters that normalize to ASCII equivalents:

```
%EF%BC%8F -> ／ (fullwidth solidus, sometimes normalized to /)
%E2%81%84 -> ⁄ (fraction slash, sometimes normalized to /)
```

## Null Byte Injection

Mostly historical, but some parsers still handle null bytes poorly:

```
GET /admin%00.jpg HTTP/1.1
```

The proxy sees a request for a .jpg file (maybe it only protects non-static paths). The backend truncates at the null byte and serves `/admin`.

PHP before 5.3.4 was famously vulnerable to this in file operations due to the underlying C string handling. Some modern applications running on older runtimes or using C-based libraries for path handling might still be affected.

## Testing Methodology

When you encounter an application behind a reverse proxy with path-based access control:

**Step 1**: identify the stack. What's the proxy? What's the backend? Response headers, error pages, and default behaviors reveal this. Knowing the stack tells you which normalization tricks to try. A Tomcat backend means semicolons are worth testing. IIS means backslashes and case sensitivity. Spring means suffix patterns and encoded slashes.

**Step 2**: find a protected path. Try accessing `/admin`, `/internal`, `/api/admin`, or whatever returns a 401/403.

**Step 3**: systematically try normalization bypasses:

```
# Semicolon (Tomcat/Jetty)
/admin;/
/admin/..;/admin/
/;param/admin/

# Encoding
/adm%69n/
/%61dmin/
/admin%2f
/admin%2Fdashboard

# Double encoding
/%2561dmin/
/admin%252f

# Case
/Admin/
/ADMIN/
/aDmIn/

# Slashes
//admin/
/admin//
\/admin\/

# Dots
/admin.
/admin.json
/admin..
/./admin/
/public/../admin/

# Null
/admin%00
/admin%00.jpg

# Combined
/public/..;/admin/
/PUBLIC/../admin/
//admin;/..;/admin/
```

**Step 4**: for each bypass that returns a different status code or response, investigate further. A change from 403 to 200 or 302 is a strong signal.

**Step 5**: automate the boring parts. Use Burp Intruder with a payload list of all these variants. Or use a tool like [403bypasser](https://github.com/iamj0ker/bypass-403) which tries many of these automatically.

## Further Reading

Orange Tsai continues to publish on parser differentials. His follow-up work after the original Black Hat talk has covered new variants in Apache, Envoy, and cloud-native proxies. If you're serious about this class of vulnerability, his blog (blog.orange.tw) and conference talks are the primary source.

The Spring Security advisory page is worth bookmarking if you test Java applications. They publish detailed descriptions of each CVE including which versions are affected and what the fix was, which helps you understand what to test when you identify the Spring version.

Detectify Labs has a series specifically on nginx misconfigurations that goes deeper than what I've covered here, including off-by-slash bugs and alias traversal.