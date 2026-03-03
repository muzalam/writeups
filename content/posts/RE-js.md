---
title: "Reverse Engineering JavaScript for Bug Bounty"
date: 2023-01-08T10:00:00-05:00
draft: false
tags: ["javascript", "recon", "bug-bounty", "source-review"]
difficulty: ""
---

One of the best things you can do as a bug bounty hunter is read the target's JavaScript. Not skim it. Actually read it. JS bundles contain API endpoints, hidden parameters, authentication logic, internal service names, debug flags, and sometimes hardcoded secrets. This is how I approach it.

<!--more-->

## Why JavaScript

When a developer builds a modern web app, the frontend is essentially a compiled version of their source code. Webpack, Vite, and other bundlers concatenate and minify everything, but the logic is still there. The variable names might be mangled, but the strings (API URLs, parameter names, error messages) are not.

Every API endpoint the frontend calls is in the JavaScript. Every parameter it sends. Every conditional check it makes. Every feature flag it reads. This is a map of the backend's attack surface, written by the developers and handed to you in the browser.

## Step 1: Collecting JS Files

Pull all JavaScript files from the target:

```bash
# Using gau (getallurls) and grep
gau example.com | grep -E '\.js$' | sort -u > js_urls.txt

# Using waybackurls for historical JS files
waybackurls example.com | grep -E '\.js(\?|$)' | sort -u >> js_urls.txt

# From the live site
hakrawler -url https://example.com -js | sort -u >> js_urls.txt

# Download them all
while read url; do
    filename=$(echo "$url" | md5sum | cut -d' ' -f1).js
    curl -s "$url" -o "js_files/$filename"
done < js_urls.txt
```

Also check the page source for inline scripts and dynamically loaded chunks. Webpack chunk names often follow a pattern like `main.abc123.js`, `vendor.def456.js`, and numbered chunks like `0.js`, `1.js`, etc.

Look at `<script>` tags and search for chunk loading patterns:

```javascript
// Webpack chunk loading - search for this pattern
__webpack_require__.e(/* import() */ 42).then(...)
```

This tells you chunk 42 exists. Fetch it: `https://example.com/static/js/42.abc123.chunk.js`

## Step 2: Beautifying

Minified JavaScript is unreadable. Use a beautifier:

```bash
# js-beautify CLI
pip install jsbeautifier
js-beautify -f minified.js -o beautified.js

# Or use Prettier
npx prettier --write minified.js

# In browser: DevTools > Sources > {} (pretty print button)
```

For webpack bundles, you can use [webpackfinder](https://github.com/nicholasgcoles/webpackfinder) or manually extract modules. Source maps (`.js.map` files) are the jackpot. If they exist, they contain the original unminified, unmangled source code:

```bash
# Check for source maps
curl -s https://example.com/static/js/main.abc123.js | tail -1
# Look for: //# sourceMappingURL=main.abc123.js.map

# Download and extract
curl -s https://example.com/static/js/main.abc123.js.map -o main.js.map

# Extract original source
npm install -g source-map-explorer
# Or use https://nicholasgcoles.github.io/webpack-sourcemap-unpack/
```

Source maps being publicly accessible is itself a vulnerability worth reporting. But more importantly, they give you the original code to read.

## Step 3: Finding API Endpoints

This is the most immediately useful thing. Search for URL patterns:

```bash
# Grep for API paths
grep -rhoP '["'"'"'`]/api/[^"'"'"'`\s]+' js_files/ | sort -u
grep -rhoP '["'"'"'`]https?://[^"'"'"'`\s]+' js_files/ | sort -u

# Common patterns
grep -rn 'fetch(' js_files/
grep -rn 'axios\.' js_files/
grep -rn '\.get(' js_files/
grep -rn '\.post(' js_files/
grep -rn '\.put(' js_files/
grep -rn '\.delete(' js_files/
grep -rn 'XMLHttpRequest' js_files/
grep -rn 'baseURL' js_files/
grep -rn 'endpoint' js_files/
```

You'll find endpoints the UI doesn't expose. Internal admin APIs, debug endpoints, deprecated routes that still work, and API versions you didn't know about. These are your best targets because they're less tested and often have weaker authorization.

Also look for:

```bash
# GraphQL endpoints and queries
grep -rn 'graphql\|mutation\|query {' js_files/

# WebSocket endpoints
grep -rn 'wss://\|ws://' js_files/
```

## Step 4: Finding Hidden Parameters

APIs often accept more parameters than the frontend sends. The JavaScript might reference parameters that are only used in certain conditions:

```bash
grep -rn 'role\|admin\|debug\|test\|internal\|secret\|token\|key\|password\|hidden' js_files/
```

Look for objects being constructed before API calls:

```javascript
const params = {
    user_id: currentUser.id,
    // is_admin: true,  // commented out but still in the minified build
    action: "update"
};
```

Commented-out code survives minification if the minifier doesn't strip comments (many don't strip all of them). Also look for conditional parameters:

```javascript
if (user.role === 'admin') {
    params.admin_override = true;
}
```

Now you know the `admin_override` parameter exists and the backend likely accepts it.

## Step 5: Finding Secrets

Developers hardcode things they shouldn't:

```bash
grep -rn 'api_key\|apikey\|api-key' js_files/
grep -rn 'secret\|password\|token' js_files/
grep -rn 'AWS_\|REACT_APP_\|VUE_APP_\|NEXT_PUBLIC_' js_files/
grep -rn 'firebase\|supabase\|algolia\|stripe\|twilio\|sendgrid' js_files/
grep -rn 'AIza\|AKIA\|sk-\|pk_live\|pk_test\|sk_live\|sk_test' js_files/
```

Firebase configs are extremely common. They're technically meant to be public, but developers often set insecure Firestore/Realtime Database rules alongside them. If you find a Firebase config, test the database rules.

AWS access keys (`AKIA...`) in JavaScript are always a valid finding.

## Step 6: Understanding Auth Logic

Read how the application handles authentication:

```bash
grep -rn 'localStorage\|sessionStorage\|cookie' js_files/
grep -rn 'Authorization\|Bearer\|x-auth\|x-token' js_files/
grep -rn 'isAuthenticated\|isAdmin\|isAuthorized\|checkPermission' js_files/
grep -rn 'jwt\|decode\|verify\|sign' js_files/
```

You'll find where tokens are stored, how they're sent, what header names are used, and sometimes the client-side authorization logic. Client-side auth checks are always bypassable, but understanding them tells you what the developers intended, which helps you figure out what they might have missed on the server side.

## Step 7: Finding Feature Flags and Debug Modes

```bash
grep -rn 'feature_flag\|feature_toggle\|featureFlag' js_files/
grep -rn 'debug\|DEBUG\|devMode\|dev_mode\|staging' js_files/
grep -rn 'beta\|internal\|canary\|experiment' js_files/
```

Feature flags often gate unreleased features that haven't been security tested. Debug modes might enable verbose error output or bypass certain security checks.

## Step 8: Diffing JS Between Versions

If you're monitoring a target over time, diff old and new JS files:

```bash
diff old_main.js new_main.js
```

New code means new features, new endpoints, new attack surface. It's often deployed before security review is complete.

Use tools like [JSMon](https://github.com/nicholasgcoles/JSMon) or set up a simple script that periodically downloads JS files and alerts you on changes.

## Automation

[LinkFinder](https://github.com/GerbenJav);) extracts endpoints from JS files:

```bash
python3 linkfinder.py -i https://example.com/main.js -o results.html
```

[SecretFinder](https://github.com/m4ll0k/SecretFinder) looks for API keys and secrets:

```bash
python3 SecretFinder.py -i https://example.com/main.js -o results.html
```

[JSluice](https://github.com/BishopFox/jsluice) is newer and faster:

```bash
cat js_urls.txt | jsluice urls
cat js_urls.txt | jsluice secrets
```

These are good for initial scanning, but they miss context. The best findings come from actually reading the code and understanding what it does. Automated tools find the obvious stuff. The edge cases require a human.