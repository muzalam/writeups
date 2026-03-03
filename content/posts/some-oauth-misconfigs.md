---
title: "Some OAuth Misconfigurations That Actually Get You Account Takeover"
date: 2024-02-10T11:00:00-05:00
draft: false
tags: ["oauth", "auth-bypass", "account-takeover", "web-security"]
difficulty: ""
---

OAuth is everywhere. Almost every modern web app uses it for "Sign in with Google/GitHub/Facebook." And almost every implementation has at least one thing wrong with it. This post covers the misconfigurations that actually lead to account takeover, not just theoretical issues.

<!--more-->

## OAuth 2.0 Flow (Quick Refresher)

The authorization code flow goes like this:

1. User clicks "Login with Google"
2. App redirects to Google: `https://accounts.google.com/o/oauth2/auth?client_id=X&redirect_uri=https://app.com/callback&response_type=code&scope=email&state=random123`
3. User approves
4. Google redirects back: `https://app.com/callback?code=AUTH_CODE&state=random123`
5. App exchanges the code for an access token (server-side)
6. App uses the token to fetch user info from Google
7. App creates a session for the user

Every parameter in that flow is a potential attack surface.

## redirect_uri Manipulation

The `redirect_uri` is where the authorization server sends the user after they approve. The app registers specific redirect URIs with the OAuth provider. The provider is supposed to enforce an exact match.

The problem: many providers and implementations are loose with matching. And even with exact matching, open redirects on the allowed domain bypass the check.

**Path traversal on redirect_uri**:

```
# Registered: https://app.com/callback
# Try:
https://app.com/callback/../attacker-controlled-page
https://app.com/callback/..%2f..%2fattacker-page
https://app.com/callback%23@attacker.com
https://app.com/callback?next=https://attacker.com
```

**Subdomain matching**: if the provider checks that the redirect_uri is under `*.app.com`, any subdomain works:

```
https://evil.app.com/steal-token
```

Combine with subdomain takeover for a full chain.

**Open redirect chaining**: find an open redirect anywhere on `app.com`:

```
https://app.com/redirect?url=https://attacker.com
```

Use this as the redirect_uri. The provider sees `app.com`, approves it, redirects to the open redirect, which forwards the code to your server.

In the implicit flow (response_type=token), this is even worse because the access token is in the URL fragment. With an authorization code, the attacker still needs to exchange it, which requires the client_secret. With a token, they have it immediately.

## Missing or Weak State Parameter

The `state` parameter prevents CSRF on the OAuth callback. Without it, an attacker can:

1. Start the OAuth flow themselves
2. Get a callback URL with their authorization code
3. Send that URL to the victim
4. The victim's browser hits the callback
5. The victim's account is now linked to the attacker's OAuth identity

This means the attacker can log in to the victim's account using their own Google/GitHub/etc credentials.

To test:

1. Start the OAuth flow and capture the authorization URL
2. Remove the `state` parameter (or set it to empty)
3. Complete the flow
4. If the app doesn't reject the request, the state isn't being validated

Some apps generate a state but never validate it on the callback. Check by using the same state value across different sessions or using an arbitrary value.

## Token Leakage Through Referrer

After the OAuth callback, if the page loads any external resources (images, scripts, analytics), the full callback URL (including the authorization code) might be sent in the Referer header.

```
GET /logo.png HTTP/1.1
Host: analytics.com
Referer: https://app.com/callback?code=AUTH_CODE&state=abc
```

The analytics provider now has a valid authorization code. If the code hasn't been exchanged yet and the provider doesn't enforce single-use, they can exchange it.

To test: complete an OAuth login and check the network tab for requests to external domains. Look at the Referer header on those requests.

## Improper Scope Handling

Sometimes the app requests a broad scope but doesn't validate what scope was actually granted. Or the token has more permissions than the app needs.

Test by:

1. Completing the OAuth flow normally
2. Intercepting the authorization request
3. Modifying the scope to something broader (e.g., adding `write` or `admin`)
4. Checking if the granted token actually has the expanded permissions

In some cases, you can also downgrade the scope and the app won't notice, leading to logic issues.

## Account Linking Issues

Many apps let you link multiple OAuth providers to one account, or sign up with email and later link Google. The bugs here are:

**No email verification**: app uses the email from the OAuth provider to match accounts. Attacker sets their Google account email to victim@example.com, signs in via OAuth, and gets linked to the victim's account. This works if the OAuth provider doesn't verify emails (or if the app doesn't check the `email_verified` claim).

**Race condition in linking**: two users simultaneously trying to link the same OAuth identity. Sometimes both succeed due to missing uniqueness constraints.

**Unlinking bypass**: unlink all auth methods from an account, leaving it in a state where nobody can log in. Then link your own OAuth identity to it.

## Token Reuse and Fixation

**Authorization code reuse**: the spec says authorization codes must be single-use. Test by capturing a code and replaying it. Some implementations allow reuse within a time window.

**Token fixation**: if the app stores the OAuth token in a predictable location (like a cookie with a known name), and doesn't rotate the session after OAuth login, you might be able to pre-set a session and have the victim authenticate it.

## Practical Checklist

When testing OAuth:

1. Map out the full OAuth flow. Capture every request.
2. Test redirect_uri with path traversal, different subdomains, and open redirect chains.
3. Remove or tamper with the state parameter.
4. Check Referer headers on the callback page for token leakage.
5. Try modifying the scope in the authorization request.
6. Test what happens when the email from the OAuth provider matches an existing account.
7. Check if the `email_verified` field is checked.
8. Replay the authorization code.
9. Test the implicit flow if supported (response_type=token). It's almost always more exploitable than the code flow.
10. Look for OAuth endpoints in JavaScript files. Sometimes there are debug or internal OAuth flows with weaker security.