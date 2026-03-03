---
title: "How i found Critical vulnerability Robinhood: JWT Signature Bypass ($25,000)"
date: 2022-10-14T09:50:00-05:00
draft: false
tages: ["bug-bounty", "JWT"]
---

I found a critical vulnerability in Robinhood where certain API endpoints weren't validating JWT signatures. This meant you could modify the user_id in the token, drop the signature entirely, and the server would just accept it — letting you act as any user. I demonstrated this by changing another user's username. Robinhood awarded their maximum bounty of $25,000.

<!--more-->

## Background

I was digging through Robinhood's JavaScript files, mostly just trying to understand how their frontend worked and what endpoints it was talking to. While reading through the JS, I noticed some API routes that followed a slightly different naming pattern than the rest of the app. They looked like they belonged to an older service or a separate internal system. I started sending requests to them and pretty quickly noticed something was off with how they handled authentication.

## The Bug

When you log into Robinhood, the app gives you a JWT. For anyone unfamiliar — a JWT has three parts separated by dots: a header, a payload, and a signature. The payload carries stuff like your user_id, and the signature is what proves nobody tampered with it. If you change anything in the payload, the signature should no longer match, and the server should reject the request.

These endpoints didn't check the signature at all.

I could take my JWT, decode it, swap my user_id for someone else's, completely remove the signature portion, and the server would process the request as if I were that user. The token field in the JWT wasn't tied to the user_id in any meaningful way — the server just blindly trusted whatever user_id was in the payload.

## Steps to Reproduce

1. Log into Robinhood, go to your profile, and click Edit Profile
2. Change your username and capture the request in Burp Suite — it contains your JWT in the headers
3. Send the request to Repeater
4. Grab the JWT and throw it into jwt.io to see the contents — the user_id in my case started with "94"
5. Change the user_id to another user's ID (in my case, one starting with "6a")
6. Strip the signature from the JWT but keep the trailing dot
7. Replace the JWT in your Repeater request with the modified one and send it
8. The other user's username is now changed

To confirm it worked, I logged into the target account and the username had been changed to whatever I set it to — "Muzammil Hackerone" staring right back at me on the profile page.

## Impact

This let an attacker change any user's username with just their user_id. The server wasn't tying the JWT's token field to the user_id, and it wasn't verifying signatures. On a platform where people have real money invested, that's a bad day.

I labeled this as an IDOR on the HackerOne report because honestly I didn't fully know the right terminology at the time. It was really a JWT signature bypass — the server was accepting unsigned tokens, which is a much more fundamental authentication failure than a typical IDOR.

## Timeline

- **Oct 14, 2022** — Submitted the report
- **Oct 14, 2022** — Triaged within hours, severity bumped to Critical (9.1) same day
- **Oct 14, 2022** — Robinhood rolled out a fix the same day and asked me to retest
- **Oct 14, 2022** — Confirmed the fix. Server now returns 401 Unauthorized when you try the same thing. JWT signature is actually validated.
- **Oct 15, 2022** — Report closed as Resolved
- **Oct 24, 2022** — $25,000 bounty paid out (Robinhood's maximum)

From report to fix in under 12 hours. Robinhood's security team moved fast on this one.

## What Robinhood Said

Their team confirmed that this was a recently introduced issue across a few services that were using an older system for verifying authentication tokens. They fixed it by enforcing proper JWT signature validation on those services.
![H1 comms](/writeups/images/rh-h1.png)


## Takeaways

Read the JavaScript. I cannot stress this enough. I didn't find this by running some automated scanner or brute-forcing endpoints. I found it by sitting down, reading their JS bundles, and noticing that a handful of API routes looked different from the rest. That curiosity led to finding endpoints that had a completely broken auth model.

Also — if you find something and you're not sure what to call it, just submit it anyway. I called this an IDOR when it was really a JWT signature bypass. Didn't matter. The impact was clear, and Robinhood's team understood what was going on.
