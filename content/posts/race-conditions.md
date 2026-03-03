---
title: "Race Conditions in Web Applications: The Single-Packet Attack"
date: 2025-01-20T09:00:00-05:00
draft: false
tags: ["race-condition", "web-security", "toctou", "bug-bounty"]
difficulty: ""
---

Race conditions happen when the outcome of an operation depends on the timing of concurrent requests. Most developers don't think about concurrency in web applications because the framework handles it. But the framework doesn't handle your business logic. If two requests hit a balance check at the same time, both might pass before either deduction is written. This post covers how to find and exploit these reliably.

<!--more-->

## The Core Problem

A typical vulnerable flow looks like this (pseudocode):

```
1. Read user balance: $100
2. Check: is balance >= $50? Yes
3. Deduct $50 from balance
4. Deliver the item
```

If you send two requests at the exact same time, both hit step 1 and read $100. Both pass step 2. Both deduct $50. You paid $50 but got two items. Your final balance might be $50 (if the deductions don't overlap) or $0 (if they do), but either way you got $100 worth of items for $50 or less.

This is a TOCTOU (Time of Check to Time of Use) vulnerability. The check (step 2) and the use (step 3) are not atomic.

## Where to Look

Race conditions are most impactful in:

- **Payment and balance operations**: buying items, transferring money, redeeming credits
- **Coupon/voucher redemption**: single-use codes that can be used multiple times
- **Voting and rating systems**: one vote per user that can be cast multiple times
- **Account creation with unique constraints**: email uniqueness checks that can be bypassed
- **Invitation and referral systems**: one-time invite links used multiple times
- **File upload with processing**: upload races where validation and processing are separate steps
- **API rate limiting**: limits that check before incrementing the counter
- **Password reset tokens**: single-use tokens that can be used multiple times

## The Single-Packet Attack

The traditional approach to race conditions was sending many requests as fast as possible using multiple threads. The problem is network jitter. Even with 100 concurrent threads, the requests arrive at the server spread across several milliseconds, which is often enough for the server to process them sequentially.

James Kettle (from PortSwigger) introduced the single-packet attack for HTTP/2. The idea: pack multiple HTTP/2 requests into a single TCP packet so they arrive at the server at the exact same time, down to the microsecond.

HTTP/2 multiplexes multiple requests over a single connection. If you construct a TCP packet containing multiple complete HTTP/2 request frames, the server's HTTP/2 implementation will process them all simultaneously.

Using Burp Suite's Turbo Intruder:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=Engine.BURP2)

    # Queue 20 identical requests
    for i in range(20):
        engine.queue(target.req, gate='race1')

    # Open the gate - all requests are sent in a single packet
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

The `gate` parameter holds all requests until `openGate` is called, then sends them simultaneously.

For HTTP/1.1, you can approximate this with the "last-byte sync" technique. Send all requests except the final byte, then send all the final bytes at once:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=20,
                          engine=Engine.THREADED)

    for i in range(20):
        engine.queue(target.req, gate='race1')

    engine.openGate('race1')
```

## Practical Example: Coupon Reuse

The application has a coupon code `SAVE50` that gives $50 off, one use per account.

Normal flow:

```
POST /api/apply-coupon
{"code": "SAVE50"}

Response: {"success": true, "discount": 50}

# Second attempt:
POST /api/apply-coupon
{"code": "SAVE50"}

Response: {"error": "Coupon already used"}
```

Race condition attack: send 20 coupon redemption requests simultaneously. The server checks "has this coupon been used?" for all 20 requests. If the check happens before any of the redemptions are written, all 20 pass the check and you get $1000 off instead of $50.

## Practical Example: Balance Transfer

User A has $100. The goal is to transfer $100 to User B multiple times, ending up with more than $100 total across both accounts.

```
POST /api/transfer
{"to": "user_b", "amount": 100}
```

Send 5 of these simultaneously. All 5 read User A's balance as $100. All 5 pass the balance check. All 5 deduct $100 (the balance goes to -$400 or the deductions overlap and it goes to $0). User B receives $500.

## Detecting Race Conditions

Not all concurrent requests indicate a race condition. You need to confirm that the outcome is different from sequential execution.

**Step 1**: understand the expected behavior. Perform the action normally and note the result.

**Step 2**: send multiple identical requests simultaneously using the single-packet technique.

**Step 3**: compare the results. Look for:

- Multiple success responses where only one should succeed
- Inconsistent final state (balance doesn't add up, more items than paid for)
- Duplicate database entries
- Missing rate limit enforcement

**Step 4**: verify by checking the account state afterward. Did the balance change more than expected? Are there duplicate records?

## Limit Overrun Race Conditions

A specific variant: the application has a limit (3 free trials, 5 API keys, 1 profile picture upload at a time), and you can exceed it by racing.

```
# Create API keys - limit is 5
POST /api/keys  (x20 simultaneous requests)

# Check: do you now have 20 keys instead of 5?
GET /api/keys
```

This works when the limit check is: "count existing keys; if count < 5, create new key." If 20 requests all count 0 existing keys (because none have been created yet), all 20 create a key.

## Multi-Endpoint Race Conditions

Sometimes the race isn't between identical requests but between different requests that interact:

**Password reset race**: request a password reset (which generates a token), then simultaneously use the current password to log in. If the reset invalidates the old password after generating the token but there's a window between the two, you might end up with both a valid session and a valid reset token.

**Edit/delete race**: simultaneously edit and delete a resource. The edit might succeed on a resource that's being deleted, causing inconsistent state or errors that leak information.

**Registration/verification race**: simultaneously register with an email and verify a different email address. The verification might apply to the newly registered account due to a race in session handling.

## Beyond Web Applications

Race conditions also exist in:

- **File systems**: two processes writing to the same file (symlink attacks)
- **Database transactions**: if the application doesn't use proper transaction isolation levels
- **Distributed systems**: two instances of the same service processing the same event
- **Smart contracts**: reentrancy attacks are essentially race conditions in blockchain execution

## Reporting

When reporting a race condition, include:

1. The exact endpoint(s) involved
2. The number of concurrent requests sent
3. The expected outcome vs the actual outcome
4. Screenshots or response bodies showing the duplicated action
5. The final state showing the inconsistency (account balance, number of items, etc.)

For high-impact race conditions (financial, involving real money), be extremely careful. Demonstrate with minimal impact. Send 2-3 concurrent requests, not 1000. Clean up after yourself. Explain that an attacker could scale this.