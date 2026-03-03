---
title: "How i found Critical vulneribility in NASA: Exposed IAM Admin Panel on Science Cloud Infrastructure"
date: 2024-10-19T08:09:00+00:00
draft: false
difficulty: ""
---

I found an exposed identity and access management admin panel with bruteforcable credentials on NASA's Science Cloud infrastructure, the platform behind science.data.nasa.gov that hosts petabytes of research data across astrophysics, planetary science, Earth science, and more. Full admin access to the IAM system, found by scanning non-standard ports during recon.

<!--more-->

## Some Context

NASA's Open Science Data Repository, accessible through science.data.nasa.gov, is the portal for their Science Cloud. This isn't some forgotten dev environment. The Science Cloud runs on AWS and Azure, stores petabytes of scientific data, and supports over 160 active research projects spanning astrophysics, planetary science, Earth science, heliophysics, and biological sciences. Researchers across the world depend on it.

The IAM service I found was part of this infrastructure, managing authentication and access control for services connected to it.

## How I Found It

This one came down to enumeration. Not a fancy exploit, not a clever bypass — just doing recon properly and being thorough about it.

I started with extensive subdomain hunting across multiple sources. I'm not going to go into the full methodology here, but I was pulling subdomains from a wide range of tools and data sources to build out as complete a picture of NASA's attack surface as I could. The goal was simple: find as many live subdomains as possible.

Once I had my list, I ran HTTPX against everything. The important part here is that I wasn't just checking ports 80 and 443 like most people do. I was scanning a full range of common service ports. That's what made the difference. One of NASA's subdomains was serving something on port 8443 — an identity and access management admin panel.

## The Bug

The IAM service handles user authentication, single sign-on, and role management for connected applications. When you set one of these up, it typically comes with a default admin account. You're supposed to change the credentials immediately.

They didn't.

I navigated to the admin console, tried a few default creds, and I was in. Full administrative access.

## Impact

Given that this IAM service sat within NASA's Science Cloud infrastructure, the potential impact here was critical(P1). From the admin panel, an attacker could:

- Create, modify, or delete any user account in the system
- Change authentication flows and weaken security policies
- Escalate privileges and assign admin roles to any account
- Access or modify configurations for all services relying on this system for authentication
- Compromise the confidentiality, integrity, and availability of every connected service

We're talking about infrastructure that supports active research across multiple scientific disciplines, running on cloud environments that store petabytes of data. Unauthorized access to the IAM layer means you're potentially one step away from the data and services those 160+ research projects depend on.

On top of that, I discovered that a message queue service running on the same host was also using this IAM system for authentication. So the blast radius extended beyond just user management — it included the messaging infrastructure as well.

## Timeline

- **Oct 19, 2024** — Submitted the report through Bugcrowd
- **Oct 21, 2024** — Triaged and validated by Bugcrowd as P1
- **Oct 21, 2024** — Added additional finding about the message queue service using the same IAM instance
- **Oct 25, 2024** — NASA changed state to Unresolved (working on fix)
- **Oct 29, 2024** — Endpoints no longer accessible, report marked as Resolved
- **Nov 1, 2024** — Received a Letter of Appreciation from NASA

![NASA comms](/writeups/images/nasa-letter.png)

## Takeaways

The whole reason I found this is because I didn't stop at the obvious. Most people run their subdomain lists through HTTPX on port 80 and 443, call it a day, and move on. This admin panel was sitting on port 8443. If I'd only scanned the default ports, I would have completely missed it.

The actual vulnerability itself was simpler — default credentials on an admin panel. 

If you're doing bug bounty, invest time in your enumeration. Scan more ports. Use multiple subdomain sources. Be thorough. The low-hanging fruit isn't always on port 443.