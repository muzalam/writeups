---
title: "DNS Recon: Going Beyond Subdomain Brute Forcing"
date: 2022-05-20T09:30:00-05:00
draft: false
tags: ["dns", "recon", "enumeration", "bug-bounty"]
difficulty: ""
---

DNS is the foundation of your recon. Every web target starts with a domain, and the DNS records behind it reveal infrastructure, services, third-party integrations, and forgotten assets. Most people stop at subdomain brute forcing. This post covers the full picture.

<!--more-->

## DNS Record Types and What They Reveal

Before running tools, understand what you're looking for:

**A/AAAA records**: IP addresses. Multiple A records might indicate load balancing. The IP ranges tell you the hosting provider (AWS, GCP, Azure, on-prem).

**CNAME records**: aliases. These reveal third-party services (Cloudflare, Heroku, GitHub Pages, S3) and are the basis for subdomain takeover.

**MX records**: mail servers. They tell you the email provider (Google Workspace, O365, Proofmail) and sometimes reveal internal hostnames.

**TXT records**: verification entries and policies. This is where it gets interesting:

```bash
dig TXT example.com +short
```

You'll find SPF records (listing all IPs authorized to send email, including third-party services), DKIM selectors, DMARC policies, Google/Microsoft domain verification tokens, and sometimes deployment verification strings that leak internal info.

**NS records**: nameservers. If they use a specific DNS provider, that's useful context. Dangling NS records are a takeover vector.

**SRV records**: service discovery. Often used for Active Directory, SIP, XMPP:

```bash
dig SRV _ldap._tcp.example.com
dig SRV _sip._tcp.example.com
dig SRV _autodiscover._tcp.example.com
```

## Certificate Transparency Logs

Every publicly trusted SSL certificate is logged in CT logs. This is a passive, non-intrusive source of subdomains:

```bash
# crt.sh API
curl -s "https://crt.sh/?q=%.example.com&output=json" | \
    jq -r '.[].name_value' | \
    sed 's/\*\.//g' | \
    sort -u

# For better performance, query the Postgres database directly
psql -h crt.sh -p 5432 -U guest certwatch -c \
    "SELECT DISTINCT ci.NAME_VALUE FROM certificate_identity ci \
    WHERE ci.NAME_TYPE='dNSName' AND reverse(ci.NAME_VALUE) LIKE reverse('%.example.com');"
```

CT logs also reveal historical certificates. Old certs might reference subdomains that no longer have DNS records but still have running services on the IP they used to point to.

## Passive DNS

Passive DNS databases record historical DNS resolutions. When someone else resolved a domain, the result was logged. This gives you:

- Subdomains that no longer exist in DNS but were once active
- Historical IP addresses (useful for finding the origin IP behind a CDN)
- Changes over time that reveal infrastructure migrations

Sources:

```bash
# SecurityTrails API
curl -s "https://api.securitytrails.com/v1/domain/example.com/subdomains" \
    -H "APIKEY: YOUR_KEY" | jq

# VirusTotal
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=KEY&domain=example.com"

# Common passive DNS sources accessible via subfinder:
subfinder -d example.com -all -v
```

## Zone Transfers

This is old school, but still worth trying. A misconfigured DNS server might allow zone transfers, which dump every record in the zone:

```bash
# First, find the nameservers
dig NS example.com +short

# Try a zone transfer against each one
dig AXFR example.com @ns1.example.com
dig AXFR example.com @ns2.example.com
```

If this works, you just got every single DNS record in one query. It rarely works on production domains, but internal or secondary nameservers sometimes allow it.

## Reverse DNS and PTR Records

Given an IP range, reverse DNS can reveal hostnames:

```bash
# Single IP
dig -x 1.2.3.4

# Scan a range
for ip in $(seq 1 255); do
    result=$(dig -x 10.10.10.$ip +short 2>/dev/null)
    if [ -n "$result" ]; then
        echo "10.10.10.$ip -> $result"
    fi
done
```

Once you know the target's IP range (from initial A record lookups), reverse DNS might reveal internal hostnames, server naming conventions, and services.

## ASN Enumeration

Find all IP ranges owned by the organization:

```bash
# Find the ASN
whois -h whois.radb.net -- '-i origin AS12345'

# Or use bgp.he.net
# Search for the company name, get their ASN, list all prefixes

# Amass intel mode
amass intel -asn 12345
```

Once you have the IP ranges, you can scan them for services and do reverse DNS on the entire range. This finds infrastructure that's not linked to the main domain through DNS.

## DNS Brute Forcing (Done Right)

Most people run a small wordlist and call it a day. Here's how to do it properly:

```bash
# Use puredns for fast, accurate resolution
# It handles wildcard detection and validation automatically
puredns bruteforce wordlist.txt example.com \
    --resolvers resolvers.txt \
    --wildcard-tests 10

# For resolvers, use a curated list of public DNS servers
# Don't use just 8.8.8.8 - you'll get rate limited
# https://github.com/trickest/resolvers has maintained lists
```

**Wordlist selection matters**. Use multiple wordlists:

```bash
# Assetnote wordlists (best for modern apps)
# https://wordlists.assetnote.io/

# SecLists DNS wordlists
# /usr/share/seclists/Discovery/DNS/

# Generate custom wordlists from the target's own content
# Crawl the site, extract words, use them as subdomains
cewl https://example.com -d 3 -m 4 -w custom_words.txt
```

**Permutation scanning**: take known subdomains and generate permutations:

```bash
# If you know: dev.example.com, staging.example.com
# Generate: dev-api.example.com, staging-api.example.com, dev2.example.com, etc.

# gotator does this
gotator -sub known_subs.txt -perm permutations.txt -depth 2 | \
    puredns resolve --resolvers resolvers.txt

# alterx is another good option
echo "dev.example.com" | alterx -silent | puredns resolve
```

## Wildcard Detection

Some domains have wildcard DNS records: `*.example.com` resolves to an IP. This breaks brute forcing because every subdomain appears to exist.

```bash
# Test for wildcards
dig randomnonexistent12345.example.com

# If it resolves, you have a wildcard
# puredns handles this automatically
# For manual testing, compare the response for random subdomains
# and filter out those that match the wildcard response
```

## DNS Rebinding for Active Exploitation

This goes beyond recon into exploitation. DNS rebinding lets you bypass IP-based access controls:

1. Register a domain with a very short TTL (like 1 second)
2. First resolution points to your IP
3. Victim application fetches your URL, security check passes (it's an external IP)
4. Second resolution points to `127.0.0.1` or `169.254.169.254`
5. The application makes the actual request to the internal IP

Tools like [singularity](https://github.com/nccgroup/singularity) and [rbndr](https://github.com/taviso/rbndr) automate the DNS rebinding setup.

## Putting It Together

My DNS recon flow:

1. Start with CT logs and passive DNS for a baseline subdomain list
2. Check all DNS record types on the main domain (TXT, MX, NS, SRV)
3. Find the ASN and enumerate all IP ranges
4. Run DNS brute forcing with good wordlists against the domain
5. Run permutation scanning against known subdomains
6. Do reverse DNS on all discovered IP ranges
7. Check for zone transfers on all nameservers
8. Run HTTPX on everything to find live web services on all ports

Each step feeds the next. New subdomains from brute forcing become inputs for permutation scanning. IP ranges from ASN lookup become targets for reverse DNS. The goal is to build the most complete map possible before you start testing.