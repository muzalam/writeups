---
title: "Subdomain Takeover: The Full Process from Enumeration to Takeover, my learnings"
date: 2022-11-05T09:00:00-05:00
draft: false
difficulty: ""
---

Subdomain takeover is one of those bugs that sounds simple on paper but requires solid recon to actually find. The vulnerability exists when a DNS record points to a service that no longer exists, and an attacker can claim that service to serve content on the target's subdomain. This is the full process I follow.

<!--more-->

## How Subdomain Takeover Works

A company sets up `blog.example.com` and points it to a GitHub Pages site, a Heroku app, an S3 bucket, or some other external service. Later, they delete the GitHub repo or the Heroku app, but forget to remove the DNS record. The CNAME still points to `example.github.io` or `example.herokuapp.com`, but nobody owns that resource anymore.

An attacker creates a GitHub Pages site or Heroku app with the matching name, and now they control what's served on `blog.example.com`. To visitors and browsers, it looks like a legitimate page under the company's domain.

## Step 1: Subdomain Enumeration

You need a comprehensive list of subdomains. No single tool or source gives you everything. I use multiple sources and merge the results.

**Passive sources** (no direct interaction with the target):

```bash
# Certificate Transparency logs
# crt.sh is the standard
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Subfinder pulls from dozens of sources
subfinder -d example.com -all -silent

# Amass passive mode
amass enum -passive -d example.com

# GitHub search (subdomains in code/configs)
# Use github-subdomains or manually search
github-subdomains -d example.com -t YOUR_TOKEN
```

**Active enumeration**:

```bash
# DNS brute forcing
puredns bruteforce wordlist.txt example.com --resolvers resolvers.txt

# For the wordlist, use:
# - SecLists DNS wordlists
# - Assetnote wordlists (best for modern apps)
# - Custom wordlists from JS files and wayback data

# Permutation scanning
gotator -sub known_subs.txt -perm permutations.txt | puredns resolve
```

**Scraping and crawling**:

```bash
# Wayback Machine
waybackurls example.com | unfurl -u domains | sort -u

# Common Crawl
# Use commoncrawl indexes to find historical subdomains
```

Merge everything, deduplicate, and resolve:

```bash
cat passive.txt active.txt scraped.txt | sort -u > all_subs.txt
puredns resolve all_subs.txt --resolvers resolvers.txt > alive_subs.txt
```

## Step 2: Identify Dangling Records

Now check which subdomains point to external services with CNAME records:

```bash
# Get CNAME records for all subdomains
while read sub; do
    cname=$(dig +short CNAME "$sub")
    if [ -n "$cname" ]; then
        echo "$sub -> $cname"
    fi
done < alive_subs.txt > cnames.txt
```

Look for CNAMEs pointing to services known to be vulnerable to takeover:

```
.github.io
.herokuapp.com
.s3.amazonaws.com
.s3-website.*.amazonaws.com
.azurewebsites.net
.cloudfront.net
.elasticbeanstalk.com
.shopify.com
.fastly.net
.ghost.io
.netlify.app
.surge.sh
.bitbucket.io
.pantheon.io
.readme.io
.zendesk.com
.teamwork.com
.helpjuice.com
.helpscoutdocs.com
.cargo.site
.statuspage.io
.tumblr.com
.wordpress.com
.fly.dev
```

The [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) repo maintains an updated list of which services are vulnerable and how to verify.

## Step 3: Verify the Takeover

A dangling CNAME alone isn't enough. You need to confirm that the target resource is actually unclaimed. The indicators depend on the service:

**GitHub Pages**: returns a 404 with "There isn't a GitHub Pages site here."

**Heroku**: "No such app"

**S3**: "NoSuchBucket" error

**Azure**: NXDOMAIN on the azurewebsites.net subdomain

**Shopify**: "Sorry, this shop is currently unavailable."

Automate the check:

```bash
# nuclei has takeover detection templates
nuclei -l alive_subs.txt -t takeovers/

# Or use subjack
subjack -w alive_subs.txt -t fingerprints.json -timeout 30 -ssl -v
```

Manual verification is still important. Automated tools have false positives. Always confirm by:

1. Checking the CNAME target resolves (or doesn't)
2. Visiting the URL and checking the response
3. Verifying you can actually claim the resource on the service

## Step 4: Claim the Resource

This depends on the service. A few examples:

**GitHub Pages**:

1. Create a new GitHub repo
2. Add a `CNAME` file containing the target subdomain
3. Enable GitHub Pages in repo settings
4. Wait for DNS propagation

**S3 bucket**:

```bash
aws s3 mb s3://the-exact-bucket-name --region us-east-1
echo "<h1>Subdomain Takeover PoC</h1>" > index.html
aws s3 cp index.html s3://the-exact-bucket-name/index.html
aws s3 website s3://the-exact-bucket-name --index-document index.html
```

**Heroku**:

```bash
heroku create the-app-name
heroku domains:add vulnerable-subdomain.example.com
```

## Impact

Subdomain takeover is more than just defacement. Because the attacker controls content on a subdomain of the target, they can:

- Set cookies scoped to `.example.com`, which the main site's browser will send on every request. This enables session fixation and potentially session hijacking.
- Host a phishing page that's technically on the real domain. The URL bar shows `blog.example.com`, SSL cert is valid, users trust it.
- Bypass CSP if the main site whitelists `*.example.com` as a script source.
- Steal OAuth tokens if the subdomain is in the redirect_uri allowlist.

For bug bounty, always mention the cookie scoping and CSP bypass angles in your report. It shows impact beyond "I can put HTML on your subdomain."

## Edge Cases

**NS takeover**: instead of a CNAME, the subdomain has NS records pointing to a nameserver that's no longer registered. If you can register that nameserver domain, you control DNS for the entire subdomain and all its sub-subdomains. This is rarer but far more impactful.

**Expired domains**: sometimes the CNAME points to a custom domain that's expired. You can register the domain and now you control the CNAME target.

**Azure tenant takeover**: Azure uses verification TXT records. If a custom domain was verified in one tenant and that tenant gets deleted, another tenant can verify and claim the domain. This applies to various Azure services including App Service, Front Door, and Traffic Manager.

**Second-order takeover**: the subdomain itself isn't vulnerable, but it loads resources (JS, CSS, images) from a domain or service that is. If you can take over the resource origin, you get script execution in the context of the main page.