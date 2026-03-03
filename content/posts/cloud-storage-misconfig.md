---
title: "Exploiting Misconfigured Cloud Storage: S3, GCS, and Azure Blobs"
date: 2023-10-02T12:00:00-05:00
draft: false
difficulty: ""
---

Misconfigured cloud storage is still one of the most common findings in bug bounty and penetration testing. Publicly readable S3 buckets exposing customer data, writable buckets allowing code injection, and storage accounts leaking backups. The vulnerability is always the same: someone set permissions too broadly and never revisited them.

<!--more-->

## Finding Buckets

Before you can test a bucket, you need to find it. Bucket names follow predictable patterns based on the company name, product name, or environment.

**From DNS and HTTP responses**:

```bash
# S3 bucket references in web pages
curl -s https://example.com | grep -oP 'https?://[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com'
curl -s https://example.com | grep -oP 's3://[a-zA-Z0-9.-]+'
curl -s https://example.com | grep -oP 'https?://s3[a-zA-Z0-9.-]*\.amazonaws\.com/[a-zA-Z0-9.-]+'

# CNAME records pointing to S3
dig CNAME assets.example.com +short
# If it returns something.s3.amazonaws.com, that's a bucket

# GCS
curl -s https://example.com | grep -oP 'https?://storage\.googleapis\.com/[a-zA-Z0-9._-]+'
curl -s https://example.com | grep -oP 'https?://[a-zA-Z0-9._-]+\.storage\.googleapis\.com'

# Azure Blob Storage
curl -s https://example.com | grep -oP 'https?://[a-zA-Z0-9]+\.blob\.core\.windows\.net'
```

**Brute forcing bucket names**:

```bash
# Common patterns
example
example-prod
example-dev
example-staging
example-backup
example-assets
example-uploads
example-data
example.com
www.example.com
example-app
example-static
example-media
```

Test each:

```bash
# AWS S3
aws s3 ls s3://example-prod --no-sign-request 2>&1

# If it returns a listing, it's publicly readable
# If "NoSuchBucket", the bucket doesn't exist
# If "AccessDenied", it exists but isn't public

# GCS
curl https://storage.googleapis.com/example-prod

# Azure
curl https://example.blob.core.windows.net/\$root?restype=container&comp=list
```

**From JavaScript files**: search the JS bundles for bucket references:

```bash
grep -rn 's3.amazonaws.com\|storage.googleapis.com\|blob.core.windows.net' js_files/
```

## Testing Permissions

Once you find a bucket, test what you can do:

**Listing (read bucket contents)**:

```bash
# AWS - unauthenticated
aws s3 ls s3://bucket-name --no-sign-request

# AWS - with any valid AWS account (some buckets allow "authenticated users" which means ANY AWS account)
aws s3 ls s3://bucket-name

# GCS
gsutil ls gs://bucket-name

# Azure
az storage blob list --container-name CONTAINER --account-name ACCOUNT --auth-mode login
```

**Reading objects**:

```bash
# Download a specific file
aws s3 cp s3://bucket-name/secret.txt . --no-sign-request

# Download everything
aws s3 sync s3://bucket-name ./bucket-dump --no-sign-request
```

**Writing**:

```bash
# Try uploading a file
echo "test" > test.txt
aws s3 cp test.txt s3://bucket-name/test.txt --no-sign-request

# If this succeeds, you can write to the bucket
# Delete your test file
aws s3 rm s3://bucket-name/test.txt --no-sign-request
```

**ACL access**:

```bash
# Read the bucket ACL
aws s3api get-bucket-acl --bucket bucket-name --no-sign-request

# Read object ACLs
aws s3api get-object-acl --bucket bucket-name --key file.txt --no-sign-request
```

## What to Look For in Bucket Contents

If you can list the bucket, look for:

- Database backups (.sql, .bak, .dump)
- Configuration files (.env, config.json, settings.yaml)
- Log files (access logs, application logs containing user data)
- Source code archives (.zip, .tar.gz containing application code)
- Credentials (SSH keys, API keys, certificates)
- User uploads (personal documents, IDs, financial records)
- Infrastructure configs (Terraform state files, CloudFormation templates, Kubernetes manifests)

Terraform state files are especially dangerous. They contain the full state of the infrastructure including secrets, database passwords, and API keys in plaintext.

```bash
# Search for sensitive files
aws s3 ls s3://bucket-name --recursive --no-sign-request | \
    grep -iE '\.(sql|bak|dump|env|pem|key|csv|xlsx|zip|tar|tfstate|log)'
```

## Writable Bucket Exploitation

If you can write to a bucket that serves static assets for the target's website, you can inject JavaScript:

1. Find a JS file the site loads from the bucket
2. Download it, add your payload, upload it back
3. Anyone visiting the site now executes your code

This is essentially stored XSS through a misconfigured CDN. The impact is the same as XSS on the main domain, but the root cause is cloud misconfiguration.

For bug bounty: don't actually inject malicious code. Upload a harmless proof file like `poc.txt` with a benign message, and explain in your report what an attacker could do.

## GCS-Specific Issues

Google Cloud Storage has some specific quirks:

**allUsers vs allAuthenticatedUsers**: `allUsers` means anyone on the internet. `allAuthenticatedUsers` means anyone with a Google account. The second one sounds restrictive but isn't, since essentially everyone has a Google account.

**Uniform vs fine-grained ACLs**: buckets using fine-grained ACLs can have individual objects with different permissions. The bucket itself might deny listing, but specific objects might be publicly readable if you know the path.

**Signed URLs**: GCS generates temporary signed URLs for private objects. If these URLs are logged, cached, or shared, anyone with the URL can access the object until it expires.

## Azure-Specific Issues

**Storage account keys**: Azure storage accounts have access keys that grant full control. If leaked (in JS, config files, or git repos), the attacker owns every container and blob in that account.

**SAS tokens**: Shared Access Signatures are time-limited tokens for specific operations. They sometimes show up in URLs:

```
https://account.blob.core.windows.net/container/blob?sv=2020-08-04&ss=b&srt=sco&sp=rwdlacitfx&se=2025-01-01&sig=...
```

If you find a SAS token, check what permissions it grants and when it expires. Overly permissive SAS tokens with long expiration times are a valid finding.

**Anonymous access**: Azure blob containers can be set to "Blob" access (anonymous read for blobs if you know the name) or "Container" access (anonymous read and list). Many people set "Container" without realizing it enables listing.

## Prevention Notes

If you're fixing these issues:

- S3: block public access at the account level using S3 Block Public Access settings
- Use bucket policies, not ACLs. ACLs are legacy and confusing.
- Enable access logging to detect unauthorized access
- Encrypt at rest and enforce encryption in transit
- Use IAM roles instead of access keys wherever possible
- Regularly audit permissions with tools like S3Scanner, CloudSplaining, or Prowler