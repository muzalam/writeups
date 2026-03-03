---
title: "Building a Recon Automation Pipeline from Scratch"
date: 2024-04-08T11:00:00-05:00
draft: false
tags: ["recon", "automation", "bug-bounty", "methodology", "tooling"]
difficulty: ""
---

Manual recon doesn't scale. If you're hunting on programs with thousands of subdomains and assets, you need a pipeline that runs continuously, finds new attack surface, and alerts you when something changes. This is how I built mine.

<!--more-->

## Architecture Overview

The pipeline has four stages:

1. **Discovery**: find subdomains, IPs, and open ports
2. **Fingerprinting**: identify what's running on each host
3. **Scanning**: run targeted checks based on what was found
4. **Monitoring**: detect changes and alert on new assets

Each stage feeds data to the next. The whole thing runs on a VPS with cron jobs. Nothing fancy. No Kubernetes, no message queues. Just bash scripts and a few Python scripts for the parts where bash gets painful.

## Stage 1: Discovery

### Subdomain Enumeration

Pull from as many sources as possible, then resolve:

```bash
#!/bin/bash
# recon_subs.sh

DOMAIN=$1
OUTPUT_DIR="results/$DOMAIN"
mkdir -p "$OUTPUT_DIR"

echo "[*] Running subfinder..."
subfinder -d "$DOMAIN" -all -silent > "$OUTPUT_DIR/subfinder.txt"

echo "[*] Running amass..."
amass enum -passive -d "$DOMAIN" -o "$OUTPUT_DIR/amass.txt" 2>/dev/null

echo "[*] Querying crt.sh..."
curl -s "https://crt.sh/?q=%.$DOMAIN&output=json" | \
    jq -r '.[].name_value' 2>/dev/null | \
    sed 's/\*\.//g' | sort -u > "$OUTPUT_DIR/crtsh.txt"

echo "[*] Running github-subdomains..."
github-subdomains -d "$DOMAIN" -t "$GITHUB_TOKEN" -o "$OUTPUT_DIR/github.txt" 2>/dev/null

echo "[*] Merging and resolving..."
cat "$OUTPUT_DIR"/*.txt | sort -u > "$OUTPUT_DIR/all_subs_raw.txt"

puredns resolve "$OUTPUT_DIR/all_subs_raw.txt" \
    -r resolvers.txt \
    --wildcard-tests 10 \
    -w "$OUTPUT_DIR/resolved.txt"

echo "[*] Running permutations on resolved subs..."
gotator -sub "$OUTPUT_DIR/resolved.txt" -perm permutations.txt -depth 1 -silent | \
    puredns resolve -r resolvers.txt -w "$OUTPUT_DIR/permuted.txt" 2>/dev/null

cat "$OUTPUT_DIR/resolved.txt" "$OUTPUT_DIR/permuted.txt" 2>/dev/null | \
    sort -u > "$OUTPUT_DIR/final_subs.txt"

TOTAL=$(wc -l < "$OUTPUT_DIR/final_subs.txt")
echo "[+] Found $TOTAL unique subdomains for $DOMAIN"
```

### Port Scanning

Don't just check 80 and 443. This is where you find the stuff everyone else misses:

```bash
#!/bin/bash
# recon_ports.sh

DOMAIN=$1
OUTPUT_DIR="results/$DOMAIN"

echo "[*] Running port scan with naabu..."
naabu -list "$OUTPUT_DIR/final_subs.txt" \
    -p 80,443,8080,8443,8000,8888,3000,3001,4443,5000,5001,9000,9090,9443,8081,8082,10000 \
    -silent \
    -o "$OUTPUT_DIR/ports.txt"

echo "[+] Port scan complete"
```

For critical targets, scan the full port range on interesting hosts:

```bash
naabu -host target.example.com -p - -silent
```

## Stage 2: Fingerprinting

### HTTP Probing

Run HTTPX on every host:port combination to identify live web services:

```bash
#!/bin/bash
# recon_httpx.sh

DOMAIN=$1
OUTPUT_DIR="results/$DOMAIN"

echo "[*] Running httpx..."
httpx -list "$OUTPUT_DIR/ports.txt" \
    -silent \
    -status-code \
    -title \
    -tech-detect \
    -content-length \
    -follow-redirects \
    -json \
    -o "$OUTPUT_DIR/httpx.json"

# Extract just the live URLs
cat "$OUTPUT_DIR/httpx.json" | jq -r '.url' > "$OUTPUT_DIR/live_urls.txt"

TOTAL=$(wc -l < "$OUTPUT_DIR/live_urls.txt")
echo "[+] Found $TOTAL live web services"
```

The JSON output from HTTPX gives you status codes, page titles, detected technologies, content length, and more. This is your map of what's running where.

### Screenshot

Take screenshots of every live URL for quick visual review:

```bash
gowitness file -f "$OUTPUT_DIR/live_urls.txt" \
    -P "$OUTPUT_DIR/screenshots/" \
    --delay 3
```

Scrolling through screenshots is one of the fastest ways to spot interesting targets: login panels, admin interfaces, default pages, error messages with stack traces.

## Stage 3: Scanning

### Nuclei for Known Vulnerabilities

Run nuclei against everything:

```bash
#!/bin/bash
# recon_nuclei.sh

DOMAIN=$1
OUTPUT_DIR="results/$DOMAIN"

echo "[*] Running nuclei..."
nuclei -list "$OUTPUT_DIR/live_urls.txt" \
    -severity critical,high,medium \
    -json \
    -o "$OUTPUT_DIR/nuclei.json" \
    -silent

# Count findings by severity
echo "[+] Nuclei results:"
cat "$OUTPUT_DIR/nuclei.json" | jq -r '.info.severity' | sort | uniq -c | sort -rn
```

Nuclei templates cover thousands of known CVEs, default credentials, misconfigurations, exposed panels, and more. Update templates regularly:

```bash
nuclei -update-templates
```

### Custom Checks

Some things need targeted checking:

```bash
# Check for subdomain takeover
subjack -w "$OUTPUT_DIR/final_subs.txt" -t 100 -timeout 30 -ssl -v \
    -o "$OUTPUT_DIR/takeover.txt"

# Check for CORS misconfigurations
while read url; do
    response=$(curl -s -H "Origin: https://evil.com" -I "$url" 2>/dev/null)
    if echo "$response" | grep -qi "access-control-allow-origin: https://evil.com"; then
        echo "[CORS] $url reflects arbitrary origin"
    fi
done < "$OUTPUT_DIR/live_urls.txt"

# Check for open redirects in common parameters
while read url; do
    for param in redirect url next dest return_url redirect_uri; do
        test_url="${url}?${param}=https://evil.com"
        location=$(curl -s -o /dev/null -w '%{redirect_url}' "$test_url")
        if echo "$location" | grep -q "evil.com"; then
            echo "[REDIRECT] $test_url -> $location"
        fi
    done
done < "$OUTPUT_DIR/live_urls.txt"
```

### JavaScript Analysis

Pull and analyze JS files from every live URL:

```bash
#!/bin/bash
# recon_js.sh

DOMAIN=$1
OUTPUT_DIR="results/$DOMAIN"
JS_DIR="$OUTPUT_DIR/js_files"
mkdir -p "$JS_DIR"

echo "[*] Extracting JS URLs..."
cat "$OUTPUT_DIR/live_urls.txt" | getJS -complete -silent | sort -u > "$OUTPUT_DIR/js_urls.txt"

echo "[*] Downloading JS files..."
while read js_url; do
    filename=$(echo "$js_url" | md5sum | cut -d' ' -f1).js
    curl -s "$js_url" -o "$JS_DIR/$filename" 2>/dev/null
done < "$OUTPUT_DIR/js_urls.txt"

echo "[*] Extracting endpoints from JS..."
cat "$OUTPUT_DIR/js_urls.txt" | jsluice urls 2>/dev/null | \
    jq -r '.url' | sort -u > "$OUTPUT_DIR/js_endpoints.txt"

echo "[*] Searching for secrets in JS..."
cat "$OUTPUT_DIR/js_urls.txt" | jsluice secrets 2>/dev/null > "$OUTPUT_DIR/js_secrets.json"

ENDPOINTS=$(wc -l < "$OUTPUT_DIR/js_endpoints.txt")
echo "[+] Found $ENDPOINTS endpoints in JS files"
```

## Stage 4: Monitoring

This is what separates a one-time scan from continuous recon. Run the pipeline on a schedule and diff the results:

```bash
#!/bin/bash
# monitor.sh

DOMAIN=$1
OUTPUT_DIR="results/$DOMAIN"
PREV_DIR="results/$DOMAIN/previous"

mkdir -p "$PREV_DIR"

# Save previous results
cp "$OUTPUT_DIR/final_subs.txt" "$PREV_DIR/final_subs.txt" 2>/dev/null
cp "$OUTPUT_DIR/live_urls.txt" "$PREV_DIR/live_urls.txt" 2>/dev/null

# Run the full pipeline
./recon_subs.sh "$DOMAIN"
./recon_ports.sh "$DOMAIN"
./recon_httpx.sh "$DOMAIN"
./recon_nuclei.sh "$DOMAIN"
./recon_js.sh "$DOMAIN"

# Diff for new subdomains
if [ -f "$PREV_DIR/final_subs.txt" ]; then
    comm -13 "$PREV_DIR/final_subs.txt" "$OUTPUT_DIR/final_subs.txt" > "$OUTPUT_DIR/new_subs.txt"
    NEW_SUBS=$(wc -l < "$OUTPUT_DIR/new_subs.txt")
    if [ "$NEW_SUBS" -gt 0 ]; then
        echo "[!] $NEW_SUBS new subdomains found!"
        # Send alert
        cat "$OUTPUT_DIR/new_subs.txt" | notify -silent -provider-config notify-config.yaml
    fi
fi

# Diff for new live URLs
if [ -f "$PREV_DIR/live_urls.txt" ]; then
    comm -13 "$PREV_DIR/live_urls.txt" "$OUTPUT_DIR/live_urls.txt" > "$OUTPUT_DIR/new_urls.txt"
    NEW_URLS=$(wc -l < "$OUTPUT_DIR/new_urls.txt")
    if [ "$NEW_URLS" -gt 0 ]; then
        echo "[!] $NEW_URLS new live URLs found!"
        cat "$OUTPUT_DIR/new_urls.txt" | notify -silent -provider-config notify-config.yaml
    fi
fi
```

Set up a cron job:

```bash
# Run daily at 2 AM
0 2 * * * /home/user/recon/monitor.sh example.com >> /home/user/recon/logs/example.com.log 2>&1
```

Use [notify](https://github.com/projectdiscovery/notify) by ProjectDiscovery to send alerts to Slack, Discord, Telegram, or email.

## Notifications

Configure notify to send you alerts:

```yaml
# notify-config.yaml
slack:
  - id: "recon-alerts"
    slack_webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    slack_username: "ReconBot"
    slack_channel: "#bug-bounty"

discord:
  - id: "recon-discord"
    discord_webhook_url: "https://discord.com/api/webhooks/YOUR/WEBHOOK"
```

The goal is to know about new subdomains, new services, and new vulnerabilities before anyone else does. When a company deploys a new service, there's a window where it hasn't been fully hardened. That's when you want to be looking at it.

## Data Storage

For simple setups, flat files work fine. If you're running this across dozens of targets, consider:

```bash
# SQLite for structured queries
sqlite3 recon.db "CREATE TABLE IF NOT EXISTS subdomains (
    domain TEXT, subdomain TEXT, first_seen TEXT, last_seen TEXT,
    UNIQUE(domain, subdomain)
);"

# Insert new findings
while read sub; do
    sqlite3 recon.db "INSERT OR IGNORE INTO subdomains (domain, subdomain, first_seen, last_seen)
        VALUES ('$DOMAIN', '$sub', datetime('now'), datetime('now'));"
    sqlite3 recon.db "UPDATE subdomains SET last_seen = datetime('now')
        WHERE domain = '$DOMAIN' AND subdomain = '$sub';"
done < "$OUTPUT_DIR/final_subs.txt"
```

## Tool Installation

For a fresh VPS, install everything:

```bash
# Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/d3mondev/puredns/v2@latest
go install -v github.com/Josue87/gotator@latest
go install -v github.com/sensepost/gowitness@latest
go install -v github.com/003random/getJS/v2@latest
go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest

# Other tools
pip3 install jsbeautifier

# Resolvers list
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt

# Nuclei templates (auto-downloads on first run)
nuclei -update-templates
```

## Final Notes

This pipeline finds bugs. Not because any individual tool is special, but because running everything together, continuously, catches things that one-off scans miss. New subdomain goes live at 3 AM? You know about it by 3:30 AM. New JavaScript file deployed with a hardcoded API key? You find it on the next scan.

The key is consistency. Set it up once, let it run, and focus your manual effort on the interesting things it surfaces.