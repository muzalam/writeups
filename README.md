# CyberSec Writeups Blog - Setup Guide

A complete Hugo blog ready to deploy on GitHub Pages with a dark terminal-style theme.

## Step 1: Install Hugo

macOS: brew install hugo
Windows: winget install Hugo.Hugo.Extended
Linux: sudo apt install hugo

Verify with: hugo version

## Step 2: Install Git

Check with: git --version
If not installed go to https://git-scm.com/downloads

## Step 3: Test locally

Unzip this folder, open a terminal inside it, run: hugo server -D
Then open http://localhost:1313/cybersec-blog/ in your browser.

## Step 4: Create a GitHub repo

Go to https://github.com/new, name it cybersec-blog, make it Public.
Do NOT check any initialization boxes.

## Step 5: Push to GitHub

Run these in the blog folder (replace YOURUSERNAME):

git init
git add .
git commit -m "initial commit"
git branch -M main
git remote add origin https://github.com/YOURUSERNAME/cybersec-blog.git
git push -u origin main

## Step 6: Enable GitHub Pages

Go to your repo Settings then Pages. Under Source select GitHub Actions.

## Step 7: Wait for deploy

Go to the Actions tab. Wait 1-2 min. Site goes live at:
https://YOURUSERNAME.github.io/cybersec-blog/

## Step 8: Edit config

Open hugo.toml and set your baseURL, author, description, tagline.
Then git add, commit, push.

## Writing a new post

Create a file in content/posts/ like this:

title: "HackTheBox: SomeMachine Writeup"
date: 2022-03-10T10:00:00-05:00
draft: false
tags: ["htb", "windows", "active-directory"]
difficulty: "Hard"

Set the date field to ANY date you want. Thats the whole point.
Set draft to false to publish. Use markdown for your content.

To publish: git add, commit, push. Auto-deploys in about 1 minute.
