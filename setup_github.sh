#!/bin/bash
# SentinelFW - Push to GitHub
# Run this after installing git

echo "================================"
echo "SentinelFW - Push to GitHub"
echo "================================"
echo ""

# Check git
if ! command -v git &> /dev/null; then
    echo "ERROR: Git not found!"
    echo "Install from: https://git-scm.com"
    exit 1
fi

echo "Configuring git..."
git config --global user.email "eduardofontana@gmail.com"
git config --global user.name "Eduardo Fontana"

echo ""
echo "1. Create repo at: https://github.com/new"
echo "   - Name: sentinelfw"
echo "   - Description: Home Firewall + IDS (Snort-inspired)"
echo "   - Public: Yes"
echo "   - Don't add README"
echo ""
echo "2. Copy the commands below after creating the repo:"
echo ""

echo "git add ."
echo 'git commit -m "Initial commit: SentinelFW v1.0"'
echo ""
echo "# Add your repo URL (replace with your actual URL):"
echo 'git remote add origin https://github.com/eduardofontana/sentinelfw.git'
echo "git push -u origin main"