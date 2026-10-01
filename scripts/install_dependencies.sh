#!/usr/bin/env bash
# ==============================================================================
# WebVulnScanner External Tool Installation Guide
# ==============================================================================
# This script provides clear, non-privilege-escalating commands for installing
# supported external security tools used by WebVulnScanner.
#
# Supported Tools:
#   - nmap       (TCP/Service port fingerprinting)
#   - nuclei     (Vulnerability template scanning)
#   - subfinder  (Passive subdomain enumeration)
#   - wappalyzer (Technology detection via wappalyzer-cli)
#   - dirsearch  (Web content/path discovery)
#   - gobuster   (High-speed directory discovery)
#   - sqlmap     (Safe query parameter injection verification)
#   - wpscan     (WordPress vulnerability assessment)
#   - whois      (Passive domain registration lookup)
#
# NOTE: Review and run these commands manually or execute this script under
# your preferred package manager environment. This script does NOT auto-elevate
# privileges.
# ==============================================================================

set -euo pipefail

echo "============================================================"
echo " WebVulnScanner Dependency Installation Helper"
echo "============================================================"
echo ""
echo "Please choose your environment or install tools individually:"
echo ""

echo "--- Debian / Ubuntu (apt) ---"
cat << 'EOF'
sudo apt update
sudo apt install -y nmap sqlmap whois git curl golang python3-pip

# Go-based tools (add $(go env GOPATH)/bin to PATH)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OJ/gobuster/v3@latest

# Python-based tools
pip install --user dirsearch

# Node-based tools
npm install -g wappalyzer-cli

# Ruby-based tools
sudo apt install -y ruby-full
gem install wpscan
EOF

echo ""
echo "--- Arch Linux (pacman / AUR) ---"
cat << 'EOF'
sudo pacman -S nmap sqlmap whois nuclei subfinder gobuster dirsearch wpscan
npm install -g wappalyzer-cli
EOF

echo ""
echo "--- macOS (Homebrew) ---"
cat << 'EOF'
brew install nmap nuclei subfinder gobuster sqlmap wpscan whois node
npm install -g wappalyzer-cli
pip install dirsearch
EOF

echo ""
echo "After installation, verify tool presence by running:"
echo "  python scripts/verify_tools.py"
echo "============================================================"
