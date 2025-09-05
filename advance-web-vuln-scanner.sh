#!/usr/bin/env bash
#
# Advance Web Vuln Scanner (Pro Edition v11.4)
# Author: Veer Kumar
#

set -u
IFS=$'\n\t'

# ---------------- Colors ----------------
RED=$'\e[31m'; GREEN=$'\e[32m'; CYAN=$'\e[36m'; YELLOW=$'\e[33m'; RESET=$'\e[0m'

# ---------------- Banner ----------------
banner() {
cat <<'EOF'
############################################################
#                                                          #
#            ADVANCE WEB VULN SCANNER (PRO EDITION)        #
#                                                          #
#                     Author: Veer Kumar                   #
#                                                          #
############################################################
EOF
echo "Version: 11.4"
echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo
}

# ---------------- Dependency Checker + Auto Installer ----------------
check_dependencies() {
    echo -e "${CYAN}[>] Checking dependencies...${RESET}"
    local deps=("wapiti" "wpscan" "nmap" "wafw00f" "whatweb" "sslscan" "dnsrecon")

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            echo -e "${RED}[-] Missing: $dep${RESET}"
            read -rp "   Do you want to install $dep now? (y/n): " ans
            if [[ "$ans" =~ ^[Yy]$ ]]; then
                echo -e "${YELLOW}[>] Installing $dep...${RESET}"
                sudo apt update -y && sudo apt install -y "$dep" || {
                    echo -e "${RED}[!] Failed to install $dep. Please install manually.${RESET}"
                }
            else
                echo -e "${YELLOW}[!] Skipping installation of $dep. Some scans may not work.${RESET}"
            fi
        else
            echo -e "${GREEN}[+] Found: $dep${RESET}"
        fi
    done
    echo
}

# ---------------- Target Parsing ----------------
parse_target() {
    local raw="$1"
    if [[ "$raw" =~ ^https?:// ]]; then
        TARGET_URL="$raw"
    else
        TARGET_URL="https://$raw"
    fi
    HOST=$(echo "$TARGET_URL" | sed -E 's#^https?://([^/]+).*#\1#')
}

# ---------------- Report ----------------
start_report() {
    REPORT_DIR="$(pwd)/awvs_${HOST}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$REPORT_DIR"
    REPORT_HTML="$REPORT_DIR/report.html"
    {
        echo "<!doctype html><html><head><meta charset=utf-8>"
        echo "<title>Scan Report for $HOST</title>"
        echo "<style>
            body { background:#0b1220; color:#eee; font-family:monospace; margin:20px; }
            h1,h2 { color:#38bdf8; }
            pre { background:#111; padding:10px; border-radius:6px; white-space:pre-wrap; }
            table { border-collapse: collapse; margin:10px 0; }
            th,td { border:1px solid #444; padding:6px 12px; }
        </style></head><body>"
        echo "<h1>Advance Web Vuln Scanner Report</h1>"
        echo "<p><b>Target:</b> $HOST<br><b>Generated:</b> $(date)<br><b>Author:</b> Veer Kumar</p><hr>"
    } > "$REPORT_HTML"
}

append_section() {
    local title="$1" tool="$2" file="$3"
    {
        echo "<h2 id='$tool'>$title ($tool)</h2><pre>"
        sed -e 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' "$file"
        echo "</pre>"
    } >> "$REPORT_HTML"
}

finish_report() {
    echo "<hr><h2>Risk Summary</h2>" >> "$REPORT_HTML"
    echo "<table><tr><th style='color:#f85149;'>High</th><th style='color:#d29922;'>Medium</th><th style='color:#58a6ff;'>Low</th><th style='color:#8b949e;'>Info</th></tr>" >> "$REPORT_HTML"
    echo "<tr align=center><td>$RISK_HIGH</td><td>$RISK_MED</td><td>$RISK_LOW</td><td>$RISK_INFO</td></tr></table>" >> "$REPORT_HTML"
    echo "<hr><p>End of Report — Advance Web Vuln Scanner</p></body></html>" >> "$REPORT_HTML"
    echo -e "${GREEN}[+] Report saved: $REPORT_HTML${RESET}"
}

# ---------------- Risk Parser ----------------
RISK_HIGH=0; RISK_MED=0; RISK_LOW=0; RISK_INFO=0
parse_risks() {
    local file="$1"
    [[ ! -f "$file" ]] && return
    while IFS= read -r line; do
        case "$line" in
            *"High"*|*"Critical"*|*"CRITICAL"*) ((RISK_HIGH++)) ;;
            *"Medium"*|*"MEDIUM"*) ((RISK_MED++)) ;;
            *"Low"*|*"LOW"*) ((RISK_LOW++)) ;;
            *"Info"*|*"Informational"*|*"INFO"*) ((RISK_INFO++)) ;;
        esac
    done <"$file"
}

# ---------------- Tool Runner ----------------
run_tool() {
    local title="$1" tool="$2"; shift 2
    local out="$REPORT_DIR/${tool}.txt"
    echo -e "${CYAN}[>] Running $title ($tool)...${RESET}"

    { "$@" 2>&1 || true; } | tee "$out"

    if [ -s "$out" ]; then
        parse_risks "$out"
        append_section "$title" "$tool" "$out"
    else
        echo "[!] No output captured for $tool" | tee -a "$out"
        append_section "$title" "$tool" "$out"
    fi

    echo -e "${GREEN}[+] Finished $title${RESET}\n"
}

# ---------------- Individual Scans ----------------
scan_wapiti()   { run_tool "Web Vulnerability Scan" "wapiti"      wapiti -u "$TARGET_URL" -m all; }
scan_wpscan()   { run_tool "WordPress Assessment" "wpscan"       wpscan --url "$TARGET_URL" --no-banner --random-user-agent --force --disable-tls-checks; }
scan_nmap()     { run_tool "Port & Service Enumeration" "nmap"   nmap -Pn -sV --top-ports 1000 -T4 "$HOST"; }
scan_wafw00f()  { run_tool "WAF Detection" "wafw00f"             wafw00f -a "$TARGET_URL"; }
scan_whatweb()  { run_tool "Technology Fingerprinting" "whatweb" whatweb -a 3 "$TARGET_URL"; }
scan_sslscan()  { run_tool "SSL/TLS Review" "sslscan"            sslscan --no-failed "$HOST:443"; }
scan_dnsrecon() { run_tool "DNS Reconnaissance" "dnsrecon"       dnsrecon -d "$HOST"; }

# ---------------- Scan All ----------------
scan_all() {
    echo -e "${YELLOW}[>] Running full scan on $TARGET_URL${RESET}\n"

    scan_wapiti   || true
    scan_wpscan   || true
    scan_nmap     || true
    scan_wafw00f  || true
    scan_whatweb  || true
    scan_sslscan  || true
    scan_dnsrecon || true

    echo -e "${GREEN}[+] Full scan finished!${RESET}\n"
}

# ---------------- Menu ----------------
menu() {
    echo -e "${YELLOW}=== Select a Scan Option ===${RESET}"
    echo "1) Wapiti (Web Vulnerability Scan)"
    echo "2) WPScan (WordPress Assessment)"
    echo "3) Nmap (Port & Service Enumeration)"
    echo "4) WAF Detection (wafw00f)"
    echo "5) WhatWeb (Technology Fingerprinting)"
    echo "6) SSLScan (SSL/TLS Review)"
    echo "7) DNSRecon (DNS Reconnaissance)"
    echo "8) Scan All"
    echo "9) Exit"
}

# ---------------- Main ----------------
main() {
    banner
    check_dependencies
    read -rp "Enter target (domain/IP/URL): " target
    parse_target "$target"
    start_report

    while true; do
        menu
        read -rp "Choice: " choice
        case $choice in
            1) scan_wapiti ;;
            2) scan_wpscan ;;
            3) scan_nmap ;;
            4) scan_wafw00f ;;
            5) scan_whatweb ;;
            6) scan_sslscan ;;
            7) scan_dnsrecon ;;
            8) scan_all ;;
            9) break ;;
            *) echo -e "${RED}Invalid choice${RESET}" ;;
        esac
    done
    finish_report
}

trap 'echo -e "${RED}\nInterrupted. Exiting...${RESET}"; exit 1' INT
main "$@"
