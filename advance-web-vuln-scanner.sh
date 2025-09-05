#!/usr/bin/env bash
#
# Advance Web Vuln Scanner (Pro Edition)
# Author: Veer Kumar
#

set -euo pipefail
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
echo "Version: 3.0"
echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
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

# ---------------- Spinner ----------------
spinner() {
    local pid=$1 label=$2
    local spin='-\|/'; local i=0
    while kill -0 "$pid" 2>/dev/null; do
        i=$(((i + 1) % 4))
        printf "\r${CYAN}[>]${RESET} %-25s %s" "$label" "${spin:$i:1}"
        sleep 0.2
    done
    wait "$pid"
    local exit_code=$?
    if [ $exit_code -eq 0 ]; then
        printf "\r${GREEN}[+] %-25s finished        \n" "$label"
    else
        printf "\r${RED}[-] %-25s failed (exit $exit_code)\n" "$label"
    fi
}

# ---------------- Tool Runner ----------------
run_tool() {
    local title="$1" tool="$2"; shift 2
    local out="$REPORT_DIR/${tool}.txt"
    if [ "$LIVE_OUTPUT" -eq 1 ]; then
        ( "$@" >"$out" 2>&1 & )
        spinner $! "$tool"
    else
        ( "$@" >"$out" 2>&1 ) &
        spinner $! "$tool"
    fi
    if [ -f "$out" ]; then
        parse_risks "$out"
        append_section "$title" "$tool" "$out"
    fi
}

# ---------------- Individual Scans ----------------
scan_wapiti()      { run_tool "Web Vulnerability Scan" "wapiti"      wapiti -u "$TARGET_URL" -m all; }
scan_wpscan()      { run_tool "WordPress Assessment" "wpscan"       wpscan --url "$TARGET_URL" --no-banner --random-user-agent --force --disable-tls-checks; }
scan_nmap()        { run_tool "Port & Service Enumeration" "nmap"   nmap -Pn -sV --top-ports 1000 -T4 "$HOST"; }
scan_wafw00f()     { run_tool "WAF Detection" "wafw00f"             wafw00f -a "$TARGET_URL"; }
scan_whatweb()     { run_tool "Technology Fingerprinting" "whatweb" whatweb -a 3 "$TARGET_URL"; }
scan_sslscan()     { run_tool "SSL/TLS Review" "sslscan"            sslscan --no-failed "$HOST:443"; }
scan_dnsrecon()    { run_tool "DNS Reconnaissance" "dnsrecon"       dnsrecon -d "$HOST"; }

scan_all() {
    declare -a jobs=()
    if [ $PARALLEL -eq 1 ]; then
        scan_wapiti & jobs+=($!)
        scan_wpscan & jobs+=($!)
        scan_nmap & jobs+=($!)
        scan_wafw00f & jobs+=($!)
        scan_whatweb & jobs+=($!)
        scan_sslscan & jobs+=($!)
        scan_dnsrecon & jobs+=($!)
        wait "${jobs[@]}"
    else
        scan_wapiti
        scan_wpscan
        scan_nmap
        scan_wafw00f
        scan_whatweb
        scan_sslscan
        scan_dnsrecon
    fi
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
    # Execution Mode
    echo "Execution Mode:"
    echo "1) Parallel (faster)"
    echo "2) Sequential (safer)"
    read -rp "Choose [1-2]: " m
    case $m in
        1) PARALLEL=1 ;;
        2) PARALLEL=0 ;;
        *) PARALLEL=0 ;;
    esac
    # Output Mode
    echo "Output Mode:"
    echo "1) Spinner-only (clean)"
    echo "2) Live Output (verbose)"
    read -rp "Choose [1-2]: " o
    case $o in
        1) LIVE_OUTPUT=0 ;;
        2) LIVE_OUTPUT=1 ;;
        *) LIVE_OUTPUT=0 ;;
    esac

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
