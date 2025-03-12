#!/bin/bash

# Function to display general usage instructions
usage() {
    echo "Usage: $0 [options]
    -a        Domain To IP's
    -b        CIDR To IP's
    -c        CIDR To Domain
    -d        HTTPX To Specific Status Code Text File
    -e        Download Directory Listing Enabled Website
    -f        Show all the cname from the provided file
    -g        Mass Port Scan
    -h        Alien Url's
    -i        Virus Total
    -j        AllDomz
    -k        AllUrls
    -l        Domains to status codes
    -m        ZipFinder"
    exit 1
}

# Function to display usage instructions for -a
usage_domain_to_ips() {
    echo "Usage for -a:
    Example: $0 -a <Domain File>"
    exit 1
}

# Function for Domain To IP's
domain_to_ips() {
    local input_file="$1"
    local output_file="DomToIP.txt"

    > "$output_file"

    while IFS=$'\r' read -r line; do
        echo "$line" | tee -a "$output_file"
        ip_addresses=$(host "$line" | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u)
        while IFS= read -r ip; do
            echo "$ip" | tee -a "$output_file"
        done <<< "$ip_addresses"
        echo | tee -a "$output_file"
    done < "$input_file"

    echo "IP addresses have been saved to $output_file"
}

# Function for CIDR To IP's
cidr_to_ips() {
    local CIDR_FILE=$1

    if ! command -v prips &> /dev/null; then
        echo "prips could not be found. Please install prips to proceed."
        exit 1
    fi

    if [ ! -f "$CIDR_FILE" ]; then
        echo "File not found: $CIDR_FILE"
        exit 1
    fi

    while IFS= read -r cidr; do
        if [[ -z "$cidr" || "$cidr" =~ ^# ]]; then
            continue
        fi
        prips "$cidr" | tee -a AllIPs.txt
    done < "$CIDR_FILE"
}

# Function for CIDR To Domain
cidr_to_domain() {
    local CIDR_FILE=$1

    if ! command -v prips &> /dev/null; then
        echo "prips could not be found. Please install prips to proceed."
        exit 1
    fi

    if ! command -v hakrevdns &> /dev/null; then
        echo "hakrevdns could not be found. Please install hakrevdns to proceed."
        exit 1
    fi

    if [ ! -f "$CIDR_FILE" ]; then
        echo "File not found: $CIDR_FILE"
        exit 1
    fi

    while IFS= read -r cidr; do
        if [[ -z "$cidr" || "$cidr" =~ ^# ]]; then
            continue
        fi
        prips "$cidr" | hakrevdns -d  -U | anew Reversed-DNS-Subdomains.txt
    done < "$CIDR_FILE"
}

# Function for HTTPX To Specific Status Code Text File
httpx_status_code() {
    local input_file="$1"
    local status_codes=($(grep -oP '\[\d{3}\]' "$input_file" | sort -u | tr -d '[]'))

    for code in "${status_codes[@]}"; do
        grep "$code" "$input_file" > "${code}.txt"
    done

    echo "Extraction completed."
}

# Function for Downloading Directory Listing Enabled website Content
directory_listing() {
    local URL="$1"
    local OUTPUT_DIR="downloaded_files"
    mkdir -p "$OUTPUT_DIR"
    wget -r -np -nH --cut-dirs=1 -P "$OUTPUT_DIR" "$URL"
    echo "Files downloaded to $OUTPUT_DIR"
}

# Function for Displaying mass CNAME/A
massCNAME() {
    local filename=$1
    local temp_file=$(mktemp)

    while read -r sub; do
        dig "$sub" +noquestion +noauthority +noadditional +nostats | \
        awk '/IN[[:space:]]+(CNAME)/ {printf "%-50s %-6s %s\n", $1, $4, $5}' >> "$temp_file"
    done < "$filename"

    sort -k2,2 -k1,1 "$temp_file"
    rm "$temp_file"
}

# Function for Displaying mass CNAME/A
massPortScan() {
    local filename=$1
    naabu -silent -nc -l $filename -tp 1000 -ep 21,22,80,443,554,1723
}

# Function for Alien URL
AlienUrl() {
    local domain=$1
    local output_file="AlienResult.txt"
    local base_url="https://otx.alienvault.com/api/v1/indicators/domain/$domain/url_list?limit=500&page="
    local page=1

    echo "[INFO] Scraping URLs for domain: $domain"

    while true; do
        response=$(curl -s "$base_url$page")
        urls=$(echo "$response" | jq -r '.url_list[].url' 2>/dev/null)

        if [ -z "$urls" ]; then
            echo "[INFO] No more URLs for $domain."
            break
        fi

        echo "$urls" >>"$output_file"
        page=$((page + 1))
    done

    if [ -s "$output_file" ]; then
        echo "[INFO] URLs saved to $output_file"
    else
        echo "[INFO] No URLs found for domain: $domain."
    fi
}

# Function for Displaying VirusTotal
VirusTotal() {
    local domain=$1
    local api_key_index=$2
    local api_key

    if [ $api_key_index -eq 1 ]; then
        api_key="2d1ed4d97f91c3c18877c02c5d14225e95c2b5dab7c16a524efa0b94cfd1c0a9"
    elif [ $api_key_index -eq 2 ]; then
        api_key="2fb731a6845f9d09e17e5334f6a1e2cf29e0131f925c9c43ac7fcf08fe4704ad"
    else
        api_key="2fb731a6845f9d09e17e5334f6a1e2cf29e0131f925c9c43ac7fcf08fe4704ad"
    fi

    local URL="https://www.virustotal.com/vtapi/v2/domain/report?apikey=$api_key&domain=$domain"

    echo -e "\nFetching data for domain: \033[1;34m$domain\033[0m (using API key $api_key_index)"
    response=$(curl -s "$URL")
    if [[ $? -ne 0 ]]; then
        echo -e "\033[1;31mError fetching data for domain: $domain\033[0m"
        return
    fi

    undetected_urls=$(echo "$response" | jq -r '.undetected_urls[][0]')
    if [[ -z "$undetected_urls" ]]; then
        echo -e "\033[1;33mNo undetected URLs found for domain: $domain\033[0m"
    else
        echo -e "\033[1;32mUndetected URLs for domain: $domain\033[0m"
        echo "$undetected_urls"
    fi
}

# Function for Displaying All Domains
AllDomz() {
    local domain=$1
    crtsh -d $domain | anew SubList1.txt
    subdom $domain | anew SubList2.txt
    shodanx subdomain -d $domain -o SubList3.txt
    subfinder -all -recursive -silent -nc -d $domain | anew SubList4.txt
    assetfinder -subs-only $domain | anew SubList5.txt
    subdominator -nc -d $domain | anew SubList6.txt
    cat SubList1.txt SubList2.txt SubList3.txt SubList4.txt SubList5.txt SubList6.txt | anew subdomains.txt 
}

# Function for Displaying All urls
AllUrls() {
    local domain=$1
    echo $domain | gau --mc 200 --blacklist woff,css,png,svg,jpg,ico,otf,ttf,woff2,jpeg,gif,svg | anew ParamFuzz1.txt
    echo $domain | waybackurls | anew ParamFuzz2.txt
    echo $domain | hakrawler -subs | anew ParamFuzz3.txt
    gospider -a -w -c 50 -m 3 -s $domain | anew ParamFuzz4.txt
    katana -silent -nc -jc -c 100 -ef woff,css,png,svg,jpg,ico,otf,ttf,woff2,jpeg,gif,svg -u $domain | anew ParamFuzz5.txt
}

# Function for clearn all domains
CleanDomains() {
    local domain=$1
    cat $domain | httpx-toolkit -sc -nc -silent -title | tee >(grep "\[3[0-9][0-9]\]" | anew 300s.txt) >(grep "\[4[0-9][0-9]\]" | anew 400s.txt) >(grep "\[5[0-9][0-9]\]" | anew 500s.txt) | grep "\[2[0-9][0-9]\]" | anew 200s.txt
}

zipfinder(){
    # Usage function
    usage() {
        echo "Usage: zipfinder <domain>"
        echo "Example: zipfinder example.com"
        exit 1
    }

    # Check for -h or missing arguments
    if [[ $# -eq 0 || $1 == "-h" ]]; then
        usage
    fi

    local domain=$1
    local output_file="wayback_files.txt"

    # Fetch backup-related files
    echo "=========================================="
    echo " Searching for backup files on Wayback Machine"
    echo " Target Domain: $domain"
    echo "=========================================="

    local result=$(curl -s "https://web.archive.org/cdx/search/cdx?url=*.$domain/*&collapse=urlkey&output=text&fl=original" | \
    grep -E '\.(zip|bak|tar|tar\.gz|tgz|7z|rar|sql|db|backup|old|gz|bz2|xls|xml|xlsx|json|pdf|doc|docx|pptx|txt|log|cache|secret|yml|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|deb|git|env|rpm|iso|img|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$')


    if [[ -n "$result" ]]; then
        echo -e "\n[+] Backup files found:\n"
        echo "Backup files for $domain" > "$output_file"
        echo "==========================================" >> "$output_file"

        while IFS= read -r url; do
            local archive_data=$(curl -s "https://web.archive.org/cdx/search/cdx?url=$url&output=json")
            local timestamp=$(echo "$archive_data" | jq -r '.[1][1]' 2>/dev/null)
            
            if [[ "$timestamp" != "null" && -n "$timestamp" ]]; then
                local snapshot_link="https://web.archive.org/web/$timestamp/$url"
                echo "[*] File: $url" | tee -a "$output_file"
                echo "    ➜ Snapshot Available: $snapshot_link" | tee -a "$output_file"
            else
                echo "[*] File: $url" | tee -a "$output_file"
                echo "    ✗ No Snapshot Available" | tee -a "$output_file"
            fi
            echo "------------------------------------------" | tee -a "$output_file"
        done <<< "$result"

        echo "[✓] Results saved to $output_file"
    else
        echo "[✗] No backup files found."
    fi

    echo "=========================================="
    echo " Done!"
    echo "=========================================="
}


# Main function to parse options and call appropriate functions
main() {
    while getopts ":a:b:c:d:e:f:g:h:i:j:k:l:m:" opt; do
        case $opt in
            a) domain_to_ips "$OPTARG" ;;
            b) cidr_to_ips "$OPTARG" ;;
            c) cidr_to_domain "$OPTARG" ;;
            d) httpx_status_code "$OPTARG" ;;
            e) directory_listing "$OPTARG" ;;
            f) massCNAME "$OPTARG" ;;
            g) massPortScan "$OPTARG" ;;
            h) AlienUrl "$OPTARG" ;;
            i) VirusTotal "$OPTARG" ;;
            j) AllDomz "$OPTARG" ;;
            k) AllUrls "$OPTARG" ;;
            l) CleanDomains "$OPTARG" ;;
            m) zipfinder "$OPTARG" ;;
            *) usage ;;
        esac
    done

    if [ $OPTIND -eq 1 ]; then
        usage
    fi
}

# Call the main function
main "$@"
