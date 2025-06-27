#!/bin/bash

# Domain Health Reporter (dhr)
# Script to check domain info, DNS records, hosting, SSL and redirects

# Parse command line arguments
dns_server=""
domain=""

# Loop through all command line arguments until none left
while [[ $# -gt 0 ]]; do
    case $1 in
        -ns)
            # If current argument is -ns, then next argument ($2) is the DNS server
            dns_server="@$2"
            # Skip both the -ns flag and the DNS server value (shift by 2 positions)
            shift 2
            ;;
        *)
            # Any other argument is treated as the domain name
            domain="$1"
            # Move to next argument (shift by 1 position)
            shift
            ;;
    esac
done

# Check if domain argument provided
if [ -z "$domain" ]; then
    echo "Usage: $(basename $0) [-ns dns_server] <domain>"
    echo "Example: $(basename $0) example.com"
    echo "Example: $(basename $0) -ns 1.1.1.1 example.com"
    echo "Example: $(basename $0) -ns 8.8.8.8 https://www.example.com/path"
    exit 1
fi

echo
# Check if dns_server variable is empty (user didn't specify -ns option)
if [ -z "$dns_server" ]; then
    # No custom DNS server specified - get system default DNS info
    dns_info=`dig | grep SERVER | cut -d " " -f 2,3 | cut -d "#" -f 1`
    printf "Lookups using DNS $dns_info"
else
    # Custom DNS server was specified - display it (strip @ symbol for clean output)
    # ${dns_server#@} removes the "@" prefix we added earlier
    printf "Lookups using DNS ${dns_server#@}"
fi
echo

# Extract clean domain from various input formats
domain=`echo $domain | awk -F "//" '{print $NF}' | awk -F "www." '{print $NF}' | awk -F "/" '{print $1}'`
echo -e "Domain : $(tput setaf 1)$domain$(tput sgr0) - finding IP & Ownership..."
echo

# Get IP and organization info for root domain
NON_WWW_IP=`dig $dns_server +short $domain | head -n 1 | xargs | sed -e 's/ /, /g'`
NON_WWW_IP_ORG=`dig $dns_server +short $domain | head -n 1 | xargs whois | grep 'OrgName\|org-name\|descr' | sort -r | head -n 1 | awk '{print $2,$3,$4,$5}'`
echo -e "IP for root\t: ${NON_WWW_IP}\t: ${NON_WWW_IP_ORG}"

# Get IP and organization info for www subdomain
WWW_IP=`dig $dns_server +short www.$domain | head -n 1 | xargs | sed -e 's/ /, /g'`
WWW_IP_ORG=`dig $dns_server +short www.$domain | head -n 1 | xargs whois | grep 'OrgName\|org-name\|descr' | sort -r | head -n 1 | awk '{print $2,$3,$4,$5}'`
echo -e "IP for www\t: ${WWW_IP}\t: ${WWW_IP_ORG}"
echo

# A records for root domain
dig $dns_server $domain | grep IN | grep -v ";" | grep -v NS | sort -k 5n,5
echo

# A records for www subdomain
dig $dns_server www.$domain | grep IN | grep -v ";" | grep -v NS
echo

# MX records
dig $dns_server MX $domain | grep IN | grep -v ";" | grep MX | sort -k 5n,5
dig $dns_server MX $domain | grep IN | grep -v ";" | grep -v NS | sort -k 5n,5 | cuts -1 | xargs dig $dns_server | grep IN | grep -v ";" | grep -v NS | grep -v SOA
echo

# NS records
dig $dns_server NS $domain | grep IN | grep -v ";" | sort -k 5n,5
echo

# TXT records
dig $dns_server TXT $domain | grep IN | grep -v ";" | grep -v NS | grep -v SOA
echo

# DMARC record
dig $dns_server TXT _dmarc.$domain | grep IN | grep \"v
echo

# DKIM records (common selectors)
dig $dns_server TXT bozmail._domainkey.$domain | grep IN | grep \"v
dig $dns_server TXT boz._domainkey.$domain | grep IN | grep \"v
echo

# Registrar information
whois $domain | grep -m 1 -A1 "Registrar:" | grep -v "Sponsoring" | grep -v "IANA ID" | sed -e 's/^[ \t]*//' 
echo

# Domain expiration
whois $domain | grep Expir | grep -v "Registrar Registration Expiration Date:" | sed -e 's/^[ \t]*//'
echo

# HTTP/HTTPS redirect testing
echo -e "Checking HTTP/HTTPS + root/www for redirects/errors..."
echo
printf 'TIME (s)|REQUEST URL|CODE|REDIRECT URL\n' > /tmp/301.txt
curl -sI http://$domain -w '%{time_total}|%{url_effective}|%{response_code}|%{redirect_url}\n' -o /dev/null >> /tmp/301.txt
curl -sI http://www.$domain -w '%{time_total}|%{url_effective}|%{response_code}|%{redirect_url}\n' -o /dev/null >> /tmp/301.txt
curl -sI https://$domain -w '%{time_total}|%{url_effective}|%{response_code}|%{redirect_url}\n' -o /dev/null >> /tmp/301.txt
curl -sI https://www.$domain -w '%{time_total}|%{url_effective}|%{response_code}|%{redirect_url}\n' -o /dev/null >> /tmp/301.txt
cat /tmp/301.txt | column -t -s '|'
echo
rm /tmp/301.txt
